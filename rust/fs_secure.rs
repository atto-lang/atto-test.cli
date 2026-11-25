//! Unix project-root anchored file operations.
//!
//! Every existing ancestor is opened with O_DIRECTORY | O_NOFOLLOW, and
//! the final file with O_NOFOLLOW | O_NONBLOCK. This prevents symlink
//! substitution at any traversed component, including during input reads
//! and fuzz reproducer creation. It does NOT constrain a test subprocess,
//! protect a root directory renamed by a hostile concurrent process,
//! or substitute for an OS sandbox.
#![cfg(unix)]

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

// open(2) flag values are architecture-specific. The previous hard-coded
// x86-64 values meant O_DIRECT | O_LARGEFILE on aarch64: the project root
// open failed with EINVAL (every --fuzz / --race --trace exited 2), and
// any open that succeeded carried no O_NOFOLLOW protection at all.
use libc::{O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_NONBLOCK, O_RDONLY, O_WRONLY};

// openat(2) is variadic. A hand-written fixed-arity declaration passes the
// mode in a register, but Apple arm64 reads variadic arguments from the
// stack, so newly created files got arbitrary permissions there. libc's
// declarations carry the real C signatures.
use libc::{mkdirat, openat};

fn components(path: &Path) -> Result<Vec<&OsStr>, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => parts.push(name),
            Component::CurDir => {}
            _ => return Err("project path contains a non-relative component".into()),
        }
    }
    if parts.is_empty() || parts.len() > 64 {
        return Err("project relative path is empty or over-depth".into());
    }
    Ok(parts)
}

fn c_name(name: &OsStr) -> Result<CString, String> {
    CString::new(name.as_bytes()).map_err(|_| "NUL in project path".into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

struct EntryStat {
    kind: Kind,
    dev: u64,
    ino: u64,
}

/// lstat relative to an opened directory: never follows a final symlink and
/// never re-resolves a pathname. Does not trust readdir's d_type.
fn stat_at(directory: &File, name: &OsStr) -> Result<EntryStat, String> {
    let c = c_name(name)?;
    // SAFETY: zeroed stat is a valid out-parameter for fstatat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(format!(
            "cannot stat project entry: {}",
            std::io::Error::last_os_error()
        ));
    }
    let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => Kind::File,
        libc::S_IFDIR => Kind::Dir,
        libc::S_IFLNK => Kind::Symlink,
        _ => Kind::Other,
    };
    // Same widening as std's MetadataExt::{dev, ino}, so values compare.
    #[allow(clippy::unnecessary_cast)]
    return Ok(EntryStat {
        kind,
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
    });
}

fn clear_errno() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        *libc::__errno_location() = 0;
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    unsafe {
        *libc::__error() = 0;
    }
}

/// Entry names of an already-opened directory, at most `limit` of them.
/// A fresh descriptor for "." keeps the caller's descriptor offset intact.
/// This replaces read_dir("/proc/self/fd/N"), which needed procfs, existed
/// only on Linux, and confined the anchored checks to that one platform.
fn read_dir_names(directory: &File, limit: usize) -> Result<Vec<OsString>, String> {
    let fd = unsafe {
        openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(format!(
            "cannot enumerate project directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fd is a fresh directory descriptor; fdopendir takes ownership.
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("cannot enumerate project directory: {error}"));
    }
    struct Guard(*mut libc::DIR);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let guard = Guard(dir);
    let mut names = Vec::new();
    loop {
        clear_errno();
        // SAFETY: guard.0 is a live DIR*; the entry is copied before the next call.
        let entry = unsafe { libc::readdir(guard.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error().unwrap_or(0) != 0 {
                return Err(format!("project directory enumeration failed: {error}"));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() >= limit {
            return Err("project directory entry budget exhausted".into());
        }
        names.push(OsStr::from_bytes(name).to_os_string());
    }
    Ok(names)
}

fn opened(fd: i32) -> Result<File, String> {
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // openat transfers ownership of a fresh descriptor to this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn root_fd(root: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        .open(root)
        .map_err(|e| format!("cannot open project root: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_dir() {
        return Err("project root is not a directory".into());
    }
    Ok(file)
}

fn step_dir(current: &File, component: &OsStr, create: bool) -> Result<File, String> {
    let name = c_name(component)?;
    if create {
        let status = unsafe { mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) };
        if status < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(format!(
                "cannot create project output directory: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    opened(unsafe {
        openat(
            current.as_raw_fd(),
            name.as_ptr(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
    })
    .map_err(|e| format!("unsafe or missing project path component: {e}"))
}

fn parent_and_name_fd(
    root: &File,
    relative: &Path,
    create_dirs: bool,
) -> Result<(File, CString), String> {
    let parts = components(relative)?;
    let mut current = root.try_clone().map_err(|e| e.to_string())?;
    for component in &parts[..parts.len() - 1] {
        current = step_dir(&current, component, create_dirs)?;
    }
    let name = c_name(parts[parts.len() - 1])?;
    Ok((current, name))
}

fn parent_and_name(
    root: &Path,
    relative: &Path,
    create_dirs: bool,
) -> Result<(File, CString), String> {
    let fd = root_fd(root)?;
    parent_and_name_fd(&fd, relative, create_dirs)
}

/// One verified directory descriptor reused by a single fuzz invocation.
/// Root pathname substitutions after construction cannot redirect corpus
/// reads or reproduced failure output.
pub struct ProjectRoot {
    fd: File,
}
impl ProjectRoot {
    pub fn new(root: &Path) -> Result<Self, String> {
        Ok(Self { fd: root_fd(root)? })
    }

    /// Check that an outward-facing pathname still denotes the pinned
    /// directory before/after a subprocess or before reporting an artifact.
    /// This is a detection gate, not an atomic path-rename lock.
    pub fn verify_path(&self, path: &Path) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let named = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        let pinned = self.fd.metadata().map_err(|e| e.to_string())?;
        if !named.is_dir()
            || named.file_type().is_symlink()
            || named.dev() != pinned.dev()
            || named.ino() != pinned.ino()
        {
            return Err("project path no longer identifies pinned root".into());
        }
        Ok(())
    }

    pub fn corpus(
        &self,
        relative: &Path,
        max_files: usize,
        per_file: usize,
        total: usize,
    ) -> Result<Vec<Vec<u8>>, String> {
        read_corpus_fd(&self.fd, relative, max_files, per_file, total)
    }

    pub fn reproducer(&self, relative: &Path, bytes: &[u8]) -> Result<bool, String> {
        create_or_match_fd(&self.fd, relative, bytes)
    }
}

fn open_input(root: &Path, relative: &Path) -> Result<File, String> {
    let (parent, name) = parent_and_name(root, relative, false)?;
    opened(unsafe {
        openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
            0,
        )
    })
    .map_err(|e| format!("unsafe project input: {e}"))
}

pub fn read_project_file(
    root: &Path,
    relative: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let file = open_input(root, relative)?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > max_bytes as u64 {
        return Err("input is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max_bytes {
        return Err("input grew beyond its read budget".into());
    }
    Ok(bytes)
}

/// List only regular corpus files using an anchored, already-opened
/// directory descriptor; the original untrusted path is never re-resolved.
#[cfg(test)]
pub fn list_project_files(
    root: &Path,
    relative: &Path,
    max_files: usize,
) -> Result<Vec<PathBuf>, String> {
    let (parent, name) = parent_and_name(root, relative, false)?;
    let directory = opened(unsafe {
        openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
    })?;
    let mut found = Vec::new();
    for name in read_dir_names(&directory, max_files.saturating_add(1))? {
        if stat_at(&directory, &name)?.kind != Kind::File {
            return Err("corpus directory contains a symlink or nonregular entry".into());
        }
        found.push(relative.join(name));
        if found.len() > max_files {
            return Err("corpus file count exceeds admission budget".into());
        }
    }
    found.sort();
    Ok(found)
}

/// Read a complete corpus from one opened directory handle. Files are opened
/// relative to that same handle, not to the original pathname. A concurrent
/// directory rename therefore cannot redirect us into a replacement corpus.
/// File dev/inode is also compared across enumeration and open, rejecting
/// replacement in the gap. The bytes are bounded on the opened descriptor.
///
/// This is not a frozen filesystem snapshot: an adversary with write access
/// can still change bytes in an already opened regular file. Do not claim
/// cryptographic provenance or snapshot isolation from this interface.
fn read_corpus_directory(
    directory: &File,
    max_files: usize,
    per_file: usize,
    total: usize,
) -> Result<Vec<Vec<u8>>, String> {
    use std::os::unix::fs::MetadataExt;
    let mut records = Vec::new();
    let mut aggregate = 0usize;
    for name in read_dir_names(directory, max_files.saturating_add(1))? {
        let listed = stat_at(directory, &name)?;
        if listed.kind != Kind::File {
            return Err("corpus contains a symlink or nonregular entry".into());
        }
        if records.len() >= max_files {
            return Err("corpus count exceeds admission budget".into());
        }
        let c = c_name(&name)?;
        let input = opened(unsafe {
            openat(
                directory.as_raw_fd(),
                c.as_ptr(),
                O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                0,
            )
        })?;
        let actual = input.metadata().map_err(|e| e.to_string())?;
        if !actual.is_file() || actual.dev() != listed.dev || actual.ino() != listed.ino {
            return Err("corpus entry changed identity during enumeration".into());
        }
        if actual.len() > per_file as u64 {
            return Err("corpus entry exceeds case byte budget".into());
        }
        let mut data = Vec::new();
        input
            .take(per_file as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        if data.len() > per_file {
            return Err("corpus case grew beyond read limit".into());
        }
        aggregate = aggregate
            .checked_add(data.len())
            .ok_or("corpus aggregate budget overflow")?;
        if aggregate > total {
            return Err("corpus aggregate budget exhausted".into());
        }
        // Drop the open file promptly instead of holding up to max_files
        // descriptors until sorting. Corpus bytes are already size-bounded.
        records.push((name, data));
    }
    records.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(records.into_iter().map(|(_, bytes)| bytes).collect())
}

/// Missing optional corpus directory yields an empty corpus, without
/// looking up the original project root pathname even once.
fn open_corpus_directory(root: &File, relative: &Path) -> Result<Option<File>, String> {
    let mut current = root.try_clone().map_err(|e| e.to_string())?;
    for component in components(relative)? {
        let name = c_name(component)?;
        let fd = unsafe {
            openat(
                current.as_raw_fd(),
                name.as_ptr(),
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(format!("unsafe corpus directory: {error}"));
        }
        current = opened(fd)?;
    }
    Ok(Some(current))
}

fn read_corpus_fd(
    root: &File,
    relative: &Path,
    max_files: usize,
    per_file: usize,
    total: usize,
) -> Result<Vec<Vec<u8>>, String> {
    match open_corpus_directory(root, relative)? {
        Some(directory) => read_corpus_directory(&directory, max_files, per_file, total),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
pub fn read_corpus_snapshot(
    root: &Path,
    relative: &Path,
    max_files: usize,
    per_file: usize,
    total: usize,
) -> Result<Vec<Vec<u8>>, String> {
    let pinned = ProjectRoot::new(root)?;
    pinned.corpus(relative, max_files, per_file, total)
}

/// Discover Oreslang source paths from *opened* directory descriptors.
/// No path-based recursive traversal. Bounds prevent enormous or cyclic
/// directory trees from causing unbounded scanning. Symlinks are rejected
/// even when their target would otherwise look like an ordinary source.
pub fn discover_sources(
    root: &Path,
    skipped: &[&str],
    max_entries: usize,
    max_files: usize,
    max_depth: usize,
) -> Result<Vec<String>, String> {
    let mut pending = vec![(root_fd(root)?, PathBuf::new(), 0usize)];
    let mut found = Vec::new();
    let mut visited_entries = 0usize;
    while let Some((directory, relative, depth)) = pending.pop() {
        if depth > max_depth {
            return Err("source discovery depth budget exhausted".into());
        }
        let remaining = max_entries
            .saturating_sub(visited_entries)
            .saturating_add(1);
        for name in read_dir_names(&directory, remaining)? {
            visited_entries = visited_entries
                .checked_add(1)
                .ok_or("source discovery counter overflow")?;
            if visited_entries > max_entries {
                return Err("source discovery entry budget exhausted".into());
            }
            let name_text = name.to_str().ok_or("non-UTF-8 source path")?;
            if name_text.starts_with('.') || skipped.contains(&name_text) {
                continue;
            }
            let kind = stat_at(&directory, &name)?.kind;
            if kind == Kind::Symlink {
                return Err("source discovery encountered a symlink".into());
            }
            let child_relative = relative.join(&name);
            if kind == Kind::Dir {
                let child = step_dir(&directory, &name, false)?;
                pending.push((child, child_relative, depth + 1));
            } else if kind == Kind::File
                && matches!(
                    child_relative.extension().and_then(|ext| ext.to_str()),
                    Some("atto" | "ores")
                )
            {
                let fd = opened(unsafe {
                    openat(
                        directory.as_raw_fd(),
                        c_name(&name)?.as_ptr(),
                        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                        0,
                    )
                })?;
                if !fd.metadata().map_err(|e| e.to_string())?.is_file() {
                    return Err("source file changed type during discovery".into());
                }
                found.push(
                    child_relative
                        .to_str()
                        .ok_or("non-UTF-8 source path")?
                        .to_owned(),
                );
                if found.len() > max_files {
                    return Err("source discovery file budget exhausted".into());
                }
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Create an immutable fuzz reproducer only if absent, or compare an existing
/// bounded regular file at the securely opened parent. No path-based
/// read-after-check, symlink following, or truncation.
///
/// Bytes go to a unique temporary file that is fsynced and then hard-linked
/// into place: linkat never replaces, so the final name holds either the
/// complete reproducer or nothing. A run killed mid-write previously left a
/// truncated file that turned every later identical finding into exit 2.
///
/// Ok(true): saved, or an identical reproducer already exists.
/// Ok(false): the name is taken by different bytes (caller picks another).
fn create_or_match_fd(root: &File, relative: &Path, expected: &[u8]) -> Result<bool, String> {
    let (parent, name) = parent_and_name_fd(root, relative, true)?;
    if let Some(same) = matches_existing(&parent, &name, expected)? {
        return Ok(same);
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp = CString::new(format!(".tmp-{}-{stamp}", std::process::id()))
        .map_err(|_| "invalid temporary reproducer name")?;
    let fd = unsafe {
        openat(
            parent.as_raw_fd(),
            temp.as_ptr(),
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    let mut file = opened(fd).map_err(|e| format!("cannot create reproducer: {e}"))?;
    let unlink_temp = || unsafe { libc::unlinkat(parent.as_raw_fd(), temp.as_ptr(), 0) };
    if let Err(e) = file.write_all(expected).and_then(|_| file.sync_all()) {
        unlink_temp();
        return Err(format!("cannot write reproducer: {e}"));
    }
    drop(file);
    let linked = unsafe {
        libc::linkat(
            parent.as_raw_fd(),
            temp.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
            0,
        )
    };
    let link_error = std::io::Error::last_os_error();
    unlink_temp();
    if linked == 0 {
        return Ok(true);
    }
    if link_error.kind() == std::io::ErrorKind::AlreadyExists {
        // Lost a race with a concurrent writer: compare what won.
        return Ok(matches_existing(&parent, &name, expected)?.unwrap_or(false));
    }
    Err(format!("cannot publish reproducer: {link_error}"))
}

/// None: absent. Some(true): identical regular file. Some(false): different
/// bytes. A symlink or nonregular entry under the name is an error.
fn matches_existing(parent: &File, name: &CStr, expected: &[u8]) -> Result<Option<bool>, String> {
    let fd = unsafe {
        openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!("unsafe existing reproducer: {error}"));
    }
    let existing = opened(fd)?;
    let metadata = existing.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("existing reproducer is not a regular file".into());
    }
    if metadata.len() != expected.len() as u64 {
        return Ok(Some(false));
    }
    let mut bytes = Vec::new();
    existing
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(Some(bytes == expected))
}

#[cfg(test)]
pub fn create_or_match(root: &Path, relative: &Path, expected: &[u8]) -> Result<bool, String> {
    ProjectRoot::new(root)?.reproducer(relative, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn read_ancestor_replacement_and_final_symlink_are_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir_all(root.join("inputs")).unwrap();
        std::fs::write(root.join("inputs/safe.ores"), b"safe").unwrap();
        assert_eq!(
            read_project_file(&root, Path::new("inputs/safe.ores"), 4).unwrap(),
            b"safe"
        );

        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("safe.ores"), b"not-safe").unwrap();
        std::fs::rename(root.join("inputs"), root.join("real-inputs")).unwrap();
        symlink(&outside, root.join("inputs")).unwrap();
        assert!(read_project_file(&root, Path::new("inputs/safe.ores"), 10).is_err());
        symlink(root.join("real-inputs/safe.ores"), root.join("alias.ores")).unwrap();
        assert!(read_project_file(&root, Path::new("alias.ores"), 10).is_err());
    }

    #[test]
    fn output_ancestor_symlink_and_colliding_file_are_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let output = Path::new(".oreslang-test/failures/fuzz-01.bin");
        assert_eq!(create_or_match(&root, output, b"abc"), Ok(true));
        assert_eq!(create_or_match(&root, output, b"abc"), Ok(true));
        assert_eq!(create_or_match(&root, output, b"bad"), Ok(false));
        assert_eq!(create_or_match(&root, output, b"abcd"), Ok(false));
        // No temporary files are left behind.
        let leftovers: Vec<_> = std::fs::read_dir(root.join(".oreslang-test/failures"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("fuzz-01.bin")]);
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::rename(root.join(".oreslang-test"), root.join(".renamed")).unwrap();
        symlink(&outside, root.join(".oreslang-test")).unwrap();
        assert!(create_or_match(&root, output, b"abc").is_err());
    }

    #[test]
    fn anchored_listing_rejects_changed_ancestor_and_nonregular_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir_all(root.join("tests/corpus")).unwrap();
        std::fs::write(root.join("tests/corpus/a"), b"data").unwrap();
        assert_eq!(
            list_project_files(&root, Path::new("tests/corpus"), 1).unwrap(),
            vec![PathBuf::from("tests/corpus/a")]
        );
        assert!(list_project_files(&root, Path::new("tests/corpus"), 0).is_err());
        symlink(root.join("tests/corpus/a"), root.join("tests/corpus/alias")).unwrap();
        assert!(list_project_files(&root, Path::new("tests/corpus"), 3).is_err());
        std::fs::remove_file(root.join("tests/corpus/alias")).unwrap();
        std::fs::rename(root.join("tests"), root.join("original-tests")).unwrap();
        symlink(root.join("original-tests"), root.join("tests")).unwrap();
        assert!(list_project_files(&root, Path::new("tests/corpus"), 3).is_err());
    }

    #[test]
    fn corpus_fd_does_not_follow_replacement_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir_all(root.join("tests/corpus")).unwrap();
        std::fs::write(root.join("tests/corpus/a"), b"original").unwrap();
        let (parent, name) = parent_and_name(&root, Path::new("tests/corpus"), false).unwrap();
        let directory = opened(unsafe {
            openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                0,
            )
        })
        .unwrap();
        std::fs::rename(root.join("tests/corpus"), root.join("tests/previous")).unwrap();
        std::fs::create_dir(root.join("tests/corpus")).unwrap();
        std::fs::write(root.join("tests/corpus/a"), b"replacement").unwrap();
        assert_eq!(
            read_corpus_directory(&directory, 2, 32, 128).unwrap(),
            vec![b"original".to_vec()]
        );
        assert_eq!(
            read_corpus_snapshot(&root, Path::new("tests/corpus"), 2, 32, 128).unwrap(),
            vec![b"replacement".to_vec()]
        );
    }

    #[test]
    fn optional_missing_corpus_is_empty_but_symlinked_corpus_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let pinned = ProjectRoot::new(&root).unwrap();
        assert!(pinned
            .corpus(Path::new("tests/corpus"), 3, 10, 20)
            .unwrap()
            .is_empty());
        std::fs::create_dir(root.join("tests")).unwrap();
        let external = tmp.path().join("external");
        std::fs::create_dir(&external).unwrap();
        symlink(&external, root.join("tests/corpus")).unwrap();
        assert!(pinned.corpus(Path::new("tests/corpus"), 3, 10, 20).is_err());
    }

    #[test]
    fn corpus_snapshot_rejects_symlink_and_aggregate_overflow() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir_all(root.join("corpus")).unwrap();
        std::fs::write(root.join("corpus/a"), b"aaa").unwrap();
        std::fs::write(root.join("corpus/b"), b"bbb").unwrap();
        let corpus = Path::new("corpus");
        assert!(read_corpus_snapshot(&root, corpus, 1, 5, 20).is_err());
        assert!(read_corpus_snapshot(&root, corpus, 2, 5, 5).is_err());
        assert_eq!(
            read_corpus_snapshot(&root, corpus, 2, 5, 6).unwrap(),
            vec![b"aaa".to_vec(), b"bbb".to_vec()]
        );
        symlink(root.join("corpus/a"), root.join("corpus/alias")).unwrap();
        assert!(read_corpus_snapshot(&root, corpus, 3, 5, 20).is_err());
    }

    #[test]
    fn pinned_root_rejects_source_root_replacement() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir_all(root.join("corpus")).unwrap();
        std::fs::write(root.join("corpus/sample"), b"original").unwrap();
        let pinned = ProjectRoot::new(&root).unwrap();
        pinned.verify_path(&root).unwrap();
        std::fs::rename(&root, tmp.path().join("previous")).unwrap();
        std::fs::create_dir_all(root.join("corpus")).unwrap();
        std::fs::write(root.join("corpus/sample"), b"replacement").unwrap();
        assert!(pinned.verify_path(&root).is_err());
        assert_eq!(
            pinned.corpus(Path::new("corpus"), 2, 40, 100).unwrap(),
            vec![b"original".to_vec()]
        );
        let output = Path::new(".oreslang-test/failures/repro.bin");
        pinned.reproducer(output, b"original").unwrap();
        assert!(tmp.path().join("previous").join(output).is_file());
        assert!(!root.join(output).exists());
    }

    #[test]
    fn source_discovery_is_anchored_and_budgeted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir_all(root.join("src/nested")).unwrap();
        std::fs::write(root.join("src/nested/test_a.ores"), b"a").unwrap();
        std::fs::write(root.join("src/nested/test_b.ores"), b"b").unwrap();
        std::fs::create_dir(root.join("target")).unwrap();
        std::fs::write(root.join("target/ignore.ores"), b"hidden").unwrap();
        assert_eq!(
            discover_sources(&root, &["target"], 100, 2, 64).unwrap(),
            vec!["src/nested/test_a.ores", "src/nested/test_b.ores"]
        );
        assert!(discover_sources(&root, &["target"], 100, 1, 64).is_err());
        assert!(discover_sources(&root, &["target"], 1, 100, 64).is_err());
        assert!(discover_sources(&root, &["target"], 100, 100, 1).is_err());
        let external = tmp.path().join("external");
        std::fs::create_dir(&external).unwrap();
        symlink(&external, root.join("untrusted")).unwrap();
        assert!(discover_sources(&root, &["target"], 100, 100, 64).is_err());
    }

    #[test]
    fn traversal_fifo_and_oversize_are_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir(&root).unwrap();
        for name in ["../elsewhere", "/etc/passwd", "a/../../b"] {
            assert!(read_project_file(&root, Path::new(name), 10).is_err());
        }
        std::fs::write(root.join("large.bin"), b"long-data").unwrap();
        assert!(read_project_file(&root, Path::new("large.bin"), 3).is_err());
        let fifo = root.join("fifo");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_project_file(&root, Path::new("fifo"), 10).is_err());
    }
}
