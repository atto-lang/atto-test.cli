//! Linux project-root anchored file operations.
//!
//! Every existing ancestor is opened with O_DIRECTORY | O_NOFOLLOW, and
//! the final file with O_NOFOLLOW | O_NONBLOCK. This prevents symlink
//! substitution at any traversed component, including during input reads
//! and fuzz reproducer creation. It does NOT constrain a test subprocess,
//! protect a root directory renamed by a hostile concurrent process,
//! or substitute for an OS sandbox.
#![cfg(target_os = "linux")]

use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};

const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_CREAT: i32 = 0o100;
const O_EXCL: i32 = 0o200;
const O_NONBLOCK: i32 = 0o4000;
const O_DIRECTORY: i32 = 0o200000;
const O_NOFOLLOW: i32 = 0o400000;
const O_CLOEXEC: i32 = 0o2000000;

unsafe extern "C" {
    fn openat(dirfd: i32, path: *const std::ffi::c_char, flags: i32, mode: u32) -> i32;
    fn mkdirat(dirfd: i32, path: *const std::ffi::c_char, mode: u32) -> i32;
}

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

fn opened(fd: i32) -> Result<File, String> {
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // openat transfers ownership of a fresh descriptor to this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn root_fd(root: &Path) -> Result<File, String> {
    let file = OpenOptions::new().read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        .open(root).map_err(|e| format!("cannot open project root: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_dir() {
        return Err("project root is not a directory".into());
    }
    Ok(file)
}

fn step_dir(current: &File, component: &OsStr, create: bool) -> Result<File, String> {
    let name = c_name(component)?;
    if create {
        let status = unsafe { mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) };
        if status < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
            return Err(format!("cannot create project output directory: {}", std::io::Error::last_os_error()));
        }
    }
    opened(unsafe {
        openat(current.as_raw_fd(), name.as_ptr(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0)
    }).map_err(|e| format!("unsafe or missing project path component: {e}"))
}

fn parent_and_name(root: &Path, relative: &Path, create_dirs: bool)
    -> Result<(File, CString), String>
{
    let parts = components(relative)?;
    let mut current = root_fd(root)?;
    for component in &parts[..parts.len() - 1] {
        current = step_dir(&current, component, create_dirs)?;
    }
    let name = c_name(parts[parts.len() - 1])?;
    Ok((current, name))
}

fn open_input(root: &Path, relative: &Path) -> Result<File, String> {
    let (parent, name) = parent_and_name(root, relative, false)?;
    opened(unsafe {
        openat(parent.as_raw_fd(), name.as_ptr(),
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0)
    }).map_err(|e| format!("unsafe project input: {e}"))
}

pub fn read_project_file(root: &Path, relative: &Path, max_bytes: usize)
    -> Result<Vec<u8>, String>
{
    let mut file = open_input(root, relative)?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > max_bytes as u64 {
        return Err("input is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > max_bytes {
        return Err("input grew beyond its read budget".into());
    }
    Ok(bytes)
}

/// Create an immutable fuzz reproducer only if absent, or compare an existing
/// bounded regular file at the securely opened parent. No path-based
/// read-after-check, symlink following, or truncation.
pub fn create_or_match(root: &Path, relative: &Path, expected: &[u8])
    -> Result<(), String>
{
    let (parent, name) = parent_and_name(root, relative, true)?;
    let fd = unsafe {
        openat(parent.as_raw_fd(), name.as_ptr(),
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    };
    if fd >= 0 {
        let mut file = opened(fd)?;
        file.write_all(expected).map_err(|e| format!("cannot write reproducer: {e}"))?;
        file.sync_all().map_err(|e| format!("cannot sync reproducer: {e}"))?;
        return Ok(());
    }
    if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
        return Err(format!("cannot create reproducer: {}", std::io::Error::last_os_error()));
    }
    let mut existing = opened(unsafe {
        openat(parent.as_raw_fd(), name.as_ptr(),
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0)
    })?;
    let metadata = existing.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() != expected.len() as u64 {
        return Err("colliding reproducer is not the same bounded file".into());
    }
    let mut bytes = Vec::new();
    existing.take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes != expected {
        return Err("fuzz reproducer collision or hostile content".into());
    }
    Ok(())
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
        assert_eq!(read_project_file(&root, Path::new("inputs/safe.ores"), 4).unwrap(), b"safe");

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
        create_or_match(&root, output, b"abc").unwrap();
        create_or_match(&root, output, b"abc").unwrap();
        assert!(create_or_match(&root, output, b"bad").is_err());
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::rename(root.join(".oreslang-test"), root.join(".renamed")).unwrap();
        symlink(&outside, root.join(".oreslang-test")).unwrap();
        assert!(create_or_match(&root, output, b"abc").is_err());
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
        use std::os::unix::ffi::OsStrExt;
        unsafe extern "C" { fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32; }
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_project_file(&root, Path::new("fifo"), 10).is_err());
    }
}
