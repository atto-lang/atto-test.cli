//! Native Oreslang test execution and reproducible byte-corpus fuzzing.
//! No Python runner, subprocess shell, or guest-authored success receipt.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
#[cfg(not(target_os = "linux"))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use super::fs_secure::ProjectRoot;
#[cfg(not(target_os = "linux"))]
struct ProjectRoot;
#[cfg(not(target_os = "linux"))]
impl ProjectRoot {
    fn new(_root: &Path) -> Result<Self, String> {
        Ok(Self)
    }
    fn verify_path(&self, _root: &Path) -> Result<(), String> {
        Ok(())
    }
}

const MAX_OUTPUT: u64 = 4_000_000;
const MAX_CASES: usize = 1_000_000;
const MAX_CORPUS_FILES: usize = 1024;
const MAX_CORPUS_BYTES: usize = 4 * 1024 * 1024;
const MAX_RETAINED_CASES: usize = 4096;
const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct Settings {
    root: PathBuf,
    fuzz: bool,
    security_fuzz: bool,
    fuzz_profile_selected: bool,
    race: bool,
    deadlock: bool,
    trace: Option<String>,
    logical: bool,
    model: Option<String>,
    max_schedules: u64,
    schedule_limit_selected: bool,
    seed: u64,
    cases: usize,
    timeout: Duration,
}

fn parse(args: &[OsString]) -> Result<Settings, String> {
    let mut out = Settings {
        root: PathBuf::from("."),
        fuzz: false,
        security_fuzz: false,
        fuzz_profile_selected: false,
        race: false,
        deadlock: false,
        trace: None,
        logical: false,
        model: None,
        max_schedules: 10000,
        schedule_limit_selected: false,
        seed: 1,
        cases: 100,
        timeout: Duration::from_secs(5),
    };
    let mut i = 0;
    while i < args.len() {
        let word = args[i].to_str().ok_or("non-UTF-8 CLI argument")?;
        let (key, inline) = word
            .split_once('=')
            .map_or((word, None), |(k, v)| (k, Some(v)));
        match key {
            "--fuzz" if inline.is_none() => out.fuzz = true,
            "--race" if inline.is_none() => out.race = true,
            "--deadlock" if inline.is_none() => out.deadlock = true,
            "--logical" if inline.is_none() => out.logical = true,
            "--root" | "--seed" | "--cases" | "--timeout" | "--fuzz-profile" | "--trace"
            | "--model" | "--max-schedules" => {
                let value = if let Some(v) = inline {
                    v.to_owned()
                } else {
                    i += 1;
                    args.get(i)
                        .and_then(|a| a.to_str())
                        .ok_or_else(|| format!("{key} needs a value"))?
                        .to_owned()
                };
                match key {
                    "--root" => out.root = PathBuf::from(value),
                    "--fuzz-profile" => {
                        out.fuzz_profile_selected = true;
                        out.security_fuzz = match value.as_str() {
                            "basic" => false,
                            "security" => true,
                            _ => return Err("fuzz profile must be basic or security".into()),
                        };
                    }
                    "--seed" => out.seed = value.parse::<u64>().map_err(|_| "invalid --seed")?,
                    "--cases" => {
                        out.cases = value.parse::<usize>().map_err(|_| "invalid --cases")?
                    }
                    "--timeout" => {
                        let t = value.parse::<f64>().map_err(|_| "invalid --timeout")?;
                        if !t.is_finite() || !(0.01..=600.0).contains(&t) {
                            return Err("timeout must be 0.01..600 seconds".into());
                        }
                        out.timeout = Duration::from_secs_f64(t);
                    }
                    "--trace" => out.trace = Some(value),
                    "--model" => out.model = Some(value),
                    "--max-schedules" => {
                        let n = value
                            .parse::<usize>()
                            .map_err(|_| "invalid --max-schedules")?;
                        if n == 0 || n > MAX_CASES {
                            return Err("invalid --max-schedules".into());
                        }
                        out.max_schedules = n as u64;
                        out.schedule_limit_selected = true;
                    }
                    _ => unreachable!(),
                }
            }
            _ => return Err(format!("unsupported test option: {word}")),
        }
        i += 1;
    }
    if out.cases == 0 || out.cases > MAX_CASES {
        return Err("cases must be 1..1000000".into());
    }
    if out.fuzz_profile_selected && !out.fuzz {
        return Err("--fuzz-profile requires --fuzz".into());
    }
    if out.fuzz
        && (out.race || out.deadlock || out.trace.is_some() || out.logical || out.model.is_some())
    {
        return Err("fuzz and race modes are exclusive".into());
    }
    if out.trace.is_some() && !out.race && !out.deadlock {
        return Err("--trace requires --race and/or --deadlock".into());
    }
    if out.logical && (!out.race || out.deadlock || out.trace.is_some() || out.model.is_none()) {
        return Err(
            "--logical requires --race --logical --model FILE without --deadlock/--trace".into(),
        );
    }
    if (out.model.is_some() || out.schedule_limit_selected) && !out.logical {
        return Err("--model/--max-schedules requires --logical".into());
    }
    Ok(out)
}

fn manifest(root: &Path) -> Result<toml::Table, String> {
    match super::test_manifest_name(root)? {
        None => Ok(toml::Table::new()),
        Some(name) => super::read_bounded_project(root, Path::new(name))?
            .parse::<toml::Table>()
            .map_err(|e| format!("invalid test manifest {name}: {e}")),
    }
}

fn section<'a>(config: &'a toml::Table, name: &str) -> Result<Option<&'a toml::Table>, String> {
    config
        .get(name)
        .map(|v| {
            v.as_table()
                .ok_or_else(|| format!("[{name}] must be a table"))
        })
        .transpose()
}

fn commands(params: &toml::Table, key: &str) -> Result<Vec<String>, String> {
    let value = params
        .get(key)
        .ok_or_else(|| format!("missing configured {key}"))?;
    let array = value
        .as_array()
        .ok_or_else(|| format!("{key} must be an argv array"))?;
    if array.is_empty() || array.len() > 64 {
        return Err(format!("{key} needs 1..64 arguments"));
    }
    array
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty() && !s.contains('\0'))
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} requires nonempty strings without NUL"))
        })
        .collect()
}

fn resolve_path_candidate(
    executable: &Path,
    project_root: &Path,
    search_path: &std::ffi::OsStr,
) -> Option<PathBuf> {
    std::env::split_paths(search_path)
        .map(|directory| {
            // The child runs with current_dir(project_root). A PATH entry
            // such as "." or "bin" must resolve against THAT directory,
            // not the CLI process's original working directory.
            let directory = if directory.is_absolute() {
                directory
            } else {
                project_root.join(directory)
            };
            directory.join(executable)
        })
        .find(|candidate| candidate.is_file())
}

fn sanitize_command(cmd: &[String], root: &Path) -> Result<Command, String> {
    let first = cmd.first().ok_or("empty command")?;
    let wrapper = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let program = if Path::new(first).components().count() > 1 {
        // Explicit relative executables stay inside the project root.
        if Path::new(first).is_absolute() {
            PathBuf::from(first)
        } else {
            let path = root.join(first);
            let canonical = path.canonicalize().map_err(|e| e.to_string())?;
            if !canonical.starts_with(root) {
                return Err("command escapes project root".into());
            }
            canonical
        }
    } else {
        PathBuf::from(first)
    };
    // Bare executable names resolve through PATH, including shell launchers.
    // Otherwise --fuzz [fuzz].command=["oreslang-test"] can recursively invoke
    // this CLI until host process/file budgets are exhausted.
    let candidate = if program.components().count() == 1 {
        std::env::var_os("PATH").and_then(|paths| resolve_path_candidate(&program, root, &paths))
    } else {
        Some(program.clone())
    };
    let forbidden = [
        wrapper,
        Path::new(env!("CARGO_MANIFEST_DIR")).join("bin/oreslang"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("bin/oreslang-test"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("bin/atto"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("bin/atto-test"),
    ];
    if candidate
        .as_ref()
        .and_then(|path| path.canonicalize().ok())
        .is_some_and(|actual| {
            forbidden
                .iter()
                .any(|path| path.canonicalize().ok().as_ref() == Some(&actual))
        })
    {
        return Err("test executable resolves to a Rust CLI wrapper (recursion refused)".into());
    }
    let mut c = Command::new(program);
    c.args(&cmd[1..]).current_dir(root).env_clear();
    for key in [
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "WINDIR",
    ] {
        if let Some(v) = std::env::var_os(key) {
            c.env(key, v);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.process_group(0); // Descendants can be terminated as a group on timeout.
    }
    Ok(c)
}

// A Unix guest runs in a process group distinct from the Rust launcher.
// Reap the group not only on timeout: an otherwise successful compiler
// command may leave background helpers writing into stale test captures.
#[cfg(unix)]
fn kill_guest_group(leader: u32) {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    if let Ok(pid) = i32::try_from(leader) {
        // Negative pid identifies the process group established at spawn.
        // This cannot contain descendants which deliberately call setsid().
        unsafe {
            kill(-pid, 9);
        }
    }
}

fn stop(child: &mut Child) {
    #[cfg(unix)]
    kill_guest_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Debug)]
struct ProcessResult {
    code: Option<i32>,
    timed_out: bool,
    output: String,
    stderr: String,
}

fn read_small(mut file: File) -> Result<String, String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_OUTPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_OUTPUT {
        return Err("test subprocess output limit exceeded".into());
    }
    String::from_utf8(bytes).map_err(|_| "test subprocess capture is not valid UTF-8".into())
}

fn invoke(
    mut command: Command,
    timeout: Duration,
    bytes: Option<&[u8]>,
    capture: bool,
) -> Result<ProcessResult, String> {
    let mut stdin_file = None;
    if let Some(input) = bytes {
        let mut f = tempfile::tempfile().map_err(|e| e.to_string())?;
        f.write_all(input)
            .and_then(|_| f.seek(SeekFrom::Start(0)).map(|_| ()))
            .map_err(|e| e.to_string())?;
        command.stdin(Stdio::from(f.try_clone().map_err(|e| e.to_string())?));
        stdin_file = Some(f);
    } else {
        command.stdin(Stdio::null());
    }
    let mut stdout = if capture {
        Some(tempfile::tempfile().map_err(|e| e.to_string())?)
    } else {
        None
    };
    let mut stderr = if capture {
        Some(tempfile::tempfile().map_err(|e| e.to_string())?)
    } else {
        None
    };
    if let Some(f) = &stdout {
        command.stdout(Stdio::from(f.try_clone().map_err(|e| e.to_string())?));
    } else {
        command.stdout(Stdio::null());
    }
    if let Some(f) = &stderr {
        command.stderr(Stdio::from(f.try_clone().map_err(|e| e.to_string())?));
    } else {
        command.stderr(Stdio::null());
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot spawn test command: {e}"))?;
    let start = Instant::now();
    let (code, timed_out) = loop {
        if capture {
            // A missing/unreadable capture must not silently disable the
            // output budget while the child continues executing.
            for output in [stdout.as_ref(), stderr.as_ref()].into_iter().flatten() {
                match output.metadata() {
                    Ok(meta) if meta.len() > MAX_OUTPUT => {
                        stop(&mut child);
                        return Err("test subprocess output limit exceeded".into());
                    }
                    Err(e) => {
                        stop(&mut child);
                        return Err(format!("cannot inspect test output capture: {e}"));
                    }
                    Ok(_) => {}
                }
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break (status.code(), false),
            Ok(None) if start.elapsed() >= timeout => {
                stop(&mut child);
                break (None, true);
            }
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(e) => {
                // Failure to inspect child status is inconclusive, but
                // must also terminate the spawned process group.
                stop(&mut child);
                return Err(format!("cannot inspect child process status: {e}"));
            }
        }
    };
    // The parent process exiting does not mean its process-group descendants
    // exited. Always terminate remaining group members before final reporting.
    // This is best-effort containment, not an OS sandbox or complete setsid
    // descendant tracking. On Windows this path needs a Job Object adapter.
    #[cfg(unix)]
    kill_guest_group(child.id());
    drop(stdin_file);
    Ok(ProcessResult {
        code,
        timed_out,
        output: match stdout.take() {
            Some(f) => read_small(f)?,
            None => String::new(),
        },
        stderr: match stderr.take() {
            Some(f) => read_small(f)?,
            None => String::new(),
        },
    })
}

#[derive(Debug, PartialEq, Eq)]
struct Counts {
    total: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
    filtered: usize,
}

fn test_receipt(output: &str) -> Result<Counts, String> {
    // Reject truncated and mixed-version machine records rather than
    // silently treating them as unrelated guest log output.
    if output
        .lines()
        .any(|line| line.starts_with("ORES_TEST") && !line.starts_with("ORES_TEST|"))
    {
        return Err("malformed or mixed-version ORES_TEST record".into());
    }
    let mut summaries = output
        .lines()
        .filter(|l| l.starts_with("ORES_TEST|SUMMARY|"));
    let summary = summaries.next().ok_or("missing ORES_TEST summary")?;
    if summaries.next().is_some() {
        return Err("duplicate ORES_TEST summaries".into());
    }
    let mut fields = BTreeMap::new();
    for pair in summary.split('|').skip(2) {
        let (key, value) = pair.split_once('=').ok_or("malformed ORES_TEST summary")?;
        if !["total", "passed", "failed", "skipped", "filtered"].contains(&key)
            || fields
                .insert(
                    key,
                    value.parse::<usize>().map_err(|_| "invalid test count")?,
                )
                .is_some()
        {
            return Err("unknown/duplicate test count".into());
        }
    }
    if fields.len() != 5 {
        return Err("incomplete test counts".into());
    }
    let c = Counts {
        total: fields["total"],
        passed: fields["passed"],
        failed: fields["failed"],
        skipped: fields["skipped"],
        filtered: fields["filtered"],
    };
    if c.total == 0 {
        // A missing test discovery path must not be reported as green.
        return Err("machine receipt executed zero tests".into());
    }
    if c.passed
        .checked_add(c.failed)
        .and_then(|n| n.checked_add(c.skipped))
        != Some(c.total)
    {
        return Err("inconsistent test counts".into());
    }
    if c.passed == 0 && c.failed == 0 {
        return Err("machine receipt has no executed cases (all skipped or filtered)".into());
    }
    let mut observed = [0usize; 3];
    let mut case_ids = BTreeSet::new();
    let mut saw_summary = false;
    for line in output.lines().filter(|l| l.starts_with("ORES_TEST|")) {
        if line == summary {
            saw_summary = true;
            continue;
        }
        // A terminal summary cannot precede case completions. Otherwise a
        // suite can pass even while a later callback writes case results.
        if saw_summary {
            return Err("ORES_TEST case emitted after terminal SUMMARY".into());
        }
        let (index, rest) = if let Some(rest) = line.strip_prefix("ORES_TEST|PASS|") {
            (0, rest)
        } else if let Some(rest) = line.strip_prefix("ORES_TEST|FAIL|") {
            (1, rest)
        } else if let Some(rest) = line.strip_prefix("ORES_TEST|SKIP|") {
            (2, rest)
        } else {
            return Err("unexpected ORES_TEST record".into());
        };
        // Optional message fields do not change the identity of a case.
        let id = rest.split('|').next().unwrap_or("");
        if id.trim().is_empty() {
            return Err("empty ORES_TEST case ID".into());
        }
        if !case_ids.insert(id) {
            return Err("duplicate ORES_TEST case ID".into());
        }
        observed[index] = observed[index]
            .checked_add(1)
            .ok_or("test case count overflow")?;
    }
    if observed != [c.passed, c.failed, c.skipped] {
        return Err("test receipt case count mismatch".into());
    }
    Ok(c)
}

// Use platform path components: discovered Windows paths contain backslashes.
fn is_native_test_path(path: &Path) -> bool {
    let base = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    return path.starts_with("tests")
        && matches!(path.extension().and_then(|ext| ext.to_str()), Some("atto" | "ores"))
        && (base.starts_with("test_")
            || base.ends_with("_test.atto")
            || base.ends_with("_test.ores"));
}

fn native(root: &Path, config: &toml::Table, timeout: Duration) -> Result<i32, String> {
    let params = section(config, "native")?;
    let lifecycle_v2 = match params.and_then(|p| p.get("receipt")) {
        None => false,
        Some(value) => match value.as_str() {
            Some("v1") => false,
            Some("lifecycle-v2") => true,
            _ => return Err("[native].receipt must be v1 or lifecycle-v2".into()),
        },
    };
    let mut files = Vec::new();
    if let Some(value) = params.and_then(|p| p.get("files")) {
        let arr = value
            .as_array()
            .ok_or("[native].files must be a source list")?;
        for value in arr {
            files.push(
                value
                    .as_str()
                    .ok_or("[native].files must contain strings")?
                    .to_owned(),
            );
        }
    } else {
        for name in super::discover(root)? {
            if is_native_test_path(Path::new(&name)) {
                files.push(name);
            }
        }
    }
    if files.is_empty() || files.len() > 512 {
        return Err("native tests require 1..512 source files".into());
    }
    let core = std::env::var("ORESLANG_BIN").unwrap_or_else(|_| "oreslang-core".into());
    let mut failures = 0;
    for name in files {
        let path = super::source_path(root, &name)?;
        let args = vec![core.clone(), path.to_string_lossy().into_owned()];
        let result = invoke(sanitize_command(&args, root)?, timeout, None, true)?;
        if result.stderr.contains("FATAL: ThreadSanitizer:") {
            return Err("ThreadSanitizer initialization failed; native run inconclusive".into());
        }
        if result.timed_out
            || result.code != Some(0)
            || sanitizer_finding(&result.stderr).is_some()
        {
            failures += 1;
            eprintln!(
                "FAIL {name}: timed_out={} exit={:?} {}",
                result.timed_out,
                result.code,
                result.stderr.chars().take(1000).collect::<String>()
            );
            continue;
        }
        let receipt = if lifecycle_v2 {
            super::lifecycle::verify(&result.output).map(|c| Counts {
                total: c.total,
                passed: c.passed,
                failed: c.failed,
                skipped: c.skipped,
                filtered: c.filtered,
            })
        } else {
            test_receipt(&result.output)
        };
        match receipt {
            Ok(counts) if counts.failed == 0 => println!(
                "PASS {name}: {} passed, {} skipped",
                counts.passed, counts.skipped
            ),
            Ok(counts) => {
                failures += 1;
                eprintln!("FAIL {name}: {} failed tests", counts.failed);
            }
            Err(e) => {
                failures += 1;
                eprintln!("FAIL {name}: invalid machine receipt: {e}");
            }
        }
    }
    Ok(i32::from(failures != 0))
}

#[derive(Clone)]
struct Rng {
    value: u64,
}
impl Rng {
    fn new(seed: u64) -> Self {
        Self { value: seed }
    }
    fn next(&mut self) -> u64 {
        self.value = self.value.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.value;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, upper: usize) -> usize {
        if upper == 0 {
            return 0;
        }
        (self.next() % upper as u64) as usize
    }
}
/// Reject path escapes and symlinked ancestors before accessing project-owned
/// input/output. This is a preflight boundary check, not an atomic openat2
/// guarantee against a concurrently malicious local filesystem writer.
#[cfg(not(target_os = "linux"))]
fn checked_project_path(root: &Path, name: &str) -> Result<PathBuf, String> {
    let relative = Path::new(name);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|c| {
            !matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return Err("unsafe project-relative path".into());
    }
    let mut result = root.to_path_buf();
    for part in relative.components() {
        result.push(part);
        match fs::symlink_metadata(&result) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "symlinked project path refused: {}",
                    result.display()
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(result)
}

// Bound bytes read from the opened stream as well as preflight file sizes.
// This limits allocation if a regular corpus file grows during ingestion.
#[cfg(any(test, not(target_os = "linux")))]
fn read_corpus_case(input: impl Read, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    input
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max_bytes {
        return Err("corpus case exceeds max_bytes while reading".into());
    }
    return Ok(bytes);
}

/// Bound reads using the *opened file descriptor*. Linux also denies a final
/// symlink and avoids FIFO blocking, even if a path changes after listing.
/// Ancestor components still require descriptor-relative openat/openat2.
#[cfg(not(target_os = "linux"))]
fn read_case_bounded(root: &Path, relative: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "linux")]
    {
        return super::fs_secure::read_project_file(root, relative, max_bytes);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let path = root.join(relative);
        let file = File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.len() > max_bytes as u64 {
            return Err("corpus item is not a bounded regular file".into());
        }
        return read_corpus_case(file, max_bytes);
    }
}

fn corpus(
    _root: &Path,
    params: &toml::Table,
    max_bytes: usize,
    _project: &ProjectRoot,
) -> Result<Vec<Vec<u8>>, String> {
    let name = params
        .get("corpus")
        .map(|v| v.as_str().ok_or("fuzz.corpus must be a relative path"))
        .transpose()?
        .unwrap_or("tests/corpus");
    #[cfg(not(target_os = "linux"))]
    let path = checked_project_path(_root, name)?;
    let mut cases = vec![vec![], vec![0], vec![255]];
    #[cfg(not(target_os = "linux"))]
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(cases),
        Err(e) => return Err(e.to_string()),
        Ok(m) if !m.is_dir() || m.file_type().is_symlink() => {
            return Err("unsafe corpus directory".into())
        }
        _ => {}
    }
    #[cfg(target_os = "linux")]
    {
        // Reuse the same project-_root descriptor as the future failure
        // artifact write. Absent optional corpora remain empty without a
        // pathname fallback into a different project _root.
        cases.extend(_project.corpus(
            Path::new(name),
            MAX_CORPUS_FILES,
            max_bytes,
            MAX_CORPUS_BYTES,
        )?);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut files = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let ty = entry.file_type().map_err(|e| e.to_string())?;
            if !ty.is_file() || ty.is_symlink() {
                return Err("corpus may contain only regular files".into());
            }
            files.push(Path::new(name).join(entry.file_name()));
            if files.len() > MAX_CORPUS_FILES {
                return Err("corpus file limit exceeded".into());
            }
        }
        files.sort();
        let mut consumed = 0usize;
        for relative in files {
            let bytes = read_case_bounded(_root, &relative, max_bytes)?;
            consumed = consumed
                .checked_add(bytes.len())
                .ok_or("corpus byte budget overflow")?;
            if consumed > MAX_CORPUS_BYTES {
                return Err("corpus byte budget exceeded".into());
            }
            cases.push(bytes);
        }
    }
    let mut unique = BTreeSet::new();
    cases.retain(|x| unique.insert(x.clone()));
    Ok(cases)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    Exit(i32),
    Sanitizer(&'static str),
}

fn sanitizer_finding(stderr: &str) -> Option<&'static str> {
    // Exact emitted prefixes minimize false positives while accepting
    // recoverable UBSan output and sanitizer-triggered abnormal termination.
    if stderr.contains("ERROR: AddressSanitizer:") {
        Some("ASan")
    } else if stderr.contains("LeakSanitizer: detected memory leaks") {
        Some("LSan")
    } else if stderr.contains("WARNING: ThreadSanitizer:")
        || stderr.contains("SUMMARY: ThreadSanitizer:")
    {
        Some("TSan")
    } else if stderr.contains("SUMMARY: UndefinedBehaviorSanitizer:")
        || stderr.contains("runtime error:")
    {
        Some("UBSan")
    } else {
        None
    }
}

fn classify(result: &ProcessResult) -> Result<Option<Failure>, String> {
    if result.timed_out {
        return Err("guest timed out; cannot classify fuzz failure".into());
    }
    if result.stderr.contains("FATAL: ThreadSanitizer:")
        || result.stderr.contains("ThreadSanitizer: unexpected memory mapping")
    {
        return Err("ThreadSanitizer failed to initialize; no race result is available".into());
    }
    // A sanitizer can abort via signal, leaving no numeric exit code.
    if let Some(kind) = sanitizer_finding(&result.stderr) {
        return Ok(Some(Failure::Sanitizer(kind)));
    }
    match result.code {
        Some(0) => Ok(None),
        Some(code) => Ok(Some(Failure::Exit(code))),
        None => Err("guest terminated abnormally without a sanitizer diagnostic".into()),
    }
}

fn candidate(
    cmd: &[String],
    root: &Path,
    timeout: Duration,
    bytes: &[u8],
    project: &ProjectRoot,
) -> Result<Option<Failure>, String> {
    project.verify_path(root)?;
    let result = invoke(sanitize_command(cmd, root)?, timeout, Some(bytes), true)?;
    project.verify_path(root)?;
    classify(&result)
}

fn write_failure(root: &Path, bytes: &[u8], _project: &ProjectRoot) -> Result<PathBuf, String> {
    // Stable filename is only a local deduplication hint, not a
    // cryptographic authentication or an attacker-resistant digest.
    let hash = bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    });
    let relative =
        Path::new(".oreslang-test/failures").join(format!("fuzz-{hash:016x}-{}.bin", bytes.len()));
    #[cfg(target_os = "linux")]
    {
        _project.verify_path(root)?;
        _project.reproducer(&relative, bytes)?;
        // Do not return a path that might now refer to a replaced root,
        // even though the write itself was anchored safely to our FD.
        _project.verify_path(root)?;
        return Ok(root.join(relative));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let folder = checked_project_path(root, ".oreslang-test/failures")?;
        fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
        checked_project_path(root, ".oreslang-test/failures")?;
        let path = root.join(&relative);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(bytes).map_err(|e| e.to_string())?;
                Ok(path)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
                if !meta.is_file()
                    || meta.file_type().is_symlink()
                    || read_case_bounded(root, &relative, bytes.len())? != bytes
                {
                    return Err("unsafe or colliding failure artifact".into());
                }
                Ok(path)
            }
            Err(e) => Err(e.to_string()),
        }
    }
}
// Retention is optional mutation feedback, not execution coverage. Once either
// budget is full, keep executing cases without growing the retained pool.
fn retain_sample(samples: &mut Vec<Vec<u8>>, retained_bytes: &mut usize, case: Vec<u8>) -> bool {
    let Some(next) = retained_bytes.checked_add(case.len()) else {
        return false;
    };
    if samples.len() >= MAX_RETAINED_CASES || next > MAX_RETAINED_BYTES {
        return false;
    }
    samples.push(case);
    *retained_bytes = next;
    return true;
}

fn fuzz(root: &Path, config: &toml::Table, settings: &Settings) -> Result<i32, String> {
    let params = section(config, "fuzz")?.ok_or("missing [fuzz] section")?;
    let cmd = commands(params, "command")?;
    let max_bytes = match params.get("max_bytes") {
        Some(v) => v.as_integer().ok_or("invalid fuzz.max_bytes")?,
        None => 256,
    };
    if !(1..=65_536).contains(&max_bytes) {
        return Err("fuzz.max_bytes must be 1..65536".into());
    }
    let project = ProjectRoot::new(root)?;
    let mut samples = corpus(root, params, max_bytes as usize, &project)?;
    project.verify_path(root)?;
    if settings.security_fuzz {
        // Adversarial inputs are *stimuli*, never standalone proof of a bug.
        // Put these before the ordinary corpus so a bounded --cases also
        // exercises the security profile with a deterministic order.
        let mut security = vec![
            b"../".repeat(10),
            b"..%2f..%2f".to_vec(),
            b"%00%00".to_vec(),
            vec![0xff, 0xfe, 0xc0, 0xaf],
            b"\\u0000\\uD800".to_vec(),
            b"<script>alert(1)</script>".to_vec(),
            b"' OR 1=1 --".to_vec(),
            b"../../etc/passwd".to_vec(),
            vec![b'A'; max_bytes as usize],
            vec![b'['; max_bytes as usize],
        ];
        for sample in &mut security {
            sample.truncate(max_bytes as usize);
        }
        security.retain(|s| !s.is_empty());
        security.extend(samples);
        let mut seen = BTreeSet::new();
        security.retain(|sample| seen.insert(sample.clone()));
        samples = security;
    }
    let mut retained_bytes = samples.iter().try_fold(0usize, |total, sample| {
        total
            .checked_add(sample.len())
            .ok_or("retained fuzz byte count overflow")
    })?;
    if samples.len() > MAX_RETAINED_CASES || retained_bytes > MAX_RETAINED_BYTES {
        return Err("initial fuzz pool exceeds retention budgets".into());
    }
    let mut rng = Rng::new(settings.seed);
    for i in 0..settings.cases {
        let case = if i < samples.len() {
            samples[i].clone()
        } else {
            let base = &samples[rng.range(samples.len())];
            let mut bytes = base.clone();
            if bytes.is_empty() || rng.range(4) == 0 {
                bytes = vec![0; rng.range(max_bytes as usize + 1)];
                for x in &mut bytes {
                    *x = rng.next() as u8;
                }
            } else {
                for _ in 0..(1 + rng.range(4)) {
                    let idx = rng.range(bytes.len());
                    bytes[idx] ^= rng.next() as u8;
                }
                bytes.truncate(max_bytes as usize);
            }
            bytes
        };
        if let Some(code) = candidate(&cmd, root, settings.timeout, &case, &project)? {
            for _ in 0..2 {
                if candidate(&cmd, root, settings.timeout, &case, &project)? != Some(code) {
                    eprintln!(
                        "FUZZ FLAKY seed={} iteration={i}: no stable reproduction",
                        settings.seed
                    );
                    return Ok(2);
                }
            }
            let mut shrunk = case.clone();
            let mut budget = 200usize;
            let mut granularity = 2usize;
            while !shrunk.is_empty() && budget > 0 {
                let chunk = shrunk.len().div_ceil(granularity);
                let mut shorter = false;
                for start in (0..shrunk.len()).step_by(chunk.max(1)) {
                    if budget == 0 {
                        break;
                    }
                    budget -= 1;
                    let mut reduced = shrunk[..start].to_vec();
                    reduced.extend_from_slice(&shrunk[(start + chunk).min(shrunk.len())..]);
                    if candidate(&cmd, root, settings.timeout, &reduced, &project)? == Some(code) {
                        shrunk = reduced;
                        granularity = 2;
                        shorter = true;
                        break;
                    }
                }
                if !shorter {
                    if granularity >= shrunk.len() {
                        break;
                    }
                    granularity = (granularity * 2).min(shrunk.len());
                }
            }
            for _ in 0..2 {
                if candidate(&cmd, root, settings.timeout, &shrunk, &project)? != Some(code) {
                    eprintln!("FUZZ FLAKY after minimization; preserving original failure");
                    shrunk = case.clone();
                    break;
                }
            }
            let saved = write_failure(root, &shrunk, &project)?;
            println!(
                "FUZZ FAILURE seed={} iteration={i} finding={code:?} initial={} minimized={} path={}",
                settings.seed,
                case.len(),
                shrunk.len(),
                saved.display()
            );
            return Ok(1);
        }
        retain_sample(&mut samples, &mut retained_bytes, case);
    }
    println!(
        "FUZZ PASS cases={} seed={} (observed inputs only)",
        settings.cases, settings.seed
    );
    Ok(0)
}

pub fn run(args: &[OsString]) -> i32 {
    let result = (|| -> Result<i32, String> {
        let settings = parse(args)?;
        let root = settings.root.canonicalize().map_err(|e| e.to_string())?;
        if !root.is_dir() {
            return Err("project root must be a directory".into());
        }
        let cfg = manifest(&root)?;
        if settings.deadlock {
            if settings.logical || settings.model.is_some() {
                return Err(
                    "combined deadlock and logical-model checking is not implemented".into(),
                );
            }
            if let Some(name) = &settings.trace {
                let deadlocks = super::deadlock::offline(&root, name)?;
                if settings.race {
                    let races = super::race_offline::offline(&root, name)?;
                    return Ok(deadlocks.max(races));
                }
                return Ok(deadlocks);
            }
            return Err("runtime --deadlock is INCONCLUSIVE without an explicit offline --trace; trusted live event capture is unavailable".into());
        }
        if settings.race {
            if settings.logical {
                return super::logical::offline(
                    &root,
                    settings.model.as_deref().ok_or("missing logical model")?,
                    settings.max_schedules,
                );
            }
            if let Some(path) = &settings.trace {
                return super::race_offline::offline(&root, path);
            }
            return Err("runtime --race is INCONCLUSIVE: trusted backend trace admission is not implemented; use --trace for explicitly offline Rust analysis".into());
        }
        if settings.fuzz {
            fuzz(&root, &cfg, &settings)
        } else {
            native(&root, &cfg, settings.timeout)
        }
    })();
    match result {
        Ok(code) => code,
        Err(message) => {
            eprintln!("atto test: {message}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizer_verdicts_survive_signal_abort_and_reduction_cannot_change_failure_kind() {
        let output = ProcessResult {
            code: None,
            timed_out: false,
            output: String::new(),
            stderr: "ERROR: AddressSanitizer: heap-use-after-free".into(),
        };
        assert_eq!(classify(&output), Ok(Some(Failure::Sanitizer("ASan"))));
        let exit = ProcessResult {
            code: Some(86),
            timed_out: false,
            output: String::new(),
            stderr: String::new(),
        };
        assert_eq!(classify(&exit), Ok(Some(Failure::Exit(86))));
        assert_ne!(classify(&output), classify(&exit));
        let init = ProcessResult {
            code: Some(66),
            timed_out: false,
            output: String::new(),
            stderr: "FATAL: ThreadSanitizer: unexpected memory mapping".into(),
        };
        assert!(classify(&init).is_err());
    }

    #[test]
    fn machine_receipts_require_executed_cases() {
        for output in [
            "ORES_TEST|SKIP|suite/disabled|reason\nORES_TEST|SUMMARY|total=1|passed=0|failed=0|skipped=1|filtered=0\n",
            "ORES_TEST|SUMMARY|total=0|passed=0|failed=0|skipped=0|filtered=3\n",
        ] {
            assert!(test_receipt(output).is_err());
        }
    }

    #[test]
    fn machine_receipts_reject_duplicate_ids_even_across_statuses() {
        for output in [
            "ORES_TEST|PASS|suite/case|first\nORES_TEST|PASS|suite/case|second\nORES_TEST|SUMMARY|total=2|passed=2|failed=0|skipped=0|filtered=0\n",
            "ORES_TEST|PASS|suite/case|\nORES_TEST|SKIP|suite/case|reason\nORES_TEST|SUMMARY|total=2|passed=1|failed=0|skipped=1|filtered=0\n",
        ] {
            assert!(test_receipt(output).is_err());
        }
    }

    #[test]
    fn machine_receipts_reject_empty_case_ids() {
        for id in ["", " ", "\t"] {
            let output = format!("ORES_TEST|PASS|{id}|message\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\n");
            assert!(test_receipt(&output).is_err());
        }
    }

    #[test]
    fn legacy_receipts_reject_late_case_events_and_truncated_marker_lines() {
        let summary = "ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\n";
        let pass = "ORES_TEST|PASS|suite/sync\n";
        assert!(test_receipt(&format!("{pass}{summary}")).is_ok());
        for malformed in [
            format!("{summary}{pass}"),
            format!("{pass}{summary}ORES_TEST\n"),
            format!("{pass}{summary}ORES_TEST_V2\n"),
            format!("{pass}{summary}ORES_TEST_V2|RUN_BEGIN|2\n"),
            format!("ORES_TEST|PASS|suite/other\n{pass}{summary}"),
            format!("{pass}{summary}ORES_TEST|FAIL|late\n"),
        ] {
            assert!(
                test_receipt(&malformed).is_err(),
                "accepted malformed v1 receipt: {malformed}"
            );
        }
    }

    #[test]
    fn machine_receipts_preserve_distinct_case_outcomes_and_messages() {
        let output = "ORES_TEST|PASS|suite/ok|message|extra\nORES_TEST|FAIL|suite/bad|reason\nORES_TEST|SKIP|suite/off|reason\nORES_TEST|SUMMARY|total=3|passed=1|failed=1|skipped=1|filtered=2\n";
        assert_eq!(
            test_receipt(output),
            Ok(Counts {
                total: 3,
                passed: 1,
                failed: 1,
                skipped: 1,
                filtered: 2,
            })
        );
    }

    #[test]
    fn retained_fuzz_payload_accepts_exact_byte_limit_then_stops_growing() {
        let mut samples = vec![vec![7; MAX_RETAINED_BYTES - 1]];
        let mut bytes = samples[0].len();
        assert!(retain_sample(&mut samples, &mut bytes, vec![8]));
        assert_eq!(bytes, MAX_RETAINED_BYTES);
        assert!(!retain_sample(&mut samples, &mut bytes, vec![9]));
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0][0], 7);
        assert_eq!(samples[1], vec![8]);
        assert_eq!(bytes, samples.iter().map(Vec::len).sum::<usize>());
    }

    #[test]
    fn retained_fuzz_pool_bounds_empty_cases_by_count() {
        let mut samples = vec![Vec::new(); MAX_RETAINED_CASES - 1];
        let mut bytes = 0;
        assert!(retain_sample(&mut samples, &mut bytes, Vec::new()));
        assert!(!retain_sample(&mut samples, &mut bytes, Vec::new()));
        assert_eq!(samples.len(), MAX_RETAINED_CASES);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn retained_fuzz_pool_rejects_oversized_case_without_changing_state() {
        let mut samples = vec![vec![1]];
        let mut bytes = 1;
        assert!(!retain_sample(
            &mut samples,
            &mut bytes,
            vec![2; MAX_RETAINED_BYTES]
        ));
        assert_eq!(samples, vec![vec![1]]);
        assert_eq!(bytes, 1);
    }

    #[test]
    fn native_discovery_uses_platform_path_components() {
        assert!(is_native_test_path(
            &Path::new("tests").join("test_one.ores")
        ));
        assert!(is_native_test_path(
            &Path::new("tests").join("nested").join("two_test.ores")
        ));
        for path in [
            PathBuf::from("test_one.ores"),
            Path::new("tests-other").join("test_one.ores"),
            Path::new("src").join("tests").join("test_one.ores"),
            Path::new("tests").join("ordinary.ores"),
            Path::new("tests").join("test_one.txt"),
        ] {
            assert!(!is_native_test_path(&path), "{path:?}");
        }
    }

    #[test]
    fn native_discovery_filters_real_nested_files_on_each_host_os() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("tests").join("nested")).unwrap();
        fs::create_dir(root.path().join("tests-other")).unwrap();
        for path in [
            Path::new("tests").join("test_one.ores"),
            Path::new("tests").join("nested").join("two_test.ores"),
            Path::new("tests").join("ordinary.ores"),
            Path::new("tests-other").join("test_ignored.ores"),
        ] {
            fs::write(root.path().join(path), "").unwrap();
        }
        let selected: Vec<_> = super::super::discover(root.path())
            .unwrap()
            .into_iter()
            .filter(|name| is_native_test_path(Path::new(name)))
            .collect();
        assert_eq!(selected.len(), 2);
        assert!(selected
            .iter()
            .any(|name| Path::new(name).ends_with("test_one.ores")));
        assert!(selected
            .iter()
            .any(|name| Path::new(name).ends_with("two_test.ores")));
    }

    #[test]
    fn corpus_stream_accepts_empty_and_exact_limit_binary_input() {
        assert_eq!(read_corpus_case(&b""[..], 4), Ok(Vec::new()));
        assert_eq!(
            read_corpus_case(&[0, 255, 128, 1][..], 4),
            Ok(vec![0, 255, 128, 1])
        );
    }

    #[test]
    fn corpus_stream_stops_after_one_byte_beyond_limit() {
        let mut input = std::io::Cursor::new(vec![7; 100]);
        assert!(read_corpus_case(&mut input, 8).is_err());
        assert_eq!(input.position(), 9);
        // A stream which keeps producing data must also terminate at the cap.
        assert!(read_corpus_case(std::io::repeat(1), 8).is_err());
    }

    #[test]
    fn corpus_stream_propagates_read_errors() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "denied",
                ));
            }
        }
        assert!(read_corpus_case(Broken, 8).is_err());
    }

    #[test]
    fn corpus_aggregate_budget_is_enforced_before_fuzz_execution() {
        let root = tempfile::tempdir().unwrap();
        let seeds = root.path().join("seeds");
        fs::create_dir(&seeds).unwrap();
        let seed = vec![3; 65_536];
        for n in 0..65 {
            fs::write(seeds.join(format!("{n:03}.bin")), &seed).unwrap();
        }
        let mut params = toml::Table::new();
        params.insert("corpus".into(), toml::Value::String("seeds".into()));
        let expected = if cfg!(target_os = "linux") {
            "corpus aggregate budget exhausted"
        } else {
            "corpus byte budget exceeded"
        };
        assert_eq!(
            corpus(
                root.path(),
                &params,
                seed.len(),
                &ProjectRoot::new(root.path()).unwrap()
            )
            .unwrap_err(),
            expected
        );
    }

    #[test]
    fn rejects_unsupported_race_without_python_fallback() {
        assert_eq!(run(&["--race".into()]), 2);
        assert_eq!(run(&["--race".into(), "--logical".into()]), 2);
        assert!(parse(&["--model".into(), "x.json".into()]).is_err());
    }
    #[test]
    fn rejects_missing_arguments_and_invalid_timeouts() {
        assert!(parse(&["--seed".into()]).is_err());
        assert!(parse(&["--timeout=NaN".into()]).is_err());
        assert!(parse(&["--cases=0".into()]).is_err());
        assert!(parse(&["--fuzz".into(), "--race".into()]).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn timeout_terminates_a_dedicated_process_group() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("sleep 5");
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        let start = Instant::now();
        let result = invoke(command, Duration::from_millis(100), None, true).unwrap();
        assert!(result.timed_out);
        assert!(result.code.is_none());
        assert!(start.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn stable_seed_reproducibility() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next(), b.next());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn opened_corpus_descriptor_denies_symlinks_and_oversize() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("case");
        std::fs::write(&source, b"abc").unwrap();
        let relative = Path::new("case");
        assert_eq!(
            crate::fs_secure::read_project_file(dir.path(), relative, 3).unwrap(),
            b"abc"
        );
        assert!(crate::fs_secure::read_project_file(dir.path(), relative, 2).is_err());
        let alias = dir.path().join("alias");
        symlink(&source, &alias).unwrap();
        assert!(crate::fs_secure::read_project_file(dir.path(), Path::new("alias"), 3).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn fuzz_failure_artifact_collision_denies_symlink_alias() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let payload = b"reproducible-crash";
        let saved = write_failure(&root, payload, &ProjectRoot::new(&root).unwrap()).unwrap();
        assert_eq!(
            write_failure(&root, payload, &ProjectRoot::new(&root).unwrap()).unwrap(),
            saved
        );
        std::fs::remove_file(&saved).unwrap();
        let external = root.join("external.bin");
        std::fs::write(&external, payload).unwrap();
        symlink(&external, &saved).unwrap();
        assert!(write_failure(&root, payload, &ProjectRoot::new(&root).unwrap()).is_err());
    }

    #[test]
    fn relative_path_lookup_uses_guest_project_root_not_caller_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(project.join("bin")).unwrap();
        let file = project.join("bin/oreslang-test");
        std::fs::write(&file, b"dummy").unwrap();
        let path = std::ffi::OsStr::new("bin");
        assert_eq!(
            resolve_path_candidate(Path::new("oreslang-test"), &project, path),
            Some(file)
        );
    }

    #[test]
    fn machine_receipts_are_strict() {
        let good = "ORES_TEST|PASS|one\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\n";
        assert_eq!(
            test_receipt(good),
            Ok(Counts {
                total: 1,
                passed: 1,
                failed: 0,
                skipped: 0,
                filtered: 0
            })
        );
        assert!(test_receipt(&format!("{good}{good}")).is_err());
        assert!(test_receipt(
            "ORES_TEST|SUMMARY|total=0|passed=0|passed=0|failed=0|skipped=0|filtered=0"
        )
        .is_err());
        assert!(
            test_receipt("ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0")
                .is_err()
        );
        assert!(
            test_receipt("ORES_TEST|SUMMARY|total=0|passed=0|failed=0|skipped=0|filtered=0")
                .is_err()
        );
        assert!(test_receipt(
            "ORES_TEST|PASS|one\nORES_TEST|SUMMARY|total=2|passed=1|failed=0|skipped=0|filtered=0"
        )
        .is_err());
    }
}
