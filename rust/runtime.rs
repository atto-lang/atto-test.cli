//! Native Oreslang test execution and reproducible byte-corpus fuzzing.
//! No Python runner, subprocess shell, or guest-authored success receipt.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
#[cfg(not(target_os = "linux"))]
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_OUTPUT: u64 = 4_000_000;
const MAX_CASES: usize = 1_000_000;
const MAX_CORPUS_FILES: usize = 1024;
const MAX_CORPUS_BYTES: usize = 4 * 1024 * 1024;

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
        root: PathBuf::from("."), fuzz: false, security_fuzz: false,
        fuzz_profile_selected: false, race: false, deadlock: false,
        trace: None, logical: false, model: None,
        max_schedules: 10000, schedule_limit_selected: false,
        seed: 1, cases: 100, timeout: Duration::from_secs(5),
    };
    let mut i = 0;
    while i < args.len() {
        let word = args[i].to_str().ok_or("non-UTF-8 CLI argument")?;
        let (key, inline) = word.split_once('=').map_or((word, None), |(k,v)| (k, Some(v)));
        match key {
            "--fuzz" if inline.is_none() => out.fuzz = true,
            "--race" if inline.is_none() => out.race = true,
            "--deadlock" if inline.is_none() => out.deadlock = true,
            "--logical" if inline.is_none() => out.logical = true,
            "--root" | "--seed" | "--cases" | "--timeout" | "--fuzz-profile" | "--trace" | "--model" | "--max-schedules" => {
                let value = if let Some(v) = inline { v.to_owned() } else {
                    i += 1;
                    args.get(i).and_then(|a| a.to_str()).ok_or_else(|| format!("{key} needs a value"))?.to_owned()
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
                    },
                    "--seed" => out.seed = value.parse::<u64>().map_err(|_| "invalid --seed")?,
                    "--cases" => out.cases = value.parse::<usize>().map_err(|_| "invalid --cases")?,
                    "--timeout" => {
                        let t = value.parse::<f64>().map_err(|_| "invalid --timeout")?;
                        if !t.is_finite() || !(0.01..=600.0).contains(&t) { return Err("timeout must be 0.01..600 seconds".into()); }
                        out.timeout = Duration::from_secs_f64(t);
                    },
                    "--trace" => out.trace = Some(value),
                    "--model" => out.model = Some(value),
                    "--max-schedules" => {
                        let n = value.parse::<usize>().map_err(|_| "invalid --max-schedules")?;
                        if n == 0 || n > MAX_CASES { return Err("invalid --max-schedules".into()); }
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
    if out.cases == 0 || out.cases > MAX_CASES { return Err("cases must be 1..1000000".into()); }
    if out.fuzz_profile_selected && !out.fuzz {
        return Err("--fuzz-profile requires --fuzz".into());
    }
    if out.fuzz && (out.race || out.deadlock || out.trace.is_some() || out.logical || out.model.is_some()) {
        return Err("fuzz and race modes are exclusive".into());
    }
    if out.trace.is_some() && !out.race && !out.deadlock {
        return Err("--trace requires --race and/or --deadlock".into());
    }
    if out.logical && (!out.race || out.deadlock || out.trace.is_some() || out.model.is_none()) {
        return Err("--logical requires --race --logical --model FILE without --deadlock/--trace".into());
    }
    if (out.model.is_some() || out.schedule_limit_selected) && !out.logical {
        return Err("--model/--max-schedules requires --logical".into());
    }
    Ok(out)
}

fn manifest(root: &Path) -> Result<toml::Table, String> {
    let path = root.join("oreslang-test.toml");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(toml::Table::new()),
        Err(e) => Err(e.to_string()),
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() { return Err("unsafe test manifest file".into()); }
            super::read_bounded_project(root, Path::new("oreslang-test.toml"))?.parse::<toml::Table>().map_err(|e| format!("invalid test manifest: {e}"))
        }
    }
}

fn section<'a>(config: &'a toml::Table, name: &str) -> Result<Option<&'a toml::Table>, String> {
    config.get(name).map(|v| v.as_table().ok_or_else(|| format!("[{name}] must be a table"))).transpose()
}

fn commands(params: &toml::Table, key: &str) -> Result<Vec<String>, String> {
    let value = params.get(key).ok_or_else(|| format!("missing configured {key}"))?;
    let array = value.as_array().ok_or_else(|| format!("{key} must be an argv array"))?;
    if array.is_empty() || array.len() > 64 { return Err(format!("{key} needs 1..64 arguments")); }
    array.iter().map(|v| v.as_str().filter(|s| !s.is_empty() && !s.contains('\0')).map(str::to_owned)
            .ok_or_else(|| format!("{key} requires nonempty strings without NUL"))).collect()
}

fn sanitize_command(cmd: &[String], root: &Path) -> Result<Command, String> {
    let first = cmd.first().ok_or("empty command")?;
    let wrapper = std::env::current_exe().map_err(|e| e.to_string())?.canonicalize().map_err(|e| e.to_string())?;
    let program = if Path::new(first).components().count() > 1 {
        // Explicit relative executables stay inside the project root.
        if Path::new(first).is_absolute() { PathBuf::from(first) } else {
            let path = root.join(first);
            let canonical = path.canonicalize().map_err(|e| e.to_string())?;
            if !canonical.starts_with(root) { return Err("command escapes project root".into()); }
            canonical
        }
    } else {
        PathBuf::from(first)
    };
    // Bare executable names resolve through PATH, including shell launchers.
    // Otherwise --fuzz [fuzz].command=["oreslang-test"] can recursively invoke
    // this CLI until host process/file budgets are exhausted.
    let candidate = if program.components().count() == 1 {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|directory| directory.join(&program))
                .find(|path| path.is_file())
        })
    } else {
        Some(program.clone())
    };
    let forbidden = [
        wrapper,
        Path::new(env!("CARGO_MANIFEST_DIR")).join("bin/oreslang"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("bin/oreslang-test"),
    ];
    if candidate.as_ref().and_then(|path| path.canonicalize().ok())
        .is_some_and(|actual| forbidden.iter().any(|path| {
            path.canonicalize().ok().as_ref() == Some(&actual)
        }))
    {
        return Err("test executable resolves to a Rust CLI wrapper (recursion refused)".into());
    }
    let mut c = Command::new(program);
    c.args(&cmd[1..]).current_dir(root).env_clear();
    for key in ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR"] {
        if let Some(v) = std::env::var_os(key) { c.env(key, v); }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.process_group(0); // Descendants can be terminated as a group on timeout.
    }
    Ok(c)
}

fn stop(child: &mut Child) {
    #[cfg(unix)]
    {
        unsafe extern "C" { fn kill(pid: i32, signal: i32) -> i32; }
        if let Ok(pid) = i32::try_from(child.id()) {
            // Negative pid identifies the private process group established at spawn.
            unsafe { kill(-pid, 9); }
        }
    }
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
    file.take(MAX_OUTPUT + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_OUTPUT { return Err("test subprocess output limit exceeded".into()); }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn invoke(mut command: Command, timeout: Duration, bytes: Option<&[u8]>, capture: bool)
    -> Result<ProcessResult, String>
{
    let mut stdin_file = None;
    if let Some(input) = bytes {
        let mut f = tempfile::tempfile().map_err(|e| e.to_string())?;
        f.write_all(input).and_then(|_| f.seek(SeekFrom::Start(0)).map(|_| ())).map_err(|e| e.to_string())?;
        command.stdin(Stdio::from(f.try_clone().map_err(|e| e.to_string())?));
        stdin_file = Some(f);
    } else {
        command.stdin(Stdio::null());
    }
    let mut stdout = if capture { Some(tempfile::tempfile().map_err(|e| e.to_string())?) } else { None };
    let mut stderr = if capture { Some(tempfile::tempfile().map_err(|e| e.to_string())?) } else { None };
    if let Some(f) = &stdout { command.stdout(Stdio::from(f.try_clone().map_err(|e| e.to_string())?)); }
    else { command.stdout(Stdio::null()); }
    if let Some(f) = &stderr { command.stderr(Stdio::from(f.try_clone().map_err(|e| e.to_string())?)); }
    else { command.stderr(Stdio::null()); }
    let mut child = command.spawn().map_err(|e| format!("cannot spawn test command: {e}"))?;
    let start = Instant::now();
    let (code, timed_out) = loop {
        if capture && (stdout.as_ref().is_some_and(|f| f.metadata().is_ok_and(|m| m.len() > MAX_OUTPUT))
            || stderr.as_ref().is_some_and(|f| f.metadata().is_ok_and(|m| m.len() > MAX_OUTPUT)))
        {
            stop(&mut child);
            return Err("test subprocess output limit exceeded".into());
        }
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => break (status.code(), false),
            None if start.elapsed() >= timeout => { stop(&mut child); break (None, true); }
            None => thread::sleep(Duration::from_millis(5)),
        }
    };
    drop(stdin_file);
    Ok(ProcessResult {
        code, timed_out,
        output: match stdout.take() { Some(f) => read_small(f)?, None => String::new() },
        stderr: match stderr.take() { Some(f) => read_small(f)?, None => String::new() },
    })
}

#[derive(Debug, PartialEq, Eq)]
struct Counts { total: usize, passed: usize, failed: usize, skipped: usize, filtered: usize }

fn test_receipt(output: &str) -> Result<Counts, String> {
    let mut summaries = output.lines().filter(|l| l.starts_with("ORES_TEST|SUMMARY|"));
    let summary = summaries.next().ok_or("missing ORES_TEST summary")?;
    if summaries.next().is_some() { return Err("duplicate ORES_TEST summaries".into()); }
    let mut fields = BTreeMap::new();
    for pair in summary.split('|').skip(2) {
        let (key,value) = pair.split_once('=').ok_or("malformed ORES_TEST summary")?;
        if !["total","passed","failed","skipped","filtered"].contains(&key) || fields.insert(key, value.parse::<usize>().map_err(|_| "invalid test count")?).is_some() {
            return Err("unknown/duplicate test count".into());
        }
    }
    if fields.len() != 5 { return Err("incomplete test counts".into()); }
    let c = Counts {
        total: fields["total"], passed: fields["passed"],
        failed: fields["failed"], skipped: fields["skipped"], filtered: fields["filtered"],
    };
    if c.total == 0 {
        // A missing test discovery path must not be reported as green.
        return Err("machine receipt executed zero tests".into());
    }
    if c.passed.checked_add(c.failed).and_then(|n| n.checked_add(c.skipped)) != Some(c.total) {
        return Err("inconsistent test counts".into());
    }
    let mut observed = [0usize; 3];
    for line in output.lines().filter(|l| l.starts_with("ORES_TEST|")) {
        if line == summary { continue; }
        if line.starts_with("ORES_TEST|PASS|") { observed[0] += 1; }
        else if line.starts_with("ORES_TEST|FAIL|") { observed[1] += 1; }
        else if line.starts_with("ORES_TEST|SKIP|") { observed[2] += 1; }
        else { return Err("unexpected ORES_TEST record".into()); }
    }
    if observed != [c.passed, c.failed, c.skipped] { return Err("test receipt case count mismatch".into()); }
    Ok(c)
}

fn native(root: &Path, config: &toml::Table, timeout: Duration) -> Result<i32, String> {
    let params = section(config, "native")?;
    let mut files = Vec::new();
    if let Some(value) = params.and_then(|p| p.get("files")) {
        let arr = value.as_array().ok_or("[native].files must be a source list")?;
        for value in arr {
            files.push(value.as_str().ok_or("[native].files must contain strings")?.to_owned());
        }
    } else {
        for name in super::discover(root)? {
            let base = Path::new(&name).file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.starts_with("tests/") && (base.starts_with("test_") || base.ends_with("_test.ores")) {
                files.push(name);
            }
        }
    }
    if files.is_empty() || files.len() > 512 { return Err("native tests require 1..512 source files".into()); }
    let core = std::env::var("ORESLANG_BIN").unwrap_or_else(|_| "oreslang-core".into());
    let mut failures = 0;
    for name in files {
        let path = super::source_path(root, &name)?;
        let args = vec![core.clone(), path.to_string_lossy().into_owned()];
        let result = invoke(sanitize_command(&args, root)?, timeout, None, true)?;
        if result.timed_out || result.code != Some(0) {
            failures += 1;
            eprintln!("FAIL {name}: timed_out={} exit={:?} {}", result.timed_out, result.code, result.stderr.chars().take(1000).collect::<String>());
            continue;
        }
        match test_receipt(&result.output) {
            Ok(counts) if counts.failed == 0 => println!("PASS {name}: {} passed, {} skipped", counts.passed, counts.skipped),
            Ok(counts) => { failures += 1; eprintln!("FAIL {name}: {} failed tests", counts.failed); },
            Err(e) => { failures += 1; eprintln!("FAIL {name}: invalid machine receipt: {e}"); },
        }
    }
    Ok(i32::from(failures != 0))
}

#[derive(Clone)]
struct Rng { value: u64 }
impl Rng {
    fn new(seed: u64) -> Self { Self { value: seed } }
    fn next(&mut self) -> u64 {
        self.value = self.value.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.value;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, upper: usize) -> usize {
        if upper == 0 { return 0; }
        (self.next() % upper as u64) as usize
    }
}
/// Reject path escapes and symlinked ancestors before accessing project-owned
/// input/output. This is a preflight boundary check, not an atomic openat2
/// guarantee against a concurrently malicious local filesystem writer.
fn checked_project_path(root: &Path, name: &str) -> Result<PathBuf, String> {
    let relative = Path::new(name);
    if relative.as_os_str().is_empty() || relative.is_absolute()
        || relative.components().any(|c| !matches!(c,
            std::path::Component::Normal(_) | std::path::Component::CurDir))
    {
        return Err("unsafe project-relative path".into());
    }
    let mut result = root.to_path_buf();
    for part in relative.components() {
        result.push(part);
        match fs::symlink_metadata(&result) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!("symlinked project path refused: {}", result.display()));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(result)
}

/// Bound reads using the *opened file descriptor*. Linux also denies a final
/// symlink and avoids FIFO blocking, even if a path changes after listing.
/// Ancestor components still require descriptor-relative openat/openat2.
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
        let mut bytes = Vec::new();
        file.take(max_bytes as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        if bytes.len() > max_bytes { return Err("corpus item grew beyond read budget".into()); }
        return Ok(bytes);
    }
}

fn corpus(root: &Path, params: &toml::Table, max_bytes: usize) -> Result<Vec<Vec<u8>>, String> {
    let name = params.get("corpus").map(|v| v.as_str().ok_or("fuzz.corpus must be a relative path")).transpose()?.unwrap_or("tests/corpus");
    let path = checked_project_path(root, name)?;
    let mut cases = vec![vec![], vec![0], vec![255]];
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(cases),
        Err(e) => return Err(e.to_string()),
        Ok(m) if !m.is_dir() || m.file_type().is_symlink() => return Err("unsafe corpus directory".into()),
        _ => {}
    }
    #[cfg(target_os = "linux")]
    let files = super::fs_secure::list_project_files(
        root, Path::new(name), MAX_CORPUS_FILES
    )?;
    #[cfg(not(target_os = "linux"))]
    let files = {
        let mut paths = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let ty = entry.file_type().map_err(|e| e.to_string())?;
            if !ty.is_file() || ty.is_symlink() {
                return Err("corpus may contain only regular files".into());
            }
            paths.push(Path::new(name).join(entry.file_name()));
            if paths.len() > MAX_CORPUS_FILES {
                return Err("corpus file limit exceeded".into());
            }
        }
        paths.sort();
        paths
    };
    let mut consumed = 0usize;
    for relative in files {
        let bytes = read_case_bounded(root, &relative, max_bytes)?;
        consumed = consumed.checked_add(bytes.len()).ok_or("corpus byte budget overflow")?;
        if consumed > MAX_CORPUS_BYTES { return Err("corpus byte budget exceeded".into()); }
        cases.push(bytes);
    }
    let mut unique = BTreeSet::new();
    cases.retain(|x| unique.insert(x.clone()));
    Ok(cases)
}

fn classify(result: &ProcessResult) -> Result<Option<i32>, String> {
    if result.timed_out || result.code.is_none() { return Err("guest timed out or terminated abnormally; cannot classify fuzz failure".into()); }
    if result.code == Some(0) { Ok(None) } else { Ok(result.code) }
}

fn candidate(cmd: &[String], root: &Path, timeout: Duration, bytes: &[u8]) -> Result<Option<i32>, String> {
    classify(&invoke(sanitize_command(cmd, root)?, timeout, Some(bytes), false)?)
}

fn write_failure(root: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    // Stable filename is only a local deduplication hint, not a
    // cryptographic authentication or an attacker-resistant digest.
    let hash = bytes.iter().fold(0xcbf29ce484222325u64,
        |h, b| (h ^ u64::from(*b)).wrapping_mul(0x100000001b3));
    let relative = Path::new(".oreslang-test/failures")
        .join(format!("fuzz-{hash:016x}-{}.bin", bytes.len()));
    #[cfg(target_os = "linux")]
    {
        super::fs_secure::create_or_match(root, &relative, bytes)?;
        return Ok(root.join(relative));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let folder = checked_project_path(root, ".oreslang-test/failures")?;
        fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
        checked_project_path(root, ".oreslang-test/failures")?;
        let path = root.join(&relative);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => { file.write_all(bytes).map_err(|e| e.to_string())?; Ok(path) }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
                if !meta.is_file() || meta.file_type().is_symlink()
                    || read_case_bounded(root, &relative, bytes.len())? != bytes {
                    return Err("unsafe or colliding failure artifact".into());
                }
                Ok(path)
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

fn fuzz(root: &Path, config: &toml::Table, settings: &Settings) -> Result<i32, String> {
    let params = section(config, "fuzz")?.ok_or("missing [fuzz] section")?;
    let cmd = commands(params, "command")?;
    let max_bytes = match params.get("max_bytes") {
        Some(v) => v.as_integer().ok_or("invalid fuzz.max_bytes")?,
        None => 256,
    };
    if !(1..=65_536).contains(&max_bytes) { return Err("fuzz.max_bytes must be 1..65536".into()); }
    let mut samples = corpus(root, params, max_bytes as usize)?;
    if settings.security_fuzz {
        // Adversarial inputs are *stimuli*, never standalone proof of a bug.
        // Put these before the ordinary corpus so a bounded --cases also
        // exercises the security profile with a deterministic order.
        let mut security = vec![
            b"../".repeat(10), b"..%2f..%2f".to_vec(),
            b"%00%00".to_vec(), vec![0xff, 0xfe, 0xc0, 0xaf],
            b"\\u0000\\uD800".to_vec(),
            b"<script>alert(1)</script>".to_vec(),
            b"' OR 1=1 --".to_vec(), b"../../etc/passwd".to_vec(),
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
    let mut rng = Rng::new(settings.seed);
    for i in 0..settings.cases {
        let case = if i < samples.len() { samples[i].clone() } else {
            let base = &samples[rng.range(samples.len())];
            let mut bytes = base.clone();
            if bytes.is_empty() || rng.range(4) == 0 {
                bytes = vec![0; rng.range(max_bytes as usize + 1)];
                for x in &mut bytes { *x = rng.next() as u8; }
            } else {
                for _ in 0..(1 + rng.range(4)) {
                    let idx = rng.range(bytes.len());
                    bytes[idx] ^= rng.next() as u8;
                }
                bytes.truncate(max_bytes as usize);
            }
            bytes
        };
        if let Some(code) = candidate(&cmd, root, settings.timeout, &case)? {
            for _ in 0..2 {
                if candidate(&cmd, root, settings.timeout, &case)? != Some(code) {
                    eprintln!("FUZZ FLAKY seed={} iteration={i}: no stable reproduction", settings.seed);
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
                    if budget == 0 { break; }
                    budget -= 1;
                    let mut reduced = shrunk[..start].to_vec();
                    reduced.extend_from_slice(&shrunk[(start + chunk).min(shrunk.len())..]);
                    if candidate(&cmd, root, settings.timeout, &reduced)? == Some(code) {
                        shrunk = reduced;
                        granularity = 2;
                        shorter = true;
                        break;
                    }
                }
                if !shorter {
                    if granularity >= shrunk.len() { break; }
                    granularity = (granularity * 2).min(shrunk.len());
                }
            }
            for _ in 0..2 {
                if candidate(&cmd, root, settings.timeout, &shrunk)? != Some(code) {
                    eprintln!("FUZZ FLAKY after minimization; preserving original failure");
                    shrunk = case.clone();
                    break;
                }
            }
            let saved = write_failure(root, &shrunk)?;
            println!("FUZZ FAILURE seed={} iteration={i} exit={code} initial={} minimized={} path={}", settings.seed, case.len(), shrunk.len(), saved.display());
            return Ok(1);
        }
        if samples.len() < 4096 { samples.push(case); }
    }
    println!("FUZZ PASS cases={} seed={} (observed inputs only)", settings.cases, settings.seed);
    Ok(0)
}

pub fn run(args: &[OsString]) -> i32 {
    let result = (|| -> Result<i32,String> {
        let settings = parse(args)?;
        let root = settings.root.canonicalize().map_err(|e| e.to_string())?;
        if !root.is_dir() { return Err("project root must be a directory".into()); }
        let cfg = manifest(&root)?;
        if settings.deadlock {
            if settings.logical || settings.model.is_some() {
                return Err("combined deadlock and logical-model checking is not implemented".into());
            }
            if let Some(name) = &settings.trace {
                let deadlocks = super::deadlock::offline(&root,name)?;
                if settings.race {
                    let races = super::race_offline::offline(&root,name)?;
                    return Ok(deadlocks.max(races));
                }
                return Ok(deadlocks);
            }
            return Err("runtime --deadlock is INCONCLUSIVE without an explicit offline --trace; trusted live event capture is unavailable".into());
        }
        if settings.race {
            if settings.logical {
                return super::logical::offline(&root,
                    settings.model.as_deref().ok_or("missing logical model")?,
                    settings.max_schedules);
            }
            if let Some(path) = &settings.trace {
                return super::race_offline::offline(&root, path);
            }
            return Err("runtime --race is INCONCLUSIVE: trusted backend trace admission is not implemented; use --trace for explicitly offline Rust analysis".into());
        }
        if settings.fuzz { fuzz(&root, &cfg, &settings) }
        else { native(&root, &cfg, settings.timeout) }
    })();
    match result {
        Ok(code) => code,
        Err(message) => { eprintln!("oreslang test: {message}"); 2 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsupported_race_without_python_fallback() {
        assert_eq!(run(&["--race".into()]), 2);
        assert_eq!(run(&["--race".into(), "--logical".into()]), 2);
        assert_eq!(parse(&["--model".into(),"x.json".into()]).is_err(), true);
    }
    #[test]
    fn rejects_missing_arguments_and_invalid_timeouts() {
        assert!(parse(&["--seed".into()]).is_err());
        assert!(parse(&["--timeout=NaN".into()]).is_err());
        assert!(parse(&["--cases=0".into()]).is_err());
        assert!(parse(&["--fuzz".into(), "--race".into()]).is_err());
    }
    #[test]
    fn stable_seed_reproducibility() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 { assert_eq!(a.next(), b.next()); }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn opened_corpus_descriptor_denies_symlinks_and_oversize() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("case");
        std::fs::write(&source, b"abc").unwrap();
        let relative = Path::new("case");
        assert_eq!(read_case_bounded(dir.path(), relative, 3).unwrap(), b"abc");
        assert!(read_case_bounded(dir.path(), relative, 2).is_err());
        let alias = dir.path().join("alias");
        symlink(&source, &alias).unwrap();
        assert!(read_case_bounded(dir.path(), Path::new("alias"), 3).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn fuzz_failure_artifact_collision_denies_symlink_alias() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let payload = b"reproducible-crash";
        let saved = write_failure(&root, payload).unwrap();
        assert_eq!(write_failure(&root, payload).unwrap(), saved);
        std::fs::remove_file(&saved).unwrap();
        let external = root.join("external.bin");
        std::fs::write(&external, payload).unwrap();
        symlink(&external, &saved).unwrap();
        assert!(write_failure(&root, payload).is_err());
    }

    #[test]
    fn machine_receipts_are_strict() {
        let good = "ORES_TEST|PASS|one\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\n";
        assert_eq!(test_receipt(good), Ok(Counts { total:1,passed:1,failed:0,skipped:0,filtered:0 }));
        assert!(test_receipt(&format!("{good}{good}")).is_err());
        assert!(test_receipt("ORES_TEST|SUMMARY|total=0|passed=0|passed=0|failed=0|skipped=0|filtered=0").is_err());
        assert!(test_receipt("ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0").is_err());
        assert!(test_receipt("ORES_TEST|SUMMARY|total=0|passed=0|failed=0|skipped=0|filtered=0").is_err());
        assert!(test_receipt("ORES_TEST|PASS|one\nORES_TEST|SUMMARY|total=2|passed=1|failed=0|skipped=0|filtered=0").is_err());
    }
}
