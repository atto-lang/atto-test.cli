mod common;
mod deadlock;
mod effects_cli;
mod fuzz;
mod model;
mod race;
mod runner;
mod schedule;

use clap::Parser;
use common::{safe_path, table_command, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(
    name = "oreslang-test",
    version,
    about = "Rust-native Oreslang test, race, fuzz, syntax and schedule CLI"
)]
struct Opt {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long)]
    check: bool,
    #[arg(long)]
    check_types: bool,
    #[arg(long)]
    effects: bool,
    #[arg(long)]
    effects_strict: bool,
    #[arg(long = "file")]
    file: Vec<String>,
    #[arg(long)]
    fuzz: bool,
    #[arg(long)]
    race: bool,
    #[arg(long)]
    deadlock: bool,
    #[arg(long)]
    model_check: bool,
    #[arg(long)]
    schedule_fuzz: bool,
    #[arg(long)]
    replay: Option<String>,
    #[arg(long)]
    trace_output: Option<String>,
    #[arg(long, default_value_t = 1)]
    iterations: usize,
    #[arg(long)]
    logical: bool,
    #[arg(long)]
    trace: Option<String>,
    #[arg(long)]
    model: Option<String>,
    #[arg(long, default_value_t = 1)]
    seed: i64,
    #[arg(long, default_value_t = 100)]
    cases: usize,
    #[arg(long, default_value_t = 5.0)]
    timeout: f64,
    #[arg(long, default_value_t = 10000)]
    max_schedules: usize,
    /// Project-relative source file/directory to syntax-check
    source: Option<String>,
}
fn validate(o: &Opt) -> Result<()> {
    let schedule = o.schedule_fuzz || o.replay.is_some();
    let checking = o.check || o.check_types;
    if (o.effects_strict || !o.file.is_empty()) && !o.effects {
        return Err("--effects-strict and --file require --effects".into());
    }
    if o.effects
        && (checking
            || o.fuzz
            || o.race
            || o.deadlock
            || o.model_check
            || o.logical
            || schedule
            || o.trace.is_some()
            || o.model.is_some()
            || o.source.is_some())
    {
        return Err("--effects is a separate advisory source mode".into());
    }
    if o.check && o.check_types {
        return Err("--check and --check-types are separate modes".into());
    }
    if checking
        && (o.fuzz
            || o.race
            || o.deadlock
            || o.model_check
            || o.logical
            || schedule
            || o.trace.is_some()
            || o.model.is_some())
    {
        return Err("--check/--check-types cannot combine with test modes".into());
    }
    if o.source.is_some() && !checking {
        return Err("source path requires --check or --check-types".into());
    }
    if o.fuzz
        && (o.race
            || o.deadlock
            || o.model_check
            || o.logical
            || schedule
            || o.trace.is_some()
            || o.model.is_some())
    {
        return Err("--fuzz is a separate test mode".into());
    }
    if (o.logical || o.model.is_some()) && !(o.race || o.model_check) {
        return Err("--logical/--model requires --race or --model-check".into());
    }
    if o.model_check && (o.race || o.deadlock || schedule) {
        return Err(
            "--model-check is reference-model exploration, not guest race instrumentation".into(),
        );
    }
    if o.trace.is_some() && !(o.race || o.deadlock) {
        return Err("--trace requires --race or --deadlock".into());
    }
    if o.replay.is_some() && o.schedule_fuzz {
        return Err("--replay and --schedule-fuzz are exclusive".into());
    }
    if (o.trace_output.is_some() || o.iterations != 1) && !schedule {
        return Err("schedule output/iteration options require --schedule-fuzz or --replay".into());
    }
    if schedule && (o.race || o.deadlock || o.fuzz || o.model_check || o.logical) {
        return Err("schedule runner is a separate backend mode".into());
    }
    if !(0.01..=600.0).contains(&o.timeout) {
        return Err("--timeout must be 0.01..600 seconds".into());
    }
    Ok(())
}
fn nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
// Strict check-only claims require an independently pinned compiler binary;
// a project manifest may choose source files, but cannot nominate any script
// as a trusted compiler by printing a matching receipt.
fn digest_trusted_compiler(command: &[String], expected: &str) -> Result<String> {
    if command.len() != 1 {
        return Err("[check].command must contain only an absolute compiler executable; no shell or wrapper argv".into());
    }
    let path = Path::new(&command[0]);
    if !path.is_absolute() {
        return Err("trusted check compiler must be an absolute executable path".into());
    }
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(
            "ORESLANG_TRUSTED_CHECK_COMPILER_SHA256 must be a 64-character SHA-256 hex digest"
                .into(),
        );
    }
    let before = path.symlink_metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > (1u64 << 30) {
        return Err("trusted check compiler must be a bounded regular file, not a symlink".into());
    }
    // Hash the same regular file opened with no final-component symlink
    // following; lstat alone permits a symlink swap before File::open.
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| e.to_string())?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let actual = file.metadata().map_err(|e| e.to_string())?;
    if !actual.is_file() || actual.len() != before.len() {
        return Err("trusted check compiler changed during validation".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != actual.dev() || before.ino() != actual.ino() {
            return Err("trusted check compiler was replaced during validation".into());
        }
    }
    let mut hasher = Sha256::new();
    let mut block = [0u8; 65536];
    use std::io::Read;
    loop {
        let n = file.read(&mut block).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&block[..n]);
    }
    let actual_sha = format!("{:x}", hasher.finalize());
    if actual_sha != expected.to_ascii_lowercase() {
        return Err("trusted check compiler SHA-256 does not match independent pin".into());
    }
    Ok(actual_sha)
}

fn check(
    root: &Path,
    cfg: &toml::Value,
    source: Option<&str>,
    types: bool,
    timeout: f64,
) -> Result<u8> {
    // No separate Rust parser: compiler frontend is the only syntax authority.
    // A binary which cannot emit a source-bound no-codegen receipt is inconclusive.
    let cmd=table_command(cfg,"check")
        .map_err(|_|"no [check].command configured; refusing syntax PASS without the canonical compiler parser".to_string())?;
    let trusted_sha = std::env::var("ORESLANG_TRUSTED_CHECK_COMPILER_SHA256")
        .map_err(|_| "missing independent ORESLANG_TRUSTED_CHECK_COMPILER_SHA256 pin; no compiler PASS allowed".to_string())?;
    digest_trusted_compiler(&cmd, &trusted_sha)?;
    let selected = safe_path(root, source.unwrap_or("."))?;
    if !selected.exists() {
        return Err("syntax-check source does not exist".into());
    }
    let mut files = Vec::new();
    if selected.is_file() {
        if selected.extension().is_none_or(|v| v != "ores") {
            return Err("--check needs a .ores source file".into());
        }
        files.push(selected);
    } else if selected.is_dir() {
        for entry in WalkDir::new(&selected)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                ![".git", "target", ".oreslang-test"]
                    .iter()
                    .any(|s| e.file_name().to_string_lossy() == *s)
            })
        {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.file_type().is_symlink() {
                return Err("source tree contains symbolic link".into());
            }
            if entry.file_type().is_file() && entry.path().extension().is_some_and(|s| s == "ores")
            {
                files.push(entry.into_path());
                if files.len() > 10000 {
                    return Err("too many sources to check".into());
                }
            }
        }
    } else {
        return Err("source must be file or directory".into());
    }
    files.sort();
    if files.is_empty() {
        return Err("no .ores source files found; no check performed".into());
    }
    for file in &files {
        let bytes = common::bounded_read(file, 4_000_000)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let mut argv = cmd.clone();
        argv.push(
            if types {
                "--check-types"
            } else {
                "--syntax-only"
            }
            .to_string(),
        );
        argv.push(file.to_string_lossy().into_owned());
        let outcome = runner::run(&argv, root, timeout, None, &[])?;
        let Some(out) = outcome else {
            eprintln!("CHECK FAIL {} timeout", file.display());
            return Ok(1);
        };
        if out.code != 0 {
            eprintln!("CHECK FAIL {} exit={}", file.display(), out.code);
            eprintln!("{}", out.stderr.chars().take(8000).collect::<String>());
            return Ok(1);
        }
        let phase = if types { "types" } else { "syntax-only" };
        let receipt = format!("ORES_CHECK|PASS|sha256={digest}|phase={phase}");
        if out.stdout.lines().filter(|line| *line == receipt).count() != 1 {
            return Err(format!(
                "{} did not produce source-bound {phase} receipt; cannot assert check-only success",
                file.display()
            ));
        }
        // The parser must have checked the exact source bytes for which the
        // receipt is published; deny mutable-source swaps during invocation.
        let after = common::bounded_read(file, 4_000_000)?;
        if format!("{:x}", Sha256::digest(&after)) != digest {
            return Err(format!(
                "{} changed during compiler check; receipt is stale",
                file.display()
            ));
        }
        // Detect compiler replacement after invocation; the binary SHA is
        // independently controlled by the trusted caller, never by the project.
        digest_trusted_compiler(&cmd, &trusted_sha)?;
    }
    println!(
        "CHECK PASS: {} .ores sources ({}) using compiler frontend, no codegen requested",
        files.len(),
        if types { "typecheck" } else { "syntax" }
    );
    Ok(0)
}
fn models(root: &Path, cfg: &toml::Value, name: Option<&str>, limit: usize) -> Result<u8> {
    let list: Vec<String> = if let Some(file) = name {
        vec![file.into()]
    } else {
        cfg.get("logical")
            .and_then(|v| v.get("models"))
            .and_then(|v| v.as_array())
            .ok_or("--logical requires --model or [logical].models")?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or("invalid model path".into())
            })
            .collect::<Result<Vec<_>>>()?
    };
    if list.is_empty() {
        return Err("no logical models configured".into());
    }
    for name in &list {
        let report = model::explore(&safe_path(root, name)?, limit)?;
        if let Some(violation) = report.violation {
            println!("LOGICAL RACE {name}: {violation}");
            return Ok(1);
        }
        println!(
            "LOGICAL PASS {name}: explored {} schedules (reference model only)",
            report.schedules
        );
    }
    Ok(0)
}
fn instrumented(
    root: &Path,
    cfg: &toml::Value,
    mode: &str,
    timeout: f64,
) -> Result<(PathBuf, String, tempfile::TempDir)> {
    let argv = if mode == "deadlock" {
        table_command(cfg, "deadlock").or_else(|_| table_command(cfg, "race"))?
    } else {
        table_command(cfg, "race")?
    };
    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    let path = tmp.path().join("events.jsonl");
    let id = nonce();
    let vars = vec![
        (
            "ORESLANG_RACE_TRACE".to_string(),
            path.to_string_lossy().into_owned(),
        ),
        ("ORESLANG_RACE_RUN_ID".into(), id.clone()),
    ];
    let result = runner::run(&argv, root, timeout, None, &vars)?;
    let Some(output) = result else {
        return Err(format!("instrumented {mode} run timed out; inconclusive"));
    };
    if output.code != 0 {
        return Err(format!(
            "instrumented {mode} run failed; inconclusive: {}",
            output.stderr
        ));
    }
    Ok((path, id, tmp))
}
fn show_races(report: &race::Report) -> u8 {
    if report.count > 0 {
        for c in report.examples.iter().take(20) {
            println!("DATA RACE: {c}");
        }
        println!(
            "{} conflicts in {} observed events (up to 100 retained)",
            report.count, report.events
        );
        1
    } else {
        println!(
            "TRACE PASS: {} observed events on {} (not a race-freedom proof)",
            report.events, report.backend
        );
        0
    }
}
fn do_race(root: &Path, cfg: &toml::Value, o: &Opt, model_only: bool) -> Result<u8> {
    let mut analyses = 0;
    let mut status = 0;
    if !model_only {
        if let Some(file) = o.trace.as_deref() {
            let report = race::analyze(&safe_path(root, file)?, None)?;
            analyses += 1;
            status |= show_races(&report);
        } else if table_command(cfg, "race").is_ok() {
            let (path, id, _hold) = instrumented(root, cfg, "race", o.timeout)?;
            let report = race::analyze(&path, Some(&id))?;
            analyses += 1;
            status |= show_races(&report);
        }
    }
    if model_only || o.logical || o.model.is_some() {
        analyses += 1;
        status |= models(root, cfg, o.model.as_deref(), o.max_schedules)?;
    }
    if analyses == 0 {
        return Err(
            "--race needs --trace, [race].command or --logical model; refusing false PASS".into(),
        );
    }
    if model_only {
        println!("Reference-model-only result: no guest runtime instrumentation");
    }
    Ok(status)
}
fn do_deadlock(root: &Path, cfg: &toml::Value, o: &Opt) -> Result<u8> {
    let report = if let Some(file) = o.trace.as_deref() {
        deadlock::analyze(&safe_path(root, file)?, None)?
    } else {
        let (path, id, _hold) = instrumented(root, cfg, "deadlock", o.timeout)?;
        deadlock::analyze(&path, Some(&id))?
    };
    for c in report.runtime.iter().take(20) {
        println!("RUNTIME CYCLE DETECTED: {c}");
    }
    if report.backend == "graal-checkpoints" && report.runtime.is_empty() {
        return Err("runtime checkpoint lacks wait-graph evidence; inconclusive".into());
    }
    for c in report.waits.iter().take(20) {
        println!("OBSERVED WAIT CYCLE: {}", c.join(" -> "));
    }
    for c in report.orders.iter().take(20) {
        println!("POTENTIAL LOCK-ORDER CYCLE: {}", c.join(" -> "));
    }
    if !report.waits.is_empty() || !report.orders.is_empty() || !report.runtime.is_empty() {
        println!(
            "DEADLOCK FINDINGS: {} wait, {} lock-order, {} runtime receipts",
            report.waits.len(),
            report.orders.len(),
            report.runtime.len()
        );
        Ok(1)
    } else {
        println!(
            "DEADLOCK TRACE PASS: {} lock events in {} observed events (no liveness proof)",
            report.lock_events, report.events
        );
        Ok(0)
    }
}
fn native(root: &Path, cfg: &toml::Value, timeout: f64) -> Result<u8> {
    let files = if let Some(arr) = cfg
        .get("native")
        .and_then(|v| v.get("files"))
        .and_then(|v| v.as_array())
    {
        arr.iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or("invalid [native].files item".to_string())
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        let dir = root.join("tests");
        if !dir.exists() {
            return Err("no tests folder and no [native].files".into());
        }
        let mut entries = Vec::new();
        for entry in WalkDir::new(dir).follow_links(false) {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.file_type().is_symlink() {
                return Err("native test discovery refuses symlink entries".into());
            }
            if entries.len() >= 20_000 {
                return Err("native test discovery exceeds 20000 filesystem entries".into());
            }
            entries.push(entry);
        }
        entries
            .into_iter()
            .filter(|e| {
                e.file_type().is_file()
                    && e.path().extension().is_some_and(|x| x == "ores")
                    && (e.file_name().to_string_lossy().starts_with("test_")
                        || e.file_name().to_string_lossy().ends_with("_test.ores"))
            })
            .map(|e| {
                e.path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    };
    if files.is_empty() {
        return Err("no native test sources discovered".into());
    }
    let core = std::env::var("ORESLANG_BIN").unwrap_or_else(|_| "oreslang-core".into());
    if let Ok(real) = std::fs::canonicalize(&core) {
        if std::env::current_exe().is_ok_and(|self_exe| self_exe == real) {
            return Err("ORESLANG_BIN points back to the test runner".into());
        }
    }
    let mut failures = 0;
    for name in &files {
        let file = safe_path(root, name)?;
        if !file.is_file() || file.extension().is_none_or(|x| x != "ores") {
            return Err(format!("not a native test source: {name}"));
        }
        let args = vec![core.clone(), file.to_string_lossy().into_owned()];
        let outcome = runner::run(&args, root, timeout, None, &[])?;
        let Some(out) = outcome else {
            eprintln!("TIMEOUT {name}");
            failures += 1;
            continue;
        };
        let mut counts = [0usize; 3];
        let mut summary = None;
        for line in out.stdout.lines() {
            if let Some(i) = ["ORES_TEST|PASS|", "ORES_TEST|FAIL|", "ORES_TEST|SKIP|"]
                .iter()
                .position(|p| line.starts_with(p))
            {
                counts[i] += 1;
            }
            if line.starts_with("ORES_TEST|SUMMARY|") {
                if summary.is_some() {
                    summary = Some(String::new());
                    break;
                }
                summary = Some(line.to_owned());
            }
        }
        let valid = summary
            .as_ref()
            .and_then(|line| {
                let rest = line.strip_prefix("ORES_TEST|SUMMARY|")?;
                let props: Vec<_> = rest.split('|').collect();
                if props.len() != 5 {
                    return None;
                }
                let values: Option<Vec<usize>> =
                    ["total", "passed", "failed", "skipped", "filtered"]
                        .iter()
                        .zip(props.iter())
                        .map(|(key, p)| p.strip_prefix(&format!("{key}="))?.parse().ok())
                        .collect();
                let v = values?;
                let accounted = v[1].checked_add(v[2])?.checked_add(v[3])?;
                Some(v[0] == accounted && v[1] > 0 && v[2] == 0 && counts == [v[1], v[2], v[3]])
            })
            .unwrap_or(false);
        if out.code != 0 || !valid {
            failures += 1;
            eprintln!("FAIL {name}: exit={} valid_summary={valid}", out.code);
            eprintln!("{}", out.stdout.chars().take(8000).collect::<String>());
            eprintln!("{}", out.stderr.chars().take(8000).collect::<String>());
        } else {
            println!("PASS {name}: {}", summary.unwrap());
        }
    }
    Ok((failures > 0) as u8)
}
fn run(o: Opt) -> Result<u8> {
    validate(&o)?;
    let root = o.root.canonicalize().map_err(|e| e.to_string())?;
    if !root.is_dir() {
        return Err("project root must be directory".into());
    }
    let manifest = root.join("oreslang-test.toml");
    let cfg: toml::Value = if manifest.exists() {
        let raw = common::bounded_read(&manifest, 1_048_576)?;
        let raw = std::str::from_utf8(&raw).map_err(|e| e.to_string())?;
        toml::from_str(raw).map_err(|e| e.to_string())?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    if o.check || o.check_types {
        return check(&root, &cfg, o.source.as_deref(), o.check_types, o.timeout);
    }
    if o.effects {
        return effects_cli::run(&root, &cfg, &o.file, o.effects_strict);
    }
    if o.schedule_fuzz || o.replay.is_some() {
        return schedule::schedule(
            &root,
            &cfg,
            o.seed,
            o.iterations,
            o.timeout,
            o.replay.as_deref(),
            o.trace_output.as_deref(),
        );
    }
    if o.fuzz {
        return fuzz::fuzz(&root, &cfg, o.seed as u64, o.cases, o.timeout);
    }
    if o.model_check {
        return do_race(&root, &cfg, &o, true);
    }
    let mut result = 0;
    if o.race {
        result |= do_race(&root, &cfg, &o, false)?;
    }
    if o.deadlock {
        result |= do_deadlock(&root, &cfg, &o)?;
    }
    if o.race || o.deadlock {
        return Ok(result);
    }
    native(&root, &cfg, o.timeout)
}
fn main() {
    let cli = Opt::parse();
    let exit = match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("oreslang test: {err}");
            2
        }
    };
    std::process::exit(exit.into());
}

#[cfg(test)]
mod check_compiler_trust_tests {
    use super::*;

    #[test]
    fn only_independently_pinned_absolute_regular_compiler_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake-compiler");
        std::fs::write(&path, b"abc").unwrap();
        let command = vec![path.to_str().unwrap().to_owned()];
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(
            digest_trusted_compiler(&command, expected).unwrap(),
            expected
        );
        assert!(
            digest_trusted_compiler(&command, &"0".repeat(64)).is_err(),
            "a forged receipt cannot substitute for an independently pinned binary"
        );
        assert!(digest_trusted_compiler(&["sh".to_string()], expected).is_err());
        assert!(digest_trusted_compiler(&[command[0].clone(), "-c".into()], expected).is_err());
        assert!(digest_trusted_compiler(&command, "not-a-sha").is_err());
        std::fs::write(&path, b"abd").unwrap();
        assert!(
            digest_trusted_compiler(&command, expected).is_err(),
            "modifying the compiler after pinning must invalidate admission"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_compiler_is_rejected_even_when_its_target_digest_matches() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("compiler");
        let alias = dir.path().join("alias");
        std::fs::write(&target, b"abc").unwrap();
        symlink(&target, &alias).unwrap();
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(digest_trusted_compiler(&[alias.to_str().unwrap().to_owned()], expected).is_err());
    }
}
