//! End-to-end Rust executable tests; no Python interpreter is involved.
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .arg("--root").arg(root).args(args).output().unwrap()
}

#[test]
fn pure_rust_offline_race_engine_exposes_observed_conflicts() {
    let root = tempfile::tempdir().unwrap();
    let racy = include_str!("traces/racy.jsonl");
    let ordered = include_str!("traces/ordered.jsonl");
    fs::write(root.path().join("racy.jsonl"), racy).unwrap();
    fs::write(root.path().join("ordered.jsonl"), ordered).unwrap();
    let found = cli(root.path(), &["--race", "--trace", "racy.jsonl"]);
    assert_eq!(found.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&found.stdout).contains("OFFLINE TRACE FINDINGS"));
    let clean = cli(root.path(), &["--race", "--trace", "ordered.jsonl"]);
    assert_eq!(clean.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&clean.stdout).contains("not a trusted runtime race-free certificate"));
}

#[test]
fn uninstrumented_runtime_and_invalid_jsonl_are_inconclusive() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(cli(root.path(), &["--race"]).status.code(), Some(2));
    assert_eq!(cli(root.path(), &["--race", "--logical"]).status.code(), Some(2));
    for s in [
        "{\"op\":\"begin\",\"version\":1,\"run_id\":\"r\",\"backend\":\"llvm\"}\n",
        "{\"op\":\"begin\",\"version\":1,\"run_id\":\"r\",\"backend\":\"llvm\"}\n{\"op\":\"task\",\"task\":\"a\",\"task\":\"b\"}\n{\"op\":\"end\",\"run_id\":\"r\",\"events\":1}\n",
        "{\"op\":\"begin\",\"version\":1,\"run_id\":\"r\",\"backend\":\"llvm\"}\n{\"op\":\"end\",\"run_id\":\"r\",\"events\":0}\n",
    ] {
        fs::write(root.path().join("invalid.jsonl"), s).unwrap();
        let result = cli(root.path(), &["--race", "--trace", "invalid.jsonl"]);
        assert_eq!(result.status.code(), Some(2), "{s}");
    }
}

#[cfg(unix)]
fn guest(root: &Path, name: &str, source: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join(name);
    fs::write(&path, source).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&path, perms).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn machine_receipts_are_checked_by_native_rust_runner() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tests")).unwrap();
    fs::write(root.path().join("tests/test_hello.ores"), "").unwrap();
    let compiler = guest(root.path(), "fake-compiler", "#!/bin/sh\nprintf 'ORES_TEST|PASS|test1\\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\\n'\n");
    let ok = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("ORESLANG_BIN", &compiler)
        .arg("--root").arg(root.path()).output().unwrap();
    assert_eq!(ok.status.code(), Some(0), "{:?}", ok);
    assert!(String::from_utf8_lossy(&ok.stdout).contains("PASS"));
    let invalid = guest(root.path(), "invalid-compiler", "#!/bin/sh\nprintf 'ORES_TEST|PASS|test1\\nORES_TEST|SUMMARY|total=2|passed=2|failed=0|skipped=0|filtered=0\\n'\n");
    let bad = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("ORESLANG_BIN", invalid)
        .arg("--root").arg(root.path()).output().unwrap();
    assert_eq!(bad.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn seeded_fuzzer_minimizes_reproducible_failure_without_python() {
    let root = tempfile::tempdir().unwrap();
    let property = guest(root.path(), "property", "#!/bin/sh\nif [ -s /dev/stdin ]; then exit 7; fi\nexit 0\n");
    fs::write(root.path().join("oreslang-test.toml"),
        format!("[fuzz]\ncommand = ['{}']\nmax_bytes = 16\n", property.display())).unwrap();
    let result = cli(root.path(), &["--fuzz", "--seed", "42", "--cases", "8"]);
    assert_eq!(result.status.code(), Some(1), "{:?}", result);
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(out.contains("FUZZ FAILURE"));
    assert!(out.contains("minimized=1"));
    let failures = root.path().join(".oreslang-test/failures");
    let names: Vec<_> = fs::read_dir(failures).unwrap().collect();
    assert_eq!(names.len(), 1);
    assert_eq!(fs::read(names[0].as_ref().unwrap().path()).unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn fuzz_timeouts_are_inconclusive_and_do_not_report_pass() {
    let root = tempfile::tempdir().unwrap();
    let property = guest(root.path(), "property", "#!/bin/sh\nsleep 5\nexit 0\n");
    fs::write(root.path().join("oreslang-test.toml"),
        format!("[fuzz]\ncommand = ['{}']\nmax_bytes = 16\n", property.display())).unwrap();
    let result = cli(root.path(), &["--fuzz", "--cases", "1", "--timeout", "0.02"]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("FUZZ PASS"));
}

#[cfg(unix)]
#[test]
fn symlinked_corpus_ancestors_and_output_directories_are_rejected() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("seeds")).unwrap();
    let property = guest(root.path(), "safe-property", "#!/bin/sh\nexit 0\n");
    fs::write(root.path().join("oreslang-test.toml"),
        format!("[fuzz]\ncommand = ['{}']\ncorpus = 'link/subdir'\nmax_bytes = 32\n", property.display())).unwrap();
    symlink(outside.path(), root.path().join("link")).unwrap();
    let traversal = cli(root.path(), &["--fuzz", "--cases", "1"]);
    assert_eq!(traversal.status.code(), Some(2), "{traversal:?}");
    fs::remove_file(root.path().join("link")).unwrap();
    fs::write(root.path().join("oreslang-test.toml"),
        format!("[fuzz]\ncommand = ['{}']\ncorpus = 'seeds'\nmax_bytes = 32\n", property.display())).unwrap();
    let failing = guest(root.path(), "failing-property", "#!/bin/sh\nexit 7\n");
    fs::write(root.path().join("oreslang-test.toml"),
        format!("[fuzz]\ncommand = ['{}']\ncorpus = 'seeds'\nmax_bytes = 32\n", failing.display())).unwrap();
    symlink(outside.path(), root.path().join(".oreslang-test")).unwrap();
    let unsafe_output = cli(root.path(), &["--fuzz", "--cases", "1"]);
    assert_eq!(unsafe_output.status.code(), Some(2), "{unsafe_output:?}");
    assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
}


#[cfg(unix)]
#[test]
fn security_fuzz_profile_injects_adversarial_cases_without_python() {
    let root = tempfile::tempdir().unwrap();
    let oracle = guest(root.path(), "path-oracle",
        "#!/bin/sh\ncase \"$(cat)\" in ../*) exit 7;; esac\nexit 0\n");
    fs::write(root.path().join("oreslang-test.toml"),
        format!("[fuzz]\ncommand = ['{}']\nmax_bytes = 64\n", oracle.display())).unwrap();
    let result = cli(root.path(), &["--fuzz", "--fuzz-profile", "security", "--cases", "1", "--seed", "9"]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("FUZZ FAILURE"));
    assert_eq!(cli(root.path(), &["--fuzz-profile", "security"]).status.code(), Some(2));
    assert_eq!(cli(root.path(), &["--fuzz", "--fuzz-profile", "unknown"]).status.code(), Some(2));
}

#[test]
fn offline_deadlock_graphs_report_cycles_and_refuse_no_lock_evidence() {
    let root = tempfile::tempdir().unwrap();
    let risky = concat!(
        "{\"op\":\"begin\",\"version\":1,\"run_id\":\"r\",\"backend\":\"llvm\"}\n",
        "{\"op\":\"task\",\"task\":\"a\"}\n",
        "{\"op\":\"task\",\"task\":\"b\"}\n",
        "{\"op\":\"lock\",\"task\":\"a\",\"name\":\"A\"}\n",
        "{\"op\":\"lock\",\"task\":\"b\",\"name\":\"B\"}\n",
        "{\"op\":\"wait\",\"task\":\"a\",\"name\":\"B\"}\n",
        "{\"op\":\"wait\",\"task\":\"b\",\"name\":\"A\"}\n",
        "{\"op\":\"end\",\"run_id\":\"r\",\"events\":6}\n",
    );
    fs::write(root.path().join("waiting.jsonl"), risky).unwrap();
    let issue = cli(root.path(), &["--deadlock", "--trace", "waiting.jsonl"]);
    assert_eq!(issue.status.code(), Some(1), "{issue:?}");
    assert!(String::from_utf8_lossy(&issue.stdout).contains("OBSERVED WAIT CYCLE"));
    assert_eq!(cli(root.path(), &["--deadlock"]).status.code(), Some(2));
    assert_eq!(cli(root.path(), &["--race","--deadlock","--trace","waiting.jsonl"]).status.code(),Some(2));
}

#[cfg(unix)]
#[test]
fn machine_summary_with_no_executed_tests_cannot_pass() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tests")).unwrap();
    fs::write(root.path().join("tests/test_noop.ores"), "").unwrap();
    let compiler = guest(root.path(), "zero-test-compiler",
        "#!/bin/sh\nprintf 'ORES_TEST|SUMMARY|total=0|passed=0|failed=0|skipped=0|filtered=0\\n'\n");
    let status = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("ORESLANG_BIN", compiler)
        .arg("--root").arg(root.path()).output().unwrap();
    assert_eq!(status.status.code(), Some(1), "{status:?}");
    assert!(String::from_utf8_lossy(&status.stderr).contains("zero tests"));
}

#[cfg(unix)]
#[test]
fn bare_path_alias_to_own_cli_cannot_invoke_recursively() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    symlink(env!("CARGO_BIN_EXE_oreslang-test"), root.path().join("loop-exec")).unwrap();
    fs::write(root.path().join("oreslang-test.toml"),
        "[fuzz]\ncommand = ['loop-exec']\nmax_bytes = 16\n").unwrap();
    let paths = std::env::join_paths([root.path(),
        std::path::Path::new("/usr/bin"), std::path::Path::new("/bin")]).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("PATH", paths).arg("--root").arg(root.path())
        .args(["--fuzz", "--cases", "1"]).output().unwrap();
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stderr).contains("recursion refused"));
}
