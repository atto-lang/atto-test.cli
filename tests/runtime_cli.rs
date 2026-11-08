//! End-to-end Rust executable tests; no Python interpreter is involved.
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .arg("--root")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
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
    assert!(String::from_utf8_lossy(&clean.stdout)
        .contains("not a trusted runtime race-free certificate"));
}

#[test]
fn uninstrumented_runtime_and_invalid_jsonl_are_inconclusive() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(cli(root.path(), &["--race"]).status.code(), Some(2));
    assert_eq!(
        cli(root.path(), &["--race", "--logical"]).status.code(),
        Some(2)
    );
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
        .arg("--root")
        .arg(root.path())
        .output()
        .unwrap();
    assert_eq!(ok.status.code(), Some(0), "{:?}", ok);
    assert!(String::from_utf8_lossy(&ok.stdout).contains("PASS"));
    let invalid = guest(root.path(), "invalid-compiler", "#!/bin/sh\nprintf 'ORES_TEST|PASS|test1\\nORES_TEST|SUMMARY|total=2|passed=2|failed=0|skipped=0|filtered=0\\n'\n");
    let bad = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("ORESLANG_BIN", invalid)
        .arg("--root")
        .arg(root.path())
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn seeded_fuzzer_minimizes_reproducible_failure_without_python() {
    let root = tempfile::tempdir().unwrap();
    let property = guest(
        root.path(),
        "property",
        "#!/bin/sh\nif [ -s /dev/stdin ]; then exit 7; fi\nexit 0\n",
    );
    fs::write(
        root.path().join("oreslang-test.toml"),
        format!(
            "[fuzz]\ncommand = ['{}']\nmax_bytes = 16\n",
            property.display()
        ),
    )
    .unwrap();
    let result = cli(root.path(), &["--fuzz", "--seed", "42", "--cases", "8"]);
    assert_eq!(result.status.code(), Some(1), "{:?}", result);
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(out.contains("FUZZ FAILURE"));
    assert!(out.contains("minimized=1"));
    let failures = root.path().join(".oreslang-test/failures");
    let names: Vec<_> = fs::read_dir(failures).unwrap().collect();
    assert_eq!(names.len(), 1);
    assert_eq!(
        fs::read(names[0].as_ref().unwrap().path()).unwrap().len(),
        1
    );
}

#[cfg(unix)]
#[test]
fn fuzz_timeouts_are_inconclusive_and_do_not_report_pass() {
    let root = tempfile::tempdir().unwrap();
    let property = guest(root.path(), "property", "#!/bin/sh\nsleep 5\nexit 0\n");
    fs::write(
        root.path().join("oreslang-test.toml"),
        format!(
            "[fuzz]\ncommand = ['{}']\nmax_bytes = 16\n",
            property.display()
        ),
    )
    .unwrap();
    let result = cli(
        root.path(),
        &["--fuzz", "--cases", "1", "--timeout", "0.02"],
    );
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
    fs::write(
        root.path().join("oreslang-test.toml"),
        format!(
            "[fuzz]\ncommand = ['{}']\ncorpus = 'link/subdir'\nmax_bytes = 32\n",
            property.display()
        ),
    )
    .unwrap();
    symlink(outside.path(), root.path().join("link")).unwrap();
    let traversal = cli(root.path(), &["--fuzz", "--cases", "1"]);
    assert_eq!(traversal.status.code(), Some(2), "{traversal:?}");
    fs::remove_file(root.path().join("link")).unwrap();
    fs::write(
        root.path().join("oreslang-test.toml"),
        format!(
            "[fuzz]\ncommand = ['{}']\ncorpus = 'seeds'\nmax_bytes = 32\n",
            property.display()
        ),
    )
    .unwrap();
    let failing = guest(root.path(), "failing-property", "#!/bin/sh\nexit 7\n");
    fs::write(
        root.path().join("oreslang-test.toml"),
        format!(
            "[fuzz]\ncommand = ['{}']\ncorpus = 'seeds'\nmax_bytes = 32\n",
            failing.display()
        ),
    )
    .unwrap();
    symlink(outside.path(), root.path().join(".oreslang-test")).unwrap();
    let unsafe_output = cli(root.path(), &["--fuzz", "--cases", "1"]);
    assert_eq!(unsafe_output.status.code(), Some(2), "{unsafe_output:?}");
    assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn security_fuzz_profile_injects_adversarial_cases_without_python() {
    let root = tempfile::tempdir().unwrap();
    let oracle = guest(
        root.path(),
        "path-oracle",
        "#!/bin/sh\ncase \"$(cat)\" in ../*) exit 7;; esac\nexit 0\n",
    );
    fs::write(
        root.path().join("oreslang-test.toml"),
        format!(
            "[fuzz]\ncommand = ['{}']\nmax_bytes = 64\n",
            oracle.display()
        ),
    )
    .unwrap();
    let result = cli(
        root.path(),
        &[
            "--fuzz",
            "--fuzz-profile",
            "security",
            "--cases",
            "1",
            "--seed",
            "9",
        ],
    );
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("FUZZ FAILURE"));
    assert_eq!(
        cli(root.path(), &["--fuzz-profile", "security"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        cli(root.path(), &["--fuzz", "--fuzz-profile", "unknown"])
            .status
            .code(),
        Some(2)
    );
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
    assert_eq!(
        cli(
            root.path(),
            &["--race", "--deadlock", "--trace", "waiting.jsonl"]
        )
        .status
        .code(),
        Some(2)
    );
}

#[cfg(unix)]
#[test]
fn machine_summary_with_no_executed_tests_cannot_pass() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tests")).unwrap();
    fs::write(root.path().join("tests/test_noop.ores"), "").unwrap();
    let compiler = guest(
        root.path(),
        "zero-test-compiler",
        "#!/bin/sh\nprintf 'ORES_TEST|SUMMARY|total=0|passed=0|failed=0|skipped=0|filtered=0\\n'\n",
    );
    let status = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("ORESLANG_BIN", compiler)
        .arg("--root")
        .arg(root.path())
        .output()
        .unwrap();
    assert_eq!(status.status.code(), Some(1), "{status:?}");
    assert!(String::from_utf8_lossy(&status.stderr).contains("zero tests"));
}

#[cfg(unix)]
#[test]
fn bare_path_alias_to_own_cli_cannot_invoke_recursively() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    symlink(
        env!("CARGO_BIN_EXE_oreslang-test"),
        root.path().join("loop-exec"),
    )
    .unwrap();
    fs::write(
        root.path().join("oreslang-test.toml"),
        "[fuzz]\ncommand = ['loop-exec']\nmax_bytes = 16\n",
    )
    .unwrap();
    let paths = std::env::join_paths([
        root.path(),
        std::path::Path::new("/usr/bin"),
        std::path::Path::new("/bin"),
    ])
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("PATH", paths)
        .arg("--root")
        .arg(root.path())
        .args(["--fuzz", "--cases", "1"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stderr).contains("recursion refused"));
}

#[test]
fn rust_logical_host_models_check_atomic_and_lost_updates() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("atomic.json"),
        include_str!("models/atomic-update.json"),
    )
    .unwrap();
    fs::write(
        root.path().join("lost.json"),
        include_str!("models/lost-update.json"),
    )
    .unwrap();

    let success = cli(
        root.path(),
        &["--race", "--logical", "--model", "atomic.json"],
    );
    assert_eq!(success.status.code(), Some(0), "{success:?}");
    assert!(String::from_utf8_lossy(&success.stdout).contains("host model only"));

    let failure = cli(
        root.path(),
        &["--race", "--logical", "--model", "lost.json"],
    );
    assert_eq!(failure.status.code(), Some(1), "{failure:?}");
    assert!(String::from_utf8_lossy(&failure.stdout).contains("LOGICAL COUNTEREXAMPLE"));

    let limited = cli(
        root.path(),
        &[
            "--race",
            "--logical",
            "--model",
            "atomic.json",
            "--max-schedules",
            "1",
        ],
    );
    assert_eq!(limited.status.code(), Some(2), "{limited:?}");
    assert!(String::from_utf8_lossy(&limited.stderr).contains("INCONCLUSIVE"));

    assert_eq!(
        cli(root.path(), &["--race", "--logical"]).status.code(),
        Some(2)
    );
    assert_eq!(
        cli(root.path(), &["--logical", "--model", "atomic.json"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        cli(root.path(), &["--race", "--model", "atomic.json"])
            .status
            .code(),
        Some(2)
    );
}

#[cfg(unix)]
#[test]
fn native_runner_refuses_skipped_duplicate_and_empty_case_receipts() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tests")).unwrap();
    fs::write(root.path().join("tests/test_receipts.ores"), "").unwrap();
    for receipt in [
        "ORES_TEST|SKIP|suite/off|reason\nORES_TEST|SUMMARY|total=1|passed=0|failed=0|skipped=1|filtered=0\n",
        "ORES_TEST|PASS|suite/same|first\nORES_TEST|PASS|suite/same|second\nORES_TEST|SUMMARY|total=2|passed=2|failed=0|skipped=0|filtered=0\n",
        "ORES_TEST|PASS||message\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\n",
    ] {
        let compiler = guest(root.path(), "receipt-compiler",
            &format!("#!/bin/sh\nprintf '%s' '{receipt}'\n"));
        let result = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
            .env("ORESLANG_BIN", compiler)
            .arg("--root").arg(root.path()).output().unwrap();
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert!(String::from_utf8_lossy(&result.stderr).contains("invalid machine receipt"));
        assert!(!String::from_utf8_lossy(&result.stdout).contains("PASS"));
    }
    // A real passed case may coexist with distinct skipped cases.
    let compiler = guest(root.path(), "receipt-compiler",
        "#!/bin/sh\nprintf 'ORES_TEST|PASS|suite/ok|\\nORES_TEST|SKIP|suite/off|reason\\nORES_TEST|SUMMARY|total=2|passed=1|failed=0|skipped=1|filtered=0\\n'\n");
    let result = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("ORESLANG_BIN", compiler)
        .arg("--root")
        .arg(root.path())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0), "{result:?}");
}

#[cfg(unix)]
fn fuzz_project(root: &Path, script: &str, extra: &str) {
    let target = guest(root, "target", script);
    // macOS assesses each newly written executable on first exec (~0.2 s
    // idle, seconds under parallel test load), and on Linux a sibling test
    // thread's fork can briefly hold our write descriptor (ETXTBSY). Warm
    // the target until one exec succeeds so the short fuzz timeouts below
    // measure the target, not the platform.
    for attempt in 0.. {
        match Command::new(&target)
            .current_dir(root)
            .stdin(std::process::Stdio::null())
            .output()
        {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempt < 100 => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => panic!("cannot warm fuzz target: {e}"),
        }
    }
    fs::write(
        root.join("atto-test.toml"),
        format!(
            "[fuzz]\ncommand = ['{}']\nmax_bytes = 16\n{extra}",
            target.display()
        ),
    )
    .unwrap();
}

// Regression: clean seeds were re-appended to the pool and the loop index
// never caught up, so only [], [0] and [255] were ever executed.
#[cfg(unix)]
#[test]
fn fuzz_executes_mutated_inputs_beyond_the_seed_pool() {
    let root = tempfile::tempdir().unwrap();
    // Every built-in seed is at most one byte; only a mutation can fail.
    fuzz_project(
        root.path(),
        "#!/bin/sh\n[ \"$(wc -c | tr -d ' ')\" -ge 2 ] && exit 9\nexit 0\n",
        "",
    );
    let result = cli(root.path(), &["--fuzz", "--seed", "42", "--cases", "64"]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("finding=Exit(9)"));

    let clean = tempfile::tempdir().unwrap();
    fuzz_project(clean.path(), "#!/bin/sh\ncat > /dev/null\nexit 0\n", "");
    let pass = cli(clean.path(), &["--fuzz", "--seed", "42", "--cases", "20"]);
    assert_eq!(pass.status.code(), Some(0), "{pass:?}");
    assert!(String::from_utf8_lossy(&pass.stdout).contains("seeds=3 mutated=17"));
}

#[cfg(unix)]
#[test]
fn fuzz_targets_echoing_binary_input_are_not_infrastructure_errors() {
    for script in ["#!/bin/sh\ncat\n", "#!/bin/sh\ncat >&2\n"] {
        let root = tempfile::tempdir().unwrap();
        fuzz_project(root.path(), script, "");
        let result = cli(root.path(), &["--fuzz", "--seed", "3", "--cases", "40"]);
        assert_eq!(result.status.code(), Some(0), "{script}: {result:?}");
    }
}

#[cfg(unix)]
#[test]
fn fuzz_crash_signal_is_a_minimized_reproducible_defect() {
    let root = tempfile::tempdir().unwrap();
    fuzz_project(
        root.path(),
        "#!/bin/sh\n[ -s /dev/stdin ] && kill -SEGV $$\nexit 0\n",
        "",
    );
    let result = cli(root.path(), &["--fuzz", "--seed", "1", "--cases", "4"]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(out.contains("finding=Signal(11)"), "{out}");
    assert!(out.contains("minimized=1"), "{out}");
}

// A reduced input that hangs must not erase an already-confirmed defect.
#[cfg(unix)]
#[test]
fn fuzz_minimization_survives_hanging_reduced_inputs() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("tests/corpus")).unwrap();
    fs::write(root.path().join("tests/corpus/seed.bin"), b"AAAAAAAA").unwrap();
    fuzz_project(
        root.path(),
        "#!/bin/sh\nn=$(wc -c | tr -d ' ')\n[ \"$n\" -ge 4 ] && exit 3\n[ \"$n\" -ge 2 ] && sleep 5\nexit 0\n",
        "",
    );
    let result = cli(
        root.path(),
        &["--fuzz", "--seed", "1", "--cases", "4", "--timeout", "1"],
    );
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains("finding=Exit(3) initial=8 minimized=4"),
        "{out}"
    );
}


// End-to-end boundary checks prove that success cannot be reported merely
// because a small run replayed its initial clean seeds.
#[cfg(unix)]
#[test]
fn fuzz_seed_only_runs_are_inconclusive_until_a_mutation_executes() {
    for (cases, expected, exit) in [
        ("1", "seeds=1 mutated=0", 2),
        ("3", "seeds=3 mutated=0", 2),
        ("4", "seeds=3 mutated=1", 0),
    ] {
        let root = tempfile::tempdir().unwrap();
        fuzz_project(root.path(), "#!/bin/sh\ncat > /dev/null\nexit 0\n", "");
        let run = cli(root.path(), &["--fuzz", "--seed", "123", "--cases", cases]);
        assert_eq!(run.status.code(), Some(exit), "{cases}: {run:?}");
        let stdout = String::from_utf8_lossy(&run.stdout);
        let stderr = String::from_utf8_lossy(&run.stderr);
        if exit == 2 {
            assert!(stderr.contains("FUZZ INCONCLUSIVE"), "{cases}: {stderr}");
            assert!(stderr.contains(expected), "{cases}: {stderr}");
            assert!(!stdout.contains("FUZZ PASS"), "{cases}: {stdout}");
        } else {
            assert!(stdout.contains("FUZZ PASS"), "{cases}: {stdout}");
            assert!(stdout.contains(expected), "{cases}: {stdout}");
        }
    }
}

#[cfg(unix)]
#[test]
fn fuzz_noncrash_signal_is_inconclusive_without_failure_artifact() {
    let root = tempfile::tempdir().unwrap();
    fuzz_project(
        root.path(),
        "#!/bin/sh\nif [ -s /dev/stdin ]; then kill -TERM $$; fi\nexit 0\n",
        "",
    );
    let run = cli(root.path(), &["--fuzz", "--seed", "9", "--cases", "3"]);
    assert_eq!(run.status.code(), Some(2), "{run:?}");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!stdout.contains("FUZZ PASS"), "{stdout}");
    assert!(stderr.contains("FUZZ INCONCLUSIVE"), "{stderr}");
    assert!(!root.path().join(".oreslang-test/failures").exists());
}

#[cfg(unix)]
#[test]
fn fuzz_runaway_output_is_inconclusive_not_a_reproducer() {
    let root = tempfile::tempdir().unwrap();
    fuzz_project(
        root.path(),
        "#!/bin/sh\nhead -c 5000000 /dev/zero\n",
        "",
    );
    let run = cli(root.path(), &["--fuzz", "--seed", "9", "--cases", "1"]);
    assert_eq!(run.status.code(), Some(2), "{run:?}");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!stdout.contains("FUZZ PASS"), "{stdout}");
    assert!(stderr.contains("FUZZ INCONCLUSIVE"), "{stderr}");
    assert!(!root.path().join(".oreslang-test/failures").exists());
}

#[cfg(unix)]
#[test]
fn fuzz_inconclusive_exit_code_does_not_create_failure_receipt() {
    let root = tempfile::tempdir().unwrap();
    fuzz_project(
        root.path(),
        "#!/bin/sh\ncat >/dev/null\nexit 9\n",
        "inconclusive_exits = [9]\n",
    );
    let run = cli(root.path(), &["--fuzz", "--seed", "11", "--cases", "1"]);
    assert_eq!(run.status.code(), Some(2), "{run:?}");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains("FUZZ INCONCLUSIVE"), "{stderr}");
    assert!(!root.path().join(".oreslang-test/failures").exists());
}

#[cfg(unix)]
#[test]
fn fuzz_sanitizer_report_outweighs_configured_inconclusive_exit() {
    let root = tempfile::tempdir().unwrap();
    fuzz_project(
        root.path(),
        "#!/bin/sh\necho 'src/demo.c:2:3: runtime error: signed integer overflow' >&2\nexit 9\n",
        "inconclusive_exits = [9]\n",
    );
    let run = cli(root.path(), &["--fuzz", "--seed", "11", "--cases", "1"]);
    assert_eq!(run.status.code(), Some(1), "{run:?}");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains("Sanitizer(\"UBSan\")"), "{stdout}");
}

#[cfg(unix)]
#[test]
fn fuzz_go_style_panic_text_does_not_spoof_ubsan() {
    let root = tempfile::tempdir().unwrap();
    fuzz_project(
        root.path(),
        "#!/bin/sh\necho 'panic: runtime error: index out of range' >&2\ncat >/dev/null\nexit 0\n",
        "",
    );
    let run = cli(root.path(), &["--fuzz", "--seed", "5", "--cases", "4"]);
    assert_eq!(run.status.code(), Some(0), "{run:?}");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains("FUZZ PASS"), "{stdout}");
}
