//! Host fixture checks only: these do not assert guest compiler or sanitizer coverage.
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::Path;
use std::process::{Command, Output};

fn invoke(binary: &str, args: &[&str]) -> Output {
    Command::new(binary).args(args).output().unwrap()
}

#[test]
fn four_entrypoints_admit_atto_help_and_fail_closed_race() {
    for (binary, direct) in [
        (env!("CARGO_BIN_EXE_atto"), false),
        (env!("CARGO_BIN_EXE_atto-test"), true),
        (env!("CARGO_BIN_EXE_oreslang"), false),
        (env!("CARGO_BIN_EXE_oreslang-test"), true),
    ] {
        let help_args: &[&str] = if direct {
            &["--help"]
        } else {
            &["test", "--help"]
        };
        let help = invoke(binary, help_args);
        assert_eq!(help.status.code(), Some(0), "{binary}: {help:?}");
        assert!(String::from_utf8_lossy(&help.stdout).contains("usage: atto test"));

        let race_args: &[&str] = if direct {
            &["--race"]
        } else {
            &["test", "--race"]
        };
        let race = invoke(binary, race_args);
        assert_eq!(race.status.code(), Some(2), "{binary}: {race:?}");
    }
}

#[cfg(unix)]
fn guest(root: &Path, name: &str, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join(name);
    fs::write(&path, body).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&path, perms).unwrap();
    path
}

#[cfg(unix)]
fn native(root: &Path, compiler: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_atto-test"))
        .arg("--root")
        .arg(root)
        .env("ORESLANG_BIN", compiler)
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn atto_and_legacy_sources_discover_but_two_manifests_are_ambiguous() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tests")).unwrap();
    for name in ["test_new.atto", "old_test.ores"] {
        fs::write(root.path().join("tests").join(name), "").unwrap();
    }
    let compiler = guest(
        root.path(),
        "compiler",
        r#"#!/bin/sh
printf 'ORES_TEST|PASS|ok\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\n'
"#,
    );
    let first = native(root.path(), &compiler);
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(stdout.contains("test_new.atto"), "{stdout}");
    assert!(stdout.contains("old_test.ores"), "{stdout}");

    fs::write(
        root.path().join("atto-test.toml"),
        "[native]\nfiles=['tests/test_new.atto']\n",
    )
    .unwrap();
    let canonical = native(root.path(), &compiler);
    assert_eq!(canonical.status.code(), Some(0), "{canonical:?}");
    fs::write(
        root.path().join("oreslang-test.toml"),
        "[native]\nfiles=['tests/old_test.ores']\n",
    )
    .unwrap();
    let ambiguous = native(root.path(), &compiler);
    assert_eq!(ambiguous.status.code(), Some(2), "{ambiguous:?}");
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("ambiguous test manifests"));
}

#[cfg(unix)]
#[test]
fn ubsan_recoverable_diagnostic_does_not_make_atto_fuzz_green() {
    let root = tempfile::tempdir().unwrap();
    let target = guest(
        root.path(),
        "ubsan",
        r#"#!/bin/sh
echo 'fixture.c:1:2: runtime error: signed integer overflow' >&2
exit 0
"#,
    );
    fs::write(
        root.path().join("atto-test.toml"),
        format!("[fuzz]\ncommand=['{}']\nmax_bytes=8\n", target.display()),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_atto"))
        .arg("test")
        .arg("--root")
        .arg(root.path())
        .args(["--fuzz", "--cases", "1", "--seed", "7"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("FUZZ FAILURE"));
}

#[cfg(unix)]
#[test]
fn observed_asan_failure_overrides_a_valid_native_guest_receipt() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tests")).unwrap();
    fs::write(root.path().join("tests/test_memory.atto"), "").unwrap();
    let target = guest(
        root.path(),
        "asan",
        r#"#!/bin/sh
printf 'ORES_TEST|PASS|ok\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\n'
echo 'ERROR: AddressSanitizer: heap-use-after-free' >&2
exit 0
"#,
    );
    let output = native(root.path(), &target);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PASS"));
}

#[cfg(unix)]
#[test]
fn tsan_initialization_failure_is_inconclusive() {
    let root = tempfile::tempdir().unwrap();
    let target = guest(
        root.path(),
        "tsan",
        r#"#!/bin/sh
echo 'FATAL: ThreadSanitizer: unexpected memory mapping' >&2
exit 66
"#,
    );
    fs::write(
        root.path().join("atto-test.toml"),
        format!("[fuzz]\ncommand=['{}']\nmax_bytes=8\n", target.display()),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_atto-test"))
        .arg("--root")
        .arg(root.path())
        .args(["--fuzz", "--cases", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}


#[cfg(unix)]
#[test]
fn llvm_native_adapter_inconclusive_exit_never_becomes_a_fuzz_defect() {
    let root = tempfile::tempdir().unwrap();
    let target = guest(
        root.path(),
        "native-adapter",
        "#!/bin/sh\nprintf 'ATTO_LLVM_FUZZ_INCONCLUSIVE input budget exceeded\\n' >&2\nexit 2\n",
    );
    fs::write(
        root.path().join("atto-test.toml"),
        format!(
            "[fuzz]\ncommand=['{}']\nmax_bytes=16\ninconclusive_exits=[2]\n",
            target.display()
        ),
    )
    .unwrap();
    let report = Command::new(env!("CARGO_BIN_EXE_atto-test"))
        .arg("--root")
        .arg(root.path())
        .args(["--fuzz", "--seed", "1729", "--cases", "4"])
        .output()
        .unwrap();
    assert_eq!(report.status.code(), Some(2), "{report:?}");
    assert!(
        String::from_utf8_lossy(&report.stderr).contains("exit 2 is inconclusive"),
        "{report:?}"
    );
    assert!(
        !String::from_utf8_lossy(&report.stdout).contains("FUZZ FAILURE"),
        "{report:?}"
    );
    assert!(!root.path().join(".oreslang-test/failures").exists());
}

#[cfg(unix)]
#[test]
fn llvm_native_adapter_real_defect_and_sanitizer_override_inconclusive_policy() {
    let root = tempfile::tempdir().unwrap();
    let target = guest(root.path(), "native-adapter", "#!/bin/sh\nexit 77\n");
    let manifest = root.path().join("atto-test.toml");
    let config = || {
        format!(
            "[fuzz]\ncommand=['{}']\nmax_bytes=16\ninconclusive_exits=[2]\n",
            target.display()
        )
    };
    fs::write(&manifest, config()).unwrap();
    let cli = |root: &Path| {
        Command::new(env!("CARGO_BIN_EXE_atto-test"))
            .arg("--root")
            .arg(root)
            .args(["--fuzz", "--cases", "1", "--seed", "1729"])
            .output()
            .unwrap()
    };
    let bug = cli(root.path());
    assert_eq!(bug.status.code(), Some(1), "{bug:?}");
    assert!(
        String::from_utf8_lossy(&bug.stdout).contains("FUZZ FAILURE"),
        "{bug:?}"
    );
    // A sanitizer finding is a concrete observed defect even if its program
    // exits with a configured infrastructure status.
    fs::write(
        &target,
        "#!/bin/sh\nprintf 'ERROR: AddressSanitizer: heap-use-after-free\\n' >&2\nexit 2\n",
    )
    .unwrap();
    let sanitizer = cli(root.path());
    assert_eq!(sanitizer.status.code(), Some(1), "{sanitizer:?}");
    assert!(
        String::from_utf8_lossy(&sanitizer.stdout).contains("Sanitizer(\"ASan\")"),
        "{sanitizer:?}"
    );
}

#[cfg(unix)]
#[test]
fn fuzz_shrinking_does_not_erase_a_confirmed_defect_when_reduced_input_is_inconclusive() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("tests/corpus")).unwrap();
    fs::write(root.path().join("tests/corpus/seed.bin"), b"x").unwrap();
    let target = guest(
        root.path(),
        "native-adapter",
        // The default first case is empty. Admit that one as clean, then
        // make all subsequent empty reductions inconclusive. The second
        // seed (one NUL byte) is a stable real defect and must be saved.
        "#!/bin/sh\nbytes=$(wc -c | tr -d ' ')\nif [ \"$bytes\" -eq 0 ]; then\n  if [ ! -f .empty-seen ]; then : > .empty-seen; exit 0; fi\n  exit 2\nfi\nexit 77\n",
    );
    fs::write(
        root.path().join("atto-test.toml"),
        format!(
            "[fuzz]\ncommand=['{}']\ncorpus='tests/corpus'\nmax_bytes=16\ninconclusive_exits=[2]\n",
            target.display()
        ),
    )
    .unwrap();

    let report = Command::new(env!("CARGO_BIN_EXE_atto-test"))
        .arg("--root")
        .arg(root.path())
        .args(["--fuzz", "--seed", "1729", "--cases", "2"])
        .output()
        .unwrap();

    assert_eq!(report.status.code(), Some(1), "{report:?}");
    let stdout = String::from_utf8_lossy(&report.stdout);
    assert!(stdout.contains("FUZZ FAILURE"), "{report:?}");
    assert!(stdout.contains("finding=Exit(77)"), "{report:?}");
    let failures = root.path().join(".oreslang-test/failures");
    assert!(failures.is_dir(), "confirmed defect must retain a reproducer");
    let saved: Vec<_> = fs::read_dir(&failures)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(saved.len(), 1, "unexpected reproducer cardinality");
    assert_eq!(fs::read(&saved[0]).unwrap(), b"\0");
}

#[cfg(unix)]
#[test]
fn fuzz_inconclusive_policy_rejects_ambiguous_codes_before_execution() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("executed");
    let target = guest(
        root.path(),
        "candidate",
        &format!("#!/bin/sh\nprintf yes > '{}'\nexit 0\n", marker.display()),
    );
    let config_path = root.path().join("atto-test.toml");
    for input in ["[]", "[0]", "[256]", "[2, 2]", "['2']", "2", "[1, -1]"] {
        fs::write(
            &config_path,
            format!(
                "[fuzz]\ncommand=['{}']\nmax_bytes=8\ninconclusive_exits={input}\n",
                target.display()
            ),
        )
        .unwrap();
        let verdict = Command::new(env!("CARGO_BIN_EXE_atto-test"))
            .arg("--root")
            .arg(root.path())
            .args(["--fuzz", "--cases", "1"])
            .output()
            .unwrap();
        assert_eq!(verdict.status.code(), Some(2), "{input} {verdict:?}");
        assert!(!marker.exists(), "invalid policy executed target: {input}");
    }
}
