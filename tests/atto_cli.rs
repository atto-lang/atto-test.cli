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
