//! Executable CLI regressions without any Python runtime dependency.
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_oreslang-test")
}

fn invoke(root: &Path, args: &[&str]) -> Output {
    Command::new(binary())
        .arg("--root")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
}

fn write(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

#[test]
fn fixture_race_and_model_contracts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(
        code(&invoke(
            root,
            &["--race", "--trace", "tests/traces/ordered.jsonl"]
        )),
        0
    );
    assert_eq!(
        code(&invoke(
            root,
            &["--race", "--trace", "tests/traces/racy.jsonl"]
        )),
        1
    );
    assert_eq!(
        code(&invoke(
            root,
            &[
                "--model-check",
                "--model",
                "tests/models/atomic-update.json",
            ]
        )),
        0
    );
    assert_eq!(
        code(&invoke(
            root,
            &["--model-check", "--model", "tests/models/lost-update.json"]
        )),
        1
    );
    assert_eq!(code(&invoke(root, &["--race"])), 2); // no instrumentation
}

#[test]
fn check_fails_closed_without_real_parser() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("unit.ores"), "fnc test() {}");
    assert_eq!(code(&invoke(dir.path(), &["--check", "unit.ores"])), 2);
}

#[test]
fn check_rejects_untrusted_project_local_compiler_even_with_matching_receipt() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("unit.ores"), "fnc test() {}");
    write(
        &dir.path().join("check.sh"),
        r#"#!/bin/sh
digest=$(sha256sum "$2" | cut -d ' ' -f1)
echo "ORES_CHECK|PASS|sha256=$digest|phase=syntax-only"
"#,
    );
    write(
        &dir.path().join("oreslang-test.toml"),
        "[check]\ncommand=[\"sh\",\"check.sh\"]\n",
    );
    // A project-local script must never certify syntax, regardless of receipt.
    let result = invoke(dir.path(), &["--check", "unit.ores"]);
    assert_eq!(code(&result), 2);
    write(
        &dir.path().join("oreslang-test.toml"),
        "[check]\ncommand=[\"/bin/sh\"]\n",
    );
    // An absolute unpinned shell is still not an independently trusted parser.
    let result = invoke(dir.path(), &["--check", "unit.ores"]);
    assert_eq!(code(&result), 2);
}

#[test]
fn fuzz_success_and_missing_command() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(code(&invoke(dir.path(), &["--fuzz", "--cases", "3"])), 2);
    write(
        &dir.path().join("pass.sh"),
        "#!/bin/sh\ncat >/dev/null\nexit 0\n",
    );
    write(
        &dir.path().join("oreslang-test.toml"),
        "[fuzz]\ncommand=[\"sh\",\"pass.sh\"]\n",
    );
    assert_eq!(
        code(&invoke(
            dir.path(),
            &["--fuzz", "--cases", "8", "--seed", "42"]
        )),
        0
    );
}

#[test]
fn fuzz_rejects_oversized_and_non_file_corpus_entries() {
    let project = tempfile::tempdir().unwrap();
    let corpus = project.path().join("corpus");
    fs::create_dir_all(&corpus).unwrap();
    write(
        &project.path().join("oreslang-test.toml"),
        "[fuzz]\ncommand=[\"sh\",\"-c\",\"cat >/dev/null\"]\ncorpus=\"corpus\"\nmax_bytes=4\n",
    );
    fs::write(corpus.join("too-large.bin"), b"12345").unwrap();
    let result = invoke(project.path(), &["--fuzz", "--cases", "1"]);
    assert_eq!(code(&result), 2);
    assert!(String::from_utf8_lossy(&result.stderr).contains("exceeds max_bytes"));

    fs::remove_file(corpus.join("too-large.bin")).unwrap();
    fs::create_dir(corpus.join("nested")).unwrap();
    let result = invoke(project.path(), &["--fuzz", "--cases", "1"]);
    assert_eq!(code(&result), 2);
    assert!(String::from_utf8_lossy(&result.stderr).contains("not a regular file"));
}

#[test]
fn deadlock_lock_order_cycle_is_failure() {
    let dir = tempfile::tempdir().unwrap();
    let ops = [
        r#"{"op":"task","task":"a"}"#,
        r#"{"op":"task","task":"b"}"#,
        r#"{"op":"lock","task":"a","name":"x"}"#,
        r#"{"op":"lock","task":"a","name":"y"}"#,
        r#"{"op":"unlock","task":"a","name":"y"}"#,
        r#"{"op":"unlock","task":"a","name":"x"}"#,
        r#"{"op":"lock","task":"b","name":"y"}"#,
        r#"{"op":"lock","task":"b","name":"x"}"#,
        r#"{"op":"unlock","task":"b","name":"x"}"#,
        r#"{"op":"unlock","task":"b","name":"y"}"#,
    ];
    let mut rows =
        vec![r#"{"op":"begin","version":1,"run_id":"fixture","backend":"test"}"#.to_owned()];
    rows.extend(ops.iter().map(|s| s.to_string()));
    rows.push(format!(
        r#"{{"op":"end","run_id":"fixture","events":{}}}"#,
        ops.len()
    ));
    write(&dir.path().join("events.jsonl"), &(rows.join("\n") + "\n"));
    assert_eq!(
        code(&invoke(
            dir.path(),
            &["--deadlock", "--trace", "events.jsonl"]
        )),
        1
    );
}

#[test]
fn scheduling_requires_real_case_receipts() {
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir.path().join("run.sh"),
        r#"#!/bin/sh
echo "ORES_TEST|PASS|suite/case|"
echo "ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0"
echo "ORES_CONCURRENCY|RUN|seed=7|events=2|deadlocks=0|schedule=perturbed|race_coverage=none"
"#,
    );
    write(
        &dir.path().join("oreslang-test.toml"),
        "[schedule]\ncommand=[\"sh\",\"run.sh\"]\n",
    );
    assert_eq!(
        code(&invoke(dir.path(), &["--schedule-fuzz", "--seed", "7"])),
        0
    );
    write(
        &dir.path().join("run.sh"),
        "#!/bin/sh\necho 'ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0'\n",
    );
    assert_eq!(
        code(&invoke(dir.path(), &["--schedule-fuzz", "--seed", "7"])),
        1
    );
}

#[test]
fn rejects_orphan_output_pipe_and_forged_clean_native_summary() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("tests")).unwrap();
    write(
        &dir.path().join("tests/test_orphan.ores"),
        r#"#!/bin/sh
sleep 4 &
echo "ORES_TEST|PASS|suite/case|"
echo "ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0"
exit 0
"#,
    );
    let manifest = String::from("[native]\nfiles=[\"tests/test_orphan.ores\"]\n");
    write(&dir.path().join("oreslang-test.toml"), &manifest);
    let output = Command::new(binary())
        .arg("--root")
        .arg(dir.path())
        .arg("--timeout")
        .arg("10")
        .env("ORESLANG_BIN", "sh")
        .output()
        .unwrap();
    // An orphaned process still holding pipes can never certify success.
    assert_eq!(code(&output), 2);
}

#[cfg(unix)]
#[test]
fn native_test_discovery_rejects_symlinked_entries() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("tests")).unwrap();
    write(
        &dir.path().join("tests/test_ok.ores"),
        "// valid source for discovery",
    );
    symlink(
        dir.path().join("tests/test_ok.ores"),
        dir.path().join("tests/test_alias.ores"),
    )
    .unwrap();
    let result = invoke(dir.path(), &[]);
    assert_eq!(
        code(&result),
        2,
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("symlink"));
}

#[test]
fn malformed_or_oversized_manifest_never_passes() {
    let project = tempfile::tempdir().unwrap();
    let manifest = project.path().join("oreslang-test.toml");
    fs::write(&manifest, vec![b'x'; 1_048_577]).unwrap();
    assert_eq!(code(&invoke(project.path(), &["--race"])), 2);
    fs::write(&manifest, "[fuzz]\ncommand = [\"sh\"]\n").unwrap();
    assert_eq!(
        code(&invoke(project.path(), &["--fuzz", "--cases", "0"])),
        2
    );
}

#[cfg(unix)]
#[test]
fn config_symlink_cannot_be_used_to_influence_runner() {
    use std::os::unix::fs::symlink;
    let project = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(outside.path(), "[fuzz]\ncommand=[\"sh\"]\n").unwrap();
    symlink(outside.path(), project.path().join("oreslang-test.toml")).unwrap();
    assert_eq!(
        code(&invoke(project.path(), &["--fuzz", "--cases", "1"])),
        2
    );
}

// A host-only runner-discovery test: shell prints test-shaped output but
// does NOT compile or execute an AttoLang guest. No guest support is certified.
#[test]
fn native_auto_discovers_atto_and_does_not_auto_choose_legacy_twin() {
    let project = tempfile::tempdir().unwrap();
    let dir = project.path().join("tests");
    fs::create_dir_all(&dir).unwrap();
    write(
        &dir.join("test_math.atto"),
        "echo 'ORES_TEST|PASS|math/add|'\necho 'ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0'\n",
    );
    write(
        &dir.join("test_math.ores"),
        "echo 'UNEXPECTED_LEGACY_TEST_EXECUTION'\nexit 9\n",
    );
    let output = Command::new(binary())
        .arg("--root")
        .arg(project.path())
        .env("ORESLANG_BIN", "sh")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS tests/test_math.atto:"));
    assert!(!stdout.contains("UNEXPECTED_LEGACY_TEST_EXECUTION"));
}

#[cfg(unix)]
#[test]
fn canonical_atto_test_launcher_delegates_to_rust_cli() {
    let project = tempfile::tempdir().unwrap();
    fs::create_dir_all(project.path().join("tests")).unwrap();
    write(
        &project.path().join("tests/test_dispatch.atto"),
        "echo 'ORES_TEST|PASS|suite/one|'\necho 'ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0'\n",
    );
    let launcher = Path::new(env!("CARGO_MANIFEST_DIR")).join("bin/atto");
    let output = Command::new(launcher)
        .arg("test")
        .arg("--root")
        .arg(project.path())
        .env("ORESLANG_TEST_BIN", binary())
        .env("ORESLANG_BIN", "sh")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("PASS tests/test_dispatch.atto:"));
}

#[test]
fn native_rejects_duplicate_receipts_even_with_matching_summary() {
    let project = tempfile::tempdir().unwrap();
    let dir = project.path().join("tests");
    fs::create_dir_all(&dir).unwrap();
    write(
        &dir.join("test_dup.atto"),
        "echo 'ORES_TEST|PASS|suite/same|'\necho 'ORES_TEST|PASS|suite/same|'\necho 'ORES_TEST|SUMMARY|total=2|passed=2|failed=0|skipped=0|filtered=0'\n",
    );
    let output = Command::new(binary())
        .arg("--root")
        .arg(project.path())
        .env("ORESLANG_BIN", "sh")
        .output()
        .unwrap();
    assert_eq!(code(&output), 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate test case identity"));
}

#[test]
fn native_summary_integer_overflow_fails_without_panicking() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("tests")).unwrap();
    write(&dir.path().join("tests/test_counts.ores"), &format!(
        "echo 'ORES_TEST|PASS|suite/case|'\necho 'ORES_TEST|SUMMARY|total=1|passed={}|failed={}|skipped=1|filtered=0'\n",
        usize::MAX,
        usize::MAX
    ));
    write(
        &dir.path().join("oreslang-test.toml"),
        "[native]\nfiles=[\"tests/test_counts.ores\"]\n",
    );
    let output = Command::new(binary())
        .arg("--root")
        .arg(dir.path())
        .env("ORESLANG_BIN", "sh")
        .output()
        .unwrap();
    assert_eq!(
        code(&output),
        1,
        "malformed child test counts must fail, not panic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn logical_model_rejects_nested_and_top_level_duplicate_json_keys() {
    let project = tempfile::tempdir().unwrap();
    let cases = [
        r#"{"initial":{"counter":0,"counter":1},"expected":{"counter":1},"actors":[]}"#,
        r#"{"initial":{"counter":0},"initial":{"counter":1},"expected":{"counter":1},"actors":[]}"#,
    ];
    for document in cases {
        write(&project.path().join("model.json"), document);
        let output = invoke(project.path(), &["--model-check", "--model", "model.json"]);
        assert_eq!(code(&output), 2);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("duplicate JSON property"),
            "unexpected validation error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
