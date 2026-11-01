//! Executable host-only abuse tests for the Rust CLI and synthetic receipt producer.
//! This does not compile or run actual Oreslang guest programs.
#![cfg(unix)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

const SUCCESS: &str = concat!(
    "ORES_TEST_V2|RUN_BEGIN|2\n",
    "ORES_TEST_V2|CASE_BEGIN|async\n",
    "ORES_TEST_V2|OPEN|async|callback|cb\n",
    "ORES_TEST_V2|OPEN|async|task|task\n",
    "ORES_TEST_V2|OPEN|async|actor|actor\n",
    "ORES_TEST_V2|OPEN|async|await|wait\n",
    "ORES_TEST_V2|CLOSE|async|await|wait|ok\n",
    "ORES_TEST_V2|CLOSE|async|callback|cb|ok\n",
    "ORES_TEST_V2|CLOSE|async|actor|actor|ok\n",
    "ORES_TEST_V2|CLOSE|async|task|task|ok\n",
    "ORES_TEST_V2|CASE_END|async|PASS\n",
    "ORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\n"
);

fn run_script(root: &Path, script: &str, args: &[&str]) -> Output {
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(root.join("tests/test_async.ores"), "/* intentionally synthetic */").unwrap();
    fs::write(root.join("oreslang-test.toml"), "[native]\nreceipt='lifecycle-v2'\n").unwrap();
    let script_path = root.join("synthetic-oreslang-compiler");
    fs::write(&script_path, script).unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();
    Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("ORESLANG_BIN", &script_path)
        .arg("--root")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
}

fn print_receipt(body: &str) -> String {
    format!("#!/bin/sh\ncat <<'NATIVE_RECEIPT'\n{body}NATIVE_RECEIPT\n")
}

#[test]
fn complete_async_receipt_is_rejected_if_guest_exits_nonzero() {
    let root = tempfile::tempdir().unwrap();
    let source = format!("{}exit 7\n", print_receipt(SUCCESS));
    let run = run_script(root.path(), &source, &[]);
    assert_eq!(run.status.code(), Some(1), "{run:?}");
    assert!(!String::from_utf8_lossy(&run.stdout).contains("PASS tests"));
}

#[test]
fn complete_async_receipt_is_rejected_on_timeout() {
    let root = tempfile::tempdir().unwrap();
    let source = format!("{}sleep 3\n", print_receipt(SUCCESS));
    let run = run_script(root.path(), &source, &["--timeout", "0.02"]);
    assert_eq!(run.status.code(), Some(1), "{run:?}");
    assert!(String::from_utf8_lossy(&run.stderr).contains("timed_out=true"));
}

#[test]
fn late_callbacks_cannot_replace_missing_close_records() {
    let root = tempfile::tempdir().unwrap();
    let missing = SUCCESS.replace("ORES_TEST_V2|CLOSE|async|callback|cb|ok\n", "");
    let source = print_receipt(&missing);
    let run = run_script(root.path(), &source, &[]);
    assert_eq!(run.status.code(), Some(1), "{run:?}");
    assert!(String::from_utf8_lossy(&run.stderr).contains("invalid machine receipt"));
}

#[test]
fn trailing_incomplete_machine_prefix_is_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    for prefix in ["ORES_TEST", "ORES_TEST_V2", "ORES_TEST|PASS|x"] {
        let source = print_receipt(&format!("{SUCCESS}{prefix}\n"));
        let run = run_script(root.path(), &source, &[]);
        assert_eq!(run.status.code(), Some(1), "accepted {prefix}: {run:?}");
    }
}

#[test]
fn ordinary_logging_does_not_break_a_complete_receipt() {
    let root = tempfile::tempdir().unwrap();
    let source = print_receipt(&format!("ordinary guest log\n{SUCCESS}more diagnostic lines\n"));
    let run = run_script(root.path(), &source, &[]);
    assert_eq!(run.status.code(), Some(0), "{run:?}");
}

#[test]
fn an_excessive_output_capture_cannot_be_reported_as_pass() {
    let root = tempfile::tempdir().unwrap();
    // Test process output is bounded independently of lifecycle receipts.
    let source = "#!/bin/sh\nhead -c 4200000 /dev/zero\n";
    let run = run_script(root.path(), source, &[]);
    assert_eq!(run.status.code(), Some(2), "{run:?}");
    assert!(String::from_utf8_lossy(&run.stderr).contains("output limit exceeded"));
}

#[test]
fn a_cleanly_exiting_parent_cannot_leave_a_late_descendant_writer() {
    let root = tempfile::tempdir().unwrap();
    let source = format!(
        "#!/bin/sh\n(sleep 1; printf 'late' > late_writer) &\n{}",
        print_receipt(SUCCESS).trim_start_matches("#!/bin/sh\n")
    );
    let run = run_script(root.path(), &source, &[]);
    assert_eq!(run.status.code(), Some(0), "{run:?}");
    thread::sleep(Duration::from_millis(1200));
    assert!(!root.path().join("late_writer").exists(), "unreaped guest descendant wrote after PASS");
}

#[test]
fn timeout_cannot_leave_a_late_descendant_writer() {
    let root = tempfile::tempdir().unwrap();
    let source = "#!/bin/sh\n(sleep 1; printf 'late' > late_timeout_writer) &\nsleep 3\n";
    let run = run_script(root.path(), source, &["--timeout", "0.02"]);
    assert_eq!(run.status.code(), Some(1), "{run:?}");
    thread::sleep(Duration::from_millis(1200));
    assert!(!root.path().join("late_timeout_writer").exists(), "timeout did not kill guest descendants");
}
