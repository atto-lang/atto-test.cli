//! Host-only end-to-end tests of synthetic guest lifecycle receipts.
//! No native Oreslang compiler or task runtime is exercised here.
#![cfg(unix)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

const V2: &str = "ORES_TEST_V2|RUN_BEGIN|2\nORES_TEST_V2|CASE_BEGIN|suite/async\nORES_TEST_V2|OPEN|suite/async|callback|cb\nORES_TEST_V2|OPEN|suite/async|task|task\nORES_TEST_V2|OPEN|suite/async|actor|actor\nORES_TEST_V2|OPEN|suite/async|await|aw\nORES_TEST_V2|CLOSE|suite/async|await|aw|ok\nORES_TEST_V2|CLOSE|suite/async|callback|cb|ok\nORES_TEST_V2|CLOSE|suite/async|task|task|ok\nORES_TEST_V2|CLOSE|suite/async|actor|actor|ok\nORES_TEST_V2|CASE_END|suite/async|PASS\nORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\n";
const V1: &str =
    "ORES_TEST|PASS|suite/sync\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\n";

fn invoke(root: &Path, receipt: &str, config: &str) -> Output {
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/test_async.ores"),
        "/* synthetic fixture */",
    )
    .unwrap();
    fs::write(root.join("oreslang-test.toml"), config).unwrap();
    let guest = root.join("synthetic-guest");
    fs::write(
        &guest,
        format!("#!/bin/sh\ncat <<'RECEIPT'\n{receipt}RECEIPT\n"),
    )
    .unwrap();
    let mut permissions = fs::metadata(&guest).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&guest, permissions).unwrap();
    Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .arg("--root")
        .arg(root)
        .env("ORESLANG_BIN", &guest)
        .output()
        .unwrap()
}

#[test]
fn strict_v2_accepts_complete_guest_records() {
    let dir = tempfile::tempdir().unwrap();
    let result = invoke(dir.path(), V2, "[native]\nreceipt='lifecycle-v2'\n");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("PASS"));
}

#[test]
fn strict_v2_rejects_early_pass_and_legacy_receipt() {
    let dir = tempfile::tempdir().unwrap();
    for fixture in [
        V2.replace("ORES_TEST_V2|CLOSE|suite/async|callback|cb|ok\n", ""),
        V2.replace("ORES_TEST_V2|CLOSE|suite/async|actor|actor|ok\n", ""),
        V2.replace("ORES_TEST_V2|CLOSE|suite/async|await|aw|ok\n", ""),
        V2.replace("ORES_TEST_V2|CLOSE|suite/async|task|task|ok\n", ""),
        V1.to_string(),
        format!("{V2}{V1}"),
    ] {
        let result = invoke(dir.path(), &fixture, "[native]\nreceipt='lifecycle-v2'\n");
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert!(String::from_utf8_lossy(&result.stderr).contains("invalid machine receipt"));
    }
}

#[test]
fn legacy_remains_default_and_cannot_claim_v2() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(invoke(dir.path(), V1, "").status.code(), Some(0));
    assert_eq!(invoke(dir.path(), V2, "").status.code(), Some(1));
    assert_eq!(
        invoke(dir.path(), &format!("{V1}{V2}"), "").status.code(),
        Some(1)
    );
}

#[test]
fn malformed_receipt_mode_is_configuration_error() {
    let dir = tempfile::tempdir().unwrap();
    let result = invoke(dir.path(), V2, "[native]\nreceipt='auto'\n");
    assert_eq!(result.status.code(), Some(2), "{result:?}");
}
