//! Canonical .atto source admission in the Rust host-only effects analyzer.
use std::fs;
use std::process::Command;

#[test]
fn canonical_atto_effects_and_legacy_alias_share_strict_exit_contract() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("sample.atto"),
        "fnc f() { raise new Error(); }",
    )
    .unwrap();
    for binary in [
        env!("CARGO_BIN_EXE_atto"),
        env!("CARGO_BIN_EXE_oreslang"),
    ] {
        let output = Command::new(binary)
            .arg("test")
            .arg("--root")
            .arg(root.path())
            .args(["--effects", "--effects-strict", "--file", "sample.atto"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{binary}: {output:?}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("EFFECT WARNING sample.atto:"), "{text}");
        assert!(text.contains("ADVISORY inspected=1 warnings=1"), "{text}");
        assert!(text.contains("no call-graph/catch/actor-runtime proof"), "{text}");
    }
}

#[test]
fn canonical_manifest_admits_atto_files_but_two_manifest_names_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("sample.atto"), "fnc f() {}").unwrap();
    fs::write(
        root.path().join("atto-test.toml"),
        "[effects]\nfiles = ['sample.atto']\n",
    )
    .unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_atto-test"))
            .arg("--root")
            .arg(root.path())
            .arg("--effects")
            .output()
            .unwrap()
    };
    let success = run();
    assert_eq!(success.status.code(), Some(0), "{success:?}");
    assert!(String::from_utf8_lossy(&success.stdout).contains("inspected=1"));
    fs::write(root.path().join("oreslang-test.toml"), "[effects]\n").unwrap();
    let error = run();
    assert_eq!(error.status.code(), Some(2), "{error:?}");
    assert!(String::from_utf8_lossy(&error.stderr).contains("ambiguous test manifests"));
    assert!(error.stdout.is_empty());
}

#[test]
fn atto_effects_malformed_and_missing_source_are_not_passes() {
    let root = tempfile::tempdir().unwrap();
    for name in ["../escape.atto", "not-present.atto", "sample.txt"] {
        let output = Command::new(env!("CARGO_BIN_EXE_atto-test"))
            .arg("--root")
            .arg(root.path())
            .args(["--effects", "--file", name])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{name}: {output:?}");
    }
}
