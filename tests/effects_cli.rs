use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn cli(root: &Path, args: &[&str]) -> Output {
    return Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .arg("--root")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
}

fn project(source: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("sample.ores"), source).unwrap();
    return dir;
}

#[test]
fn advisory_and_strict_keep_golden_exit_and_output_contract() {
    let root = project("fnc f() { raise new Error(); }");
    let result = cli(root.path(), &["--effects", "--file", "sample.ores"]);
    assert_eq!(result.status.code(), Some(0));
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("EFFECT WARNING sample.ores:1 [undeclared-effect] f contains raise; consider annotating raises"));
    assert!(output.contains("EFFECTS ADVISORY inspected=1 warnings=1; direct syntax only, no call-graph/catch/actor-runtime proof"));
    assert_eq!(
        cli(
            root.path(),
            &["--effects", "--effects-strict", "--file", "sample.ores"]
        )
        .status
        .code(),
        Some(1)
    );
}

#[test]
fn clean_advisory_is_never_a_proof_statement() {
    let root = project("fnc f() raises { raise new Error(); }");
    let result = cli(root.path(), &["--effects", "--effects-strict"]);
    assert_eq!(result.status.code(), Some(0));
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("ADVISORY inspected=1 warnings=0"));
    assert!(output.contains("no call-graph/catch/actor-runtime proof"));
}

#[test]
fn runtime_modes_and_invalid_options_cannot_mix_with_effects() {
    let root = project("fnc f() {}");
    for args in [
        vec!["--effects", "--race"],
        vec!["--effects", "--fuzz"],
        vec!["--effects", "--logical"],
        vec!["--effects", "--trace", "x"],
        vec!["--effects-strict"],
        vec!["--file", "sample.ores"],
        vec!["--effects", "--unknown"],
        vec!["--effects", "--file"],
    ] {
        let result = cli(root.path(), &args);
        assert_eq!(result.status.code(), Some(2), "{args:?}");
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn lexical_incomplete_and_empty_coverage_are_inconclusive() {
    for source in [
        "fnc f() { /*",
        "// no body",
        "method f() => void;",
        "fnc f() { let cb = |x| -> { raise new Error(); }; }",
    ] {
        let root = project(source);
        let result = cli(root.path(), &["--effects", "--file", "sample.ores"]);
        assert_eq!(result.status.code(), Some(2), "{source}");
        assert!(String::from_utf8_lossy(&result.stderr).contains("EFFECTS INCONCLUSIVE"));
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn no_partial_advisory_output_when_later_file_fails() {
    let root = project("fnc f() { raise new Error(); }");
    fs::write(root.path().join("bad.ores"), "fnc bad() {").unwrap();
    let result = cli(
        root.path(),
        &["--effects", "--file", "sample.ores", "--file", "bad.ores"],
    );
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
}

#[test]
fn paths_extensions_non_utf8_and_oversized_sources_fail_closed() {
    let root = project("fnc f() {}");
    for name in [
        "../outside.ores",
        "/outside.ores",
        "missing.ores",
        "sample.txt",
        "",
    ] {
        assert_eq!(
            cli(root.path(), &["--effects", "--file", name])
                .status
                .code(),
            Some(2)
        );
    }
    for bytes in [vec![0xff, 0xfe], vec![b' '; 262_145]] {
        fs::write(root.path().join("sample.ores"), bytes).unwrap();
        assert_eq!(cli(root.path(), &["--effects"]).status.code(), Some(2));
    }
}

#[test]
fn explicit_files_config_discovery_and_deduplication() {
    let root = project("fnc f() panics { panic new Error(); }");
    fs::write(root.path().join("ignored.ores"), "bad {").unwrap();
    fs::write(
        root.path().join("oreslang-test.toml"),
        "[effects]\nfiles = ['sample.ores']\n",
    )
    .unwrap();
    let result = cli(root.path(), &["--effects"]);
    assert_eq!(result.status.code(), Some(0));
    let result = cli(
        root.path(),
        &["--effects", "--file=sample.ores", "--file=./sample.ores"],
    );
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stdout).contains("inspected=1"));
}

#[test]
fn malformed_config_is_not_a_success() {
    let root = project("fnc f() {}");
    for config in [
        "[effects",
        "effects = 1",
        "[effects]\nfiles = 42",
        "[effects]\nfiles = [42]",
        "[effects]\nfiles = []",
    ] {
        fs::write(root.path().join("oreslang-test.toml"), config).unwrap();
        assert_eq!(
            cli(root.path(), &["--effects"]).status.code(),
            Some(2),
            "{config}"
        );
    }
}

#[test]
fn public_oreslang_test_dispatch_uses_the_same_native_analyzer() {
    let root = project("fnc f() { panic new Error(); }");
    let result = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .args(["test", "--effects", "--effects-strict", "--root"])
        .arg(root.path())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stdout).contains("panics"));
}

#[cfg(unix)]
#[test]
fn file_and_parent_symlinks_are_refused() {
    use std::os::unix::fs::symlink;
    let root = project("fnc f() {}");
    symlink(
        root.path().join("sample.ores"),
        root.path().join("alias.ores"),
    )
    .unwrap();
    symlink(root.path(), root.path().join("linked")).unwrap();
    for name in ["alias.ores", "linked/sample.ores"] {
        let result = cli(root.path(), &["--effects", "--file", name]);
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&result.stderr).contains("symlink refused"));
    }
}

#[cfg(unix)]
#[test]
fn legacy_non_success_status_is_preserved() {
    use std::os::unix::fs::PermissionsExt;
    let root = project("fnc f() {}");
    let script = root.path().join("legacy");
    fs::write(
        &script,
        "#!/bin/sh\n[ \"$1\" = --root ] || exit 8\n[ \"$3\" = --race ] || exit 9\nexit 7\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("ORESLANG_TEST_LEGACY", script)
        .arg("--root")
        .arg(root.path())
        .arg("--race")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(7));
}

#[test]
fn self_delegation_is_refused() {
    let result = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .env("ORESLANG_BIN", env!("CARGO_BIN_EXE_oreslang"))
        .arg("version")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("recursion refused"));
}

#[test]
fn migrated_output_cap_keeps_true_warning_count_and_strict_failure() {
    let root = project(&format!(
        "fnc f() {{\n{} }}",
        "panic new Error();\n".repeat(150)
    ));
    let result = cli(root.path(), &["--effects", "--effects-strict"]);
    assert_eq!(result.status.code(), Some(1));
    let output = String::from_utf8(result.stdout).unwrap();
    assert_eq!(output.matches("EFFECT WARNING sample.ores:").count(), 100);
    assert!(output.contains("EFFECT WARNINGS TRUNCATED shown=100 total=150"));
    assert!(output.contains("warnings=150"));
}

#[test]
fn migrated_file_discovery_and_total_source_budgets() {
    let root = project("fnc f() {}");
    fs::write(root.path().join(".hidden.ores"), "fnc bad() {").unwrap();
    assert_eq!(cli(root.path(), &["--effects"]).status.code(), Some(0));
    for i in 0..512 {
        fs::write(root.path().join(format!("source{i}.ores")), "fnc f() {}").unwrap();
    }
    assert_eq!(cli(root.path(), &["--effects"]).status.code(), Some(2));
    let root = tempfile::tempdir().unwrap();
    let source = format!("fnc f() {{ let x = \"{}\"; }}", "x".repeat(249_900));
    let mut command = Command::new(env!("CARGO_BIN_EXE_oreslang-test"));
    command.arg("--effects").arg("--root").arg(root.path());
    for i in 0..17 {
        let name = format!("source{i}.ores");
        fs::write(root.path().join(&name), &source).unwrap();
        command.arg("--file").arg(name);
    }
    let result = command.output().unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("4 MiB"));
}

#[test]
fn legacy_override_rejects_recursion() {
    let binary = env!("CARGO_BIN_EXE_oreslang-test");
    let result = Command::new(binary)
        .env("ORESLANG_TEST_LEGACY", binary)
        .arg("--race")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("recursion refused"));
}

#[cfg(unix)]
#[test]
fn legacy_override_rejects_symlink_to_launcher() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let alias = root.path().join("legacy-alias");
    symlink(env!("CARGO_BIN_EXE_oreslang-test"), &alias).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("ORESLANG_TEST_LEGACY", alias)
        .arg("--race")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("recursion refused"));
}

#[cfg(unix)]
#[test]
fn legacy_override_rejects_path_alias() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    symlink(
        env!("CARGO_BIN_EXE_oreslang-test"),
        root.path().join("legacy-alias"),
    )
    .unwrap();
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(root.path().to_path_buf()).chain(std::env::split_paths(&old_path)),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_oreslang-test"))
        .env("PATH", path)
        .env("ORESLANG_TEST_LEGACY", "legacy-alias")
        .arg("--race")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("recursion refused"));
}
