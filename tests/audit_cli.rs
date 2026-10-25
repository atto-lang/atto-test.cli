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
fn security_lints_flag_credentials_and_insecure_calls_without_printing_secrets() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("one.ores"), 
        "// secret = \"never-a-finding\"\nlet api_key = \"livecredVALUE123\";\nlet site = \"http://example.com\";\nlet loopback = \"http://localhost:3000\";\ncrypto.md5(data);\nshell.exec(input);").unwrap();
    let out = cli(dir.path(), &["--security", "--fail-on", "medium"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("SEC001"), "{text}");
    assert!(text.contains("SEC002"), "{text}");
    assert!(text.contains("SEC003"), "{text}");
    assert!(text.contains("SEC004"), "{text}");
    assert!(!text.contains("livecredVALUE123"));
    let low = cli(dir.path(), &["--security", "--fail-on", "none"]);
    assert_eq!(low.status.code(), Some(0));
}

#[test]
fn anti_patterns_ignore_masked_literals_and_comments() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("code.ores"),
        "// catch {} while true {}\nlet fake=\"catch {} while true {}\";\ncatch(error) {/* silent */}\nwhile true { spin(); }\nwhile true { await next(); }").unwrap();
    let result = cli(dir.path(), &["--anti-patterns", "--fail-on", "low"]);
    assert_eq!(result.status.code(), Some(1));
    let text = String::from_utf8(result.stdout).unwrap();
    assert_eq!(text.matches("ANTI001").count(), 1);
    assert_eq!(text.matches("ANTI002").count(), 1);
}

#[test]
fn incomplete_audit_exits_two_and_never_emits_clean_result() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("code.ores"), "let x=\"incomplete").unwrap();
    assert_eq!(cli(dir.path(), &["--audit"]).status.code(), Some(2));
    fs::write(dir.path().join("code.ores"), "/* still incomplete").unwrap();
    assert_eq!(cli(dir.path(), &["--audit"]).status.code(), Some(2));
    fs::write(dir.path().join("code.ores"), "let valid=1;").unwrap();
    assert_eq!(
        cli(dir.path(), &["--audit-file", "code.ores"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        cli(dir.path(), &["--audit", "--audit-file", "../other.ores"])
            .status
            .code(),
        Some(2)
    );
}

#[cfg(unix)]
#[test]
fn audit_refuses_symlinks() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("source.ores"), "let valid=1;").unwrap();
    symlink(
        dir.path().join("source.ores"),
        dir.path().join("shortcut.ores"),
    )
    .unwrap();
    assert_eq!(cli(dir.path(), &["--audit"]).status.code(), Some(2));
    assert_eq!(
        cli(dir.path(), &["--audit", "--audit-file", "shortcut.ores"])
            .status
            .code(),
        Some(2)
    );
}
