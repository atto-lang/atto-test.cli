//! Executable CLI regressions without any Python runtime dependency.
use std::{fs, path::Path, process::{Command, Output}};
fn binary() -> &'static str { env!("CARGO_BIN_EXE_oreslang-test") }
fn invoke(root:&Path,args:&[&str])->Output {
    Command::new(binary()).arg("--root").arg(root).args(args).output().unwrap()
}
fn write(path:&Path,content:&str){fs::write(path,content).unwrap();}
fn code(o:&Output)->i32 {o.status.code().unwrap_or(-1)}
#[test]
fn fixture_race_and_model_contracts(){
    let root=Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(code(&invoke(root,&["--race","--trace","tests/traces/ordered.jsonl"])),0);
    assert_eq!(code(&invoke(root,&["--race","--trace","tests/traces/racy.jsonl"])),1);
    assert_eq!(code(&invoke(root,&["--model-check","--model","tests/models/atomic-update.json"])),0);
    assert_eq!(code(&invoke(root,&["--model-check","--model","tests/models/lost-update.json"])),1);
    assert_eq!(code(&invoke(root,&["--race"])),2); // no instrumentation
}
#[test]
fn check_fails_closed_without_real_parser(){
    let dir=tempfile::tempdir().unwrap();
    write(&dir.path().join("unit.ores"),"fnc test() {}");
    assert_eq!(code(&invoke(dir.path(),&["--check","unit.ores"])),2);
}
#[test]
fn syntax_only_compiler_receipt_must_bind_source_hash(){
    let dir=tempfile::tempdir().unwrap();
    write(&dir.path().join("unit.ores"),"fnc test() {}");
    write(&dir.path().join("check.sh"),r#"#!/bin/sh
digest=$(sha256sum "$2" | cut -d ' ' -f1)
echo "ORES_CHECK|PASS|sha256=$digest|phase=syntax-only"
"#);
    write(&dir.path().join("oreslang-test.toml"),r#"[check]
command=["sh","check.sh"]
"#);
    assert_eq!(code(&invoke(dir.path(),&["--check","unit.ores"])),0);
    write(&dir.path().join("check.sh"),"#!/bin/sh\necho 'ORES_CHECK|PASS|sha256=forged|phase=syntax-only'\n");
    assert_eq!(code(&invoke(dir.path(),&["--check","unit.ores"])),2);
    write(&dir.path().join("check.sh"),"#!/bin/sh\nexit 1\n");
    assert_eq!(code(&invoke(dir.path(),&["--check","unit.ores"])),1);
}
#[test]
fn fuzz_success_and_missing_command(){
    let dir=tempfile::tempdir().unwrap();
    assert_eq!(code(&invoke(dir.path(),&["--fuzz","--cases","3"])),2);
    write(&dir.path().join("pass.sh"),"#!/bin/sh\ncat >/dev/null\nexit 0\n");
    write(&dir.path().join("oreslang-test.toml"),"[fuzz]\ncommand=[\"sh\",\"pass.sh\"]\n");
    assert_eq!(code(&invoke(dir.path(),&["--fuzz","--cases","8","--seed","42"])),0);
}
#[test]
fn deadlock_lock_order_cycle_is_failure(){
    let dir=tempfile::tempdir().unwrap();
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
    let mut rows=vec![r#"{"op":"begin","version":1,"run_id":"fixture","backend":"test"}"#.to_owned()];
    rows.extend(ops.into_iter().map(str::to_owned));
    rows.push(format!(r#"{{"op":"end","run_id":"fixture","events":{}}}"#,ops.len()));
    write(&dir.path().join("events.jsonl"),&(rows.join("\n")+"\n"));
    assert_eq!(code(&invoke(dir.path(),&["--deadlock","--trace","events.jsonl"])),1);
}
#[test]
fn scheduling_requires_real_case_receipts(){
    let dir=tempfile::tempdir().unwrap();
    write(&dir.path().join("run.sh"),r#"#!/bin/sh
echo "ORES_TEST|PASS|suite/case|"
echo "ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0"
echo "ORES_CONCURRENCY|RUN|seed=7|events=2|deadlocks=0|schedule=perturbed|race_coverage=none"
"#);
    write(&dir.path().join("oreslang-test.toml"),"[schedule]\ncommand=[\"sh\",\"run.sh\"]\n");
    assert_eq!(code(&invoke(dir.path(),&["--schedule-fuzz","--seed","7"])),0);
    write(&dir.path().join("run.sh"),"#!/bin/sh\necho 'ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0'\n");
    assert_eq!(code(&invoke(dir.path(),&["--schedule-fuzz","--seed","7"])),1);
}
