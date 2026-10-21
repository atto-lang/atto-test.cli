//! Native 'oreslang' dispatcher. Rust only: no Python, shell, or legacy test runner.
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command,exit};

fn same_file(core:&OsString, me:&PathBuf)->bool {
    if let Ok(real)=std::fs::canonicalize(core) {
        if real==*me {return true;}
    }
    if std::path::Path::new(core).components().count()==1 {
        if let Some(path)=std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                if std::fs::canonicalize(dir.join(core)).ok().as_ref()==Some(me) {
                    return true;
                }
            }
        }
    }
    false
}
fn main(){
    let args:Vec<OsString>=std::env::args_os().skip(1).collect();
    let me=match std::env::current_exe().and_then(|p|std::fs::canonicalize(p)) {
        Ok(v)=>v,
        Err(e)=>{eprintln!("oreslang: cannot locate self: {e}");exit(2)}
    };
    if args.first().is_some_and(|s|s.to_string_lossy()=="test") {
        let mut test=me.clone();
        test.set_file_name(if cfg!(windows) {"oreslang-test.exe"}else{"oreslang-test"});
        if !test.is_file() {
            eprintln!("oreslang: Rust oreslang-test executable not installed alongside oreslang");
            exit(2);
        }
        match Command::new(test).args(&args[1..]).status(){
            Ok(status)=>exit(status.code().unwrap_or(2)),
            Err(e)=>{eprintln!("oreslang: cannot launch native test CLI: {e}");exit(2)}
        }
    }
    let core=std::env::var_os("ORESLANG_BIN").unwrap_or_else(||"oreslang-core".into());
    if same_file(&core,&me) {
        eprintln!("oreslang: recursion refused: ORESLANG_BIN resolves to oreslang dispatcher");
        exit(2);
    }
    match Command::new(core).args(&args).status() {
        Ok(status)=>exit(status.code().unwrap_or(2)),
        Err(e)=>{eprintln!("oreslang: cannot launch compiler: {e}");exit(2)}
    }
}
