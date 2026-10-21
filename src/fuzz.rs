//! Deterministic byte mutation fuzzer. A passing corpus is not coverage proof.
use crate::common::{bounded_read, safe_path, table_command, Result};
use crate::runner;
use rand::{Rng, RngCore, SeedableRng, seq::SliceRandom};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::io::Write;
fn failure(output: Option<runner::Outcome>) -> Option<String> {
    match output {
        None => Some("timeout".into()),
        Some(v) if v.code != 0 => Some(format!("exit:{}",v.code)),
        _ => None,
    }
}
fn classify(cmd: &[String], root: &Path, timeout: f64, data: &[u8]) -> Result<Option<String>> {
    Ok(failure(runner::run(cmd,root,timeout,Some(data),&[])?))
}
pub fn fuzz(root: &Path, cfg: &toml::Value, seed: u64, cases: usize, timeout: f64) -> Result<u8> {
    if !(1..=1_000_000).contains(&cases) { return Err("--cases must be 1..1000000".into()); }
    let cmd=table_command(cfg,"fuzz")?;
    let max=cfg.get("fuzz").and_then(|v|v.get("max_bytes")).and_then(|v|v.as_integer()).unwrap_or(256);
    if !(1..=65536).contains(&max) {return Err("fuzz.max_bytes must be 1..65536".into());}
    let max=max as usize;
    let corpus_name=cfg.get("fuzz").and_then(|v|v.get("corpus")).and_then(|v|v.as_str()).unwrap_or("tests/corpus");
    let dir=safe_path(root,corpus_name)?;
    let mut corpus:Vec<Vec<u8>>=vec![vec![],vec![0],vec![255]];
    if dir.exists() {
        if !dir.is_dir() {return Err("fuzz corpus is not a directory".into());}
        // Bound enumeration before allocating a path list, then bound aggregate
        // corpus bytes. Oversized/non-file members fail closed instead of
        // being silently excluded from coverage.
        let mut paths=Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(|e|e.to_string())? {
            if paths.len() >= 512 {return Err("fuzz corpus exceeds 512 entries".into());}
            paths.push(entry.map_err(|e|e.to_string())?.path());
        }
        paths.sort();
        let mut corpus_bytes=0usize;
        for path in paths {
            let kind=path.symlink_metadata().map_err(|e|e.to_string())?.file_type();
            if kind.is_symlink() {return Err("fuzz corpus may not contain symlinks".into());}
            if !kind.is_file() {return Err("fuzz corpus must contain regular files only".into());}
            let bytes=bounded_read(&path,max)?;
            corpus_bytes=corpus_bytes.checked_add(bytes.len())
                .ok_or("fuzz corpus size overflow")?;
            if corpus_bytes > 4*1024*1024 {
                return Err("fuzz corpus exceeds 4 MiB aggregate input".into());
            }
            corpus.push(bytes);
        }
    }
    corpus.sort(); corpus.dedup();
    let mut pool_bytes=corpus.iter().map(Vec::len).sum::<usize>();
    let mut rng=StdRng::seed_from_u64(seed);
    for iteration in 0..cases {
        let case=if iteration < corpus.len() {corpus[iteration].clone()} else {
            let mut base=corpus.choose(&mut rng).cloned().unwrap_or_default();
            if base.is_empty() || rng.gen_range(0..4)==0 {
                let size=rng.gen_range(0..=max);
                base.resize(size,0); rng.fill_bytes(&mut base);
            } else {
                for _ in 0..rng.gen_range(1..=4) {
                    let idx=rng.gen_range(0..base.len());
                    base[idx]^=rng.gen::<u8>();
                }
            }
            base.truncate(max); base
        };
        if let Some(reason)=classify(&cmd,root,timeout,&case)? {
            for _ in 0..2 {
                if classify(&cmd,root,timeout,&case)?.as_deref()!=Some(reason.as_str()) {
                    eprintln!("FUZZ FLAKY seed={seed} iteration={iteration} reason={reason}");
                    return Ok(2);
                }
            }
            eprintln!("FUZZ FAILURE seed={seed} iteration={iteration} reason={reason} size={}",case.len());
            let mut reduced=case.clone();
            let (mut granularity,mut budget)=(2usize,200usize);
            while !reduced.is_empty() && budget>0 {
                let step=reduced.len().div_ceil(granularity);
                let mut shorter=false;
                for start in (0..reduced.len()).step_by(step) {
                    budget-=1;
                    let mut candidate=reduced.clone();
                    candidate.drain(start..(start+step).min(reduced.len()));
                    if classify(&cmd,root,timeout,&candidate)?.as_deref()==Some(&reason) {
                        reduced=candidate; granularity=2; shorter=true; break;
                    }
                    if budget==0 {break;}
                }
                if !shorter {
                    if granularity>=reduced.len(){break;}
                    granularity=(granularity*2).min(reduced.len());
                }
            }
            for _ in 0..2 {
                if classify(&cmd,root,timeout,&reduced)?.as_deref()!=Some(&reason) {
                    eprintln!("FUZZ FLAKY during shrink; retaining original");
                    reduced=case.clone(); break;
                }
            }
            let failures=safe_path(root,".oreslang-test/failures")?;
            std::fs::create_dir_all(&failures).map_err(|e|e.to_string())?;
            let hash=format!("{:x}",Sha256::digest(&reduced));
            let dest=failures.join(format!("fuzz-{}.bin",&hash[..20]));
            if dest.exists() {
                if bounded_read(&dest,65536)?!=reduced {return Err("failure artifact hash collision".into());}
            } else {
                let mut file=std::fs::OpenOptions::new().write(true).create_new(true).open(&dest)
                    .map_err(|e|e.to_string())?;
                file.write_all(&reduced).map_err(|e|e.to_string())?;
            }
            eprintln!("Minimized to {} bytes: {}",reduced.len(),dest.display());
            return Ok(1);
        }
        // The 4,096-case historical count limit alone could retain 256 MiB
        // when fuzz.max_bytes=65536; cap the live mutation pool by bytes too.
        if corpus.len()<4096
            && pool_bytes.saturating_add(case.len()) <= 16*1024*1024
            && !corpus.contains(&case) {
            pool_bytes+=case.len();
            corpus.push(case);
        }
    }
    println!("FUZZ PASS cases={cases} seed={seed} (tested inputs only; no coverage claim)");
    Ok(0)
}

#[cfg(test)]
mod corpus_limit_tests {
    use super::*;

    fn cfg() -> toml::Value {
        r#"[fuzz]
command=["unavailable-fuzz-command-for-preflight"]
corpus="corpus"
max_bytes=65536
"#.parse().unwrap()
    }

    #[test]
    fn rejects_unbounded_corpus_entry_count_before_invoking_guest() {
        let project=tempfile::tempdir().unwrap();
        let dir=project.path().join("corpus");
        std::fs::create_dir(&dir).unwrap();
        for n in 0..513 {
            std::fs::write(dir.join(format!("{n:04}.bin")), b"").unwrap();
        }
        let error=fuzz(project.path(), &cfg(), 1, 1, 1.0).unwrap_err();
        assert!(error.contains("512 entries"), "{error}");
    }

    #[test]
    fn rejects_oversized_aggregate_corpus_before_invoking_guest() {
        let project=tempfile::tempdir().unwrap();
        let dir=project.path().join("corpus");
        std::fs::create_dir(&dir).unwrap();
        let data=vec![0u8;65536];
        for n in 0..65 {
            std::fs::write(dir.join(format!("{n:04}.bin")), &data).unwrap();
        }
        let error=fuzz(project.path(), &cfg(), 1, 1, 1.0).unwrap_err();
        assert!(error.contains("4 MiB aggregate"), "{error}");
    }
}
