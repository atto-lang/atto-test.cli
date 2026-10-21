//! Deterministic byte mutation fuzzer. A passing corpus is not coverage proof.
use crate::common::{bounded_read, safe_path, table_command, Result};
use crate::runner;
use rand::rngs::StdRng;
use rand::{seq::SliceRandom, Rng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
fn failure(output: Option<runner::Outcome>) -> Option<String> {
    match output {
        None => Some("timeout".into()),
        Some(v) if v.code != 0 => Some(format!("exit:{}", v.code)),
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
        let mut paths=Vec::new();
        for entry in std::fs::read_dir(dir).map_err(|e|e.to_string())? {
            if paths.len() >= 4096 { return Err("fuzz corpus exceeds 4096 entries".into()); }
            paths.push(entry.map_err(|e|e.to_string())?.path());
        }
        paths.sort();
        let mut total_bytes=0usize;
        for path in paths {
            if path.symlink_metadata().map_err(|e|e.to_string())?.file_type().is_symlink() {
                return Err("fuzz corpus may not contain symlinks".into());
            }
            let metadata = path.symlink_metadata().map_err(|e| e.to_string())?;
            if !metadata.file_type().is_file() {
                return Err(format!("fuzz corpus entry is not a regular file: {}", path.display()));
            }
            if metadata.len() > max as u64 {
                return Err(format!("fuzz corpus seed exceeds max_bytes: {}", path.display()));
            }
            let input=bounded_read(&path,max)?;
            total_bytes=total_bytes.checked_add(input.len()).ok_or("corpus byte-size overflow")?;
            if total_bytes > 16_777_216 { return Err("fuzz corpus exceeds 16 MiB".into()); }
            corpus.push(input);
        }
    }
    corpus.sort();
    corpus.dedup();
    let mut rng = StdRng::seed_from_u64(seed);
    for iteration in 0..cases {
        let case = if iteration < corpus.len() {
            corpus[iteration].clone()
        } else {
            let mut base = corpus.choose(&mut rng).cloned().unwrap_or_default();
            if base.is_empty() || rng.gen_range(0..4) == 0 {
                let size = rng.gen_range(0..=max);
                base.resize(size, 0);
                rng.fill_bytes(&mut base);
            } else {
                for _ in 0..rng.gen_range(1..=4) {
                    let idx = rng.gen_range(0..base.len());
                    base[idx] ^= rng.gen::<u8>();
                }
            }
            base.truncate(max);
            base
        };
        if let Some(reason) = classify(&cmd, root, timeout, &case)? {
            for _ in 0..2 {
                if classify(&cmd, root, timeout, &case)?.as_deref() != Some(reason.as_str()) {
                    eprintln!("FUZZ FLAKY seed={seed} iteration={iteration} reason={reason}");
                    return Ok(2);
                }
            }
            eprintln!(
                "FUZZ FAILURE seed={seed} iteration={iteration} reason={reason} size={}",
                case.len()
            );
            let mut reduced = case.clone();
            let (mut granularity, mut budget) = (2usize, 200usize);
            while !reduced.is_empty() && budget > 0 {
                let step = reduced.len().div_ceil(granularity);
                let mut shorter = false;
                for start in (0..reduced.len()).step_by(step) {
                    budget -= 1;
                    let mut candidate = reduced.clone();
                    candidate.drain(start..(start + step).min(reduced.len()));
                    if classify(&cmd, root, timeout, &candidate)?.as_deref() == Some(&reason) {
                        reduced = candidate;
                        granularity = 2;
                        shorter = true;
                        break;
                    }
                    if budget == 0 {
                        break;
                    }
                }
                if !shorter {
                    if granularity >= reduced.len() {
                        break;
                    }
                    granularity = (granularity * 2).min(reduced.len());
                }
            }
            for _ in 0..2 {
                if classify(&cmd, root, timeout, &reduced)?.as_deref() != Some(&reason) {
                    eprintln!("FUZZ FLAKY during shrink; retaining original");
                    reduced = case.clone();
                    break;
                }
            }
            let failures = safe_path(root, ".oreslang-test/failures")?;
            std::fs::create_dir_all(&failures).map_err(|e| e.to_string())?;
            let hash = format!("{:x}", Sha256::digest(&reduced));
            let dest = failures.join(format!("fuzz-{}.bin", &hash[..20]));
            if dest.exists() {
                if bounded_read(&dest, 65536)? != reduced {
                    return Err("failure artifact hash collision".into());
                }
            } else {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&dest)
                    .map_err(|e| e.to_string())?;
                file.write_all(&reduced).map_err(|e| e.to_string())?;
            }
            eprintln!("Minimized to {} bytes: {}", reduced.len(), dest.display());
            return Ok(1);
        }
        if corpus.len() < 4096 && !corpus.contains(&case) {
            corpus.push(case);
        }
    }
    println!("FUZZ PASS cases={cases} seed={seed} (tested inputs only; no coverage claim)");
    Ok(0)
}
