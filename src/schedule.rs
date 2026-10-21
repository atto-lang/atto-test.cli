//! Delegate deterministic-ish scheduler probes to an instrumented backend.
use crate::common::{bounded_read, safe_path, table_command, Result};
use crate::runner;
use regex::Regex;
use std::path::Path;
fn replay_trace(path: &Path) -> Result<(i64, usize)> {
    let bytes = bounded_read(path, 8_000_000)?;
    let raw = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let lines: Vec<_> = raw.lines().collect();
    if !(2..=100_001).contains(&lines.len()) {
        return Err("schedule trace has no checkpoints or exceeds budget".into());
    }
    let header=Regex::new(
        r"^ORES_CONCURRENCY_TRACE_V3\|seed=(-?[0-9]+)\|entry-sha256=[0-9a-f]{64}\|workspace-sha256=[0-9a-f]{64}\|backend=[A-Za-z0-9_.-]{1,80}\|probe=3$"
    ).unwrap();
    let caps=header.captures(lines[0]).ok_or("schedule replay requires workspace-bound V3 provenance")?;
    let event=Regex::new(r"^[a-z][a-z0-9-]{0,47}\|[012]$").unwrap();
    if lines[1..].iter().any(|line|!event.is_match(line)) {return Err("malformed schedule checkpoint event".into());}
    Ok((caps[1].parse::<i64>().map_err(|e|e.to_string())?,lines.len()-1))
}
fn fields(line:&str,header:&str,keys:&[&str])->Option<Vec<String>> {
    let rest=line.strip_prefix(header)?;
    let pieces:Vec<_>=rest.split('|').collect();
    if pieces.len()!=keys.len() {return None;}
    pieces.iter().zip(keys.iter()).map(|(piece,key)|piece.strip_prefix(&format!("{key}=")).map(str::to_owned)).collect()
}
fn validate(stdout:&str,iterations:usize, seed:i64, replay_events:Option<usize>)->Result<usize> {
    let mut records=Vec::new();
    let mut cases=[0usize;3];
    let mut summary=None;
    for line in stdout.lines() {
        if let Some(index)=["ORES_TEST|PASS|","ORES_TEST|FAIL|","ORES_TEST|SKIP|"].iter().position(|p|line.starts_with(p)) {
            if summary.is_some(){return Err("case records after summary".into());}
            cases[index]+=1;
        } else if line.starts_with("ORES_TEST|SUMMARY|") {
            if summary.is_some(){return Err("duplicate summary".into());}
            summary=Some(line.to_string());
        } else if line.starts_with("ORES_CONCURRENCY|RUN|") {
            let previous=summary.take().ok_or("receipt without summary")?;
            records.push((previous,line.to_string(),cases));
            cases=[0;3];
        }
    }
    if summary.is_some() || cases.iter().any(|n|*n!=0) || records.len()!=iterations {
        return Err("missing/duplicate backend receipts".into());
    }
    for (index,(summary,receipt,counted)) in records.iter().enumerate() {
        let summary=fields(summary,"ORES_TEST|SUMMARY|",&["total","passed","failed","skipped","filtered"])
            .ok_or("malformed suite summary")?;
        let nums:Vec<usize>=summary.iter().map(|s|s.parse::<usize>()).collect::<std::result::Result<_,_>>()
            .map_err(|e|e.to_string())?;
        let run=fields(receipt,"ORES_CONCURRENCY|RUN|",
            &["seed","events","deadlocks","schedule","race_coverage"]).ok_or("malformed runtime receipt")?;
        if run[4]!="none" || (run[3]!="normal" && run[3]!="perturbed") {
            return Err("invalid runtime receipt capabilities".into());
        }
        let seen_seed=run[0].parse::<i64>().map_err(|e|e.to_string())?;
        let events=run[1].parse::<usize>().map_err(|e|e.to_string())?;
        let deadlocks=run[2].parse::<usize>().map_err(|e|e.to_string())?;
        if nums[1]==0 || nums[2]!=0 || nums[1].checked_add(nums[2]).and_then(|v|v.checked_add(nums[3]))!=Some(nums[0]) ||
           counted!=&[nums[1],nums[2],nums[3]] || seen_seed!=seed.checked_add(index as i64).ok_or("seed overflow")? ||
           events==0 || deadlocks!=0 || replay_events.is_some_and(|expected|events!=expected) {
            return Err("backend suite receipt inconsistent with case events".into());
        }
    }
    Ok(records.len())
}
pub fn schedule(
    root: &Path,
    cfg: &toml::Value,
    seed: i64,
    iterations: usize,
    timeout: f64,
    replay: Option<&str>,
    trace_out: Option<&str>,
) -> Result<u8> {
    if !(1..=1000).contains(&iterations) {
        return Err("--iterations must be 1..1000".into());
    }
    if replay.is_some() && iterations != 1 {
        return Err("--replay requires --iterations=1".into());
    }
    if trace_out.is_some() && iterations != 1 {
        return Err("--trace-output requires --iterations=1".into());
    }
    let mut cmd = table_command(cfg, "schedule")?;
    let (expected_seed, replay_events) = if let Some(name) = replay {
        let path = safe_path(root, name)?;
        let (expected, events) = replay_trace(&path)?;
        cmd.push(format!("--replay={}", path.display()));
        (expected, Some(events))
    } else {
        seed.checked_add(iterations as i64 - 1)
            .ok_or("schedule seed overflow")?;
        cmd.extend([
            String::from("--schedule-fuzz"),
            format!("--seed={seed}"),
            format!("--iterations={iterations}"),
        ]);
        (seed, None)
    };
    cmd.push("--deadlock".into());
    let dest = if let Some(name) = trace_out {
        let file = safe_path(root, name)?;
        if file.exists() {
            return Err("schedule trace output must be new, not stale".into());
        }
        cmd.push(format!("--trace-output={}", file.display()));
        Some(file)
    } else {
        None
    };
    let output = runner::run(&cmd, root, timeout, None, &[])?;
    let Some(output) = output else {
        println!("SCHEDULE TIMEOUT");
        return Ok(1);
    };
    let valid = if output.code != 0 {
        Err("backend returned nonzero exit".into())
    } else {
        validate(&output.stdout, iterations, expected_seed, replay_events)
    };
    let valid = valid.and_then(|_| {
        if let Some(path) = dest {
            let (actual_seed, events) = replay_trace(&path)?;
            let receipts: Vec<&str> = output
                .stdout
                .lines()
                .filter(|l| l.starts_with("ORES_CONCURRENCY|RUN|"))
                .collect();
            let run = fields(
                receipts[0],
                "ORES_CONCURRENCY|RUN|",
                &["seed", "events", "deadlocks", "schedule", "race_coverage"],
            )
            .ok_or("bad receipt")?;
            if actual_seed != expected_seed
                || events != run[1].parse::<usize>().map_err(|e| e.to_string())?
            {
                return Err("output trace inconsistent with receipt".into());
            }
        }
        Ok(())
    });
    if let Err(reason) = valid {
        eprintln!("SCHEDULE FAIL: {reason}");
        eprintln!("{}", output.stdout.chars().take(8000).collect::<String>());
        eprintln!("{}", output.stderr.chars().take(8000).collect::<String>());
        return Ok(1);
    }
    println!("SCHEDULE PASS: {iterations} backend runs (carrier interleavings not deterministic)");
    Ok(0)
}
#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn summary_only_is_not_success(){
    let out="ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\nORES_CONCURRENCY|RUN|seed=7|events=1|deadlocks=0|schedule=perturbed|race_coverage=none\n";
    assert!(validate(out,1,7,None).is_err());
  }
  #[test]
  fn overflowing_scheduler_summary_is_rejected_not_panicked(){
    let out=format!(
      "ORES_TEST|PASS|case\nORES_TEST|SUMMARY|total={}|passed={}|failed=0|skipped=1|filtered=0\nORES_CONCURRENCY|RUN|seed=7|events=1|deadlocks=0|schedule=perturbed|race_coverage=none\n",
      usize::MAX, usize::MAX
    );
    assert!(validate(&out,1,7,None).is_err());
  }
  #[test]
  fn mismatched_suite_receipt_fails_closed(){
    let out="ORES_TEST|PASS|case\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\nORES_CONCURRENCY|RUN|seed=8|events=1|deadlocks=0|schedule=perturbed|race_coverage=none\n";
    assert!(validate(out,1,7,None).is_err());
  }
  #[test]
  fn validated_case_receipts(){
    let out="ORES_TEST|PASS|case\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\nORES_CONCURRENCY|RUN|seed=7|events=1|deadlocks=0|schedule=perturbed|race_coverage=none\n";
    assert!(validate(out,1,7,None).is_ok());
  }
}
