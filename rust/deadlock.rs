//! Bounded OFFLINE lock-order and observed unresolved wait-cycle analysis.
//! Findings indicate a potential lock-order hazard or an observed wait cycle,
//! NOT inevitable deadlock, runtime coverage, or a certified liveness result.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(not(target_os = "linux"))]
use std::io::Read;
use std::path::Path;
use crate::race_offline::{Parser, relative_trace};

type Graph = BTreeMap<String, BTreeSet<String>>;
const MAX_EVENTS: usize = 100_000;
const MAX_BYTES: u64 = 10_000_000;
const MAX_TASKS: usize = 256;
const MAX_LOCKS: usize = 2048;
const MAX_EDGES: usize = 10_000;
const MAX_WITNESSES: usize = 100;
const TRAVERSAL_BUDGET: usize = 250_000;

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub events: usize,
    pub observed_lock_events: usize,
    pub pending_waits: usize,
    pub potential_lock_order_cycles: Vec<Vec<String>>,
    pub observed_wait_cycles: Vec<Vec<String>>,
}

fn cycle_witnesses(graph: &Graph) -> Result<Vec<Vec<String>>, String> {
    let mut result = Vec::new();
    let mut known = BTreeSet::new();
    let mut budget = TRAVERSAL_BUDGET;
    for origin in graph.keys() {
        let mut queue = VecDeque::new();
        queue.push_back((origin.clone(), vec![origin.clone()]));
        let mut seen = BTreeSet::new();
        seen.insert(origin.clone());
        while let Some((node, path)) = queue.pop_front() {
            if budget == 0 { return Err("deadlock graph traversal budget exhausted".into()); }
            budget -= 1;
            if let Some(neighbors) = graph.get(&node) {
                for next in neighbors {
                    if next == origin {
                        let best = (0..path.len()).map(|i| {
                            path[i..].iter().chain(path[..i].iter())
                                .cloned().collect::<Vec<_>>()
                        }).min().ok_or("empty cycle path")?;
                        if known.insert(best.clone()) {
                            let mut witness = best;
                            witness.push(witness[0].clone());
                            result.push(witness);
                            if result.len() >= MAX_WITNESSES { return Ok(result); }
                        }
                        queue.clear();
                        break;
                    }
                    if seen.insert(next.clone()) {
                        let mut extension = path.clone();
                        extension.push(next.clone());
                        queue.push_back((next.clone(), extension));
                    }
                }
            }
        }
    }
    Ok(result)
}

pub fn analyze(contents: &str) -> Result<Report, String> {
    if contents.len() > MAX_BYTES as usize { return Err("deadlock input exceeds 10 MB".into()); }
    let lines: Vec<&str> = contents.lines().collect();
    if !(2..=MAX_EVENTS+2).contains(&lines.len()) {
        return Err("deadlock trace event count outside bounds".into());
    }
    let begin = Parser::object(lines[0])?;
    begin.keys(&["op", "version", "run_id", "backend"])?;
    if begin.text("op")? != "begin" || begin.number("version")? != 1 {
        return Err("invalid deadlock JSONL begin".into());
    }
    let run_id = begin.text("run_id")?.to_owned();
    begin.text("backend")?;
    let end = Parser::object(lines[lines.len()-1])?;
    end.keys(&["op", "run_id", "events"])?;
    if end.text("op")? != "end" || end.text("run_id")? != run_id
        || end.number("events")? != (lines.len()-2) as u64 {
        return Err("inconsistent deadlock JSONL end".into());
    }

    let mut participants = BTreeSet::<String>::new();
    let mut finished = BTreeSet::<String>::new();
    let mut held = BTreeMap::<String,BTreeSet<String>>::new();
    let mut owners = BTreeMap::<String,String>::new();
    let mut pending = BTreeMap::<String,String>::new();
    let mut ordering = Graph::new();
    let mut edges = 0usize;
    let mut observed_lock_events = 0usize;

    for (idx,line) in lines[1..lines.len()-1].iter().enumerate() {
        let record = Parser::object(line).map_err(|e| format!("event {}: {e}", idx+2))?;
        let op = record.text("op")?;
        let task = record.text("task")?.to_owned();
        let keys = match op {
            "task" | "finish" => &["op","task"][..],
            "fork" | "join" => &["op","task","child"][..],
            "lock" | "unlock" | "wait" | "unwait" => &["op","task","name"][..],
            "send" | "recv" => &["op","task","message"][..],
            "access" => &["op","task","location","mode"][..],
            _ => return Err(format!("event {}: unsupported deadlock op {op}", idx+2)),
        };
        record.keys(keys)?;
        if op == "task" {
            if participants.len() >= MAX_TASKS || !participants.insert(task.clone()) {
                return Err("duplicate or over-budget participant".into());
            }
            held.insert(task, BTreeSet::new());
            continue;
        }
        if !participants.contains(&task) || finished.contains(&task) {
            return Err("event from unregistered or finished task".into());
        }
        match op {
            "fork" => {
                let child = record.text("child")?.to_owned();
                if participants.len() >= MAX_TASKS || !participants.insert(child.clone()) {
                    return Err("duplicate fork child or too many participants".into());
                }
                held.insert(child, BTreeSet::new());
            }
            "finish" => {
                if held.get(&task).is_some_and(|x| !x.is_empty()) || pending.contains_key(&task) {
                    return Err("task finished with held lock or unresolved wait".into());
                }
                finished.insert(task.clone());
            }
            "lock" => {
                let name = record.text("name")?.to_owned();
                if pending.contains_key(&task) || owners.contains_key(&name)
                    || owners.len() >= MAX_LOCKS {
                    return Err("lock admission rejected (owner, pending wait or capacity)".into());
                }
                for prev in held.get(&task).ok_or("missing task lock state")? {
                    let graph = ordering.entry(prev.clone()).or_default();
                    if !graph.contains(&name) {
                        if edges >= MAX_EDGES { return Err("lock ordering edge budget exceeded".into()); }
                        graph.insert(name.clone());
                        edges += 1;
                    }
                }
                held.get_mut(&task).ok_or("missing task lock state")?.insert(name.clone());
                owners.insert(name, task.clone());
                observed_lock_events += 1;
            }
            "unlock" => {
                let name = record.text("name")?;
                if pending.contains_key(&task) || owners.get(name) != Some(&task) {
                    return Err("unlock without matching owner".into());
                }
                owners.remove(name);
                held.get_mut(&task).ok_or("missing task locks")?.remove(name);
            }
            "wait" => {
                let name = record.text("name")?.to_owned();
                if pending.contains_key(&task) || !owners.contains_key(&name) {
                    return Err("waiting without an observed lock owner".into());
                }
                pending.insert(task.clone(),name);
                observed_lock_events += 1;
            }
            "unwait" => {
                let name = record.text("name")?;
                if pending.get(&task).map(String::as_str) != Some(name) {
                    return Err("unmatched lock unwait".into());
                }
                pending.remove(&task);
            }
            "join" => { record.text("child")?; }
            "send" | "recv" => { record.text("message")?; }
            "access" => {
                record.text("location")?;
                if !matches!(record.text("mode")?, "R" | "W") {
                    return Err("invalid observed memory mode".into());
                }
            }
            _ => unreachable!(),
        }
    }
    if observed_lock_events == 0 {
        return Err("deadlock trace contains no observed lock acquisitions or waits".into());
    }
    let mut waits = Graph::new();
    for (task,name) in &pending {
        if let Some(owner) = owners.get(name) {
            waits.entry(task.clone()).or_default().insert(owner.clone());
        }
    }
    Ok(Report {
        events: lines.len()-2,
        observed_lock_events,
        pending_waits: pending.len(),
        potential_lock_order_cycles: cycle_witnesses(&ordering)?,
        observed_wait_cycles: cycle_witnesses(&waits)?,
    })
}

pub fn offline(root: &Path, name: &str) -> Result<i32, String> {
    let path = relative_trace(root, name)?;
    #[cfg(target_os = "linux")]
    let data = crate::fs_secure::read_project_file(root, Path::new(name), MAX_BYTES as usize)?;
    #[cfg(not(target_os = "linux"))]
    let data = {
        if path.metadata().map_err(|e|e.to_string())?.len() > MAX_BYTES {
            return Err("deadlock trace exceeds byte budget".into());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path).map_err(|e|e.to_string())?
            .take(MAX_BYTES+1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
        bytes
    };
    if data.len() as u64 > MAX_BYTES {
        return Err("deadlock trace exceeds byte budget".into());
    }
    let text = String::from_utf8(data).map_err(|_|"deadlock trace is not UTF-8")?;
    // GraalVM ORES_CONCURRENCY_TRACE checkpoint-only files require a
    // separate schema and cannot certify a complete observed wait graph.
    if text.starts_with("ORES_CONCURRENCY_TRACE_V") {
        return Err("GraalVM checkpoint-only deadlock trace is not authenticated or complete".into());
    }
    let report = analyze(&text)?;
    let n = report.observed_wait_cycles.len() + report.potential_lock_order_cycles.len();
    println!("OFFLINE DEADLOCK ANALYSIS: {} lock events; {} pending waits; {} potential cycles; not a liveness proof",
        report.observed_lock_events,report.pending_waits,n);
    for witness in report.observed_wait_cycles.iter().take(10) {
        println!("OBSERVED WAIT CYCLE: {}", witness.join(" -> "));
    }
    for witness in report.potential_lock_order_cycles.iter().take(10) {
        println!("POTENTIAL LOCK ORDER CYCLE: {}", witness.join(" -> "));
    }
    Ok(i32::from(n > 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn trace(events: &[&str]) -> String {
        let mut out = String::from("{\"op\":\"begin\",\"version\":1,\"run_id\":\"test\",\"backend\":\"llvm\"}\n");
        for event in events {out.push_str(event);out.push('\n');}
        out.push_str(&format!("{{\"op\":\"end\",\"run_id\":\"test\",\"events\":{}}}\n",events.len()));
        out
    }
    #[test]
    fn detects_potential_lock_order_cycle() {
        let t=trace(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"lock","task":"a","name":"A"}"#,
            r#"{"op":"lock","task":"a","name":"B"}"#,
            r#"{"op":"unlock","task":"a","name":"B"}"#,
            r#"{"op":"unlock","task":"a","name":"A"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"lock","task":"b","name":"B"}"#,
            r#"{"op":"lock","task":"b","name":"A"}"#,
            r#"{"op":"unlock","task":"b","name":"A"}"#,
            r#"{"op":"unlock","task":"b","name":"B"}"#,
        ]);
        let result=analyze(&t).unwrap();
        assert_eq!(result.potential_lock_order_cycles.len(),1);
        assert!(result.observed_wait_cycles.is_empty());
    }
    #[test]
    fn detects_unresolved_wait_cycle() {
        let t=trace(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"lock","task":"a","name":"A"}"#,
            r#"{"op":"lock","task":"b","name":"B"}"#,
            r#"{"op":"wait","task":"a","name":"B"}"#,
            r#"{"op":"wait","task":"b","name":"A"}"#,
        ]);
        assert_eq!(analyze(&t).unwrap().observed_wait_cycles.len(),1);
    }
    #[test]
    fn no_lock_evidence_or_invalid_unlock_is_inconclusive() {
        let t=trace(&[r#"{"op":"task","task":"a"}"#,
                      r#"{"op":"access","task":"a","location":"x","mode":"R"}"#]);
        assert!(analyze(&t).is_err());
        let bad=trace(&[r#"{"op":"task","task":"a"}"#,
                         r#"{"op":"unlock","task":"a","name":"A"}"#]);
        assert!(analyze(&bad).is_err());
    }
}
