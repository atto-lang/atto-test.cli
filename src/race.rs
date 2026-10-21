//! ORES_RACE_V1 happens-before analyzer (observed events, not a race-freedom proof).
use crate::common::{field, trace, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
type Clock = HashMap<String, u64>;
fn ordered(a: &Clock, b: &Clock) -> bool {
    a.iter().all(|(k, v)| *v <= *b.get(k).unwrap_or(&0))
}
fn merge(a: &mut Clock, b: &Clock) {
    for (k, v) in b {
        let x = a.entry(k.clone()).or_default();
        *x = (*x).max(*v);
    }
}
#[derive(Default)]
struct Access {
    read: HashMap<String, Clock>,
    write: HashMap<String, Clock>,
}
#[derive(Debug)]
pub struct Report {
    pub count: u64,
    pub events: usize,
    pub backend: String,
    pub examples: Vec<String>,
}

pub fn analyze(path: &Path, expected: Option<&str>) -> Result<Report> {
    let records = trace(path, expected)?;
    let backend = field(&records[0], "backend")?.to_owned();
    analyze_records(&records, backend)
}
fn analyze_records(records: &[Value], backend: String) -> Result<Report> {
    let mut clocks: HashMap<String, Clock> = HashMap::new();
    let mut finished = HashSet::new();
    let mut parents: HashMap<String, String> = HashMap::new();
    let mut joined = HashSet::new();
    let mut locks: HashMap<String, (Option<String>, u32, Clock)> = HashMap::new();
    let mut messages: HashMap<String, Clock> = HashMap::new();
    let mut seen_messages = HashSet::new();
    let mut accesses: HashMap<String, Access> = HashMap::new();
    let (mut total, mut memory_accesses) = (0u64, 0usize);
    let mut examples = Vec::new();
    for (offset, event) in records[1..records.len() - 1].iter().enumerate() {
        let line = offset + 2;
        let op = field(event, "op")?;
        let task = field(event, "task")?.to_owned();
        if op == "task" {
            if clocks.contains_key(&task) || clocks.len() >= 256 {
                return Err("duplicate task or >256 tasks".into());
            }
            clocks.insert(task.clone(), Clock::from([(task, 1)]));
            continue;
        }
        if finished.contains(&task) {
            return Err(format!("event {line} after finish"));
        }
        let mut clock = clocks
            .get(&task)
            .cloned()
            .ok_or_else(|| format!("unregistered task at {line}"))?;
        match op {
            "fork" => {
                let child = field(event, "child")?.to_owned();
                if clocks.len() >= 256 || clocks.contains_key(&child) {
                    return Err("duplicate forked task".into());
                }
                let mut new = clock.clone();
                new.insert(child.clone(), 1);
                clocks.insert(child.clone(), new);
                parents.insert(child, task.clone());
            }
            "finish" => {
                if locks
                    .values()
                    .any(|(owner, _, _)| owner.as_deref() == Some(task.as_str()))
                {
                    return Err("task finished while holding lock".into());
                }
                finished.insert(task.clone());
            }
            "join" => {
                let child = field(event, "child")?;
                if parents.get(child).map(String::as_str) != Some(task.as_str())
                    || !finished.contains(child)
                    || joined.contains(child)
                {
                    return Err("join requires finished unjoined direct child".into());
                }
                merge(&mut clock, clocks.get(child).ok_or("missing child clock")?);
                joined.insert(child.to_owned());
            }
            "lock" => {
                let key = field(event, "name")?.to_owned();
                let entry = locks.entry(key).or_insert_with(|| (None, 0, Clock::new()));
                if entry.0.as_deref().is_some_and(|o| o != task.as_str()) || entry.1 == u32::MAX {
                    return Err("lock already held by other task or reentrancy limit".into());
                }
                if entry.0.is_none() {
                    merge(&mut clock, &entry.2);
                    entry.0 = Some(task.clone());
                    entry.1 = 1;
                } else {
                    entry.1 += 1;
                }
            }
            "unlock" => {
                let key = field(event, "name")?;
                let entry = locks.get_mut(key).ok_or("unlock of unknown lock")?;
                if entry.0.as_deref() != Some(task.as_str()) || entry.1 == 0 {
                    return Err("unlock of unowned lock".into());
                }
                entry.1 -= 1;
                if entry.1 == 0 {
                    entry.0 = None;
                    entry.2 = clock.clone();
                }
            }
            "send" => {
                let msg = field(event, "message")?.to_owned();
                if !seen_messages.insert(msg.clone()) {
                    return Err("message identity reused".into());
                }
                messages.insert(msg, clock.clone());
            }
            "recv" => {
                let msg = field(event, "message")?;
                let sent = messages.remove(msg).ok_or("recv without send")?;
                merge(&mut clock, &sent);
            }
            "access" => {
                let location = field(event, "location")?.to_owned();
                let mode = field(event, "mode")?;
                if mode != "R" && mode != "W" {
                    return Err("memory access mode must be R or W".into());
                }
                memory_accesses += 1;
                let history = accesses.entry(location.clone()).or_default();
                for (prior_mode, records) in [("W", &history.write), ("R", &history.read)] {
                    if prior_mode == "R" && mode == "R" {
                        continue;
                    }
                    for (previous_task, prior) in records {
                        if previous_task != &task && !ordered(prior, &clock) {
                            total += 1;
                            if examples.len() < 100 {
                                examples.push(format!(
                                "{location} {previous_task}:{prior_mode} vs {task}:{mode} event={line}"));
                            }
                        }
                    }
                }
                if mode == "W" {
                    history.write.insert(task.clone(), clock.clone());
                } else {
                    history.read.insert(task.clone(), clock.clone());
                }
            }
            _ => return Err(format!("unsupported race trace op {op} at event {line}")),
        }
        *clock.entry(task.clone()).or_default() += 1;
        clocks.insert(task, clock);
    }
    if memory_accesses == 0 {
        return Err("no memory accesses; refusing false PASS".into());
    }
    if locks
        .values()
        .any(|(owner, depth, _)| owner.is_some() || *depth > 0)
    {
        return Err("trace ends with held locks".into());
    }
    if parents.keys().any(|child| !finished.contains(child)) {
        return Err("trace ends with unfinished child".into());
    }
    Ok(Report {
        count: total,
        events: records.len() - 2,
        backend,
        examples,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_conflict() {
        let rows = vec![
            serde_json::json!({"op":"begin"}),
            serde_json::json!({"op":"task","task":"a"}),
            serde_json::json!({"op":"task","task":"b"}),
            serde_json::json!({"op":"access","task":"a","location":"cell","mode":"W"}),
            serde_json::json!({"op":"access","task":"b","location":"cell","mode":"R"}),
            serde_json::json!({"op":"end"}),
        ];
        assert_eq!(analyze_records(&rows, "test".into()).unwrap().count, 1);
    }
    #[test]
    fn synchronized_send_receive() {
        let rows = vec![
            serde_json::json!({"op":"begin"}),
            serde_json::json!({"op":"task","task":"a"}),
            serde_json::json!({"op":"task","task":"b"}),
            serde_json::json!({"op":"access","task":"a","location":"cell","mode":"W"}),
            serde_json::json!({"op":"send","task":"a","message":"m"}),
            serde_json::json!({"op":"recv","task":"b","message":"m"}),
            serde_json::json!({"op":"access","task":"b","location":"cell","mode":"R"}),
            serde_json::json!({"op":"end"}),
        ];
        assert_eq!(analyze_records(&rows, "test".into()).unwrap().count, 0);
    }
}
