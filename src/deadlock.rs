//! Bounded lock-order and wait-for graph checks; no whole-program liveness claim.
use crate::common::{bounded_read, field, trace, Result};
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::Path;
type Graph=BTreeMap<String,BTreeSet<String>>;
#[derive(Debug)]
pub struct Report {
    pub backend: String, pub events: usize, pub lock_events: usize,
    pub orders: Vec<Vec<String>>, pub waits: Vec<Vec<String>>, pub runtime: Vec<String>,
}
fn cycles(graph:&Graph)->Result<Vec<Vec<String>>>{
    let mut witnesses=Vec::new();
    let mut found=HashSet::new();
    let mut budget=250_000i32;
    for origin in graph.keys() {
        let mut todo=VecDeque::from([(origin.clone(),vec![origin.clone()])]);
        let mut seen=HashSet::from([origin.clone()]);
        while let Some((here,path))=todo.pop_front() {
            budget-=1;
            if budget<0 {return Err("inconclusive: lock graph traversal budget exceeded".into());}
            if let Some(next)=graph.get(&here) {
                for node in next {
                    if node==origin {
                        let rotation=(0..path.len())
                            .map(|i|{let mut v=path[i..].to_vec();v.extend_from_slice(&path[..i]);v})
                            .min().unwrap_or_default();
                        if found.insert(rotation.clone()) {
                            let mut cycle=rotation.clone();cycle.push(rotation[0].clone());
                            witnesses.push(cycle);
                        }
                        todo.clear();break;
                    }
                    if seen.insert(node.clone()) {
                        let mut branch=path.clone();branch.push(node.clone());
                        todo.push_back((node.clone(),branch));
                    }
                }
            }
            if witnesses.len()>=100 {return Ok(witnesses);}
        }
    }
    Ok(witnesses)
}
fn checkpoint(raw:&str)->Result<Report>{
    let lines:Vec<_>=raw.lines().collect();
    if lines.is_empty() || lines.len()>100_001 {return Err("runtime checkpoint event budget exceeded".into());}
    let valid= [
      r"^ORES_CONCURRENCY_TRACE_V1\|seed=-?[0-9]+$",
      r"^ORES_CONCURRENCY_TRACE_V2\|seed=-?[0-9]+\|entry-sha256=[0-9a-f]{64}\|backend=[A-Za-z0-9_.-]{1,80}\|probe=1$",
      r"^ORES_CONCURRENCY_TRACE_V3\|seed=-?[0-9]+\|entry-sha256=[0-9a-f]{64}\|workspace-sha256=[0-9a-f]{64}\|backend=[A-Za-z0-9_.-]{1,80}\|probe=3$"
    ].iter().any(|p|Regex::new(p).unwrap().is_match(lines[0]));
    if !valid {return Err("invalid runtime checkpoint header".into());}
    let event=Regex::new(r"^[a-z][a-z0-9-]{0,47}\|[012]$").unwrap();
    let mut runtime=Vec::new();
    for line in &lines[1..] {
        if !event.is_match(line){return Err("invalid runtime checkpoint event".into());}
        if line.starts_with("deadlock-") {
            let name=line.split('|').next().unwrap_or("");
            if name!="deadlock-future-cycle" && name!="deadlock-mutex-cycle" {
                return Err("unsupported runtime deadlock event".into());
            }
            runtime.push(name.to_owned());
        }
    }
    Ok(Report {backend:"graal-checkpoints".into(),events:lines.len()-1,lock_events:0,
        orders:vec![],waits:vec![],runtime})
}
pub fn analyze(path:&Path,expected:Option<&str>)->Result<Report>{
    let bytes=bounded_read(path,10_000_000)?;
    if bytes.starts_with(b"ORES_CONCURRENCY_TRACE_V") {
        if expected.is_some(){return Err("runtime checkpoint trace has no nonce binding".into());}
        let raw=std::str::from_utf8(&bytes).map_err(|e|e.to_string())?;
        if bytes.len()>8_000_000 {return Err("runtime checkpoint exceeds 8 MB".into());}
        return checkpoint(raw);
    }
    let rows=trace(path,expected)?;
    analyze_records(&rows)
}
fn analyze_records(rows:&[Value])->Result<Report>{
    let mut participants=HashSet::new();
    let mut finished=HashSet::new();
    let mut owners:HashMap<String,String>=HashMap::new();
    let mut held:HashMap<String,HashSet<String>>=HashMap::new();
    let mut pending:HashMap<String,String>=HashMap::new();
    let mut ordering:Graph=Graph::new();
    let (mut edges,mut observed)=(0,0usize);
    for (index,event) in rows[1..rows.len()-1].iter().enumerate() {
        let task=field(event,"task")?.to_owned();
        let op=field(event,"op")?;
        if op=="task" {
            if participants.len()>=256 || !participants.insert(task.clone()) {
                return Err("duplicate task or >256 tasks".into());
            }
            held.insert(task,HashSet::new()); continue;
        }
        if !participants.contains(&task) || finished.contains(&task) {return Err(format!("unknown or finished participant at {}",index+2));}
        match op {
            "fork" => {
                let child=field(event,"child")?.to_owned();
                if participants.len()>=256 || !participants.insert(child.clone()) {return Err("duplicate forked child".into());}
                held.insert(child,HashSet::new());
            },
            "finish" => {
                if !held[&task].is_empty() || pending.contains_key(&task) {return Err("finish while holding/waiting for lock".into());}
                finished.insert(task.clone());
            },
            "lock" => {
                let name=field(event,"name")?.to_owned();
                if pending.contains_key(&task) || owners.contains_key(&name) {return Err("lock acquired during wait or already held".into());}
                if owners.len()>=2048 {return Err("more than 2048 held locks".into());}
                for prev in &held[&task] {
                    let set=ordering.entry(prev.clone()).or_default();
                    if !set.contains(&name) {
                        if edges>=10_000 {return Err("lock-order graph too large".into());}
                        set.insert(name.clone());edges+=1;
                    }
                }
                held.get_mut(&task).unwrap().insert(name.clone());
                owners.insert(name,task.clone());observed+=1;
            },
            "unlock" => {
                let name=field(event,"name")?;
                if owners.get(name).map(String::as_str)!=Some(task.as_str()) || pending.contains_key(&task) {
                    return Err("unlock of unowned lock or blocked participant".into());
                }
                owners.remove(name);held.get_mut(&task).unwrap().remove(name);
            },
            "wait" => {
                let name=field(event,"name")?.to_owned();
                if pending.contains_key(&task) || !owners.contains_key(&name) {
                    return Err("wait without a known lock owner or duplicate wait".into());
                }
                pending.insert(task.clone(),name); observed+=1;
            },
            "unwait" => {
                let name=field(event,"name")?;
                if pending.get(&task).map(String::as_str)!=Some(name) {
                    return Err("unwait does not match pending wait".into());
                }
                pending.remove(&task);
            },
            "join"=>{field(event,"child")?;},
            "send" | "recv"=>{field(event,"message")?;},
            "access" => {
                field(event,"location")?;
                let mode=field(event,"mode")?;
                if mode!="R" && mode!="W" {return Err("invalid access mode".into());}
            },
            _=>return Err(format!("unsupported deadlock event {op}"))
        }
    }
    if observed==0 {return Err("no lock acquisition/wait events; inconclusive".into());}
    let mut waits:Graph=Graph::new();
    for (task,name) in pending {
        if let Some(owner)=owners.get(&name) {waits.entry(task).or_default().insert(owner.clone());}
    }
    Ok(Report{backend:field(&rows[0],"backend")?.to_owned(),events:rows.len()-2,lock_events:observed,
        orders:cycles(&ordering)?,waits:cycles(&waits)?,runtime:vec![]})
}
#[cfg(test)]
mod tests {
 use super::*;
 #[test]
 fn inversion() {
    let mut rows=vec![serde_json::json!({"op":"begin","backend":"test"})];
    for task in ["a","b"] {
        rows.push(serde_json::json!({"op":"task","task":task}));
        for lock in if task=="a"{["left","right"]}else{["right","left"]} {
            rows.push(serde_json::json!({"op":"lock","task":task,"name":lock}));
        }
        for lock in if task=="a"{["right","left"]}else{["left","right"]} {
            rows.push(serde_json::json!({"op":"unlock","task":task,"name":lock}));
        }
    }
    rows.push(serde_json::json!({"op":"end"}));
    assert_eq!(analyze_records(&rows).unwrap().orders.len(),1);
 }
}
