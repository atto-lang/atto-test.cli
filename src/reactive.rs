//! Bounded reactive subscription protocol reference checker, not guest instrumentation.
use serde_json::Value;
use std::collections::{HashMap,HashSet};
use crate::common::Result;
#[derive(Default)]
pub struct Report {pub events:usize,pub subscriptions:usize,pub next:usize,pub terminals:usize,pub active:usize}
struct Subscriber {mode:String,requested:u32,terminal:bool,disposed:bool}
pub fn analyze(events:&[Value])->Result<Report> {
    if events.len()>100_000{return Err("reactive trace too large".into());}
    let mut sources:HashMap<String,HashSet<String>>=HashMap::new();
    let mut subs:HashMap<String,Subscriber>=HashMap::new();
    let mut report=Report{events:events.len(),..Report::default()};
    for (position,e) in events.iter().enumerate() {
        let op=e.get("op").and_then(Value::as_str).ok_or("invalid reactive op")?;
        let keys:Vec<&str>=match op{
            "subscribe"=>vec!["op","subscription","source","mode"],
            "request"=>vec!["op","subscription","count"],
            "next"=>vec!["op","subscription","payload"],
            "complete"|"cancel"|"dispose"=>vec!["op","subscription"],
            "error"=>vec!["op","subscription","reason"],
            _=>return Err(format!("invalid reactive op at {position}"))
        };
        let obj=e.as_object().ok_or("reactive event must be an object")?;
        if obj.keys().any(|k|!keys.contains(&k.as_str())){return Err("unexpected reactive event field".into());}
        let id=e.get("subscription").and_then(Value::as_str).ok_or("missing subscription")?;
        if id.is_empty()||id.len()>256{return Err("invalid subscription identity".into());}
        if op=="subscribe"{
            let source=e.get("source").and_then(Value::as_str).ok_or("missing source")?;
            let mode=e.get("mode").and_then(Value::as_str).ok_or("missing mode")?;
            if source.is_empty()||source.len()>256||!["hot_single","cold"].contains(&mode) {return Err("invalid subscription source or mode".into());}
            if subs.contains_key(id){return Err("duplicate subscription".into());}
            let assigned=sources.entry(source.into()).or_default();
            if mode=="hot_single" && !assigned.is_empty(){return Err("single-consumer hot source cannot multicast".into());}
            if mode=="cold" && assigned.iter().any(|n|subs.get(n).is_some_and(|s:&Subscriber|s.mode=="hot_single")){
                return Err("mixed source cardinality modes".into());
            }
            assigned.insert(id.into());
            subs.insert(id.into(),Subscriber{mode:mode.into(),requested:0,terminal:false,disposed:false});
            continue;
        }
        let state=subs.get_mut(id).ok_or("reactive event before subscribe")?;
        if op=="dispose"{
            if state.disposed || !state.terminal{return Err("duplicate disposal or no terminal cause".into());}
            state.disposed=true;continue;
        }
        if state.terminal{return Err("event after terminal".into());}
        match op {
            "request" => {
                let count=e.get("count").and_then(Value::as_u64).ok_or("invalid demand count")?;
                if count==0||count>4096||state.requested as u64 + count>4096 {
                    return Err("outstanding demand exceeds 4096".into());
                }
                state.requested+=count as u32;
            },
            "next" => {
                if state.requested==0{return Err("next without downstream demand".into());}
                state.requested-=1;report.next+=1;
            },
            "error"|"complete"|"cancel" => {
                if op=="error" {
                    let reason=e.get("reason").and_then(Value::as_str).ok_or("error missing reason")?;
                    if reason.is_empty()||reason.len()>4096{return Err("invalid error reason".into());}
                }
                state.terminal=true;report.terminals+=1;
            },
            _=>return Err("invalid reactive operation".into())
        }
    }
    if subs.values().any(|s|s.terminal && !s.disposed){return Err("terminal without disposal".into());}
    report.subscriptions=subs.len();report.active=subs.len()-report.terminals;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unrequested_next(){
        let events=vec![
            serde_json::json!({"op":"subscribe","subscription":"a","source":"s","mode":"hot_single"}),
            serde_json::json!({"op":"next","subscription":"a","payload":1})
        ];
        assert!(analyze(&events).is_err());
    }
}
