//! Bounded logical actor-turn reference model explorer (not guest scheduler control).
use crate::common::{bounded_read, strict_json_object, Result};
use serde_json::Value;
use std::{collections::{BTreeMap,HashSet},path::Path};
type State=BTreeMap<String,i64>;
#[derive(Clone)]
struct Actor { name:String, turns:Vec<Vec<Value>> }
pub struct ModelReport {pub schedules:usize,pub violation:Option<String>}
fn int(v:&Value)->Result<i64>{v.as_i64().ok_or_else(||"expected integer".into())}
fn object_state(v:&Value)->Result<State> {
    let obj=v.as_object().ok_or("expected state object")?;
    if obj.len()>256 {return Err("at most 256 state keys".into());}
    obj.iter().map(|(k,v)|{
        if k.is_empty(){return Err("empty state key".into());}
        Ok((k.clone(),int(v)?))
    }).collect()
}
fn exact_keys(v:&Value, keys:&[&str])->bool{
    v.as_object().is_some_and(|m|m.len()==keys.len() && keys.iter().all(|k|m.contains_key(*k)))
}
fn eval(v:&Value,local:&State)->Result<i64>{
    if let Some(n)=v.as_i64(){return Ok(n);}
    let name=v.get("local").and_then(Value::as_str).ok_or("invalid local reference")?;
    if !exact_keys(v,&["local"]) && !exact_keys(v,&["local","add"]) {return Err("invalid local expression".into());}
    let start=*local.get(name).ok_or("unbound local expression")?;
    start.checked_add(v.get("add").map(int).transpose()?.unwrap_or(0))
        .ok_or_else(||"arithmetic overflow".into())
}
fn apply(ops:&[Value],state:&mut State,local:&mut State)->Result<()> {
    for op in ops {
        let key=op.get("key").and_then(Value::as_str).ok_or("missing operation key")?;
        if !state.contains_key(key){return Err("operation refers to unknown state key".into());}
        match op.get("op").and_then(Value::as_str) {
            Some("read")=>{
                let dest=op.get("as").and_then(Value::as_str).ok_or("missing local name")?;
                local.insert(dest.into(),state[key]);
            },
            Some("write")=>{
                let value=eval(op.get("value").ok_or("missing write value")?,local)?;
                state.insert(key.into(),value);
            },
            Some("atomic_add")=>{
                let inc=int(op.get("value").ok_or("missing atomic_add value")?)?;
                state.insert(key.into(),state[key].checked_add(inc).ok_or("arithmetic overflow")?);
            },
            _=>return Err("unknown model operation".into())
        }
    }
    Ok(())
}
struct Search<'a> {
    actors: &'a [Actor],
    expected: &'a State,
    limit: usize,
    report: &'a mut ModelReport,
    nodes: &'a mut usize,
}
impl Search<'_> {
    fn dfs(&mut self, indices:&[usize], state:&State, locals:&[State], path:&[String])->Result<()> {
        *self.nodes+=1;
        if *self.nodes>10_000_000 { return Err("inconclusive: exploration node budget exhausted".into()); }
        if indices.iter().enumerate().all(|(i,index)|*index==self.actors[i].turns.len()) {
            if self.report.schedules>=self.limit {return Err(format!("inconclusive: reached schedule limit {}", self.limit));}
            self.report.schedules+=1;
            if self.expected.iter().any(|(k,v)|state.get(k)!=Some(v)) {
                self.report.violation=Some(format!("schedule={path:?} final={state:?} expected={:?}", self.expected));
            }
            return Ok(());
        }
        if self.report.violation.is_some(){return Ok(());}
        if self.report.schedules>=self.limit{return Err(format!("inconclusive: reached schedule limit {}", self.limit));}
        for (i,actor) in self.actors.iter().enumerate(){
            if indices[i]>=actor.turns.len(){continue;}
            let mut next_state=state.clone();
            let mut next_locals=locals.to_vec();
            apply(&actor.turns[indices[i]],&mut next_state,&mut next_locals[i])?;
            let mut next_indices=indices.to_vec();next_indices[i]+=1;
            let mut next_path=path.to_vec();next_path.push(format!("{}:{}",actor.name,indices[i]));
            self.dfs(&next_indices,&next_state,&next_locals,&next_path)?;
            if self.report.violation.is_some(){break;}
        }
        Ok(())
    }
}
pub fn explore(path:&Path,limit:usize)->Result<ModelReport>{
    if !(1..=1_000_000).contains(&limit){return Err("invalid schedule limit".into());}
    let bytes=bounded_read(path,2_000_000)?;
    let model:Value=strict_json_object(&bytes)?;
    if !model.is_object() {return Err("model must be a JSON object".into());}
    let state=object_state(model.get("initial").ok_or("model missing initial")?)?;
    let expected=object_state(model.get("expected").ok_or("model missing expected")?)?;
    if expected.is_empty() || expected.keys().any(|k|!state.contains_key(k)){
        return Err("expected must constrain initialized state".into());
    }
    let array=model.get("actors").and_then(Value::as_array).ok_or("missing actor array")?;
    if !(2..=16).contains(&array.len()){return Err("model requires 2..16 actors".into());}
    let mut actors=Vec::new();let mut names=HashSet::new();
    let (mut turns,mut operations)=(0,0);
    for actor in array {
        let name=actor.get("name").and_then(Value::as_str).ok_or("invalid actor name")?;
        if name.is_empty() || name.len()>128 || !names.insert(name.to_owned()){return Err("invalid/duplicate actor name".into());}
        let raw=actor.get("turns").and_then(Value::as_array).ok_or("missing turns")?;
        if raw.is_empty(){return Err("each actor requires turns".into());}
        let mut parsed=Vec::new();
        let mut declared=HashSet::new();
        for turn in raw {
            let ops=turn.as_array().ok_or("turn must be an array")?;
            if ops.is_empty(){return Err("empty actor turn".into());}
            turns+=1;operations+=ops.len();
            for op in ops {
                let key=op.get("key").and_then(Value::as_str).ok_or("invalid op key")?;
                if !state.contains_key(key){return Err("undeclared key".into());}
                match op.get("op").and_then(Value::as_str) {
                    Some("read") if exact_keys(op,&["op","key","as"])=>{
                        let name=op.get("as").and_then(Value::as_str).ok_or("missing read local")?;
                        if name.is_empty(){return Err("empty local name".into());}
                        declared.insert(name.to_string());
                    },
                    Some("write") if exact_keys(op,&["op","key","value"])=>{
                        let value=&op["value"];
                        if !value.is_i64() {
                            let name=value.get("local").and_then(Value::as_str).ok_or("invalid write expression")?;
                            if !declared.contains(name) || (!exact_keys(value,&["local"]) && !exact_keys(value,&["local","add"])) ||
                               value.get("add").is_some_and(|x|!x.is_i64()){
                                return Err("unbound/invalid write local".into());
                            }
                        }
                    },
                    Some("atomic_add") if exact_keys(op,&["op","key","value"]) && op["value"].is_i64()=>{},
                    _=>return Err("unknown/invalid model operation".into())
                }
            }
            parsed.push(ops.clone());
        }
        actors.push(Actor{name:name.into(),turns:parsed});
    }
    if turns>64 || operations>4096 {return Err("model exceeds turns/operations limit".into());}
    let mut report=ModelReport{schedules:0,violation:None};
    let mut nodes=0;
    let mut search=Search{actors:&actors,expected:&expected,limit,report:&mut report,nodes:&mut nodes};
    search.dfs(&vec![0;actors.len()],&state,&vec![State::new();actors.len()],&[])?;
    Ok(report)
}
