//! Bounded, deterministic host-only logical schedule explorer.
//! This is a reference state machine, not a guest runtime scheduler or a
//! proof of race freedom. Exhaustion and arithmetic overflows fail closed.

use crate::race_offline::relative_trace;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(unix))]
use std::io::Read;
use std::path::Path;

const MAX_SOURCE: u64 = 2_000_000;
const MAX_DEPTH: usize = 32;
const MAX_ITEMS: usize = 8_192;
const MAX_ACTORS: usize = 16;
const MAX_STATE_KEYS: usize = 256;
const MAX_TURNS: usize = 64;
const MAX_OPS: usize = 4_096;
const MAX_VISITS: u64 = 10_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Json {
    Object(BTreeMap<String, Json>),
    Array(Vec<Json>),
    String(String),
    Int(i64),
    Bool,
    Null,
}

struct JsonReader<'a> {
    src: &'a str,
    at: usize,
    items: usize,
}
impl<'a> JsonReader<'a> {
    fn next(&self) -> Option<char> {
        self.src[self.at..].chars().next()
    }
    fn pop(&mut self) -> Option<char> {
        let c = self.next()?;
        self.at += c.len_utf8();
        Some(c)
    }
    fn ws(&mut self) {
        while self
            .next()
            .is_some_and(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
        {
            self.pop();
        }
    }
    fn expect(&mut self, c: char) -> Result<(), String> {
        if self.pop() == Some(c) {
            Ok(())
        } else {
            Err(format!("invalid JSON, expected {c}"))
        }
    }
    fn hex4(&mut self) -> Result<u16, String> {
        let mut n = 0u16;
        for _ in 0..4 {
            n = n
                .checked_mul(16)
                .and_then(|x| {
                    self.pop()
                        .and_then(|c| c.to_digit(16))
                        .and_then(|d| x.checked_add(d as u16))
                })
                .ok_or("invalid JSON Unicode escape")?;
        }
        Ok(n)
    }
    fn string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut result = String::new();
        loop {
            let c = self.pop().ok_or("unterminated JSON string")?;
            if c == '"' {
                return Ok(result);
            }
            if c.is_control() {
                return Err("unescaped control code".into());
            }
            if c != '\\' {
                result.push(c);
            } else {
                match self.pop().ok_or("unterminated escape")? {
                    '"' => result.push('"'),
                    '\\' => result.push('\\'),
                    '/' => result.push('/'),
                    'b' => result.push('\u{0008}'),
                    'f' => result.push('\u{000c}'),
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    'u' => {
                        let head = self.hex4()?;
                        let code = if (0xD800..=0xDBFF).contains(&head) {
                            self.expect('\\')?;
                            self.expect('u')?;
                            let tail = self.hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&tail) {
                                return Err("invalid Unicode surrogate".into());
                            }
                            0x10000
                                + ((u32::from(head) - 0xD800) << 10)
                                + (u32::from(tail) - 0xDC00)
                        } else {
                            if (0xDC00..=0xDFFF).contains(&head) {
                                return Err("orphan Unicode surrogate".into());
                            }
                            u32::from(head)
                        };
                        result.push(char::from_u32(code).ok_or("invalid Unicode codepoint")?);
                    }
                    _ => return Err("invalid JSON string escape".into()),
                }
            }
            if result.len() > 4096 {
                return Err("JSON string length budget exceeded".into());
            }
        }
    }
    fn integer(&mut self) -> Result<i64, String> {
        let start = self.at;
        if self.next() == Some('-') {
            self.pop();
        }
        let zero = self.next() == Some('0');
        let mut digits = 0;
        while self.next().is_some_and(|c| c.is_ascii_digit()) {
            self.pop();
            digits += 1;
            if zero && digits > 1 {
                return Err("leading-zero JSON number".into());
            }
        }
        if digits == 0
            || self
                .next()
                .is_some_and(|c| matches!(c, '.' | 'e' | 'E' | '+'))
        {
            return Err("JSON model only supports signed 64-bit integers".into());
        }
        self.src[start..self.at]
            .parse::<i64>()
            .map_err(|_| "JSON integer overflow".into())
    }
    fn literal(&mut self, lit: &str) -> Result<(), String> {
        for c in lit.chars() {
            self.expect(c)?;
        }
        Ok(())
    }
    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err("JSON nesting depth exceeded".into());
        }
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err("JSON element budget exceeded".into());
        }
        self.ws();
        match self.next() {
            Some('{') => {
                self.pop();
                let mut map = BTreeMap::new();
                self.ws();
                if self.next() == Some('}') {
                    self.pop();
                    return Ok(Json::Object(map));
                }
                loop {
                    self.ws();
                    let key = self.string()?;
                    self.ws();
                    self.expect(':')?;
                    let val = self.value(depth + 1)?;
                    if map.insert(key, val).is_some() {
                        return Err("duplicate JSON property".into());
                    }
                    self.ws();
                    match self.pop() {
                        Some('}') => break,
                        Some(',') => {}
                        _ => return Err("malformed JSON object delimiter".into()),
                    }
                }
                Ok(Json::Object(map))
            }
            Some('[') => {
                self.pop();
                let mut array = Vec::new();
                self.ws();
                if self.next() == Some(']') {
                    self.pop();
                    return Ok(Json::Array(array));
                }
                loop {
                    array.push(self.value(depth + 1)?);
                    self.ws();
                    match self.pop() {
                        Some(']') => break,
                        Some(',') => {}
                        _ => return Err("malformed JSON array delimiter".into()),
                    }
                }
                Ok(Json::Array(array))
            }
            Some('"') => self.string().map(Json::String),
            Some('-' | '0'..='9') => self.integer().map(Json::Int),
            Some('t') => {
                self.literal("true")?;
                Ok(Json::Bool)
            }
            Some('f') => {
                self.literal("false")?;
                Ok(Json::Bool)
            }
            Some('n') => {
                self.literal("null")?;
                Ok(Json::Null)
            }
            _ => Err("invalid JSON value".into()),
        }
    }
    fn parse(src: &'a str) -> Result<Json, String> {
        let mut parser = Self {
            src,
            at: 0,
            items: 0,
        };
        let result = parser.value(0)?;
        parser.ws();
        if parser.next().is_some() {
            return Err("trailing JSON input".into());
        }
        Ok(result)
    }
}
fn obj(value: &Json) -> Result<&BTreeMap<String, Json>, String> {
    match value {
        Json::Object(v) => Ok(v),
        _ => Err("expected JSON object".into()),
    }
}
fn array(value: &Json) -> Result<&[Json], String> {
    match value {
        Json::Array(v) => Ok(v),
        _ => Err("expected JSON array".into()),
    }
}
fn string(value: &Json) -> Result<&str, String> {
    match value {
        Json::String(v) if !v.is_empty() && v.len() <= 128 => Ok(v),
        _ => Err("expected bounded string".into()),
    }
}
fn integer(value: &Json) -> Result<i64, String> {
    match value {
        Json::Int(n) => Ok(*n),
        _ => Err("expected signed 64-bit integer".into()),
    }
}
fn exact(map: &BTreeMap<String, Json>, keys: &[&str]) -> Result<(), String> {
    if map.len() != keys.len() || keys.iter().any(|x| !map.contains_key(*x)) {
        return Err("unknown or missing model properties".into());
    }
    Ok(())
}
fn required<'a>(map: &'a BTreeMap<String, Json>, key: &str) -> Result<&'a Json, String> {
    map.get(key)
        .ok_or_else(|| format!("missing model property: {key}"))
}
fn state(value: &Json) -> Result<BTreeMap<String, i64>, String> {
    let map = obj(value)?;
    if map.len() > MAX_STATE_KEYS {
        return Err("model state key budget exceeded".into());
    }
    let mut output = BTreeMap::new();
    for (k, v) in map {
        if k.is_empty() || k.len() > 128 {
            return Err("invalid state key".into());
        }
        output.insert(k.clone(), integer(v)?);
    }
    Ok(output)
}

#[derive(Clone, Debug)]
enum Value {
    Literal(i64),
    Local { name: String, add: i64 },
}
#[derive(Clone, Debug)]
enum Operation {
    Read { key: String, local: String },
    Write { key: String, value: Value },
    AtomicAdd { key: String, delta: i64 },
}
#[derive(Clone, Debug)]
struct Actor {
    name: String,
    turns: Vec<Vec<Operation>>,
}
struct Model {
    initial: BTreeMap<String, i64>,
    expected: BTreeMap<String, i64>,
    actors: Vec<Actor>,
}
impl Model {
    fn load(input: &str) -> Result<Self, String> {
        if input.len() > MAX_SOURCE as usize {
            return Err("logical model exceeds 2 MB".into());
        }
        let root = JsonReader::parse(input)?;
        let r = obj(&root)?;
        exact(r, &["initial", "expected", "actors"])?;
        let initial = state(required(r, "initial")?)?;
        let expected = state(required(r, "expected")?)?;
        if expected.is_empty() || expected.keys().any(|k| !initial.contains_key(k)) {
            return Err("expected must constrain initialized state".into());
        }
        let actor_list = array(required(r, "actors")?)?;
        if !(2..=MAX_ACTORS).contains(&actor_list.len()) {
            return Err("logical model requires 2..16 actors".into());
        }
        let mut actors = Vec::new();
        let mut names = BTreeSet::new();
        let mut turns_total = 0;
        let mut ops_total = 0;
        for spec in actor_list {
            let data = obj(spec)?;
            exact(data, &["name", "turns"])?;
            let name = string(required(data, "name")?)?.to_owned();
            if !names.insert(name.clone()) {
                return Err("duplicate logical actor".into());
            }
            let turns = array(required(data, "turns")?)?;
            if turns.is_empty() {
                return Err("actor must declare a turn".into());
            }
            turns_total += turns.len();
            if turns_total > MAX_TURNS {
                return Err("model turn budget exceeded".into());
            }
            let mut actor_turns = Vec::new();
            let mut prior = BTreeSet::new();
            for turn in turns {
                let ops = array(turn)?;
                if ops.is_empty() {
                    return Err("actor turn has no operations".into());
                }
                ops_total += ops.len();
                if ops_total > MAX_OPS {
                    return Err("logical model operation budget exceeded".into());
                }
                let mut decoded = Vec::new();
                for raw in ops {
                    let fields = obj(raw)?;
                    let kind = string(required(fields, "op")?)?;
                    let key = string(required(fields, "key")?)?.to_owned();
                    if !initial.contains_key(&key) {
                        return Err("operation references unknown state key".into());
                    }
                    match kind {
                        "read" => {
                            exact(fields, &["op", "key", "as"])?;
                            let name = string(required(fields, "as")?)?.to_owned();
                            prior.insert(name.clone());
                            decoded.push(Operation::Read { key, local: name });
                        }
                        "write" => {
                            exact(fields, &["op", "key", "value"])?;
                            let value = match required(fields, "value")? {
                                Json::Int(i) => Value::Literal(*i),
                                other => {
                                    let expr = obj(other)?;
                                    if !expr.contains_key("local")
                                        || !(expr.len() == 1
                                            || (expr.len() == 2 && expr.contains_key("add")))
                                    {
                                        return Err("invalid local arithmetic expression".into());
                                    }
                                    let name = string(required(expr, "local")?)?.to_owned();
                                    if !prior.contains(&name) {
                                        return Err("read local before definition".into());
                                    }
                                    let add = match expr.get("add") {
                                        Some(v) => integer(v)?,
                                        None => 0,
                                    };
                                    Value::Local { name, add }
                                }
                            };
                            decoded.push(Operation::Write { key, value });
                        }
                        "atomic_add" => {
                            exact(fields, &["op", "key", "value"])?;
                            let delta = integer(required(fields, "value")?)?;
                            decoded.push(Operation::AtomicAdd { key, delta });
                        }
                        _ => return Err("unsupported logical operation".into()),
                    }
                }
                actor_turns.push(decoded);
            }
            actors.push(Actor {
                name,
                turns: actor_turns,
            });
        }
        Ok(Self {
            initial,
            expected,
            actors,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub schedule: Vec<String>,
    pub final_state: BTreeMap<String, i64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub schedules: u64,
    pub visits: u64,
    pub truncated: bool,
    pub violation: Option<Violation>,
}

fn apply(
    turn: &[Operation],
    state: &mut BTreeMap<String, i64>,
    locals: &mut BTreeMap<String, i64>,
) -> Result<(), String> {
    for op in turn {
        match op {
            Operation::Read { key, local } => {
                let v = *state.get(key).ok_or("unknown model read key")?;
                locals.insert(local.clone(), v);
            }
            Operation::Write { key, value } => {
                let number = match value {
                    Value::Literal(v) => *v,
                    Value::Local { name, add } => locals
                        .get(name)
                        .ok_or("missing read local")?
                        .checked_add(*add)
                        .ok_or("logical arithmetic overflow")?,
                };
                *state.get_mut(key).ok_or("unknown model write key")? = number;
            }
            Operation::AtomicAdd { key, delta } => {
                let n = state.get_mut(key).ok_or("unknown atomic state key")?;
                *n = n.checked_add(*delta).ok_or("logical arithmetic overflow")?;
            }
        }
    }
    Ok(())
}
fn dfs(
    model: &Model,
    indices: &mut [usize],
    state: &BTreeMap<String, i64>,
    locals: &[BTreeMap<String, i64>],
    schedule: &mut Vec<String>,
    result: &mut Report,
    limit: u64,
) -> Result<(), String> {
    if result.visits >= MAX_VISITS {
        result.truncated = true;
        return Ok(());
    }
    result.visits += 1;
    if indices
        .iter()
        .enumerate()
        .all(|(i, n)| *n == model.actors[i].turns.len())
    {
        if result.schedules >= limit {
            result.truncated = true;
            return Ok(());
        }
        result.schedules += 1;
        if model.expected.iter().any(|(k, v)| state.get(k) != Some(v)) {
            result.violation = Some(Violation {
                schedule: schedule.clone(),
                final_state: state.clone(),
            });
        }
        return Ok(());
    }
    if result.schedules >= limit {
        result.truncated = true;
        return Ok(());
    }
    for (i, actor) in model.actors.iter().enumerate() {
        if indices[i] == actor.turns.len() {
            continue;
        }
        let mut next_state = state.clone();
        let mut next_locals = locals.to_vec();
        apply(
            &actor.turns[indices[i]],
            &mut next_state,
            &mut next_locals[i],
        )?;
        let original = indices[i];
        indices[i] += 1;
        schedule.push(format!("{}:{original}", actor.name));
        let step = dfs(
            model,
            indices,
            &next_state,
            &next_locals,
            schedule,
            result,
            limit,
        );
        schedule.pop();
        indices[i] = original;
        step?;
        if result.violation.is_some() || result.truncated {
            break;
        }
    }
    Ok(())
}
pub fn explore(input: &str, max_schedules: u64) -> Result<Report, String> {
    if !(1..=1_000_000).contains(&max_schedules) {
        return Err("schedule limit must be 1..1000000".into());
    }
    let model = Model::load(input)?;
    let mut result = Report {
        schedules: 0,
        visits: 0,
        truncated: false,
        violation: None,
    };
    dfs(
        &model,
        &mut vec![0; model.actors.len()],
        &model.initial,
        &vec![BTreeMap::new(); model.actors.len()],
        &mut Vec::new(),
        &mut result,
        max_schedules,
    )?;
    if result.schedules == 0 {
        return Err("no completed logical schedules".into());
    }
    Ok(result)
}
pub fn offline(root: &Path, name: &str, max_schedules: u64) -> Result<i32, String> {
    let path = relative_trace(root, name)?;
    if path.extension().is_none_or(|ext| ext != "json") {
        return Err("logical model requires .json".into());
    }
    #[cfg(unix)]
    let bytes = crate::fs_secure::read_project_file(root, Path::new(name), MAX_SOURCE as usize)?;
    #[cfg(not(unix))]
    let bytes = {
        if path.metadata().map_err(|e| e.to_string())?.len() > MAX_SOURCE {
            return Err("model exceeds 2 MB".into());
        }
        let mut data = Vec::new();
        std::fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(MAX_SOURCE + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        data
    };
    if bytes.len() as u64 > MAX_SOURCE {
        return Err("model exceeds 2 MB".into());
    }
    let input = String::from_utf8(bytes).map_err(|_| "model is not UTF-8")?;
    let report = explore(&input, max_schedules)?;
    if let Some(found) = report.violation {
        println!(
            "LOGICAL COUNTEREXAMPLE schedules={} visits={} schedule={:?} final={:?}",
            report.schedules, report.visits, found.schedule, found.final_state
        );
        return Ok(1);
    }
    if report.truncated {
        return Err(format!("logical exploration INCONCLUSIVE: schedule/visit bound at {max_schedules}; explored {} schedules",report.schedules));
    }
    println!("LOGICAL MODEL OBSERVED-CLEAN: {} schedules, {} search visits; host model only, not guest runtime scheduling proof",report.schedules,report.visits);
    Ok(0)
}
#[cfg(test)]
mod tests {
    use super::*;
    const ATOMIC: &str = include_str!("../tests/models/atomic-update.json");
    const LOST: &str = include_str!("../tests/models/lost-update.json");

    #[test]
    fn atomic_add_has_no_counterexample_on_all_two_actor_schedules() {
        let result = explore(ATOMIC, 10).unwrap();
        assert_eq!(result.schedules, 2);
        assert!(!result.truncated);
        assert!(result.violation.is_none());
    }
    #[test]
    fn lost_update_produces_reproducible_counterexample() {
        let result = explore(LOST, 100).unwrap();
        assert!(result.violation.is_some());
        let fail = result.violation.unwrap();
        assert_eq!(fail.final_state.get("count"), Some(&1));
        assert_eq!(fail.schedule.len(), 4);
    }
    #[test]
    fn schedule_budget_fails_closed_for_insufficient_exploration() {
        let result = explore(ATOMIC, 1).unwrap();
        assert!(result.truncated);
        assert_eq!(result.schedules, 1);
    }
    #[test]
    fn rejects_duplicate_json_keys_boolean_state_and_invalid_local() {
        let dupe = ATOMIC.replace("\"count\": 0", "\"count\": 0, \"count\": 0");
        assert!(explore(&dupe, 10).is_err());
        let boolean = ATOMIC.replace("\"count\": 0", "\"count\": true");
        assert!(explore(&boolean, 10).is_err());
        let missing = LOST.replace("\"local\": \"seen\"", "\"local\": \"missing\"");
        assert!(explore(&missing, 10).is_err());
    }
    #[test]
    fn checked_signed_arithmetic_and_unicode_escape() {
        let src = ATOMIC.replace("\"count\": 0", &format!("\"count\": {}", i64::MAX));
        assert!(explore(&src, 10).is_err());
        assert!(JsonReader::parse(r#"{"value":"\uD800"}"#).is_err());
        assert!(JsonReader::parse(r#"{"value":"\uD83D\uDE00"}"#).is_ok());
    }
}
