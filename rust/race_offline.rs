//! Strict, bounded Rust analysis of OFFLINE observed JSONL traces.
//! This is not a trusted runtime race-freedom certificate. Guest-authored
//! traces never authorize runtime instrumentation completeness.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(target_os = "linux"))]
use std::io::Read;
use std::path::{Component, Path};

const MAX_BYTES: u64 = 10_000_000;
const MAX_EVENTS: usize = 100_000;
const MAX_FIELDS: usize = 16;
const MAX_TASKS: usize = 256;
const MAX_REPORTED: usize = 100;
type Clock = BTreeMap<String, u64>;

#[derive(Clone, Debug)]
enum Value {
    Text(String),
    Integer(u64),
}
#[derive(Clone, Debug)]
pub(crate) struct Event {
    fields: BTreeMap<String, Value>,
}
impl Event {
    pub(crate) fn text(&self, key: &str) -> Result<&str, String> {
        match self.fields.get(key) {
            Some(Value::Text(s))
                if !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control) =>
            {
                Ok(s.as_str())
            }
            _ => Err(format!("missing/invalid text field {key}")),
        }
    }
    pub(crate) fn number(&self, key: &str) -> Result<u64, String> {
        match self.fields.get(key) {
            Some(Value::Integer(n)) => Ok(*n),
            _ => Err(format!("missing/invalid integer field {key}")),
        }
    }
    pub(crate) fn keys(&self, required: &[&str]) -> Result<(), String> {
        if self.fields.len() != required.len()
            || required.iter().any(|k| !self.fields.contains_key(*k))
        {
            return Err(format!("invalid fields for {}", self.text("op")?));
        }
        Ok(())
    }
}
pub(crate) struct Parser<'a> {
    text: &'a str,
    at: usize,
}
impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> {
        self.text[self.at..].chars().next()
    }
    fn take(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.at += ch.len_utf8();
        Some(ch)
    }
    fn ws(&mut self) {
        while self
            .peek()
            .is_some_and(|c| c == ' ' || c == '\t' || c == '\r')
        {
            self.take();
        }
    }
    fn expect(&mut self, target: char) -> Result<(), String> {
        if self.take() == Some(target) {
            Ok(())
        } else {
            Err(format!("invalid JSON: expected {target}"))
        }
    }
    fn hex16(&mut self) -> Result<u16, String> {
        let mut n = 0u16;
        for _ in 0..4 {
            n = n.checked_mul(16).ok_or("invalid Unicode escape")?;
            n = n
                .checked_add(
                    self.take()
                        .and_then(|c| c.to_digit(16))
                        .ok_or("invalid Unicode escape")? as u16,
                )
                .ok_or("invalid Unicode escape")?;
        }
        Ok(n)
    }
    fn quoted(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut result = String::new();
        loop {
            let c = self.take().ok_or("unterminated JSON string")?;
            if c == '"' {
                break;
            }
            if c.is_control() {
                return Err("unescaped control character in JSON".into());
            }
            if c != '\\' {
                result.push(c);
                continue;
            }
            match self.take().ok_or("unterminated JSON escape")? {
                '"' => result.push('"'),
                '\\' => result.push('\\'),
                '/' => result.push('/'),
                'b' => result.push('\u{0008}'),
                'f' => result.push('\u{000c}'),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                'u' => {
                    let first = self.hex16()?;
                    let cp = if (0xD800..=0xDBFF).contains(&first) {
                        self.expect('\\')?;
                        self.expect('u')?;
                        let lower = self.hex16()?;
                        if !(0xDC00..=0xDFFF).contains(&lower) {
                            return Err("invalid Unicode surrogate pair".into());
                        }
                        0x10000 + ((u32::from(first) - 0xD800) << 10) + (u32::from(lower) - 0xDC00)
                    } else {
                        if (0xDC00..=0xDFFF).contains(&first) {
                            return Err("isolated Unicode low surrogate".into());
                        }
                        u32::from(first)
                    };
                    result.push(char::from_u32(cp).ok_or("invalid Unicode scalar")?);
                }
                _ => return Err("unsupported JSON escape".into()),
            }
            if result.len() > 4096 {
                return Err("JSON string budget exceeded".into());
            }
        }
        if result.len() > 4096 {
            return Err("JSON string budget exceeded".into());
        }
        Ok(result)
    }
    fn integer(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        let mut digits = 0usize;
        let leading_zero = self.peek() == Some('0');
        while let Some(digit) = self.peek().and_then(|c| c.to_digit(10)) {
            if digits > 0 && leading_zero {
                return Err("leading-zero JSON number".into());
            }
            value = value
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(digit)))
                .ok_or("JSON integer overflow")?;
            digits += 1;
            self.take();
        }
        if digits == 0 {
            return Err("expected unsigned JSON integer".into());
        }
        Ok(value)
    }
    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some('"') => self.quoted().map(Value::Text),
            Some('0'..='9') => self.integer().map(Value::Integer),
            _ => Err("unsupported JSON event field type".into()),
        }
    }
    pub(crate) fn object(text: &'a str) -> Result<Event, String> {
        let mut p = Parser { text, at: 0 };
        p.ws();
        p.expect('{')?;
        let mut fields = BTreeMap::new();
        p.ws();
        if p.peek() == Some('}') {
            p.take();
        } else {
            loop {
                if fields.len() >= MAX_FIELDS {
                    return Err("event property budget exceeded".into());
                }
                let key = p.quoted()?;
                p.ws();
                p.expect(':')?;
                p.ws();
                let value = p.value()?;
                if fields.insert(key, value).is_some() {
                    return Err("duplicate JSON event property".into());
                }
                p.ws();
                match p.take() {
                    Some('}') => break,
                    Some(',') => {
                        p.ws();
                    }
                    _ => return Err("malformed JSON object separator".into()),
                }
            }
        }
        p.ws();
        if p.peek().is_some() {
            return Err("trailing JSON data".into());
        }
        Ok(Event { fields })
    }
}
/// Full vector-clock comparison. Retained as the test oracle for the epoch
/// check used by `analyze`.
#[cfg(test)]
fn ordered(earlier: &Clock, later: &Clock) -> bool {
    earlier
        .iter()
        .all(|(k, v)| *v <= later.get(k).copied().unwrap_or(0))
}
fn merge(target: &mut Clock, source: &Clock) {
    for (k, v) in source {
        target
            .entry(k.clone())
            .and_modify(|existing| *existing = (*existing).max(*v))
            .or_insert(*v);
    }
}
/// Last access per task, stored as an epoch: that task's own clock component
/// at the access. Every event increments its task's component, so access e
/// by task p happens-before a later event f iff `V_e[p] <= V_f[p]` (the
/// FastTrack epoch property). Comparing full clocks gave identical verdicts
/// but cost O(tasks) per prior access: a 5.5 MB in-budget trace (256 tasks,
/// ~99k unsynchronized writes) took 54 s of CPU.
#[derive(Default)]
struct MemoryHistory {
    reads: BTreeMap<String, u64>,
    writes: BTreeMap<String, u64>,
    #[cfg(test)]
    full: BTreeMap<(bool, String), Clock>,
}

fn happens_before(prior_task: &str, epoch: u64, current: &Clock) -> bool {
    return epoch <= current.get(prior_task).copied().unwrap_or(0);
}
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub events: usize,
    pub accesses: usize,
    pub conflicts: u64,
    pub backend: String,
    pub examples: Vec<String>,
}
pub fn analyze(text: &str) -> Result<Report, String> {
    if text.len() > MAX_BYTES as usize {
        return Err("trace exceeds 10 MB".into());
    }
    let lines: Vec<&str> = text.lines().collect();
    if !(2..=MAX_EVENTS + 2).contains(&lines.len()) {
        return Err("invalid trace event count".into());
    }
    let begin = Parser::object(lines[0])?;
    begin.keys(&["op", "version", "run_id", "backend"])?;
    if begin.text("op")? != "begin" || begin.number("version")? != 1 {
        return Err("missing ORES_RACE_V1 header".into());
    }
    let run_id = begin.text("run_id")?.to_owned();
    let backend = begin.text("backend")?.to_owned();
    let end = Parser::object(lines[lines.len() - 1])?;
    end.keys(&["op", "run_id", "events"])?;
    if end.text("op")? != "end"
        || end.text("run_id")? != run_id
        || end.number("events")? != (lines.len() - 2) as u64
    {
        return Err("missing or inconsistent terminal trace receipt".into());
    }
    let mut clocks: BTreeMap<String, Clock> = BTreeMap::new();
    let mut finished = BTreeSet::new();
    let mut parents = BTreeMap::new();
    let mut joined = BTreeSet::new();
    let mut locks: BTreeMap<String, (Option<String>, Clock)> = BTreeMap::new();
    let mut messages = BTreeMap::<String, Clock>::new();
    let mut seen_messages = BTreeSet::<String>::new();
    let mut pending_waits = BTreeMap::<String, String>::new();
    let mut history = BTreeMap::<String, MemoryHistory>::new();
    let mut conflicts = 0u64;
    let mut examples = Vec::new();
    let mut accesses = 0usize;

    for (index, line) in lines[1..lines.len() - 1].iter().enumerate() {
        let e = Parser::object(line).map_err(|err| format!("event {}: {err}", index + 2))?;
        let op = e.text("op")?.to_owned();
        let task = e.text("task")?.to_owned();
        let allow = match op.as_str() {
            "task" | "finish" => &["op", "task"][..],
            "fork" | "join" => &["op", "task", "child"][..],
            "lock" | "unlock" | "wait" | "unwait" => &["op", "task", "name"][..],
            "send" | "recv" => &["op", "task", "message"][..],
            "access" => &["op", "task", "location", "mode"][..],
            _ => return Err(format!("event {}: unsupported operation {op}", index + 2)),
        };
        e.keys(allow)?;
        if op == "task" {
            if clocks.len() >= MAX_TASKS || clocks.contains_key(&task) {
                return Err("duplicate or over-budget trace task".into());
            }
            let mut initial = Clock::new();
            initial.insert(task.clone(), 1);
            clocks.insert(task, initial);
            continue;
        }
        if finished.contains(&task) {
            return Err("event after task completion".into());
        }
        // A task blocked waiting for a held lock cannot execute memory
        // accesses, send/receive messages or spawn children. Previously
        // those events were admitted while pending_waits was set, allowing
        // an impossible trace to obtain an OBSERVED-CLEAN verdict.
        if pending_waits.contains_key(&task) && op != "unwait" {
            return Err("blocked task executed before lock wait cancellation".into());
        }
        // Take the clock out instead of cloning it on every event; it is
        // reinserted below. Checks against `clocks` must account for it.
        let mut clock = clocks.remove(&task).ok_or("event from unknown task")?;
        match op.as_str() {
            "fork" => {
                let child = e.text("child")?.to_owned();
                if clocks.len() + 1 >= MAX_TASKS || child == task || clocks.contains_key(&child) {
                    return Err("duplicate/over-budget fork child".into());
                }
                let mut child_clock = clock.clone();
                child_clock.insert(child.clone(), 1);
                clocks.insert(child.clone(), child_clock);
                parents.insert(child, task.clone());
            }
            "finish" => {
                if pending_waits.contains_key(&task) {
                    return Err("task finished while waiting on a lock".into());
                }
                if locks
                    .values()
                    .any(|(owner, _)| owner.as_deref() == Some(task.as_str()))
                {
                    return Err("task finished while owning a lock".into());
                }
                finished.insert(task.clone());
            }
            "join" => {
                let child = e.text("child")?;
                if parents.get(child).map(String::as_str) != Some(task.as_str())
                    || !finished.contains(child)
                    || !joined.insert(child.to_owned())
                {
                    return Err("join requires finished, unjoined direct child".into());
                }
                merge(
                    &mut clock,
                    clocks.get(child).ok_or("missing joined task clock")?,
                );
            }
            "lock" => {
                if pending_waits.contains_key(&task) {
                    return Err("task acquired lock while waiting".into());
                }
                let name = e.text("name")?.to_owned();
                let (owner, released) = locks.entry(name).or_insert((None, Clock::new()));
                if owner.is_some() {
                    return Err("lock acquired while owned".into());
                }
                merge(&mut clock, released);
                *owner = Some(task.clone());
            }
            "unlock" => {
                if pending_waits.contains_key(&task) {
                    return Err("task unlocked while waiting".into());
                }
                let name = e.text("name")?;
                let (owner, released) = locks.get_mut(name).ok_or("unlock of unknown lock")?;
                if owner.as_deref() != Some(task.as_str()) {
                    return Err("unlock by non-owner".into());
                }
                *released = clock.clone();
                *owner = None;
            }
            "wait" => {
                let name = e.text("name")?.to_owned();
                if pending_waits.contains_key(&task)
                    || locks.get(&name).is_none_or(|(owner, _)| owner.is_none())
                {
                    return Err("lock wait without observed owner or duplicate wait".into());
                }
                pending_waits.insert(task.clone(), name);
            }
            "unwait" => {
                let name = e.text("name")?;
                if pending_waits.get(&task).map(String::as_str) != Some(name) {
                    return Err("unmatched lock wait cancellation".into());
                }
                pending_waits.remove(&task);
            }
            "send" => {
                let message = e.text("message")?.to_owned();
                if !seen_messages.insert(message.clone()) {
                    return Err("reused message identity".into());
                }
                messages.insert(message, clock.clone());
            }
            "recv" => {
                let message = e.text("message")?;
                merge(
                    &mut clock,
                    &messages
                        .remove(message)
                        .ok_or("receive without matching send")?,
                );
            }
            "access" => {
                let location = e.text("location")?.to_owned();
                let mode = e.text("mode")?;
                if mode != "R" && mode != "W" {
                    return Err("access mode is not R or W".into());
                }
                accesses += 1;
                let past = history.entry(location.clone()).or_default();
                #[cfg(test)]
                for ((was_write, prior_task), prior) in &past.full {
                    let epoch = if *was_write {
                        past.writes[prior_task]
                    } else {
                        past.reads[prior_task]
                    };
                    assert_eq!(
                        happens_before(prior_task, epoch, &clock),
                        ordered(prior, &clock),
                        "epoch verdict diverged from vector clock at event {}",
                        index + 2
                    );
                }
                for (prior_task, prior) in &past.writes {
                    if prior_task != &task && !happens_before(prior_task, *prior, &clock) {
                        conflicts = conflicts.checked_add(1).ok_or("race counter overflow")?;
                        if examples.len() < MAX_REPORTED {
                            examples.push(format!("location={location} first={prior_task} second={task} first=W second={mode} event={}", index+2));
                        }
                    }
                }
                if mode == "W" {
                    for (prior_task, prior) in &past.reads {
                        if prior_task != &task && !happens_before(prior_task, *prior, &clock) {
                            conflicts = conflicts.checked_add(1).ok_or("race counter overflow")?;
                            if examples.len() < MAX_REPORTED {
                                examples.push(format!("location={location} first={prior_task} second={task} first=R second=W event={}", index+2));
                            }
                        }
                    }
                }
                let epoch = clock.get(&task).copied().unwrap_or(0);
                #[cfg(test)]
                past.full.insert((mode == "W", task.clone()), clock.clone());
                if mode == "W" {
                    past.writes.insert(task.clone(), epoch);
                } else {
                    past.reads.insert(task.clone(), epoch);
                }
            }
            _ => unreachable!(),
        }
        let current = clock.entry(task.clone()).or_insert(0);
        *current = current.checked_add(1).ok_or("vector-clock overflow")?;
        clocks.insert(task, clock);
    }
    if accesses == 0 {
        return Err("no memory accesses observed (inconclusive)".into());
    }
    if locks.values().any(|(owner, _)| owner.is_some()) {
        return Err("held lock at trace end".into());
    }
    if !pending_waits.is_empty() {
        return Err("trace ended with unresolved lock waits".into());
    }
    if !messages.is_empty() {
        return Err("trace ended with unreceived messages".into());
    }
    if parents
        .keys()
        .any(|child| !finished.contains(child) || !joined.contains(child))
    {
        return Err("forked tasks must finish and be joined before an offline clean result".into());
    }
    Ok(Report {
        events: lines.len() - 2,
        accesses,
        conflicts,
        examples,
        backend,
    })
}

pub(crate) fn relative_trace(root: &Path, name: &str) -> Result<std::path::PathBuf, String> {
    let path = Path::new(name);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err("trace must be a project-relative file".into());
    }
    let mut result = root.to_path_buf();
    for component in path.components() {
        result.push(component);
        let m = std::fs::symlink_metadata(&result).map_err(|e| e.to_string())?;
        if m.file_type().is_symlink() {
            return Err("trace symlink refused".into());
        }
    }
    if !result.is_file() {
        return Err("trace is not a regular file".into());
    }
    Ok(result)
}

pub fn offline(root: &Path, name: &str) -> Result<i32, String> {
    #[cfg(target_os = "linux")]
    relative_trace(root, name)?;
    #[cfg(not(target_os = "linux"))]
    let path = relative_trace(root, name)?;
    #[cfg(target_os = "linux")]
    let bytes = crate::fs_secure::read_project_file(root, Path::new(name), MAX_BYTES as usize)?;
    #[cfg(not(target_os = "linux"))]
    let bytes = {
        let meta = path.metadata().map_err(|e| e.to_string())?;
        if meta.len() > MAX_BYTES {
            return Err("trace exceeds 10 MB".into());
        }
        let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut data = Vec::new();
        f.by_ref()
            .take(MAX_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        data
    };
    if bytes.len() as u64 > MAX_BYTES {
        return Err("trace exceeds 10 MB".into());
    }
    let contents = String::from_utf8(bytes).map_err(|_| "trace is not UTF-8")?;
    let result = analyze(&contents)?;
    if result.conflicts > 0 {
        for example in result.examples.iter().take(20) {
            eprintln!("OFFLINE DATA RACE: {example}");
        }
        println!(
            "OFFLINE TRACE FINDINGS: {} conflicts across {} observed events",
            result.conflicts, result.events
        );
        return Ok(1);
    }
    println!("OFFLINE TRACE OBSERVED-CLEAN: {} accesses on {}; not a trusted runtime race-free certificate", result.accesses, result.backend);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn demo(racy: bool) -> String {
        let mut s = String::from("{\"op\":\"begin\",\"version\":1,\"run_id\":\"id\",\"backend\":\"llvm\"}\n{\"op\":\"task\",\"task\":\"a\"}\n{\"op\":\"task\",\"task\":\"b\"}\n{\"op\":\"access\",\"task\":\"a\",\"location\":\"item\",\"mode\":\"W\"}\n");
        if !racy {
            s.push_str("{\"op\":\"send\",\"task\":\"a\",\"message\":\"m\"}\n{\"op\":\"recv\",\"task\":\"b\",\"message\":\"m\"}\n");
        }
        s.push_str("{\"op\":\"access\",\"task\":\"b\",\"location\":\"item\",\"mode\":\"R\"}\n");
        let events = if racy { 4 } else { 6 };
        s.push_str(&format!(
            "{{\"op\":\"end\",\"run_id\":\"id\",\"events\":{events}}}\n"
        ));
        s
    }
    #[test]
    fn finds_unordered_conflict() {
        assert_eq!(analyze(&demo(true)).unwrap().conflicts, 1);
    }
    #[test]
    fn respects_send_receive_order() {
        assert_eq!(analyze(&demo(false)).unwrap().conflicts, 0);
    }
    #[test]
    fn fails_closed_on_duplicates_and_truncation() {
        let a = demo(true);
        assert!(
            analyze(&a.replace("\"run_id\":\"id\"", "\"run_id\":\"id\",\"run_id\":\"id\""))
                .is_err()
        );
        assert!(analyze(&a.replace("\"events\":4", "\"events\":3")).is_err());
        assert!(analyze(&a.replace("\"mode\":\"R\"", "\"mode\":true")).is_err());
        assert!(analyze(&a.replace("\"mode\":\"R\"", "\"mode\":\"Z\"")).is_err());
    }
    #[test]
    fn rejects_unpaired_unicode_surrogates() {
        assert!(Parser::object(r#"{"op":"task","task":"\uD800"}"#).is_err());
        assert!(Parser::object(r#"{"op":"task","task":"\uDC00"}"#).is_err());
        assert!(Parser::object(r#"{"op":"task","task":"\uD83D\uDE00"}"#).is_ok());
    }
    #[test]
    fn incomplete_mailboxes_and_unjoined_forks_are_inconclusive() {
        let missing_receive = concat!(
            "{\"op\":\"begin\",\"version\":1,\"run_id\":\"r\",\"backend\":\"llvm\"}\n",
            "{\"op\":\"task\",\"task\":\"a\"}\n",
            "{\"op\":\"access\",\"task\":\"a\",\"location\":\"x\",\"mode\":\"W\"}\n",
            "{\"op\":\"send\",\"task\":\"a\",\"message\":\"m\"}\n",
            "{\"op\":\"end\",\"run_id\":\"r\",\"events\":3}\n",
        );
        assert!(analyze(missing_receive).is_err());

        let detached_child = concat!(
            "{\"op\":\"begin\",\"version\":1,\"run_id\":\"r\",\"backend\":\"llvm\"}\n",
            "{\"op\":\"task\",\"task\":\"a\"}\n",
            "{\"op\":\"fork\",\"task\":\"a\",\"child\":\"b\"}\n",
            "{\"op\":\"access\",\"task\":\"b\",\"location\":\"x\",\"mode\":\"R\"}\n",
            "{\"op\":\"finish\",\"task\":\"b\"}\n",
            "{\"op\":\"end\",\"run_id\":\"r\",\"events\":4}\n",
        );
        assert!(analyze(detached_child).is_err());
    }
    #[test]
    fn fork_to_self_is_rejected() {
        let s = concat!(
            "{\"op\":\"begin\",\"version\":1,\"run_id\":\"r\",\"backend\":\"llvm\"}\n",
            "{\"op\":\"task\",\"task\":\"a\"}\n",
            "{\"op\":\"fork\",\"task\":\"a\",\"child\":\"a\"}\n",
            "{\"op\":\"access\",\"task\":\"a\",\"location\":\"x\",\"mode\":\"W\"}\n",
            "{\"op\":\"end\",\"run_id\":\"r\",\"events\":3}\n",
        );
        assert!(analyze(s).is_err());
    }

    /// Random well-formed traces. `analyze` asserts (under cfg(test)) that
    /// every epoch verdict equals the full vector-clock comparison.
    #[test]
    fn epoch_happens_before_matches_full_vector_clocks_on_random_traces() {
        let mut state = 0x2545F4914F6CDD1Du64;
        let mut next = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        let mut total_conflicts = 0;
        for trace in 0..300 {
            let roots = 2 + next(3);
            let mut ev: Vec<String> = (0..roots)
                .map(|t| format!("{{\"op\":\"task\",\"task\":\"t{t}\"}}"))
                .collect();
            let mut live: Vec<String> = (0..roots).map(|t| format!("t{t}")).collect();
            let mut children: Vec<(String, String)> = Vec::new();
            let mut pending: Vec<String> = Vec::new();
            let (mut msg, mut kid) = (0, 0);
            for _ in 0..(10 + next(60)) {
                let t = live[next(live.len() as u64) as usize].clone();
                match next(6) {
                    0 | 1 => ev.push(format!(
                        "{{\"op\":\"access\",\"task\":\"{t}\",\"location\":\"l{}\",\"mode\":\"{}\"}}",
                        next(3),
                        if next(2) == 0 { "R" } else { "W" }
                    )),
                    2 => {
                        msg += 1;
                        ev.push(format!("{{\"op\":\"send\",\"task\":\"{t}\",\"message\":\"m{msg}\"}}"));
                        pending.push(format!("m{msg}"));
                    }
                    3 if !pending.is_empty() => {
                        let m = pending.remove(next(pending.len() as u64) as usize);
                        ev.push(format!("{{\"op\":\"recv\",\"task\":\"{t}\",\"message\":\"{m}\"}}"));
                    }
                    4 => {
                        ev.push(format!("{{\"op\":\"lock\",\"task\":\"{t}\",\"name\":\"mu\"}}"));
                        ev.push(format!(
                            "{{\"op\":\"access\",\"task\":\"{t}\",\"location\":\"l{}\",\"mode\":\"W\"}}",
                            next(3)
                        ));
                        ev.push(format!("{{\"op\":\"unlock\",\"task\":\"{t}\",\"name\":\"mu\"}}"));
                    }
                    5 if live.len() < 8 => {
                        kid += 1;
                        let c = format!("c{kid}");
                        ev.push(format!("{{\"op\":\"fork\",\"task\":\"{t}\",\"child\":\"{c}\"}}"));
                        live.push(c.clone());
                        children.push((t, c));
                    }
                    _ => {}
                }
            }
            ev.push(format!(
                "{{\"op\":\"access\",\"task\":\"{}\",\"location\":\"l0\",\"mode\":\"R\"}}",
                live[0]
            ));
            for m in pending.drain(..) {
                ev.push(format!(
                    "{{\"op\":\"recv\",\"task\":\"{}\",\"message\":\"{m}\"}}",
                    live[0]
                ));
            }
            // Finish and join children innermost-first so parents are live.
            for (parent, child) in children.iter().rev() {
                ev.push(format!("{{\"op\":\"finish\",\"task\":\"{child}\"}}"));
                ev.push(format!(
                    "{{\"op\":\"join\",\"task\":\"{parent}\",\"child\":\"{child}\"}}"
                ));
            }
            let text = format!(
                "{{\"op\":\"begin\",\"version\":1,\"run_id\":\"r\",\"backend\":\"x\"}}\n{}\n{{\"op\":\"end\",\"run_id\":\"r\",\"events\":{}}}\n",
                ev.join("\n"),
                ev.len()
            );
            let report = analyze(&text).unwrap_or_else(|e| panic!("trace {trace}: {e}\n{text}"));
            total_conflicts += report.conflicts;
        }
        // Both racy and ordered comparisons must actually be exercised.
        assert!(total_conflicts > 0);
    }

    #[test]
    fn cross_task_history_is_not_erased() {
        let s = "{\"op\":\"begin\",\"version\":1,\"run_id\":\"id\",\"backend\":\"llvm\"}\n{\"op\":\"task\",\"task\":\"a\"}\n{\"op\":\"task\",\"task\":\"b\"}\n{\"op\":\"task\",\"task\":\"c\"}\n{\"op\":\"access\",\"task\":\"a\",\"location\":\"x\",\"mode\":\"W\"}\n{\"op\":\"access\",\"task\":\"b\",\"location\":\"x\",\"mode\":\"W\"}\n{\"op\":\"access\",\"task\":\"c\",\"location\":\"x\",\"mode\":\"R\"}\n{\"op\":\"end\",\"run_id\":\"id\",\"events\":6}\n";
        assert_eq!(analyze(s).unwrap().conflicts, 3);
    }

    // These are deterministic, complete ORES_RACE_V1 traces. Their verdicts
    // probe the scheduler's happens-before edges, not live guest execution.
    fn receipt(events: &[&str]) -> String {
        let mut lines =
            vec![r#"{"op":"begin","version":1,"run_id":"r","backend":"llvm"}"#.to_owned()];
        lines.extend(events.iter().map(|event| (*event).to_owned()));
        lines.push(format!(
            r#"{{"op":"end","run_id":"r","events":{}}}"#,
            events.len()
        ));
        return lines.join("\n") + "\n";
    }

    #[test]
    fn read_read_across_tasks_is_not_a_race() {
        let trace = receipt(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"R"}"#,
            r#"{"op":"access","task":"b","location":"x","mode":"R"}"#,
        ]);
        let result = analyze(&trace).unwrap();
        assert_eq!(result.accesses, 2);
        assert_eq!(result.conflicts, 0);
    }

    #[test]
    fn fork_join_transfers_child_write_to_parent_without_race() {
        let trace = receipt(&[
            r#"{"op":"task","task":"parent"}"#,
            r#"{"op":"fork","task":"parent","child":"child"}"#,
            r#"{"op":"access","task":"child","location":"x","mode":"W"}"#,
            r#"{"op":"finish","task":"child"}"#,
            r#"{"op":"join","task":"parent","child":"child"}"#,
            r#"{"op":"access","task":"parent","location":"x","mode":"R"}"#,
        ]);
        let result = analyze(&trace).unwrap();
        assert_eq!(result.accesses, 2);
        assert_eq!(result.conflicts, 0);
    }

    #[test]
    fn lock_release_acquire_orders_other_task_accesses() {
        let ordered = receipt(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"lock","task":"a","name":"mu"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"W"}"#,
            r#"{"op":"unlock","task":"a","name":"mu"}"#,
            r#"{"op":"lock","task":"b","name":"mu"}"#,
            r#"{"op":"access","task":"b","location":"x","mode":"R"}"#,
            r#"{"op":"unlock","task":"b","name":"mu"}"#,
        ]);
        assert_eq!(analyze(&ordered).unwrap().conflicts, 0);
        let unordered = receipt(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"W"}"#,
            r#"{"op":"access","task":"b","location":"x","mode":"R"}"#,
        ]);
        assert_eq!(analyze(&unordered).unwrap().conflicts, 1);
    }

    #[test]
    fn multihop_message_dependency_orders_transitive_accesses() {
        let ordered = receipt(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"task","task":"c"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"W"}"#,
            r#"{"op":"send","task":"a","message":"m1"}"#,
            r#"{"op":"recv","task":"b","message":"m1"}"#,
            r#"{"op":"send","task":"b","message":"m2"}"#,
            r#"{"op":"recv","task":"c","message":"m2"}"#,
            r#"{"op":"access","task":"c","location":"x","mode":"W"}"#,
        ]);
        assert_eq!(analyze(&ordered).unwrap().conflicts, 0);
    }

    #[test]
    fn replayed_message_identity_fails_even_after_consumption() {
        let trace = receipt(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"W"}"#,
            r#"{"op":"send","task":"a","message":"m"}"#,
            r#"{"op":"recv","task":"b","message":"m"}"#,
            r#"{"op":"send","task":"a","message":"m"}"#,
        ]);
        assert!(analyze(&trace)
            .unwrap_err()
            .contains("reused message identity"));
    }

    #[test]
    fn unexpected_join_or_post_completion_access_is_rejected() {
        let invalid_join = receipt(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"R"}"#,
            r#"{"op":"join","task":"a","child":"b"}"#,
        ]);
        assert!(analyze(&invalid_join).is_err());
        let late_access = receipt(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"R"}"#,
            r#"{"op":"finish","task":"a"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"W"}"#,
        ]);
        assert!(analyze(&late_access).is_err());
    }

    #[test]
    fn blocked_task_cannot_read_write_send_receive_or_spawn() {
        let begin = [
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"lock","task":"a","name":"mu"}"#,
            r#"{"op":"access","task":"a","location":"safe","mode":"R"}"#,
            r#"{"op":"wait","task":"b","name":"mu"}"#,
        ];
        let forbidden = [
            r#"{"op":"access","task":"b","location":"secret","mode":"R"}"#,
            r#"{"op":"access","task":"b","location":"secret","mode":"W"}"#,
            r#"{"op":"send","task":"b","message":"m"}"#,
            r#"{"op":"recv","task":"b","message":"m"}"#,
            r#"{"op":"fork","task":"b","child":"c"}"#,
            r#"{"op":"finish","task":"b"}"#,
        ];
        for forbidden_event in forbidden {
            let mut events = begin.to_vec();
            events.push(forbidden_event);
            events.push(r#"{"op":"unwait","task":"b","name":"mu"}"#);
            events.push(r#"{"op":"unlock","task":"a","name":"mu"}"#);
            let trace = receipt(&events);
            let err = analyze(&trace).unwrap_err();
            assert!(
                err.contains("blocked task executed"),
                "{forbidden_event}: {err}"
            );
        }
    }

    #[test]
    fn cancelled_wait_can_resume_without_claiming_lock_ownership() {
        let trace = receipt(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"lock","task":"a","name":"mu"}"#,
            r#"{"op":"wait","task":"b","name":"mu"}"#,
            r#"{"op":"unwait","task":"b","name":"mu"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"W"}"#,
            r#"{"op":"access","task":"b","location":"y","mode":"R"}"#,
            r#"{"op":"unlock","task":"a","name":"mu"}"#,
        ]);
        let report = analyze(&trace).unwrap();
        assert_eq!(report.accesses, 2);
        assert_eq!(report.conflicts, 0);
    }

    #[test]
    fn unrelated_memory_location_does_not_change_existing_conflict_count() {
        let base = [
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"W"}"#,
            r#"{"op":"access","task":"b","location":"x","mode":"R"}"#,
        ];
        let original = analyze(&receipt(&base)).unwrap();
        assert_eq!(original.conflicts, 1);
        let extra = [
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"access","task":"a","location":"unrelated","mode":"W"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"W"}"#,
            r#"{"op":"access","task":"b","location":"x","mode":"R"}"#,
            r#"{"op":"access","task":"b","location":"unrelated2","mode":"R"}"#,
        ];
        let augmented = analyze(&receipt(&extra)).unwrap();
        assert_eq!(augmented.conflicts, original.conflicts);
        assert_eq!(augmented.accesses, original.accesses + 2);
    }

    #[test]
    fn same_task_reads_and_writes_do_not_race_with_themselves() {
        let mut events = vec![r#"{"op":"task","task":"a"}"#];
        for i in 0..64 {
            let mode = if i % 2 == 0 { "W" } else { "R" };
            events.push(if mode == "W" {
                r#"{"op":"access","task":"a","location":"x","mode":"W"}"#
            } else {
                r#"{"op":"access","task":"a","location":"x","mode":"R"}"#
            });
        }
        let report = analyze(&receipt(&events)).unwrap();
        assert_eq!(report.conflicts, 0);
        assert_eq!(report.accesses, 64);
    }

    #[test]
    fn terminal_receipt_mismatch_and_extra_json_fields_fail_closed() {
        let valid = receipt(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"R"}"#,
        ]);
        assert_eq!(analyze(&valid).unwrap().events, 2);
        for bad in [
            valid.replace(r#""events":2"#, r#""events":3"#),
            valid.replacen(r#""run_id":"r""#, r#""run_id":"other""#, 1),
            valid.replace(r#""mode":"R""#, r#""mode":"R","ignored":true"#),
            valid.replace(r#""version":1"#, r#""version":2"#),
        ] {
            assert!(analyze(&bad).is_err(), "accepted malformed trace: {bad}");
        }
    }
}
