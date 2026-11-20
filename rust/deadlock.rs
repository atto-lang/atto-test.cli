//! Bounded OFFLINE lock-order and observed unresolved wait-cycle analysis.
//! Findings indicate a potential lock-order hazard or an observed wait cycle,
//! NOT inevitable deadlock, runtime coverage, or a certified liveness result.

use crate::race_offline::{relative_trace, Parser};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(not(unix))]
use std::io::Read;
use std::path::Path;

type Graph = BTreeMap<String, BTreeSet<String>>;
/// Lock sequence of each cycle, and the task of each of its edges.
type CycleWitnesses = (Vec<Vec<String>>, Vec<Vec<String>>);
const MAX_EVENTS: usize = 100_000;
const MAX_BYTES: u64 = 10_000_000;
const MAX_TASKS: usize = 256;
const MAX_LOCKS: usize = 2048;
const MAX_DEPENDENCIES: usize = 10_000;
const MAX_NESTING: usize = 256;
const MAX_WITNESSES: usize = 100;
const TRAVERSAL_BUDGET: usize = 250_000;
const CHAIN_BUDGET: usize = 2_000_000;

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub events: usize,
    pub observed_lock_events: usize,
    pub pending_waits: usize,
    pub potential_lock_order_cycles: Vec<Vec<String>>,
    /// Task of each edge in the matching `potential_lock_order_cycles` entry.
    pub lock_order_cycle_tasks: Vec<Vec<String>>,
    pub observed_wait_cycles: Vec<Vec<String>>,
}

/// iGoodlock dependencies grouped by shape: (held set, acquired lock) ->
/// tasks that acquired `acquired` while holding exactly `held`.
type Dependencies = BTreeMap<(Vec<String>, String), BTreeSet<String>>;
/// A shape with its candidate tasks, as searched.
type Shape<'a> = ((&'a [String], &'a str), Vec<&'a str>);

/// Lock-order cycles that observed tasks could actually deadlock on: a chain
/// d1..dk of dependencies from pairwise distinct tasks, with pairwise
/// disjoint held sets (no common gate lock), where each d(i+1) holds the lock
/// d(i) acquires and d1 holds the lock dk acquires.
///
/// The previous lock-graph search reported a cycle formed by one task alone
/// (A->B then B->A cannot deadlock without a second task) or by tasks
/// serialized by a common gate lock, and ran a BFS from every origin, which
/// exhausted its budget on an acyclic 1000-node hand-over-hand traversal.
/// Chains here are at most one dependency per task deep.
/// Strongly connected component id per lock (iterative Tarjan), counting
/// only components that contain a cycle. Locks outside any cycle are absent.
static NO_SUCCESSORS: BTreeSet<String> = BTreeSet::new();

fn cyclic_components(graph: &Graph) -> BTreeMap<&str, usize> {
    let mut index = BTreeMap::<&str, usize>::new();
    let mut low = BTreeMap::<&str, usize>::new();
    let mut on_stack = BTreeSet::<&str>::new();
    let mut stack = Vec::<&str>::new();
    let mut result = BTreeMap::new();
    let mut next_index = 0;
    let mut next_component = 0;
    for root in graph.keys() {
        if index.contains_key(root.as_str()) {
            continue;
        }
        let mut work: Vec<(&str, Vec<&str>)> = Vec::new();
        index.insert(root, next_index);
        low.insert(root, next_index);
        next_index += 1;
        stack.push(root);
        on_stack.insert(root);
        work.push((
            root,
            graph
                .get(root)
                .unwrap_or(&NO_SUCCESSORS)
                .iter()
                .map(String::as_str)
                .collect(),
        ));
        while let Some((node, pending)) = work.last_mut() {
            let node = *node;
            if let Some(next) = pending.pop() {
                if !index.contains_key(next) {
                    index.insert(next, next_index);
                    low.insert(next, next_index);
                    next_index += 1;
                    stack.push(next);
                    on_stack.insert(next);
                    let succ = graph
                        .get(next)
                        .unwrap_or(&NO_SUCCESSORS)
                        .iter()
                        .map(String::as_str)
                        .collect();
                    work.push((next, succ));
                } else if on_stack.contains(next) {
                    let candidate = index[next].min(low[node]);
                    low.insert(node, candidate);
                }
                continue;
            }
            work.pop();
            if let Some((parent, _)) = work.last() {
                let candidate = low[node].min(low[*parent]);
                low.insert(*parent, candidate);
            }
            if low[node] == index[node] {
                let mut members = Vec::new();
                while let Some(member) = stack.pop() {
                    on_stack.remove(member);
                    members.push(member);
                    if member == node {
                        break;
                    }
                }
                // Lock graphs have no self-loops (a held lock cannot be
                // re-acquired), so a cycle needs at least two members.
                if members.len() > 1 {
                    for member in members {
                        result.insert(member, next_component);
                    }
                    next_component += 1;
                }
            }
        }
    }
    result
}

fn feasible_lock_cycles(deps: &Dependencies) -> Result<CycleWitnesses, String> {
    let mut graph = Graph::new();
    for (held, acquired) in deps.keys() {
        for lock in held {
            graph
                .entry(lock.clone())
                .or_default()
                .insert(acquired.clone());
        }
    }
    // Every lock of a cycle lies in one cyclic SCC. Searching only those
    // dependencies keeps consistently ordered programs (an acyclic lock
    // graph) at zero search cost however many tasks they have.
    let component = cyclic_components(&graph);
    // Symmetry reduction: dependencies differing only by task share a shape.
    // Searching shapes instead of (task, shape) pairs keeps one inversion in
    // a large, otherwise consistently ordered program from multiplying the
    // search by the task count. Distinct tasks are assigned afterwards.
    let shapes: Vec<Shape> = deps
        .iter()
        .filter(|((held, acquired), _)| {
            component
                .get(acquired.as_str())
                .is_some_and(|c| held.iter().any(|h| component.get(h.as_str()) == Some(c)))
        })
        .map(|((held, acquired), tasks)| {
            (
                (held.as_slice(), acquired.as_str()),
                tasks.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let mut holding = BTreeMap::<&str, Vec<usize>>::new();
    for (index, ((held, _), _)) in shapes.iter().enumerate() {
        for lock in held.iter() {
            holding.entry(lock.as_str()).or_default().push(index);
        }
    }
    struct Search<'a> {
        shapes: &'a [Shape<'a>],
        holding: BTreeMap<&'a str, Vec<usize>>,
        chain: Vec<usize>,
        held: BTreeSet<&'a str>,
        budget: usize,
        known: BTreeSet<Vec<String>>,
        cycles: Vec<Vec<String>>,
        cycle_tasks: Vec<Vec<String>>,
    }
    impl<'a> Search<'a> {
        fn spend(&mut self) -> Result<(), String> {
            self.budget = self
                .budget
                .checked_sub(1)
                .ok_or("deadlock lock-order search budget exhausted")?;
            Ok(())
        }
        fn extend(&mut self, start: usize) -> Result<(), String> {
            let tail = self.shapes[*self.chain.last().ok_or("empty chain")?].0 .1;
            let candidates = self.holding.get(tail).cloned().unwrap_or_default();
            for next in candidates {
                if self.cycles.len() >= MAX_WITNESSES {
                    return Ok(());
                }
                // Canonical start: the smallest shape index in the cycle.
                if next <= start {
                    continue;
                }
                self.spend()?;
                let (held, acquired) = self.shapes[next].0;
                // Pairwise disjoint held sets: no common gate lock, and no
                // shape repeats (a repeated shape has an identical held set).
                if held.iter().any(|l| self.held.contains(l.as_str())) {
                    continue;
                }
                self.chain.push(next);
                if self.shapes[start].0 .0.iter().any(|h| h == acquired) {
                    self.record()?;
                } else {
                    self.held.extend(held.iter().map(String::as_str));
                    self.extend(start)?;
                    for lock in held.iter() {
                        self.held.remove(lock.as_str());
                    }
                }
                self.chain.pop();
            }
            Ok(())
        }
        /// Distinct tasks per chain position (bipartite matching).
        fn assign(&mut self) -> Result<Option<Vec<&'a str>>, String> {
            fn augment<'b>(
                position: usize,
                options: &[&[&'b str]],
                owner: &mut BTreeMap<&'b str, usize>,
                seen: &mut BTreeSet<&'b str>,
                budget: &mut usize,
            ) -> Result<bool, String> {
                for &task in options[position] {
                    *budget = budget
                        .checked_sub(1)
                        .ok_or("deadlock lock-order search budget exhausted")?;
                    if !seen.insert(task) {
                        continue;
                    }
                    let free = match owner.get(task).copied() {
                        None => true,
                        Some(other) => augment(other, options, owner, seen, budget)?,
                    };
                    if free {
                        owner.insert(task, position);
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            let options: Vec<&[&str]> = self
                .chain
                .iter()
                .map(|&i| self.shapes[i].1.as_slice())
                .collect();
            let mut owner = BTreeMap::new();
            for position in 0..options.len() {
                let mut seen = BTreeSet::new();
                if !augment(position, &options, &mut owner, &mut seen, &mut self.budget)? {
                    return Ok(None);
                }
            }
            let mut tasks = vec![""; options.len()];
            for (task, position) in owner {
                tasks[position] = task;
            }
            Ok(Some(tasks))
        }
        fn record(&mut self) -> Result<(), String> {
            let Some(tasks) = self.assign()? else {
                return Ok(());
            };
            let last = self.shapes[*self.chain.last().ok_or("empty chain")?].0 .1;
            let mut locks = vec![last.to_owned()];
            locks.extend(self.chain.iter().map(|&i| self.shapes[i].0 .1.to_owned()));
            let ring = &locks[..locks.len() - 1];
            let canonical = (0..ring.len())
                .map(|i| {
                    ring[i..]
                        .iter()
                        .chain(&ring[..i])
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .min()
                .unwrap_or_default();
            if self.known.insert(canonical) {
                self.cycles.push(locks);
                self.cycle_tasks
                    .push(tasks.into_iter().map(str::to_owned).collect());
            }
            Ok(())
        }
    }
    let mut search = Search {
        shapes: &shapes,
        holding,
        chain: Vec::new(),
        held: BTreeSet::new(),
        budget: CHAIN_BUDGET,
        known: BTreeSet::new(),
        cycles: Vec::new(),
        cycle_tasks: Vec::new(),
    };
    for (start, ((held, _), _)) in shapes.iter().enumerate() {
        search.chain = vec![start];
        search.held = held.iter().map(String::as_str).collect();
        search.extend(start)?;
    }
    Ok((search.cycles, search.cycle_tasks))
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
            if budget == 0 {
                return Err("deadlock graph traversal budget exhausted".into());
            }
            budget -= 1;
            if let Some(neighbors) = graph.get(&node) {
                for next in neighbors {
                    if next == origin {
                        let best = (0..path.len())
                            .map(|i| {
                                path[i..]
                                    .iter()
                                    .chain(path[..i].iter())
                                    .cloned()
                                    .collect::<Vec<_>>()
                            })
                            .min()
                            .ok_or("empty cycle path")?;
                        if known.insert(best.clone()) {
                            let mut witness = best;
                            witness.push(witness[0].clone());
                            result.push(witness);
                            if result.len() >= MAX_WITNESSES {
                                return Ok(result);
                            }
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
    if contents.len() > MAX_BYTES as usize {
        return Err("deadlock input exceeds 10 MB".into());
    }
    let lines: Vec<&str> = contents.lines().collect();
    if !(2..=MAX_EVENTS + 2).contains(&lines.len()) {
        return Err("deadlock trace event count outside bounds".into());
    }
    let begin = Parser::object(lines[0])?;
    begin.keys(&["op", "version", "run_id", "backend"])?;
    if begin.text("op")? != "begin" || begin.number("version")? != 1 {
        return Err("invalid deadlock JSONL begin".into());
    }
    let run_id = begin.text("run_id")?.to_owned();
    begin.text("backend")?;
    let end = Parser::object(lines[lines.len() - 1])?;
    end.keys(&["op", "run_id", "events"])?;
    if end.text("op")? != "end"
        || end.text("run_id")? != run_id
        || end.number("events")? != (lines.len() - 2) as u64
    {
        return Err("inconsistent deadlock JSONL end".into());
    }

    let mut participants = BTreeSet::<String>::new();
    let mut finished = BTreeSet::<String>::new();
    let mut held = BTreeMap::<String, BTreeSet<String>>::new();
    let mut owners = BTreeMap::<String, String>::new();
    let mut pending = BTreeMap::<String, String>::new();
    let mut dependencies = Dependencies::new();
    let mut observed_lock_events = 0usize;

    for (idx, line) in lines[1..lines.len() - 1].iter().enumerate() {
        let record = Parser::object(line).map_err(|e| format!("event {}: {e}", idx + 2))?;
        let op = record.text("op")?;
        let task = record.text("task")?.to_owned();
        let keys = match op {
            "task" | "finish" => &["op", "task"][..],
            "fork" | "join" => &["op", "task", "child"][..],
            "lock" | "unlock" | "wait" | "unwait" => &["op", "task", "name"][..],
            "send" | "recv" => &["op", "task", "message"][..],
            "access" => &["op", "task", "location", "mode"][..],
            _ => return Err(format!("event {}: unsupported deadlock op {op}", idx + 2)),
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
                if pending.contains_key(&task)
                    || owners.contains_key(&name)
                    || owners.len() >= MAX_LOCKS
                {
                    return Err("lock admission rejected (owner, pending wait or capacity)".into());
                }
                let current = held.get(&task).ok_or("missing task lock state")?;
                if current.len() >= MAX_NESTING {
                    return Err("lock nesting depth budget exceeded".into());
                }
                if !current.is_empty() {
                    // Bound distinct shapes; tasks per shape are bounded by
                    // MAX_TASKS, so many tasks sharing one order are cheap.
                    dependencies
                        .entry((current.iter().cloned().collect(), name.clone()))
                        .or_default()
                        .insert(task.clone());
                    if dependencies.len() > MAX_DEPENDENCIES {
                        return Err("lock dependency shape budget exceeded".into());
                    }
                }
                held.get_mut(&task)
                    .ok_or("missing task lock state")?
                    .insert(name.clone());
                owners.insert(name, task.clone());
                observed_lock_events += 1;
            }
            "unlock" => {
                let name = record.text("name")?;
                if pending.contains_key(&task) || owners.get(name) != Some(&task) {
                    return Err("unlock without matching owner".into());
                }
                owners.remove(name);
                held.get_mut(&task)
                    .ok_or("missing task locks")?
                    .remove(name);
            }
            "wait" => {
                let name = record.text("name")?.to_owned();
                if pending.contains_key(&task) || !owners.contains_key(&name) {
                    return Err("waiting without an observed lock owner".into());
                }
                pending.insert(task.clone(), name);
                observed_lock_events += 1;
            }
            "unwait" => {
                let name = record.text("name")?;
                if pending.get(&task).map(String::as_str) != Some(name) {
                    return Err("unmatched lock unwait".into());
                }
                pending.remove(&task);
            }
            "join" => {
                record.text("child")?;
            }
            "send" | "recv" => {
                record.text("message")?;
            }
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
    for (task, name) in &pending {
        if let Some(owner) = owners.get(name) {
            waits.entry(task.clone()).or_default().insert(owner.clone());
        }
    }
    let (potential_lock_order_cycles, lock_order_cycle_tasks) =
        feasible_lock_cycles(&dependencies)?;
    Ok(Report {
        events: lines.len() - 2,
        observed_lock_events,
        pending_waits: pending.len(),
        potential_lock_order_cycles,
        lock_order_cycle_tasks,
        observed_wait_cycles: cycle_witnesses(&waits)?,
    })
}

pub fn offline(root: &Path, name: &str) -> Result<i32, String> {
    #[cfg(unix)]
    relative_trace(root, name)?;
    #[cfg(not(unix))]
    let path = relative_trace(root, name)?;
    #[cfg(unix)]
    let data = crate::fs_secure::read_project_file(root, Path::new(name), MAX_BYTES as usize)?;
    #[cfg(not(unix))]
    let data = {
        if path.metadata().map_err(|e| e.to_string())?.len() > MAX_BYTES {
            return Err("deadlock trace exceeds byte budget".into());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        bytes
    };
    if data.len() as u64 > MAX_BYTES {
        return Err("deadlock trace exceeds byte budget".into());
    }
    let text = String::from_utf8(data).map_err(|_| "deadlock trace is not UTF-8")?;
    // GraalVM ORES_CONCURRENCY_TRACE checkpoint-only files require a
    // separate schema and cannot certify a complete observed wait graph.
    if text.starts_with("ORES_CONCURRENCY_TRACE_V") {
        return Err(
            "GraalVM checkpoint-only deadlock trace is not authenticated or complete".into(),
        );
    }
    let report = analyze(&text)?;
    let n = report.observed_wait_cycles.len() + report.potential_lock_order_cycles.len();
    println!("OFFLINE DEADLOCK ANALYSIS: {} lock events; {} pending waits; {} potential cycles; not a liveness proof",
        report.observed_lock_events,report.pending_waits,n);
    for witness in report.observed_wait_cycles.iter().take(10) {
        println!("OBSERVED WAIT CYCLE: {}", witness.join(" -> "));
    }
    for (witness, tasks) in report
        .potential_lock_order_cycles
        .iter()
        .zip(&report.lock_order_cycle_tasks)
        .take(10)
    {
        println!(
            "POTENTIAL LOCK ORDER CYCLE: {} (tasks {})",
            witness.join(" -> "),
            tasks.join(", ")
        );
    }
    Ok(i32::from(n > 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn trace(events: &[&str]) -> String {
        let mut out = String::from(
            "{\"op\":\"begin\",\"version\":1,\"run_id\":\"test\",\"backend\":\"llvm\"}\n",
        );
        for event in events {
            out.push_str(event);
            out.push('\n');
        }
        out.push_str(&format!(
            "{{\"op\":\"end\",\"run_id\":\"test\",\"events\":{}}}\n",
            events.len()
        ));
        out
    }
    #[test]
    fn detects_potential_lock_order_cycle() {
        let t = trace(&[
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
        let result = analyze(&t).unwrap();
        assert_eq!(result.potential_lock_order_cycles.len(), 1);
        assert!(result.observed_wait_cycles.is_empty());
    }
    fn locks(task: &str, order: &[&str]) -> Vec<String> {
        let mut events: Vec<String> = order
            .iter()
            .map(|l| format!(r#"{{"op":"lock","task":"{task}","name":"{l}"}}"#))
            .collect();
        events.extend(
            order
                .iter()
                .rev()
                .map(|l| format!(r#"{{"op":"unlock","task":"{task}","name":"{l}"}}"#)),
        );
        events
    }
    fn run(tasks: &[&str], blocks: Vec<Vec<String>>) -> Report {
        let mut events: Vec<String> = tasks
            .iter()
            .map(|t| format!(r#"{{"op":"task","task":"{t}"}}"#))
            .collect();
        events.extend(blocks.into_iter().flatten());
        let refs: Vec<&str> = events.iter().map(String::as_str).collect();
        analyze(&trace(&refs)).unwrap()
    }

    #[test]
    fn single_task_inversion_cannot_deadlock() {
        let r = run(
            &["a"],
            vec![locks("a", &["A", "B"]), locks("a", &["B", "A"])],
        );
        assert!(r.potential_lock_order_cycles.is_empty(), "{r:?}");
    }

    #[test]
    fn common_gate_lock_serializes_inversion() {
        let r = run(
            &["a", "b"],
            vec![locks("a", &["G", "A", "B"]), locks("b", &["G", "B", "A"])],
        );
        assert!(r.potential_lock_order_cycles.is_empty(), "{r:?}");
        // Different gates do not serialize anything.
        let r = run(
            &["a", "b"],
            vec![locks("a", &["G", "A", "B"]), locks("b", &["H", "B", "A"])],
        );
        assert_eq!(r.potential_lock_order_cycles.len(), 1, "{r:?}");
    }

    #[test]
    fn three_task_cycle_reports_locks_and_tasks() {
        let r = run(
            &["a", "b", "c"],
            vec![
                locks("a", &["A", "B"]),
                locks("b", &["B", "C"]),
                locks("c", &["C", "A"]),
            ],
        );
        assert_eq!(r.potential_lock_order_cycles.len(), 1, "{r:?}");
        let mut ring = r.potential_lock_order_cycles[0].clone();
        ring.pop();
        ring.sort();
        assert_eq!(ring, ["A", "B", "C"]);
        let mut tasks = r.lock_order_cycle_tasks[0].clone();
        tasks.sort();
        assert_eq!(tasks, ["a", "b", "c"]);
    }

    #[test]
    fn long_hand_over_hand_traversal_is_clean_not_budget_exhausted() {
        let mut events = vec![r#"{"op":"task","task":"a"}"#.to_owned()];
        events.push(r#"{"op":"lock","task":"a","name":"n0"}"#.to_owned());
        for i in 1..5000 {
            events.push(format!(r#"{{"op":"lock","task":"a","name":"n{i}"}}"#));
            events.push(format!(
                r#"{{"op":"unlock","task":"a","name":"n{}"}}"#,
                i - 1
            ));
        }
        events.push(r#"{"op":"unlock","task":"a","name":"n4999"}"#.to_owned());
        let refs: Vec<&str> = events.iter().map(String::as_str).collect();
        let r = analyze(&trace(&refs)).unwrap();
        assert!(r.potential_lock_order_cycles.is_empty());
    }

    #[test]
    fn many_tasks_with_consistent_order_are_clean_and_inversion_still_found() {
        let mut blocks = Vec::new();
        let names: Vec<String> = (0..120).map(|t| format!("t{t}")).collect();
        for t in &names {
            for a in 0..8 {
                for b in a + 1..8 {
                    blocks.push(locks(t, &[&format!("X{a}"), &format!("X{b}")]));
                }
            }
        }
        let tasks: Vec<&str> = names.iter().map(String::as_str).collect();
        let r = run(&tasks, blocks.clone());
        assert!(r.potential_lock_order_cycles.is_empty());
        blocks.push(locks("t7", &["X5", "X2"]));
        let r = run(&tasks, blocks);
        assert!(!r.potential_lock_order_cycles.is_empty());
        // Longer chains (X2->X3 in one task, X3->X5 in another, X5->X2 in
        // t7) are feasible too; every witness needs distinct tasks and t7.
        for tasks in &r.lock_order_cycle_tasks {
            let distinct: BTreeSet<_> = tasks.iter().collect();
            assert_eq!(distinct.len(), tasks.len(), "{tasks:?}");
            assert!(tasks.iter().any(|t| t == "t7"), "{tasks:?}");
        }
    }

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Dependency {
        task: String,
        held: Vec<String>,
        acquired: String,
    }

    fn brute_force_has_cycle(deps: &[Dependency]) -> bool {
        fn go(deps: &[Dependency], chain: &mut Vec<usize>) -> bool {
            let first = &deps[chain[0]];
            let last = &deps[*chain.last().unwrap()];
            if chain.len() >= 2 && first.held.contains(&last.acquired) {
                return true;
            }
            for (j, d) in deps.iter().enumerate() {
                let ok = !chain.contains(&j)
                    && d.held.contains(&last.acquired)
                    && chain.iter().all(|&i| {
                        deps[i].task != d.task && deps[i].held.iter().all(|h| !d.held.contains(h))
                    });
                if ok {
                    chain.push(j);
                    if go(deps, chain) {
                        return true;
                    }
                    chain.pop();
                }
            }
            false
        }
        (0..deps.len()).any(|i| go(deps, &mut vec![i]))
    }

    #[test]
    fn feasible_cycle_search_matches_brute_force_on_random_dependencies() {
        let mut state = 0x9E3779B97F4A7C15u64;
        let mut next = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        let (mut positive, mut negative) = (0, 0);
        for _ in 0..3000 {
            let mut deps = BTreeSet::new();
            for _ in 0..(1 + next(7)) {
                let task = format!("t{}", next(4));
                let mut held: Vec<String> = (0..5)
                    .filter(|_| next(3) == 0)
                    .map(|l| format!("L{l}"))
                    .collect();
                if held.is_empty() {
                    held.push(format!("L{}", next(5)));
                }
                let acquired = format!("L{}", next(5));
                if held.contains(&acquired) {
                    continue;
                }
                deps.insert(Dependency {
                    task,
                    held,
                    acquired,
                });
            }
            let deps: Vec<Dependency> = deps.into_iter().collect();
            let expected = brute_force_has_cycle(&deps);
            let mut grouped = Dependencies::new();
            for d in &deps {
                grouped
                    .entry((d.held.clone(), d.acquired.clone()))
                    .or_default()
                    .insert(d.task.clone());
            }
            let found = !feasible_lock_cycles(&grouped).unwrap().0.is_empty();
            assert_eq!(found, expected, "{deps:?}");
            if expected {
                positive += 1;
            } else {
                negative += 1;
            }
        }
        assert!(positive > 50 && negative > 50, "{positive}/{negative}");
    }

    #[test]
    fn detects_unresolved_wait_cycle() {
        let t = trace(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"task","task":"b"}"#,
            r#"{"op":"lock","task":"a","name":"A"}"#,
            r#"{"op":"lock","task":"b","name":"B"}"#,
            r#"{"op":"wait","task":"a","name":"B"}"#,
            r#"{"op":"wait","task":"b","name":"A"}"#,
        ]);
        assert_eq!(analyze(&t).unwrap().observed_wait_cycles.len(), 1);
    }
    #[test]
    fn no_lock_evidence_or_invalid_unlock_is_inconclusive() {
        let t = trace(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"access","task":"a","location":"x","mode":"R"}"#,
        ]);
        assert!(analyze(&t).is_err());
        let bad = trace(&[
            r#"{"op":"task","task":"a"}"#,
            r#"{"op":"unlock","task":"a","name":"A"}"#,
        ]);
        assert!(analyze(&bad).is_err());
    }
}
