//! Bounded, offline callback/Task/actor/await lifecycle contract model.
//! Events are host-provided, NOT authenticated Oreslang runtime instrumentation.
//! No scheduler, race-freedom, or guest execution conclusion follows from PASS.
use std::collections::BTreeMap;
const MAX_EVENTS: usize = 100_000;
const MAX_OBJECTS: usize = 4096;

#[derive(Debug, Clone)]
pub enum Event {
    SpawnActor(String),
    StopActor(String),
    SpawnTask { actor: String, task: String },
    FinishTask(String),
    CancelTask(String),
    RetireTask(String),
    RegisterCallback { actor: String, callback: String },
    FireCallback(String),
    UnregisterCallback(String),
    Suspend { task: String, wake: String },
    Ready(String),
    Resume { task: String, wake: String },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub actors: usize,
    pub tasks: usize,
    pub callbacks: usize,
    pub fired: usize,
    pub suspended: usize,
    pub resumed: usize,
    pub retired: usize,
}
enum Phase {
    Running,
    Waiting(String),
    Completed,
    Cancelled,
    Retired,
}
struct Task {
    actor: String,
    phase: Phase,
}
struct Wake {
    task: String,
    ready: bool,
    used: bool,
}
fn check_id(id: &str) -> Result<(), String> {
    if id.trim().is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err("empty, oversized or control-character identity".into());
    }
    Ok(())
}
fn budget(n: usize) -> Result<(), String> {
    if n >= MAX_OBJECTS {
        Err("identity budget exceeded".into())
    } else {
        Ok(())
    }
}
/// Requires a complete, leak-free trace and at least one observable operation.
/// Identity strings must include the actor incarnation/generation. Tokens are one-use.
pub fn analyze(events: &[Event]) -> Result<Report, String> {
    if events.is_empty() || events.len() > MAX_EVENTS {
        return Err("event count outside 1..100000".into());
    }
    let mut actors = BTreeMap::<String, bool>::new();
    let mut tasks = BTreeMap::<String, Task>::new();
    let mut callbacks = BTreeMap::<String, (String, bool)>::new();
    let mut wakes = BTreeMap::<String, Wake>::new();
    let mut out = Report {
        actors: 0,
        tasks: 0,
        callbacks: 0,
        fired: 0,
        suspended: 0,
        resumed: 0,
        retired: 0,
    };
    for (i, event) in events.iter().enumerate() {
        let result: Result<(), String> = (|| {
            match event {
                Event::SpawnActor(id) => {
                    check_id(id)?;
                    budget(actors.len())?;
                    if actors.insert(id.clone(), true).is_some() {
                        return Err("actor ID reused".into());
                    }
                    out.actors += 1;
                }
                Event::StopActor(id) => {
                    if actors.get(id) != Some(&true) {
                        return Err("stop of absent/stopped actor".into());
                    }
                    if tasks
                        .values()
                        .any(|t| t.actor == *id && !matches!(&t.phase, Phase::Retired))
                    {
                        return Err("actor stopped before physical task retirement".into());
                    }
                    if callbacks
                        .values()
                        .any(|(owner, active)| owner == id && *active)
                    {
                        return Err("actor stopped with live callback".into());
                    }
                    actors.insert(id.clone(), false);
                }
                Event::SpawnTask { actor, task } => {
                    check_id(task)?;
                    if actors.get(actor) != Some(&true) {
                        return Err("task owner absent".into());
                    }
                    budget(tasks.len())?;
                    if tasks
                        .insert(
                            task.clone(),
                            Task {
                                actor: actor.clone(),
                                phase: Phase::Running,
                            },
                        )
                        .is_some()
                    {
                        return Err("task ID reused".into());
                    }
                    out.tasks += 1;
                }
                Event::FinishTask(id) => {
                    let t = tasks.get_mut(id).ok_or("unknown task")?;
                    if !matches!(&t.phase, Phase::Running) {
                        return Err("task finished during await or after terminal".into());
                    }
                    t.phase = Phase::Completed;
                }
                Event::CancelTask(id) => {
                    let t = tasks.get_mut(id).ok_or("unknown task")?;
                    match &t.phase {
                        Phase::Waiting(wake) => {
                            wakes.get_mut(wake).ok_or("missing wake")?.used = true;
                        }
                        Phase::Running => {}
                        _ => return Err("cancel after terminal or duplicate cancel".into()),
                    }
                    t.phase = Phase::Cancelled;
                }
                Event::RetireTask(id) => {
                    let t = tasks.get_mut(id).ok_or("unknown task")?;
                    if !matches!(&t.phase, Phase::Completed | Phase::Cancelled) {
                        return Err("task retirement without logical terminal".into());
                    }
                    t.phase = Phase::Retired;
                    out.retired += 1;
                }
                Event::RegisterCallback { actor, callback } => {
                    check_id(callback)?;
                    if actors.get(actor) != Some(&true) {
                        return Err("callback owner absent".into());
                    }
                    budget(callbacks.len())?;
                    if callbacks
                        .insert(callback.clone(), (actor.clone(), true))
                        .is_some()
                    {
                        return Err("callback ID reused".into());
                    }
                    out.callbacks += 1;
                }
                Event::FireCallback(id) => {
                    let (owner, live) = callbacks.get(id).ok_or("unregistered callback")?;
                    if !*live || actors.get(owner) != Some(&true) {
                        return Err("late callback after unregister or actor stop".into());
                    }
                    out.fired += 1;
                }
                Event::UnregisterCallback(id) => {
                    let (_, live) = callbacks.get_mut(id).ok_or("unregistered callback")?;
                    if !*live {
                        return Err("duplicate callback cleanup".into());
                    }
                    *live = false;
                }
                Event::Suspend { task, wake } => {
                    check_id(wake)?;
                    let t = tasks.get_mut(task).ok_or("unknown task")?;
                    if !matches!(&t.phase, Phase::Running) {
                        return Err("double await or await after terminal".into());
                    }
                    budget(wakes.len())?;
                    if wakes
                        .insert(
                            wake.clone(),
                            Wake {
                                task: task.clone(),
                                ready: false,
                                used: false,
                            },
                        )
                        .is_some()
                    {
                        return Err("reused wake token/ABA".into());
                    }
                    t.phase = Phase::Waiting(wake.clone());
                    out.suspended += 1;
                }
                Event::Ready(id) => {
                    let wake = wakes.get_mut(id).ok_or("unregistered wake")?;
                    if wake.ready {
                        return Err("duplicate wake readiness".into());
                    }
                    // A late completion after cancellation is permitted;
                    // a resumed cancelled task is never permitted.
                    wake.ready = true;
                }
                Event::Resume { task, wake } => {
                    let t = tasks.get_mut(task).ok_or("unknown task")?;
                    if !matches!(&t.phase, Phase::Waiting(token) if token == wake) {
                        return Err("resume without a matching suspension".into());
                    }
                    let w = wakes.get_mut(wake).ok_or("missing wake")?;
                    if w.task != *task || !w.ready || w.used {
                        return Err("premature, stale or replayed wake".into());
                    }
                    w.used = true;
                    t.phase = Phase::Running;
                    out.resumed += 1;
                }
            }
            Ok(())
        })();
        result.map_err(|message| format!("event {i}: {message}"))?;
    }
    if out.actors == 0 || out.fired + out.retired == 0 {
        return Err("no actor work observed".into());
    }
    if actors.values().any(|live| *live)
        || callbacks.values().any(|(_, live)| *live)
        || tasks.values().any(|t| !matches!(&t.phase, Phase::Retired))
    {
        return Err("incomplete lifecycle: actor, task or callback remains live".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn a(id: &str) -> Event {
        Event::SpawnActor(id.into())
    }
    fn z(id: &str) -> Event {
        Event::StopActor(id.into())
    }
    fn t(actor: &str, task: &str) -> Event {
        Event::SpawnTask {
            actor: actor.into(),
            task: task.into(),
        }
    }
    fn s(task: &str, wake: &str) -> Event {
        Event::Suspend {
            task: task.into(),
            wake: wake.into(),
        }
    }
    fn r(task: &str, wake: &str) -> Event {
        Event::Resume {
            task: task.into(),
            wake: wake.into(),
        }
    }
    #[test]
    fn two_actors_callback_and_await_interleave_without_carrier_parking() {
        let trace = [
            a("actor-a#1"),
            a("actor-b#1"),
            t("actor-a#1", "task-1"),
            s("task-1", "wake-1"),
            Event::RegisterCallback {
                actor: "actor-b#1".into(),
                callback: "cb".into(),
            },
            Event::FireCallback("cb".into()),
            Event::UnregisterCallback("cb".into()),
            z("actor-b#1"),
            Event::Ready("wake-1".into()),
            r("task-1", "wake-1"),
            Event::FinishTask("task-1".into()),
            Event::RetireTask("task-1".into()),
            z("actor-a#1"),
        ];
        assert_eq!(analyze(&trace).unwrap().retired, 1);
    }
    #[test]
    fn cancellation_is_not_physical_task_retirement() {
        let pending = [
            a("a"),
            t("a", "t"),
            s("t", "w"),
            Event::CancelTask("t".into()),
            z("a"),
        ];
        assert!(analyze(&pending).is_err());
        let complete = [
            a("a"),
            t("a", "t"),
            s("t", "w"),
            Event::CancelTask("t".into()),
            Event::Ready("w".into()),
            Event::RetireTask("t".into()),
            z("a"),
        ];
        assert!(analyze(&complete).is_ok());
        let stale = [
            a("a"),
            t("a", "t"),
            s("t", "w"),
            Event::CancelTask("t".into()),
            Event::Ready("w".into()),
            r("t", "w"),
            Event::RetireTask("t".into()),
            z("a"),
        ];
        assert!(analyze(&stale).is_err());
    }
    #[test]
    fn callback_lifetime_failures_are_not_green() {
        assert!(analyze(&[a("a"), Event::FireCallback("cb".into()), z("a")]).is_err());
        assert!(analyze(&[
            a("a"),
            Event::RegisterCallback {
                actor: "a".into(),
                callback: "cb".into()
            },
            z("a")
        ])
        .is_err());
        assert!(analyze(&[
            a("a"),
            Event::RegisterCallback {
                actor: "a".into(),
                callback: "cb".into()
            },
            Event::UnregisterCallback("cb".into()),
            Event::FireCallback("cb".into()),
            z("a")
        ])
        .is_err());
    }
    #[test]
    fn early_duplicate_and_replayed_wake_are_rejected() {
        assert!(analyze(&[
            a("a"),
            t("a", "t"),
            s("t", "w"),
            r("t", "w"),
            Event::FinishTask("t".into()),
            Event::RetireTask("t".into()),
            z("a")
        ])
        .is_err());
        assert!(analyze(&[
            a("a"),
            t("a", "t"),
            s("t", "w"),
            Event::Ready("w".into()),
            Event::Ready("w".into()),
            r("t", "w"),
            Event::FinishTask("t".into()),
            Event::RetireTask("t".into()),
            z("a")
        ])
        .is_err());
    }
    #[test]
    fn empty_partial_and_reused_actor_id_fail_closed() {
        assert!(analyze(&[]).is_err());
        assert!(analyze(&[a("a")]).is_err());
        assert!(analyze(&[a("a"), a("a"), z("a")]).is_err());
        assert!(analyze(&[a("bad\nidentity"), z("bad\nidentity")]).is_err());
        assert!(analyze(&vec![a("a"); MAX_EVENTS + 1]).is_err());
    }
}
