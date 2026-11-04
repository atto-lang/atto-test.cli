//! Bounded host-side reactive composition invariant checker.
//! NOT runtime instrumentation, a scheduler proof, or a race certificate.
use std::collections::{BTreeMap, BTreeSet};

const MAX_EVENTS: usize = 100_000;
const MAX_DEMAND: u32 = 4096;
const MAX_IDENTITY_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMode {
    HotSingle,
    Cold,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Subscribe {
        subscription: String,
        source: String,
        mode: SourceMode,
    },
    Request {
        subscription: String,
        count: u32,
    },
    Next {
        subscription: String,
    },
    Complete {
        subscription: String,
    },
    Cancel {
        subscription: String,
    },
    Error {
        subscription: String,
        reason: String,
    },
    Dispose {
        subscription: String,
    },
}

impl Event {
    fn subscription(&self) -> &str {
        match self {
            Self::Subscribe { subscription, .. }
            | Self::Request { subscription, .. }
            | Self::Next { subscription }
            | Self::Complete { subscription }
            | Self::Cancel { subscription }
            | Self::Error { subscription, .. }
            | Self::Dispose { subscription } => subscription,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub events: usize,
    pub subscriptions: usize,
    pub next: usize,
    pub terminals: usize,
    pub active: usize,
}
struct Subscriber {
    mode: SourceMode,
    requested: u32,
    terminal: bool,
    disposed: bool,
}

fn identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTITY_BYTES && !value.chars().any(char::is_control)
}

pub fn analyze(events: &[Event]) -> Result<Report, String> {
    if events.len() > MAX_EVENTS {
        return Err("reactive trace exceeds 100000 events".into());
    }
    let mut sources = BTreeMap::<String, BTreeSet<String>>::new();
    let mut subscribers = BTreeMap::<String, Subscriber>::new();
    let mut next_count = 0;
    let mut terminal_count = 0;
    for (position, event) in events.iter().enumerate() {
        let id = event.subscription();
        if !identity(id) {
            return Err(format!("event {position}: invalid subscription identity"));
        }
        if let Event::Subscribe { source, mode, .. } = event {
            if !identity(source) {
                return Err("invalid reactive source identity".into());
            }
            if subscribers.contains_key(id) {
                return Err("duplicate subscription identity".into());
            }
            let assigned = sources.entry(source.clone()).or_default();
            if *mode == SourceMode::HotSingle && !assigned.is_empty() {
                return Err("hot single-consumer source cannot multicast".into());
            }
            if *mode == SourceMode::Cold
                && assigned.iter().any(|earlier| {
                    subscribers
                        .get(earlier)
                        .is_some_and(|x| x.mode == SourceMode::HotSingle)
                })
            {
                return Err("mixed source cardinality modes".into());
            }
            assigned.insert(id.to_owned());
            subscribers.insert(
                id.to_owned(),
                Subscriber {
                    mode: *mode,
                    requested: 0,
                    terminal: false,
                    disposed: false,
                },
            );
            continue;
        }
        let state = subscribers
            .get_mut(id)
            .ok_or_else(|| format!("event {position}: operation before subscribe"))?;
        if let Event::Dispose { .. } = event {
            if state.disposed {
                return Err("duplicate reactive disposal".into());
            }
            if !state.terminal {
                return Err("disposal without terminal cause".into());
            }
            state.disposed = true;
            continue;
        }
        if state.terminal {
            return Err("reactive event after terminal".into());
        }
        match event {
            Event::Request { count, .. } => {
                if *count == 0 || *count > MAX_DEMAND {
                    return Err("reactive demand increment must be 1..4096".into());
                }
                state.requested = state
                    .requested
                    .checked_add(*count)
                    .filter(|x| *x <= MAX_DEMAND)
                    .ok_or("reactive outstanding demand exceeds 4096")?;
            }
            Event::Next { .. } => {
                if state.requested == 0 {
                    return Err("next without downstream demand".into());
                }
                state.requested -= 1;
                next_count += 1;
            }
            Event::Complete { .. } | Event::Cancel { .. } => {
                state.terminal = true;
                terminal_count += 1;
            }
            Event::Error { reason, .. } => {
                if reason.is_empty() || reason.len() > 4096 {
                    return Err("terminal error requires bounded nonempty reason".into());
                }
                state.terminal = true;
                terminal_count += 1;
            }
            Event::Subscribe { .. } | Event::Dispose { .. } => unreachable!(),
        }
    }
    if subscribers
        .values()
        .any(|state| state.terminal && !state.disposed)
    {
        return Err("terminated subscription missing exact-once disposal".into());
    }
    Ok(Report {
        events: events.len(),
        subscriptions: subscribers.len(),
        next: next_count,
        terminals: terminal_count,
        active: subscribers.len() - terminal_count,
    })
}

/// Strict completion gate for a captured observable run.
///
/// `analyze` intentionally permits partial traces for interactive inspection.
/// A test verdict must instead require at least one subscription and every
/// subscriber to terminate and dispose, otherwise a truncated trace looks green.
pub fn analyze_complete(events: &[Event]) -> Result<Report, String> {
    let report = analyze(events)?;
    if report.subscriptions == 0 {
        return Err("reactive test executed no subscriptions".into());
    }
    if report.active != 0 || report.terminals != report.subscriptions {
        return Err("reactive test trace ended with live subscriptions".into());
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(id: &str, source: &str, mode: SourceMode) -> Event {
        Event::Subscribe {
            subscription: id.into(),
            source: source.into(),
            mode,
        }
    }
    fn req(id: &str, count: u32) -> Event {
        Event::Request {
            subscription: id.into(),
            count,
        }
    }
    fn next(id: &str) -> Event {
        Event::Next {
            subscription: id.into(),
        }
    }
    fn complete(id: &str) -> Event {
        Event::Complete {
            subscription: id.into(),
        }
    }
    fn dispose(id: &str) -> Event {
        Event::Dispose {
            subscription: id.into(),
        }
    }

    #[test]
    fn complete_bounded_backpressure_and_terminal_disposal_pass() {
        let events = [
            s("sub1", "source", SourceMode::HotSingle),
            req("sub1", 2),
            next("sub1"),
            next("sub1"),
            complete("sub1"),
            dispose("sub1"),
        ];
        assert_eq!(
            analyze(&events),
            Ok(Report {
                events: 6,
                subscriptions: 1,
                next: 2,
                terminals: 1,
                active: 0,
            })
        );
    }

    #[test]
    fn no_demand_or_repeated_terminal_or_missing_disposal_fails() {
        assert!(analyze(&[s("x", "a", SourceMode::Cold), next("x")]).is_err());
        assert!(analyze(&[s("x", "a", SourceMode::Cold), req("x", 4096), req("x", 1)]).is_err());
        assert!(analyze(&[s("x", "a", SourceMode::Cold), complete("x")]).is_err());
        assert!(analyze(&[
            s("x", "a", SourceMode::Cold),
            complete("x"),
            complete("x"),
            dispose("x")
        ])
        .is_err());
        assert!(analyze(&[
            s("x", "a", SourceMode::Cold),
            complete("x"),
            dispose("x"),
            dispose("x")
        ])
        .is_err());
    }

    #[test]
    fn source_cardinality_and_identity_are_preserved() {
        assert!(analyze(&[
            s("one", "src", SourceMode::HotSingle),
            s("two", "src", SourceMode::Cold)
        ])
        .is_err());
        assert!(analyze(&[
            s("one", "src", SourceMode::Cold),
            s("two", "src", SourceMode::HotSingle)
        ])
        .is_err());
        assert!(analyze(&[
            s("one", "src", SourceMode::Cold),
            s("one", "else", SourceMode::Cold)
        ])
        .is_err());
        assert_eq!(
            analyze(&[
                s("one", "src", SourceMode::Cold),
                s("two", "src", SourceMode::Cold)
            ])
            .unwrap()
            .active,
            2
        );
    }

    #[test]
    fn cancellation_failure_and_late_next_are_distinct() {
        assert!(analyze(&[
            s("x", "src", SourceMode::Cold),
            Event::Error {
                subscription: "x".into(),
                reason: "".into()
            }
        ])
        .is_err());
        assert!(analyze(&[
            s("x", "src", SourceMode::Cold),
            Event::Cancel {
                subscription: "x".into()
            },
            next("x")
        ])
        .is_err());
        assert_eq!(
            analyze(&[
                s("x", "src", SourceMode::Cold),
                Event::Error {
                    subscription: "x".into(),
                    reason: "I/O failure".into()
                },
                dispose("x")
            ])
            .unwrap()
            .terminals,
            1
        );
    }

    #[test]
    fn excessive_work_does_not_certify_empty_results() {
        assert!(analyze(&vec![s("x", "src", SourceMode::Cold); MAX_EVENTS + 1]).is_err());
    }

    #[test]
    fn complete_trace_gate_rejects_empty_and_unfinished_observers() {
        assert!(analyze_complete(&[]).is_err());
        assert_eq!(
            analyze(&[s("x", "src", SourceMode::Cold)]).unwrap().active,
            1
        );
        assert!(analyze_complete(&[s("x", "src", SourceMode::Cold)]).is_err());
        assert!(
            analyze_complete(&[s("x", "src", SourceMode::Cold), req("x", 1), next("x")]).is_err()
        );
        assert!(
            analyze_complete(&[s("x", "src", SourceMode::Cold), complete("x"), dispose("x")])
                .is_ok()
        );
    }

    #[test]
    fn complete_trace_gate_handles_independent_cold_observers() {
        let partial = [
            s("a", "cold", SourceMode::Cold),
            s("b", "cold", SourceMode::Cold),
            req("a", 1),
            next("a"),
            complete("a"),
            dispose("a"),
        ];
        assert_eq!(analyze(&partial).unwrap().active, 1);
        assert!(analyze_complete(&partial).is_err());
        let mut finished = partial.to_vec();
        finished.extend([complete("b"), dispose("b")]);
        assert_eq!(analyze_complete(&finished).unwrap().active, 0);
    }
}
