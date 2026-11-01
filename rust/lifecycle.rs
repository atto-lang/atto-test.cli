//! Strict, structural v2 receipt checks for native Oreslang async test suites.
//! Guest stdout is unauthenticated: this verifies consistency, not scheduler truth.
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Counts {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub filtered: usize,
}

#[derive(Default)]
struct Case {
    seen: BTreeSet<(String, String)>,
    pending: BTreeSet<(String, String)>,
    bad_close: bool,
    ended: Option<&'static str>,
}

fn label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
}

fn summary(parts: &[&str]) -> Result<Counts, String> {
    if parts.len() != 5 {
        return Err("lifecycle RUN_END requires five counts".into());
    }
    let mut fields = BTreeMap::new();
    for item in parts {
        let (key, value) = item.split_once('=').ok_or("malformed lifecycle count")?;
        if !["total", "passed", "failed", "skipped", "filtered"].contains(&key)
            || value.is_empty()
            || !value.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("invalid lifecycle count".into());
        }
        if fields
            .insert(key, value.parse::<usize>().map_err(|_| "lifecycle count overflow")?)
            .is_some()
        {
            return Err("duplicate lifecycle count".into());
        }
    }
    if fields.len() != 5 {
        return Err("missing lifecycle count".into());
    }
    Ok(Counts {
        total: fields["total"],
        passed: fields["passed"],
        failed: fields["failed"],
        skipped: fields["skipped"],
        filtered: fields["filtered"],
    })
}

pub(super) fn verify(output: &str) -> Result<Counts, String> {
    let mut started = false;
    let mut finished = false;
    let mut reported = None;
    let mut cases: BTreeMap<String, Case> = BTreeMap::new();
    let mut events = 0usize;
    for line in output.lines() {
        // The entire ORES_TEST namespace is reserved, including truncated
        // records such as "ORES_TEST_V2" without the final delimiter.
        // Ignoring malformed machine-looking lines could mask lost writes.
        if line.starts_with("ORES_TEST") && !line.starts_with("ORES_TEST_V2|") {
            return Err("mixed or malformed lifecycle machine receipt".into());
        }
        let Some(record) = line.strip_prefix("ORES_TEST_V2|") else {
            continue;
        };
        events += 1;
        if events > 100_000 || finished {
            return Err("lifecycle event after RUN_END or event budget exhausted".into());
        }
        if !record.is_ascii() || record.bytes().any(|b| b.is_ascii_control()) {
            return Err("invalid lifecycle event character".into());
        }
        let fields: Vec<_> = record.split('|').collect();
        match fields.as_slice() {
            ["RUN_BEGIN", "2"] if !started => started = true,
            ["CASE_BEGIN", id] if started => {
                if !label(id) || cases.len() >= 10_000 || cases.contains_key(*id) {
                    return Err("invalid or duplicate lifecycle case".into());
                }
                cases.insert((*id).to_owned(), Case::default());
            }
            ["OPEN", id, kind, handle] if started => {
                if !["callback", "task", "actor", "await"].contains(kind) || !label(handle) {
                    return Err("invalid lifecycle resource".into());
                }
                let case = cases.get_mut(*id).ok_or("OPEN for unknown case")?;
                if case.ended.is_some() {
                    return Err("OPEN after case completion".into());
                }
                let key = ((*kind).to_owned(), (*handle).to_owned());
                // A handle denotes one logical resource, not an arbitrary
                // (kind, handle) pair. Reusing it across kinds creates ABA
                // ambiguity in cross-backend lifecycle instrumentation.
                if case.seen.iter().any(|(_, used)| used == *handle)
                    || !case.seen.insert(key.clone())
                    || !case.pending.insert(key)
                {
                    return Err("duplicate lifecycle resource handle".into());
                }
            }
            ["CLOSE", id, kind, handle, outcome] if started => {
                if !["callback", "task", "actor", "await"].contains(kind)
                    || !["ok", "error", "cancel"].contains(outcome)
                {
                    return Err("invalid lifecycle completion".into());
                }
                let case = cases.get_mut(*id).ok_or("CLOSE for unknown case")?;
                if case.ended.is_some()
                    || !case.pending.remove(&((*kind).to_owned(), (*handle).to_owned()))
                {
                    return Err("duplicate or unmatched lifecycle CLOSE".into());
                }
                case.bad_close |= *outcome != "ok";
            }
            ["CASE_END", id, status] if started => {
                if !["PASS", "FAIL", "SKIP"].contains(status) {
                    return Err("invalid lifecycle case status".into());
                }
                let case = cases.get_mut(*id).ok_or("CASE_END for unknown case")?;
                if case.ended.is_some() || !case.pending.is_empty() {
                    return Err("case ended twice or with outstanding resources".into());
                }
                if (*status == "PASS" && case.bad_close)
                    || (*status == "SKIP" && !case.seen.is_empty())
                {
                    return Err("PASS/SKIP hides lifecycle resource error/activity".into());
                }
                case.ended = Some(match *status {
                    "PASS" => "PASS",
                    "FAIL" => "FAIL",
                    _ => "SKIP",
                });
            }
            ["RUN_END", rest @ ..] if started => {
                reported = Some(summary(rest)?);
                finished = true;
            }
            _ => return Err("malformed or out-of-order lifecycle event".into()),
        }
    }
    if !started || !finished || cases.values().any(|c| c.ended.is_none()) {
        return Err("incomplete lifecycle receipt".into());
    }
    let result = reported.ok_or("missing lifecycle RUN_END")?;
    let observed = [
        cases.values().filter(|c| c.ended == Some("PASS")).count(),
        cases.values().filter(|c| c.ended == Some("FAIL")).count(),
        cases.values().filter(|c| c.ended == Some("SKIP")).count(),
    ];
    if observed[0] == 0 && observed[1] == 0 {
        return Err("lifecycle suite executed zero test bodies".into());
    }
    if result.total > 10_000 || result.filtered > 10_000
        || result.total.checked_add(result.filtered).is_none()
    {
        return Err("lifecycle discovery count exceeds budget".into());
    }
    if observed != [result.passed, result.failed, result.skipped]
        || observed.iter().sum::<usize>() != result.total
    {
        return Err("lifecycle summary does not match events".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "ORES_TEST_V2|RUN_BEGIN|2\nORES_TEST_V2|CASE_BEGIN|suite/async\nORES_TEST_V2|OPEN|suite/async|callback|cb\nORES_TEST_V2|OPEN|suite/async|task|t1\nORES_TEST_V2|OPEN|suite/async|actor|a1\nORES_TEST_V2|OPEN|suite/async|await|aw1\nORES_TEST_V2|CLOSE|suite/async|callback|cb|ok\nORES_TEST_V2|CLOSE|suite/async|await|aw1|ok\nORES_TEST_V2|CLOSE|suite/async|task|t1|ok\nORES_TEST_V2|CLOSE|suite/async|actor|a1|ok\nORES_TEST_V2|CASE_END|suite/async|PASS\nORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\n";

    #[test]
    fn scoped_callbacks_tasks_actors_and_awaits_complete() {
        assert_eq!(
            verify(GOOD),
            Ok(Counts { total: 1, passed: 1, failed: 0, skipped: 0, filtered: 0 })
        );
    }

    #[test]
    fn incomplete_or_mismatched_async_receipts_are_rejected() {
        let mut bad = Vec::new();
        for kind in [
            "callback|cb", "task|t1", "actor|a1", "await|aw1",
        ] {
            let line = format!("ORES_TEST_V2|CLOSE|suite/async|{kind}|ok\n");
            bad.push(GOOD.replace(&line, ""));
        }
        bad.push(GOOD.replace("ORES_TEST_V2|RUN_BEGIN|2\n", ""));
        bad.push(GOOD.replace("ORES_TEST_V2|CASE_END|suite/async|PASS\n", ""));
        bad.push(GOOD.replace("ORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\n", ""));
        bad.push(format!("{GOOD}ORES_TEST_V2|CASE_BEGIN|late\n"));
        bad.push(GOOD.replace("|actor|a1|ok", "|actor|a1|cancel"));
        bad.push(GOOD.replace("|callback|cb|ok", "|callback|cb|error"));
        bad.push(GOOD.replace("|CASE_END|suite/async|PASS", "|CASE_END|suite/async|SKIP"));
        bad.push(GOOD.replace("|RUN_END|total=1", "|RUN_END|total=2"));
        bad.push(GOOD.replace("|OPEN|suite/async|task|t1\n", ""));
        bad.push(GOOD.replace("|OPEN|suite/async|task|t1", "|OPEN|suite/async|task|t1\nORES_TEST_V2|OPEN|suite/async|task|t1"));
        bad.push(GOOD.replace("|CLOSE|suite/async|actor|a1|ok", "|CLOSE|suite/async|actor|a1|ok\nORES_TEST_V2|CLOSE|suite/async|actor|a1|ok"));
        bad.push(GOOD.replace("|CASE_BEGIN|suite/async", "|CASE_BEGIN|suite/async\nORES_TEST_V2|CASE_BEGIN|suite/async"));
        bad.push(GOOD.replace("|CASE_BEGIN|suite/async", "|CASE_BEGIN|suite/async\nORES_TEST|PASS|suite/async"));
        for output in bad {
            assert!(verify(&output).is_err(), "accepted invalid receipt: {output}");
        }
    }

    #[test]
    fn rejects_incomplete_discovery_bad_ids_and_bad_counts() {
        let all_skipped = "ORES_TEST_V2|RUN_BEGIN|2\nORES_TEST_V2|CASE_BEGIN|skipped\nORES_TEST_V2|CASE_END|skipped|SKIP\nORES_TEST_V2|RUN_END|total=1|passed=0|failed=0|skipped=1|filtered=0\n";
        let unfinished_case = "ORES_TEST_V2|RUN_BEGIN|2\nORES_TEST_V2|CASE_BEGIN|unfinished\nORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\n";
        for text in [
            all_skipped.to_owned(),
            unfinished_case.to_owned(),
            GOOD.replace("|CASE_BEGIN|suite/async", "|CASE_BEGIN|suite/async with spaces"),
            GOOD.replace("|OPEN|suite/async|actor|a1", "|OPEN|suite/async|thread|a1"),
            GOOD.replace("|OPEN|suite/async|actor|a1", "|OPEN|suite/other|actor|a1"),
            GOOD.replace("|CLOSE|suite/async|actor|a1", "|CLOSE|suite/wrong|actor|a1"),
            GOOD.replace("|RUN_END|total=1", "|RUN_END|total=1|total=1"),
            GOOD.replace("|RUN_END|total=1", "|RUN_END|total=+1"),
            GOOD.replace("|RUN_END|total=1", "|RUN_END|total=18446744073709551616000"),
            GOOD.replace("|RUN_END|total=1", "|RUN_END|unknown=1"),
            GOOD.replace("|CASE_END|suite/async|PASS", "|CASE_END|suite/async|TODO"),
            GOOD.replace("|RUN_BEGIN|2", "|RUN_BEGIN|3"),
        ] {
            assert!(verify(&text).is_err(), "accepted invalid lifecycle stream: {text}");
        }
    }

    #[test]
    fn all_twenty_four_async_completion_orders_remain_valid() {
        let start = concat!(
            "ORES_TEST_V2|RUN_BEGIN|2\n",
            "ORES_TEST_V2|CASE_BEGIN|async\n",
            "ORES_TEST_V2|OPEN|async|callback|cb\n",
            "ORES_TEST_V2|OPEN|async|task|t\n",
            "ORES_TEST_V2|OPEN|async|actor|a\n",
            "ORES_TEST_V2|OPEN|async|await|w\n"
        );
        let closings = [
            "ORES_TEST_V2|CLOSE|async|callback|cb|ok\n",
            "ORES_TEST_V2|CLOSE|async|task|t|ok\n",
            "ORES_TEST_V2|CLOSE|async|actor|a|ok\n",
            "ORES_TEST_V2|CLOSE|async|await|w|ok\n",
        ];
        let end = concat!(
            "ORES_TEST_V2|CASE_END|async|PASS\n",
            "ORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\n"
        );
        let mut orders = 0;
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        if a == b || a == c || a == d || b == c || b == d || c == d {
                            continue;
                        }
                        orders += 1;
                        let valid = format!(
                            "{start}{}{}{}{}{end}",
                            closings[a], closings[b], closings[c], closings[d]
                        );
                        assert!(verify(&valid).is_ok(), "rejected valid completion ordering");
                        let incomplete = format!(
                            "{start}{}{}{}{end}",
                            closings[a], closings[b], closings[c]
                        );
                        assert!(verify(&incomplete).is_err(), "accepted incomplete ordering");
                    }
                }
            }
        }
        assert_eq!(orders, 24);
    }

    #[test]
    fn eighty_one_async_completion_outcome_combinations() {
        let start = concat!(
            "ORES_TEST_V2|RUN_BEGIN|2\n",
            "ORES_TEST_V2|CASE_BEGIN|async\n",
            "ORES_TEST_V2|OPEN|async|callback|cb\n",
            "ORES_TEST_V2|OPEN|async|task|t\n",
            "ORES_TEST_V2|OPEN|async|actor|a\n",
            "ORES_TEST_V2|OPEN|async|await|w\n"
        );
        let mut cases = 0;
        for callback in ["ok", "error", "cancel"] {
            for task in ["ok", "error", "cancel"] {
                for actor in ["ok", "error", "cancel"] {
                    for awaited in ["ok", "error", "cancel"] {
                        cases += 1;
                        let completes = format!(
                            "ORES_TEST_V2|CLOSE|async|callback|cb|{callback}\n\
                             ORES_TEST_V2|CLOSE|async|task|t|{task}\n\
                             ORES_TEST_V2|CLOSE|async|actor|a|{actor}\n\
                             ORES_TEST_V2|CLOSE|async|await|w|{awaited}\n"
                        );
                        let pass = format!(
                            "{start}{completes}ORES_TEST_V2|CASE_END|async|PASS\n\
                             ORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\n"
                        );
                        let all_ok = [callback, task, actor, awaited]
                            .iter()
                            .all(|outcome| *outcome == "ok");
                        assert_eq!(verify(&pass).is_ok(), all_ok);
                        let fail = format!(
                            "{start}{completes}ORES_TEST_V2|CASE_END|async|FAIL\n\
                             ORES_TEST_V2|RUN_END|total=1|passed=0|failed=1|skipped=0|filtered=0\n"
                        );
                        assert_eq!(verify(&fail).unwrap().failed, 1);
                    }
                }
            }
        }
        assert_eq!(cases, 81);
    }

    #[test]
    fn adversarial_lifecycle_mutations_cannot_claim_pass() {
        let mutations = [
            ("ORES_TEST_V2|RUN_BEGIN|2\n", ""),
            ("ORES_TEST_V2|RUN_BEGIN|2\n", "ORES_TEST_V2|RUN_BEGIN|2\nORES_TEST_V2|RUN_BEGIN|2\n"),
            ("ORES_TEST_V2|CASE_BEGIN|suite/async\n", ""),
            ("ORES_TEST_V2|CASE_BEGIN|suite/async\n", "ORES_TEST_V2|CASE_BEGIN|suite/async\nORES_TEST_V2|CASE_BEGIN|suite/async\n"),
            ("ORES_TEST_V2|OPEN|suite/async|callback|cb\n", ""),
            ("ORES_TEST_V2|CLOSE|suite/async|callback|cb|ok\n", ""),
            ("ORES_TEST_V2|CLOSE|suite/async|callback|cb|ok\n", "ORES_TEST_V2|CLOSE|suite/async|callback|cb|ok\nORES_TEST_V2|CLOSE|suite/async|callback|cb|ok\n"),
            ("ORES_TEST_V2|OPEN|suite/async|task|t1\n", "ORES_TEST_V2|OPEN|suite/async|task|other\n"),
            ("ORES_TEST_V2|CLOSE|suite/async|task|t1|ok\n", "ORES_TEST_V2|CLOSE|suite/async|task|t2|ok\n"),
            ("ORES_TEST_V2|CLOSE|suite/async|actor|a1|ok\n", "ORES_TEST_V2|CLOSE|suite/async|actor|a1|cancel\n"),
            ("ORES_TEST_V2|CLOSE|suite/async|await|aw1|ok\n", "ORES_TEST_V2|CLOSE|suite/async|await|aw1|error\n"),
            ("ORES_TEST_V2|CASE_END|suite/async|PASS\n", "ORES_TEST_V2|CASE_END|suite/async|FAIL\nORES_TEST_V2|CASE_END|suite/async|PASS\n"),
            ("ORES_TEST_V2|CASE_END|suite/async|PASS\n", ""),
            ("ORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\n", ""),
            ("ORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\n", "ORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\nORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0\n"),
            ("ORES_TEST_V2|RUN_BEGIN|2", "ORES_TEST_V2|RUN_BEGIN|3"),
            ("ORES_TEST_V2|RUN_END|total=1", "ORES_TEST_V2|RUN_END|total=2"),
            ("ORES_TEST_V2|RUN_END|total=1", "ORES_TEST_V2|RUN_END|total=01|total=1"),
        ];
        for (from, to) in mutations {
            let altered = GOOD.replacen(from, to, 1);
            assert_ne!(GOOD, altered, "mutation fixture must change baseline");
            assert!(verify(&altered).is_err(), "accepted invalid mutation: {altered}");
        }
    }

    #[test]
    fn truncated_machine_prefixes_are_never_ignored() {
        for invalid in ["ORES_TEST", "ORES_TEST_V2", "ORES_TEST_V2_BAD", "ORES_TEST|PASS|legacy"] {
            let output = format!("{GOOD}{invalid}\n");
            assert!(verify(&output).is_err(), "accepted reserved prefix: {invalid}");
        }
    }

    #[test]
    fn callback_task_actor_and_await_handles_do_not_reopen() {
        for (kind, handle) in [
            ("callback", "cb"),
            ("task", "t1"),
            ("actor", "a1"),
            ("await", "aw1"),
        ] {
            let original = format!("ORES_TEST_V2|OPEN|suite/async|{kind}|{handle}\n");
            let duplicate = format!("{original}{original}");
            let output = GOOD.replacen(&original, &duplicate, 1);
            assert!(verify(&output).is_err(), "accepted reopened {kind} handle");
        }
    }

    #[test]
    fn failed_case_must_drain_its_children_before_end() {
        let failed = GOOD.replace("|CASE_END|suite/async|PASS", "|CASE_END|suite/async|FAIL")
            .replace("|passed=1|failed=0", "|passed=0|failed=1");
        assert_eq!(verify(&failed).unwrap().failed, 1);
        for (kind, handle) in [
            ("callback", "cb"),
            ("task", "t1"),
            ("actor", "a1"),
            ("await", "aw1"),
        ] {
            let closed = format!("ORES_TEST_V2|CLOSE|suite/async|{kind}|{handle}|ok\n");
            assert!(verify(&failed.replace(&closed, "")).is_err(), "undrained {kind}");
        }
    }

    #[test]
    fn concurrent_cases_can_interleave_without_cross_scope_completion() {
        let valid = concat!(
            "ORES_TEST_V2|RUN_BEGIN|2\n",
            "ORES_TEST_V2|CASE_BEGIN|a\n",
            "ORES_TEST_V2|CASE_BEGIN|b\n",
            "ORES_TEST_V2|OPEN|a|task|child\n",
            "ORES_TEST_V2|OPEN|b|task|child\n",
            "ORES_TEST_V2|CLOSE|b|task|child|ok\n",
            "ORES_TEST_V2|CLOSE|a|task|child|ok\n",
            "ORES_TEST_V2|CASE_END|a|PASS\n",
            "ORES_TEST_V2|CASE_END|b|PASS\n",
            "ORES_TEST_V2|RUN_END|total=2|passed=2|failed=0|skipped=0|filtered=0\n"
        );
        assert_eq!(verify(valid).unwrap().passed, 2);
        let cross_scope = valid.replacen(
            "ORES_TEST_V2|CLOSE|b|task|child|ok\n",
            "ORES_TEST_V2|CLOSE|a|task|child|ok\n", 1
        );
        assert!(verify(&cross_scope).is_err());
    }

    #[test]
    fn bounded_ten_thousand_case_discovery_cannot_overflow() {
        let mut at_limit = String::from("ORES_TEST_V2|RUN_BEGIN|2\n");
        for index in 0..10_000 {
            at_limit.push_str(&format!("ORES_TEST_V2|CASE_BEGIN|case/{index}\n"));
            at_limit.push_str(&format!("ORES_TEST_V2|CASE_END|case/{index}|PASS\n"));
        }
        let valid = format!(
            "{at_limit}ORES_TEST_V2|RUN_END|total=10000|passed=10000|failed=0|skipped=0|filtered=0\n"
        );
        assert_eq!(verify(&valid).unwrap().passed, 10_000);
        at_limit.push_str("ORES_TEST_V2|CASE_BEGIN|case/overflow\n");
        at_limit.push_str("ORES_TEST_V2|CASE_END|case/overflow|PASS\n");
        let excessive = format!(
            "{at_limit}ORES_TEST_V2|RUN_END|total=10001|passed=10001|failed=0|skipped=0|filtered=0\n"
        );
        assert!(verify(&excessive).is_err());
    }

    #[test]
    fn rejects_oversized_identifiers_and_noncanonical_resources() {
        let allowed = "x".repeat(256);
        let rejected = "x".repeat(257);
        let one = GOOD.replace("suite/async", &allowed);
        assert!(verify(&one).is_ok());
        assert!(verify(&GOOD.replace("suite/async", &rejected)).is_err());
        assert!(verify(&GOOD.replace("|callback|cb", &format!("|callback|{rejected}"))).is_err());
        for bad in ["callback/other", "actor ", "TASK", "", "actor|bad"] {
            assert!(verify(&GOOD.replace("|OPEN|suite/async|actor|a1", &format!("|OPEN|suite/async|{bad}|a1"))).is_err());
        }
    }

    #[test]
    fn interleaved_cases_and_cleanup_on_failure() {
        let data = "ORES_TEST_V2|RUN_BEGIN|2\nORES_TEST_V2|CASE_BEGIN|a\nORES_TEST_V2|OPEN|a|task|one\nORES_TEST_V2|CASE_BEGIN|b\nORES_TEST_V2|OPEN|b|actor|two\nORES_TEST_V2|CLOSE|a|task|one|error\nORES_TEST_V2|CLOSE|b|actor|two|ok\nORES_TEST_V2|CASE_END|a|FAIL\nORES_TEST_V2|CASE_END|b|PASS\nORES_TEST_V2|RUN_END|total=2|passed=1|failed=1|skipped=0|filtered=0\n";
        assert_eq!(verify(data).unwrap().failed, 1);
    }
}
