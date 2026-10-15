"""Happens-before checker for instrumented Oreslang event traces, protocol v1.

This *analyzes observed accesses*. A trace cannot certify that a compiler/runtime
instrumented all accesses; instrumentation coverage is an independent gate.
"""
import json
from pathlib import Path


class TraceError(ValueError):
    pass


def _require(ok, message):
    if not ok:
        raise TraceError(message)


def _string(value, name):
    _require(isinstance(value, str) and 0 < len(value) <= 512, f"invalid {name}")
    return value


def _leq(left, right):
    return all(v <= right.get(k, 0) for k, v in left.items())


def _merge(dst, src):
    for k, v in src.items():
        dst[k] = max(dst.get(k, 0), v)


def analyze_trace(path, expected_run_id=None):
    path = Path(path)
    _require(path.is_file() and path.stat().st_size <= 10_000_000, "trace missing or exceeds 10 MB")
    with path.open(encoding="utf-8") as handle:
        lines = handle.readlines()
    _require(2 <= len(lines) <= 100_002, "trace must contain begin/end and <=100000 events")
    try:
        records = [json.loads(line) for line in lines]
    except (ValueError, UnicodeError) as exc:
        raise TraceError(f"invalid JSONL trace: {exc}") from exc
    _require(all(isinstance(r, dict) for r in records), "all trace records must be objects")
    first, last = records[0], records[-1]
    _require(first.get("op") == "begin" and first.get("version") == 1, "missing ORES_RACE_V1 begin")
    _require(last.get("op") == "end", "missing trace end")
    run_id = _string(first.get("run_id"), "run_id")
    _require(last.get("run_id") == run_id, "trace end run_id differs")
    if expected_run_id is not None:
        _require(run_id == expected_run_id, "trace is stale or not from this invocation")
    _require(type(last.get("events")) is int and last["events"] == len(records) - 2,
             "incorrect trace event count")
    _string(first.get("backend"), "backend")
    clocks = {}
    locks = {}  # lock -> (owner, released vector clock)
    messages = {}
    accesses = {}  # location -> {'read': task/vc, 'write': task/vc}
    races = []
    access_count = 0
    for index, event in enumerate(records[1:-1], 2):
        op = event.get("op")
        task = _string(event.get("task"), f"event {index} task")
        if op == "task":
            _require(task not in clocks, f"duplicate task {task}")
            clocks[task] = {task: 1}
            continue
        _require(task in clocks, f"unregistered task {task} at event {index}")
        clock = clocks[task]
        if op == "fork":
            child = _string(event.get("child"), "child")
            _require(child not in clocks, "duplicate child")
            clocks[child] = dict(clock)
            clocks[child][child] = 1
        elif op == "join":
            child = _string(event.get("child"), "child")
            _require(child in clocks and child != task, "join requires another registered task")
            _merge(clock, clocks[child])
        elif op == "lock":
            name = _string(event.get("name"), "lock name")
            owner, release = locks.get(name, (None, {}))
            _require(owner is None, f"lock {name} acquired while owned")
            _merge(clock, release)
            locks[name] = (task, release)
        elif op == "unlock":
            name = _string(event.get("name"), "lock name")
            owner, _ = locks.get(name, (None, {}))
            _require(owner == task, f"unlock of unowned lock {name}")
            locks[name] = (None, dict(clock))
        elif op == "send":
            name = _string(event.get("message"), "message")
            _require(name not in messages, "message identity reused")
            messages[name] = dict(clock)
        elif op == "recv":
            name = _string(event.get("message"), "message")
            _require(name in messages, "receive without send")
            _merge(clock, messages.pop(name))
        elif op == "access":
            access_count += 1
            location = _string(event.get("location"), "location")
            mode = event.get("mode")
            _require(mode in ("R", "W"), "access mode must be R or W")
            previous = accesses.setdefault(location, {"R": {}, "W": {}})
            checks = [("W", t, v) for t, v in previous["W"].items()]
            if mode == "W":
                checks += [("R", t, v) for t, v in previous["R"].items()]
            for prior_mode, other, prior_clock in checks:
                if other != task and not _leq(prior_clock, clock):
                    races.append({"location": location, "first": other,
                                  "second": task, "first_mode": prior_mode,
                                  "second_mode": mode, "event": index})
            if mode == "W":
                previous["W"] = {task: dict(clock)}
                previous["R"] = {}
            else:
                previous["R"][task] = dict(clock)
        else:
            raise TraceError(f"unsupported trace op {op!r} at event {index}")
        clock[task] = clock.get(task, 0) + 1
    _require(access_count > 0, "trace contains no observed memory accesses; refusing false PASS")
    _require(all(owner is None for owner, _ in locks.values()), "trace ends with held locks")
    return {"events": len(records)-2, "races": races, "backend": first["backend"]}
