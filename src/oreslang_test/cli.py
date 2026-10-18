"""Oreslang test CLI. Python >=3.11, standard library only.

Runtime-backed race capture is opt-in and fail-closed pending Java/LLVM hooks.
"""
import argparse
import hashlib
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import tempfile
import threading
import tomllib
import uuid

from .race import TraceError, analyze_trace
from .logical import ModelError, explore
from .deadlock import analyze_deadlocks


class UsageError(ValueError):
    pass


def _relative(root, name):
    if not isinstance(name, str) or not name:
        raise UsageError("expected nonempty relative path")
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise UsageError(f"path must be project-relative: {name}")
    target = (root / path).resolve()
    if not target.is_relative_to(root):
        raise UsageError(f"path escapes project root: {name}")
    return target


def _command(value, label):
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and x for x in value):
        raise UsageError(f"{label}.command must be a nonempty TOML array of argv strings")
    return value


def _run(command, root, timeout, data=None, env=None):
    # Drain each output pipe into bounded memory while the guest is running.
    # Post-exit file-size checks permit unlimited disk growth before admission.
    limit = 4_000_000

    def terminate(process):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            elif process.poll() is None:
                process.kill()
        except ProcessLookupError:
            pass
        except PermissionError:
            # Darwin may return EPERM once wait() has reaped the sole group
            # member. A live process still requires successful termination.
            if process.poll() is None:
                raise

    exceeded = threading.Event()
    reader_errors = []

    def drain(stream, output, process):
        try:
            while chunk := stream.read(65536):
                if len(output) + len(chunk) > limit:
                    exceeded.set()
                    terminate(process)
                    break
                output.extend(chunk)
        except (OSError, ValueError) as error:
            reader_errors.append(error)
            terminate(process)
        finally:
            stream.close()

    # A guest that never reads stdin cannot block an input-writer thread.
    with tempfile.TemporaryFile() as stdin:
        if data is not None:
            stdin.write(data)
            stdin.seek(0)
        try:
            process = subprocess.Popen(command, cwd=root, env=env, stdin=stdin,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=(os.name == "posix"))
        except OSError as exc:
            raise UsageError(f"cannot start executable {command[0]}: {exc}") from exc
        stdout, stderr = bytearray(), bytearray()
        readers = [threading.Thread(target=drain, args=(stream, output, process), daemon=True)
                   for stream, output in ((process.stdout, stdout), (process.stderr, stderr))]
        for reader in readers:
            reader.start()
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate(process)
            process.wait()
        finally:
            for reader in readers:
                reader.join(timeout=1)
            leaked_output = any(reader.is_alive() for reader in readers)
            if leaked_output:
                terminate(process)
                for reader in readers:
                    reader.join(timeout=1)
        if any(reader.is_alive() for reader in readers):
            raise UsageError("test process output never closed")
        if reader_errors:
            raise UsageError(f"test process output reader failed: {reader_errors[0]}")
        if exceeded.is_set():
            raise UsageError("test process emitted more than 4 MB stdout or stderr")
        if timed_out:
            return None
        if leaked_output:
            raise UsageError("test process descendants outlived the runner")
        return subprocess.CompletedProcess(command, process.returncode, bytes(stdout), bytes(stderr))


def _decode(output):
    return output.decode("utf-8", errors="replace")[:8000]


def run_native(root, config, timeout):
    native = config.get("native", {})
    files = native.get("files")
    if files is None:
        files = [str(p.relative_to(root)) for p in sorted((root / "tests").rglob("*.ores"))
                 if p.name.startswith("test_") or p.name.endswith("_test.ores")]
    if not isinstance(files, list) or not all(isinstance(x, str) for x in files) or not files:
        raise UsageError("no native test files; configure [native].files or tests/test_*.ores")
    executable = os.environ.get("ORESLANG_BIN", "oreslang-core")
    if Path(executable).resolve() == Path(sys.argv[0]).resolve():
        raise UsageError("ORESLANG_BIN points to the test wrapper (would recurse)")
    failed = 0
    for name in files:
        path = _relative(root, name)
        if not path.is_file() or path.suffix != ".ores":
            raise UsageError(f"not an Oreslang test file: {name}")
        result = _run([executable, str(path)], root, timeout)
        if result is None:
            print(f"TIMEOUT {name}")
            failed += 1
            continue
        output = result.stdout.decode("utf-8", errors="replace")
        summaries = [line for line in output.splitlines() if line.startswith("ORES_TEST|SUMMARY|")]
        status_lines = [line for line in output.splitlines()
                        if line.startswith(("ORES_TEST|PASS|", "ORES_TEST|FAIL|", "ORES_TEST|SKIP|"))]
        valid = False
        if len(summaries) == 1:
            try:
                pairs = [item.split("=", 1) for item in summaries[0].split("|")[2:]]
                counts = {k: int(v) for k, v in pairs}
                valid = (set(counts) == {"total", "passed", "failed", "skipped", "filtered"}
                         and all(x >= 0 for x in counts.values())
                         and counts["total"] == counts["passed"] + counts["failed"] + counts["skipped"]
                         and len(status_lines) == counts["total"])
                for status in ("PASS", "FAIL", "SKIP"):
                    valid &= sum(line.startswith(f"ORES_TEST|{status}|") for line in status_lines) == counts[{"PASS": "passed", "FAIL": "failed", "SKIP": "skipped"}[status]]
                valid &= counts["failed"] == 0
            except (ValueError, KeyError):
                valid = False
        if result.returncode != 0 or not valid:
            failed += 1
            print(f"FAIL {name}: exit={result.returncode}, valid_summary={valid}")
            print(output[:8000] or _decode(result.stderr))
        else:
            print(f"PASS {name}: {summaries[0]}")
    return 1 if failed else 0


def _failure(result):
    if result is None:
        return "timeout"
    return f"exit:{result.returncode}" if result.returncode else None


def fuzz(root, config, seed, cases, timeout):
    params = config.get("fuzz", {})
    cmd = _command(params.get("command"), "fuzz")
    if not 1 <= cases <= 1_000_000:
        raise UsageError("--cases must be between 1 and 1000000")
    max_bytes = params.get("max_bytes", 256)
    if type(max_bytes) is not int or not 1 <= max_bytes <= 65536:
        raise UsageError("fuzz.max_bytes must be between 1 and 65536")
    rng = random.Random(seed)
    corpus_path = _relative(root, params.get("corpus", "tests/corpus"))
    corpus = [b"", b"\x00", b"\xff"]
    if corpus_path.exists():
        if not corpus_path.is_dir():
            raise UsageError("fuzz corpus is not a directory")
        for p in sorted(corpus_path.iterdir()):
            if p.is_symlink():
                raise UsageError("fuzz corpus cannot contain symlinks")
            if p.is_file() and p.stat().st_size <= max_bytes:
                corpus.append(p.read_bytes())
    else:
        print("No corpus directory; using built-in seed cases")
    unique = list(dict.fromkeys(corpus))
    for i in range(cases):
        if i < len(unique):
            case = unique[i]
        else:
            base = bytearray(rng.choice(unique))
            if not base or rng.randrange(4) == 0:
                case = rng.randbytes(rng.randrange(max_bytes + 1))
            else:
                for _ in range(1 + rng.randrange(4)):
                    idx = rng.randrange(len(base))
                    base[idx] ^= rng.randrange(256)
                case = bytes(base[:max_bytes])
        result = _run(cmd, root, timeout, data=case)
        failure = _failure(result)
        if failure:
            # A reproducible counterexample must fail more than once. Do not
            # minimize a flaky invocation or silently treat it as success.
            if any(_failure(_run(cmd, root, timeout, data=case)) != failure for _ in range(2)):
                print(f"FUZZ FLAKY seed={seed} iteration={i} reason={failure}; cannot minimize")
                return 2
            print(f"FUZZ FAILURE seed={seed} iteration={i} reason={failure} size={len(case)}")
            # Deterministic delta debugging. Never accept a shrink with a different failure class.
            minimized, budget, granularity = case, 200, 2
            while len(minimized) > 0 and budget > 0:
                size = max(1, (len(minimized) + granularity - 1) // granularity)
                candidates = [minimized[:start] + minimized[start + size:]
                              for start in range(0, len(minimized), size)]
                shorter = False
                for candidate in candidates:
                    budget -= 1
                    if _failure(_run(cmd, root, timeout, data=candidate)) == failure:
                        minimized, granularity, shorter = candidate, 2, True
                        break
                    if budget == 0:
                        break
                if not shorter:
                    if granularity >= len(minimized):
                        break
                    granularity = min(len(minimized), granularity * 2)
            if any(_failure(_run(cmd, root, timeout, data=minimized)) != failure for _ in range(2)):
                print("FUZZ FLAKY minimized case changed behavior; retaining original counterexample")
                minimized = case
            dest_dir = _relative(root, ".oreslang-test/failures")
            dest_dir.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(minimized).hexdigest()[:20]
            saved = dest_dir / f"fuzz-{digest}.bin"
            if saved.is_symlink() or (saved.exists() and not saved.is_file()):
                raise UsageError("unsafe failure artifact destination")
            if saved.exists() and saved.read_bytes() != minimized:
                raise UsageError("failure artifact hash collision")
            saved.write_bytes(minimized)
            print(f"Minimized to {len(minimized)} bytes: {saved.relative_to(root)}")
            if result is not None:
                print(_decode(result.stderr))
            return 1
        if len(unique) < 4096:
            unique.append(case)
    print(f"FUZZ PASS cases={cases} seed={seed} (tested inputs only)")
    return 0


def race(root, config, trace, logical, model, timeout, max_schedules):
    params = config.get("race", {})
    status = 0
    analyses = 0
    if trace:
        report = analyze_trace(_relative(root, trace))
        analyses += 1
        status |= _show_races(report)
    elif params.get("command"):
        cmd = _command(params["command"], "race")
        run_id = uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix="oreslang-race-") as d:
            path = Path(d) / "events.jsonl"
            env = dict(os.environ, ORESLANG_RACE_TRACE=str(path), ORESLANG_RACE_RUN_ID=run_id)
            result = _run(cmd, root, timeout, env=env)
            if result is None or result.returncode != 0:
                raise UsageError("instrumented race test failed or timed out; cannot certify trace")
            report = analyze_trace(path, expected_run_id=run_id)
            analyses += 1
            status |= _show_races(report)
    if logical or model:
        paths = [model] if model else config.get("logical", {}).get("models", [])
        if not isinstance(paths, list) or not paths:
            raise UsageError("--logical needs --model or [logical].models")
        for name in paths:
            report = explore(_relative(root, name), max_schedules=max_schedules)
            analyses += 1
            if report["violation"]:
                print(f"LOGICAL RACE {name}: {report['violation']}")
                status = 1
            else:
                print(f"LOGICAL PASS {name}: explored {report['schedules']} schedules (reference model only)")
    if analyses > 0 and (logical or model) and not (trace or params.get("command")):
        print("No instrumented memory-access trace analyzed; result is logical-model-only")
    if analyses == 0:
        raise UsageError("--race needs --trace, [race].command instrumentation, or --logical model; refusing a false PASS")
    return status


def deadlock(root, config, trace, timeout):
    """Analyze lock order risk and unresolved wait cycles in actual trace events."""
    if trace:
        report = analyze_deadlocks(_relative(root, trace))
    else:
        params = config.get("deadlock", {})
        command = params.get("command") or config.get("race", {}).get("command")
        if command is None:
            raise UsageError("--deadlock requires --trace or [deadlock].command "
                             "instrumentation; refusing false PASS")
        cmd = _command(command, "deadlock")
        run_id = uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix="oreslang-deadlock-") as d:
            path = Path(d) / "events.jsonl"
            env = dict(os.environ, ORESLANG_RACE_TRACE=str(path),
                       ORESLANG_RACE_RUN_ID=run_id)
            result = _run(cmd, root, timeout, env=env)
            if result is None or result.returncode != 0:
                raise UsageError("instrumented deadlock test failed or timed out")
            report = analyze_deadlocks(path, expected_run_id=run_id)
    for cycle in report["observed_wait_cycles"][:20]:
        print("OBSERVED WAIT CYCLE: " + " -> ".join(cycle))
    for cycle in report["potential_lock_order_cycles"][:20]:
        print("POTENTIAL LOCK-ORDER CYCLE: " + " -> ".join(cycle))
    if report["observed_wait_cycles"] or report["potential_lock_order_cycles"]:
        print("DEADLOCK FINDINGS: "
              f"{len(report['observed_wait_cycles'])} observed wait cycles, "
              f"{len(report['potential_lock_order_cycles'])} potential lock-order cycles")
        return 1
    print(f"DEADLOCK TRACE PASS: {report['lock_events']} observed lock events "
          "(no cycles in observed lock graph; no whole-program liveness proof)")
    return 0


def schedule(root, config, seed, iterations, timeout, replay, trace_output):
    """Delegate schedule perturbation/replay to the explicitly configured runtime."""
    if not 1 <= iterations <= 1_000:
        raise UsageError("--iterations must be between 1 and 1000")
    if replay is not None and iterations != 1:
        raise UsageError("--replay requires --iterations=1")
    if trace_output is not None and iterations != 1:
        raise UsageError("--trace-output requires --iterations=1")
    params = config.get("schedule", {})
    cmd = _command(params.get("command"), "schedule")
    if replay is not None:
        args = ["--replay=" + str(_relative(root, replay))]
    else:
        args = ["--schedule-fuzz", "--seed=" + str(seed),
                "--iterations=" + str(iterations)]
    if trace_output is not None:
        args += ["--trace-output=" + str(_relative(root, trace_output))]
    result = _run(cmd + args, root, timeout)
    if result is None:
        print("SCHEDULE TIMEOUT")
        return 1
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    summaries = [line for line in stdout.splitlines()
                 if line.startswith("ORES_TEST|SUMMARY|")]
    receipts = [line for line in stdout.splitlines()
                if line.startswith("ORES_CONCURRENCY|RUN|")]
    valid = (result.returncode == 0 and len(summaries) == iterations
             and len(receipts) == iterations
             and all("|failed=0|" in line for line in summaries))
    if not valid:
        print("SCHEDULE FAIL: backend did not provide complete native suite receipts")
        print((stdout + stderr)[:8000])
        return 1
    print(f"SCHEDULE PASS: {iterations} backend perturbation/replay runs "
          "(carrier interleavings are not deterministic)")
    return 0


def _show_races(report):
    if report["race_count"]:
        for conflict in report["races"][:20]:
            print(f"DATA RACE: {conflict}")
        print(f"{report['race_count']} conflicts in {report['events']} observed events (first 100 shown)")
        return 1
    print(f"TRACE PASS: {report['events']} observed events on {report['backend']} (no conflicts in observed trace; not a full-race-freedom proof)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="oreslang test")
    parser.add_argument("--root", default=".")
    parser.add_argument("--fuzz", action="store_true")
    parser.add_argument("--race", action="store_true")
    parser.add_argument("--deadlock", action="store_true")
    parser.add_argument("--schedule-fuzz", action="store_true")
    parser.add_argument("--replay", help="project-relative backend schedule replay trace")
    parser.add_argument("--trace-output", help="project-relative schedule trace output")
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--logical", action="store_true")
    parser.add_argument("--trace", help="offline ORES_RACE_V1 JSONL trace (project-relative)")
    parser.add_argument("--model", help="bounded actor model JSON (project-relative)")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--cases", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-schedules", type=int, default=10000)
    args = parser.parse_args(argv)
    try:
        if args.fuzz and (args.race or args.deadlock or args.logical
                          or args.model or args.trace or args.schedule_fuzz):
            raise UsageError("--fuzz cannot combine with other testing modes")
        if (args.logical or args.model) and not args.race:
            raise UsageError("--logical/--model requires --race")
        if args.trace and not (args.race or args.deadlock):
            raise UsageError("--trace requires --race or --deadlock")
        if args.replay and args.schedule_fuzz:
            raise UsageError("--replay and --schedule-fuzz are mutually exclusive")
        if (args.replay or args.trace_output or args.iterations != 1) and not (args.schedule_fuzz or args.replay):
            raise UsageError("schedule options require --schedule-fuzz or --replay")
        if (args.schedule_fuzz or args.replay) and (args.race or args.deadlock or args.fuzz):
            raise UsageError("schedule runner is a separate backend test mode")
        if not 0.01 <= args.timeout <= 600:
            raise UsageError("--timeout must be between 0.01 and 600 seconds")
        root = Path(args.root).resolve(strict=True)
        if not root.is_dir():
            raise UsageError("project root must be a directory")
        manifest = root / "oreslang-test.toml"
        if manifest.is_file():
            with manifest.open("rb") as fh:
                config = tomllib.load(fh)
        else:
            config = {}
        if args.schedule_fuzz or args.replay:
            return schedule(root, config, args.seed, args.iterations,
                            args.timeout, args.replay, args.trace_output)
        if args.fuzz:
            return fuzz(root, config, args.seed, args.cases, args.timeout)
        status = 0
        if args.race:
            status |= race(root, config, args.trace, args.logical, args.model,
                           args.timeout, args.max_schedules)
        if args.deadlock:
            status |= deadlock(root, config, args.trace, args.timeout)
        if args.race or args.deadlock:
            return status
        return run_native(root, config, args.timeout)
    except (UsageError, TraceError, ModelError, OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"oreslang test: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
