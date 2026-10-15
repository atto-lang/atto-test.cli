"""Reproducible Oreslang fuzz runs and fail-closed race evidence admission."""

import argparse
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
from dataclasses import dataclass

MAX_RUNS = 100_000
MAX_INPUT = 1_048_576
MAX_OUTPUT = 1_048_576
MAX_CORPUS_BYTES = 16 * 1_048_576
# Preserve only host essentials by default; do not leak arbitrary CI secrets.
HOST_ENV_ALLOWLIST = frozenset((
    "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE",
    "SYSTEMROOT", "WINDIR", "COMSPEC", "USERPROFILE", "JAVA_HOME", "GRAALVM_HOME",
))


class GuestTimeoutError(RuntimeError):
    """A fuzzed child exceeded its configured execution budget."""


class EvidenceError(ValueError):
    """A backend did not provide sufficient trustworthy test evidence."""


@dataclass(frozen=True)
class TestSummary:
    total: int
    passed: int
    failed: int
    skipped: int
    filtered: int


def _parse_numbers(parts, prefix, keys):
    if not parts or parts[0] != prefix:
        raise EvidenceError(f"missing {prefix} record")
    fields = {}
    for part in parts[1:]:
        name, marker, value = part.partition("=")
        if not marker or not name or name in fields:
            raise EvidenceError(f"malformed or duplicate field in {prefix}")
        fields[name] = value
    if set(fields) != set(keys):
        raise EvidenceError(f"{prefix} expected fields {', '.join(keys)}")
    parsed = {}
    for name in keys:
        if not fields[name].isascii() or not fields[name].isdecimal():
            raise EvidenceError(f"{prefix} invalid counter {name}")
        parsed[name] = int(fields[name])
    return parsed


def _record_lines(stdout, kind):
    return [line.split("|") for line in stdout.splitlines() if line.startswith(kind + "|")]


def parse_test_summary(stdout):
    records = [x[1:] for x in _record_lines(stdout, "ORES_TEST") if len(x) > 1 and x[1] == "SUMMARY"]
    if len(records) != 1:
        raise EvidenceError("expected exactly one ORES_TEST|SUMMARY record")
    nums = _parse_numbers(records[0], "SUMMARY", ("total", "passed", "failed", "skipped", "filtered"))
    if nums["total"] != nums["passed"] + nums["failed"] + nums["skipped"]:
        raise EvidenceError("ORES_TEST summary counters are inconsistent")
    if nums["passed"] + nums["failed"] == 0:
        raise EvidenceError("no executable tests ran")
    return TestSummary(**nums)


def parse_race_evidence(stdout):
    records = [x[1:] for x in _record_lines(stdout, "ORES_RACE")]
    beginnings = [x for x in records if x and x[0] == "BEGIN"]
    summaries = [x for x in records if x and x[0] == "SUMMARY"]
    if len(beginnings) != 1 or len(summaries) != 1:
        raise EvidenceError("race backend absent: requires exactly one BEGIN and SUMMARY")
    if beginnings[0] != ["BEGIN", "version=1", "memory_instrumented=true", "logical_instrumented=true"]:
        raise EvidenceError("race backend lacks versioned memory + logical instrumentation")
    nums = _parse_numbers(summaries[0], "SUMMARY", ("memory_accesses", "memory_races", "logical_checks", "logical_violations"))
    if nums["memory_accesses"] == 0 or nums["logical_checks"] == 0:
        raise EvidenceError("race instrumentation reported no memory accesses or logical checks")
    return nums


def build_input(rng, corpus, case, max_input):
    seeds = corpus or [b"", b"\x00", b"A", b"0", b"\n", b"\xff"]
    original = seeds[case % len(seeds)][:max_input]
    if case < len(seeds):
        return original  # Always run the unmodified corpus before mutation.
    candidate = bytearray(original)
    action = rng.randrange(4)
    if action == 0 and candidate:
        candidate[rng.randrange(len(candidate))] ^= 1 << rng.randrange(8)
    elif action == 1 and candidate:
        del candidate[rng.randrange(len(candidate))]
    elif action == 2 and len(candidate) < max_input:
        candidate.insert(rng.randrange(len(candidate) + 1), rng.randrange(256))
    elif action == 3 and candidate:
        candidate[rng.randrange(len(candidate))] = rng.randrange(256)
    elif len(candidate) < max_input:
        candidate.append(rng.randrange(256))
    return bytes(candidate)


def load_corpus(directory, max_input):
    if directory is None:
        return []
    root = Path(directory)
    if not root.is_dir():
        raise EvidenceError(f"corpus directory missing: {root}")
    files = sorted(path for path in root.iterdir() if path.is_file() and not path.is_symlink())
    if not files or len(files) > 10_000:
        raise EvidenceError("corpus must contain 1..10000 regular files")
    corpus = []
    total_bytes = 0
    for path in files:
        size = path.stat().st_size
        if size > max_input:
            raise EvidenceError(f"corpus input exceeds max size: {path}")
        total_bytes += size
        if total_bytes > MAX_CORPUS_BYTES:
            raise EvidenceError("corpus exceeds total 16 MiB memory budget")
        data = path.read_bytes()
        if len(data) > max_input:
            raise EvidenceError(f"corpus input changed size while reading: {path}")
        corpus.append(data)
    return corpus


def run_guest(args, data, case):
    command = [args.runner]
    if not args.direct_runner:
        command.append("run")
    command.extend(args.runner_arg)
    command.append(str(args.file))
    environment = (os.environ.copy() if args.inherit_env
                   else {key: value for key, value in os.environ.items()
                         if key in HOST_ENV_ALLOWLIST})
    environment["ORES_TEST_MACHINE"] = "1"
    environment["ORES_TEST_MODE"] = "race" if args.race else "fuzz"
    environment["ORES_TEST_SEED"] = str(args.seed)
    environment["ORES_TEST_CASE"] = str(case)
    if args.race:
        environment["ORES_RACE_REQUIRED"] = "1"
        environment["ORES_RACE_SCHEDULE_SEED"] = str((args.seed + case) % (1 << 64))
    else:
        environment["ORES_FUZZ_INPUT_STDIN"] = "1"
    try:
        # Bounded reading prevents a noisy guest from exhausting CLI memory.
        # OS-backed temporary files hold subprocess output outside Python heap.
        with tempfile.TemporaryFile(mode="w+b") as out, tempfile.TemporaryFile(mode="w+b") as err:
            result = subprocess.run(command, input=data, stdout=out, stderr=err,
                                    env=environment, timeout=args.timeout, check=False)
            if out.tell() > MAX_OUTPUT or err.tell() > MAX_OUTPUT:
                raise EvidenceError("runner output exceeded the 1 MiB limit")
            out.seek(0)
            err.seek(0)
            return (result.returncode, out.read().decode("utf-8", "replace"),
                    err.read().decode("utf-8", "replace"))
    except subprocess.TimeoutExpired as exc:
        raise GuestTimeoutError(f"case {case} timed out after {args.timeout}s") from exc
    except OSError as exc:
        raise EvidenceError(f"unable to start runner {args.runner!r}: {exc}") from exc


def save_failing_case(args, case, payload, reason):
    root = Path(args.artifacts)
    root.mkdir(parents=True, exist_ok=True)
    name = f"seed-{args.seed}-case-{case}"
    (root / f"{name}.bin").write_bytes(payload)
    corpus_arg = f" --corpus {args.corpus}" if args.corpus is not None else ""
    (root / f"{name}.txt").write_text(
        f"seed={args.seed}\ncase={case}\nreason={reason}\n"
        f"runner={args.runner}\n"
        f"replay: oreslang test --fuzz {args.file} --seed {args.seed} "
        f"--runs {case+1} --max-input {args.max_input}{corpus_arg}\n"
        "The original corpus, runner binary and CLI version must be retained for replay.\n",
        encoding="utf-8")
    print(f"saved failing input: {root / (name + '.bin')}", file=sys.stderr)


def make_parser():
    parser = argparse.ArgumentParser(prog="oreslang test",
        description="Fail-closed race evidence validation and deterministic black-box fuzzing")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--race", action="store_true", help="require instrumented memory and logical race evidence")
    mode.add_argument("--fuzz", action="store_true", help="run deterministic black-box fuzz input cases")
    parser.add_argument("file", type=Path, help="Oreslang test program using stdlib/testing.ores machine output")
    parser.add_argument("--runner", default=os.environ.get("ORESLANG_TEST_RUNNER", "oreslang"),
                        help="runner executable (default: oreslang)")
    parser.add_argument("--direct-runner", action="store_true", help="omit the default 'run' subcommand")
    parser.add_argument("--runner-arg", action="append", default=[], help="extra runner argument before FILE")
    parser.add_argument("--runs", type=int, default=None, help="repetitions (race: 1, fuzz: 100)")
    parser.add_argument("--seed", type=int, default=1, help="unsigned 64-bit deterministic seed")
    parser.add_argument("--timeout", type=float, default=10.0, help="timeout for each child process in seconds")
    parser.add_argument("--corpus", type=Path, help="fuzz input corpus directory")
    parser.add_argument("--max-input", type=int, default=4096, help="maximum fuzz payload bytes")
    parser.add_argument("--artifacts", type=Path, default=Path("target/oreslang-fuzz-failures"),
                        help="directory for failing fuzz inputs")
    parser.add_argument("--inherit-env", action="store_true",
                        help="explicitly pass all host environment variables to test guests (may expose secrets)")
    return parser


def main(argv=None):
    parser = make_parser()
    args = parser.parse_args(argv)
    args.runs = args.runs if args.runs is not None else (1 if args.race else 100)
    if not args.file.is_file():
        parser.error(f"source file not found: {args.file}")
    if not (1 <= args.runs <= MAX_RUNS and 0 <= args.seed < (1 << 64)
            and args.timeout > 0 and args.timeout <= 3600
            and 1 <= args.max_input <= MAX_INPUT):
        parser.error("invalid --runs, --seed, --timeout or --max-input range")
    if args.race and args.corpus is not None:
        parser.error("--corpus applies only to --fuzz")
    try:
        corpus = load_corpus(args.corpus, args.max_input) if args.fuzz else []
    except EvidenceError as exc:
        print(f"oreslang test: {exc}", file=sys.stderr)
        return 2
    rng = random.Random(args.seed)
    for case in range(args.runs):
        payload = build_input(rng, corpus, case, args.max_input) if args.fuzz else b""
        try:
            code, stdout, stderr = run_guest(args, payload, case)
            if code != 0:
                if args.fuzz:
                    save_failing_case(args, case, payload, f"guest exited {code}")
                print(f"oreslang test: guest exited {code} in case {case}", file=sys.stderr)
                if stderr:
                    print(stderr[-4096:], file=sys.stderr)
                return 1
            summary = parse_test_summary(stdout)
            evidence = parse_race_evidence(stdout) if args.race else None
            if args.race:
                # NEVER treat a guest-printed ORES_RACE line as trusted instrumentation:
                # a guest can forge perfect counters. The future backend-owned
                # reporting channel must authenticate observations independently.
                raise EvidenceError(
                    "no trusted backend race attestation is configured; "
                    "guest stdout reports do not prove absence of races")
        except GuestTimeoutError as exc:
            if args.fuzz:
                save_failing_case(args, case, payload, str(exc))
            print(f"oreslang test: failing case {case}: {exc}", file=sys.stderr)
            return 1
        except EvidenceError as exc:
            if args.fuzz:
                save_failing_case(args, case, payload, str(exc))
            print(f"oreslang test: inconclusive case {case}: {exc}", file=sys.stderr)
            return 2
        if code != 0 or summary.failed:
            if args.fuzz:
                save_failing_case(args, case, payload, f"exit={code} failures={summary.failed}")
            print(f"oreslang test: failing case {case}: exit={code}, failed={summary.failed}", file=sys.stderr)
            if stderr:
                print(stderr[-4096:], file=sys.stderr)
            return 1
        # evidence is deliberately not promoted to a race-clean result until
        # the Java/LLVM backends add an authenticated, runner-owned channel.
    if args.race:
        raise AssertionError("race mode must remain fail-closed until trusted instrumentation")
    else:
        print(f"black-box fuzz passed: {args.runs} cases, seed={args.seed}; "
              "not coverage-guided; guest input consumption not verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
