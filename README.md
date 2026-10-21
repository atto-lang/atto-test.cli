# Oreslang Test CLI

The new test command runner for the Oreslang language.

**Status: working host-side prototype, not yet a fully instrumented language feature.** Rust 1.85+ owns the public launchers and exceptional-effect hints. Native tests, race traces, logical models and fuzzing currently delegate to the existing Python 3.11+ runner; those engines remain migration debt. The Java/GraalVM and LLVM runtimes do not yet emit comprehensive memory-access traces, and actual guest schedule control is still to be implemented. Tests here are conformance tests of the tool and synthetic reference models.

## Install and try it

Put the repository's bin directory on PATH, with ORESLANG_BIN pointing to your *existing* Oreslang launcher (not to the shim itself). Non-test commands delegate to that launcher. The alternative executable oreslang-test accepts the test options directly.

The checkout's shell launchers build/run the Rust binaries through Cargo. For
native startup without Cargo on each invocation, use `cargo install --path . --locked`.
`--effects` needs no Python runtime. Legacy modes locate the preserved runner
in this checkout; keep the checkout available after installation, or set
`ORESLANG_TEST_LEGACY` to the absolute path of its `bin/legacy-oreslang-test`.
Python 3.11+ must be available as `python3` on PATH for those legacy modes.

    export PATH=/path/to/oreslang-test.cli/bin:$PATH
    export ORESLANG_BIN=/path/to/real/oreslang

    oreslang test
    oreslang test --fuzz --seed 87 --cases 2000
    oreslang test --race
    oreslang test --race --trace tests/traces/recorded.jsonl
    oreslang test --race --logical --model tests/models/lost-update.json

A project must contain oreslang-test.toml. Native tests are automatically discovered as tests/**/test_*.ores and tests/**/*_test.ores, or listed via [native].files. The existing Oreslang stdlib/testing.ores machine protocol (ORES_TEST|...) is parsed and validated. An interpreter failure, absent summary or inconsistent counts makes the suite fail.

Run the included test suite with:

    cargo test --locked
    cargo clippy --locked --all-targets -- -D warnings
    python3 -m unittest discover -s tests -v
    bin/oreslang test --race --trace tests/traces/racy.jsonl
    bin/oreslang test --race --logical --model tests/models/lost-update.json

The two example invocations deliberately report detected defects.

## Fuzzing

Configure a real executable target that reads a raw test case on standard input and exits nonzero when a property fails:

~~~toml
[fuzz]
command = ["/path/to/oreslang", "tests/fuzz_stdin.ores"]
corpus = "tests/corpus/my-property"
max_bytes = 256
~~~

The runner mutates seed/corpus bytes reproducibly using --seed, runs one isolated process per --cases input, enforces --timeout, stops on failure and attempts delta-debugging shrinkage without changing the failure class. Minimized case bytes are saved under .oreslang-test/failures/fuzz-<hash>.bin. Reproduce by redirecting these bytes into the configured command. This is *mutation fuzzing*, not coverage-guided fuzzing yet; there is no automatic source-level fuzz target discovery or Oreslang-native input generation yet.

## Data races and happens-before

The race analyzer consumes version-1 JSONL records with explicit task and memory location identities. Supported events are task; fork/join with child; lock/unlock with name; send/recv with message; and access with location and mode R/W. It checks unordered conflicting accesses using vector clocks. A minimal intentionally racy record sequence is:

~~~jsonl
{"op":"begin","version":1,"run_id":"test","backend":"graal"}
{"op":"task","task":"a"}
{"op":"task","task":"b"}
{"op":"access","task":"a","location":"heap:alloc-1.field","mode":"W"}
{"op":"access","task":"b","location":"heap:alloc-1.field","mode":"R"}
{"op":"end","run_id":"test","events":4}
~~~

Production runtime integrations must write a *fresh* trace to ORESLANG_RACE_TRACE and echo the invocation's ORESLANG_RACE_RUN_ID in begin/end markers:

~~~toml
[race]
command = ["/path/to/instrumented-oreslang", "tests/race_suite.ores"]
~~~

The tool refuses missing, stale, truncated, malformed and failed traces. Task identifiers mean physical concurrency contexts; all relevant synchronization including actor turn serialization and mailbox handoff must be captured. Memory locations must use stable allocation identities to avoid address reuse false positives. No checker's silence can prove absence of races that instrumentation did not observe. Sample traces here are synthetic.

## Logical races in actor programs

In addition to physical data races, a reentrant actor can suspend after reading a snapshot, then resume and write a stale value. This is a logical race even if native memory accesses are correctly synchronized.

For now --race --logical explores *declarative bounded models*, not compiled Oreslang programs. Each actor contains arrays of atomic turns; boundaries represent suspension. The model supports read, write, atomic_add and final expected integer invariants. The explorer enumerates enabled actor turns and reports a counterexample schedule on invariant failure. If --max-schedules is hit before exploration completes, the result is **inconclusive** (exit code 2). Example files: tests/models/lost-update.json and tests/models/atomic-update.json.

~~~toml
[logical]
models = ["tests/models/atomic-update.json"]
~~~

## Exit codes and integration milestones

- **0:** Tests or observed trace/model run passed. Never interpret this as proof of complete race freedom.
- **1:** Executed test failed, fuzz counterexample, data-race conflict or model invariant violation.
- **2:** Invalid configuration, missing instrumented backend, invalid/incomplete trace, or inconclusive model search.

The native language testing API remains in oreslang-source.java/stdlib/testing.ores. The shared ACTOR_LOGICAL_RACE_V1 contract in Java and LLVM currently certifies the VersionedActorCell *host-side foundation only*, not guest-level enforcement.

Before promoting these flags as general automatic detectors, integrate compiler/runtime memory-access hooks, actor mailbox/lock/suspend happens-before edges, coverage accounting, real guest controlled scheduling, cancellation/continuation generation checks, Java native-image parity, LLVM sanitizer builds, and cross-backend reproducible regression tests. The CLI must continue to fail closed in the absence of such instrumentation.


## Audit hardening (2026-10-15)

The hardening revision strengthens the host-only tool without claiming language-level instrumentation:

- The vector-clock checker **retains all per-task, per-access-mode histories** (bounded to the last event in each task/mode), rather than silently dropping unordered reads/writes when another task writes. It caps printed conflict examples at 100 while retaining the total count.
- The trace grammar adds `{"op":"finish","task":"..."}`. A `join` now requires a finished, directly forked child that has not already been joined. Any forked child left unfinished at trace termination, post-finish access, duplicate JSON key, or invalid encoding is a hard error.
- Model files are limited to 2 MB, 16 actors, 64 turns, 4096 operations, and 256 state keys. Operation schemas and local references are validated before exploring interleavings.
- Each test subprocess captures no more than 4 MB per stdout/stderr stream in memory; larger outputs fail. Timed-out process groups are terminated on POSIX hosts. A fuzz counterexample is re-executed twice before minimization and the reduced input is also checked twice; flaky first failures become an explicit non-success status.
- `python -m unittest discover -s tests -v` covers 28 cases including race-history and synchronization adversarial examples. The local audit test result is **not** a GitHub Actions result until the complete exact Git tree has run on a CI runner.

The `finish` event is an extension of the v1 JSONL trace vocabulary. Existing traces with independent root tasks remain valid; actual `fork` traces should emit corresponding task completion events. This remains host-side analysis of observed events, and runtime coverage must be separately attested before claiming race freedom.

## Advisory exceptional-effect analysis (prototype)

`oreslang test --effects --file path/to/module.ores` reports local
`throw`, `raise`, and `panic` statements whose enclosing named
`fnc`, `routine`, or method lacks an optional corresponding `throws`,
`raises`, or `panics` annotation. Use `--effects-strict` to exit
1 on warnings. With no `--file`, source files are selected via
`[effects].files` in oreslang-test.toml or bounded recursive discovery.

This is **syntax-only advisory analysis**, NOT proof of exceptional-control
semantics, whole-program effects, checked exceptions, race freedom or source
execution. It does not resolve transitive calls, dynamic dispatch, nominal
Error ancestry, exceptional control-flow recovery, or
unbounded code. Unsupported input fails closed with exit 2; clean results
list the number of braced named callables inspected. A missing clause
does not mean a function is guaranteed not to throw, raise or panic.
The native compiler still independently controls admissibility.

The `--effects` mode cannot combine with `--race`, `--fuzz`, or
logical-model/trace modes. Keep runtime verification separate.

The Rust scanner covers explicit and bare named class methods, explicit
receivers, generic named declarations and named pipe declarations. It rejects
anonymous/pipe expressions, interpolated literals, record return types and
uninspected exceptional-effect scopes as inconclusive. Ordinary comments,
nested block comments, literals and Symbol names do not introduce effects.
Interface signatures alone are not counted as executable bodies. This is a
bounded source scanner, not a replacement for the compiler parser.

Limits: 256 KiB per source/config file, 25,000 tokens per source, 256 delimiter
or comment levels, 512 files, 4 MiB total source and 16,384 diagnostics. Discovery
skips hidden paths, `target` and `node_modules`, refuses symlinks, and stops at
20,000 directory entries or 64 directory levels. Explicit source paths must
stay inside the project and contain no symlink components. All files are
analyzed before printing a completed advisory report; an invalid later file
cannot leave an earlier apparent success on stdout.

Static-mode exits: **0** means advisory analysis completed, **1** means strict
mode found warnings, and **2** means invalid or inconclusive input. Exit 0,
including with every marker present, never certifies effect freedom or runtime
admission. The requested [effect semantics and remaining compiler/runtime
gates](docs/exception-effects.md) are tracked separately.


## Trusted backend race evidence (under development)

See [docs/RACE_EVIDENCE_V1.md](docs/RACE_EVIDENCE_V1.md) for the proposed
LLVM/GraalVM admission contract. The Rust-only `rust/race_evidence.rs`
module checks bounded receipt *shape* (build/run binding, event counters,
memory scopes, complete surface manifest and sticky overflow). It deliberately
does **not** certify a runtime: no authenticated host-only event channel,
backend scheduler coverage or source-to-binary provenance handoff has been
implemented yet. The current `--race --trace` paths are **offline trace
analysis**, not a trusted-run race-free certificate. Do not wire a successful
shape check to CLI exit 0 until those backend admission gates exist.
