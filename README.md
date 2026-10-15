# Oreslang Test CLI

The new test command runner for the Oreslang language.

**Status: working host-side prototype, not yet a fully instrumented language feature.** Python 3.11+ (standard library only). The Java/GraalVM and LLVM runtimes do not yet emit comprehensive memory-access traces, and actual guest schedule control is still to be implemented. Tests here are conformance tests of the tool and synthetic reference models.

## Install and try it

Put the repository's bin directory on PATH, with ORESLANG_BIN pointing to your *existing* Oreslang launcher (not to the shim itself). Non-test commands delegate to that launcher. The alternative executable oreslang-test accepts the test options directly.

    export PATH=/path/to/oreslang-test.cli/bin:$PATH
    export ORESLANG_BIN=/path/to/real/oreslang

    oreslang test
    oreslang test --fuzz --seed 87 --cases 2000
    oreslang test --race
    oreslang test --race --trace tests/traces/recorded.jsonl
    oreslang test --race --logical --model tests/models/lost-update.json

A project must contain oreslang-test.toml. Native tests are automatically discovered as tests/**/test_*.ores and tests/**/*_test.ores, or listed via [native].files. The existing Oreslang stdlib/testing.ores machine protocol (ORES_TEST|...) is parsed and validated. An interpreter failure, absent summary or inconsistent counts makes the suite fail.

Run the included test suite with:

    python3 -m unittest discover -s tests -v
    python3 bin/oreslang test --race --trace tests/traces/racy.jsonl
    python3 bin/oreslang test --race --logical --model tests/models/lost-update.json

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
