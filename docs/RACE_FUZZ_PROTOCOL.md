# Oreslang race and fuzz CLI — v1 protocol (staged)

## Command line

- `oreslang test --race test.ores --runs 10 --seed 123`
- `oreslang test --fuzz test.ores --runs 1000 --seed 123 --corpus ./testdata/fuzz`

This Python CLI orchestrates guest executions and consumes the native
`stdlib/testing.ores` machine protocol. It is intentionally a separate
repository; the Rust `oreslang-cli` provides the `oreslang test` entry point.

## Machine records

The guest test framework emits exactly one test summary per run:

```
ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0
```

For `--race`, a **trusted, instrumented backend** must additionally emit:

```
ORES_RACE|BEGIN|version=1|memory_instrumented=true|logical_instrumented=true
ORES_RACE|SUMMARY|memory_accesses=10|memory_races=0|logical_checks=2|logical_violations=0
```

Without exactly one BEGIN/SUMMARY, valid counters, at least one memory access
and one logical check, `--race` exits **2 (inconclusive)**, not green.
Any race/logical violation or failing test exits **1 (failure)**.
The protocol is not itself instrumentation, nor is untrusted stdout an
attestation; the backend must own the measurement and trusted publication.
Do not advertise a clean data-race result based only on a fabricated log.
Compiler-owned access instrumentation and scheduler-state evidence remain
to be implemented on Java and LLVM.

For `--fuzz`, `ORES_FUZZ_INPUT_STDIN=1` and the seed/case are provided in
the guest environment, with binary input on stdin. The guest test must consume
and assert over the input. The CLI cannot currently attest that the guest
actually read stdin or that coverage increased, so success is **black-box**
crash/property fuzzing, not coverage-guided fuzzing. Inputs are deterministic
for a given Python runtime, seed, corpus and CLI version; failing input bytes
and replay metadata are saved under `target/oreslang-fuzz-failures`.

## Isolation and security

Each case runs a separate child process without a shell, with a bounded
timeout and maximum generated input size. Corpus files are read-only, with
symlinks ignored. No private source is mirrored, published or checked out
across organizations. No GitHub credentials or arbitrary secrets are needed.

The caller is responsible for testing trusted guest programs and restricting
their filesystem/network/process capabilities. The CLI does not itself
sandbox guest code. Future releases should add deterministic scheduler
exploration, shrinking, corpus deduplication, coverage feedback, and
source-level race access probes only after the backend can provide them.
