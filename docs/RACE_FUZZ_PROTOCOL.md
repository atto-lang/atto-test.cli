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

Versioned BEGIN/SUMMARY records can be parsed as diagnostics, but **all guest
stdout race reports are untrusted and cannot produce exit 0 in this stage**.
`--race` exits **2 (inconclusive)** even if the guest prints perfect-looking
counters. A failing guest process exits **1 (failure)**. This closes the
forged-report false-green gap until the Java/LLVM backends provide a distinct,
backend-owned measurement and attestation channel. An executable that merely
prints these records is **not** a race detector. Compiler-owned memory-access
instrumentation and scheduler invariant evidence remain to be implemented.

For `--fuzz`, `ORES_FUZZ_INPUT_STDIN=1` and the seed/case are provided in
the guest environment, with binary input on stdin. The guest test must consume
and assert over the input. The CLI cannot currently attest that the guest
actually read stdin or that coverage increased, so success is **black-box**
crash/property fuzzing, not coverage-guided fuzzing. Inputs are deterministic
for a given Python runtime, seed, corpus and CLI version; failing input bytes
and replay metadata are saved under `target/oreslang-fuzz-failures`.

## Isolation and security

Each case runs a separate child process without a shell, with a bounded
timeout, maximum generated input size and 1 MiB capture/read budget per output
stream. Fuzz timeouts fail the case (exit 1) and save replay artifacts; an
oversized output or missing machine report is inconclusive (exit 2). Corpus files are read-only, with
symlinks ignored. No private source is mirrored, published or checked out
across organizations. No GitHub credentials or arbitrary secrets are needed.

The caller is responsible for testing trusted guest programs and restricting
their filesystem/network/process capabilities. The CLI does not itself
sandbox guest code. Future releases should add deterministic scheduler
exploration, shrinking, corpus deduplication, coverage feedback, and
source-level race access probes only after the backend can provide them.
