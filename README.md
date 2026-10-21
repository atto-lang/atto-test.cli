# Oreslang Test CLI (Rust)

All public Oreslang test CLI entrypoints and their implemented engines are
native Rust 1.85+. There is **no Python launcher or Python subprocess**.
Use the two Cargo binaries:

- oreslang: delegates non-test commands to the real Oreslang executable
  (ORESLANG_BIN), routes oreslang test to this Rust implementation.
- oreslang-test: runs test subcommands directly.

Build and test with cargo build --locked, cargo test --locked, cargo clippy
--locked --all-targets -- -D warnings, and cargo fmt --all --check.
The bin/oreslang and bin/oreslang-test shell shims only locate Cargo; neither
invokes Python. To avoid compiling on each launch, install with
cargo install --path . --locked.

## Supported commands

    oreslang test
    oreslang test --fuzz --seed 42 --cases 2000 --timeout 5
    oreslang test --race --trace tests/traces/ordered.jsonl
    oreslang test --audit --fail-on high --audit-format json
    oreslang test --security --audit-file src/server.ores
    oreslang test --anti-patterns --fail-on low
    oreslang test --effects --effects-strict --file src/server.ores

**Native Oreslang tests:** discovers tests/**/test_*.ores and
tests/**/*_test.ores, or [native].files in oreslang-test.toml. The real
compiler is selected by ORESLANG_BIN (default oreslang-core). A test only
passes if the child exits successfully and emits a consistent ORES_TEST
PASS/FAIL/SKIP + SUMMARY machine receipt. The CLI uses a bounded host-owned
process runner, an allowlisted environment, process group isolation on
Unix, timeout enforcement, and limits output captures to 4 MB per stream.

**Fuzzing:** [fuzz].command must be a TOML array of a real executable and
argv. Corpus default tests/corpus; max_bytes defaults to 256 (range 1..65536).
The Rust engine uses deterministic SplitMix64 byte mutation and deduplicated
seed cases. It replays a failing case twice before minimization, then applies
a bounded reduction while preserving the exit code. Reproduced failures are
stored under .oreslang-test/failures. A timeout, crash without a numeric
exit code or incomplete run is inconclusive rather than a clean pass.
This is black-box mutation fuzzing, not coverage-guided source fuzzing.
Guest processes receive a minimal environment; unrelated CI secrets are not
forwarded by default.

Example project manifest:

    [native]
    files = ["tests/test_suite.ores"]

    [fuzz]
    command = ["/path/to/real/oreslang", "tests/fuzz_stdin.ores"]
    corpus = "tests/corpus"
    max_bytes = 256

**Offline race analysis:** --race --trace NAME analyzes an explicitly
project-relative ORES_RACE_V1 JSONL file in Rust. It validates the JSONL
structure, strict event fields, task lifecycle, fork/finish/join ordering,
mutex ownership, single-use message IDs, and memory-access happens-before
relations using vector clocks. It reports observed conflicts and rejects
incomplete/ambiguous traces. A clean observed trace is **never** a
runtime race-freedom certificate.

**Unsupported/pending:** --race without --trace returns exit 2 because
trusted runtime instrumentation, source/build attestation, shared-memory
coverage accounting and an authenticated host-only event channel are not
yet implemented. --race --logical / --model also returns exit 2 until the
bounded reference-model engine is migrated to Rust. The available
rust/race_evidence.rs only checks a *potential* receipt's shape; it is not
a trusted-runtime attestation or sufficient to enable a race-free PASS.
See docs/RACE_EVIDENCE_V1.md.

**Source audits:** --security, --anti-patterns and --audit run advisory
Rust-only lexical/heuristic checks for hard-coded credentials, MD5/SHA-1,
plaintext non-loopback HTTP URLs, shell invocation, empty catch/recover and
simple busy loops. The scanner masks string and comment bodies for code
matching, redacts credential contents, bounds the workload and rejects
incomplete inputs. It does not provide typechecking, taint tracking or a
vulnerability-free certification. Select [--fail-on
none|low|medium|high|critical] and [--audit-format text|json].
--audit-file is repeatable; unknown or mixed options are rejected.
See docs/security-audit-rust.md.

**Effects:** --effects and --effects-strict execute an advisory Rust
exception-effect source scan; not full compiler type/effect analysis.
See docs/exception-effects.md.

## Exit conventions

- 0: selected tests or observations completed without detected failures.
- 1: executed test failure, reproduced fuzz defect, observed race, or
  advisory finding meeting the selected severity threshold.
- 2: invalid input, timeout/inconclusive fuzz target, unsupported feature,
  incomplete evidence, partial analysis, missing backend or resource budget.

This is an in-progress source branch. Do not merge until exact-head
Cargo builds/tests and native source integration tests have executed on
an authorized runner with inspectable logs. GitHub Actions jobs with zero
executed steps provide no compiler or regression-test evidence.

No new Oreslang test CLI implementation should be written in Python.
