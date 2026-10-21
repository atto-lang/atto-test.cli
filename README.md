# Oreslang Test CLI (Rust)

The Oreslang test command runner and host-side analyzers are written in **Rust**, distributed as a native executable. No Python interpreter is needed for building or running this CLI.

**Status:** Rust migration branch. Runtime race instrumentation and compiler syntax-only support are separate integration requirements; the CLI refuses unsupported clean verdicts.

## Build

```sh
cargo build --release
cargo test --all-targets
./target/release/oreslang-test --help
```

Put `bin/` on `PATH` to use the launcher, which delegates `oreslang test` to the Rust binary; ordinary `oreslang` commands delegate to `ORESLANG_BIN` (or `oreslang-core`). Or invoke `target/release/oreslang-test` directly.

## CLI

```sh
oreslang test --check src/main.ores
oreslang test --check .
oreslang test --check-types .
oreslang test --fuzz --seed 87 --cases 2000 --timeout 5
oreslang test --race --trace tests/traces/ordered.jsonl
oreslang test --race --logical --model tests/models/atomic-update.json
oreslang test --deadlock --trace tests/traces/lock-orders.jsonl
oreslang test --model-check --model tests/models/lost-update.json
oreslang test --schedule-fuzz --seed 42 --iterations 20
oreslang test --replay evidence.trace
oreslang test
```

`oreslang-test` accepts exactly the same test arguments without the `oreslang test` prefix. `--root` selects the project root (default `.`).

## Syntax-only and type checks

The Rust CLI **does not invent an Oreslang grammar**. It invokes the canonical language frontend configured under `[check].command`, adding `--syntax-only <file>` or `--check-types <file>`. The backend must return success *and* emit a source-bound no-codegen receipt:

```text
ORES_CHECK|PASS|sha256=<64 lowercase hex digits>|phase=syntax-only
ORES_CHECK|PASS|sha256=<64 lowercase hex digits>|phase=types
```

The digest is the SHA-256 of the exact source bytes submitted. A missing/mismatched receipt, missing compiler, empty source selection or inaccessible file is **inconclusive/error (exit 2)**, never success. A backend-reported syntax/type error is **exit 1**. The frontend must actually implement the noncompiling flags and receipt contract; simply configuring an executable is not proof that compilation was skipped.

Example configuration, once the chosen Oreslang compiler supports the above contract:

```toml
[check]
command = ["/path/to/oreslang-compiler", "check"]
```

This adapter deliberately does **not** substitute a second parser for Java/GraalVM, LLVM, WASM, JS or .NET. Canonical frontend conformance is pending those integrations.

## Exceptional-effect advisory checking

The separate Rust `--effects` mode incorporates the existing Rust source analyzer from exceptional-effects PR #6. It reports direct `throw`, `raise`, and `panic` syntax and annotation mismatches without claiming compiler-grade transitive effects or runtime correctness.

```sh
oreslang test --effects --file src/main.ores
oreslang test --effects --effects-strict --file src/main.ores
```

Use `[effects].files = ["src/main.ores"]` or automatic source discovery. Advisory warnings exit `0` unless `--effects-strict` is used, which exits `1` for warnings. Inconclusive parsing or zero inspected callable bodies exits `2`. See `docs/exception-effects.md`.

## Fuzzing

```toml
[fuzz]
command = ["/path/to/oreslang", "tests/fuzz_stdin.ores"]
corpus = "tests/corpus/my-property"
max_bytes = 256
```

`--fuzz` mutates and extends bounded seed corpora reproducibly with `--seed`, executes inputs in isolated subprocesses, classifies failure by exit code or timeout, replays failures twice, shrinks reproducible failures, and saves SHA-256-addressed reproductions under `.oreslang-test/failures/`. This is **mutation fuzzing**, not coverage-guided fuzzing; empty/unsupported corpus instrumentation does not establish coverage.

## Race analysis

`--race --trace` ingests ORES_RACE_V1 JSONL with matching `begin`/`end` nonces and strict event counts. It tracks happens-before vector clocks for task, fork, finish, join, reentrant mutex lock/unlock, send/recv and R/W memory accesses. A fresh capture from `[race].command` must write to `ORESLANG_RACE_TRACE` and include `ORESLANG_RACE_RUN_ID` in both markers.

```toml
[race]
command = ["/path/to/instrumented-oreslang", "tests/race_suite.ores"]
```

The race checker preserves per-task access histories and reports observed unsynchronized conflicts. It **cannot prove full race freedom** without complete compiler/runtime memory instrumentation. Missing or malformed traces are errors, not passes.

## Deadlocks, logical models and schedules

`--deadlock` analyzes bounded observed wait-for cycles and potential lock-order inversions from observed lock events, including Graal concurrency checkpoint receipts. A pure checkpoint stream without wait-graph evidence is inconclusive.

`--model-check` and `--race --logical` enumerate bounded declarative actor-turn models from JSON fixtures; they are not compiled guest model checking. Hitting exploration budgets without a counterexample is **exit 2**.

`--schedule-fuzz`/`--replay` delegate to `[schedule].command` and require real per-case ORES_TEST and ORES_CONCURRENCY receipts. Replay input must be the workspace-bound V3 trace, and newly generated output traces must agree with the runtime's event count. Fake summaries, zero coverage, bad hashes and stale traces must never produce a pass.

```toml
[logical]
models = ["tests/models/atomic-update.json"]
[schedule]
command = ["/path/to/oreslang-compiler", "test", "tests/concurrency.ores"]
```

## Exit codes

* **0:** Supported checks passed for the executed inputs/events only.
* **1:** Confirmed test failure, detected observed race/cycle, model violation or reproducible fuzz counterexample.
* **2:** Invalid arguments, unsupported tooling, malformed/stale traces, flaky fuzz case, inconclusive exploration or missing backend instrumentation.

## Security and CI

The runner applies per-stream output caps, timeouts and process-group termination, rejects symlinked project-relative artifacts, bounds model/trace/corpus sizes, and does not invoke a shell internally. Unit and fixture tests run with `cargo test --all-targets`. `scripts/ci-verify-concurrency-p0.sh` requires an exact Git source tree SHA; previous Python CI checks have been replaced with Rust tests.

Host-side analyzers, reference models and receipt verification must not be described as complete LLVM or GraalVM runtime instrumentation. Full guest memory hooks, controlled scheduler execution, native-image parity and cross-backend conformance tests remain integration milestones.

## Engineering policy: Rust-only host tooling

Python is prohibited in this repository and across the `ores-truffle-oreslang` organization for host tooling, scripts, tests, generators, CI helpers, analyzers, and automation. Do not add `.py`, `.pyi`, `.ipynb`, Python dependency manifests, `python`/`python3` execution, `pip`, `pytest`, `poetry`, `uv`, or `actions/setup-python`. If equivalent functionality exists in Python elsewhere in the organization, migrate it to Rust while preserving semantics, security properties, fixtures, and test coverage. Rust replacements must be covered by `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` as appropriate.
