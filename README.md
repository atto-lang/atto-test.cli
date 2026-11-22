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

## AttoLang native .atto tests (candidate)

From a checkout with `bin/` on `PATH`, run `atto test --root .` or invoke
`atto-test --root .` directly. Both are thin executable launchers for the
same existing Rust test binary; the legacy `oreslang test` entrypoint remains
available for compatibility. The Rust binary must be built first. Set
`ATTO_BIN=/absolute/path/to/your/atto-compiler` for the native test compiler;
`ORESLANG_BIN` remains the compatibility fallback. Neither environment
variable is a trust attestation: the test execution environment must still
admit and pin the intended compiler independently.

Automatic native test discovery now selects canonical **.atto** source files
under tests/ with names test_*.atto or *_test.atto. A project may explicitly
list files using [native].files in oreslang-test.toml, including a legacy .ores
file during migration. Do not automatically select a legacy .ores twin merely
because a .atto file is available. The configured ORESLANG_BIN or default
compiler command must truly compile and execute each selected source; an
unrecognized extension or unavailable backend must fail, not silently skip.

Example:

```toml
[native]
files = ["tests/test_math.atto", "tests/test_collections.atto"]
```

A hosted compiler (for example the Java/GraalVM backend) can use an
**explicit argv template** in a trusted project-root `atto-test.toml`.
Exactly one `{source}` placeholder is required, and the runner replaces it
inside one argument with the compiler-admitted absolute `.atto` path.
No shell splitting, environment interpolation, or implicit `sh -c` occurs.
Use `atto-test.toml` for new projects; `oreslang-test.toml` is the
legacy fallback. If both are present the runner fails closed.

```toml
[native]
files = ["examples/native-testing-regressions-40.atto"]
command = ["mvn", "-q", "-B", "-ntp", "-DskipTests", "compile", "exec:java", "-Dexec.args={source}"]
```

This example is intended for a Java compiler checkout containing the
Maven entry point. Its actual success requires JDK 25, Maven, the matching
Java compiler branch, and a compiled guest run. The source cannot claim
support merely because the manifest can construct the command.
Project-controlled `[native].command` **executes arbitrary host code**. The CLI
refuses it by default; pass `--allow-project-command` only after reviewing
and trusting the checkout and its compiler command. For the Java adapter above,
run `atto test --root . --allow-project-command`. The opt-in is not a sandbox:
never run an untrusted checkout with ambient secrets or filesystem/network
privileges. The same warning applies to a configured `ATTO_BIN` executable.

The native runner checks one final ORES_TEST|SUMMARY record, observed
PASS/FAIL/SKIP counts, positive executed coverage, unique case identities,
canonical escaped fields and no extra output after the summary. Duplicates,
truncated output, nonzero process status, malformed records, false aggregate
counts, timeouts and empty/all-skipped/all-filtered suites fail closed.
This is **strict receipt shape validation**, not cryptographic authentication:
a compromised guest can print forged stdout. CI must independently pin its
exact source tree, compiler binary/runtime, trusted runner, expected test
inventory and nonzero executed steps. The stdlib's summary_is_valid checks
only local counter consistency and cannot authenticate provenance.

Canonical .atto syntax-only and type-check selection is also supported, but
the command remains inconclusive (exit 2) unless a pinned compiler emits
the exact source-bound no-codegen proof required below. Native Rust unit
tests for receipt validation are not AttoLang guest execution evidence.

## Syntax-only and type checks

The Rust CLI **does not invent an Oreslang grammar**. It invokes the canonical language frontend configured under `[check].command`, adding `--syntax-only <file>` or `--check-types <file>`. The backend must return success *and* emit a source-bound no-codegen receipt:

```text
ORES_CHECK|PASS|sha256=<64 lowercase hex digits>|phase=syntax-only
ORES_CHECK|PASS|sha256=<64 lowercase hex digits>|phase=types
```

The digest is the SHA-256 of the exact source bytes submitted. The host running strict checks must also provide an **independent compiler executable pin** in `ORESLANG_TRUSTED_CHECK_COMPILER_SHA256` (64-character SHA-256). The `[check].command` must consist of **exactly one absolute path** to the actual compiler executable, not a shell, wrapper, relative PATH lookup or additional arguments. The Rust CLI hashes the compiler before and after running it and rejects symlinks, unexpected replacements, and unpinned/mismatched binaries. The SHA must be supplied by an authorized CI/release process independent of the project being checked; a hash copied from the untrusted project is not proof of trust. This does not itself prove a trusted compiler actually performed a no-codegen pass; backend receipt compliance still requires independent conformance tests. A missing/mismatched receipt, missing compiler, empty source selection or inaccessible file is **inconclusive/error (exit 2)**, never success. A backend-reported syntax/type error is **exit 1**. The frontend must actually implement the noncompiling flags and receipt contract; simply configuring an executable is not proof that compilation was skipped.

Example configuration, once the chosen Oreslang compiler supports the above contract:

```toml
[check]
command = ["/absolute/path/to/pinned-oreslang-compiler"]
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

`--fuzz` mutates and extends bounded seed corpora reproducibly with `--seed`, executes inputs in bounded subprocesses, classifies failure by exit code or timeout, replays failures twice, shrinks reproducible failures, and saves SHA-256-addressed reproductions under `.oreslang-test/failures/`. This is **mutation fuzzing**, not coverage-guided fuzzing; empty/unsupported corpus instrumentation does not establish coverage.

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

### Untrusted test commands are not OS-sandboxed

The Rust CLI launches configured commands as ordinary host processes. Its
`env_clear`, process-group cleanup, output limits, and path checks do **not**
prevent a guest command from reading files accessible to the current user,
accessing the network, starting detached processes, or modifying the checkout.
`[race].command`, `[fuzz].command`, `[native]` compiler selection and other
project-controlled commands must therefore be treated as **executable code**,
not inert test data. Do not execute unreviewed third-party project manifests
on a privileged CI runner or anywhere with secrets, private credentials,
writable deployment state, or ambient cloud service permissions. Use a fresh,
independently configured operating-system/container/VM security boundary
when testing untrusted projects; setting `HOME` or clearing environment
variables alone is not a filesystem or network isolation mechanism.

A test destination in another GitHub organization does not become authorized
merely because it has funded Actions minutes or receives the Git tree without
a cross-organization checkout token. Private-source mirroring requires
independent policy approval of the exact destination repository **and numeric
repository ID**, current protected-ref checks, a pinned source tree,
short-lived private refs, and source/destination tree verification. Without
that authorization, run tests in the source organization or report **not
executed**; do not manufacture a passing CI attestation.

The runner applies per-stream output caps, timeouts and process-group termination, rejects symlinked project-relative artifacts, bounds model/trace/corpus sizes, and does not invoke a shell internally. Unit and fixture tests run with `cargo test --all-targets`. `scripts/ci-verify-concurrency-p0.sh` requires an exact Git source tree SHA; previous Python CI checks have been replaced with Rust tests.

Host-side analyzers, reference models and receipt verification must not be described as complete LLVM or GraalVM runtime instrumentation. Full guest memory hooks, controlled scheduler execution, native-image parity and cross-backend conformance tests remain integration milestones.

## Engineering policy: Rust-only host tooling

Python is prohibited in this repository and across the `ores-truffle-oreslang` organization for host tooling, scripts, tests, generators, CI helpers, analyzers, and automation. Do not add `.py`, `.pyi`, `.ipynb`, Python dependency manifests, `python`/`python3` execution, `pip`, `pytest`, `poetry`, `uv`, or `actions/setup-python`. If equivalent functionality exists in Python elsewhere in the organization, migrate it to Rust while preserving semantics, security properties, fixtures, and test coverage. Rust replacements must be covered by `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` as appropriate.
