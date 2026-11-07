# AttoLang Test CLI (Rust)

All public AttoLang test CLI entrypoints and their implemented engines are
native Rust 1.85+. There is **no Python launcher or Python subprocess**.
Use `atto` / `atto-test` (canonical) or the preserved `oreslang` / `oreslang-test` aliases:

- oreslang: delegates non-test commands to the real Oreslang executable
  (ORESLANG_BIN), routes oreslang test to this Rust implementation.
- oreslang-test: runs test subcommands directly.

Build and test with cargo build --locked, cargo test --locked, cargo clippy
--locked --all-targets -- -D warnings, and cargo fmt --all --check.
The bin/oreslang and bin/oreslang-test shell shims only locate Cargo; neither
invokes Python. To avoid compiling on each launch, install with
cargo install --path . --locked.

## Supported commands

    atto test
    atto test --fuzz --seed 42 --cases 2000 --timeout 5
    atto test --race --trace tests/traces/ordered.jsonl
    atto test --audit --fail-on high --audit-format json
    atto test --security --audit-file src/server.ores
    atto test --anti-patterns --fail-on low
    atto test --effects --effects-strict --file src/server.ores

**Native Oreslang tests:** discovers tests/**/test_*.ores and
tests/**/*_test.ores, or [native].files in oreslang-test.toml.
Discovery matches the `tests` path component using the host platform's
separator rules, including Windows backslashes. Similarly named directories
such as `tests-other` are excluded. The real
compiler is selected by ORESLANG_BIN (default oreslang-core). A test only
passes if the child exits successfully and emits a consistent ORES_TEST
PASS/FAIL/SKIP + SUMMARY machine receipt. These are **structural
checks of guest output**, not authenticated host-only events: a hostile
executable can print a plausible receipt. A green native receipt does not
establish secure provenance or runtime race freedom. The CLI uses a bounded
host-owned process runner, an allowlisted environment, process-group
isolation on Unix, timeout enforcement, and a 4 MB capture limit per stream.

A native receipt must include at least one executed PASS or FAIL case;
all-skipped or all-filtered suites cannot pass. Case IDs must be nonblank
and unique within each invocation, including across PASS, FAIL and SKIP.
Optional message fields do not change case identity. Invalid receipts make
the native suite fail with exit 1.

**Experimental async/actor receipt validation:** set `[native].receipt = "lifecycle-v2"`
for strict `ORES_TEST_V2` structural lifecycle verification of callbacks, tasks,
actors, and awaits. A case cannot report PASS with outstanding OPEN handles,
failed/cancelled CLOSE records, duplicate completion or mismatched RUN_END.
The default remains `v1` and mixed protocols are rejected. This does **not**
implement the guest TestKit or authenticate guest lifecycle events: runtime
provenance and real compiler execution remain release blockers. See
[Native lifecycle v2](docs/NATIVE_LIFECYCLE_V2.md).

**Fuzzing:** [fuzz].command must be a TOML array of a real executable and
argv. Corpus default tests/corpus; max_bytes defaults to 256 (range 1..65536).
The Rust engine uses deterministic SplitMix64 byte mutation and deduplicated
seed cases. It replays a failing case twice before minimization, then applies
a bounded reduction while preserving the exit code. Reproduced failures are
stored under .oreslang-test/failures. On Unix a crash signal (SIGSEGV,
SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGTRAP) is a reproducible defect and is
minimized like a nonzero exit. A timeout, runaway output beyond the 4 MB
capture budget, a non-crash signal (SIGKILL/SIGTERM from an OOM killer or CI
cancellation) or an incomplete run is inconclusive (exit 2) rather than a
clean pass. During minimization such an outcome simply does not reproduce
the confirmed defect; it cannot erase it. Targets may echo arbitrary bytes
to stdout or stderr: captures are decoded lossily for fuzzing. A passing run
reports `seeds=N mutated=M` so a run that executed no mutations is visible.
This is black-box mutation fuzzing, not coverage-guided source fuzzing.
For native fuzz adapters that reserve nonzero process exits for
**inconclusive infrastructure conditions**, optionally declare
`[fuzz].inconclusive_exits = [2]`. A configured status (1..255; 1..16
distinct entries) cannot become a reported fuzz defect or a saved
reproducer. This is explicit per-project policy; normal nonzero exits
remain defects by default. Sanitizer findings retain priority over
configured exit codes, so an ASan/UBSan/TSan error is still a failure
even when the child exits 2. An inconclusive status observed for the initial
case or mandatory replay makes the fuzz run inconclusive (exit 2). During
minimization, however, an inconclusive reduced input simply does not reproduce
the already-confirmed defect; it cannot erase that defect or turn it green.
Invalid or duplicate policy codes fail before executing the target. The LLVM
native stdin adapter reserves exit 2 for input budget/IO failure and exit 77
for a reproduced guest-versus-oracle mismatch.


Guest processes receive a minimal environment; unrelated CI secrets are not
forwarded by default.

The retained mutation pool is capped at 4096 cases and 16 MiB of case
payload, including initial seeds and security-profile inputs. When the pool
is full, fuzzing continues for the requested case count without retaining
additional cases. This bounds retained payload, not total process memory;
case buffers, allocator overhead and guest memory are separate. High-budget
runs may generate different inputs than earlier versions after retention
stops, so reproductions must record the CLI revision as well as the seed.

Corpus ingestion limits each opened stream to max_bytes plus one overflow
sentinel byte, rejecting oversized reads and accounting aggregate corpus
bytes from the data actually read. Preflight sizes alone are insufficient
when files can grow. This bounds read allocation; descriptor-relative
no-follow protection against concurrent path replacement remains pending.

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
relations using vector clocks. Prior accesses are compared by epoch
(the accessing task's own clock component), which gives the same verdicts as
full vector-clock comparison in O(1) per prior access, so a worst-case
in-budget trace (256 tasks, 100k events) is analyzed in about a second
rather than nearly a minute. It reports observed conflicts and rejects
incomplete/ambiguous traces. A clean observed trace is **never** a
runtime race-freedom certificate.

**Unsupported/pending:** --race without --trace or --logical --model returns exit 2 because
trusted runtime instrumentation, source/build attestation, shared-memory
coverage accounting and an authenticated host-only event channel are not
yet implemented. The Rust-native --race --logical --model FILE.json
explores a bounded deterministic **host reference model** (read/write/
atomic_add turns) but is never guest runtime scheduler evidence; incomplete
exploration returns exit 2. The available
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

## Rust logical schedule models

    atto test --race --logical --model tests/models/atomic-update.json
    atto test --race --logical --model tests/models/lost-update.json
    atto test --race --logical --model tests/models/atomic-update.json --max-schedules 1

This evaluates a **host-provided finite actor-turn model**, not compiled
Oreslang source. Model JSON declares `initial` and `expected` signed 64-bit
state keys and 2–16 actors, each with ordered, nonempty `turns` made of
`read`, `write`, and `atomic_add`. `read` stores a local name and
`write` can use that local plus an integer offset. One actor turn executes
atomically; all turn interleavings are examined until a counterexample or
limit is reached. The engine strictly rejects duplicate JSON keys, unknown
operations, arithmetic overflow, malformed strings, and over-budget models.
Maximums include 64 total actor turns, 4096 operations, 2 MiB JSON,
one million completed schedules, and ten million search visits.

Exit 0 is only a complete clean result for the **bounded reference model**.
Exit 1 means a counterexample schedule was found. Exit 2 means incomplete,
unsupported, malformed, or truncated exploration. Neither a clean nor an
unsuccessful model run is evidence that the guest runtime executed the
model's schedule or that its instrumentation covered all memory accesses.

## Continued Rust parity hardening

- `--fuzz --fuzz-profile security` adds deterministic adversarial byte inputs
  (traversal, encoded NUL, invalid UTF-8, injection-looking payloads and
  oversize shapes), constrained by the configured per-case maximum. A test
  target must demonstrate a reproducible violated property; the input's
  appearance alone is not a vulnerability finding. The `basic` profile is
  the default. On Linux, effects and audit source discovery,
  source/config reads, advisory audit inputs, offline race/deadlock traces,
  logical models, corpus enumeration and reads, and fuzz-reproducer creation
  use root-anchored directory descriptors with `O_NOFOLLOW`;
  input reads are size-bounded on the opened file, and `/proc/self/fd`
  is required for secure enumeration. A single fuzz invocation additionally
  retains one project-root FD across corpus loading and failure-artifact
  creation. It opens corpus files relative to the same pinned directory,
  checks device/inode across enumeration and open, and promptly closes
  input descriptors. Visible-root identity is checked before and after
  each fuzz guest execution and before reporting artifact paths.
  These are conservative detection checks, **not** atomic snapshot isolation
  or protection against concurrent writes to already-open regular files.
  The non-Linux fallback still uses pathname-based preflight checks.
  On Unix, the launcher now also kills surviving members of the guest's
  isolated process group after normal parent exit (not only on timeout).
  This reduces late-writer leaks but does not contain descendants that
  escape via setsid(), and Windows Job Object containment remains pending.
  Full descendant containment, OS-level resource isolation and
  cryptographic authenticity of guest test receipts remain open gates.
- `--deadlock --trace file.jsonl` analyzes observed lock ordering and
  outstanding wait cycles in Rust. It is offline only and does not certify
  liveness. `--race --deadlock --trace` combines the two findings on the
  same trace, but a missing memory access event makes the race half
  inconclusive rather than claiming a complete result.
- The `oreslang_test::reactive::analyze` Rust host library replaces the
  prior Python reactive-composition reference model with typed Subscribe,
  Request, Next, Complete, Cancel, Error and Dispose events. It is not a
  CLI runtime instrumentation mode. See
  `docs/REACTIVE_COMPOSITION_TRACE_V1.md`.
- This branch is reconciled against the latest `main`, retains the newer
  integration contract, native P0 verifier and reactive documentation, and
  has no `.py` files. The older Python deadlock, reactive and model-checker
  scripts are removed, not silently delegated to.
- Runtime-controlled schedule replay and GraalVM checkpoint-only trace
  adapters are still unsupported and may not return an evidence-free clean
  verdict. The Rust host-only model explorer is not runtime instrumentation.

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


## AttoLang migration and native sanitizers

Use `atto test --fuzz` for bounded black-box input mutation and `atto test --race
--trace path.jsonl` for explicitly offline race analysis. The live `atto test
--race` mode still returns inconclusive (2) without authenticated runtime
instrumentation. Canonical source files are `.atto` and the project manifest
is `atto-test.toml`; legacy `.ores` and `oreslang-test.toml` are accepted.
Two manifests in the same project root are rejected, not silently mixed.

Fuzz now retains bounded child stderr/stdout and treats observed ASan,
LeakSanitizer, UBSan and TSan diagnostic text as a reproducible failure, even
when a recoverable sanitizer exits 0. UBSan lines must have the sanitizer's
`file:line:col: runtime error:` (or `<unknown>: runtime error:`) shape; a bare
`runtime error:` such as a Go panic is not attributed to UBSan. An unsupported TSan runtime is
inconclusive (2). These reports are **observations**, not evidence that the
guest executable was compiled with sanitizers, that all code was instrumented,
or that AttoLang actors are data-race free. Exact-head sanitizer builds and
native executed steps remain required.
