# AttoLang trusted race-evidence v1 — admission contract (proposed)

Status: **not implemented end-to-end**. This is a cross-backend design gate,
not a claim that `atto test --race` currently certifies race freedom.
The Rust CLI must use exit 2 (inconclusive) until every relevant requirement
below is verified by a trusted host implementation.

## Trust boundary

Guest stdout/stderr, a guest-writable file, a user-supplied JSONL trace,
and an environment variable visible to guest code are **not attestation**.
They may be analyzed offline, but may not authorize a race-free verdict.
A runtime that is itself untrusted cannot attest its own correctness solely
by emitting this format.

The trusted test runner must authenticate the exact compiler/runtime build
and source revision, launch an admitted instrumentation profile, and receive
events and a terminal receipt over a host-owned channel unavailable to guest
code (for example, an inherited dedicated OS pipe whose descriptor remains
outside the guest's accessible descriptor table). Event framing, monotonic
sequence numbering, and a fresh runner-held challenge bind the receipt to
the invocation. These are necessary conditions, not substitutes for a
trusted runtime or independently executable CI provenance.

## Identity and event envelope

Every complete event stream carries these trusted host-derived dimensions:

- Protocol version and fresh run identity; backend kind and exact runtime
  build identity; compiler/source snapshot and instrumentation profile.
- Source-level task/actor execution identity, actor *incarnation*, isolated
  memory-scope identity, and logical scheduling turn/segment.
- For memory accesses: allocation identity and generation (not a reused raw
  pointer), offset, positive byte width, and read/write/allocate/free action.
- For scheduling: task spawn/finish/join, mailbox send/receive, lock
  acquire/release, await/resume/cancel, and shared-memory publish/revoke.
  Each ordering edge must be tied to the participating execution contexts.
- Consecutive frame sequence numbers and a terminal recorder summary that
  ties emitted, observed, and dropped counts to the same run.

No guest values, secrets, or native pointer addresses are necessary.
Java's actor-relative offsets are only meaningful inside its host-process-
local recorder scope. LLVM's heap domain/actor-id/incarnation/slot generation
are only meaningful inside the trusted run identity. Neither identity may
be conflated across processes, isolates, reload generations, or backends.

## Coverage admission and mandatory failure conditions

Each backend declares and enforces a fail-closed coverage manifest covering
the *actual compiled program's* access paths and synchronization mechanisms:
ordinary object fields, actor state, arrays/collections, text, native
allocations, async/continuation frames, shared regions, task scheduling,
locks, mailbox channels and ownership transitions. Runtime or compiler
paths not instrumented must be rejected for a certified profile. Guest FFI
remains prohibited; stdlib/core native pathways still require accounting.

The runner must return exit 2 for any of the following:

- Missing or unauthenticated provenance, absent terminal receipt, reused run
  identity, invalid counters, duplicated/missing/out-of-order frames.
- Recorder disabled, buffer exhaustion (`dropped > 0`), unreadable buffers,
  unsupported allocation or synchronization surface, or uninstrumented path.
- Unjoined/incomplete tasks, dangling continuation state, unobserved source
  imports, unverified hot-reload generation, or incomplete scheduling edges.
- No meaningful coverage despite no observed conflicts; cancellation,
  timeout, runner crash, or limits that truncate exploration.

Exit 1 represents a proven observed conflict, execution failure, or
violated invariant. Exit 0 may represent a clean result **only for the
explicitly admitted coverage scope**, never mathematical race freedom for
all possible executions. An offline synthetic trace may report that it
contains no conflicting observed events, but must be labeled **offline
analysis**, not a trusted-run PASS.

## Backend-to-CLI staging

1. LLVM `ActorOwnedI64Heap` and GraalVM `ActorNativeArena` report only
   bounded *observed memory events* today; these are insufficient.
2. Add trusted scheduler happens-before edges and coverage accounting
   throughout the compiler, stdlib, and runtime. Keep collector buffers
   inaccessible to guest code. Track dropped counts as sticky failure.
3. Implement and fuzz a bounded, strict **Rust** receipt parser/validator.
   Reject duplicate keys, unknown versions, integer overflow, missing
   required fields, inconsistent counters and over-budget frame counts.
4. Wire only host-verified receipts into the Rust CLI's runtime `--race`
   admission. Keep `--trace` as clearly labeled offline analysis.
5. Run positive and adversarial fixtures across LLVM and GraalVM first,
   then WASM, JavaScript and .NET as they implement verified emitters.
   Test runner jobs must execute on exact-head authorized source and
   produce inspectable compiler, test and sanitizer logs.

No Python component should be introduced in the AttoLang test CLI.

## Sanitizer observation admission (ASan, UBSan, TSan)

The new `atto test --fuzz` runner may classify bounded stderr containing
ASan, LeakSanitizer, UBSan or TSan diagnostics as **observed failures**.
Sanitizer text is guest-controlled and is not a provenance certificate:
a malicious or synthetic guest can print the same strings. It may cause
a conservative failure, never authorize a clean runtime race result.

A native sanitizer CI lane must establish all of the following separately:

1. Exact compiler source head and Git tree, including compiler version,
   instrumentation flags at compile **and** link, target triple and runtime
   dependency identity; record zero dropped/omitted steps in hosted logs.
2. A source-free *negative detector control* deliberately causing a native
   out-of-bounds access (ASan), signed overflow (UBSan), or multithreaded data
   race (TSan), with expected diagnostic, nonzero exit, and no TSan startup
   failure. A mutation build without sanitizer instrumentation must **fail
   detector admission**, not pass silently.
3. A separately instrumented **real native actor/runtime workload** proving
   that the tested source files and linked symbols are part of the executable.
   ASan+UBSan and TSan must run in separate executables; an ASan pass cannot
   stand in for a race detector. Retain repeated runs under bounded timeouts.
4. A clean optimized non-instrumented execution lane; sanitizer-only
   successes do not establish production behavior.

A TSan `FATAL` loader/startup failure, unsupported target, missing
instrumentation, missing expected control finding, truncated report,
unknown guest exit/signal, absent runnable compiler, or zero-step workflow
must classify as **inconclusive**, not as absence of data races.

TSan only covers memory operations it can observe; it does not certify
actor mailbox ordering, scheduler logical races, cancellation, message
linearizability, deadlock freedom, or ownership boundaries. A compiler-backed
`.atto` guest and source-free host negative control remain distinct.

Backend scoping: LLVM and native Cranelift/Rust components can potentially
run native sanitizer builds. JVM/Graal managed heaps, CLR managed code,
and Wasm linear memory are **not** automatically instrumented by these
native host compiler flags. Their runtime/FFI/native ABI components may
be checked separately; guest coverage requires backend-specific evidence.

`atto test --race` without a trusted admitted runtime event channel
continues to return exit 2. Offline `--race --trace` is never promoted to a
live-runtime race certificate merely because TSan did not report a problem.
