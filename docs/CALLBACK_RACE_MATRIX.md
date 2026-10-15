# Callback and actor race regression matrix

This is the intended Java/GraalVM + LLVM integration suite for the test
runner. **No live runtime instrumentation is claimed by this document.**

| ID | Scenario | Safety assertion |
| --- | --- | --- |
| CB-01 | Sync map/filter-style callback | Inline, no scheduler admission |
| CB-02 | Sync event emitter listener | Inline, caller's stack ordering preserved |
| CB-03 | Ready Future registers async callback | Callback guest body never invoked on registration stack |
| CB-04 | Pending Future completes on foreign carrier | Producer only enqueues; actor-owned execution lease required |
| CB-05 | Implicit CPU preemption | Carrier may yield; unrelated same-actor callback cannot interleave with synchronous continuation |
| CB-06 | Explicit await/select/readch | Actor interleaving only if actor logical concurrency allows |
| CB-07 | Borrowed local captured into deferred callback | Compile error |
| CB-08 | Mutable actor state loan crosses await | Compile error |
| CB-09 | Move-only capture reused after transfer | Compile error |
| CB-10 | Cancellation races callback wakeup | At most one committed cancellation/normal terminal result |
| CB-11 | Actor retirement and stale event | Old incarnation callback cannot run |
| CB-12 | Reentrant read/await/write | Optimistic revision check rejects stale state |
| CB-13 | Parent CONTROL and DATA handlers | Same physical actor execution lease |
| CB-14 | Concurrent actor mailboxes | No two physical carriers executing the same actor |
| CB-15 | Deferred callback attempts direct/aliased call | Rejected until verified scheduler lowering |

For `oreslang test --race`, the backend must instrument actual memory access
events and logical invariant checks. A no-op backend or empty test suite must
**never** report clean. Assertions are backend-owned, with unforgeable actor
incarnation, continuation, lease, and generation identities. A guest printing a
text line cannot certify an internal event.

For `oreslang test --fuzz`, vary message order, cancellation timing,
ready/pending Future publication, channel buffer fullness, select fairness,
reduction budget, and callback registration order. Each failing seed should
produce a replayable trace and the exact compiled program/source Git tree.

Current CLI fuzzing changes only stdin bytes and gives the guest the seed/case
in environment variables. Deterministic scheduler perturbation, trace
minimization and memory-access recording are **backend milestones**, not
features delivered by the initial CLI.

## Acceptance gate

One compiled three-actor Oreslang program must exchange typed data and
return typed results with `self.forward()`/`self.backward()`, under at least
two different deterministic scheduler schedules, with no physical overlap.
Every run must include the native `ORES_TEST` summary and instrumented
`ORES_RACE` observations. Run the same program and properties on
Java/GraalVM and native LLVM without handwritten host callbacks. All
tests should run against exact Git tree SHA snapshots.
