# Native Rx / actor harness audit — 2026-10-31

This branch strengthens the Rust **host-side contract checks**; it is not a
replacement for the canonical Oreslang `ores.std/testing` TestSuite.

## Implemented

- `reactive::analyze_complete`: rejects zero subscriptions, outstanding
  subscriptions, or incomplete terminal/disposal traces. The existing
  `reactive::analyze` intentionally retains partial-trace introspection.
- `reactive_async::analyze`: bounded typed lifecycle model for actor spawn/
  stop, callback registration/delivery/unregistration, Task spawn, completion,
  cancellation and **physical retirement**, and await suspend/ready/resume.
  It rejects premature actor shutdown, missed or duplicate callbacks cleanup,
  wake-token ABA, resume without readiness, resume after cancellation,
  duplicate notifications, incomplete traces, invalid identities, oversized
  traces and unretired Tasks.
- Cancellation is *logical* until a distinct `RetireTask` arrives. A late
  ready notification may be ignored, but never resume the cancelled Task.
- All actor, Task, callback and wake identifiers are single-use within a
  trace; actor identity must include the incarnation/generation.

Run `cargo test --locked reactive` and `cargo test --locked` on a verified
exact-head source runner.

## Guest-side integration gates (NOT YET VERIFIED)

1. Reconcile Java canonical `stdlib/testing.ores` PRs #2393 and #2395,
   including the `ORES_TEST` escaping contract and the Rust receipt parser.
2. Execute native `.ores` suites against each library: callbacks, pull/Future,
   Channel/select, and native Task. No host reference/model pass substitutes
   for executing compiled guest source.
3. Prove callback failure propagation, retry/termination semantics, per-test
   deadline enforcement and complete teardown under real guest execution.
4. Add runtime-owned trace collection with authenticated or protected origin,
   scheduler event capture and coverage accounting before claiming a
   concurrency/race-freedom test.
5. Check exact compiler SHA, source/tree, executed workflow steps, source
   isolation, positive and negative controls, and actual `ORES_TEST`
   receipts. Missing CI execution is NOT_EXECUTED, not PASS or FAIL.

## Inspirations (not a claim of framework adoption)

Erlang EUnit + Common Test; Erlang PropEr; Elixir ExUnit + StreamData;
Akka Typed TestKit + Apache Pekko Typed TestKit; Orleans InProcessTestCluster
+ Microsoft Coyote; and PonyTest. Focus is lifecycle isolation, monitored
message expectations, deterministic interleavings, shrinking, bounded async
completion, and thorough teardown.

## Source-transfer restriction

Do not mirror any private code to another GitHub organization while the
current private-source transfer hold remains in effect. Authorized source-org
CI or separately approved secured execution is required. No secrets, private
source, or test tokens are added by this branch.
