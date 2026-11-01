# Native Oreslang test lifecycle v2 — host verifier, design benchmark

Status: **experimental Rust receipt verification only**, not a native Oreslang actor/task TestKit.
The canonical public API remains `oreslang-source.java/stdlib/testing.ores`, coordinated
with the overlapping draft PRs #2393 and #2395. This change does not modify, supersede,
or claim execution of that guest library.

## Opt-in

```toml
[native]
files = ["tests/test_async.ores"]
receipt = "lifecycle-v2"
```

The default `receipt = "v1"` preserves existing synchronous suites. Mixed v1 and v2
machine event families are rejected by both verifiers. With v2 enabled,
only a fully consistent `ORES_TEST_V2` event stream with at least one executed
PASS/FAIL case is admissible. The host still waits for the *process* exit, applies
the existing wall-clock timeout, output budget, restricted environment and
process-group shutdown, then checks exit zero and the lifecycle receipt.

Proposed event stream, ASCII protocol, exact syntax:

```text
ORES_TEST_V2|RUN_BEGIN|2
ORES_TEST_V2|CASE_BEGIN|suite/async
ORES_TEST_V2|OPEN|suite/async|callback|cb1
ORES_TEST_V2|OPEN|suite/async|task|t1
ORES_TEST_V2|OPEN|suite/async|actor|a1
ORES_TEST_V2|OPEN|suite/async|await|aw1
ORES_TEST_V2|CLOSE|suite/async|await|aw1|ok
ORES_TEST_V2|CLOSE|suite/async|callback|cb1|ok
ORES_TEST_V2|CLOSE|suite/async|task|t1|ok
ORES_TEST_V2|CLOSE|suite/async|actor|a1|ok
ORES_TEST_V2|CASE_END|suite/async|PASS
ORES_TEST_V2|RUN_END|total=1|passed=1|failed=0|skipped=0|filtered=0
```

`OPEN` and `CLOSE` identify a case-local obligation with kind
`callback|task|actor|await` and a unique handle; each handle is single-use.
`CLOSE` accepts `ok|error|cancel`. A PASS cannot follow an error or
cancellation, or close while a resource remains open. A SKIP cannot hide
any resource activity. FAIL still requires complete cleanup before CASE_END.
Interleaving events from concurrent cases is allowed; each has its own set of
handles. RUN_END must be terminal, and its per-status counts must equal
individual completed cases. Empty/all-skipped, missing, duplicated, dangling,
late, unknown or malformed lifecycle records are refused. Limits: 10,000
cases, 100,000 lifecycle records, and 256 bytes per identifier.

## Important evidence boundary

This parser is **not authenticated**. A guest can omit OPEN events or print
fabricated CLOSE events; a malicious executable can forge the whole stream.
A structurally valid receipt is **not proof** of real callback invocation,
task join, awaited completion, actor termination, scheduler fairness,
physical heap retirement, or absence of data races. A native compiler/runtime
adapter must later emit host-verified events for every admitted resource and
bind them to the source/compiler/runner identities before this can become a
release gate. Until then, the CLI self-tests below are host-only, not Oreslang
guest tests.

## Ten benchmark tools across five actor-runtime ecosystems

These are ten *widely used/relevant reference facilities*, not an empirical
rating leaderboard. No verified cross-framework score ranking is implied.

| Actor ecosystem | Tool 1 | Tool 2 | Oreslang feature to adopt |
|---|---|---|---|
| Erlang / OTP | [EUnit](https://www.erlang.org/docs/26/apps/eunit/chapter.html) | [Common Test](https://www.erlang.org/doc/apps/common_test/users_guide.html) | Per-test process isolation, timetraps, suite/fixture lifecycle, distributed-node diagnostics |
| Pony actor runtime | [PonyTest UnitTest](https://www.ponylang.io/use/testing/) | [PonyTest Property](https://www.ponylang.io/use/testing/) | Exact-once expected async actions, long-test timeouts, actor disposal and shrinking (two modes of one framework) |
| Akka / Apache Pekko | [Typed ActorTestKit](https://doc.akka.io/libraries/akka-core/current/typed/testing-async.html) | [BehaviorTestKit](https://pekko.apache.org/docs/pekko/current/typed/testing-sync.html) | TestProbe mailbox assertions, synchronous behavior model vs real scheduler |
| Microsoft Orleans | [InProcessTestCluster](https://dotnet.github.io/orleans/docs/grains/testing/) | [OrleansTestKit](https://github.com/OrleansContrib/OrleansTestKit) | Full activation/cluster fidelity vs isolated grain doubles; never confuse the two |
| Actix / Rust async actors | [actix_rt::test](https://docs.rs/actix-rt/latest/actix_rt/attr.test.html) | [tokio::test](https://docs.rs/tokio/latest/tokio/attr.test.html) | Async task execution, structured child tracking and scheduler/clock test controls |

Pony's `long_test`, `expect_action`, `complete_action` and `dispose_when_done`\nare especially relevant to late callbacks and actor lifetime: they demonstrate\nwhy merely returning from a test body is not proof of async completion.\nElixir's [ExUnit](https://hexdocs.pm/ex_unit/ExUnit.html) and\n[StreamData](https://stream-data.hexdocs.pm/ExUnitProperties.html)\nremain useful additional BEAM-language design references, but are not counted\nas a separate actor *runtime* from Erlang/OTP.\n\n## Native Oreslang core TestKit acceptance gates

1. **Callbacks:** synchronously completed, late, repeated, never-called, double-called,
   cross-test and error-first callbacks. Cancellation must suppress post-close
   delivery; late notices must be attributed to the original case.
2. **Tasks:** spawn, await/join, child panic/raise, parent cancellation, unjoined
   child, nested scope, deadline race and physical child retirement.
3. **Actors:** real mailbox send/ack, TestProbe ordering/negative assertions,
   actor stop, supervisor CONTROL panic path, restart-generation fencing,
   mailbox backpressure and isolated per-test actor heap.
4. **Async/await:** immediate and suspended completion, nested await,
   synchronous callback timing (Zalgo), abort during suspension, continuation
   scheduling without parking a carrier thread.
5. **Isolation and reporting:** deterministic seeds and clock controls only
   within the test scheduler, reverse cleanup order, exact-once terminal result,
   bounded resources, complete compiler and run identity, v1 backward compatibility.
6. **Five backends:** Java/Graal, LLVM, Wasm, .NET NativeAOT and Forge must
   independently compile and run real `.ores` cases; report each backend's
   unsupported feature explicitly, not as a skip counted toward passing.

## Additional adversarial suite (this PR)

The extended Rust tests enumerate all **24** completion orders for callback,
task, actor and await handles, all **81** combinations of their
`ok|error|cancel` outcomes (each checked against PASS and FAIL),
multiple interleaved cases, cross-case close spoofing and a 10,001-case
discovery overflow boundary. Mutated transcripts exercise duplicate
RUN_BEGIN/CASE_BEGIN/CLOSE/CASE_END/RUN_END, unknown statuses, outstanding
resources, late case events and truncated reserved machine prefixes.

The CLI subprocess tests also check whether a guest can produce a valid-looking
PASS receipt and then exit nonzero, exceed its output budget, time out,
or leave a background Unix process alive after its parent exits.
The launcher now sends SIGKILL to its **own guest process group** after normal
child exit as well as on timeout, before it reports a result.
This is **best-effort cleanup**: a descendant can escape by creating a new
session/process group; on Windows there is not yet equivalent Job Object
containment. Neither guard authenticates guest-reported actor retirement,
which must be verified through compiler/runtime-owned instrumentation.

All added cases are still **authored/unexecuted** as long as the source CI jobs
have `steps=[]` and no local Cargo toolchain is available. Treat CI
admission failure separately from test failure and do not report these as
native guest passes.

## Host-only regression commands

```sh
cargo fmt --all --check
cargo test --locked --test lifecycle_cli
cargo test --locked lifecycle
cargo clippy --locked --all-targets -- -D warnings
```

The two added Rust suites cover valid interleaved cases and failure
cleanup as well as missing callback/task/actor/await completions, repeated
handles, double settlement, cancellation/error reported as PASS, early
CASE_END, missing RUN_END, mixed protocol versions and invalid configuration.
These tests require a working Rust toolchain and do not count as executed
native Oreslang tests. If CI has zero admitted steps, report `NOT_EXECUTED`,
not green. Private source cannot be mirrored to a second organization merely
because that organization has GitHub Actions minutes.
