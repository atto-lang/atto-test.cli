# Exceptional callable effects: tooling and runtime boundary

`throws`, `raises`, and `panics` are optional **may-effect** declarations.
Omitting one never means the callable is proven effect-free. Their singular
statements remain `throw`, `raise`, and `panic`.

| Effect | catch / trap | direct deferred recover | actor boundary |
| --- | --- | --- | --- |
| throw | Matching ordinary handler | Recoverable in the same logical invocation | Unhandled failure escalates with throw origin |
| raise | Bypasses both | First eligible direct deferred recover during unwind | Unhandled failure escalates with raise origin |
| panic | Bypasses both | Never consumable by the failed actor | Direct supervisor CONTROL delivery |

Defers run LIFO. Recovery completes unwinding; it does not resume after the
failed statement. Panic delivery must be exactly once, on the supervisor's
control lane, isolated from the failed child's recover state. Cancellation and
host-fatal failures cannot become ordinary recoverable guest errors. Cleanup
must preserve the failure-priority and bounded-suppression rules from the
shared contract.

These are the intended semantics. The Rust scanner observes direct source
syntax and suggests missing markers. It does not implement unwinding, validate
Error ancestry, resolve call targets, prove local handling, or admit guest
execution. Even a function containing only `call_unknown()` has unknown
transitive effects. A scanner result with zero warnings does not change that.

The existing proposal uses postfix declarations:

```ores
fnc load() -> User throws(NetworkError) raises(AccessError) panics {
  // Proposed syntax; production Java/LLVM admission is still gated.
}
```

Run the advisory mode independently:

```sh
oreslang test --effects --file src/load.ores
oreslang test --effects --effects-strict --file src/load.ores
```

The formatter preserves supplied effect clauses and their ordering; it must
not insert annotations or claim they are semantically verified. Rust analyzer
coverage includes bare class methods, generic fncs, explicit receivers,
routines and named pipe declarations. Unknown anonymous scopes or unsupported
headers return inconclusive, rather than silently transferring effects to the
wrong enclosing callable.

## Promotion gates

1. [Shared exceptional-effect proposal](https://github.com/ores-truffle-oreslang/oreslang-common-source/pull/35): independent source grammar and semantic fixtures.
2. [Java compiler issue #1010](https://github.com/ores-truffle-oreslang/oreslang-source.java/issues/1010): preserve nominal typed may-effects through AST, callable resolution, generic substitution, interfaces/overrides, HIR/MIR and ABI; build compiler-owned transitive effect analysis with unknown states.
3. Source execution: typed throw/catch/trap; raise bypass to eligible direct defer/recover; non-void recovered-exit return proofs.
4. Actor execution: panic goes directly to supervisor CONTROL; multiple awaits/carrier migration preserve logical unwind ownership; cancellation and cleanup failures retain their distinct priority.
5. Real guest regression runs on Java/GraalVM and LLVM, including fuzzed cleanup/recovery order and race schedules for exactly-once supervisor events. The current CLI trace/model fixtures are host-side evidence only.
6. Exact-head CI and cross-backend conformance before lifting production admission gates.

## Rust migration evidence

The Python draft's original 41 tests passed locally with Python 3.12 before
migration. The effect checker and its tests are replaced by the Rust library,
CLI golden tests and deterministic malformed-input corpus. Later draft
hardening for all quote-style interpolations, whole-file delimiters, nested
scope attribution and token budgets is carried into Rust as regressions.
The legacy native/race/fuzz engines remain unchanged and need a separate Rust
migration with observable-output and failure-mode parity. Their existing unit
suite continues to run during this transition.
