# Reactive composition trace model v1 (Rust host reference)

The source branch now uses `oreslang_test::reactive::analyze`, written in
**Rust**, rather than the prior Python `analyze_reactive_events` prototype.
The Rust API consumes typed `Event` variants: `Subscribe`, `Request`,
`Next`, `Complete`, `Cancel`, `Error`, and `Dispose`.

The bounded host model checks single-consumer source cardinality,
cold/hot mode isolation, explicit downstream demand, single terminal
cause, and exactly one disposal after termination. Invalid identities,
excessive demand, and events after completion or cancellation fail
closed. Capacity is limited to 100,000 events.

Use `cargo test --locked reactive` (and the full Rust test suite) on an
authorized exact-head runner. No Python tests are required.

**Scope:** This is a typed *host-side protocol model*, not runtime
instrumentation, a scheduler simulator, source-language implementation, or
proof against races. A trusted capture adapter from Java/LLVM reactive
sources, JSONL schema validation, and runtime coverage accounting
remain future work. It is not currently a public `--reactive` CLI option.
The common-source and reactive-runtime contracts still require separate
backend parity validation.
