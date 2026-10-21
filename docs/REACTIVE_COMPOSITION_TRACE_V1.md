# Reactive composition trace model v1

The native Rust module `src/reactive.rs` provides finite host-side conformance checking for `subscribe`, `request`, `next`, `complete`, `cancel`, `error`, and `dispose` events.

Checks include single-consumer ownership, demand accounting, terminal/disposal consistency, and a 100,000-event budget. This is **not** guest runtime instrumentation, a scheduler proof, or a substitute for `--race`.

Run its unit tests with `cargo test reactive`. Java/LLVM runtime integrations remain necessary before promoting results as guest-level evidence.
