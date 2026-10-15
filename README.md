# Oreslang Test CLI

Native Oreslang test orchestration, deterministic fuzzing, and race-evidence
validation. The language test library remains in
`oreslang-source.java/stdlib/testing.ores`.

## Installation

Requires Python 3.10+:

```sh
python -m pip install .
```

When installed alongside the Rust `oreslang` CLI, invoke:

```sh
oreslang test --fuzz tests/my_fuzz_suite.ores --runs 1000 --seed 42
oreslang test --race tests/my_actor_suite.ores --runs 20 --seed 42
```

Standalone usage:

```sh
oreslang-test --fuzz tests/my_fuzz_suite.ores --runs 100 --seed 1
python -m oreslang_test --race tests/my_actor_suite.ores
```

`--fuzz` currently implements reproducible **black-box crash/property fuzzing**
with optional corpus directory, maximum input size, per-process timeout, and
failure inputs saved under `target/oreslang-fuzz-failures`. Guest fuzz
programs must consume their binary input from stdin and emit
`ORES_TEST|SUMMARY|...` via the native test framework. This is **not yet
coverage-guided**.

`--race` is an **evidence gate, not a finished race detector**. It will
report *inconclusive* (exit 2) until a trusted backend emits the defined
`ORES_RACE|BEGIN` and `ORES_RACE|SUMMARY` records with real memory-access
and logical-invariant instrumentation. It never prints a fake green result
when backend instrumentation is absent.

Exit codes: `0` = observed tests passed, `1` = failure/race detected,
`2` = insufficient evidence or runner/configuration error.

To run standalone unit tests (no guest backend required):

```sh
PYTHONPATH=. python -m unittest discover -s tests -v
```

See [docs/RACE_FUZZ_PROTOCOL.md](docs/RACE_FUZZ_PROTOCOL.md) for the versioned
protocol and its trust boundaries. Compiler/runtime instrumentation remains
separate work in the Java/GraalVM and LLVM repositories.
