#!/usr/bin/env bash
set -euo pipefail
: "${EXPECTED_SOURCE_TREE_SHA:?Set EXPECTED_SOURCE_TREE_SHA to the exact source Git tree SHA}"
[[ ${EXPECTED_SOURCE_TREE_SHA} =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid SHA" >&2; exit 2; }
actual="$(git rev-parse 'HEAD^{tree}')"
[[ "$actual" == "$EXPECTED_SOURCE_TREE_SHA" ]] || { echo "MISMATCH: source Git tree" >&2; exit 2; }
git diff --quiet HEAD -- || { echo "Modified checkout" >&2; exit 2; }
[[ -z "$(git ls-files --others --exclude-standard)" ]] || { echo "Untracked files before CI" >&2; exit 2; }
cargo --version
cargo test --all-targets
cargo build --release
./target/release/oreslang-test --root . --race --trace tests/traces/ordered.jsonl
./target/release/oreslang-test --root . --model-check --model tests/models/atomic-update.json
git diff --quiet HEAD -- || { echo "Tracked files modified during test" >&2; exit 2; }
echo "ORES_CONCURRENCY_CI|backend=rust-cli|source_tree=${actual}|result=PASS|scope=cargo-test"
