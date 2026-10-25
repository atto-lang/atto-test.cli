#!/usr/bin/env bash
set -euo pipefail

: "${EXPECTED_SOURCE_TREE_SHA:?Set EXPECTED_SOURCE_TREE_SHA to the exact source Git tree SHA}"
if [[ ! ${EXPECTED_SOURCE_TREE_SHA} =~ ^[0-9a-f]{40}$ ]]; then
  echo "Invalid expected source tree SHA" >&2
  exit 2
fi
actual="$(git rev-parse 'HEAD^{tree}')"
if [[ "${actual}" != "${EXPECTED_SOURCE_TREE_SHA}" ]]; then
  echo "MISMATCH: checked-out Git tree does not match source PR" >&2
  exit 2
fi
git diff --quiet HEAD -- || { echo "Tracked files modified before test" >&2; exit 2; }
if [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  echo "Untracked checkout files present before exact-tree test" >&2
  exit 2
fi

command -v cargo >/dev/null || { echo "Rust Cargo toolchain unavailable" >&2; exit 2; }
cargo --version
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all --check

# These are Rust CLI/unit conformance tests, NOT guest runtime race-freedom
# certificates. Do not print success if any command above did not execute.
git diff --quiet HEAD -- || { echo "Tracked files modified during tests" >&2; exit 2; }
echo "ORES_CONCURRENCY_CI|backend=rust-cli|source_tree=${actual}|result=PASS|scope=rust-host-unit-and-integration-not-runtime-race"
