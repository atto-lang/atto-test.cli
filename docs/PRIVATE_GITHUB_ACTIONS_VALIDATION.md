# Private cross-organization Rust CI validation

Status as of 2026-10-22: **no confirmed usable source-private runner**.
This is an execution/runbook gate, not successful CI evidence.

## Diagnosis completed

- Source: `ores-truffle-oreslang/oreslang-test.cli` draft PR #6.
  Private-repository Actions jobs failed before executing any steps;
  downloaded job logs were unavailable. This alone does *not* identify
  whether the cause is billing, Actions runner quota, policy, or scheduling.
- Private candidate repositories tested with a tiny Rust compiler probe:
  `zed-pkg-test/java-app`, `gha-indie-worker/gha-indie-worker-docs`,
  `agent-pontifex/agent-pontifex-docs`,
  `3fa-app-test/clients-rust-consumer`,
  `ORESoftware/formal-methods.rs`.
  None demonstrated an executed job; most failed with no steps. Do not copy
  the private source to a candidate until the probe actually executes.
- **Control case:** the public repository
  `gha-indie-worker/gha-indie-worker.rs` ran Rust runner smoke workflow
  [39687787282](https://github.com/gha-indie-worker/gha-indie-worker.rs/actions/runs/39687787282)
  successfully. Its log includes runner setup and successful `rustc` and
  `cargo` commands. **No private source was copied to the public repo.**
  This narrows the issue to private-repository admission/billing rather than
  a universal GitHub-hosted Linux runner outage.

## Source-local runner unblock checklist (admin action)

The current PR-head Linux/macOS/Windows matrix still fails before allocating
a runner (job `steps: []`, empty `runner_name`). This cannot be diagnosed
as a Rust compilation failure or even uniquely as exhausted Actions minutes.

1. Inspect source-repository/org Actions usage, spending cap, active payment,
   workflow restrictions, eligible runner groups, and each failed run's
   GitHub UI failure banner/annotations. The integration cannot administer
   these settings.
2. Prefer restoring the existing GitHub-hosted source-repo runners.
   Alternatively provision an ephemeral, single-use self-hosted runner
   **inside the private source repo**, not in an unapproved external org;
   assign only a dedicated runner label and prohibit untrusted fork PRs
   from using it. No long-lived credentials, broad network access, or caches.
3. Execute the exact PR-head checkout verifier before Cargo. Require
   successful recorded steps for `rustc --version`, `cargo --version`,
   `cargo test --locked`, `cargo build --locked --bins`,
   `cargo clippy --locked --all-targets -- -D warnings`, and
   `cargo fmt --all --check`. Collect logs and the checked Git tree.
4. Independently run Linux symlink-ancestor, FIFO, pathname traversal,
   corpus directory listing, and fuzz collision regressions; on macOS and
   Windows explicitly record that current filesystem admission is still
   preflight/path-based rather than Linux descriptor-relative.
5. Do not merge or delete Python comparison oracles solely on structural
   tests. Run real backend/guest conformance and review the remaining
   guest-provided native receipt spoofing and subprocess containment gaps.

No cross-organization private tree copying or public-runner fallback is
authorized by this checklist.

## Controlled mirror protocol (once a PRIVATE runner actually works)

1. Confirm test organization and repository are authorized for private
   source retention. Check carrier visibility is `private`, access controls
   are comparable to the source, and sufficient Actions capacity is
   available. Never infer minutes from an old successful run.
2. Commit and execute a minimal `rustc --version; cargo --version` private
   workflow first; inspect job **steps and logs**. Zero-step failure or
   queued-only status is not capacity proof.
3. Pin the source PR head commit and the exact `git rev-parse HEAD^{tree}`
   SHA. Enumerate all blob paths, Git file modes and SHA-1 blob identities.
   Abort if the ref advances mid-export. Retain an audit manifest of source,
   carrier, scopes and expected tree.
4. Through the connected GitHub file/tree interface, mirror **only** the
   approved immutable Git tree into a temporary private carrier branch.
   Never use a public repo or relax an explicit connector access denial.
   Git blob SHA checks and a carrier `HEAD^{tree}` comparison must match
   the source, including executable permissions. An incomplete tree is
   inadmissible.
5. In the carrier workflow, use `permissions: contents: read`,
   `actions/checkout` with `persist-credentials: false`; never attach
   cross-repo secrets, write tokens, CI environment credentials or cache
   publication to the guest test subprocess. Pin trusted actions by commit
   digest. Test `cargo test --locked`, `cargo build --locked`,
   `cargo clippy --locked --all-targets -- -D warnings` and
   `cargo fmt --all --check`; capture step-level outputs.
6. Compare source blob and tree hashes *before* the build and confirm that
   tracked files remain unchanged after the test. Never mark a source
   PR green merely because a workflow was created, queued or finished
   with zero steps. Mirror tests validate only their executed scope.
7. Delete the temporary refs after acceptance **subject to repo and
   retention policy**. Deleting refs does not reliably purge underlying
   Git objects, caches, logs or forks. If private source was transmitted
   to an unapproved retention domain, treat it as a security incident;
   rollback/ref deletion alone is not sufficient mitigation.

If no private-hosted org has capacity, investigate the individual
organization's Actions/billing budget or provision an authorized self-hosted
runner. A public GitHub-hosted runner is NOT an acceptable workaround for
private Oreslang sources.

## Release gate

PR #6 remains draft until exact-head Rust CI produces real compiler,
lint, test and format evidence. A successful synthetic/offline trace scan
still is not a backend runtime race-freedom attestation.
