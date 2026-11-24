> **AI agent instructions (organization-wide):** Before working on code, issues, or pull requests, read and follow the [organization `AGENTS.md`](https://github.com/atto-lang/.github/blob/main/AGENTS.md), including its **merge-first stealth-development policy**. Honor any repository-local `AGENTS.md`, explicit holds, and GitHub-enforced rules.

# atto-test.cli

Command-line testing tools and execution harnesses for AttoLang programs.

## Naming migration and language authority

This repository is maintained at [atto-lang/atto-test.cli](https://github.com/atto-lang/atto-test.cli); use `https://github.com/atto-lang/atto-test.cli.git` for Git remotes and canonical `.atto` source examples. The normative language contract is [atto-spec](https://github.com/atto-lang/atto-spec), with executable guest evidence tracked by [atto-platform-conformance](https://github.com/atto-lang/atto-platform-conformance). Follow current ownership, borrowing, effects, actor, and syntax rules there; do not infer implemented features from a README or unexecuted CI.

## Purpose

Test discovery, harnesses, and reporting for compiler/runtime tests.

## Verification model

- Keep fixtures and expected results versioned with the repository.
- Track exact backend, toolchain, commit SHA, and executed test command.
- Report each feature as **passed**, **failed**, **unsupported**, or **not executed**; never infer guest execution from host-only tests.
- Use [AttoLang's language specification](https://github.com/atto-lang/atto-spec) as the portable semantic contract.

## Development

Use actual source and checked-in CI workflows to determine build and test commands. Changes should include positive, negative, and boundary cases appropriate to the tested behavior.

## Status

This README documents intended scope; current conformance must be established from executable fixtures and CI evidence.

## Related

- [AttoLang](https://github.com/atto-lang)
- [Platform conformance](https://github.com/atto-lang/atto-platform-conformance)

## Repository ownership and contribution routing

**Belongs here:** Test discovery, assertion/reporting CLI, reproducible guest harness, receipt capture and explicit backend execution classification.

**Belongs elsewhere:** Conformance fixtures belong in atto-platform-conformance; differential comparisons in atto-compilers-parity-testing; building programs in atto-cli.

**Security and portability boundary:** A green workflow with zero executed steps is not a passing test. Distinguish host unit, source-free canary, compiled guest and actual guest execution.

AttoLang is the canonical project name; new source, examples and documentation use `.atto` and the `atto-lang` repository organization. This README defines scope, not feature readiness.

**Acceptance:** name the exact source SHA/tree, runtime/toolchain, positive and negative checks and execution receipt before claiming support. Host-only tests and empty CI steps do not prove guest execution.

## Source-free execution receipt gate (host-side prototype)

`python3 -m atto_test_cli.receipt path/to/receipt.json` validates v1 receipt metadata and emits `{"gate_pass":false,"host_only":0,"passed_guest":0,"total":0}`-shaped JSON. Exit codes: 0 only when **all** cases report a successful guest execution with exact source SHA, command, runtime, case exit and evidence digest; 1 for a well-formed non-passing receipt; 2 for invalid input. Duplicate JSON keys, skipped/pending surrogate claims, missing digests and zero-case receipts are rejected. Run `python3 -m unittest discover -s tests -v` to exercise positive and adversarial host tests.

This is a **metadata validator, not cryptographic attestation or guest execution**. A fabricated digest is not evidence of real runtime execution. A trusted verifier must independently bind recorded digests to executed artifacts, guest identity and exact commit before accepting parity or release claims.
