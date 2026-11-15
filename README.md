# atto-test.cli

Command-line testing tools and execution harnesses for AttoLang programs.

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

AttoLang is the public name; preserve existing Oreslang/.ores compatibility and use canonical .atto for new portable library source. This README defines scope, not feature readiness.

**Acceptance:** name the exact source SHA/tree, runtime/toolchain, positive and negative checks and execution receipt before claiming support. Host-only tests and empty CI steps do not prove guest execution.
