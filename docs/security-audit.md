# Security and anti-pattern testing

The Oreslang test CLI provides an **advisory source scan**, not a compiler,
a dependency scanner, a taint engine, or a proof of security.

## Commands

    oreslang test --security
    oreslang test --anti-patterns
    oreslang test --audit
    oreslang test --audit --fail-on high --audit-format json
    oreslang test --security --audit-file src/server.ores --audit-file src/auth.ores

- --security: security heuristics only.
- --anti-patterns: code-quality/concurrency heuristics only.
- --audit: both families.
- --audit-file: repeatable project-relative path. Without it, scan discovered
  .ores files except hidden, generated, vendored and cache directories.
- --fail-on: none, low, medium (default), high, critical.
- --audit-format json: machine-readable findings with scan counts, rule IDs,
  relative paths, lines, severities, caveats, and failure counts.
- --inherit-env: explicit opt-in for guest test processes to receive the entire
  host environment; otherwise only basic OS necessities are forwarded.
  Static audit launches no guest process.

Source audit is separate from native test execution, fuzzing, data race
analysis, deadlock analysis, schedule perturbation, and bounded model checking.
Security lint output does not certify dynamic race or memory-safety properties.

## Initial rule catalog (advisory)

| ID | Severity | Finding |
| --- | --- | --- |
| SEC001 | high | Possible hard-coded credential string assignment |
| SEC002 | medium | Use of an MD5 or SHA-1 hash function |
| SEC003 | low | Plaintext non-loopback HTTP URL literal |
| SEC004 | medium | Shell invocation requiring command-injection review |
| ANTI001 | medium | Empty catch/recover block |
| ANTI002 | low | Simple brace-delimited infinite loop with no visible suspension/cooperation |

Rules are deliberately narrow heuristics. MD5 might be legitimate for
non-security checksums; an empty handler might be intentional; a loop may rely
on compiler-inserted watchdog checks. These findings prompt review but are not
confirmed vulnerabilities. Secret **values are never included** in findings.

Lexical matching excludes comments and string bodies from code-expression
rules and supports nested block comments. It does not perform import
resolution, typechecking, interprocedural analysis, dataflow, capability
tracking, path sensitivity, exception effects, or reachability analysis.

Unreadable/invalid source, unclosed literal/comment, symbolic-link source,
traversal path, missing source, or exhausted budget exits **2** rather than
reporting a clean scan. Limits: 2,000 files, 1 MB each, 16 MB total,
10,000 findings. Symlinked directory trees are not followed.
Select files explicitly for oversized workspaces.

## Race/fuzz defense-in-depth

- Guest subprocess environments contain only basic OS variables unless
  --inherit-env is passed. Race instrumentation nonce/path are added for
  the guest run; CI credentials are not forwarded by default.
- Fuzz corpora are bounded to 4,096 files, 16 MB total loaded bytes and the
  configured per-case size, with no-follow reads. Existing deterministic seeds,
  timeouts, process-tree termination, output caps, re-execution, minimization,
  and replay artifacts remain.
- Race traces validate **observed** happens-before events only. Offline traces
  and synthetic reference models cannot prove that real memory accesses were
  instrumented. Missing/inconsistent evidence is inconclusive (exit 2).
- Fuzzing is black-box mutation fuzzing, not coverage-guided fuzzing. A passing
  harness certifies only the tested inputs and properties it checks.

**Exit codes:** 0 = selected checks completed without threshold failures;
1 = threshold findings or reproducible counterexamples; 2 = incomplete,
unsupported, invalid, or inconclusive analysis/evidence.

## Roadmap requiring backend work

- GraalVM/Java: runtime-owned actor arena/linear-memory access hooks,
  synchronization and task provenance, authenticated execution receipts.
- LLVM: TSAN/ASAN/UBSAN compatible native test builds and runtime hooks,
  with explicit coverage receipts and stable actor/allocation identities.
- JS/Node/browser, WASM, .NET: advertise available backend-specific
  sanitizer support; unsupported test modes must exit 2.
- Native structured fuzz targets, coverage maps, differential testing
  across backends, and reproducible compiler/target-keyed fuzz artifacts.
- AST/HIR-driven checks for capability leaks, unsafe FFI, borrowing across
  suspensions, actor trust-domain crossings, leaked secrets in logs,
  unbounded work, missing timeout/cancellation, and dangerous path handling.

No backend runtime coverage or security sign-off is provided by this
source-only CLI change.
