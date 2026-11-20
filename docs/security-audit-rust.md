# Rust-only Oreslang source audit (advisory)

This draft CLI implements the source-heuristic scanners in Rust. It never
executes Python and never exposes secret literal contents in a finding.

Commands:

    oreslang test --security
    oreslang test --anti-patterns
    oreslang test --audit
    oreslang test --audit --fail-on low --audit-format json
    oreslang test --audit --audit-file src/auth.ores

Implemented rule IDs and baseline severity:

| Rule | Severity | Finding |
| --- | --- | --- |
| SEC001 | high | Probable hardcoded non-placeholder credential literal |
| SEC002 | medium | MD5 or SHA-1 function call |
| SEC003 | low | Plaintext non-loopback HTTP URL literal |
| SEC004 | medium | Shell/system execution call |
| ANTI001 | medium | Empty catch or recover block |
| ANTI002 | low | Brace-delimited infinite loop without visible await/select/cooperate |

Scanner scope is intentionally narrower than a compiler AST/HIR security
analysis. It can miss obfuscated calls, indirect dataflow, dynamic code,
unusual formatting and nonliteral credentials, and may flag benign uses.
A zero-finding report does not certify code as secure.

Guards: source path traversal and symlinks rejected; bounded nested-comment
handling; incomplete comments or strings refused; maximum 2000 files,
1 MiB per file, 16 MiB total and 10000 findings. Configured exclusions
apply to implicit discovery. Explicitly selected sources may include
generated paths, but must remain project-relative regular files.
Output values contain rule/severity/file/line and generic explanation,
not secret values.

Exit 0 means no findings at or above threshold on the inspected source,
1 means findings at or above threshold, 2 means malformed or incomplete
analysis. --fail-on none never reports a finding failure.

Limitations: existing Python-based security-audit draft PR #9 must not
be merged as the canonical implementation. Any additional security-fuzz
profiles, taint analysis or dynamic enforcement should be implemented and
tested in Rust with separate trusted backend coverage contracts.
