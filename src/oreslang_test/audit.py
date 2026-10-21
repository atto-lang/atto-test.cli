"""Bounded advisory static audit for Oreslang source code.

This is intentionally not a parser, taint engine, or vulnerability proof.
Incomplete/unreadable analysis is an error, never a clean verdict.
"""
from bisect import bisect_right
import json
import os
from pathlib import Path
import re
import stat


class AuditError(ValueError):
    pass


MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 16_000_000
MAX_FILES = 2_000
MAX_FINDINGS = 10_000
EXCLUDED_DIRS = {".git", ".oreslang-test", "target", "build", "dist", "vendor",
                 "node_modules", "__pycache__", ".venv"}
SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}
RULES = {
    "SEC001": ("security", "high", "Possible hard-coded credential"),
    "SEC002": ("security", "medium", "Weak hash primitive requires review"),
    "SEC003": ("security", "low", "Non-loopback plaintext HTTP URL"),
    "SEC004": ("security", "medium", "Shell-based command execution requires review"),
    "ANTI001": ("anti-patterns", "medium", "Empty catch/recover discards errors"),
    "ANTI002": ("anti-patterns", "low", "Busy loop has no visible suspension/cooperation"),
}
KEY = re.compile(r"(?i)\b(?:password|passwd|secret|api_key|access_token|private_key|auth_token)\b[ \t]*(?::[ \t]*[A-Za-z_]\w*[ \t]*)?(?:=|:)")
WEAK_HASH = re.compile(r"\b(?:md5|sha1|sha_1)(?:_hash)?[ \t]*\(", re.IGNORECASE)
SHELL = re.compile(r"\b(?:shell\.(?:exec|execute|run)|os\.system)[ \t]*\(", re.IGNORECASE)
EMPTY_CATCH = re.compile(r"\b(?:catch|recover)\b[ \t]*(?:\([^{}\n]{0,300}\)[ \t]*)?\{[ \t\r\n]*\}")
BUSY_LOOP = re.compile(r"\bwhile[ \t]*(?:\([ \t]*true[ \t]*\)|true)[ \t]*\{([^{}]{0,2000})\}")
YIELD = re.compile(r"\b(?:await|select)\b|\brt[. ]+cooperate\b", re.IGNORECASE)
PLACEHOLDER = re.compile(r"(?i)^(?:example|dummy|test|fake|placeholder|changeme|replace.?me|your[_-]?|x{4,}|\*{4,}|\.{4,})")
HTTP = re.compile(r"http://([^/\s\"']+)", re.IGNORECASE)


def _lex(source):
    """Mask comments/quoted strings without changing source offsets/newlines."""
    code = list(source)
    strings = []
    n = len(source)
    i = 0

    def blank(start, end):
        for k in range(start, end):
            if code[k] not in "\r\n":
                code[k] = " "

    while i < n:
        if source.startswith("//", i):
            start = i
            i = source.find("\n", i)
            if i == -1:
                i = n
            blank(start, i)
        elif source.startswith("/*", i):
            start = i
            i += 2
            depth = 1
            while i < n and depth:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth:
                raise AuditError("unterminated block comment (source coverage incomplete)")
            blank(start, i)
        elif source[i] in ('"', "'"):
            start = i
            quote = source[i]
            triple = source.startswith(quote * 3, i)
            delim = quote * (3 if triple else 1)
            i += len(delim)
            value_start = i
            while i < n:
                if source[i] == "\\":
                    i += 2
                elif source.startswith(delim, i):
                    strings.append((start, source[value_start:i]))
                    i += len(delim)
                    blank(start, i)
                    break
                elif not triple and source[i] == "\n":
                    raise AuditError("unterminated string literal (source coverage incomplete)")
                else:
                    i += 1
            else:
                raise AuditError("unterminated string literal (source coverage incomplete)")
        else:
            i += 1
    return "".join(code), strings


def _safe_read(root, path):
    try:
        rel = path.relative_to(root)
        parent = root
        for piece in rel.parts:
            parent /= piece
            if parent.is_symlink():
                raise AuditError(f"symlinked audit input rejected: {rel}")
        if path.suffix != ".ores":
            raise AuditError(f"not an Oreslang source file: {rel}")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as src:
            mode = os.fstat(src.fileno())
            if not stat.S_ISREG(mode.st_mode) or mode.st_size > MAX_FILE_BYTES:
                raise AuditError(f"source is not a regular file or exceeds 1 MB: {rel}")
            data = src.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise AuditError(f"source exceeds 1 MB read limit: {rel}")
        return data.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise AuditError(f"invalid UTF-8 source: {path.relative_to(root)}") from exc
    except OSError as exc:
        raise AuditError(f"cannot inspect {path.relative_to(root)}: {exc.strerror}") from exc


def _discover(root, explicit):
    if explicit:
        paths = []
        for name in explicit:
            if not isinstance(name, str) or not name or Path(name).is_absolute() or ".." in Path(name).parts:
                raise AuditError("audit files must be nonempty project-relative paths")
            path = root / name
            if not path.resolve().is_relative_to(root):
                raise AuditError(f"audit file escapes root: {name}")
            paths.append(path)
    else:
        paths = []
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith("."))
            for name in sorted(files):
                if name.endswith(".ores"):
                    paths.append(Path(directory) / name)
                    if len(paths) > MAX_FILES:
                        raise AuditError("more than 2000 Oreslang sources; select --audit-file")
    paths = sorted(set(paths))
    if not paths:
        raise AuditError("no Oreslang source files found; analysis inconclusive")
    if len(paths) > MAX_FILES:
        raise AuditError("more than 2000 Oreslang sources")
    return paths


def analyze(root, *, security=True, anti_patterns=True, files=None):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise AuditError("audit root must be a directory")
    findings = []
    bytes_total = 0
    paths = _discover(root, files)

    def emit(rule, relative, line):
        kind, severity, message = RULES[rule]
        if kind == "security" and not security or kind == "anti-patterns" and not anti_patterns:
            return
        if len(findings) == MAX_FINDINGS:
            raise AuditError("finding budget exceeded; report is incomplete")
        findings.append({"rule": rule, "kind": kind, "severity": severity,
                         "file": relative, "line": line, "message": message})

    for path in paths:
        source = _safe_read(root, path)
        bytes_total += len(source.encode("utf-8"))
        if bytes_total > MAX_TOTAL_BYTES:
            raise AuditError("source scan exceeds 16 MB; report is incomplete")
        try:
            code, strings = _lex(source)
        except AuditError as exc:
            raise AuditError(f"{path.relative_to(root)}: {exc}") from exc
        relative = path.relative_to(root).as_posix()
        newline_positions = [-1] + [m.start() for m in re.finditer("\n", source)]

        def line(offset):
            return bisect_right(newline_positions, offset)

        if security:
            literals = dict(strings)
            for match in KEY.finditer(code):
                pos = match.end()
                while pos < len(source) and source[pos] in " \t":
                    pos += 1
                secret = literals.get(pos)
                if secret is not None and len(secret.strip()) >= 8 and not PLACEHOLDER.match(secret.strip()):
                    emit("SEC001", relative, line(match.start()))
            for match in WEAK_HASH.finditer(code):
                emit("SEC002", relative, line(match.start()))
            for match in SHELL.finditer(code):
                emit("SEC004", relative, line(match.start()))
            for pos, value in strings:
                for match in HTTP.finditer(value):
                    hostname = match.group(1).split(":", 1)[0].lower().strip("[]")
                    if hostname not in ("localhost", "127.0.0.1", "::1") and not hostname.startswith("127."):
                        emit("SEC003", relative, line(pos))
        if anti_patterns:
            for match in EMPTY_CATCH.finditer(code):
                emit("ANTI001", relative, line(match.start()))
            for match in BUSY_LOOP.finditer(code):
                if not YIELD.search(match.group(1)):
                    emit("ANTI002", relative, line(match.start()))
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    return {"analysis": "advisory-source-heuristics-v1", "files_scanned": len(paths),
            "bytes_scanned": bytes_total,
            "enabled": [name for name, selected in (("security", security), ("anti-patterns", anti_patterns)) if selected],
            "findings": findings,
            "limits": "No taint/control-flow analysis, compiler validation, runtime sanitizer, or completeness proof"}


def run(root, *, security, anti_patterns, files, threshold="medium", output_format="text"):
    if threshold not in (*SEVERITIES, "none"):
        raise AuditError("invalid --fail-on value")
    if output_format not in ("text", "json"):
        raise AuditError("invalid --audit-format value")
    report = analyze(root, security=security, anti_patterns=anti_patterns, files=files)
    cutoff = SEVERITIES.get(threshold, 100)
    failures = sum(SEVERITIES[f["severity"]] >= cutoff for f in report["findings"])
    report["failure_threshold"] = threshold
    report["failing_findings"] = failures
    if output_format == "json":
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        for finding in report["findings"]:
            path = finding["file"].encode("unicode_escape").decode("ascii")
            print(f"{path}:{finding['line']}: {finding['severity'].upper()} "
                  f"{finding['rule']} {finding['message']}")
        print(f"AUDIT: {report['files_scanned']} files, {len(report['findings'])} advisory findings, "
              f"{failures} at or above {threshold} (not a vulnerability-free certification)")
    return 1 if failures else 0
