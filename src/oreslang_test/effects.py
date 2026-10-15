"""Conservative source-level exceptional-effect hints, not an effect typechecker.

Scans named braced fnc/method bodies. It cannot prove transitive effects,
overload resolution, catch coverage, or actor supervisor execution.
"""
from dataclasses import dataclass
from bisect import bisect_right
import re

WORDS = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|->|=>|[{}();,.]")
EFFECTS = {"throw": "throws", "raise": "raises", "panic": "panics"}
ANNOTATIONS = frozenset(EFFECTS.values())


class EffectsInconclusive(ValueError):
    """The source is outside the supported analysis subset."""


@dataclass(frozen=True)
class Token:
    value: str
    line: int


@dataclass(frozen=True)
class Diagnostic:
    line: int
    code: str
    message: str


def tokenize(source: str) -> list[Token]:
    """Mask comments and literals, retaining line numbers and punctuation."""
    masked = list(source)
    i, line, start_line = 0, 1, 1
    mode = ""
    while i < len(source):
        c = source[i]
        n = source[i + 1] if i + 1 < len(source) else ""
        if c == "\n":
            line += 1
            if mode == "line":
                mode = ""
            if mode:
                masked[i] = "\n"
            i += 1
            continue
        if mode == "line":
            masked[i] = " "
        elif mode == "block":
            masked[i] = " "
            if c == "*" and n == "/":
                masked[i + 1] = " "
                i += 2
                mode = ""
                continue
        elif mode in ("'", '"', chr(96)):
            masked[i] = " "
            if c == "$" and n == "{":
                raise EffectsInconclusive(f"interpolated string requires compiler analysis at line {line}")
            if c == "\\" and n:
                masked[i + 1] = " "
                if n == "\n":
                    line += 1
                    masked[i + 1] = "\n"
                i += 2
                continue
            if c == mode:
                mode = ""
        elif c == "/" and n in ("/", "*"):
            masked[i] = masked[i + 1] = " "
            mode = "line" if n == "/" else "block"
            start_line = line
            i += 2
            continue
        elif c in ("'", '"', chr(96)):
            masked[i] = " "
            mode = c
            start_line = line
        i += 1
    if mode and mode != "line":
        kind = "block comment" if mode == "block" else "string"
        raise EffectsInconclusive(f"unterminated {kind} at line {start_line}")
    text = "".join(masked)
    # Do not claim a clean result for unbalanced nonliteral source.
    nesting = []
    pairs = {")": "(", "}": "{"}
    for char in text:
        if char in ("(", "{"):
            nesting.append(char)
        elif char in pairs:
            if not nesting or nesting.pop() != pairs[char]:
                raise EffectsInconclusive("unbalanced source delimiters")
    if nesting:
        raise EffectsInconclusive("unbalanced source delimiters")
    newlines = [i for i, char in enumerate(text) if char == "\n"]
    return [Token(m.group(), bisect_right(newlines, m.start()) + 1)
            for m in WORDS.finditer(text)]


def _matching(tokens: list[Token], start: int, opening: str, closing: str) -> int:
    depth = 0
    for i in range(start, len(tokens)):
        if tokens[i].value == opening:
            depth += 1
        elif tokens[i].value == closing:
            depth -= 1
            if depth == 0:
                return i
    raise EffectsInconclusive(f"unbalanced {opening} at line {tokens[start].line}")


def _signature(tokens: list[Token], start: int):
    marker = tokens[start]
    if start + 2 >= len(tokens):
        raise EffectsInconclusive(f"incomplete callable at line {marker.line}")
    name = tokens[start + 1]
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name.value):
        raise EffectsInconclusive(f"unsupported callable name at line {marker.line}")
    paren = start + 2
    while paren < len(tokens) and tokens[paren].value not in ("(", "{", ";"):
        paren += 1
    if paren == len(tokens) or tokens[paren].value != "(":
        raise EffectsInconclusive(f"unrecognized callable signature at line {marker.line}")
    end_params = _matching(tokens, paren, "(", ")")
    annotations = set()
    issues = []
    i = end_params + 1
    while i < len(tokens):
        word = tokens[i].value
        if word in ("{", ";"):
            if word == ";":
                return name.value, annotations, None, None, issues
            end_body = _matching(tokens, i, "{", "}")
            return name.value, annotations, i, end_body, issues
        if word in ANNOTATIONS:
            if word in annotations:
                issues.append(Diagnostic(tokens[i].line, "duplicate-annotation",
                                         f"duplicate {word} on {name.value}"))
            annotations.add(word)
            if i + 1 < len(tokens) and tokens[i + 1].value == "(":
                end = _matching(tokens, i + 1, "(", ")")
                if end == i + 2:
                    issues.append(Diagnostic(tokens[i].line, "empty-effect-types",
                                             f"{word}() has no Error types; use {word} or {word}(ErrorType)"))
                i = end + 1
                continue
        i += 1
    raise EffectsInconclusive(f"unfinished signature/body at line {marker.line}")


def analyze(source: str) -> tuple[list[Diagnostic], int]:
    """Return advisory hints and count of inspected braced callable bodies."""
    tokens = tokenize(source)
    diagnostics: list[Diagnostic] = []
    inspected = 0
    i = 0
    while i < len(tokens):
        if tokens[i].value not in ("fnc", "method"):
            i += 1
            continue
        if i > 0 and tokens[i - 1].value in (".", "import"):
            i += 1
            continue
        name, declared, first, last, issues = _signature(tokens, i)
        diagnostics.extend(issues)
        if first is not None:
            inspected += 1
            j = first + 1
            while j < last:
                word = tokens[j].value
                if word in ("fnc", "method") and tokens[j - 1].value != ".":
                    _, _, nested_first, nested_last, _ = _signature(tokens, j)
                    if nested_first is not None:
                        j = nested_last + 1
                        continue
                effect = EFFECTS.get(word)
                if effect and (j == 0 or tokens[j - 1].value != ".") and effect not in declared:
                    diagnostics.append(Diagnostic(
                        tokens[j].line, "undeclared-effect",
                        f"{name} contains {word}; consider annotating {effect}"
                        f" (catch/trap handles only throw, not raise/panic)"))
                j += 1
            # Inspect nested named callables independently; never silently
            # omit them from the reported coverage count.
            i = first + 1
        else:
            i += 1
    return diagnostics, inspected
