//! Advisory source hints, never compiler admission or a no-effect certificate.
use std::collections::BTreeSet;

pub const MAX_SOURCE: usize = 262_144;
const MAX_TOKENS: usize = 25_000;
const MAX_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub line: usize,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub diagnostics: Vec<Diagnostic>,
    pub inspected: usize,
}

#[derive(Debug)]
struct Token {
    text: String,
    line: usize,
    parent: Option<usize>,
    close: Option<usize>,
}

fn lex(source: &str) -> Result<Vec<Token>, String> {
    if source.len() > MAX_SOURCE {
        return Err("source exceeds 256 KiB analysis bound".into());
    }
    if source.contains('\0') {
        return Err("source contains NUL byte".into());
    }
    let chars: Vec<char> = source.chars().collect();
    let mut result: Vec<Token> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut i = 0;
    let mut line = 1;
    while i < chars.len() {
        if result.len() >= MAX_TOKENS {
            return Err("token budget exceeded".into());
        }
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c.is_whitespace() {
            if c == '\n' {
                line += 1;
            }
            i += 1;
            continue;
        }
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let start = line;
            let mut depth = 1;
            i += 2;
            while i + 1 < chars.len() && depth > 0 {
                if chars[i] == '\n' {
                    line += 1;
                }
                if chars[i] == '/' && chars[i + 1] == '*' {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err("comment nesting budget exceeded".into());
                    }
                    i += 2;
                } else if chars[i] == '*' && chars[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if depth > 0 {
                return Err(format!("unterminated block comment at line {start}"));
            }
            continue;
        }
        if c == '#' && next.is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_') {
            i += 2;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            result.push(Token {
                text: "$symbol$".into(),
                line,
                parent: stack.last().copied(),
                close: None,
            });
            continue;
        }
        if matches!(c, '\'' | '"' | '`') {
            let start = line;
            i += 1;
            let mut closed = false;
            while i < chars.len() {
                if chars[i] == '\n' {
                    line += 1;
                }
                if chars[i] == '\\' {
                    if chars.get(i + 1) == Some(&'\n') {
                        line += 1;
                    }
                    i += 2;
                    continue;
                }
                if chars[i] == '$' && chars.get(i + 1) == Some(&'{') {
                    return Err(format!(
                        "template interpolation is outside advisory coverage at line {line}"
                    ));
                }
                if chars[i] == c {
                    i += 1;
                    closed = true;
                    break;
                }
                i += 1;
            }
            if !closed {
                return Err(format!("unterminated string at line {start}"));
            }
            // Retain a literal sentinel so effect clauses cannot erase string operands.
            result.push(Token {
                text: "$literal$".into(),
                line: start,
                parent: stack.last().copied(),
                close: None,
            });
            continue;
        }
        let start = i;
        if c.is_alphabetic() || c == '_' {
            i += 1;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
        } else if (c == '-' || c == '=') && next == Some('>') {
            i += 2;
        } else {
            i += 1;
        }
        let text: String = chars[start..i].iter().collect();
        let index = result.len();
        let parent = stack.last().copied();
        result.push(Token {
            text: text.clone(),
            line,
            parent,
            close: None,
        });
        if result.len() > MAX_TOKENS {
            return Err("token budget exceeded".into());
        }
        if matches!(text.as_str(), "(" | "{" | "[") {
            if stack.len() >= MAX_DEPTH {
                return Err("delimiter nesting budget exceeded".into());
            }
            stack.push(index);
        } else if matches!(text.as_str(), ")" | "}" | "]") {
            let Some(open) = stack.pop() else {
                return Err(format!("unexpected {text} at line {line}"));
            };
            let expected = match result[open].text.as_str() {
                "(" => ")",
                "{" => "}",
                "[" => "]",
                _ => unreachable!(),
            };
            if expected != text {
                return Err(format!("mismatched {text} at line {line}"));
            }
            result[open].close = Some(index);
        }
    }
    if let Some(open) = stack.last() {
        return Err(format!(
            "unbalanced {} at line {}",
            result[*open].text, result[*open].line
        ));
    }
    Ok(result)
}

fn ident(word: &str) -> bool {
    let mut chars = word.chars();
    chars.next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && chars.all(|c| c.is_alphanumeric() || c == '_')
}

fn effect(word: &str) -> Option<&'static str> {
    match word {
        "throw" => Some("throws"),
        "raise" => Some("raises"),
        "panic" => Some("panics"),
        _ => None,
    }
}

fn annotation(word: &str) -> bool {
    matches!(word, "throws" | "raises" | "panics")
}

fn word(tokens: &[Token], i: usize) -> &str {
    tokens.get(i).map_or("", |t| t.text.as_str())
}

#[derive(Debug)]
struct Callable {
    name: String,
    start: usize,
    body: Option<(usize, usize)>,
    end: usize,
    declared: BTreeSet<String>,
    diagnostics: Vec<Diagnostic>,
}

fn signature(tokens: &[Token], start: usize, name_index: usize) -> Result<Callable, String> {
    let fail = || {
        format!(
            "unsupported callable signature at line {}",
            tokens[start].line
        )
    };
    if !ident(word(tokens, name_index)) {
        Err(fail())
    }
    let name = word(tokens, name_index).to_string();
    let mut i = name_index + 1;
    let mut named_lambda = false;
    if word(tokens, i) == "<" {
        let mut depth = 1;
        i += 1;
        while i < tokens.len() && depth > 0 {
            match word(tokens, i) {
                "<" => depth += 1,
                ">" => depth -= 1,
                "{" | ";" => return Err(fail()),
                _ => {}
            }
            i += 1;
        }
        if depth != 0 {
            return Err(fail());
        }
    }
    // The compiler also permits `fnc name = |Type arg| -> Type { ... }`.
    if word(tokens, i) == "=" && word(tokens, i + 1) == "|" {
        named_lambda = true;
        i += 2;
        while i < tokens.len() && !matches!(word(tokens, i), "|" | "{" | ";") {
            i += 1;
        }
        if word(tokens, i) != "|" || word(tokens, i + 1) != "->" {
            return Err(fail());
        }
        i += 2;
    } else {
        if word(tokens, i) != "(" {
            return Err(fail());
        }
        i = tokens[i].close.ok_or_else(fail)? + 1;
        // Explicit read/mutable receiver has a second parameter list.
        if word(tokens, i) == "(" {
            i = tokens[i].close.ok_or_else(fail)? + 1;
        }
    }
    let mut declared = BTreeSet::new();
    let mut diagnostics = Vec::new();
    let mut type_depth = 0usize;
    while i < tokens.len() {
        let text = word(tokens, i);
        if text == "<" {
            type_depth += 1;
        } else if text == ">" {
            type_depth = type_depth.saturating_sub(1);
        }
        if matches!(text, "{" | ";") {
            let previous = i.checked_sub(1).map_or("", |p| word(tokens, p));
            if text == "{"
                && (type_depth > 0
                    || matches!(previous, "struct" | "record" | ":")
                    || (previous == "->" && !named_lambda))
            {
                return Err(format!(
                    "record return type outside advisory coverage at line {}",
                    tokens[i].line
                ));
            }
            let body = if text == "{" {
                Some((i, tokens[i].close.ok_or_else(fail)?))
            } else {
                None
            };
            return Ok(Callable {
                name,
                start,
                end: body.map_or(i, |(_, end)| end),
                body,
                declared,
                diagnostics,
            });
        }
        if annotation(text) {
            if !declared.insert(text.to_string()) {
                diagnostics.push(Diagnostic {
                    line: tokens[i].line,
                    code: "duplicate-annotation",
                    message: format!("duplicate {text} on {name}"),
                });
            }
            if word(tokens, i + 1) == "(" {
                let end = tokens[i + 1].close.ok_or_else(fail)?;
                if end == i + 2 {
                    diagnostics.push(Diagnostic {
                        line: tokens[i].line,
                        code: "empty-effect-types",
                        message: format!(
                            "{text}() has no Error types; use {text} or {text}(ErrorType)"
                        ),
                    });
                } else {
                    // Finite nominal type-name lists; inheritance is compiler-owned.
                    let mut expect_name = true;
                    for token in &tokens[i + 2..end] {
                        if expect_name && ident(&token.text) {
                            expect_name = false;
                        } else if !expect_name && matches!(token.text.as_str(), "," | ".") {
                            expect_name = true;
                        } else {
                            return Err(format!(
                                "unsupported effect type list at line {}",
                                token.line
                            ));
                        }
                    }
                    if expect_name {
                        return Err(format!(
                            "unfinished effect type list at line {}",
                            tokens[i].line
                        ));
                    }
                }
                i = end + 1;
                continue;
            }
        } else if matches!(text, "(" | "[") {
            i = tokens[i].close.ok_or_else(fail)? + 1;
            continue;
        } else if matches!(text, "fnc" | "method" | "routine" | "}" | "end" | "=") {
            return Err(fail());
        }
        i += 1;
    }
    return Err(fail());
}

/// Class member ranges for recognizing optional `method` without treating calls as declarations.
fn class_members(tokens: &[Token]) -> Result<Vec<(usize, usize, Option<usize>)>, String> {
    let mut ranges = Vec::new();
    let mut budget = 1_000_000usize;
    for (i, token) in tokens.iter().enumerate() {
        if token.text != "class"
            || matches!(
                i.checked_sub(1).map(|p| word(tokens, p)),
                Some("import" | ".")
            )
        {
            continue;
        }
        // `import class X from ...` is a use, never a class body.
        let mut header = i + 1;
        while header < tokens.len() && !matches!(word(tokens, header), "as" | ";" | "from" | "{") {
            budget = budget
                .checked_sub(1)
                .ok_or("class header budget exceeded")?;
            header += 1;
        }
        if word(tokens, header) != "as" {
            continue;
        }
        if word(tokens, header + 1) == "{" {
            let first = header + 1;
            ranges.push((first + 1, tokens[first].close.unwrap(), Some(first)));
        } else {
            let parent = tokens[i].parent;
            let mut last = header + 1;
            while last < tokens.len()
                && !(word(tokens, last) == "end" && tokens[last].parent == parent)
            {
                budget = budget.checked_sub(1).ok_or("class body budget exceeded")?;
                last += 1;
            }
            if last == tokens.len() {
                return Err(format!("unfinished class at line {}", tokens[i].line));
            }
            ranges.push((header + 1, last, parent));
        }
    }
    Ok(ranges)
}

pub fn analyze(source: &str) -> Result<Report, String> {
    let tokens = lex(source)?;
    let ranges = class_members(&tokens)?;
    let mut members = vec![false; tokens.len()];
    let mut range_budget = 1_000_000usize;
    for (first, last, parent) in ranges {
        range_budget = range_budget
            .checked_sub(last - first)
            .ok_or("class range budget exceeded")?;
        for i in first..last {
            members[i] |= tokens[i].parent == parent;
        }
    }
    let mut callables = Vec::new();
    let mut signature_end = 0;
    for (i, is_member) in members.iter().enumerate() {
        if i < signature_end {
            continue;
        }
        let text = word(&tokens, i);
        let previous = i.checked_sub(1).map_or("", |p| word(&tokens, p));
        if matches!(text, "fnc" | "method" | "routine") && !matches!(previous, "." | "import" | ":")
        {
            let callable = signature(&tokens, i, i + 1)?;
            signature_end = callable
                .body
                .map_or(callable.end + 1, |(first, _)| first + 1);
            callables.push(callable);
        } else if ident(text)
            && matches!(word(&tokens, i + 1), "(" | "<")
            && *is_member
            && !matches!(
                previous,
                "." | "=" | ":" | "@" | "fnc" | "method" | "routine"
            )
            && !matches!(text, "throws" | "raises" | "panics" | "new")
        {
            let callable = signature(&tokens, i, i)?;
            signature_end = callable
                .body
                .map_or(callable.end + 1, |(first, _)| first + 1);
            callables.push(callable);
        }
    }
    let mut report = Report {
        diagnostics: Vec::new(),
        inspected: 0,
    };
    let mut starts = vec![None; tokens.len()];
    let mut covered = vec![false; tokens.len()];
    for (index, callable) in callables.iter().enumerate() {
        starts[callable.start] = Some(index);
    }
    for callable in &callables {
        report.diagnostics.extend(callable.diagnostics.clone());
        let Some((first, last)) = callable.body else {
            continue;
        };
        report.inspected += 1;
        let mut i = first + 1;
        while i < last {
            if let Some(nested) = starts[i].map(|index| &callables[index]) {
                i = nested.end + 1;
                continue;
            }
            covered[i] = true;
            let text = word(&tokens, i);
            if text == "|" || text == "=>" {
                // An anonymous invocation has its own effect scope. Do not attach
                // its failure to the enclosing caller or certify that scope empty.
                return Err(format!(
                    "anonymous callable or pipe expression outside advisory coverage at line {}",
                    tokens[i].line
                ));
            }
            if let Some(effect) = effect(text) {
                if (i == 0 || !matches!(word(&tokens, i - 1), "." | ":"))
                    && !callable.declared.contains(effect)
                {
                    report.diagnostics.push(Diagnostic { line: tokens[i].line, code: "undeclared-effect",
                            message: format!("{} contains {text}; consider annotating {effect} (catch/trap handles only throw, not raise/panic)", callable.name) });
                }
            }
            i += 1;
        }
    }
    for (i, token) in tokens.iter().enumerate() {
        if effect(&token.text).is_some()
            && !covered[i]
            && (i == 0 || !matches!(word(&tokens, i - 1), "." | ":"))
        {
            return Err(format!(
                "uninspected exceptional-effect scope at line {}",
                token.line
            ));
        }
    }
    report.diagnostics.sort_by_key(|d| d.line);
    Ok(report)
}
