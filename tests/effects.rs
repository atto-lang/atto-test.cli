use oreslang_test::effects::analyze;

#[test]
fn golden_direct_effect_diagnostics() {
    let report = analyze("fnc work() -> void {\n  throw new Error();\n  raise new Error();\n  panic new Error();\n}\n").unwrap();
    assert_eq!(report.inspected, 1);
    let actual = report
        .diagnostics
        .iter()
        .map(|d| format!("{} [{}] {}\n", d.line, d.code, d.message))
        .collect::<String>();
    let expected = include_str!("fixtures/effects-direct.txt").replace("\r\n", "\n");
    assert_eq!(actual, expected);
}

#[test]
fn golden_postfix_annotations_and_optional_clauses() {
    let report = analyze("fnc load() -> User throws(IOError) raises(PermissionError) panics(InvariantError) {\n throw new IOError(); raise new PermissionError(); panic new InvariantError();\n}\nmethod commit() -> void raises { raise new Error(); }").unwrap();
    assert_eq!(report.inspected, 2);
    assert!(report.diagnostics.is_empty());
}

#[test]
fn comments_literals_and_callable_imports_are_masked() {
    let source = "import fnc build from \"./utils\";\nfnc real() {\n let text = \"panic raise throw fnc fake()\";\n /* panic\n throw */\n // raise\n log(\"throws()\");\n}";
    let report = analyze(source).unwrap();
    assert_eq!(report.inspected, 1);
    assert!(report.diagnostics.is_empty());
}

#[test]
fn duplicate_and_empty_annotations_remain_warnings() {
    let report = analyze("fnc f() throws() throws(IOError) { throw new IOError(); }").unwrap();
    assert_eq!(report.inspected, 1);
    assert_eq!(
        report
            .diagnostics
            .iter()
            .map(|d| d.code)
            .collect::<Vec<_>>(),
        vec!["empty-effect-types", "duplicate-annotation"]
    );
}

#[test]
fn incomplete_source_is_inconclusive() {
    for source in [
        "fnc f() { panic new Error();",
        "fnc f() { let s = \"oops; }",
        "fnc f() { /* not closed",
        "fnc f() { ] }",
        "fnc f(",
        "fnc f() { `bad\\",
    ] {
        assert!(analyze(source).is_err(), "{source}");
    }
}

#[test]
fn nested_named_callables_have_separate_scopes() {
    let report =
        analyze("fnc outer() { fnc inner() throws { throw new Error(); } return; }").unwrap();
    assert_eq!(report.inspected, 2);
    assert!(report.diagnostics.is_empty());
    let report =
        analyze("fnc outer() throws { fnc inner() { raise new Error(); } panic new Error(); }")
            .unwrap();
    assert_eq!(report.inspected, 2);
    assert_eq!(report.diagnostics.len(), 2);
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.starts_with("inner contains raise")));
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.starts_with("outer contains panic")));
}

#[test]
fn qualified_calls_are_not_exception_statements() {
    let report =
        analyze("fnc f() { obj.raise(); obj.panic(); obj.throw(); obj.method(); }").unwrap();
    assert_eq!(report.inspected, 1);
    assert!(report.diagnostics.is_empty());
}

#[test]
fn handles_bare_static_and_explicit_receiver_methods() {
    let source = "define class Worker as {\n pub load() -> void raises { raise new Error(); }\n pub save(mut self)() -> void panics { panic new Error(); }\n pub static fnc create() -> Worker throws { throw new Error(); }\n method receive(self Worker)() throws { throw new Error(); }\n}";
    let report = analyze(source).unwrap();
    assert_eq!(report.inspected, 4);
    assert!(report.diagnostics.is_empty());
}

#[test]
fn bare_methods_in_end_classes_and_calls_inside_methods() {
    let report = analyze(
        "define class Worker as\n pub commit() -> void { other.commit(); raise new Error(); }\nend",
    )
    .unwrap();
    assert_eq!(report.inspected, 1);
    assert_eq!(report.diagnostics.len(), 1);
}

#[test]
fn generic_named_lambda_and_routine_declarations() {
    let report = analyze("fnc f<T = String>(x: T) -> T throws { throw new Error(); }\nfnc g = |int x| -> void raises { raise new Error(); }\nroutine run() panics { panic new Error(); }").unwrap();
    assert_eq!(report.inspected, 3);
    assert!(report.diagnostics.is_empty());
}

#[test]
fn signatures_are_not_counted_as_executable_bodies() {
    let report = analyze("method load() => User throws(NetworkError);").unwrap();
    assert_eq!(report.inspected, 0);
    assert!(report.diagnostics.is_empty());
}

#[test]
fn raise_and_panic_in_try_trap_and_defer_are_never_silenced() {
    let report = analyze("fnc f() { try { raise new Error(); panic new Error(); } catch e { log(e); } defer cleanup(); }").unwrap();
    assert_eq!(report.diagnostics.len(), 2);
    assert!(report
        .diagnostics
        .iter()
        .all(|d| d.message.contains("catch/trap handles only throw")));
}

#[test]
fn closures_and_interpolation_cannot_be_certified_empty() {
    for source in [
        "fnc f() { let x = |v| -> { panic new Error(); }; }",
        "fnc f() { const x = (v) => { raise new Error(); }; }",
        "fnc f() { log(`${panic new Error()}`); }",
    ] {
        assert!(analyze(source).is_err(), "{source}");
    }
}

#[test]
fn malformed_effect_type_lists_fail_closed() {
    for clause in [
        "throws(,)",
        "raises(Error,)",
        "panics(Error Error)",
        "throws(\"Error\")",
        "raises(42)",
        "throws(Error.)",
    ] {
        assert!(
            analyze(&format!("fnc f() {clause} {{}} ")).is_err(),
            "{clause}"
        );
    }
}

#[test]
fn literal_escaping_and_line_numbers() {
    let report = analyze(
        "fnc f() { let s = \"escaped \\\" panic\";\n /* raise\n panic */\n raise new Error(); }",
    )
    .unwrap();
    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(report.diagnostics[0].line, 4);
}

#[test]
fn unicode_callable_names_and_crlf() {
    let report = analyze("fnc café() {\r\n raise new Error();\r\n}").unwrap();
    assert_eq!(report.inspected, 1);
    assert_eq!(report.diagnostics[0].line, 2);
}

#[test]
fn bounded_source_and_nesting() {
    assert!(analyze(&" ".repeat(262_145)).is_err());
    assert!(analyze(&format!(
        "fnc f() {{ {} {} }}",
        "(".repeat(300),
        ")".repeat(300)
    ))
    .is_err());
}

#[test]
fn record_return_types_and_uninspected_scopes_fail_closed() {
    for source in [
        "fnc f() -> {x: int} { raise new Error(); }",
        "fnc f() -> Box<{x: int}> { raise new Error(); }",
        "fnc f() {} raise new Error();",
        "define class C as { val cb = |x| -> { panic new Error(); }; f() {} }",
    ] {
        assert!(analyze(source).is_err(), "{source}");
    }
}

#[test]
fn named_void_lambda_body_is_counted() {
    let report = analyze("fnc f = || -> { raise new Error(); }").unwrap();
    assert_eq!(report.inspected, 1);
    assert_eq!(report.diagnostics.len(), 1);
}

#[test]
fn migrated_hardening_qualified_markers_and_all_quote_interpolation() {
    let report = analyze("fnc f() { obj.method(); obj.fnc(); obj.raise(); obj.panic(); }").unwrap();
    assert_eq!(report.inspected, 1);
    assert!(report.diagnostics.is_empty());
    for quote in ['"', '`', '\''] {
        assert!(analyze(&format!(
            "fnc f() {{ return {quote}${{panic new Error()}}{quote}; }}"
        ))
        .is_err());
    }
}

#[test]
fn migrated_hardening_opaque_delimiters_and_nested_scope() {
    let report = analyze("fnc f() {\n let s = \"panic } raise ( throw\";\n // }\n /* ( throw { */\n throw new Error();\n}").unwrap();
    assert_eq!(report.inspected, 1);
    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(report.diagnostics[0].line, 5);
    let report = analyze("fnc outer() throws {\n fnc inner() panics {\n panic new Error();\n }\n throw new Error();\n}").unwrap();
    assert_eq!(report.inspected, 2);
    assert!(report.diagnostics.is_empty());
    let report = analyze("fnc outer() { fnc inner() { raise new Error(); } }").unwrap();
    assert_eq!(report.diagnostics.len(), 1);
    assert!(report.diagnostics[0]
        .message
        .starts_with("inner contains raise"));
}

#[test]
fn migrated_hardening_generic_returns_and_comment_newlines() {
    let report =
        analyze("fnc get<T>(x: T) -> Result<T, Error> throws(IOError) { throw new IOError(); }")
            .unwrap();
    assert_eq!(report.inspected, 1);
    assert!(report.diagnostics.is_empty());
    let report = analyze("fnc x() {\r\n // panic\r\n raise new Error();\r\n}\r\n").unwrap();
    assert_eq!(report.diagnostics[0].line, 3);
}

#[test]
fn migrated_hardening_token_limit_and_whole_file_balance() {
    for source in [
        "fnc f() { throw new Error(); } }",
        "fnc f() { throw new Error();",
        "fnc f((x: int) { }",
        "fnc f() { } )",
    ] {
        assert!(analyze(source).is_err(), "{source}");
    }
    assert!(analyze(&format!("fnc f() {{ {} }}", "a; ".repeat(12_501))).is_err());
}

#[test]
fn deterministic_5000_case_malformed_input_fuzz_never_panics() {
    let words = [
        "fnc", "method", "throw", "raise", "panic", "throws", "raises", "panics", "abc", "def",
        "123", ";", "{", "}", "(", ")", "\"", "'", "/", "*", "\\", "$", "`", ",", ".",
    ];
    let mut state = 419u64;
    let mut accepted = 0;
    let mut rejected = 0;
    for _ in 0..5_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let count = (state >> 32) as usize % 34 + 1;
        let mut source = String::from("fnc f() { ");
        for _ in 0..count {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            source.push_str(words[(state >> 32) as usize % words.len()]);
            source.push(' ');
        }
        source.push('}');
        match analyze(&source) {
            Ok(_) => accepted += 1,
            Err(_) => rejected += 1,
        }
    }
    assert_eq!(accepted + rejected, 5_000);
    assert!(accepted > 0);
    assert!(rejected > 0);
}

#[test]
fn nested_comments_symbols_and_nul_follow_compiler_lexical_boundaries() {
    let report = analyze("fnc f() { /* outer /* inner */ panic raise throw */ let s = #panic; let t = #raise; raise new Error(); }").unwrap();
    assert_eq!(report.diagnostics.len(), 1);
    assert!(report.diagnostics[0].message.contains("contains raise"));
    assert!(analyze("fnc f() {} /* a /* b */").is_err());
    assert!(analyze("fnc f() { let s = \"\0\"; }").is_err());
}
