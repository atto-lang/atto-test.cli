import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from oreslang_test.effects import EffectsInconclusive, analyze
from oreslang_test.cli import main


class EffectAnalyzerTests(unittest.TestCase):
    def test_distinct_keywords_are_advisory_and_line_numbered(self):
        source = """fnc work() -> void {
  throw new Error();
  raise new Error();
  panic new Error();
}
"""
        diagnostics, count = analyze(source)
        self.assertEqual(count, 1)
        self.assertEqual([d.line for d in diagnostics], [2, 3, 4])
        self.assertEqual([d.code for d in diagnostics], ["undeclared-effect"] * 3)
        for word in ("throws", "raises", "panics"):
            self.assertTrue(any(word in d.message for d in diagnostics))

    def test_postfix_annotations_on_functions_and_methods(self):
        source = """fnc load() -> User throws(IOError) raises(PermissionError) panics(InvariantError) {
  throw new IOError();
  raise new PermissionError();
  panic new InvariantError();
}
method commit() -> void raises {
  raise new Error();
}
"""
        diagnostics, count = analyze(source)
        self.assertEqual(count, 2)
        self.assertEqual(diagnostics, [])

    def test_quoted_strings_comments_and_imports_are_not_exceptions(self):
        source = '''import fnc build from "./utils";
fnc real() {
  let text = "panic raise throw fnc fake()";
  /* panic
     throw
  */
  // raise
  log("throws()");
}
'''
        diagnostics, count = analyze(source)
        self.assertEqual(count, 1)
        self.assertEqual(diagnostics, [])

    def test_duplicate_and_empty_annotation_diagnostics(self):
        diagnostics, count = analyze("fnc f() throws() throws(IOError) { throw new IOError(); }")
        self.assertEqual(count, 1)
        self.assertEqual({d.code for d in diagnostics},
                         {"duplicate-annotation", "empty-effect-types"})

    def test_incomplete_source_fails_closed(self):
        for source in ("fnc f() { panic new Error();",
                       'fnc f() { let s = "oops; }',
                       "fnc f() { /* not closed"):
            with self.subTest(source=source):
                with self.assertRaises(EffectsInconclusive):
                    analyze(source)

    def test_nested_callables_do_not_inherit_direct_effects(self):
        source = "fnc outer() { fnc inner() throws { throw new Error(); } return; }"
        diagnostics, count = analyze(source)
        self.assertEqual(count, 1)
        self.assertEqual(diagnostics, [])


class EffectCliTests(unittest.TestCase):
    def run_cli(self, root, *args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = main(["--root", str(root), *args])
        return status, output.getvalue(), error.getvalue()

    def test_advisory_and_strict_and_race_separation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.ores").write_text(
                "fnc f() { raise new Error(); }", encoding="utf-8")
            advisory = self.run_cli(root, "--effects", "--file", "sample.ores")
            self.assertEqual(advisory[0], 0)
            self.assertIn("EFFECT WARNING", advisory[1])
            self.assertIn("no call-graph/catch/actor-runtime proof", advisory[1])
            strict = self.run_cli(root, "--effects", "--effects-strict", "--file", "sample.ores")
            self.assertEqual(strict[0], 1)
            invalid = self.run_cli(root, "--effects", "--race", "--file", "sample.ores")
            self.assertEqual(invalid[0], 2)
            self.assertIn("separate static mode", invalid[2])

    def test_unclosed_lexical_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.ores").write_text("fnc f() { /* ", encoding="utf-8")
            status, _, err = self.run_cli(root, "--effects", "--file", "bad.ores")
            self.assertEqual(status, 2)
            self.assertIn("EFFECTS INCONCLUSIVE", err)

    def test_no_supported_callable_cannot_claim_clean_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bare.ores").write_text("// no body", encoding="utf-8")
            status, _, err = self.run_cli(root, "--effects", "--file", "bare.ores")
            self.assertEqual(status, 2)
            self.assertIn("no braced named", err)

    def test_file_scope_cannot_escape_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            status, _, err = self.run_cli(root, "--effects", "--file", "../outside.ores")
            self.assertEqual(status, 2)
            self.assertIn("project-relative", err)


if __name__ == "__main__":
    unittest.main()
