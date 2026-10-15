"""Adversarial regression gates for the bounded advisory effects scanner."""
from pathlib import Path
import random
import sys
import tempfile
import unittest
import io
import contextlib

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from oreslang_test.effects import EffectsInconclusive, analyze
from oreslang_test.cli import main


class EffectsHardeningTests(unittest.TestCase):
    def test_qualified_methods_not_mistaken_for_declarations(self):
        src = "fnc f() { obj.method(); obj.fnc(); obj.raise(); obj.panic(); }"
        problems, count = analyze(src)
        self.assertEqual(count, 1)
        self.assertEqual(problems, [])

    def test_unbalanced_delimiters_in_any_part_of_file_are_inconclusive(self):
        cases = (
            "fnc f() { throw new Error(); } }",
            "fnc f() { throw new Error();",
            "fnc f((x: int) { }",
            "fnc f() { } )",
        )
        for src in cases:
            with self.subTest(src=src), self.assertRaises(EffectsInconclusive):
                analyze(src)

    def test_interpolation_does_not_hide_executable_effects(self):
        for quote in ('"', chr(96)):
            src = "fnc f() { return " + quote + chr(36) + "{panic new Error()}" + quote + "; }"
            with self.subTest(quote=quote), self.assertRaisesRegex(
                    EffectsInconclusive, "interpolated"):
                analyze(src)

    def test_literal_braces_and_comment_delimiters_are_opaque(self):
        source = """fnc f() {
  let s = "panic } raise ( throw";
  // }
  /* ( throw {  */
  throw new Error();
}
"""
        problems, count = analyze(source)
        self.assertEqual(count, 1)
        self.assertEqual([x.line for x in problems], [5])

    def test_nested_effects_count_once_per_callable(self):
        src = """fnc outer() throws {
 fnc inner() panics {
  panic new Error();
 }
 throw new Error();
}
"""
        problems, count = analyze(src)
        self.assertEqual(count, 2)
        self.assertEqual(problems, [])

    def test_nested_unannotated_effect_is_attributed_to_inner(self):
        src = "fnc outer() { fnc inner() { raise new Error(); } }"
        problems, count = analyze(src)
        self.assertEqual(count, 2)
        self.assertEqual(len(problems), 1)
        self.assertIn("inner contains raise", problems[0].message)
        self.assertNotIn("outer contains raise", problems[0].message)

    def test_generic_signature_annotations(self):
        src = "fnc get<T>(x: T) -> Result<T, Error> throws(IOError) { throw new IOError(); }"
        problems, count = analyze(src)
        self.assertEqual((problems, count), ([], 1))

    def test_comment_ending_and_newline_counts(self):
        src = "fnc x() {\r\n // panic\r\n raise new Error();\r\n}\r\n"
        problems, count = analyze(src)
        self.assertEqual(count, 1)
        self.assertEqual([p.line for p in problems], [3])

    def test_deterministic_random_malformed_input_never_crashes(self):
        rng = random.Random(419)
        tokens = ("fnc", "method", "throw", "raise", "panic", "throws",
                  "raises", "panics", "abc", "def", "123", ";", "{",
                  "}", "(", ")", '"', "'", "/", "*", chr(92), "$",
                  chr(96), ",", ".")
        accepted = 0
        rejected = 0
        for _ in range(5000):
            src = "fnc f() { " + " ".join(
                rng.choice(tokens) for _ in range(rng.randrange(1, 35))) + " }"
            try:
                analyze(src)
                accepted += 1
            except EffectsInconclusive:
                rejected += 1
        self.assertEqual(accepted + rejected, 5000)
        self.assertGreater(rejected, 0)
        self.assertGreater(accepted, 0)


class EffectScannerBudgetTests(unittest.TestCase):
    def invoke(self, root, *flags):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = main(["--root", str(root), "--effects", *flags])
        return status, out.getvalue(), err.getvalue()

    def test_caps_warning_output_without_losing_true_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "warnings.ores").write_text(
                "fnc f() {\n" + "panic new Error();\n" * 150 + "}\n", encoding="utf8")
            status, out, err = self.invoke(root, "--effects-strict", "--file", "warnings.ores")
            self.assertEqual(status, 1, err)
            self.assertEqual(out.count("EFFECT WARNING warnings.ores:"), 100)
            self.assertIn("EFFECT WARNINGS TRUNCATED shown=100 total=150", out)
            self.assertIn("warnings=150", out)

    def test_rejects_large_token_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.ores").write_text(
                "fnc f(){ " + "panic " * 25001 + "}", encoding="utf8")
            status, _, err = self.invoke(root, "--file", "large.ores")
            self.assertEqual(status, 2)
            self.assertIn("25000-token analysis budget", err)

    def test_directory_discovery_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for n in range(513):
                (root / f"sample_{n}.ores").write_text("fnc f() {}\n", encoding="utf8")
            status, _, err = self.invoke(root)
            self.assertEqual(status, 2)
            self.assertIn("exceeds 512 source files", err)

    def test_hidden_source_is_not_included_during_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "valid.ores").write_text("fnc f() {}\n", encoding="utf8")
            (root / ".hidden.ores").write_text("fnc f() { panic new Error(); }\n", encoding="utf8")
            status, out, err = self.invoke(root)
            self.assertEqual(status, 0, err)
            self.assertIn("warnings=0", out)

    def test_aggregate_source_bytes_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            src = 'fnc f() { let value = "' + ("x" * 249900) + '"; }\n'
            file_args = []
            for n in range(17):
                name = f"source_{n}.ores"
                (root / name).write_text(src, encoding="utf8")
                file_args.extend(("--file", name))
            status, _, err = self.invoke(root, *file_args)
            self.assertEqual(status, 2)
            self.assertIn("4 MB aggregate source budget", err)


if __name__ == "__main__":
    unittest.main()
