"""Adversarial regression gates for the bounded advisory effects scanner."""
from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from oreslang_test.effects import EffectsInconclusive, analyze


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


if __name__ == "__main__":
    unittest.main()
