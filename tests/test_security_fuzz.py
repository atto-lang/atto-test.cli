import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from oreslang_test.cli import main


class ProcessBoundaryTests(unittest.TestCase):
    def call(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = main(args)
        return result, out.getvalue(), err.getvalue()

    def create_harness(self, root, body):
        root = Path(root)
        (root / "harness.py").write_text(body, encoding="utf8")
        (root / "oreslang-test.toml").write_text(
            '[fuzz]\ncommand = ["' + sys.executable + '", "harness.py"]\nmax_bytes = 512\n',
            encoding="utf8")

    def test_security_seed_profile_catches_harness_invariant(self):
        with tempfile.TemporaryDirectory() as d:
            self.create_harness(d,
                'import sys\nx = sys.stdin.buffer.read()\nsys.exit(9 if b"../../etc/passwd" in x else 0)\n')
            status, out, err = self.call("--root", d, "--fuzz", "--fuzz-profile",
                                         "security", "--seed", "42", "--cases", "12")
            self.assertEqual(status, 1, err)
            self.assertIn("FUZZ FAILURE seed=42", out)

    def test_security_profile_requires_fuzz(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(2, self.call("--root", d, "--fuzz-profile", "security")[0])

    def test_host_credentials_not_inherited_without_opt_in(self):
        with tempfile.TemporaryDirectory() as d:
            self.create_harness(d,
                'import os,sys\nsys.stdin.buffer.read()\nsys.exit(12 if "ORES_TEST_PRIVATE_TOKEN" in os.environ else 0)\n')
            old = os.environ.get("ORES_TEST_PRIVATE_TOKEN")
            os.environ["ORES_TEST_PRIVATE_TOKEN"] = "should-never-reach-guest"
            try:
                status, out, err = self.call("--root", d, "--fuzz", "--cases", "3")
                self.assertEqual(status, 0, (out, err))
                status, out, err = self.call("--root", d, "--fuzz", "--cases", "3",
                                             "--inherit-env")
                self.assertEqual(status, 1, (out, err))
            finally:
                if old is None:
                    os.environ.pop("ORES_TEST_PRIVATE_TOKEN", None)
                else:
                    os.environ["ORES_TEST_PRIVATE_TOKEN"] = old


if __name__ == "__main__":
    unittest.main()
