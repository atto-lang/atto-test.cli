import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from oreslang_test.audit import analyze, run, AuditError
from oreslang_test.cli import main


class AuditTests(unittest.TestCase):
    def project(self, root, code):
        p = Path(root)
        (p / "src").mkdir(exist_ok=True)
        (p / "src/main.ores").write_text(code, encoding="utf8")
        (p / "oreslang-test.toml").write_text("", encoding="utf8")
        return p

    def call(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = main(args)
        return status, out.getvalue(), err.getvalue()

    def test_security_detection_and_no_secret_leak(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.project(d, """// secret = "do-not-report-secret!"
let api_key = "topsecretvalue1234";
let url = "http://example.org/api";
let loopback = "http://localhost:1234";
let loopback_ipv6 = "http://[::1]:8080/";
crypto.md5(input);
shell.exec(command);
let safe = "// this is not a code comment";
""")
            report = analyze(p, security=True, anti_patterns=False)
            self.assertEqual([f["rule"] for f in report["findings"]],
                             ["SEC001", "SEC003", "SEC002", "SEC004"])
            status, out, err = self.call("--root", d, "--security", "--audit-format", "json")
            self.assertEqual(status, 1, err)
            self.assertNotIn("topsecretvalue1234", out)
            self.assertEqual(json.loads(out)["failing_findings"], 3)

    def test_detects_antipatterns_ignores_comments_and_literals(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.project(d, """// catch {} while true {}
let s = "catch {} while true {}";
catch(error) { /* silence */ }
recover { }
while (true) { compute(); }
while true { await receive(); }
""")
            report = analyze(p, security=False, anti_patterns=True)
            self.assertEqual([f["rule"] for f in report["findings"]],
                             ["ANTI001", "ANTI001", "ANTI002"])

    def test_missing_sources_inconclusive(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(AuditError, "no Oreslang"):
                analyze(d)

    def test_bad_source_inconclusive(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.project(d, 'let x = "unclosed')
            with self.assertRaisesRegex(AuditError, "unterminated string"):
                analyze(p)

    def test_nested_comment_and_malicious_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.project(d, '/* /* secret = "foofoofoo" */ still comment */\nlet x = 2;')
            self.assertFalse(analyze(p)["findings"])
            (p / "src/sym.ores").symlink_to(p / "src/main.ores")
            with self.assertRaisesRegex(AuditError, "symlinked"):
                analyze(p)

    def test_symlink_directory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.project(d, "let x = 2;")
            (p / "alias").symlink_to(p / "src", target_is_directory=True)
            with self.assertRaisesRegex(AuditError, "symlinked audit directory"):
                analyze(p)

    def test_static_scan_does_not_require_parseable_runtime_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.project(d, 'let website = "http://example.org";')
            (p / "oreslang-test.toml").write_text("broken = [", encoding="utf8")
            status, out, err = self.call("--root", d, "--audit", "--audit-format", "json")
            self.assertEqual(status, 0, err)
            self.assertEqual(json.loads(out)["files_scanned"], 1)

    def test_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.project(d, "let x = 2;")
            with self.assertRaises(AuditError):
                analyze(p, files=["../outside.ores"])

    def test_threshold_and_advisory_pass(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.project(d, 'let website = "http://example.org";')
            status, out, _ = self.call("--root", d, "--security", "--fail-on", "medium")
            self.assertEqual(status, 0)
            self.assertIn("not a vulnerability-free certification", out)
            status, out, _ = self.call("--root", d, "--audit", "--fail-on", "low")
            self.assertEqual(status, 1)

    def test_explicit_files_and_excluded_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.project(d, "let x = 2;")
            (p / "target").mkdir()
            (p / "target/bad.ores").write_text('let api_key = "hardcodedkey1234";')
            self.assertEqual(1, analyze(p)["files_scanned"])
            self.assertEqual(1, analyze(p, files=["target/bad.ores"])["files_scanned"])
            status, out, err = self.call("--root", d, "--security", "--audit-file", "target/bad.ores")
            self.assertEqual(status, 1, err)

    def test_utf8_invalid_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.project(d, "let x = 2;")
            (p / "src/main.ores").write_bytes(b"\xff")
            with self.assertRaisesRegex(AuditError, "invalid UTF-8"):
                analyze(p)

    def test_invalid_mode_combination_and_paths(self):
        with tempfile.TemporaryDirectory() as d:
            self.project(d, "let x = 2;")
            self.assertEqual(2, self.call("--root", d, "--audit", "--fuzz")[0])
            self.assertEqual(2, self.call("--root", d, "--audit-file", "src/main.ores")[0])
            self.assertEqual(2, self.call("--root", d, "--security",
                                         "--audit-file", "../escape.ores")[0])


if __name__ == "__main__":
    unittest.main()
