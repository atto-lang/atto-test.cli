import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from oreslang_test.cli import main


class AnalysisTests(unittest.TestCase):
    def run_project(self, source, command, flags=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test.ores').write_text(source)
            # TOML strings use JSON-compatible quoting for executable paths.
            import json
            (root / 'oreslang-test.toml').write_text('[analysis]\ncommand = ' + json.dumps([sys.executable, '-c', command]) + '\nfiles = ["test.ores"]\n')
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(['--root', directory, '--analyze', *flags])
            return code, out.getvalue(), err.getvalue()

    def test_reports_diagnostics_without_running_guest(self):
        code, out, err = self.run_project('panic "must not execute";', 'import sys; print("failure-suggestion", file=sys.stderr)')
        self.assertEqual(code, 0)
        self.assertIn('failure-suggestion', err)

    def test_failed_analysis_prevents_fuzz_execution(self):
        code, out, err = self.run_project('', 'import sys; sys.exit(1)', ['--fuzz'])
        self.assertEqual(code, 1)
        self.assertIn('ANALYSIS FAIL', out)
        self.assertNotIn('fuzz.command', err)

    def test_analysis_timeout_fails(self):
        code, out, _ = self.run_project('', 'import time; time.sleep(1)', ['--timeout', '0.01'])
        self.assertEqual(code, 1)
        self.assertIn('TIMEOUT', out)

    def test_missing_compiler_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test.ores').write_text('')
            (root / 'oreslang-test.toml').write_text('[analysis]\ncommand = ["/nonexistent/oreslang"]\n')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['--root', directory, '--analyze']), 2)

    def test_malformed_analysis_configuration_returns_usage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'oreslang-test.toml').write_text('analysis = 1\n')
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(main(['--root', directory, '--analyze']), 2)
            self.assertIn('TOML table', err.getvalue())

    def test_discovery_prunes_ignored_and_symlink_directories(self):
        from unittest.mock import patch
        from oreslang_test.cli import analyze
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'source.ores').write_text('')
            for name in ['target', 'node_modules', '.hidden']:
                (root / name).mkdir()
                (root / name / 'ignored.ores').write_text('')
            (root / 'linked').symlink_to(root / 'target', target_is_directory=True)
            import subprocess
            with patch('oreslang_test.cli._run', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as run:
                self.assertEqual(analyze(root, {}, 1), 0)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0][-1], str(root / 'source.ores'))


if __name__ == '__main__':
    unittest.main()
