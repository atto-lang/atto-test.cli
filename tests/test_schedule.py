"""Schedule-runner CLI delegation contract; stub is not guest compiler proof."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from oreslang_test.cli import main


class ScheduleDelegationTests(unittest.TestCase):
    def invoke(self, root, *args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            result = main(["--root", str(root), *args])
        return result, output.getvalue(), error.getvalue()

    def test_configured_seeded_schedule_runner(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            script = root / "fake_runtime.py"
            script.write_text("""import sys
count = next((int(x.split('=', 1)[1]) for x in sys.argv
              if x.startswith('--iterations=')), 1)
for _ in range(count):
    print('ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0')
    print('ORES_CONCURRENCY|RUN|seed=7|events=2|deadlocks=0|schedule=perturbed|race_coverage=none')
""", encoding="utf-8")
            (root / "oreslang-test.toml").write_text(
                '[schedule]\ncommand = ["' + sys.executable + '", "fake_runtime.py"]\n',
                encoding="utf-8")
            status, out, err = self.invoke(root, "--schedule-fuzz",
                                           "--seed", "7", "--iterations", "3")
            self.assertEqual(status, 0, err)
            self.assertIn("SCHEDULE PASS: 3", out)

    def test_missing_backend_and_conflicting_modes_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            status, _, err = self.invoke(root, "--schedule-fuzz")
            self.assertEqual(status, 2)
            self.assertIn("schedule.command", err)
            status, _, err = self.invoke(root, "--schedule-fuzz", "--race")
            self.assertEqual(status, 2)
            self.assertIn("separate backend test mode", err)

    def test_replay_requires_single_iteration(self):
        with tempfile.TemporaryDirectory() as d:
            status, _, err = self.invoke(Path(d), "--replay", "events.trace",
                                         "--iterations", "2")
            self.assertEqual(status, 2)
            self.assertIn("requires --iterations=1", err)


if __name__ == "__main__":
    unittest.main()
