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
for i in range(count):
    print('ORES_TEST|PASS|suite/case|')
    print('ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0')
    print(f'ORES_CONCURRENCY|RUN|seed={7+i}|events=2|deadlocks=0|schedule=perturbed|race_coverage=none')
""", encoding="utf-8")
            (root / "oreslang-test.toml").write_text(
                '[schedule]\ncommand = ["' + sys.executable + '", "fake_runtime.py"]\n',
                encoding="utf-8")
            status, out, err = self.invoke(root, "--schedule-fuzz",
                                           "--seed", "7", "--iterations", "3")
            self.assertEqual(status, 0, err)
            self.assertIn("SCHEDULE PASS: 3", out)

    def test_fabricated_suite_summary_without_case_events_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            script = root / "empty_case.py"
            script.write_text(
                "print('ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0')\n"
                "print('ORES_CONCURRENCY|RUN|seed=7|events=0|deadlocks=0|schedule=perturbed|race_coverage=none')\n",
                encoding="utf-8")
            (root / "oreslang-test.toml").write_text(
                '[schedule]\ncommand = ["' + sys.executable + '", "empty_case.py"]\n',
                encoding="utf-8")
            status, output, error = self.invoke(root, "--schedule-fuzz", "--seed", "7")
            self.assertEqual(status, 1, error)
            self.assertIn("SCHEDULE FAIL", output)

    def test_all_skipped_schedule_never_passes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            script = root / "skipped.py"
            script.write_text(
                "print('ORES_TEST|SKIP|suite/case|')\n"
                "print('ORES_TEST|SUMMARY|total=1|passed=0|failed=0|skipped=1|filtered=0')\n"
                "print('ORES_CONCURRENCY|RUN|seed=7|events=0|deadlocks=0|schedule=perturbed|race_coverage=none')\n",
                encoding="utf-8")
            (root / "oreslang-test.toml").write_text(
                '[schedule]\ncommand = ["' + sys.executable + '", "skipped.py"]\n',
                encoding="utf-8")
            status, output, error = self.invoke(root, "--schedule-fuzz", "--seed", "7")
            self.assertEqual(status, 1, error)
            self.assertIn("SCHEDULE FAIL", output)

    def test_deadlock_or_forged_seed_receipt_is_never_success(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "broken.py").write_text(
                "print('ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0')\n"
                "print('ORES_CONCURRENCY|RUN|seed=999|events=1|deadlocks=1|schedule=perturbed|race_coverage=none')\n",
                encoding="utf-8")
            (root / "oreslang-test.toml").write_text(
                '[schedule]\ncommand = ["' + sys.executable + '", "broken.py"]\n',
                encoding="utf-8")
            status, out, err = self.invoke(root, "--schedule-fuzz", "--seed", "3")
            self.assertEqual(status, 1, err)
            self.assertIn("SCHEDULE FAIL", out)

    def test_missing_backend_and_conflicting_modes_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            status, _, err = self.invoke(root, "--schedule-fuzz")
            self.assertEqual(status, 2)
            self.assertIn("schedule.command", err)
            status, _, err = self.invoke(root, "--schedule-fuzz", "--race")
            self.assertEqual(status, 2)
            self.assertIn("separate backend test mode", err)

    def test_model_check_uses_bounded_reference_model(self):
        fixture = (Path(__file__).resolve().parent / "models" / "atomic-update.json")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "model.json").write_bytes(fixture.read_bytes())
            status, out, err = self.invoke(root, "--model-check",
                                           "--model", "model.json")
            self.assertEqual(status, 0, err)
            self.assertIn("LOGICAL PASS", out)
            self.assertIn("reference model only", out)

    def test_reference_model_not_mixed_with_runtime_deadlock(self):
        with tempfile.TemporaryDirectory() as d:
            status, _, err = self.invoke(Path(d), "--model-check", "--deadlock")
            self.assertEqual(status, 2)
            self.assertIn("do not combine", err)

    def test_replay_requires_single_iteration(self):
        with tempfile.TemporaryDirectory() as d:
            status, _, err = self.invoke(Path(d), "--replay", "events.trace",
                                         "--iterations", "2")
            self.assertEqual(status, 2)
            self.assertIn("requires --iterations=1", err)


if __name__ == "__main__":
    unittest.main()
