import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

from oreslang_test.__main__ import (
    EvidenceError, build_input, main, parse_race_evidence, parse_test_summary
)

TEST_OK = "ORES_TEST|PASS|suite/one|\nORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0\n"
RACE_OK = ("ORES_RACE|BEGIN|version=1|memory_instrumented=true|logical_instrumented=true\n"
           "ORES_RACE|SUMMARY|memory_accesses=5|memory_races=0|logical_checks=2|logical_violations=0\n")


class ProtocolTests(unittest.TestCase):
    def test_summary(self):
        self.assertEqual(1, parse_test_summary(TEST_OK).passed)
        for bad in ("", TEST_OK + TEST_OK, "ORES_TEST|SUMMARY|total=0|passed=0|failed=0|skipped=0|filtered=0\n",
                    "ORES_TEST|SUMMARY|total=2|passed=1|failed=0|skipped=0|filtered=0\n"):
            with self.assertRaises(EvidenceError):
                parse_test_summary(bad)

    def test_race_requires_instrumentation_and_positive_proof(self):
        self.assertEqual(0, parse_race_evidence(RACE_OK)["memory_races"])
        for bad in ("", RACE_OK + RACE_OK,
                    RACE_OK.replace("memory_accesses=5", "memory_accesses=0"),
                    RACE_OK.replace("logical_checks=2", "logical_checks=0"),
                    RACE_OK.replace("memory_instrumented=true", "memory_instrumented=false")):
            with self.assertRaises(EvidenceError):
                parse_race_evidence(bad)

    def test_mutation_is_seed_reproducible(self):
        import random
        a, b = random.Random(123), random.Random(123)
        self.assertEqual([build_input(a, [b"hello"], n, 100) for n in range(200)],
                         [build_input(b, [b"hello"], n, 100) for n in range(200)])
        self.assertEqual(b"hello", build_input(random.Random(4), [b"hello"], 0, 100))


class ProcessTests(unittest.TestCase):
    def _run(self, script, flags):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "fixture.ores"
            source.write_text("test fixture\n")
            helper = root / "guest.py"
            helper.write_text(script)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = main(flags + [str(source), "--runner", sys.executable,
                               "--direct-runner", "--runner-arg", str(helper),
                               "--artifacts", str(root / "artifacts")])
            artifacts = sorted((root / "artifacts").glob("*.bin")) if (root / "artifacts").exists() else []
            return status, len(artifacts)

    def test_missing_instrumentation_is_not_a_clean_race_report(self):
        status, _ = self._run(f"print({TEST_OK!r})", ["--race"])
        self.assertEqual(2, status)

    def test_guest_printed_race_counters_never_prove_memory_safety(self):
        # A guest could forge an apparently perfect report; zero races is NOT proof.
        for report in (RACE_OK, RACE_OK.replace("memory_races=0", "memory_races=1")):
            status, _ = self._run(f"print({(TEST_OK + report)!r})", ["--race"])
            self.assertEqual(2, status)

    def test_backend_race_attestation_is_still_required_for_multiple_runs(self):
        status, _ = self._run(f"print({(TEST_OK + RACE_OK)!r})", ["--race", "--runs", "2"])
        self.assertEqual(2, status)

    def test_fuzz_crash_saves_replay_artifact(self):
        script = ("import sys\n"
                  "payload=sys.stdin.buffer.read()\n"
                  "if payload==b'A':\n"
                  "    print('ORES_TEST|SUMMARY|total=1|passed=0|failed=1|skipped=0|filtered=0')\n"
                  "else:\n"
                  "    print('ORES_TEST|SUMMARY|total=1|passed=1|failed=0|skipped=0|filtered=0')\n")
        status, saved = self._run(script, ["--fuzz", "--runs", "10", "--seed", "42"])
        self.assertEqual(1, status)
        self.assertEqual(1, saved)

    def test_fuzz_passes_with_machine_report(self):
        status, saved = self._run(f"print({TEST_OK!r})", ["--fuzz", "--runs", "8"])
        self.assertEqual(0, status)
        self.assertEqual(0, saved)

    def test_fuzz_timeout_is_failure_and_saves_seed(self):
        status, saved = self._run(
            "import time\ntime.sleep(2)\n",
            ["--fuzz", "--timeout", "0.01", "--runs", "1"])
        self.assertEqual(1, status)
        self.assertEqual(1, saved)

    def test_unbounded_guest_output_is_inconclusive(self):
        status, _ = self._run(
            "print('x' * 1048577)\n",
            ["--fuzz", "--runs", "1"])
        self.assertEqual(2, status)


if __name__ == "__main__":
    unittest.main()
