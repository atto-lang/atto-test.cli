import unittest
from atto_test_cli.receipt import ReceiptError, assess_receipt


def report(status="passed", execution="guest", exit_code=0, digest="a" * 64):
    return {"schema_version": 1, "source_sha": "b" * 40,
            "backend": "rs", "command": "attoc run example.atto",
            "runtime": "wasm32", "cases": [{
                "id": "basic", "status": status, "execution": execution,
                "exit_code": exit_code, "evidence_sha256": digest
            }]}


class ReceiptTest(unittest.TestCase):
    def test_guest_pass(self):
        self.assertEqual(assess_receipt(report())["gate_pass"], True)

    def test_host_only_not_admitted(self):
        self.assertEqual(assess_receipt(report(execution="host"))["gate_pass"], False)

    def test_not_executed_never_passes(self):
        summary = assess_receipt(report("not_executed", "none", None, None))
        self.assertFalse(summary["gate_pass"])
        self.assertEqual(summary["passed_guest"], 0)

    def test_reject_ambiguous_or_unsupported_claims(self):
        for bad in [
            report(execution="none"),
            report(exit_code=1),
            report(digest=None),
            report("unsupported", "guest"),
            report("failed", "none", None, None),
            dict(report(), cases=[]),
            dict(report(), source_sha="not-sha"),
            dict(report(), schema_version=True),
        ]:
            with self.assertRaises(ReceiptError):
                assess_receipt(bad)

    def test_reject_duplicate_case_id(self):
        bad = report()
        bad["cases"].append(dict(bad["cases"][0]))
        with self.assertRaises(ReceiptError):
            assess_receipt(bad)


if __name__ == "__main__":
    unittest.main()
