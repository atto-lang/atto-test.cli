"""Strict metadata admission for Atto guest test receipts; does not execute guests."""
import json
import re
import sys

_SHA40 = re.compile("[0-9a-f]{40}", re.ASCII)
_SHA64 = re.compile("[0-9a-f]{64}", re.ASCII)
_ID = re.compile("[a-z][a-z0-9_./-]{0,127}", re.ASCII)
_VALID_STATUS = {"passed", "failed", "unsupported", "not_executed"}
_VALID_EXECUTION = {"guest", "host", "none"}


class ReceiptError(ValueError):
    pass


def _object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ReceiptError("duplicate JSON key")
        result[name] = value
    return result


def assess_receipt(report):
    if type(report) is not dict or set(report) != {
        "schema_version", "source_sha", "backend", "command", "runtime", "cases"
    }:
        raise ReceiptError("invalid receipt metadata fields")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise ReceiptError("unsupported receipt schema")
    if type(report["source_sha"]) is not str or not _SHA40.fullmatch(report["source_sha"]):
        raise ReceiptError("source_sha must be exact 40-digit lowercase Git SHA")
    if type(report["backend"]) is not str or not _ID.fullmatch(report["backend"]):
        raise ReceiptError("invalid backend")
    if any(type(report[key]) is not str or not report[key].strip() or len(report[key]) > 2048
           for key in ("command", "runtime")):
        raise ReceiptError("missing command or runtime")
    cases = report["cases"]
    if type(cases) is not list or not 1 <= len(cases) <= 10000:
        raise ReceiptError("at least one case is required")
    ids = set()
    for case in cases:
        if type(case) is not dict or set(case) != {
            "id", "status", "execution", "exit_code", "evidence_sha256"
        }:
            raise ReceiptError("invalid case fields")
        name = case["id"]
        if type(name) is not str or not _ID.fullmatch(name) or name in ids:
            raise ReceiptError("invalid or duplicate case id")
        ids.add(name)
        status, execution = case["status"], case["execution"]
        if status not in _VALID_STATUS or execution not in _VALID_EXECUTION:
            raise ReceiptError("unknown status or execution")
        if status in ("passed", "failed") and execution == "none":
            raise ReceiptError("an unexecuted case cannot pass or fail")
        if status in ("unsupported", "not_executed") and execution != "none":
            raise ReceiptError("unsupported/not_executed cannot assert execution")
        exit_code = case["exit_code"]
        digest = case["evidence_sha256"]
        if execution == "none":
            if exit_code is not None or digest is not None:
                raise ReceiptError("unexecuted case cannot carry execution evidence")
        else:
            if type(exit_code) is not int or not -255 <= exit_code <= 255:
                raise ReceiptError("executed case requires an exit code")
            if type(digest) is not str or not _SHA64.fullmatch(digest):
                raise ReceiptError("executed case requires exact SHA-256 digest")
            if status == "passed" and exit_code != 0:
                raise ReceiptError("passing case cannot have nonzero exit")
    passed_guest = sum(c["status"] == "passed" and c["execution"] == "guest" for c in cases)
    return {"total": len(cases), "passed_guest": passed_guest,
            "host_only": sum(c["execution"] == "host" for c in cases),
            "gate_pass": passed_guest == len(cases)}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python3 -m atto_test_cli.receipt <receipt.json>", file=sys.stderr)
        return 2
    try:
        with open(args[0], "rb") as stream:
            data = stream.read(1048577)
        if len(data) > 1048576:
            raise ReceiptError("receipt exceeds 1 MiB")
        report = json.loads(data.decode("utf-8"), object_pairs_hook=_object,
                            parse_constant=lambda x: (_ for _ in ()).throw(ReceiptError("nonfinite JSON")))
        summary = assess_receipt(report)
    except (OSError, UnicodeError, json.JSONDecodeError, ReceiptError) as exc:
        print("invalid receipt: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
