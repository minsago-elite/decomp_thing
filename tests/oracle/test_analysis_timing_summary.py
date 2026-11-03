import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "summarize-analysis-timings.py"
SPEC = importlib.util.spec_from_file_location("analysis_timing_summary", SCRIPT)
summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(summary)


def record(invocation, duration, *, input_hash="a" * 64, complete=True, truncated=False):
    return {
        "schemaVersion": 1,
        "analysisInvocationId": invocation,
        "recoveryMode": "full",
        "analysisToolSha256": "b" * 64,
        "profileSha256": "c" * 64,
        "configurationSha256": "d" * 64,
        "inputSha256": input_hash,
        "exporterSha256": "e" * 64,
        "terminalStatus": "succeeded",
        "workerTerminalStatus": "succeeded",
        "spans": [{"phase": "analysis", "clockDomain": "parent-monotonic", "startOffsetNanos": 0,
                   "durationNanos": duration, "status": "succeeded"}],
        "workerSpans": [{"phase": "analysis", "clockDomain": "worker-monotonic", "startOffsetNanos": 0,
                         "durationNanos": duration // 2, "status": "completed"}],
        "coverage": {"complete": complete, "missingPhases": [] if complete else ["export"], "truncated": truncated},
    }


def write_record(directory, name, value):
    path = directory / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


class AnalysisTimingSummaryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_summarizes_clock_domains_and_repeated_runs_separately(self):
        one = write_record(self.root, "one.json", record("one", 10))
        two = write_record(self.root, "two.json", record("two", 30))
        other_input = write_record(self.root, "other.json", record("other", 500, input_hash="f" * 64))

        result = summary.summarize([one, two, other_input])
        self.assertEqual(result["sidecars"], 3)
        by_key = {(item["bindings"]["inputSha256"], item["clockDomain"]): item for item in result["summaries"]}
        parent = by_key[("a" * 64, "parent-monotonic")]
        worker = by_key[("a" * 64, "worker-monotonic")]
        self.assertEqual(parent["invocations"], worker["invocations"], 2)
        self.assertEqual(parent["phases"]["analysis"],
                         {"samples": 2, "minNanos": 10, "medianNanos": 20.0, "maxNanos": 30})
        self.assertEqual(worker["phases"]["analysis"]["maxNanos"], 15)
        self.assertEqual(by_key[("f" * 64, "parent-monotonic")]["invocations"], 1)

    def test_rejects_incomplete_or_truncated_coverage(self):
        for changes in ({"complete": False}, {"complete": True, "truncated": True}):
            with self.subTest(changes=changes):
                path = write_record(self.root, "partial.json", record("partial", 10, **changes))
                with self.assertRaises(summary.TimingEvidenceError):
                    summary.summarize([path])

    def test_rejects_duplicate_invocation_id(self):
        one = write_record(self.root, "one.json", record("same", 10))
        two = write_record(self.root, "two.json", record("same", 12))
        with self.assertRaisesRegex(summary.TimingEvidenceError, "duplicate analysisInvocationId"):
            summary.summarize([one, two])

    def test_rejects_unsuccessful_span_in_successful_record(self):
        value = record("mixed", 10)
        value["workerSpans"][0]["status"] = "failed"
        path = write_record(self.root, "mixed.json", value)
        with self.assertRaisesRegex(summary.TimingEvidenceError, "unsuccessful span status"):
            summary.summarize([path])


if __name__ == "__main__":
    unittest.main()
