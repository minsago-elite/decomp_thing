#!/usr/bin/env python3
"""Offline integrity controls for the #1833 timing evidence summarizer."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("summarize-analysis-timings.py")
SPEC = importlib.util.spec_from_file_location("analysis_timing_summary", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


def sidecar() -> dict[str, object]:
    parent_phases = (
        "analysis-invocation",
        "process-launch-request-to-worker-entry-frame",
    )
    worker_phases = (
        "worker-entry-to-parent-permit",
        "application-initialization",
        "project-import-analysis-pre-script",
        "exporter:ExportProgramModelOwned.java",
    )

    def spans(phases: tuple[str, ...], domain: str, status: str) -> list[dict[str, object]]:
        return [
            {
                "phase": phase,
                "clockDomain": domain,
                "startOffsetNanos": 5,
                "durationNanos": 10,
                "status": status,
            }
            for phase in phases
        ]

    return {
        "schemaVersion": 1,
        "analysisInvocationId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "workflowRunId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "recoveryMode": "reuse",
        "analysisToolSha256": "a" * 64,
        "profileSha256": "b" * 64,
        "configurationSha256": "c" * 64,
        "inputSha256": "d" * 64,
        "exporterSha256": "e" * 64,
        "parentTotalElapsedNanos": 100,
        "workerTerminalElapsedNanos": 100,
        "terminalStatus": "succeeded",
        "workerTerminalStatus": "succeeded",
        "spans": spans(parent_phases, "parent-monotonic", "succeeded"),
        "workerSpans": spans(worker_phases, "worker-monotonic", "completed"),
        "coverage": {"complete": True, "missingPhases": [], "truncated": False},
    }


class AnalysisTimingSummaryTests(unittest.TestCase):
    def read_record(self, value: dict[str, object]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "timing.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return SUMMARY.load_record(path)

    def test_accepts_complete_correlated_timing_record(self) -> None:
        record = self.read_record(sidecar())
        self.assertEqual(record["analysisInvocationId"], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    def test_rejects_coverage_claim_missing_required_worker_phase(self) -> None:
        record = sidecar()
        record["workerSpans"] = record["workerSpans"][:-1]
        with self.assertRaisesRegex(SUMMARY.TimingEvidenceError, "exporter span is missing"):
            self.read_record(record)

    def test_rejects_span_past_its_terminal_clock_time(self) -> None:
        record = sidecar()
        record["workerSpans"][0]["startOffsetNanos"] = 95
        with self.assertRaisesRegex(SUMMARY.TimingEvidenceError, "past its clock-domain terminal time"):
            self.read_record(record)

    def test_rejects_boolean_schema_version(self) -> None:
        record = sidecar()
        record["schemaVersion"] = True
        with self.assertRaisesRegex(SUMMARY.TimingEvidenceError, "unsupported timing record schema"):
            self.read_record(record)

    def test_rejects_malformed_workflow_run_binding(self) -> None:
        record = sidecar()
        record["workflowRunId"] = "not-a-run-id"
        with self.assertRaisesRegex(SUMMARY.TimingEvidenceError, "malformed workflowRunId"):
            self.read_record(record)


if __name__ == "__main__":
    unittest.main()
