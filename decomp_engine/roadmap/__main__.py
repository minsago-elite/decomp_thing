from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
ROADMAP_PATH = REPO_ROOT / "ROADMAP.md"
ROADMAP_DIR = REPO_ROOT / "roadmap"
PROGRESS_PATH = ROADMAP_DIR / "progress.json"
SCHEMA_PATH = ROADMAP_DIR / "progress.schema.json"
REPORT_PATH = ROADMAP_DIR / "reports" / "latest.json"

TABLE_START = "<!-- roadmap:progress:start -->"
TABLE_END = "<!-- roadmap:progress:end -->"
SUMMARY_START = "<!-- roadmap:summary:start -->"
SUMMARY_END = "<!-- roadmap:summary:end -->"

LEVEL_STATUSES = {"pending", "active", "complete", "blocked"}
GATE_STATUSES = {"pending", "passing", "failing", "blocked", "manual_review"}
GATE_SOURCES = {"test", "benchmark", "manual", "report"}


class RoadmapError(Exception):
    """Raised when roadmap state is invalid."""


@dataclass(frozen=True)
class GateSummary:
    passing: int
    total: int
    blocking_gate: str


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def require_keys(obj: dict[str, Any], keys: set[str], context: str) -> None:
    missing = sorted(keys - set(obj))
    if missing:
        raise RoadmapError(f"{context} is missing required key(s): {', '.join(missing)}")


def validate_progress(progress: dict[str, Any]) -> None:
    require_keys(progress, {"current_level", "current_status", "last_updated", "levels"}, "progress")
    if progress["current_status"] not in LEVEL_STATUSES:
        raise RoadmapError(f"progress.current_status has invalid status: {progress['current_status']}")
    if not isinstance(progress["levels"], list) or not progress["levels"]:
        raise RoadmapError("progress.levels must be a non-empty list")

    level_ids = set()
    for level in progress["levels"]:
        require_keys(level, {"id", "name", "status", "gates"}, f"level {level.get('id', '<unknown>')}")
        level_ids.add(level["id"])
        if level["status"] not in LEVEL_STATUSES:
            raise RoadmapError(f"level {level['id']} has invalid status: {level['status']}")
        if not isinstance(level["gates"], list) or not level["gates"]:
            raise RoadmapError(f"level {level['id']} must define at least one gate")

        gate_ids = set()
        for gate in level["gates"]:
            require_keys(
                gate,
                {"id", "description", "status", "source", "evidence"},
                f"gate {gate.get('id', '<unknown>')}",
            )
            if gate["id"] in gate_ids:
                raise RoadmapError(f"level {level['id']} has duplicate gate id: {gate['id']}")
            gate_ids.add(gate["id"])
            if gate["status"] not in GATE_STATUSES:
                raise RoadmapError(f"gate {gate['id']} has invalid status: {gate['status']}")
            if gate["source"] not in GATE_SOURCES:
                raise RoadmapError(f"gate {gate['id']} has invalid source: {gate['source']}")
            if not str(gate["evidence"]).strip():
                raise RoadmapError(f"gate {gate['id']} must include evidence")

    if progress["current_level"] not in level_ids:
        raise RoadmapError(f"current_level does not match any level: {progress['current_level']}")


def validate_with_json_schema(progress: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        import jsonschema
    except ImportError:
        return

    try:
        jsonschema.validate(instance=progress, schema=schema)
    except jsonschema.ValidationError as exc:
        path = ".".join(str(part) for part in exc.absolute_path)
        location = f" at {path}" if path else ""
        raise RoadmapError(f"progress.json does not match progress.schema.json{location}: {exc.message}") from exc


def validate_level_consistency(progress: dict[str, Any]) -> None:
    active_count = 0
    for level in progress["levels"]:
        gate_statuses = [gate["status"] for gate in level["gates"]]
        if level["status"] == "complete" and any(status != "passing" for status in gate_statuses):
            raise RoadmapError(f"level {level['id']} is complete but has non-passing gates")
        if level["status"] == "active":
            active_count += 1
    if active_count > 1:
        raise RoadmapError("only one level may be active at a time")
    current = find_current_level(progress)
    if progress["current_status"] != current["status"]:
        raise RoadmapError(
            f"current_status ({progress['current_status']}) must match "
            f"current level status ({current['status']})"
        )


def validate_evidence(progress: dict[str, Any]) -> None:
    for level in progress["levels"]:
        for gate in level["gates"]:
            if gate["status"] != "passing":
                continue
            evidence = str(gate["evidence"])
            if evidence.startswith(("http://", "https://")):
                continue
            if not (REPO_ROOT / evidence).exists():
                raise RoadmapError(f"passing gate {gate['id']} references missing evidence: {evidence}")


def summarize_level(level: dict[str, Any]) -> GateSummary:
    gates = level["gates"]
    passing = sum(1 for gate in gates if gate["status"] == "passing")
    blocking_gate = "none"
    for gate in gates:
        if gate["status"] in {"failing", "blocked", "manual_review", "pending"}:
            blocking_gate = gate["description"]
            break
    return GateSummary(passing=passing, total=len(gates), blocking_gate=blocking_gate)


def find_current_level(progress: dict[str, Any]) -> dict[str, Any]:
    for level in progress["levels"]:
        if level["id"] == progress["current_level"]:
            return level
    raise RoadmapError(f"current level not found: {progress['current_level']}")


def find_next_failing_gate(progress: dict[str, Any]) -> str:
    current = find_current_level(progress)
    for gate in current["gates"]:
        if gate["status"] in {"failing", "blocked", "manual_review", "pending"}:
            return gate["description"]
    return "none"


def render_summary(progress: dict[str, Any]) -> str:
    current = find_current_level(progress)
    next_gate = find_next_failing_gate(progress)
    return "\n".join(
        [
            f"- Current maturity level: `{progress['current_level']}`",
            f"- Current milestone: {current['name']}",
            f"- Current status: `{progress['current_status']}`",
            f"- Next failing gate: {next_gate}",
            "- Latest generated report: `roadmap/reports/latest.json`",
        ]
    )


def render_progress_table(progress: dict[str, Any]) -> str:
    rows = [
        "| Level | Name | Status | Passing Gates | Blocking Gate |",
        "|---|---|---:|---:|---|",
    ]
    for level in progress["levels"]:
        summary = summarize_level(level)
        rows.append(
            f"| {level['id']} | {level['name']} | {level['status']} | "
            f"{summary.passing}/{summary.total} | {summary.blocking_gate} |"
        )
    return "\n".join(rows)


def replace_marked_section(text: str, start: str, end: str, replacement: str) -> str:
    if start not in text or end not in text:
        raise RoadmapError(f"ROADMAP.md is missing generated markers {start} / {end}")
    before, rest = text.split(start, 1)
    _, after = rest.split(end, 1)
    return f"{before}{start}\n{replacement}\n{end}{after}"


def render_roadmap(text: str, progress: dict[str, Any]) -> str:
    text = replace_marked_section(text, SUMMARY_START, SUMMARY_END, render_summary(progress))
    return replace_marked_section(text, TABLE_START, TABLE_END, render_progress_table(progress))


def build_report(progress: dict[str, Any]) -> dict[str, Any]:
    levels = []
    total_gates = 0
    passing_gates = 0
    failing_gates = 0
    for level in progress["levels"]:
        summary = summarize_level(level)
        total_gates += summary.total
        passing_gates += summary.passing
        failing_gates += sum(1 for gate in level["gates"] if gate["status"] in {"failing", "blocked"})
        levels.append(
            {
                "id": level["id"],
                "name": level["name"],
                "status": level["status"],
                "passing_gates": summary.passing,
                "total_gates": summary.total,
                "blocking_gate": summary.blocking_gate,
            }
        )
    return {
        "generated_at": utc_now(),
        "current_level": progress["current_level"],
        "current_status": progress["current_status"],
        "next_failing_gate": find_next_failing_gate(progress),
        "totals": {
            "levels": len(progress["levels"]),
            "gates": total_gates,
            "passing_gates": passing_gates,
            "failing_or_blocked_gates": failing_gates,
        },
        "levels": levels,
    }


def command_update(_: argparse.Namespace) -> int:
    progress = load_json(PROGRESS_PATH)
    schema = load_json(SCHEMA_PATH)
    validate_with_json_schema(progress, schema)
    validate_progress(progress)
    validate_level_consistency(progress)
    validate_evidence(progress)

    progress["last_updated"] = utc_now()
    write_json(PROGRESS_PATH, progress)
    write_json(REPORT_PATH, build_report(progress))

    roadmap = ROADMAP_PATH.read_text(encoding="utf-8")
    ROADMAP_PATH.write_text(render_roadmap(roadmap, progress), encoding="utf-8")
    print(f"Updated {PROGRESS_PATH}, {REPORT_PATH}, and {ROADMAP_PATH}")
    return 0


def command_check(_: argparse.Namespace) -> int:
    try:
        progress = load_json(PROGRESS_PATH)
        schema = load_json(SCHEMA_PATH)
        if schema.get("$id") != "https://decomp-engine.local/schemas/progress.schema.json":
            raise RoadmapError("progress.schema.json has an unexpected $id")
        validate_with_json_schema(progress, schema)
        validate_progress(progress)
        validate_level_consistency(progress)
        validate_evidence(progress)

        expected = render_roadmap(ROADMAP_PATH.read_text(encoding="utf-8"), progress)
        actual = ROADMAP_PATH.read_text(encoding="utf-8")
        if actual != expected:
            raise RoadmapError("ROADMAP.md is stale; run `python -m decomp_engine.roadmap update`")

        print("Roadmap check passed")
        return 0
    except RoadmapError as exc:
        print(f"Roadmap check failed: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Maintain the decomp_engine roadmap.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    update = subparsers.add_parser("update", help="Regenerate roadmap progress files.")
    update.set_defaults(func=command_update)

    check = subparsers.add_parser("check", help="Validate roadmap state for CI.")
    check.set_defaults(func=command_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
