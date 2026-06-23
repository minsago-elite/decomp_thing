from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_progress_json_has_required_evidence() -> None:
    progress = json.loads((REPO_ROOT / "roadmap" / "progress.json").read_text())
    assert progress["current_level"] == "L0"
    assert progress["levels"]
    for level in progress["levels"]:
        assert level["gates"]
        for gate in level["gates"]:
            assert gate["evidence"]


def test_roadmap_check_passes() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "decomp_engine.roadmap", "check"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Roadmap check passed" in result.stdout
