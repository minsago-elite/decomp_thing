#!/usr/bin/env python3
"""Run a program-agnostic behavior corpus in its authenticated OCI sandbox."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.behavior_corpus import (  # noqa: E402
    BehaviorCorpusError,
    behavior_error_notes,
    run_corpus_file,
    write_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify an opaque executable against a closed behavior corpus. "
            "Production profiles should additionally authenticate provenance "
            "in a thin profile adapter."
        )
    )
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--container-runtime")
    arguments = parser.parse_args()
    runtime_name = (
        arguments.container_runtime or os.environ.get("DOCKER") or shutil.which("docker")
    )
    if runtime_name is None:
        print("verification failed: container runtime not found; set DOCKER", file=sys.stderr)
        return 1
    runtime = Path(runtime_name)
    if not runtime.is_absolute():
        resolved = shutil.which(runtime_name)
        if resolved is None:
            print(f"verification failed: container runtime not found: {runtime_name}", file=sys.stderr)
            return 1
        runtime = Path(resolved)
    runtime_environment = (
        {"DOCKER_HOST": os.environ["DOCKER_HOST"]}
        if "DOCKER_HOST" in os.environ
        else None
    )
    try:
        report = run_corpus_file(
            arguments.corpus,
            arguments.executable,
            container_runtime=runtime,
            container_runtime_environment=runtime_environment,
        )
        write_report(arguments.json_output, report)
    except BehaviorCorpusError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        for note in behavior_error_notes(error):
            print(f"verification detail: {note}", file=sys.stderr)
        return 1
    print(
        f"behavior corpus passed: {report['summary']['passed']}/"
        f"{report['summary']['cases']} cases"
    )
    print(f"JSON report: {arguments.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
