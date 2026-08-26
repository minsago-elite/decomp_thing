#!/usr/bin/env python3
"""Check whether this host matches the locked GCC behavior executor profile."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.behavior_corpus import (  # noqa: E402
    BehaviorCorpusError,
    ExactExecutorProfileMismatch,
)
from oracle.gcc.behavior_corpus import verify_gcc_executor_profile  # noqa: E402


def main() -> int:
    runtime_name = os.environ.get("DOCKER") or shutil.which("docker")
    if runtime_name is None:
        print("executor probe failed: container runtime not found; set DOCKER", file=sys.stderr)
        return 1
    runtime = Path(runtime_name)
    if not runtime.is_absolute():
        resolved = shutil.which(runtime_name)
        if resolved is None:
            print(f"executor probe failed: runtime not found: {runtime_name}", file=sys.stderr)
            return 1
        runtime = Path(resolved)
    supplied_environment = (
        {"DOCKER_HOST": os.environ["DOCKER_HOST"]}
        if "DOCKER_HOST" in os.environ
        else None
    )
    try:
        verify_gcc_executor_profile(
            runtime,
            container_runtime_environment=supplied_environment,
        )
    except ExactExecutorProfileMismatch as error:
        print(f"checked GCC executor profile mismatch: {error}", file=sys.stderr)
        return 78
    except BehaviorCorpusError as error:
        print(f"executor probe failed: {error}", file=sys.stderr)
        return 1
    print("checked GCC behavior executor profile matches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
