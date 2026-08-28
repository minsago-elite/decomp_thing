#!/usr/bin/env python3
"""Regenerate checked Clang behavior expectations in the locked OCI sandbox."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.behavior_corpus import BehaviorCorpusError, write_corpus  # noqa: E402
from oracle.llvm.generate_behavior_corpus import generate_corpus  # noqa: E402


DEFAULT_PROFILE = REPOSITORY_ROOT / "oracle/llvm/22.1.6"


def _runtime(value: str | None) -> Path:
    candidate = value or os.environ.get("DOCKER") or shutil.which("docker")
    if candidate is None:
        raise argparse.ArgumentTypeError("container runtime not found; set DOCKER")
    path = Path(candidate)
    if not path.is_absolute():
        resolved = shutil.which(candidate)
        if resolved is None:
            raise argparse.ArgumentTypeError(f"container runtime not found: {candidate}")
        path = Path(resolved)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--executable",
        type=Path,
        default=DEFAULT_PROFILE / "artifacts/clang-driver.stripped",
    )
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_PROFILE / "behavior-corpus.json"
    )
    parser.add_argument("--container-runtime")
    arguments = parser.parse_args()
    try:
        runtime = _runtime(arguments.container_runtime)
        environment = (
            {"DOCKER_HOST": os.environ["DOCKER_HOST"]}
            if "DOCKER_HOST" in os.environ
            else None
        )
        corpus = generate_corpus(
            arguments.executable,
            container_runtime=runtime,
            container_runtime_environment=environment,
        )
        write_corpus(arguments.output, corpus)
    except (BehaviorCorpusError, argparse.ArgumentTypeError) as error:
        print(f"generation failed: {error}", file=sys.stderr)
        return 1
    print(f"recorded {len(corpus['cases'])} cases in {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

