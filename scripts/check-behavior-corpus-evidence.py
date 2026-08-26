#!/usr/bin/env python3
"""Offline cross-check deterministic evidence against its exact behavior corpus."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.behavior_corpus import (  # noqa: E402
    BehaviorCorpusError,
    load_corpus,
    load_report,
    validate_corpus_report_pair,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline-check that canonical behavior evidence exactly matches its "
            "canonical reviewed corpus. This does not execute the target."
        )
    )
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        corpus, corpus_payload = load_corpus(arguments.corpus)
        report, _ = load_report(arguments.evidence)
        validate_corpus_report_pair(
            corpus,
            report,
            corpus_payload=corpus_payload,
        )
    except BehaviorCorpusError as error:
        print(f"evidence check failed: {error}", file=sys.stderr)
        return 1
    print(
        f"behavior evidence matches {corpus['id']}: "
        f"{report['summary']['passed']}/{report['summary']['cases']} cases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
