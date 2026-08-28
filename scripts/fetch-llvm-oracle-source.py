#!/usr/bin/env python3
"""Fetch and authenticate the exact LLVM source release used by the oracle."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlsplit


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.llvm.verify_source_lock import (  # noqa: E402
    VerificationError,
    load_and_validate_lock,
    verify_locked_file,
    verify_source_release,
)


DEFAULT_LOCK = REPOSITORY_ROOT / "oracle/llvm/22.1.6/source-lock.json"


def fetch_artifact(destination: Path, specification: dict[str, object], label: str) -> Path:
    target = destination / str(specification["fileName"])
    if target.exists():
        verify_locked_file(target, specification, label)
        print(f"reused verified {label}: {target}")
        return target
    url = str(specification["url"])
    request = urllib.request.Request(url, headers={"User-Agent": "decomp-thing-llvm-oracle-fetch/1"})
    try:
        with tempfile.TemporaryDirectory(prefix=".llvm-oracle-download-", dir=destination) as temporary:
            staged = Path(temporary) / target.name
            with urllib.request.urlopen(request, context=ssl.create_default_context(), timeout=120) as response:
                if urlsplit(response.geturl()).scheme != "https":
                    raise VerificationError(f"{label} redirected to a non-HTTPS URL")
                if response.headers.get("Content-Encoding") not in {None, "identity"}:
                    raise VerificationError(f"{label} used an unexpected content encoding")
                expected = int(specification["bytes"])
                observed = 0
                with staged.open("xb") as output:
                    while chunk := response.read(1024 * 1024):
                        observed += len(chunk)
                        if observed > expected:
                            raise VerificationError(f"{label} exceeded its locked byte length")
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            verify_locked_file(staged, specification, label)
            try:
                os.link(staged, target)
            except FileExistsError:
                verify_locked_file(target, specification, label)
            print(f"fetched and verified {label}: {target}")
            return target
    except (OSError, ValueError, urllib.error.URLError) as error:
        raise VerificationError(f"could not fetch {label}: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch and verify the pinned LLVM source release.")
    parser.add_argument("destination", type=Path)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    arguments = parser.parse_args()
    try:
        data = load_and_validate_lock(arguments.lock)
        destination = arguments.destination.resolve()
        destination.mkdir(parents=True, exist_ok=True)
        signature = fetch_artifact(destination, data["source"]["detachedSignature"], "detached signature")
        archive = fetch_artifact(destination, data["source"]["archive"], "source archive")
        verify_source_release(arguments.lock, archive, signature)
        print(f"LLVM {data['oracle']['version']} source provenance verified in {destination}")
        return 0
    except VerificationError as error:
        print(f"fetch failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
