#!/usr/bin/env python3
"""Fetch the pinned GCC source and detached signature without overwriting files."""

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

from oracle.gcc.verify_source_lock import (  # noqa: E402
    VerificationError,
    load_and_validate_lock,
    verify_locked_file,
    verify_source_release,
)


DEFAULT_LOCK = REPOSITORY_ROOT / "oracle/gcc/16.2.0/source-lock.json"


def fetch_artifact(destination: Path, specification: dict[str, object], label: str) -> Path:
    target = destination / str(specification["fileName"])
    if target.exists():
        verify_locked_file(target, specification, label)
        print(f"reused verified {label}: {target}")
        return target

    request = urllib.request.Request(
        str(specification["url"]),
        headers={"User-Agent": "decomp-thing-gcc-oracle-fetch/1"},
    )
    context = ssl.create_default_context()
    try:
        with tempfile.TemporaryDirectory(
            prefix=".gcc-oracle-download-", dir=destination
        ) as temporary:
            staged = Path(temporary) / str(specification["fileName"])
            print(f"fetching {label}: {specification['url']}")
            with urllib.request.urlopen(request, context=context, timeout=60) as response:
                final_url = response.geturl()
                if urlsplit(final_url).scheme != "https":
                    raise VerificationError(f"{label} redirected to a non-HTTPS URL: {final_url}")
                content_encoding = response.headers.get("Content-Encoding")
                if content_encoding not in {None, "identity"}:
                    raise VerificationError(
                        f"{label} used unexpected Content-Encoding {content_encoding!r}"
                    )
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) != specification["bytes"]:
                    raise VerificationError(
                        f"{label} HTTP Content-Length mismatch: expected "
                        f"{specification['bytes']}, got {content_length}"
                    )
                with staged.open("xb") as output:
                    while chunk := response.read(1024 * 1024):
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            verify_locked_file(staged, specification, label)
            try:
                os.link(staged, target)
            except FileExistsError:
                verify_locked_file(target, specification, label)
            print(f"fetched and verified {label}: {target}")
    except VerificationError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as error:
        raise VerificationError(f"could not fetch {label}: {error}") from error
    return target


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch and fully verify the exact GCC source release used by the oracle."
    )
    parser.add_argument("destination", type=Path)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    arguments = parser.parse_args()

    try:
        data = load_and_validate_lock(arguments.lock)
        destination = arguments.destination.resolve()
        destination.mkdir(parents=True, exist_ok=True)
        signature = fetch_artifact(
            destination,
            data["source"]["detachedSignature"],
            "detached signature",
        )
        archive = fetch_artifact(destination, data["source"]["archive"], "source archive")
        verify_source_release(arguments.lock, archive, signature)
        print(f"GCC {data['oracle']['version']} source provenance verified in {destination}")
        return 0
    except VerificationError as error:
        print(f"fetch failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
