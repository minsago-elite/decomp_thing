#!/usr/bin/env python3
"""Fetch the pinned GCC source and detached signature without overwriting files."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from collections.abc import Callable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.gcc.verify_source_lock import (  # noqa: E402
    VerificationError,
    load_and_validate_lock,
    verify_locked_file,
    verify_source_release,
)


DEFAULT_LOCK = REPOSITORY_ROOT / "oracle/gcc/16.2.0/source-lock.json"
FETCH_ATTEMPTS_PER_ENDPOINT = 2
FETCH_TIMEOUT_SECONDS = 20
FETCH_TOTAL_SECONDS = 120
FETCH_RETRY_DELAY_SECONDS = 1


def official_candidate_urls(canonical_url: str) -> list[str]:
    parsed = urlsplit(canonical_url)
    path_parts = parsed.path.strip("/").split("/")
    if (
        parsed.scheme != "https"
        or parsed.netloc != "ftp.gnu.org"
        or len(path_parts) != 4
        or path_parts[:2] != ["gnu", "gcc"]
        or not path_parts[2].startswith("gcc-")
    ):
        raise VerificationError(f"unsupported canonical GNU GCC URL: {canonical_url}")
    release = path_parts[2]
    file_name = path_parts[3]
    return [
        canonical_url,
        f"https://gcc.gnu.org/pub/gcc/releases/{release}/{file_name}",
        f"https://ftpmirror.gnu.org/gcc/{release}/{file_name}",
    ]


def fetch_artifact(
    destination: Path,
    specification: dict[str, object],
    label: str,
    *,
    opener: Callable[..., object] = urllib.request.urlopen,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> Path:
    target = destination / str(specification["fileName"])
    if target.exists():
        verify_locked_file(target, specification, label)
        print(f"reused verified {label}: {target}")
        return target

    urls = official_candidate_urls(str(specification["url"]))
    context = ssl.create_default_context()
    deadline = monotonic() + FETCH_TOTAL_SECONDS
    failures: list[str] = []
    for url in urls:
        for attempt in range(1, FETCH_ATTEMPTS_PER_ENDPOINT + 1):
            remaining = deadline - monotonic()
            if remaining <= 0:
                failures.append("total fetch deadline exhausted")
                break
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "decomp-thing-gcc-oracle-fetch/2"},
            )
            try:
                with tempfile.TemporaryDirectory(
                    prefix=".gcc-oracle-download-", dir=destination
                ) as temporary:
                    staged = Path(temporary) / str(specification["fileName"])
                    print(f"fetching {label} (attempt {attempt}): {url}")
                    with opener(
                        request,
                        context=context,
                        timeout=min(FETCH_TIMEOUT_SECONDS, max(1, int(remaining))),
                    ) as response:
                        final_url = response.geturl()
                        if urlsplit(final_url).scheme != "https":
                            raise VerificationError(
                                f"{label} redirected to a non-HTTPS URL: {final_url}"
                            )
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
                        expected_bytes = int(specification["bytes"])
                        observed_bytes = 0
                        with staged.open("xb") as output:
                            while chunk := response.read(1024 * 1024):
                                observed_bytes += len(chunk)
                                if observed_bytes > expected_bytes:
                                    raise VerificationError(
                                        f"{label} exceeded its locked byte length {expected_bytes}"
                                    )
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
            except (VerificationError, OSError, ValueError, urllib.error.URLError) as error:
                failures.append(f"{url} attempt {attempt}: {error}")
                if attempt < FETCH_ATTEMPTS_PER_ENDPOINT and monotonic() < deadline:
                    sleeper(FETCH_RETRY_DELAY_SECONDS)
        if monotonic() >= deadline:
            break
    raise VerificationError(
        f"could not fetch {label} from any official endpoint: {'; '.join(failures)}"
    )


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
