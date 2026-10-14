#!/usr/bin/env python3
"""Fetch locked GCC bytes without overwrites. Requires an unused Unix main-thread alarm."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import ssl
import signal
import threading
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


class FetchDeadline(VerificationError):
    """Dedicated absolute timeout, distinct from endpoint and validation failures."""
    def __init__(self, phase):
        self.phase = phase
        super().__init__(f"{phase} fetch deadline exhausted")


class FetchClock:
    """Unix main-thread network guard; not preemption of arbitrary kernel/C stalls."""
    def __init__(self, monotonic):
        self.now = monotonic
        self.total_end = self.end = monotonic() + FETCH_TOTAL_SECONDS
        self.phase = 'total'

    def check(self):
        now = self.now()
        if now >= self.total_end:
            raise FetchDeadline('total')
        if now >= self.end:
            raise FetchDeadline(self.phase)
        return self.end - now

    def _expired(self, *unused):
        raise FetchDeadline('total' if self.now() >= self.total_end else self.phase)

    def arm(self, attempt=False):
        self.phase = 'attempt' if attempt else 'total'
        self.end = min(self.total_end, self.now() + FETCH_TIMEOUT_SECONDS) if attempt else self.total_end
        signal.setitimer(signal.ITIMER_REAL, self.check())

    def __enter__(self):
        if (not hasattr(signal,'setitimer') or not hasattr(signal,'SIGALRM') or
                threading.current_thread() is not threading.main_thread()):
            raise VerificationError('GCC fetch requires Unix main-thread deadline support')
        if signal.getitimer(signal.ITIMER_REAL) != (0.0,0.0):
            raise VerificationError('GCC fetch refuses a preexisting alarm')
        self.previous = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM,self._expired)
        try:
            self.arm()
        except BaseException:
            signal.setitimer(signal.ITIMER_REAL,0)
            signal.signal(signal.SIGALRM,self.previous)
            raise
        return self

    def __exit__(self, kind, failure, traceback):
        try:
            signal.setitimer(signal.ITIMER_REAL,0)
        finally:
            signal.signal(signal.SIGALRM,self.previous)
        if failure is None:
            self.check()  # Never accept a result observed late, even during guard teardown.
        return False


def read_chunk(response, clock):
    remaining = clock.check()
    # HTTPResponse.read can fill its requested amount across indefinitely many receives.
    # read1 performs at most one underlying read; shorten its socket timeout each time.
    if response.fp is None and response.isclosed():
        return b''
    try:
        socket = response.fp.raw._sock
    except AttributeError as error:
        raise VerificationError('GCC fetch requires a timeout-capable HTTPResponse transport') from error
    socket.settimeout(remaining)
    chunk = response.read1(1024 * 1024)
    clock.check()
    return chunk


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
    with FetchClock(monotonic) as clock:
        return _fetch_artifact(destination, specification, label, opener, sleeper, clock)


def _fetch_artifact(destination, specification, label, opener, sleeper, clock):
    target = destination / str(specification['fileName'])
    if target.exists():
        verify_locked_file(target,specification,label)
        clock.check()
        print(f"reused verified {label}: {target}")
        clock.check()
        return target
    urls = official_candidate_urls(str(specification['url']))
    context = ssl.create_default_context()
    clock.check()
    failures = []
    for url in urls:
        for attempt in range(1,FETCH_ATTEMPTS_PER_ENDPOINT+1):
            clock.arm(attempt=True)
            request = urllib.request.Request(url,headers={'User-Agent':'decomp-thing-gcc-oracle-fetch/2'})
            try:
                with tempfile.TemporaryDirectory(prefix='.gcc-oracle-download-',dir=destination) as temporary:
                    staged = Path(temporary)/str(specification['fileName'])
                    print(f"fetching {label} (attempt {attempt}): {url}")
                    # The alarm covers DNS/connect/TLS/redirect/status/header processing too;
                    # an inactivity socket timeout alone is not an absolute opener bound.
                    with opener(request,context=context,timeout=clock.check()) as response:
                        clock.check()
                        final_url = response.geturl()
                        if urlsplit(final_url).scheme != 'https':
                            raise VerificationError(f"{label} redirected to a non-HTTPS URL: {final_url}")
                        encoding = response.headers.get('Content-Encoding')
                        if encoding not in {None,'identity'}:
                            raise VerificationError(f"{label} used unexpected Content-Encoding {encoding!r}")
                        length = response.headers.get('Content-Length')
                        if length is not None and int(length) != specification['bytes']:
                            raise VerificationError(f"{label} HTTP Content-Length mismatch: expected {specification['bytes']}, got {length}")
                        expected_bytes = int(specification['bytes'])
                        observed_bytes = 0
                        with staged.open('xb') as output:
                            while chunk := read_chunk(response,clock):
                                observed_bytes += len(chunk)
                                if observed_bytes > expected_bytes:
                                    raise VerificationError(f"{label} exceeded its locked byte length {expected_bytes}")
                                output.write(chunk)
                                clock.check()
                            output.flush()
                            clock.check()
                            os.fsync(output.fileno())
                            clock.check()
                    clock.check()
                    verify_locked_file(staged,specification,label)
                    clock.check()
                    try:
                        os.link(staged,target)
                    except FileExistsError:
                        verify_locked_file(target,specification,label)
                    # A verified cache entry may remain if publication completed late;
                    # never unlink/overwrite a concurrent or already verified target.
                    clock.check()
                clock.check()  # Includes staged-directory/response cleanup, before success.
                print(f"fetched and verified {label}: {target}")
                clock.check()
                return target
            except FetchDeadline as error:
                failures.append(f"{url} attempt {attempt}: {error}")
                if error.phase == 'total':
                    raise VerificationError(f"could not fetch {label}: {'; '.join(failures)}") from error
            except (VerificationError,OSError,ValueError,urllib.error.URLError) as error:
                failures.append(f"{url} attempt {attempt}: {error}")
            clock.arm()  # Retry work/sleep consumes only the remaining original total.
            if attempt < FETCH_ATTEMPTS_PER_ENDPOINT:
                sleeper(min(FETCH_RETRY_DELAY_SECONDS,clock.check()))
                clock.check()
    raise VerificationError(f"could not fetch {label} from any official endpoint: {'; '.join(failures)}")


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
