#!/usr/bin/env python3
"""Standalone CLI fetch with an unused/unblocked Unix main-thread alarm.

An actual total alarm exits124 without Python cleanup, retaining staged bytes;
fetch_artifact is not a general in-process library API. Attempt unwind remains
under the original total alarm. Never treat retained staging as verified cache.
"""

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
        self.total_end = monotonic() + FETCH_TOTAL_SECONDS
        self.state = ('total', self.total_end)
        self.replacing = False
        self.closing = False

    def check(self):
        now = self.now()
        if now >= self.total_end:
            raise FetchDeadline('total')
        phase, end = self.state
        if now >= end:
            raise FetchDeadline(phase)
        return end - now

    def _total_remaining(self, now=None):
        remaining = self.total_end - (self.now() if now is None else now)
        if remaining <= 0:
            # No budget remains for Python context-manager unwind. This standalone
            # CLI terminates without I/O/finalizers; only owned staging may remain.
            os._exit(124)
            raise RuntimeError('fatal fetch deadline exit unexpectedly returned')
        return remaining

    def _arm_total_unwind(self):
        # Publish the same logical end as the guard BEFORE any attempt exception.
        self.state = ('total', self.total_end)
        signal.setitimer(signal.ITIMER_REAL, self._total_remaining())
        self._total_remaining()

    def _adjudicate(self, desired):
        now = self.now()
        self._total_remaining(now)
        phase, end = desired
        if phase == 'attempt' and now >= end:
            self._arm_total_unwind()
            raise FetchDeadline('attempt')
        return end - now

    def _expired(self, *unused):
        if self.closing:
            return
        self._total_remaining()  # Even a deferred callback during replacement is fatal at total.
        if self.replacing:
            return
        current = self.state
        # A stale/early callback is not proof that the current logical end expired.
        signal.setitimer(signal.ITIMER_REAL, self._adjudicate(current))
        self._adjudicate(current)

    def _replace(self, desired):
        previous_mask = None
        ready = False
        primary = None
        self.replacing = True
        try:
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.sigtimedwait({signal.SIGALRM}, 0)  # One coalesced owned signal; never wait.
            remaining = self._adjudicate(desired)
            self.state = desired
            signal.setitimer(signal.ITIMER_REAL, remaining)
            self._adjudicate(desired)
            ready = True
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                try:
                    # OS masking does not remove an already-scheduled Python callback.
                    # Clear suppression FIRST, then freshly adjudicate BOTH original ends.
                    self.replacing = False
                    if ready:
                        self._adjudicate(desired)
                    else:
                        self._total_remaining()
                except FetchDeadline as error:
                    if error.phase != 'attempt':
                        raise
                    self._arm_total_unwind()
                    if primary is not None and not (isinstance(primary, FetchDeadline) and primary.phase == 'attempt'):
                        raise primary from error
                    raise
            finally:
                if previous_mask is not None:
                    try:
                        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                    except FetchDeadline as error:
                        if error.phase != 'attempt':
                            raise
                        # A callback can interrupt the restoration call itself. The exact
                        # mask restore is idempotent; complete it once, without a new end.
                        try:
                            self._arm_total_unwind()
                        finally:
                            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                        if primary is not None and not (isinstance(primary, FetchDeadline) and primary.phase == 'attempt'):
                            raise primary from error
                        raise

    def arm(self, attempt=False):
        desired = None
        try:
            desired = ('attempt', min(self.total_end, self.now() + FETCH_TIMEOUT_SECONDS)) if attempt else ('total', self.total_end)
            self._replace(desired)
        except FetchDeadline as error:
            if error.phase != 'attempt' or desired is None:
                raise
            # At most one old-attempt continuation, retaining the already computed end.
            self._adjudicate(desired)
            self._replace(desired)

    def __enter__(self):
        if (not hasattr(signal,'setitimer') or not hasattr(signal,'SIGALRM') or not hasattr(signal,'pthread_sigmask') or
                not hasattr(signal,'sigpending') or not hasattr(signal,'sigtimedwait') or
                threading.current_thread() is not threading.main_thread()):
            raise VerificationError('GCC fetch requires Unix main-thread deadline support')
        inherited_mask = signal.pthread_sigmask(signal.SIG_BLOCK,[])
        if signal.SIGALRM in inherited_mask or signal.SIGALRM in signal.sigpending():
            raise VerificationError('GCC fetch refuses blocked or pending SIGALRM')
        if signal.getitimer(signal.ITIMER_REAL) != (0.0,0.0):
            raise VerificationError('GCC fetch refuses a preexisting alarm')
        self.previous = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM,self._expired)
        try:
            self.arm()
        except BaseException as error:
            self.__exit__(type(error),error,error.__traceback__)
            raise
        return self

    def __exit__(self, kind, failure, traceback):
        self.closing = True
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGALRM})
        try:
            signal.setitimer(signal.ITIMER_REAL,0)
            # Standard signals coalesce; consume any owned pending alarm while blocked,
            # before restoring a prior/default disposition. Never wait for a new signal.
            signal.sigtimedwait({signal.SIGALRM},0)
            signal.signal(signal.SIGALRM,self.previous)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK,previous_mask)
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
            try:
                clock.arm(attempt=True)
                request = urllib.request.Request(url,headers={'User-Agent':'decomp-thing-gcc-oracle-fetch/2'})
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
            try:
                clock.arm()  # Retry work/sleep consumes only the remaining original total.
            except FetchDeadline as error:
                if error.phase != 'attempt':
                    raise
                # A callback before arm's desired value existed already armed total.
                # Finish only that same unwind guard, not another artifact attempt.
                clock._arm_total_unwind()
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
