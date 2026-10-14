from __future__ import annotations

import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
import urllib.error


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FETCHER = runpy.run_path(str(REPOSITORY_ROOT / "scripts/fetch-gcc-oracle-source.py"))
fetch_artifact = FETCHER["fetch_artifact"]
official_candidate_urls = FETCHER["official_candidate_urls"]
VerificationError = FETCHER["VerificationError"]


class FakeResponse:
    def __init__(self, url: str, content: bytes):
        self.url = url
        self.content = content
        self.offset = 0
        self.timeouts = []
        self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=self.timeouts.append)))
        self.headers = {"Content-Length": str(len(content))}

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *unused: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read1(self, amount: int) -> bytes:
        chunk = self.content[self.offset : self.offset + amount]
        self.offset += len(chunk)
        return chunk


class GccOracleSourceFetchTest(unittest.TestCase):
    payload = b"locked GCC release fixture\n"
    specification = {
        "fileName": "gcc-fixture.tar.xz.sig",
        "url": "https://ftp.gnu.org/gnu/gcc/gcc-16.2.0/gcc-16.2.0.tar.xz.sig",
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }

    def setUp(self):
        # No real alarms/signals/network: retain actual guard logic with fake timer APIs.
        module = fetch_artifact.__globals__['signal']
        for name,value in [('getitimer',(0.0,0.0)),('getsignal',module.SIG_DFL),('signal',None),('setitimer',(0.0,0.0))]:
            patcher=mock.patch.object(module,name,return_value=value)
            setattr(self,name,patcher.start());self.addCleanup(patcher.stop)

    def fetch(self,destination,opener,now,**kwargs):
        return fetch_artifact(destination,self.specification,'fixture signature',opener=opener,
                              monotonic=lambda:now[0],sleeper=lambda delay:now.__setitem__(0,now[0]+delay),**kwargs)

    def test_slow_progress_read1_times_out_attempt_and_shortens_socket_timeout(self):
        now=[0.0];responses=[]
        class SlowResponse(FakeResponse):
            def read1(inner,amount):
                now[0]+=11
                return super().read1(1)
        def opener(request,**kwargs):
            response=SlowResponse(request.full_url,self.payload);responses.append(response);return response
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-deadline-') as temporary:
            with self.assertRaisesRegex(VerificationError,'deadline'):
                self.fetch(Path(temporary),opener,now)
            self.assertFalse((Path(temporary)/self.specification['fileName']).exists())
        self.assertEqual([20.0,9.0],responses[0].timeouts)
        self.assertGreaterEqual(now[0],120)

    def test_opener_and_response_cleanup_late_results_are_refused(self):
        for phase in ('opener','cleanup'):
            now=[0.0]
            class LateResponse(FakeResponse):
                def __exit__(inner,*unused):now[0]+=21
            def opener(request,**kwargs):
                if phase=='opener':now[0]+=21
                return (FakeResponse if phase=='opener' else LateResponse)(request.full_url,self.payload)
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-deadline-') as temporary:
                with self.assertRaisesRegex(VerificationError,'deadline'):self.fetch(Path(temporary),opener,now)
                self.assertFalse((Path(temporary)/self.specification['fileName']).exists())

    def test_late_verification_refuses_publication_and_late_cache_reuse(self):
        original=fetch_artifact.__globals__['verify_locked_file']
        for cached in (False,True):
            now=[0.0]
            def verify(*args):original(*args);now[0]+=121
            with self.subTest(cached=cached), tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-deadline-') as temporary:
                destination=Path(temporary);target=destination/self.specification['fileName']
                if cached:target.write_bytes(self.payload)
                with mock.patch.dict(fetch_artifact.__globals__,verify_locked_file=verify), self.assertRaisesRegex(VerificationError,'total'):
                    self.fetch(destination,lambda request,**kwargs:FakeResponse(request.full_url,self.payload),now)
                self.assertEqual(cached,target.exists())
                if cached:self.assertEqual(self.payload,target.read_bytes())

    def test_late_atomic_publication_preserves_verified_cache_but_never_returns_success(self):
        now=[0.0];original=FETCHER['os'].link
        def late_link(*args):original(*args);now[0]+=121
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-deadline-') as temporary:
            destination=Path(temporary)
            with mock.patch.object(FETCHER['os'],'link',side_effect=late_link), self.assertRaisesRegex(VerificationError,'total'):
                self.fetch(destination,lambda request,**kwargs:FakeResponse(request.full_url,self.payload),now)
            self.assertEqual(self.payload,(destination/self.specification['fileName']).read_bytes())

    def test_late_flush_and_success_output_refuse_without_cache_corruption(self):
        for phase in ('fsync','success-output'):
            now=[0.0];original=FETCHER['os'].fsync
            def fsync(fd):
                original(fd)
                if phase=='fsync':now[0]+=121
            def output(text):
                if phase=='success-output' and text.startswith('fetched and verified'):now[0]+=121
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-deadline-') as temporary:
                destination=Path(temporary)
                with mock.patch.object(FETCHER['os'],'fsync',side_effect=fsync), mock.patch.dict(fetch_artifact.__globals__,print=output), self.assertRaisesRegex(VerificationError,'total'):
                    self.fetch(destination,lambda request,**kwargs:FakeResponse(request.full_url,self.payload),now)
                target=destination/self.specification['fileName']
                self.assertEqual(phase=='success-output',target.exists())
                if target.exists():self.assertEqual(self.payload,target.read_bytes())

    def test_alarm_interrupting_opener_is_attempt_timeout_not_endpoint_success(self):
        now=[0.0];calls=[];module=FETCHER['signal']
        def opener(request,**kwargs):
            calls.append(request.full_url)
            handler=self.signal.call_args.args[1]
            now[0]+=21
            handler(module.SIGALRM,None)
            self.fail('deadline handler returned')
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-deadline-') as temporary:
            with self.assertRaisesRegex(VerificationError,'deadline'):self.fetch(Path(temporary),opener,now)
            self.assertFalse((Path(temporary)/self.specification['fileName']).exists())
        self.assertEqual(mock.call(module.SIGALRM,module.SIG_DFL),self.signal.call_args)
        self.assertTrue(calls)

    def test_concurrent_corrupt_cache_never_overwritten(self):
        now=[0.0]
        def contested_link(staged,target):
            target.write_bytes(b'corrupt')
            raise FileExistsError('inert concurrent cache')
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-deadline-') as temporary:
            destination=Path(temporary)
            with mock.patch.object(FETCHER['os'],'link',side_effect=contested_link), self.assertRaises(VerificationError):
                self.fetch(destination,lambda request,**kwargs:FakeResponse(request.full_url,self.payload),now)
            self.assertEqual(b'corrupt',(destination/self.specification['fileName']).read_bytes())

    def test_retry_sleep_is_capped_to_remaining_total(self):
        now=[0.0];sleeps=[]
        def opener(*args,**kwargs):now[0]+=119.75;raise urllib.error.URLError('inert')
        def sleep(delay):sleeps.append(delay);now[0]+=delay
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-deadline-') as temporary:
            with self.assertRaisesRegex(VerificationError,'total'):
                fetch_artifact(Path(temporary),self.specification,'fixture',opener=opener,
                               monotonic=lambda:now[0],sleeper=sleep)
        self.assertEqual([.25],sleeps)

    def test_alarm_capability_restore_and_dedicated_timeout(self):
        Clock=FETCHER['FetchClock'];Deadline=FETCHER['FetchDeadline'];module=FETCHER['signal']
        now=[0.0]
        with self.assertRaisesRegex(VerificationError,'preexisting'), mock.patch.object(module,'getitimer',return_value=(1.0,0.0)):
            with Clock(lambda:now[0]):pass
        self.signal.assert_not_called();self.setitimer.assert_not_called()
        with self.assertRaisesRegex(Deadline,'attempt'):
            with Clock(lambda:now[0]) as clock:
                clock.arm(attempt=True)
                clock._expired()
        self.assertEqual(mock.call(module.SIGALRM,module.SIG_DFL),self.signal.call_args)
        self.assertEqual(mock.call(module.ITIMER_REAL,0),self.setitimer.call_args)
        with mock.patch.object(FETCHER['threading'],'current_thread',return_value=object()), self.assertRaisesRegex(VerificationError,'main-thread'):
            with Clock(lambda:0):pass

    def test_guard_teardown_late_success_is_refused_after_restoration(self):
        now=[0.0];module=FETCHER['signal']
        def timer(which,delay):
            if delay==0:now[0]=121
        self.setitimer.side_effect=timer
        with self.assertRaisesRegex(FETCHER['FetchDeadline'],'total'):
            with FETCHER['FetchClock'](lambda:now[0]):pass
        self.assertEqual(mock.call(module.SIGALRM,module.SIG_DFL),self.signal.call_args)

    def test_primary_failure_uses_verified_official_fallback(self) -> None:
        attempted: list[str] = []

        def opener(request: object, **unused: object) -> FakeResponse:
            url = request.full_url  # type: ignore[attr-defined]
            attempted.append(url)
            if "ftp.gnu.org" in url:
                raise urllib.error.URLError("primary unavailable")
            return FakeResponse(url, self.payload)

        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix="gcc-fetch-fallback-") as temporary:
            fetched = fetch_artifact(
                Path(temporary),
                self.specification,
                "fixture signature",
                opener=opener,
                sleeper=lambda unused: None,
            )

            self.assertEqual(self.payload, fetched.read_bytes())
            self.assertEqual(3, len(attempted))
            self.assertIn("gcc.gnu.org", attempted[-1])

    def test_all_endpoint_failures_are_reported_and_leave_no_target(self) -> None:
        def opener(request: object, **unused: object) -> FakeResponse:
            raise urllib.error.URLError(request.full_url)  # type: ignore[attr-defined]

        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix="gcc-fetch-failure-") as temporary:
            destination = Path(temporary)
            with self.assertRaisesRegex(VerificationError, "any official endpoint") as failure:
                fetch_artifact(
                    destination,
                    self.specification,
                    "fixture signature",
                    opener=opener,
                    sleeper=lambda unused: None,
                )

            for url in official_candidate_urls(str(self.specification["url"])):
                self.assertIn(url, str(failure.exception))
            self.assertFalse((destination / str(self.specification["fileName"])).exists())

    def test_corrupt_fallback_bytes_are_rejected_without_partial_cache(self) -> None:
        corrupt = b"x" * len(self.payload)

        def opener(request: object, **unused: object) -> FakeResponse:
            return FakeResponse(request.full_url, corrupt)  # type: ignore[attr-defined]

        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix="gcc-fetch-corrupt-") as temporary:
            destination = Path(temporary)
            with self.assertRaisesRegex(VerificationError, "SHA-256 mismatch"):
                fetch_artifact(
                    destination,
                    self.specification,
                    "fixture signature",
                    opener=opener,
                    sleeper=lambda unused: None,
                )

            self.assertFalse((destination / str(self.specification["fileName"])).exists())

    def test_verified_existing_artifact_is_reused_without_network(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix="gcc-fetch-cache-") as temporary:
            destination = Path(temporary)
            target = destination / str(self.specification["fileName"])
            target.write_bytes(self.payload)

            reused = fetch_artifact(
                destination,
                self.specification,
                "fixture signature",
                opener=lambda *args, **kwargs: self.fail("network must not be used"),
            )

            self.assertEqual(target, reused)


if __name__ == "__main__":
    unittest.main()
