from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
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
        (REPOSITORY_ROOT/'build').mkdir(mode=0o700,parents=True,exist_ok=True)
        # No real alarms/signals/network: retain actual guard logic with fake timer APIs.
        module = fetch_artifact.__globals__['signal']
        exit_patch=mock.patch.object(FETCHER['os'],'_exit',side_effect=AssertionError('unexpected real/fatal exit'))
        self.fatal_exit=exit_patch.start();self.addCleanup(exit_patch.stop)
        for name,value in [('pthread_sigmask',set()),('sigpending',set()),('sigtimedwait',None),('getitimer',(0.0,0.0)),('getsignal',module.SIG_DFL),('signal',None),('setitimer',(0.0,0.0))]:
            patcher=mock.patch.object(module,name,return_value=value)
            setattr(self,name,patcher.start());self.addCleanup(patcher.stop)

    def fetch(self,destination,opener,now,**kwargs):
        return fetch_artifact(destination,self.specification,'fixture signature',opener=opener,
                              monotonic=lambda:now[0],sleeper=lambda delay:now.__setitem__(0,now[0]+delay),**kwargs)

    def test_total_delivery_before_teardown_mask_is_fatal_for_success_and_existing_failure(self):
        Clock = FETCHER["FetchClock"]
        module = FETCHER["signal"]
        class AuthoredFatalExit(BaseException):
            pass
        for failure in (None, VerificationError("authored existing failure")):
            with self.subTest(existing_failure=failure is not None):
                now = [0.0]
                clock = Clock(lambda: now[0])
                clock.__enter__()
                self.fatal_exit.reset_mock()
                self.fatal_exit.side_effect = AuthoredFatalExit("authored exit124")
                timer_calls = len(self.setitimer.call_args_list)
                def deliver_before_block(how, signals):
                    self.assertEqual(module.SIG_BLOCK, how)
                    self.assertEqual({module.SIGALRM}, signals)
                    now[0] = 120.0
                    clock._expired(module.SIGALRM, None)
                    return set()
                with mock.patch.object(module, "pthread_sigmask", side_effect=deliver_before_block):
                    with self.assertRaises(AuthoredFatalExit):
                        clock.__exit__(None if failure is None else type(failure), failure, None)
                self.fatal_exit.assert_called_once_with(124)
                self.assertFalse(clock.closing, "total delivery must be adjudicated before closing is published")
                self.assertEqual(timer_calls, len(self.setitimer.call_args_list), "fatal delivery must not disarm the owned guard")

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

    def test_late_eof_is_refused_before_fsync_or_publication(self):
        now=[0.0];opened=[]
        class LateEof(FakeResponse):
            def read1(inner,amount):
                chunk=super().read1(amount)
                if not chunk:now[0]=120
                return chunk
        def opener(request,**kwargs):
            opened.append(request.full_url)
            return LateEof(request.full_url,self.payload)
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-late-eof-') as temporary:
            with mock.patch.object(FETCHER['os'],'fsync') as fsync,self.assertRaisesRegex(VerificationError,'total'):
                self.fetch(Path(temporary),opener,now)
            fsync.assert_not_called()
            self.assertFalse((Path(temporary)/self.specification['fileName']).exists())
        self.assertEqual(1,len(opened))

    def test_opener_timeout_keeps_fractional_remaining_total_without_one_second_floor(self):
        now=[0.0];timeouts=[];sleeps=[]
        def context():now[0]=119.75;return object()
        def opener(request,**kwargs):
            timeouts.append(kwargs['timeout'])
            raise urllib.error.URLError('authored endpoint refusal')
        def sleep(delay):sleeps.append(delay);now[0]+=delay
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-remaining-') as temporary:
            with mock.patch.object(FETCHER['ssl'],'create_default_context',side_effect=context),self.assertRaisesRegex(VerificationError,'total'):
                fetch_artifact(Path(temporary),self.specification,'fixture signature',opener=opener,
                               monotonic=lambda:now[0],sleeper=sleep)
            self.assertFalse((Path(temporary)/self.specification['fileName']).exists())
        self.assertEqual([.25],timeouts);self.assertEqual([.25],sleeps)
        self.assertEqual(120,now[0])

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
            if len(calls)>1:return FakeResponse(request.full_url,self.payload)
            handler=self.signal.call_args.args[1]
            now[0]+=21
            handler(module.SIGALRM,None)
            self.fail('deadline handler returned')
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-deadline-') as temporary:
            result=self.fetch(Path(temporary),opener,now)
            self.assertEqual(self.payload,result.read_bytes())
        self.assertEqual(mock.call(module.SIGALRM,module.SIG_DFL),self.signal.call_args)
        self.assertEqual(2,len(calls))

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
                now[0]=20
                clock._expired()
        self.assertEqual(mock.call(module.SIGALRM,module.SIG_DFL),self.signal.call_args)
        self.assertEqual(mock.call(module.ITIMER_REAL,0),self.setitimer.call_args)
        with mock.patch.object(FETCHER['threading'],'current_thread',return_value=object()), self.assertRaisesRegex(VerificationError,'main-thread'):
            with Clock(lambda:0):pass

    def test_attempt_alarm_rearms_original_total_before_context_unwind(self):
        now=[0.0];module=FETCHER['signal'];observed=[]
        class ClosingResponse(FakeResponse):
            def read1(inner,amount):
                now[0]=21
                clock._expired()
            def __exit__(inner,*unused):
                observed.append(self.setitimer.call_args)
                self.assertEqual(mock.call(module.ITIMER_REAL,99.0),self.setitimer.call_args)
                self.assertEqual(('total',120),clock.state)
        with self.assertRaisesRegex(FETCHER['FetchDeadline'],'attempt'):
            with FETCHER['FetchClock'](lambda:now[0]) as clock:
                clock.arm(attempt=True)
                with ClosingResponse('https://ftp.gnu.org',self.payload) as response:
                    response.read1(1)
        self.assertEqual(1,len(observed))

    def test_inherited_blocked_or_pending_alarm_rejected_without_ownership_change(self):
        module=FETCHER['signal']
        for mask,pending in [({module.SIGALRM},set()),(set(),{module.SIGALRM})]:
            self.signal.reset_mock();self.setitimer.reset_mock()
            with mock.patch.object(module,'pthread_sigmask',return_value=mask), mock.patch.object(module,'sigpending',return_value=pending), self.assertRaisesRegex(VerificationError,'blocked or pending'):
                with FETCHER['FetchClock'](lambda:0):pass
            self.signal.assert_not_called();self.setitimer.assert_not_called()

    def test_teardown_blocks_disarms_drains_then_restores_handler_and_mask(self):
        module=FETCHER['signal'];events=[]
        self.pthread_sigmask.side_effect=lambda how,mask:events.append(('mask',how,mask)) or set()
        self.setitimer.side_effect=lambda which,delay:events.append(('timer',delay))
        self.sigtimedwait.side_effect=lambda signals,timeout:events.append(('drain',signals,timeout))
        self.signal.side_effect=lambda which,handler:events.append(('handler',handler))
        with FETCHER['FetchClock'](lambda:0):pass
        block=max(index for index,event in enumerate(events) if event==('mask',module.SIG_BLOCK,{module.SIGALRM}))
        self.assertEqual([('mask',module.SIG_BLOCK,{module.SIGALRM}),('timer',0),('drain',{module.SIGALRM},0),
                          ('handler',module.SIG_DFL),('mask',module.SIG_SETMASK,set())],events[block:])

    def test_total_alarm_during_attempt_unwind_uses_fatal_exit_without_new_grace(self):
        now=[0.0];module=FETCHER['signal']
        class FatalExit(BaseException):pass
        self.fatal_exit.side_effect=FatalExit
        class ClosingResponse(FakeResponse):
            def __exit__(inner,*unused):
                self.assertEqual(mock.call(module.ITIMER_REAL,99.0),self.setitimer.call_args)
                now[0]=120
                clock._expired()
        with self.assertRaises(FatalExit):
            with FETCHER['FetchClock'](lambda:now[0]) as clock:
                clock.arm(attempt=True)
                with ClosingResponse('https://ftp.gnu.org',self.payload):
                    now[0]=21
                    clock._expired()
        self.fatal_exit.assert_called_once_with(124)
        self.assertEqual([0,120,0,20,99.0,0],[call.args[1] for call in self.setitimer.call_args_list])

    def test_total_alarm_exits_without_cleanup_window_and_cannot_return(self):
        now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);now[0]=120
        class FatalExit(BaseException):pass
        self.fatal_exit.side_effect=FatalExit
        with self.assertRaises(FatalExit):clock._expired()
        self.fatal_exit.assert_called_once_with(124)
        self.setitimer.assert_not_called()  # No new grace or total deadline reset.
        self.fatal_exit.side_effect=None
        with self.assertRaisesRegex(RuntimeError,'unexpectedly returned'):clock._expired()

    def test_guard_teardown_late_success_is_refused_after_restoration(self):
        now=[0.0];module=FETCHER['signal']
        original=FETCHER['FetchClock'].__exit__
        def teardown(clock,*args):
            def timer(which,delay):
                if clock.closing and delay==0:now[0]=121
            self.setitimer.side_effect=timer
            return original(clock,*args)
        with self.assertRaisesRegex(FETCHER['FetchDeadline'],'total'):
            with mock.patch.object(FETCHER['FetchClock'],'__exit__',teardown):
                with FETCHER['FetchClock'](lambda:now[0]):pass
        self.assertEqual(mock.call(module.SIGALRM,module.SIG_DFL),self.signal.call_args)

    def test_early_total_callback_rearms_same_end_without_total_failure(self):
        now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);module=FETCHER['signal']
        now[0]=20
        clock._expired()
        self.assertEqual(('total',120),clock.state)
        self.assertEqual(mock.call(module.ITIMER_REAL,100),self.setitimer.call_args)
        self.fatal_exit.assert_not_called()

    def test_old_attempt_before_retry_marker_keeps_next_attempt_and_verified_fallback(self):
        Clock=FETCHER['FetchClock'];original=Clock._replace;now=[0.0];calls=[];injected=[]
        def replace(clock,desired):
            if desired[0]=='total' and clock.state[0]=='attempt' and not injected:
                injected.append(desired)
                clock._expired()  # Due old callback BEFORE replacement can claim its marker.
            return original(clock,desired)
        def opener(request,**kwargs):
            calls.append(request.full_url)
            if len(calls)==1:
                now[0]=20
                raise urllib.error.URLError('authored attempt boundary')
            return FakeResponse(request.full_url,self.payload)
        with mock.patch.object(Clock,'_replace',replace), tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-transition-') as temporary:
            target=self.fetch(Path(temporary),opener,now)
            self.assertEqual(self.payload,target.read_bytes())
        self.assertEqual([('total',120)],injected)
        self.assertEqual(2,len(calls))
        self.assertEqual(calls[0],calls[1])
        self.assertEqual(21,now[0])

    def test_old_attempt_continuation_keeps_precomputed_new_attempt_end(self):
        Clock=FETCHER['FetchClock'];now=[0.0];clock=Clock(lambda:now[0]);clock.arm(attempt=True)
        now[0]=20;original=clock._replace;seen=[]
        def replace(desired):
            seen.append(desired)
            if len(seen)==1:
                clock._expired()
            return original(desired)
        with mock.patch.object(clock,'_replace',side_effect=replace):clock.arm(attempt=True)
        self.assertEqual([('attempt',40),('attempt',40)],seen)
        self.assertEqual(('attempt',40),clock.state)
        self.assertEqual(20,clock.check())

    def test_attempt_due_while_arming_never_reaches_opener_and_next_attempt_is_bounded(self):
        Clock=FETCHER['FetchClock'];original=Clock.arm;now=[0.0];calls=[];attempt_ends=[];injected=[]
        def arm(clock,attempt=False):
            if attempt:attempt_ends.append(min(clock.total_end,now[0]+20))
            return original(clock,attempt)
        def timer(which,delay):
            if delay==20 and not injected:
                injected.append(True);now[0]=20
                self.signal.call_args.args[1]()
        def opener(request,**kwargs):
            calls.append((request.full_url,kwargs['timeout']))
            return FakeResponse(request.full_url,self.payload)
        self.setitimer.side_effect=timer
        with mock.patch.object(Clock,'arm',arm), tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT/'build',prefix='fetch-admission-') as temporary:
            target=self.fetch(Path(temporary),opener,now)
            self.assertEqual(self.payload,target.read_bytes())
        self.assertEqual([20,41],attempt_ends)
        self.assertEqual([(self.specification['url'],20)],calls)
        self.assertEqual(21,now[0])

    def test_uncommitted_attempt_anchor_cannot_be_recomputed_after_callback(self):
        now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);clock.arm(attempt=True)
        now[0]=20;injected=[]
        def current():
            if not injected:
                injected.append(True)
                clock._expired()
            return now[0]
        clock.now=current
        with self.assertRaisesRegex(FETCHER['FetchDeadline'],'attempt'):clock.arm(attempt=True)
        self.assertEqual(('total',120),clock.state)
        self.assertEqual(100,self.setitimer.call_args.args[1])

    def test_attempt_consumed_during_rearm_or_before_clear_installs_total_before_refusal(self):
        for stage in ('rearm','before-clear'):
            for when in (20.0,20.25):
                with self.subTest(stage=stage,when=when):
                    now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);original=clock._adjudicate
                    observations=[];injected=[];inherited={FETCHER['signal'].SIGUSR1}
                    self.pthread_sigmask.return_value=inherited
                    def callback():
                        injected.append(True);now[0]=when
                        self.assertTrue(clock.replacing)
                        clock._expired()  # No OS pending bit is needed for a Python callback.
                    def timer(which,delay):
                        if delay==20 and stage=='rearm' and not injected:callback()
                    def observe(desired):
                        observations.append(clock.replacing)
                        result=original(desired)
                        if len(observations)==2 and stage=='before-clear':callback()
                        return result
                    self.setitimer.side_effect=timer
                    with mock.patch.object(clock,'_adjudicate',side_effect=observe), self.assertRaisesRegex(FETCHER['FetchDeadline'],'attempt'):
                        clock.arm(attempt=True)
                    self.assertEqual([True],injected)
                    self.assertEqual(('total',120),clock.state)
                    self.assertFalse(clock.replacing)
                    self.assertEqual(120-when,self.setitimer.call_args.args[1])
                    self.assertEqual(mock.call(FETCHER['signal'].SIG_SETMASK,inherited),self.pthread_sigmask.call_args)
                    self.fatal_exit.assert_not_called()

    def test_postclear_callback_is_caught_with_coherent_total_guard_and_mask(self):
        now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);original=clock._adjudicate;injected=[]
        inherited={FETCHER['signal'].SIGUSR1};self.pthread_sigmask.return_value=inherited
        def observe(desired):
            if not clock.replacing and not injected:
                injected.append(True);now[0]=20
                clock._expired()
            return original(desired)
        with mock.patch.object(clock,'_adjudicate',side_effect=observe), self.assertRaisesRegex(FETCHER['FetchDeadline'],'attempt'):
            clock.arm(attempt=True)
        self.assertEqual([True],injected)
        self.assertEqual(('total',120),clock.state)
        self.assertEqual(100,self.setitimer.call_args.args[1])
        self.assertFalse(clock.replacing)
        self.assertEqual(mock.call(FETCHER['signal'].SIG_SETMASK,inherited),self.pthread_sigmask.call_args)

    def test_total_expiry_in_transition_is_fatal_even_when_pending_set_is_empty(self):
        class FatalExit(BaseException):pass
        self.fatal_exit.side_effect=FatalExit
        for stage in ('drain','rearm','before-clear','after-clear'):
            for when in (120.0,120.25):
                with self.subTest(stage=stage,when=when):
                    self.fatal_exit.reset_mock();now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0])
                    original=clock._adjudicate;observations=[];injected=[]
                    def callback():
                        injected.append(True);now[0]=when;clock._expired()
                    def drain(*unused):
                        if stage=='drain' and not injected:callback()
                    def timer(which,delay):
                        if stage=='rearm' and delay==20 and not injected:callback()
                    def observe(desired):
                        observations.append(clock.replacing)
                        if stage=='after-clear' and not clock.replacing and not injected:callback()
                        result=original(desired)
                        if stage=='before-clear' and len(observations)==2 and not injected:callback()
                        return result
                    self.sigtimedwait.side_effect=drain;self.setitimer.side_effect=timer
                    with mock.patch.object(clock,'_adjudicate',side_effect=observe), self.assertRaises(FatalExit):
                        clock.arm(attempt=True)
                    self.assertEqual([True],injected)
                    self.assertTrue(self.fatal_exit.called)
                    self.assertTrue(all(call==mock.call(124) for call in self.fatal_exit.call_args_list))
                    self.assertFalse(clock.replacing)
                    self.assertEqual(mock.call(FETCHER['signal'].SIG_SETMASK,set()),self.pthread_sigmask.call_args)

    def test_total_expiry_during_attempt_retirement_never_grants_unwind_grace(self):
        class FatalExit(BaseException):pass
        self.fatal_exit.side_effect=FatalExit
        for when in (120.0,120.25):
            with self.subTest(when=when):
                now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);injected=[]
                def timer(which,delay):
                    if delay==20:now[0]=20
                    elif delay==100 and not injected:
                        injected.append(True);now[0]=when
                self.setitimer.side_effect=timer
                with self.assertRaises(FatalExit):clock.arm(attempt=True)
                self.assertEqual([True],injected)
                self.assertEqual(('total',120),clock.state)
                self.assertFalse(clock.replacing)
                self.assertTrue(all(call==mock.call(124) for call in self.fatal_exit.call_args_list))

    def test_attempt_retirement_preserves_fractional_original_total(self):
        now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);now[0]=99.75
        def timer(which,delay):
            if delay==20:now[0]=119.75
        self.setitimer.side_effect=timer
        with self.assertRaisesRegex(FETCHER['FetchDeadline'],'attempt'):clock.arm(attempt=True)
        self.assertEqual(('total',120),clock.state)
        self.assertEqual(.25,self.setitimer.call_args.args[1])
        self.fatal_exit.assert_not_called()

    def test_early_callbacks_on_both_sides_of_clear_preserve_same_attempt_end(self):
        now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);original=clock._adjudicate;seen=[]
        def observe(desired):
            stage='before' if clock.replacing else 'after'
            if stage not in seen:
                seen.append(stage);now[0]=5
                clock._expired()
            return original(desired)
        with mock.patch.object(clock,'_adjudicate',side_effect=observe):clock.arm(attempt=True)
        self.assertEqual(['before','after'],seen)
        self.assertEqual(('attempt',20),clock.state)
        self.assertEqual(15,clock.check())
        self.assertEqual(15,self.setitimer.call_args.args[1])
        self.fatal_exit.assert_not_called()

    def test_attempt_callback_during_mask_restore_completes_exact_restore(self):
        now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);module=FETCHER['signal'];inherited={module.SIGUSR1};restores=[]
        def mask(how,value):
            if how==module.SIG_SETMASK:
                restores.append(value)
                if len(restores)==1:
                    self.assertFalse(clock.replacing);now[0]=20;clock._expired()
            return inherited
        self.pthread_sigmask.side_effect=mask
        with self.assertRaisesRegex(FETCHER['FetchDeadline'],'attempt'):clock.arm(attempt=True)
        self.assertEqual([inherited,inherited],restores)
        self.assertEqual(('total',120),clock.state)
        self.assertEqual(100,self.setitimer.call_args.args[1])

    def test_transition_uses_one_zero_drain_and_preserves_primary_syscall_failures(self):
        module=FETCHER['signal']
        for stage in ('block','disarm','drain','rearm'):
            with self.subTest(stage=stage):
                clock=FETCHER['FetchClock'](lambda:0);failure=OSError('authored transition failure');events=[]
                inherited={module.SIGUSR1}
                def mask(how,value):
                    events.append(('mask',how,value))
                    if how==module.SIG_BLOCK and stage=='block':raise failure
                    return inherited
                def timer(which,delay):
                    events.append(('timer',delay))
                    if (stage=='disarm' and delay==0) or (stage=='rearm' and delay>0):raise failure
                def drain(signals,timeout):
                    events.append(('drain',signals,timeout))
                    if stage=='drain':raise failure
                self.pthread_sigmask.side_effect=mask;self.setitimer.side_effect=timer;self.sigtimedwait.side_effect=drain
                with self.assertRaises(OSError) as raised:clock.arm(attempt=True)
                self.assertIs(failure,raised.exception)
                self.assertFalse(clock.replacing)
                self.assertLessEqual(sum(event[0]=='drain' for event in events),1)
                if stage!='block':self.assertEqual(('mask',module.SIG_SETMASK,inherited),events[-1])
                else:self.assertEqual(1,len(events))

    def test_total_callback_during_mask_restore_is_fatal_not_another_attempt(self):
        class FatalExit(BaseException):pass
        self.fatal_exit.side_effect=FatalExit
        now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);module=FETCHER['signal'];restores=[]
        def mask(how,value):
            if how==module.SIG_SETMASK:
                restores.append(value)
                self.assertFalse(clock.replacing);now[0]=120;clock._expired()
            return set()
        self.pthread_sigmask.side_effect=mask
        with self.assertRaises(FatalExit):clock.arm(attempt=True)
        self.assertEqual([set()],restores)
        self.fatal_exit.assert_called_once_with(124)

    def test_deferred_attempt_does_not_hide_original_transition_failure(self):
        module=FETCHER['signal']
        for stage in ('postclear','restore'):
            with self.subTest(stage=stage):
                self.setitimer.side_effect=None;self.pthread_sigmask.side_effect=None
                self.pthread_sigmask.return_value=set()
                now=[0.0];clock=FETCHER['FetchClock'](lambda:now[0]);clock.arm(attempt=True)
                now[0]=20;failure=OSError('authored failed disarm');failed=[];injected=[]
                def timer(which,delay):
                    if delay==0 and not failed:
                        failed.append(True);raise failure
                def current():
                    if stage=='postclear' and not clock.replacing and failed and not injected:
                        injected.append(True);clock._expired()
                    return now[0]
                def mask(how,value):
                    if stage=='restore' and how==module.SIG_SETMASK and not injected:
                        injected.append(True);clock._expired()
                    return set()
                clock.now=current;self.setitimer.side_effect=timer;self.pthread_sigmask.side_effect=mask
                with self.assertRaises(OSError) as raised:clock.arm(attempt=True)
                self.assertIs(failure,raised.exception)
                self.assertEqual([True],injected)
                self.assertEqual(('total',120),clock.state)
                self.assertFalse(clock.replacing)
                self.assertEqual(mock.call(module.SIG_SETMASK,set()),self.pthread_sigmask.call_args)

    def test_successful_transition_blocks_disarms_drains_once_and_restores_exact_mask(self):
        clock=FETCHER['FetchClock'](lambda:0);module=FETCHER['signal'];events=[];inherited={module.SIGUSR1}
        self.pthread_sigmask.side_effect=lambda how,value:events.append(('mask',how,value)) or inherited
        self.setitimer.side_effect=lambda which,delay:events.append(('timer',delay))
        self.sigtimedwait.side_effect=lambda signals,timeout:events.append(('drain',signals,timeout)) or SimpleNamespace(si_signo=module.SIGALRM)
        clock.arm(attempt=True)
        self.assertEqual([('mask',module.SIG_BLOCK,{module.SIGALRM}),('timer',0),
                          ('drain',{module.SIGALRM},0),('timer',20),('mask',module.SIG_SETMASK,inherited)],events)
        self.assertEqual(('attempt',20),clock.state)
        self.assertFalse(clock.replacing)

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


def _native_deadline_fixture(case: str, root: Path) -> None:
    """Child-only authored timer fixture; no network, verifier child or source release."""
    if case not in {"attempt", "total", "attempt-unwind"}:
        raise ValueError("unknown native deadline case")
    root = root.resolve()
    if not root.is_relative_to((REPOSITORY_ROOT / "build").resolve()):
        raise ValueError("native deadline fixture must stay in the repository build directory")
    namespace = fetch_artifact.__globals__
    namespace["FETCH_TIMEOUT_SECONDS"] = 0.20
    namespace["FETCH_TOTAL_SECONDS"] = 3.0 if case == "attempt" else 1.20
    Clock = namespace["FetchClock"]
    Deadline = namespace["FetchDeadline"]
    prior_handler = signal.getsignal(signal.SIGALRM)
    prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    observation = {
        "case": case,
        "fetcherSha256": hashlib.sha256((REPOSITORY_ROOT / "scripts/fetch-gcc-oracle-source.py").read_bytes()).hexdigest(),
        "fixtureSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "pythonVersion": sys.version,
        "scope": "actual FetchClock signal delivery in one authored child; no network or release proof",
    }
    (root / "verified-cache").write_bytes(b"previous verified fixture")
    (root / "owned-staging").write_bytes(b"partial unverified fixture")
    (root / "observation.json").write_text(json.dumps(observation) + "\n")
    started = time.monotonic()
    if case == "attempt":
        ticks = 0
        try:
            with Clock(time.monotonic) as clock:
                clock.arm(attempt=True)
                while True:
                    ticks += 1
                    time.sleep(0.01)  # No cooperative clock.check: delivery must interrupt progress.
        except Deadline as failure:
            observation.update(phase=failure.phase, elapsedSeconds=time.monotonic() - started,
                progressTicks=ticks, timerDisarmed=signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
                handlerRestored=signal.getsignal(signal.SIGALRM) == prior_handler,
                maskRestored=signal.pthread_sigmask(signal.SIG_BLOCK, set()) == prior_mask)
            (root / "observation.json").write_text(json.dumps(observation) + "\n")
            return
    else:
        with Clock(time.monotonic) as clock:
            if case == "attempt-unwind":
                clock.arm(attempt=True)
            try:
                while True:
                    time.sleep(0.01)
            finally:
                (root / "python-finally-entered").write_text("entered")
                if case == "attempt-unwind":
                    time.sleep(10)  # The original total guard must stay armed during this unwind.
                (root / "python-finally-completed").write_text("completed")
    raise AssertionError("native deadline fixture unexpectedly returned")


class GccOracleSourceFetchNativeDeadlineTest(unittest.TestCase):
    def run_fixture(self, case):
        build = REPOSITORY_ROOT / "build"
        build.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build, prefix="fetch-native-deadline-") as temporary:
            root = Path(temporary)
            command = [sys.executable, "-B", str(Path(__file__).resolve()), "--native-deadline-fixture", case, str(root)]
            started = time.monotonic()
            result = subprocess.run(command, cwd=REPOSITORY_ROOT,
                env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(root)},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8, check=False)
            observation = json.loads((root / "observation.json").read_text())
            observation.update(returnCode=result.returncode, childWallSeconds=time.monotonic() - started,
                command=command, finallyEntered=(root / "python-finally-entered").exists(),
                finallyCompleted=(root / "python-finally-completed").exists())
            self.assertEqual(b"previous verified fixture", (root / "verified-cache").read_bytes())
            self.assertEqual(b"partial unverified fixture", (root / "owned-staging").read_bytes())
            self.assertEqual("", result.stdout, result.stdout)
            self.assertEqual("", result.stderr, result.stderr)
            print("native-fetch-deadline " + json.dumps(observation, sort_keys=True), flush=True)
            return observation

    def test_actual_attempt_alarm_interrupts_progress_and_restores_owned_signal_state(self):
        observed = self.run_fixture("attempt")
        self.assertEqual(0, observed["returnCode"], observed)
        self.assertEqual("attempt", observed["phase"], observed)
        self.assertGreater(observed["progressTicks"], 1, observed)
        self.assertLess(observed["elapsedSeconds"], 2, observed)
        self.assertTrue(observed["timerDisarmed"], observed)
        self.assertTrue(observed["handlerRestored"], observed)
        self.assertTrue(observed["maskRestored"], observed)

    def test_actual_total_alarm_exits124_without_python_cleanup_or_cache_overwrite(self):
        observed = self.run_fixture("total")
        self.assertEqual(124, observed["returnCode"], observed)
        self.assertFalse(observed["finallyEntered"], observed)
        self.assertFalse(observed["finallyCompleted"], observed)

    def test_actual_attempt_unwind_remains_under_the_original_fatal_total_alarm(self):
        observed = self.run_fixture("attempt-unwind")
        self.assertEqual(124, observed["returnCode"], observed)
        self.assertTrue(observed["finallyEntered"], observed)
        self.assertFalse(observed["finallyCompleted"], observed)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--native-deadline-fixture":
        _native_deadline_fixture(sys.argv[2], Path(sys.argv[3]))
    else:
        unittest.main()
