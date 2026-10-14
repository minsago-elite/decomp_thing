"""Real Unix alarm controls in bounded benign Python children; no network fetch."""
from pathlib import Path
import hashlib
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHILD_PREFIX = r'''
import os,runpy,signal,sys,time

def deny(event,args):
    if event.startswith(('subprocess.','os.exec','os.spawn','os.fork')) or event in ('os.system','pty.spawn','socket.connect','socket.getaddrinfo'):
        raise AssertionError('child network/process operation forbidden: '+event)
sys.addaudithook(deny)
module=runpy.run_path(sys.argv[1],run_name='signal_control_import')
Clock=module['FetchClock'];Deadline=module['FetchDeadline'];Error=module['VerificationError']
# Test-only accelerated budget, never a production limit change/qualification.
Clock.__init__.__globals__['FETCH_TIMEOUT_SECONDS']=0.2
Clock.__init__.__globals__['FETCH_TOTAL_SECONDS']=1.2
'''


class GccOracleRealSignalDeadlineTest(unittest.TestCase):
    child_observations = []

    @classmethod
    def setUpClass(cls):
        required = ('SIGALRM','ITIMER_REAL','setitimer','getitimer','pthread_sigmask','sigpending','sigtimedwait')
        if os.name != 'posix' or any(not hasattr(signal,name) for name in required):
            if sys.platform.startswith('linux'):
                raise AssertionError('required Linux real deadline-signal capability unavailable')
            raise unittest.SkipTest('UNSUPPORTED_PLATFORM: Unix alarm control requires POSIX signal APIs')
        cls.controller_end = time.monotonic() + 20
        cls.child_observations = []
        (ROOT/'build').mkdir(mode=0o700,parents=True,exist_ok=True)

    def child(self, body, expected, marker):
        remaining = self.controller_end-time.monotonic()
        self.assertGreater(remaining,0,'20-second aggregate controller budget exhausted')
        with tempfile.TemporaryDirectory(dir=ROOT/'build',prefix='fetch-real-signal-') as directory:
            work=Path(directory)
            for name in ('home','tmp'):(work/name).mkdir(mode=0o700)
            environment={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(work/'home'),
                         'TMPDIR':str(work/'tmp'),'TMP':str(work/'tmp'),'TEMP':str(work/'tmp'),
                         'PYTHONDONTWRITEBYTECODE':'1'}
            script=CHILD_PREFIX+body
            argv=[sys.executable,'-I','-B','-c',script,str(ROOT/'scripts/fetch-gcc-oracle-source.py')]
            began=time.monotonic()
            try:
                result=subprocess.run(argv,cwd=work,env=environment,stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                      timeout=min(3,remaining),check=False)
            except subprocess.TimeoutExpired as error:
                self.child_observations.append({'case':marker,'timeout':True,'elapsedSeconds':time.monotonic()-began})
                self.fail('benign Python child exceeded controller deadline: '+marker)
            observation={'case':marker,'returncode':result.returncode,'stdout':result.stdout.decode('ascii',errors='replace'),
                         'stderr':result.stderr.decode('ascii',errors='replace'),'elapsedSeconds':time.monotonic()-began,
                         'scriptSha256':hashlib.sha256(script.encode()).hexdigest(),'argvPrefix':argv[:4],
                         'sourcePath':argv[-1],'environment':environment,'controllerSeconds':min(3,remaining)}
            self.child_observations.append(observation)
            self.assertLessEqual(len(result.stdout)+len(result.stderr),4096,'unexpected child diagnostics')
            self.assertEqual(expected,result.returncode,observation)
            self.assertEqual(marker+'\n',observation['stdout'],observation)
            self.assertEqual('',observation['stderr'],observation)

    def test_real_attempt_alarm_keeps_original_total_armed_during_blocking_exit(self):
        self.child(r'''
class BlockingExit:
    def __enter__(self):return self
    def __exit__(self,kind,error,traceback):
        assert isinstance(error,Deadline) and error.phase=='attempt'
        sampled_before=time.monotonic()
        remaining,interval=signal.getitimer(signal.ITIMER_REAL)
        assert 0 < remaining <= clock.total_end-sampled_before+0.03 and interval==0
        print('ATTEMPT_UNWIND_TOTAL_ARMED',flush=True)
        time.sleep(2)  # Finite fallback; the original total alarm must exit124 first.
        raise AssertionError('total deadline failed to terminate blocked unwind')
with Clock(time.monotonic) as clock:
    clock.arm(attempt=True)
    with BlockingExit():time.sleep(2)
raise AssertionError('fatal total alarm returned')
''',124,'ATTEMPT_UNWIND_TOTAL_ARMED')

    def test_real_success_teardown_restores_handler_timer_and_mask(self):
        self.child(r'''
def previous(signum,frame):raise AssertionError('prior handler unexpectedly invoked')
signal.signal(signal.SIGALRM,previous)
mask=signal.pthread_sigmask(signal.SIG_BLOCK,[])
with Clock(time.monotonic) as clock:
    clock.arm(attempt=True)
    assert signal.getsignal(signal.SIGALRM)!=previous
assert signal.getsignal(signal.SIGALRM) is previous
assert signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0)
assert signal.pthread_sigmask(signal.SIG_BLOCK,[])==mask
assert signal.SIGALRM not in signal.sigpending()
print('SUCCESS_STATE_RESTORED')
''',0,'SUCCESS_STATE_RESTORED')

    def test_real_blocked_and_pending_inherited_alarm_refused_before_ownership(self):
        self.child(r'''
def previous(signum,frame):raise AssertionError('inherited pending alarm delivered')
signal.signal(signal.SIGALRM,previous)
old=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGALRM})
for pending in (False,True):
    if pending:os.kill(os.getpid(),signal.SIGALRM)
    before=signal.sigpending()
    try:
        with Clock(time.monotonic):raise AssertionError('blocked alarm admitted')
    except Error as error:assert 'blocked or pending' in str(error)
    assert signal.getsignal(signal.SIGALRM) is previous
    assert signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0)
    assert signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK,[])
    assert signal.sigpending()==before
    if pending:
        info=signal.sigtimedwait({signal.SIGALRM},0)
        assert info is not None and info.si_signo==signal.SIGALRM
signal.pthread_sigmask(signal.SIG_SETMASK,old)
print('INHERITED_ALARM_UNCHANGED')
''',0,'INHERITED_ALARM_UNCHANGED')

    def test_real_existing_timer_is_refused_without_changing_owner(self):
        self.child(r'''
def previous(signum,frame):raise AssertionError('prior timer unexpectedly fired')
signal.signal(signal.SIGALRM,previous)
signal.setitimer(signal.ITIMER_REAL,2)
try:
    try:
        with Clock(time.monotonic):raise AssertionError('existing timer admitted')
    except Error as error:assert 'preexisting alarm' in str(error)
    assert signal.getsignal(signal.SIGALRM) is previous
    remaining,interval=signal.getitimer(signal.ITIMER_REAL)
    assert 0 < remaining <= 2 and interval==0
finally:signal.setitimer(signal.ITIMER_REAL,0)
print('EXISTING_TIMER_UNCHANGED')
''',0,'EXISTING_TIMER_UNCHANGED')


if __name__=='__main__':unittest.main()
