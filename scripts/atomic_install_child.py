"""Linux per-launch sole-reaper custody. No numeric signals or global adoption.

A catastrophic supervisor death cannot prove descendant settlement. Such owners
remain unresolved; this is cooperative finite-tree custody, not containment.
"""
from __future__ import annotations

import array
import ctypes
import errno
import hashlib
import json
import math
import os
import pathlib
import resource
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager

MAX_FRAME = 16384
MAX_CHILDREN = 8192
CLEANUP_SECONDS = 10
STARTUP_SECONDS = 10
_ADMISSION = threading.RLock()


@contextmanager
def admission(deadline):
    if not _ADMISSION.acquire(timeout=max(0, deadline-time.monotonic())):
        raise TimeoutError('descriptor admission exceeded original startup deadline')
    try:
        if time.monotonic() >= deadline:
            raise TimeoutError('startup expired before descriptor admission')
        yield
    finally:
        _ADMISSION.release()


class OwnershipError(RuntimeError):
    pass


class FD:
    """Detach before exactly one close, including EINTR/wrapper uncertainty."""
    def __init__(self, number):
        self.number = number
        self.close_error = None

    def close(self):
        number, self.number = self.number, None
        if number is not None:
            try:
                os.close(number)
            except BaseException as failure:
                self.close_error = failure
                raise


def retire_all(handles):
    primary = sys.exception()
    errors = []
    for handle in handles:
        try:
            handle.close()
        except BaseException as failure:
            errors.append(failure)
    if errors:
        if primary is not None:
            for failure in errors:
                primary.add_note('Descriptor close uncertainty: ' + repr(failure))
            return  # Never replace the original protocol/startup failure.
        for failure in errors[1:]:
            errors[0].add_note(repr(failure))
        raise errors[0]


def readable(fd):
    poll = select.poll()  # Unlike select(), supports descriptor numbers >1023.
    poll.register(fd, select.POLLIN)
    return bool(poll.poll(0))


def receive(sock):
    """Take custody of every delivered right BEFORE any frame validation."""
    raw, ancillary, flags, _ = sock.recvmsg(MAX_FRAME, socket.CMSG_SPACE(256 * 4), socket.MSG_CMSG_CLOEXEC)
    rights = []
    transferred = False
    try:
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array('i')
                values.frombytes(data[:len(data) - len(data) % values.itemsize])
                rights.extend(FD(number) for number in values)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise OwnershipError('truncated protocol frame')
        if not raw:
            raise EOFError('supervisor transport EOF')
        if any(level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS for level, kind, _ in ancillary):
            raise OwnershipError('unexpected ancillary data')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise OwnershipError('duplicate protocol key')
                result[key] = value
            return result
        frame = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(frame, dict):
            raise OwnershipError('protocol frame is not an object')
        transferred = True
        return frame, rights
    finally:
        if not transferred:
            primary = sys.exception()
            try:
                retire_all(rights)
            except BaseException as failure:
                if primary is None:
                    raise
                primary.add_note('Received-FD close uncertainty: ' + repr(failure))


def packet(nonce, direction, seq, kind, **data):
    return dict(v=1, nonce=nonce, direction=direction, seq=seq, kind=kind, **data)


def validate(frame, nonce, direction, seq, kind, keys):
    expected = {'v', 'nonce', 'direction', 'seq', 'kind'} | set(keys)
    if (set(frame) != expected or type(frame.get('v')) is not int or frame.get('v') != 1 or type(frame.get('seq')) is not int or
            frame.get('nonce') != nonce or frame.get('direction') != direction or
            frame.get('seq') != seq or frame.get('kind') != kind):
        raise OwnershipError('wrong protocol schema/nonce/direction/sequence/state')


def encode(frame):
    raw = json.dumps(frame, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > MAX_FRAME:
        raise OwnershipError('protocol frame exceeds bound')
    return raw


def send(sock, frame, fd=None):
    rights = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]
    raw = encode(frame)
    if sock.sendmsg([raw], rights) != len(raw):
        raise OwnershipError('partial seqpacket send')


def capacity(reserve):
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY:
        soft = 1 << 20
    baseline = len(os.listdir('/proc/self/fd'))
    usable = int(soft) - baseline - reserve
    if usable < 2:
        raise OwnershipError('insufficient reserved descriptor headroom')
    return min(MAX_CHILDREN, usable)


def interpreter():
    # The harness can expose an AppImage as sys.executable. /proc/self/exe is
    # the actual executing ELF, never that unverified application alias.
    executable = pathlib.Path('/proc/self/exe').resolve(strict=True)
    if not executable.name.startswith('python') or not os.access(executable, os.X_OK):
        raise OwnershipError('executing Python interpreter cannot be verified')
    return str(executable)


def validate_pidfd(handle, pid):
    if type(pid) is not int or pid <= 0:
        raise OwnershipError('invalid actual PID')
    if os.readlink(f'/proc/self/fd/{handle.number}') != 'anon_inode:[pidfd]':
        raise OwnershipError('BOUND descriptor is not a pidfd')
    with open(f'/proc/self/fdinfo/{handle.number}', 'rb') as stream:
        data = stream.read(4097)
    if len(data) > 4096 or b'Pid:\t' + str(pid).encode() + b'\n' not in data:
        raise OwnershipError('BOUND pidfd identity mismatch')


def status(result):
    if result.si_code == os.CLD_EXITED:
        return result.si_status
    if result.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
        return -result.si_status
    raise OwnershipError('nonterminal child status')


class ActualProcess:
    def __init__(self, owner, pid, args, stdout):
        self.owner, self.pid, self.args, self.stdout = owner, pid, args, stdout
        self.returncode = None

    def poll(self):
        # A pending EXIT is NOT evidence of liveness; use is_running below.
        return self.returncode

    def is_running(self):
        return self.returncode is None and not self.owner.actual_exited()

    def wait(self, timeout=None):
        deadline = time.monotonic() + timeout if timeout is not None else self.owner.phase_deadline
        with self.owner._condition:
            while self.returncode is None:
                if self.owner._protocol_error:
                    raise self.owner._protocol_error
                if self.owner.error:
                    raise self.owner.error
                if self.owner.cleanup_deadline is not None and time.monotonic() >= self.owner.cleanup_deadline:
                    raise OwnershipError('actual status unresolved at original cleanup deadline')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(self.args, timeout)
                self.owner._condition.wait(min(.05, remaining))
            return self.returncode


class Child:
    def __init__(self, args, *, env=None, cwd=None, log, active, phase_deadline=None, max_log=16*1024*1024):
        started = time.monotonic()
        self.phase_deadline = phase_deadline if phase_deadline is not None else float('inf')
        self.startup_deadline = min(self.phase_deadline, started + STARTUP_SECONDS)
        self.cleanup_deadline = None
        self.log = pathlib.Path(log)
        self.error = self._protocol_error = None
        self.tail, self.total = bytearray(), 0
        self.max_log = max_log
        self.process = self._helper = None
        self._helper_fd = self._actual_fd = None
        self._socket = self._peer = self.sink = self._output = None
        self.reader = self.pump = None
        self._condition = threading.Condition(threading.RLock())
        self._close_lock = threading.RLock()
        self._send_lock = threading.RLock()
        self._reader_stop = threading.Event()
        self._pump_stop = threading.Event()
        self._protocol_complete = False
        self._nonce = uuid.uuid4().hex
        self._args = list(map(str, args))
        self._pre_go_receipt = None
        self._initial_received = False
        self._out_seq = self._in_seq = 0
        self._started = self._exec_error = None
        self.settlement = None
        self._exit_ready = self._complete = False
        self._active = active
        self._active.add(self)  # Provisional receipt precedes all fallible work.
        reserves = []
        try:
            with admission(self.startup_deadline):
                if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
                    raise OwnershipError('parent requires default SIGCHLD and sole helper waiter')
                capacity(24)
                # Real reservations, not a concurrent check pretending to reserve.
                for _ in range(8):
                    reserves.append(FD(os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)))
                self.log.parent.mkdir(parents=True, exist_ok=True)
                self.sink = self.log.open('xb', buffering=0)
                self._socket, self._peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                self._socket.setblocking(False)
                command = [interpreter(), '-I', '-B', str(pathlib.Path(__file__).resolve()),
                           str(self._peer.fileno()), self._nonce, str(self.startup_deadline),
                           str(self.phase_deadline), *map(str, args)]
                self._helper = subprocess.Popen(command, pass_fds=(self._peer.fileno(),), cwd=cwd, env=env,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
                self._output = self._helper.stdout
                # No poll/wait precedes this exact helper-handle retention.
                self._helper_fd = FD(os.pidfd_open(self._helper.pid))
                peer, self._peer = self._peer, None
                peer.close()
                frame, rights = self._receive_start()
                self._bind(frame, rights)
                os.set_blocking(self._output.fileno(), False)
                self.reader = threading.Thread(target=self._drain, name='atomic-output', daemon=True)
                self.pump = threading.Thread(target=self._pump, name='atomic-protocol', daemon=True)
                self.reader.start(); self.pump.start()
                self._send('GO', deadline=self.startup_deadline)
                retire_all(reserves); reserves = []
            with self._condition:
                while self._started is None and self._exec_error is None and self.process.returncode is None:
                    if self._protocol_error:
                        raise self._protocol_error
                    remaining = self.startup_deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('actual command startup deadline expired')
                    self._condition.wait(min(.05, remaining))
                if self._exec_error is not None:
                    item = self._exec_error
                    raise OSError(item['errno'], item['stage'], item['filename'])
        except BaseException as primary:
            self._trigger_cleanup()
            try:
                self.close()
            except BaseException as secondary:
                primary.add_note('Secondary child cleanup failure: ' + repr(secondary))
            raise
        finally:
            if self._peer is not None:
                peer, self._peer = self._peer, None
                peer.close()
            retire_all(reserves)

    def _bind(self, frame, rights):
        self._initial_received = True
        try:
            kind = frame.get('kind')
            if kind in ('REFUSED', 'ABORTED'):
                keys = {'errno', 'message'} if kind == 'REFUSED' else {'pid', 'code', 'actualReaped', 'echild', 'message'}
                validate(frame, self._nonce, 'helper', 0, kind, keys)
                if rights or not isinstance(frame['message'], str) or len(frame['message']) > 4096:
                    raise OwnershipError('invalid pre-GO failure receipt')
                if kind == 'REFUSED':
                    if type(frame['errno']) is not int or not 0 < frame['errno'] < 4096:
                        raise OwnershipError('invalid preflight errno')
                elif (type(frame['pid']) is not int or frame['pid'] <= 0 or type(frame['code']) is not int or
                      frame['actualReaped'] is not True or frame['echild'] is not True):
                    raise OwnershipError('invalid gated-child abort receipt')
                self._pre_go_receipt = frame
                raise OSError(frame.get('errno', errno.EIO), frame['message'], self._args[0])
            validate(frame, self._nonce, 'helper', 0, 'BOUND', {'pid'})
            if len(rights) != 1:
                raise OwnershipError('BOUND must deliver exactly one descriptor')
            validate_pidfd(rights[0], frame['pid'])
            self._actual_fd = rights.pop()
            self.process = ActualProcess(self, frame['pid'], self._args, self._output)
            self._in_seq = 1
        finally:
            retire_all(rights)

    def _receive_start(self):
        while True:
            try:
                return receive(self._socket)
            except BlockingIOError:
                if time.monotonic() >= self.startup_deadline:
                    raise TimeoutError('BOUND startup deadline expired')
                poll = select.poll(); poll.register(self._socket, select.POLLIN)
                poll.poll(max(0, min(50, int((self.startup_deadline-time.monotonic())*1000))))

    def _send(self, kind, *, deadline, **data):
        with self._send_lock:
            while True:
                try:
                    send(self._socket, packet(self._nonce, 'parent', self._out_seq, kind, **data))
                    self._out_seq += 1
                    return
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('protocol send deadline expired')
                    poll = select.poll(); poll.register(self._socket, select.POLLOUT); poll.poll(10)

    def _trigger_cleanup(self, deadline=None):
        with self._condition:
            value = time.monotonic() + CLEANUP_SECONDS if deadline is None else deadline
            self.cleanup_deadline = value if self.cleanup_deadline is None else min(self.cleanup_deadline, value)
            self._condition.notify_all()
            return self.cleanup_deadline

    def actual_exited(self):
        if self._exit_ready:
            return True
        if self._actual_fd is not None and self._actual_fd.number is not None:
            self._exit_ready = readable(self._actual_fd.number)
        return self._exit_ready

    def _accept(self, frame, rights):
        try:
            if rights:
                raise OwnershipError('unexpected late descriptors')
            kind = frame.get('kind')
            keys = {'STARTED': {'pid'}, 'EXEC_ERROR': {'pid', 'errno', 'filename', 'stage'},
                    'EXIT': {'pid', 'code', 'deadline'},
                    'SETTLED': {'pid', 'code', 'deadline', 'actualReaped', 'allRegisteredReaped', 'echild', 'error', 'reaped', 'sample', 'reapDigest'}}
            if kind not in keys:
                raise OwnershipError('unknown helper state')
            validate(frame, self._nonce, 'helper', self._in_seq, kind, keys[kind])
            if type(frame['pid']) is not int or frame['pid'] != self.process.pid:
                raise OwnershipError('actual PID changed')
            if kind in ('STARTED', 'EXEC_ERROR'):
                if self._started is not None or self._exec_error is not None or self.process.returncode is not None:
                    raise OwnershipError('duplicate/reordered startup')
                if kind == 'STARTED':
                    self._started = True
                else:
                    if type(frame['errno']) is not int or not 0 < frame['errno'] < 4096 or not all(isinstance(frame[k], str) and len(frame[k]) <= 4096 for k in ('filename', 'stage')):
                        raise OwnershipError('invalid exec error')
                    self._exec_error = frame
            elif kind == 'EXIT':
                if type(frame['deadline']) not in (int, float) or not math.isfinite(frame['deadline']) or not 0 < frame['deadline'] <= time.monotonic()+CLEANUP_SECONDS:
                    raise OwnershipError('invalid EXIT cleanup deadline')
                if self.process.returncode is not None or type(frame['code']) is not int:
                    raise OwnershipError('duplicate/invalid actual exit')
                self.process.returncode = frame['code']
                self._trigger_cleanup(frame['deadline'])
            else:
                if (self.settlement is not None or self.process.returncode is None or frame['code'] != self.process.returncode or
                        any(frame[k] is not True for k in ('actualReaped', 'allRegisteredReaped', 'echild')) or not self.actual_exited()):
                    raise OwnershipError('incomplete actual settlement ACK')
                if (type(frame['deadline']) not in (int, float) or not math.isfinite(frame['deadline']) or
                        not 0 < frame['deadline'] <= time.monotonic()+CLEANUP_SECONDS or type(frame['reaped']) is not int or frame['reaped'] < 1 or
                        not isinstance(frame['sample'], list) or len(frame['sample']) > 32 or
                        not isinstance(frame['reapDigest'], str) or len(frame['reapDigest']) != 64 or
                        (frame['error'] is not None and (not isinstance(frame['error'], str) or len(frame['error']) > 4096))):
                    raise OwnershipError('invalid settlement receipt')
                self._trigger_cleanup(frame['deadline'])
                self.settlement = frame
                if frame['error'] is not None:
                    self.error = self.error or OwnershipError(frame['error'])
            self._in_seq += 1
        finally:
            retire_all(rights)

    def _pump(self):
        try:
            while not self._pump_stop.is_set():
                if self.cleanup_deadline is not None and time.monotonic() >= self.cleanup_deadline:
                    return
                try:
                    frame, rights = receive(self._socket)
                except BlockingIOError:
                    poll = select.poll(); poll.register(self._socket, select.POLLIN); poll.poll(25)
                    continue
                except (EOFError, ConnectionResetError):
                    if self.settlement is None:
                        raise OwnershipError('supervisor lost before settlement; descendants unresolved')
                    self._protocol_complete = True
                    return
                with self._condition:
                    self._accept(frame, rights)
                    self._condition.notify_all()
        except BaseException as failure:
            with self._condition:
                self._protocol_error = failure
                self.error = self.error or failure
                self._trigger_cleanup()
                self._condition.notify_all()
            # EOF makes the live helper settle independently; no cross-thread
            # descriptor close used as a wakeup mechanism.
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _drain(self):
        try:
            poll = select.poll(); poll.register(self._output, select.POLLIN)
            while not self._reader_stop.is_set():
                if self.cleanup_deadline is not None and time.monotonic() >= self.cleanup_deadline:
                    return
                if not poll.poll(25):
                    continue
                try:
                    chunk = os.read(self._output.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    return
                remaining = max(0, self.max_log-self.total)
                data = chunk[:remaining]
                if data and self.sink.write(data) != len(data):
                    raise OSError('short output sink write')
                self.total += len(chunk)
                self.tail.extend(chunk); del self.tail[:-12000]
                if self.total > self.max_log:
                    raise RuntimeError(f'output exceeded {self.max_log} bytes: {self.log}')
        except BaseException as failure:
            with self._condition:
                self.error = self.error or failure
            deadline = self._trigger_cleanup()
            try:
                self._send('STOP', deadline=deadline, cleanup=deadline)
            except BaseException as secondary:
                failure.add_note('Output STOP failure: ' + repr(secondary))

    def close(self):
        with self._close_lock:
            if self._complete:
                if self.error:
                    raise self.error
                return
            deadline = self._trigger_cleanup()
            if self._peer is not None:
                peer, self._peer = self._peer, None
                try: peer.close()
                except BaseException as failure: self.error = self.error or failure
            if self._helper is None:
                self._retire()
                return
            # Missing helper pidfd is a post-spawn fault, never permission to
            # poll/reap a PID before binding it. Its unreaped child pins identity.
            if self._helper_fd is None:
                try:
                    self._helper_fd = FD(os.pidfd_open(self._helper.pid))
                except OSError as failure:
                    self.error = self.error or failure
            if self.process is None and not self._initial_received:
                # A provisional-helper fault may precede receipt of BOUND. Keep
                # receiving under the ORIGINAL startup budget so cleanup can own
                # the exact gated root and consume its ACK instead of trusting
                # helper exit alone.
                try:
                    frame, rights = self._receive_start()
                    self._bind(frame, rights)
                except BaseException as failure:
                    self.error = self.error or failure
            if self.process is not None and (self.pump is None or self.pump.ident is None):
                # A reader-start/GO failure must still consume the exact ACK.
                self.pump = threading.Thread(target=self._pump, name='atomic-protocol', daemon=True)
                self.pump.start()
            if self.pump is None or self.pump.ident is None:
                if self._socket is not None:
                    self._socket.shutdown(socket.SHUT_WR)  # pre-GO gate abort
            elif self.settlement is None and self._protocol_error is None and self.process.returncode is None:
                try:
                    self._send('STOP', deadline=deadline, cleanup=deadline)
                except OSError:
                    pass  # Pump must validate pending ACK/EOF, never infer settlement.
                except TimeoutError as failure:
                    self._protocol_error = failure
            if self._protocol_error and self._actual_fd is not None and self._actual_fd.number is not None:
                # Catastrophic transport/helper loss: best effort is restricted
                # to this exact retained root. Unknown descendants stay unresolved.
                try:
                    signal.pidfd_send_signal(self._actual_fd.number, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            with self._condition:
                while self.settlement is None and self._protocol_error is None and self.process is not None:
                    left = deadline-time.monotonic()
                    if left <= 0:
                        break
                    self._condition.wait(min(.05, left))
            # Helper wait consumes only the helper. Actual waits belong solely
            # to its supervisor, even when the actual pidfd is readable here.
            helper_done = False
            if self._helper_fd is not None:
                try:
                    code = self._helper.wait(timeout=max(0, deadline-time.monotonic()))
                    helper_done = True
                    if code != 0:
                        self.error = self.error or OwnershipError(f'supervisor exited {code}')
                except subprocess.TimeoutExpired:
                    pass
            if self.settlement is None:
                self._reader_stop.set()
            if time.monotonic() >= deadline:
                self._pump_stop.set()
            for thread in (self.reader, self.pump):
                if thread is not None and thread.ident is not None:
                    thread.join(max(0, deadline-time.monotonic()))
            joined = all(t is None or t.ident is None or not t.is_alive() for t in (self.reader, self.pump))
            if joined and self.process is not None and not self._protocol_complete and not self._protocol_error:
                # An expired retry can harvest already delivered frames, without
                # restarting a reader, extending a deadline, or blocking.
                try:
                    for _ in range(8):
                        frame, rights = receive(self._socket)
                        with self._condition:
                            self._accept(frame, rights)
                except BlockingIOError:
                    pass
                except (EOFError, ConnectionResetError):
                    self._protocol_complete = self.settlement is not None
                except BaseException as failure:
                    self._protocol_error = failure
                    self.error = self.error or failure
            if self.settlement is not None and helper_done and joined and self._protocol_complete and self.actual_exited():
                self._retire()
            elif self.process is None and self._pre_go_receipt is not None and helper_done and joined:
                # Explicit no-child / exact gated-child abort proof, not EOF.
                self._retire()
            else:
                self.error = self.error or OwnershipError('cleanup deadline/transport loss: unresolved child custody')
            if self._protocol_error:
                raise self._protocol_error
            if self.error:
                raise self.error

    def _retire(self):
        failures = []
        for attr in ('_actual_fd', '_helper_fd', '_socket', '_output', 'sink'):
            resource_, setattr_value = getattr(self, attr), None
            setattr(self, attr, setattr_value)
            if resource_ is not None:
                try:
                    resource_.close()
                except BaseException as failure:
                    failures.append(failure)
        if failures:
            self.error = self.error or OwnershipError('descriptor close uncertainty: ' + repr(failures[0]))
        self._complete = True
        if not failures:
            self._active.discard(self)
        if self.process is not None:
            receipt = {'nonce': self._nonce, 'actualPid': self.process.pid, 'helperPid': self._helper.pid,
                       'actualCode': self.process.returncode, 'helperCode': self._helper.returncode,
                       'startupDeadline': self.startup_deadline, 'cleanupDeadline': self.cleanup_deadline,
                       'protocolComplete': self._protocol_complete, 'actualPidfdExited': self._exit_ready,
                       'settlement': self.settlement, 'error': repr(self.error) if self.error else None}
            try:
                self.log.with_suffix(self.log.suffix+'.ownership.json').write_text(json.dumps(receipt, indent=2)+'\n')
            except BaseException as failure:
                self.error = self.error or failure

    def wait(self, timeout):
        try:
            code = self.process.wait(timeout=timeout)
            if self.error:
                raise self.error
            return code
        finally:
            primary = sys.exception()
            try:
                self.close()
            except BaseException as secondary:
                if primary is None:
                    raise
                primary.add_note('Secondary child cleanup failure: ' + repr(secondary))

    def text(self):
        return self.tail.decode('utf-8', errors='replace')


class Supervisor:
    def __init__(self, sock, nonce, startup, phase, args):
        self.sock, self.nonce, self.startup, self.phase, self.args = sock, nonce, startup, phase, args
        self.handles, self.queue = {}, []
        self.seq = self.inseq = 0
        self.pid = self.code = self.deadline = None
        self.actual_reaped = False
        self.failure = None
        self.reaped = 0
        self.sample = []
        self.reap_digest = hashlib.sha256()
        self.peer = True
        self.gate = self.exec_read = None
        self.gate_read = self.error_write = None
        self.exec_data = bytearray()
        self.launched = self.start_sent = False
        self.bound_ack = False
        self.reserves = []

    def fail(self, error):
        if self.failure is None:
            # Preserve the primary acquisition/protocol error and bounded close
            # uncertainty notes in the receipt, not just in Python's context.
            detail = repr(error)[:3072]
            for note in getattr(error, '__notes__', ())[:4]:
                detail += '\n' + str(note)[:255]
            self.failure = detail[:4096]
        self.stop()

    def stop(self, deadline=None):
        value = time.monotonic()+CLEANUP_SECONDS if deadline is None else deadline
        self.deadline = value if self.deadline is None else min(self.deadline, value)
        if self.gate is not None:
            gate, self.gate = self.gate, None
            try:
                gate.close()
            except BaseException as failure:
                self.failure = self.failure or ('gate close uncertainty: ' + repr(failure))[:4096]

    def emit(self, kind, fd=None, **data):
        if len(self.queue) >= 8:
            raise OwnershipError('protocol queue bound')
        self.queue.append((packet(self.nonce, 'helper', self.seq, kind, pid=self.pid, **data), fd))
        self.seq += 1

    def flush(self):
        while self.queue and self.peer:
            frame, fd = self.queue[0]
            try:
                send(self.sock, frame, fd)
            except BlockingIOError:
                return
            except (BrokenPipeError, ConnectionResetError):
                self.peer = False; self.stop(); return
            self.queue.pop(0)

    def acquire(self, pid):
        # Called only for unreaped children of this sole waiter. There is NO
        # consuming wait between census and acquisition, so PID reuse cannot race.
        if pid in self.handles:
            return
        if len(self.handles) >= self.cap:
            raise OwnershipError('simultaneous child handle cap')
        handle = FD(os.pidfd_open(pid))
        try:
            os.waitid(os.P_PIDFD, handle.number, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except BaseException:
            retire_all([handle])
            raise
        self.handles[pid] = handle

    def census(self):
        deadline = min(time.monotonic()+2, self.deadline or self.phase)
        with open(f'/proc/self/task/{os.getpid()}/children', 'rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise OwnershipError('direct-child census byte bound')
        children = raw.split()
        if len(children) > MAX_CHILDREN:
            raise OwnershipError('direct-child census count bound')
        for value in children:
            if time.monotonic() >= deadline:
                raise TimeoutError('direct-child census deadline')
            self.acquire(int(value))

    def signal_owned(self, handle):
        try:
            signal.pidfd_send_signal(handle.number, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def harvest(self):
        for pid, handle in list(self.handles.items()):
            if pid == self.pid and not self.bound_ack and self.peer and time.monotonic() < self.startup:
                # Preserve the gated root's PID even if it dies before GO. Its
                # pidfd fdinfo remains verifiable until the parent binds it.
                continue
            result = os.waitid(os.P_PIDFD, handle.number, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if result is None:
                continue
            if result.si_pid != pid:
                raise OwnershipError('wait identity mismatch')
            if pid == self.pid and self.code is None:
                self.code = status(result)
                self.stop()
                self.emit('EXIT', code=self.code, deadline=self.deadline)
            result2 = os.waitid(os.P_PIDFD, handle.number, os.WEXITED | os.WNOHANG)
            if result2 is None or result2.si_pid != pid or status(result2) != status(result):
                raise OwnershipError('exact consuming wait mismatch')
            del self.handles[pid]  # Reap committed BEFORE the fallible close.
            self.reaped += 1
            self.reap_digest.update(f'{pid}:{status(result2)}\n'.encode())
            if len(self.sample) < 32:
                self.sample.append({'pid': pid, 'code': status(result2)})
            if pid == self.pid:
                self.actual_reaped = True
            handle.close()

    def empty(self):
        if self.handles:
            return False
        try:
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return True
        return False  # no event is NOT ECHILD

    def preflight(self):
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'subreaper setup')
        self.cap = capacity(16)
        for _ in range(8):
            self.reserves.append(FD(os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)))
        test = FD(os.pidfd_open(os.getpid()))
        try:
            signal.pidfd_send_signal(test.number, 0)
            try:
                os.waitid(os.P_PIDFD, test.number, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                pass
        finally:
            test.close()
        self.census()

    def initial_failure(self, kind, **data):
        frame = packet(self.nonce, 'helper', 0, kind, **data)
        while time.monotonic() < self.startup:
            try:
                send(self.sock, frame)
                return
            except BlockingIOError:
                time.sleep(.005)
            except (BrokenPipeError, ConnectionResetError):
                return

    def fork(self):
        self.gate_read, self.gate = map(FD, os.pipe2(os.O_CLOEXEC))
        self.exec_read, self.error_write = map(FD, os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK))
        self.pid = os.fork()
        if self.pid == 0:
            try:
                signal.signal(signal.SIGINT, signal.SIG_DFL)
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
                for name in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ'):
                    if hasattr(signal, name):
                        signal.signal(getattr(signal, name), signal.SIG_DFL)
                self.gate.close(); self.exec_read.close(); self.sock.close()
                for handle in self.reserves:
                    handle.close()
                if os.read(self.gate_read.number, 1) != b'G':
                    os._exit(125)
                self.gate_read.close()
                os.setsid()
                os.execvpe(self.args[0], self.args, os.environ)
            except BaseException as failure:
                detail = {'errno': getattr(failure, 'errno', None) or errno.EFAULT,
                          'filename': self.args[0][:4096], 'stage': str(failure)[:1024]}
                try:
                    os.write(self.error_write.number, json.dumps(detail).encode()[:8192])
                finally:
                    os._exit(127)
        self.gate_read.close(); self.error_write.close()
        os.close(1); os.close(2)  # Only the actual tree owns output writers.
        self.acquire(self.pid)
        self.emit('BOUND', fd=self.handles[self.pid].number)

    def control(self):
        if not self.peer:
            return
        try:
            frame, rights = receive(self.sock)
        except BlockingIOError:
            return
        except (EOFError, ConnectionResetError):
            self.peer = False; self.stop(); return
        try:
            if rights:
                raise OwnershipError('parent sent unexpected descriptors')
            kind = frame.get('kind')
            if kind not in ('GO', 'STOP'):
                raise OwnershipError('unknown parent state')
            validate(frame, self.nonce, 'parent', self.inseq, kind, set() if kind == 'GO' else {'cleanup'})
            self.inseq += 1
            self.bound_ack = True
            if kind == 'STOP':
                value = frame['cleanup']
                if type(value) not in (int, float) or not 0 < value <= time.monotonic()+CLEANUP_SECONDS:
                    raise OwnershipError('invalid cleanup deadline')
                self.stop(value)
            else:
                if self.launched or self.deadline is not None or time.monotonic() >= self.startup:
                    raise OwnershipError('GO outside original startup deadline')
                try:
                    os.write(self.gate.number, b'G')
                except BrokenPipeError:
                    pass  # Pre-exec death: preserve the actual negative EXIT.
                gate, self.gate = self.gate, None
                self.launched = True
                gate.close()
        finally:
            retire_all(rights)

    def startup_result(self):
        if self.start_sent:
            return
        try:
            data = os.read(self.exec_read.number, 8193-len(self.exec_data))
        except BlockingIOError:
            return
        self.exec_data.extend(data)
        if len(self.exec_data) > 8192:
            raise OwnershipError('exec error pipe bound')
        if data:
            return self.startup_result()  # bounded error bytes, then EOF before EXIT
        handle, self.exec_read = self.exec_read, None
        handle.close()
        self.start_sent = True
        if self.exec_data:
            self.emit('EXEC_ERROR', **json.loads(self.exec_data))
            self.stop()
        elif self.launched:
            # EOF alone is no claim of successful exec: actual EXIT still governs.
            self.emit('STARTED')

    def run(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: self.stop())
        try:
            self.preflight()
            self.fork()
        except BaseException as failure:
            if self.pid is None:
                self.initial_failure('REFUSED', errno=getattr(failure, 'errno', None) or errno.EIO,
                                     message=repr(failure)[:4096])
                return 1  # Explicit preflight/no-child receipt.
            self.fail(failure)
            # Acquisition failed before BOUND/GO. Closing the gate prevents any
            # exec; the sole waiter may reap this exact unreaped gated child.
            if not self.handles:
                while True:
                    try:
                        pid, code = os.waitpid(self.pid, os.WNOHANG)
                        if pid == self.pid:
                            self.actual_reaped = True
                            if not self.empty():
                                raise OwnershipError('gated abort lacks ECHILD')
                            self.initial_failure('ABORTED', pid=pid, code=os.waitstatus_to_exitcode(code),
                                                 actualReaped=True, echild=True, message=self.failure)
                            return 1
                    except InterruptedError:
                        pass
                    # On expiry retain custody; only completed status harvesting
                    # continues. No new allowance and no numeric signal.
                    time.sleep(.005)
        while True:
            try:
                self.flush()
                self.control()
                self.startup_result()
                if not self.start_sent and time.monotonic() >= self.startup:
                    self.fail(TimeoutError('startup deadline'))
                self.harvest()
                if self.deadline is not None:
                    if time.monotonic() < self.deadline:
                        try:
                            self.census()
                        except BaseException as failure:
                            self.fail(failure)
                            reserves, self.reserves = self.reserves, []
                            retire_all(reserves)
                        for handle in list(self.handles.values()):
                            try:
                                self.signal_owned(handle)
                            except BaseException as failure:
                                self.fail(failure)
                        self.harvest()
                    if self.empty():
                        if not self.actual_reaped or self.code is None:
                            raise OwnershipError('missing actual reap/status')
                        self.emit('SETTLED', code=self.code, deadline=self.deadline, actualReaped=True,
                                  allRegisteredReaped=True, echild=True, error=self.failure,
                                  reaped=self.reaped, sample=self.sample, reapDigest=self.reap_digest.hexdigest())
                        while self.queue and self.peer and time.monotonic() < self.deadline:
                            self.flush()
                            if self.queue:
                                time.sleep(.005)
                        return 0 if not self.queue or not self.peer else 1
                    if time.monotonic() >= self.deadline:
                        self.failure = self.failure or 'cleanup expired; live custody retained'
                        # No renewed work allowance: only exact completed handles
                        # are harvested on later turns. Unresolved helper stays alive.
            except BaseException as failure:
                self.fail(failure)
                if self.reserves:
                    reserves, self.reserves = self.reserves, []
                    try:
                        retire_all(reserves)
                    except BaseException as secondary:
                        self.fail(secondary)
            time.sleep(.005)


def main():
    sock = socket.socket(fileno=int(sys.argv[1])); sock.setblocking(False)
    owner = Supervisor(sock, sys.argv[2], float(sys.argv[3]), float(sys.argv[4]), sys.argv[5:])
    try:
        return owner.run()
    finally:
        # On normal settlement only; unresolved custody never exits the loop.
        retire_all(owner.reserves)
        sock.close()


if __name__ == '__main__':
    sys.exit(main())
