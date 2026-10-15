#!/usr/bin/env python3
"""Run the 42 v1 credential-free native provider guardian controls.

--include-v2 also runs separately counted authenticated terminal-receipt controls.

Usage: python3 scripts/verify-acp-provider-guardian.py [--output-dir build/NAME]
Requires Linux with usable bubblewrap user/PID/network namespaces, Python 3.9+,
/usr/bin/cc with static C libraries, /usr/bin/bwrap, and /usr/bin/readelf.
A missing prerequisite fails the command; no control is silently skipped.
All binaries, compiler temporary files and evidence stay inside this checkout.

This standalone candidate qualification does NOT admit a production cgroup,
authenticate a Codex runtime, or prove descendant channel separation. The fixture
supervisor requires ECHILD while its PID namespace is still live.

Historical control correction: a preliminary 64 KiB response fit available pipe
and socket buffers and recorded 0 ms sender blocking. That experiment failed its
backpressure assertion; the retained control uses 1 MiB and requires >=100 ms.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import select
import signal
import struct
import subprocess
import time
ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'src/main/c/decomp_acp_provider_guardian.c'
FIXTURE = ROOT / 'src/test/resources/acp/provider_guardian_fixture.c'
parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument(
    '--output-dir', type=pathlib.Path,
    default=ROOT / 'build/provider-guardian-qualification',
    help='Evidence directory inside this checkout (default: build/provider-guardian-qualification)',
)
parser.add_argument('--include-v2', action='store_true', help='Also run independent v2 terminal receipt controls')
parser.add_argument('--compare-prior-guardian', type=pathlib.Path,
                    help='Optional repository-local pre-fix guardian for startup regression comparison')
args = parser.parse_args()
if args.compare_prior_guardian and not args.include_v2:
    parser.error('--compare-prior-guardian requires --include-v2')
if not sys.platform.startswith('linux'):
    parser.error('Linux namespaces and Linux-specific guardian syscalls are required')
if not __debug__:
    parser.error('Python optimization (-O/PYTHONOPTIMIZE) disables qualification assertions')
BASE = (ROOT / args.output_dir).resolve()
if not BASE.is_relative_to(ROOT) or BASE == ROOT:
    parser.error('--output-dir must resolve strictly inside this checkout')
for prerequisite in ('cc', 'bwrap', 'readelf'):
    path = pathlib.Path('/usr/bin') / prerequisite
    if not path.is_file() or not os.access(path, os.X_OK):
        parser.error(f'required executable is unavailable: {path}')
BWRAP = pathlib.Path('/usr/bin/bwrap').resolve()
BASE.mkdir(parents=True, exist_ok=True)
RUN = BASE / f'run-{time.time_ns()}'
RUN.mkdir(mode=0o700)
TEMP = RUN / 'tmp'
TEMP.mkdir(mode=0o700)
ENV = {'PATH': '/usr/bin:/bin', 'TMPDIR': str(TEMP), 'LANG': 'C', 'UNTRUSTED_SENTINEL': 'must-not-reach-child'}
CAP = bytes(range(32))  # Deterministic synthetic capability, never a real credential.
LIMITS = (4096, 65536, 2048, 16, 1024, 2, 4, 128)
HEADERS = struct.pack('!HH', 200, 17) + b'text/event-stream'
CLEANUP_DOMAIN = bytes.fromhex('616370702d76322d636c65616e757000')
CLEANUP_GOLDEN = '4459a42aef304df78057779ff8fba8c874da172721f2e93a0e6d1566c297cc85'

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

INPUT_HASHES = {path: digest(path) for path in (SOURCE, FIXTURE, pathlib.Path(__file__).resolve())}
PRIOR_GUARDIAN = None
if args.compare_prior_guardian:
    PRIOR_GUARDIAN = (ROOT / args.compare_prior_guardian).resolve()
    if not PRIOR_GUARDIAN.is_relative_to(ROOT):
        parser.error('--compare-prior-guardian must resolve inside this checkout')
    INPUT_HASHES[PRIOR_GUARDIAN] = digest(PRIOR_GUARDIAN)
    if INPUT_HASHES[PRIOR_GUARDIAN] != '3a051d6335798e471c865fac800c8a984cbae6b071cedae19d5f5ca7490bb598':
        parser.error('--compare-prior-guardian does not match the retained pre-fix binary')
TOOLCHAIN = {
    name: {
        'path': str(pathlib.Path('/usr/bin') / name),
        'resolvedPath': str((pathlib.Path('/usr/bin') / name).resolve()),
        'sha256': digest((pathlib.Path('/usr/bin') / name).resolve()),
    }
    for name in ('cc', 'bwrap', 'readelf')
}

def frame(tag, seq=0, payload=b'', version=1):
    return struct.pack('!4sBBQI', b'ACPP', version, tag, seq, len(payload)) + payload

def setup(limits=LIMITS, times=(3000, 750, 500), version=1, features=1):
    baseline = CAP + bytes([0x11]) * 32 + bytes([0x22]) * 32 + struct.pack('!8I3Q', *limits, *times)
    return baseline + (struct.pack('!I', features) if version == 2 else b'')

def compile_one(source, output):
    source_hash = digest(source)
    command = ['/usr/bin/cc', '-std=c11', '-O2', '-static', '-Wall', '-Wextra', '-Werror', '-Wl,--build-id=none', str(source), '-o', str(output)]
    # The trusted compiler runs in its own process group so a timeout also stops
    # cc1/as/ld. Do not reap its leader before signalling the owned process group.
    p = subprocess.Popen(
        command, env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = p.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = p.communicate(timeout=3)
    finally:
        if p.returncode is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait(timeout=3)
        p.stdout.close()
        p.stderr.close()
    (RUN / (output.name + '-compile.stdout.log')).write_bytes(stdout)
    (RUN / (output.name + '-compile.stderr.log')).write_bytes(stderr)
    assert not timed_out, 'Static C compilation exceeded its deadline'
    assert p.returncode == 0, 'Static C compilation failed; inspect repository-local compiler logs: ' + str(RUN)
    assert digest(source) == source_hash, 'Compile input changed during compilation'
    return {
        'command': command, 'exitCode': p.returncode,
        'sourceSha256': source_hash, 'binarySha256': digest(output),
    }
BUILD = [compile_one(SOURCE, RUN / 'guardian'), compile_one(FIXTURE, RUN / 'fixture')]
BAD_EXECUTABLE = RUN / 'bad-executable'
BAD_EXECUTABLE.write_bytes(b'Not an executable format; this must make execveat fail.\n')
BAD_EXECUTABLE.chmod(0o555)
for binary in ('guardian', 'fixture'):
    p = subprocess.run(['/usr/bin/readelf', '-l', '-d', str(RUN / binary)], capture_output=True, env=ENV, timeout=5)
    assert p.returncode == 0 and b'INTERP' not in p.stdout and (b'NEEDED' not in p.stdout)
    (RUN / f'{binary}-elf.txt').write_bytes(p.stdout)
CHILDREN = []

class Case:

    def __init__(self, name, mode='success', initial=None, limits=LIMITS, times=(3000, 750, 500), version=1, child_path='/fixture', suite=None, supervisor='supervise', guardian_binary=None):
        self.name = name
        self.version = version
        self.suite = suite or ('v1' if version == 1 else 'v2')
        self.supervisor = supervisor
        self.times = times
        self.receipt = None
        self.dir = RUN / name
        self.dir.mkdir(mode=0o700)
        self.state = self.dir / 'state'
        self.state.mkdir(mode=0o700)
        guardian_binary = guardian_binary or RUN / 'guardian'
        assert guardian_binary.resolve().is_relative_to(ROOT)
        self.guardian_binary_sha256 = digest(guardian_binary)
        command = [str(BWRAP), '--unshare-all', '--new-session', '--die-with-parent', '--ro-bind', str(guardian_binary), '/guardian', '--ro-bind', str(RUN / 'fixture'), '/fixture']
        if child_path == '/bad-executable':
            command += ['--ro-bind', str(BAD_EXECUTABLE), child_path]
        for path in reversed(self.state.parents):
            if str(path) != '/':
                command += ['--dir', str(path)]
        command += (['--bind', str(self.state), str(self.state)] if version == 1 else ['--perms', '0700', '--dir', str(self.state)])
        command += ['--proc', '/proc', '--dev', '/dev', '--chdir', str(self.state), '--', '/fixture', supervisor, '/guardian', '--state-root', str(self.state), '--codex-path', '/fixture', '--', child_path, mode]
        self.command = command
        self.started = time.monotonic()
        self.p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, bufsize=0)
        CHILDREN.append(self.p)
        if version == 2 and mode == 'flood':
            assert fcntl.fcntl(self.p.stdout, fcntl.F_SETPIPE_SZ, 4096) == 4096
        os.set_blocking(self.p.stdin.fileno(), False)
        self.raw = bytearray()
        self.stderr = bytearray()
        self.frames = []
        self.acp = bytearray()
        self.requests = []
        self.guardian = None
        initial_frame = frame(7, payload=setup(limits, times, version), version=version) if initial is None else initial
        self.v2_selected = (len(initial_frame) >= 18 and
                            struct.unpack('!4sBBQI', initial_frame[:18]) == (b'ACPP', 2, 7, 0, 156))
        if version == 2 and initial is None:
            (self.dir / 'setup.bin').write_bytes(setup(limits, times, version))
        self.send(initial_frame)

    def send(self, data, timeout=5, release_after_pressure=False):
        deadline = time.monotonic() + timeout
        pressure_released = False
        try:
            while data:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f'{self.name}: bounded host write timed out')
                if release_after_pressure and not pressure_released:
                    poller = select.poll()
                    poller.register(self.p.stdin, select.POLLOUT)
                    began = time.monotonic()
                    events = poller.poll(min(150, int(remaining * 1000)))
                    assert all(not flags & (select.POLLERR | select.POLLHUP | select.POLLNVAL)
                               for _, flags in events), 'Provider fixture pipe closed during pressure control'
                    if not events:
                        blocked_ms = round((time.monotonic() - began) * 1000)
                        assert blocked_ms >= 100 and self.p.poll() is None
                        # Only this test-owned file releases the reader. A loaded
                        # CI host cannot let a fixed fixture sleep expire early.
                        fd = os.open(self.state / 'release-read',
                                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
                        os.close(fd)
                        self.non_writable_millis = blocked_ms
                        pressure_released = True
                        continue
                else:
                    _, writable, _ = select.select([], [self.p.stdin], [], remaining)
                    if not writable:
                        raise AssertionError(f'{self.name}: bounded host write timed out')
                try:
                    n = os.write(self.p.stdin.fileno(), data)
                except BlockingIOError:
                    continue
                assert n > 0
                data = data[n:]
            if release_after_pressure:
                assert pressure_released, 'Stream never demonstrated sustained backpressure'
        except BrokenPipeError:
            if release_after_pressure:
                raise AssertionError('Provider fixture pipe closed before completing pressure control')
            pass

    def pump(self, until=None, timeout=5, read_stdout=True):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            streams = [self.p.stderr] + ([self.p.stdout] if read_stdout else [])
            ready, _, _ = select.select(streams, [], [], 0.05)
            for stream in ready:
                data = os.read(stream.fileno(), 65536)
                if stream is self.p.stderr:
                    self.stderr.extend(data)
                    assert len(self.stderr) < 8192, 'unbounded diagnostics'
                    if b'SUPERVISOR guardian=' in self.stderr and b'namespace-still-live\n' in self.stderr:
                        msg = self.stderr.decode('ascii')
                        tail = msg.split('SUPERVISOR guardian=')[-1]
                        self.guardian = int(tail.split()[0])
                        self.cleanup = 'cleanup=ECHILD' in tail
                else:
                    self.raw.extend(data)
                    assert len(self.raw) < 262144, 'unbounded test capture'
                    while len(self.raw) >= 18:
                        magic, ver, tag, seq, n = struct.unpack('!4sBBQI', self.raw[:18])
                        assert magic == b'ACPP' and ver == self.version and (tag in ((1, 2, 6, 8) if ver == 2 else (1, 2, 6))) and (n <= 8 * 1024 * 1024)
                        if len(self.raw) < 18 + n:
                            break
                        payload = bytes(self.raw[18:18 + n])
                        del self.raw[:18 + n]
                        self.frames.append((tag, seq, payload))
                        assert self.receipt is None, 'Frame followed the final cleanup receipt'
                        if tag == 8:
                            assert ver == 2 and seq == 0 and n == 116
                            assert payload[:96] == setup()[:96], 'Wrong cleanup capability/policy/invocation identity'
                            assert hashlib.sha256(CLEANUP_DOMAIN + payload[:96]).hexdigest() == CLEANUP_GOLDEN
                            for domain in (CLEANUP_DOMAIN[:-1], b'\x00' + CLEANUP_DOMAIN[1:], CLEANUP_DOMAIN[:-1] + b'\x01'):
                                assert hashlib.sha256(domain + payload[:96]).hexdigest() != CLEANUP_GOLDEN
                            schema, cause, outcome, flags, status, count, mask, elapsed = struct.unpack('!4B4I', payload[96:])
                            assert schema == 1 and cause in (0, 1, 2, 3, 4, 5, 6, 255) and outcome in range(5)
                            present = bool(flags & 1)
                            assert present == (outcome != 0)
                            assert present or status == 0
                            if present:
                                assert (outcome == 1 and os.WIFEXITED(status)) or (os.WIFSIGNALED(status) and outcome == (2 if os.WTERMSIG(status) == 15 else 3 if os.WTERMSIG(status) == 9 else 4))
                            assert count == 0xffffffff or count in range(33)
                            assert bool(flags & 64) == (count == 0)
                            assert mask & ~0x3f == 0 and bool(flags & 16) == (mask == 0x3f)
                            assert elapsed <= self.times[2] + 1
                            assert bool(flags & 128) == (elapsed == self.times[2] + 1)
                            self.receipt = {'cause': cause, 'outcome': outcome, 'flags': flags, 'rawWaitStatus': status, 'remainingDescendants': count, 'closedDescriptorMask': mask, 'elapsedMillis': elapsed}
                            (self.dir / 'cleanup-frame.bin').write_bytes(frame(8, payload=payload, version=2))
                            (self.dir / 'cleanup-payload.bin').write_bytes(payload)
                            # Raw receipt identity is test-only; evidence records no capability bytes.
                        if tag == 1:
                            assert seq == 0
                            self.acp.extend(payload)
                        if tag == 2:
                            self.requests.append((seq, payload))
            if until and until(self):
                return
            if self.guardian is not None:
                return
            if self.p.poll() is not None:
                raise AssertionError(f'{self.name}: namespace exited without supervisor proof: {self.stderr!r}')
        raise AssertionError(f'{self.name}: control timeout')

    def request(self):
        self.pump(lambda c: len(c.requests) == 1)
        assert len(self.requests) == 1, (self.name, self.guardian, bytes(self.acp), self.stderr)
        seq, payload = self.requests[0]
        assert seq == 1 and payload[:32] == CAP and (payload[32:] == b'{"model":"fixture","input":"ping"}')

    def finish(self, expected, marker=None, read_stdout=True):
        self.pump(read_stdout=read_stdout)
        assert self.guardian in expected, (self.name, self.guardian, bytes(self.acp), self.stderr)
        assert self.cleanup, (self.name, self.stderr)
        if marker:
            assert marker in self.acp, (self.name, bytes(self.acp))
        assert self.p.poll() is None, 'namespace disappeared before cleanup observation'
        if not self.p.stdin.closed:
            self.send(b'\x1eDECOMP_SUPERVISOR_RELEASE\x1f')
            self.p.stdin.close()
        self.p.wait(timeout=2)
        assert self.p.returncode == 0
        assert CAP.hex().encode() not in self.stderr and CAP not in self.stderr
        prefix = bytes(self.stderr).split(b'SUPERVISOR guardian=', 1)[0]
        trace_lines = ([line.decode('ascii') for line in prefix.splitlines() if line.startswith(b'TRACE_')]
                       if self.supervisor != 'supervise' else [])
        guardian_stderr = b''.join(line for line in prefix.splitlines(keepends=True)
                                   if not (self.supervisor != 'supervise' and line.startswith(b'TRACE_')))
        if self.v2_selected:
            assert not guardian_stderr, (self.name, guardian_stderr)
        record = {
            'name': self.name,
            'command': self.command,
            'guardianExitCode': self.guardian,
            'supervisorExitCode': self.p.returncode,
            'cleanupBeforeNamespaceExit': 'ECHILD',
            'elapsedMillis': round((time.monotonic() - self.started) * 1000),
            'frameTags': [t for t, _, _ in self.frames],
            'providerSequences': [s for s, _ in self.requests],
            'ACPBytes': len(self.acp),
            'diagnostics': self.stderr.decode('ascii'),
            'stateFiles': [str(p.relative_to(self.state)) for p in self.state.rglob('*')],
        }
        if self.version == 2:
            record['cleanupReceipt'] = self.receipt
            record['guardianStderrBytes'] = len(guardian_stderr)
            record['guardianBinarySha256'] = self.guardian_binary_sha256
            if trace_lines:
                record['trustedSupervisorTrace'] = trace_lines
            record.pop('stateFiles')
            record['stateObservation'] = 'authenticated receipt; namespace-private root is not a host bind'
            if self.receipt:
                record['cleanupFrameSha256'] = digest(self.dir / 'cleanup-frame.bin')
                record['cleanupPayloadSha256'] = digest(self.dir / 'cleanup-payload.bin')
            if (self.dir / 'setup.bin').exists():
                record['setupSha256'] = digest(self.dir / 'setup.bin')
        (self.dir / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
        (RESULTS if self.suite == 'v1' else V2_RESULTS if self.suite == 'v2' else
         REVIEW_RESULTS if self.suite == 'review-regression' else PRIOR_RESULTS).append(record)
RESULTS = []
V2_RESULTS = []
REVIEW_RESULTS = []
PRIOR_RESULTS = []
try:
    c = Case('allowed-exchange')
    c.request()
    c.send(frame(3, 1, HEADERS) + frame(4, 1, b'data: fixture\n\n') + frame(5, 1, b'\x00'))
    c.finish({0}, b'HTTP_OK')
    assert len(c.requests) == 1
    c = Case('backpressured-final-no-redispatch', 'backpressure', limits=(4096, 1024 * 1024, 2048, 16, 1024, 2, 4, 128), times=(10000, 2000, 500))
    c.request()
    payload = b'data: fixture\n\n' + b'x' * (1024 * 1024 - 15)
    start = time.monotonic()
    c.send(frame(3, 1, HEADERS) + b''.join((frame(4, 1, payload[i:i + 1024]) for i in range(0, len(payload), 1024))) + frame(5, 1, b'\x00'), release_after_pressure=True)
    blocked_millis = round((time.monotonic() - start) * 1000)
    assert blocked_millis >= 100, blocked_millis
    c.finish({0}, b'HTTP_OK')
    assert len(c.requests) == 1
    RESULTS[-1]['boundedStreamBytes'] = len(payload)
    RESULTS[-1]['senderBackpressureMillis'] = blocked_millis
    RESULTS[-1]['observedNonWritableMillis'] = c.non_writable_millis
    c = Case('opaque-acp-smuggling', 'smuggle')
    c.finish({0}, b'ACPP')
    assert not c.requests and [x[0] for x in c.frames] == [1]
    c = Case('opaque-acp-echo', 'echo')
    c.pump(lambda x: b'ECHO_READY' in x.acp)
    c.send(frame(1, payload=b'opaque\x00\xffACP\n'))
    c.finish({0}, b'opaque\x00\xffACP\n')
    for mode in ('method', 'path', 'query', 'absolute', 'host', 'wrong-auth', 'duplicate-length', 'transfer-encoding', 'routing-header', 'bare-cr', 'duplicate-agent'):
        c = Case('http-deny-' + mode, mode)
        c.finish({0}, b'HTTP_DENIED')
        assert not c.requests
    for name, data in [('wrong-initial-role', frame(2, 1, b'x')), ('wrong-version', b'ACPP\x02\x07' + bytes(12)), ('oversized-open', struct.pack('!4sBBQI', b'ACPP', 1, 7, 0, 4294967295)), ('zero-limit', frame(7, payload=setup((0,) + LIMITS[1:]))), ('high-sequence-open', frame(7, 2 ** 63, setup()))]:
        c = Case(name, 'idle', initial=data)
        c.finish({126})
        assert not list(c.state.iterdir())
    for name, data in [('chunk-before-headers', frame(4, 1, b'x')), ('wrong-sequence', frame(3, 2, HEADERS)), ('end-without-headers', frame(5, 1, b'\x00')), ('bad-status-envelope', frame(3, 1, struct.pack('!HH', 302, 0))), ('bad-terminal', frame(5, 1, b'\xff'))]:
        c = Case(name)
        c.request()
        c.send(data)
        c.finish({126})
    c = Case('cumulative-response-limit', 'twice', limits=(4096, 20, 2048, 16, 20, 2, 4, 128))
    c.request()
    c.send(frame(3, 1, HEADERS) + frame(4, 1, b'data: fixture\n\n') + frame(5, 1, b'\x00'))
    c.pump(lambda x: len(x.requests) == 2)
    assert len(c.requests) == 2 and c.requests[1][0] == 2
    c.send(frame(3, 2, HEADERS) + frame(4, 2, b'data: fixture\n\n'))
    c.finish({126})
    c = Case('request-count-no-retry', 'twice', limits=(4096, 65536, 2048, 16, 1024, 2, 1, 128))
    c.request()
    c.send(frame(3, 1, HEADERS) + frame(4, 1, b'data: fixture\n\n') + frame(5, 1, b'\x00'))
    c.finish({0}, b'HTTP_DENIED')
    assert len(c.requests) == 1
    c = Case('host-cancel-terminal')
    c.request()
    c.send(frame(6, 1) + frame(5, 1, b'\x05'))
    c.finish({87}, b'HTTP_INCOMPLETE')
    c = Case('cancel-reject-completed')
    c.request()
    c.send(frame(6, 1) + frame(5, 1, b'\x00'))
    c.finish({126})
    c = Case('duplicate-headers')
    c.request()
    c.send(frame(3, 1, HEADERS) * 2)
    c.finish({126})
    c = Case('typed-error-before-headers')
    c.request()
    c.send(frame(5, 1, b'\x01'))
    c.finish({0}, b'HTTP_TYPED_FAILURE')
    c = Case('typed-error-headers')
    c.request()
    c.send(frame(3, 1, struct.pack('!HH', 401, 0)) + frame(5, 1, b'\x01'))
    c.finish({0}, b'HTTP_TYPED_FAILURE')
    c = Case('response-byte-overflow', limits=(4096, 8, 2048, 16, 8, 2, 4, 128))
    c.request()
    c.send(frame(3, 1, HEADERS) + frame(4, 1, b'12345678') + frame(4, 1, b'9'))
    c.finish({126})
    c = Case('local-disconnect-cancels', 'disconnect')
    c.request()
    c.pump(lambda x: any((t == 6 for t, _, _ in x.frames)))
    assert [(s, p) for t, s, p in c.frames if t == 6] == [(1, b'')]
    c.send(frame(5, 1, b'\x05'))
    c.finish({0})
    c = Case('cancel-mid-response-frame', 'disconnect')
    c.request()
    encoded = frame(3, 1, HEADERS)
    c.send(encoded[:18])
    c.pump(lambda x: any((t == 6 for t, _, _ in x.frames)))
    c.send(encoded[18:] + frame(5, 1, b'\x05'))
    c.finish({126})
    c = Case('truncated-frame-child-exit', 'exit-soon')
    c.pump(lambda x: b'EXIT_READY' in x.acp)
    c.send(b'ACPP\x01')
    c.finish({126})
    c = Case('owner-eof-revokes-active')
    c.request()
    c.p.stdin.close()
    c.finish({126})
    c = Case('truncated-open-eof', initial=frame(7, payload=setup())[:30])
    c.p.stdin.close()
    c.finish({126})
    assert not list(c.state.iterdir())
    c = Case('idle-deadline', 'idle', times=(1000, 150, 500))
    c.finish({124}, b'IDLE_READY')
    c = Case('reduced-remaining-deadline', 'idle', times=(150, 750, 500))
    c.finish({124}, b'IDLE_READY')
    c = Case('detached-descendant-cleanup', 'descendant', times=(1000, 150, 500))
    c.finish({124}, b'DESCENDANT_READY')
    c = Case('blocked-output-deadline', 'flood', times=(1000, 150, 500))
    c.finish({124}, read_stdout=False)
    if args.include_v2:
        def complete_receipt(case, cause, outcome=None):
            receipt = case.receipt
            assert receipt is not None, case.name
            assert receipt['cause'] == cause, (case.name, receipt)
            assert receipt['flags'] & 0x73 == 0x73 and not receipt['flags'] & 128, (case.name, receipt)
            assert receipt['remainingDescendants'] == 0 and receipt['closedDescriptorMask'] == 0x3f
            if outcome is not None:
                assert receipt['outcome'] == outcome, (case.name, receipt)

        c = Case('v2-opaque-echo-natural', 'echo', version=2)
        c.pump(lambda x: b'ECHO_READY' in x.acp)
        c.send(frame(1, payload=b'v2 opaque\x00\xffACP\n', version=2))
        c.finish({0}, b'v2 opaque\x00\xffACP\n')
        complete_receipt(c, 0, 1)
        assert os.WEXITSTATUS(c.receipt['rawWaitStatus']) == 0 and c.receipt['flags'] & 12 == 0

        c = Case('v2-allowed-exchange', version=2)
        c.request()
        c.send(frame(3, 1, HEADERS, 2) + frame(4, 1, b'data: fixture\n\n', 2) + frame(5, 1, b'\x00', 2))
        c.finish({0}, b'HTTP_OK')
        complete_receipt(c, 0, 1)

        for mode, outcome in (('term-exit', 1), ('ignore-term', 3)):
            c = Case('v2-owner-eof-' + mode, mode, version=2)
            c.pump(lambda x: b'SIGNAL_READY' in x.acp)
            c.p.stdin.close()
            c.finish({126})
            complete_receipt(c, 1, outcome)
            assert c.receipt['flags'] & 4
            if mode == 'term-exit':
                assert os.WEXITSTATUS(c.receipt['rawWaitStatus']) == 23 and not c.receipt['flags'] & 8
            else:
                assert os.WTERMSIG(c.receipt['rawWaitStatus']) == 9 and c.receipt['flags'] & 8

        c = Case('v2-other-signal', 'other-signal', version=2)
        c.finish({128 + signal.SIGUSR1})
        complete_receipt(c, 0, 4)
        assert os.WTERMSIG(c.receipt['rawWaitStatus']) == signal.SIGUSR1

        c = Case('v2-secret-stderr-race', 'stderr-exit', version=2)
        c.finish({126})
        complete_receipt(c, 5)
        assert b'DEFAULT_AUTH_REQUEST' not in c.stderr and b'gateway' not in c.stderr and not c.acp

        c = Case('v2-nonempty-state-unverified', 'nonempty-state', version=2)
        c.finish({127}, b'STATE_NONEMPTY')
        assert c.receipt and c.receipt['cause'] == 0 and not c.receipt['flags'] & 32
        assert c.receipt['flags'] & 3 == 3 and c.receipt['remainingDescendants'] == 0

        c = Case('v2-prelaunch-no-child-status', 'idle', version=2, child_path='/missing-child')
        c.finish({127})
        assert c.receipt and c.receipt['cause'] == 6 and c.receipt['outcome'] == 0
        assert not c.receipt['flags'] & 1 and c.receipt['rawWaitStatus'] == 0

        c = Case('v2-real-execveat-failure', 'idle', version=2, child_path='/bad-executable')
        c.finish({126})
        complete_receipt(c, 6, 1)
        assert os.WEXITSTATUS(c.receipt['rawWaitStatus']) == 122

        c = Case('v2-deadline-truthful', 'idle', version=2, times=(1000, 100, 500))
        c.finish({124}, b'IDLE_READY')
        complete_receipt(c, 3, 2)

        c = Case('v2-detached-descendants', 'descendant', version=2, times=(1000, 100, 500))
        c.finish({124}, b'DESCENDANT_READY')
        complete_receipt(c, 3, 2)
        assert c.receipt['flags'] & 12 == 12

        for name, initial in (
            ('missing-feature', frame(7, payload=setup(version=2, features=0), version=2)),
            ('unknown-feature', frame(7, payload=setup(version=2, features=3), version=2)),
            ('v1-sized-setup', frame(7, payload=setup(), version=2)),
            ('nonzero-open-sequence', frame(7, 1, setup(version=2), 2)),
        ):
            c = Case('v2-reject-' + name, 'idle', initial=initial, version=2)
            c.finish({126})
            assert not c.frames and not c.receipt

        for name, data in (
            ('downgrade', frame(1, payload=b'x')),
            ('host-cleanup-role', frame(8, payload=bytes(116), version=2)),
            ('duplicate-open', frame(7, payload=setup(version=2), version=2)),
        ):
            c = Case('v2-reject-' + name, 'idle', version=2)
            c.pump(lambda x: b'IDLE_READY' in x.acp)
            c.send(data)
            c.finish({126})
            complete_receipt(c, 4, 2)

        c = Case('v1-reject-cleanup-tag', 'idle', suite='v2')
        c.pump(lambda x: b'IDLE_READY' in x.acp)
        c.send(frame(8, payload=bytes(116)))
        c.finish({126})
        assert c.receipt is None and all(tag != 8 for tag, _, _ in c.frames)

        c = Case('v1-reject-version-upgrade', 'idle', suite='v2')
        c.pump(lambda x: b'IDLE_READY' in x.acp)
        c.send(frame(1, payload=b'x', version=2))
        c.finish({126})
        assert c.receipt is None and all(tag != 8 for tag, _, _ in c.frames)

        # 4114-byte ACP frames exceed the exact4096-byte pipe, forcing a real
        # partial frame and preventing any terminal receipt from fitting.
        c = Case('v2-blocked-receipt-unverified', 'flood', version=2,
                 limits=(4096, 65536, 2048, 16, 4096, 2, 4, 128), times=(1000, 100, 150))
        c.finish({127}, read_stdout=False)
        assert c.receipt is None
        blocked_prefix = c.p.stdout.read()
        assert len(blocked_prefix) == 4096
        assert struct.unpack('!4sBBQI', blocked_prefix[:18]) == (b'ACPP', 2, 1, 0, 4096)
        assert blocked_prefix[18:] == b'x' * (4096 - 18)
        (c.dir / 'blocked-stdout-prefix.bin').write_bytes(blocked_prefix)
        V2_RESULTS[-1]['blockedPipeBytes'] = len(blocked_prefix)
        V2_RESULTS[-1]['unfinishedFrameBytes'] = 4114 - len(blocked_prefix)
        V2_RESULTS[-1]['blockedStdoutPrefixSha256'] = digest(c.dir / 'blocked-stdout-prefix.bin')
        (c.dir / 'result.json').write_text(json.dumps(V2_RESULTS[-1], indent=2) + '\n')

        for dimension, times, point, supervisor, expected_exit in (
            (dimension, times, *control)
            for dimension, times in (('overall', (100, 750, 500)), ('idle', (1000, 100, 500)))
            for control in (('state-mkdir', 'supervise-delay-state', 127),
                            ('exec-read', 'supervise-delay-exec-read', 126))
        ):
            c = Case('review-startup-' + dimension + '-deadline-' + point, 'idle', version=2,
                     times=times, suite='review-regression', supervisor=supervisor)
            c.finish({expected_exit})
            assert c.receipt and c.receipt['cause'] == 3 and not c.acp
            traces = REVIEW_RESULTS[-1].get('trustedSupervisorTrace', [])
            assert any('TRACE_HOLD point=' + point in line and
                       int(line.split('elapsedMillis=')[1].split()[0]) >= 200 for line in traces)
            summaries = [dict(part.split('=', 1) for part in line.split()[1:])
                         for line in traces if line.startswith('TRACE_SUMMARY ')]
            assert len(summaries) == 1
            assert summaries[0]['point'] == point and int(summaries[0]['held']) == 1
            assert int(summaries[0]['forkCloneCount']) == (0 if point == 'state-mkdir' else 1)
            assert c.receipt['flags'] & 0x72 == 0x72 and not c.receipt['flags'] & 128
            if point == 'state-mkdir':
                assert c.receipt['outcome'] == 0 and not c.receipt['flags'] & 1
            else:
                assert c.receipt['flags'] & 1 and c.receipt['outcome'] == 2

        c = Case('review-stderr-flood-rejected', 'stderr-flood', version=2,
                 suite='review-regression')
        c.finish({126})
        complete_receipt(c, 5)
        assert not REVIEW_RESULTS[-1]['guardianStderrBytes']

        # Call the actual production static drain function with a real flooded
        # stderr pipe. Immediate rejection must not count as valid idle progress.
        progress_source = RUN / 'stderr-progress-control.c'
        progress_source.write_text('#define main guardian_program_main\n#include "' + str(SOURCE) + '"\n#undef main\n' + r'''
int main(void) {
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC | O_NONBLOCK)) return 1;
    unsigned char bytes[1024];
    memset(bytes, 's', sizeof bytes);
    unsigned filled = 0;
    for (unsigned i = 0; i < 128; i++) {
        ssize_t n = write(pipes[1], bytes, sizeof bytes);
        if (n > 0) filled += (unsigned)n;
        else if (n < 0 && errno == EAGAIN) break;
        else return 2;
    }
    Guardian g = {.last_progress = 123, .terminal_cause = UNKNOWN};
    int result = drain_child(&g, &pipes[0], false);
    close(pipes[0]); close(pipes[1]);
    return filled >= sizeof bytes && result == -1 &&
           g.terminal_cause == CHILD_STDERR && g.last_progress == 123 ? 0 : 3;
}
''')
        progress_binary = RUN / 'stderr-progress-control'
        BUILD.append(compile_one(progress_source, progress_binary))
        p = subprocess.run([str(progress_binary)], capture_output=True, env=ENV, timeout=3)
        assert p.returncode == 0 and not p.stdout and not p.stderr
        REVIEW_RESULTS.append({'name': 'review-rejected-stderr-is-not-progress',
                               'sourceSha256': digest(progress_source),
                               'binarySha256': digest(progress_binary), 'exitCode': p.returncode,
                               'realPipeFlooded': True, 'lastProgressUnchanged': True})

        for interrupt_name, interrupt_signal in (('term', signal.SIGTERM), ('int', signal.SIGINT)):
            for point, trace_point in (('state', 'state-mkdir'), ('pidfd', 'child-pidfd'),
                                       ('exec-read', 'exec-read'), ('pending', 'pending'),
                                       ('post-admission', 'post-admission')):
                c = Case('review-startup-interrupt-' + interrupt_name + '-' + point,
                         'idle', version=2, suite='review-regression',
                         supervisor='supervise-interrupt-' + interrupt_name + '-' + point)
                c.finish({126, 127})
                assert c.receipt and c.receipt['cause'] == 2 and not c.acp
                traces = REVIEW_RESULTS[-1].get('trustedSupervisorTrace', [])
                summaries = [dict(part.split('=', 1) for part in line.split()[1:])
                             for line in traces if line.startswith('TRACE_SUMMARY ')]
                assert len(summaries) == 1, traces
                summary = summaries[0]
                assert summary['point'] == trace_point and int(summary['signal']) == interrupt_signal
                assert int(summary['forwarded']) == 1
                assert int(summary['forkCloneCount']) == (0 if point == 'state' else 1)
                assert int(summary['gateReleaseWrites']) == (1 if point in ('exec-read', 'post-admission') else 0)
                assert int(summary['criticalMaskEntered']) == (0 if point == 'state' else 1)
                assert int(summary['maskRestored']) == (0 if point == 'state' else 1)
                assert c.receipt['flags'] & 0x72 == 0x72 and not c.receipt['flags'] & 128
                if point == 'state':
                    assert c.guardian == 127 and c.receipt['outcome'] == 0 and not c.receipt['flags'] & 1
                else:
                    assert c.guardian == 126 and c.receipt['flags'] & 1
                    assert (c.receipt['outcome'] == 2 or
                            (c.receipt['outcome'] == 4 and
                             os.WTERMSIG(c.receipt['rawWaitStatus']) == signal.SIGPIPE) or
                            (c.receipt['outcome'] == 1 and
                             os.WEXITSTATUS(c.receipt['rawWaitStatus']) == 121))

        # This test translation unit includes the unchanged production function.
        # Its syscall scheduling wrapper forwards REAL kernel results. At the
        # send boundary it can release and reap the real owned child first, so
        # ESRCH is observed rather than synthesized. The wrapper is not built
        # into the guardian and does not qualify a standalone cleanup receipt.
        signal_source = RUN / 'signal-delivery-control.c'
        signal_source.write_text(r'''
#define _GNU_SOURCE
#include <stdarg.h>
#include <unistd.h>
static long scheduled_guardian_syscall(long number, ...);
#define syscall scheduled_guardian_syscall
#define main guardian_program_main
#include "''' + str(SOURCE) + r'''"
#undef main
#undef syscall
static Guardian *controlled_guardian;
static pid_t controlled_child;
static int release_fd, exit_before_send, send_calls, observed_return, observed_errno;
static long scheduled_guardian_syscall(long number, ...) {
    va_list arguments;
    va_start(arguments, number);
    if (number == SYS_pidfd_open) {
        int pid = va_arg(arguments, int), flags = va_arg(arguments, int);
        va_end(arguments);
        if (pid != controlled_child || flags) { errno = EINVAL; return -1; }
        return syscall(number, pid, flags);
    }
    if (number == SYS_pidfd_send_signal) {
        int fd = va_arg(arguments, int), sig = va_arg(arguments, int);
        void *info = va_arg(arguments, void *);
        int flags = va_arg(arguments, int);
        va_end(arguments);
        if (exit_before_send) {
            siginfo_t status;
            if (write(release_fd, "R", 1) != 1 ||
                waitid(P_PID, (id_t)controlled_child, &status, WEXITED | WNOWAIT) ||
                status.si_pid != controlled_child || reap_owned(controlled_guardian) != 1) {
                errno = EIO; return -1;
            }
        }
        long result = syscall(number, fd, sig, info, flags);
        int saved = errno;
        send_calls++;
        observed_return = (int)result;
        observed_errno = result < 0 ? saved : 0;
        errno = saved;
        return result;
    }
    va_end(arguments);
    errno = ENOSYS;
    return -1;
}
static int control(int sig, int before) {
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC)) return 10;
    pid_t child = fork();
    if (child < 0) { close(pipes[0]); close(pipes[1]); return 11; }
    if (!child) {
        close(pipes[1]);
        char release;
        ssize_t received = read(pipes[0], &release, 1);
        _exit(received == 1 && release == 'R' ? 0 : 91);
    }
    close(pipes[0]);
    Guardian guardian = {.childpid = child, .terminal_cause = UNKNOWN};
    controlled_child = child; controlled_guardian = &guardian;
    release_fd = pipes[1]; exit_before_send = before; send_calls = 0;
    observed_return = -2; observed_errno = -1;
    unsigned flags = 0;
    int result = 12;
    int snapshot_count = owned_children(&guardian, sig, &flags);
    if (snapshot_count != 1 || send_calls != 1 || guardian.auxiliary_close_failure) goto done;
    if (!before) {
        siginfo_t status;
        if (waitid(P_PID, (id_t)child, &status, WEXITED | WNOWAIT) ||
            status.si_pid != child || reap_owned(&guardian) != 1) goto done;
    }
    if (!guardian.child_reaped || owned_children(&guardian, 0, &flags) != 0 ||
        reap_owned(&guardian) != 1) goto done;
    printf("SIGNAL_DELIVERY signal=%d phase=%s sendReturn=%d sendErrno=%d flags=%u waitStatus=%u childReaped=1 finalEchild=1\n",
           sig, before ? "exited-before-send" : "delivered", observed_return,
           observed_errno, flags, (unsigned)guardian.child_status);
    if (before ? (observed_return != -1 || observed_errno != ESRCH || flags != 0 ||
                  !WIFEXITED(guardian.child_status) || WEXITSTATUS(guardian.child_status) != 0)
               : (observed_return != 0 || observed_errno != 0 ||
                  flags != (sig == SIGTERM ? SIGTERM_SENT : SIGKILL_SENT) ||
                  !WIFSIGNALED(guardian.child_status) || WTERMSIG(guardian.child_status) != sig)) goto done;
    result = 0;
done:
    if (!guardian.child_reaped) { (void)kill(child, SIGKILL); (void)waitpid(child, NULL, 0); }
    close(pipes[1]);
    return result;
}
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    int sig = !strcmp(argv[1], "term") ? SIGTERM : !strcmp(argv[1], "kill") ? SIGKILL : 0;
    if (!sig) return 2;
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL) || sigaction(SIGTERM, &action, NULL)) return 3;
    int result = control(sig, 0);
    return result ? result : control(sig, 1);
}
''')
        signal_binary = RUN / 'signal-delivery-control'
        BUILD.append(compile_one(signal_source, signal_binary))
        for signal_name, delivered_signal in (('term', signal.SIGTERM), ('kill', signal.SIGKILL)):
            p = subprocess.Popen([str(signal_binary), signal_name], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=ENV, start_new_session=True)
            try:
                stdout, stderr = p.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                stdout, stderr = p.communicate(timeout=3)
                raise AssertionError('Signal delivery control exceeded its deadline')
            finally:
                if p.returncode is None:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait(timeout=3)
                p.stdout.close(); p.stderr.close()
            output = RUN / ('signal-delivery-' + signal_name + '.stdout.log')
            error = RUN / ('signal-delivery-' + signal_name + '.stderr.log')
            output.write_bytes(stdout); error.write_bytes(stderr)
            assert p.returncode == 0 and not stderr, (signal_name, p.returncode, stdout, stderr)
            observations = [dict(part.split('=', 1) for part in line.split()[1:])
                            for line in stdout.decode('ascii').splitlines()]
            assert len(observations) == 2
            for observation, phase in zip(observations, ('delivered', 'exited-before-send')):
                assert observation['phase'] == phase and int(observation['signal']) == delivered_signal
                assert observation['childReaped'] == observation['finalEchild'] == '1'
            REVIEW_RESULTS.append({'name': 'review-signal-delivery-' + signal_name,
                                   'sourceSha256': digest(signal_source),
                                   'binarySha256': digest(signal_binary), 'exitCode': p.returncode,
                                   'stdoutSha256': digest(output), 'stderrSha256': digest(error),
                                   'actualKernelSignalObservations': observations,
                                   'testOnlySchedulingWrapperCallsRealKernel': True,
                                   'standaloneCleanupReceiptQualified': False})

        if args.compare_prior_guardian:
            for point, supervisor in (('state-mkdir', 'supervise-delay-state'),
                                      ('exec-read', 'supervise-delay-exec-read')):
                c = Case('prior-startup-budget-reset-' + point, 'idle', version=2,
                         times=(100, 750, 500), suite='prior-regression', supervisor=supervisor,
                         guardian_binary=PRIOR_GUARDIAN)
                c.finish({124}, b'IDLE_READY')
                assert c.receipt and c.receipt['cause'] == 3 and c.receipt['flags'] & 1
                PRIOR_RESULTS[-1]['regressionObserved'] = 'child ACP forwarded after original startup budget expired'
finally:
    failure_type = sys.exc_info()[0]
    cleanup_failures = []
    for owned in CHILDREN:
        if owned.poll() is not None:
            continue
        try:
            if not owned.stdin.closed:
                owned.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            owned.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                owned.kill()
                owned.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_failures.append('owned-process-cleanup-unverified')
        except OSError:
            cleanup_failures.append('owned-process-wait-failed')
    inputs_unchanged = all(digest(path) == sha for path, sha in INPUT_HASHES.items())
    tools_unchanged = all(digest(pathlib.Path(tool['resolvedPath'])) == tool['sha256']
                          for tool in TOOLCHAIN.values())
    binaries_unchanged = all(digest(pathlib.Path(build['command'][-1])) == build['binarySha256']
                             for build in BUILD)
    report = {
        'schema': 'native-provider-guardian-control-v1',
        'scope': 'standalone credential-free candidate, NOT production qualification',
        'hostMachine': os.uname().machine,
        'startupDelayMechanism': ('trusted supervisor PTRACE_SYSCALL/GET_SYSCALL_INFO scheduling hold; native ABI only'
                                  if args.include_v2 else None),
        'startupInterruptMechanism': ('trusted supervisor actual TERM/INT at syscall barriers; actual gate-write and signal-mask observations'
                                      if args.include_v2 else None),
        'signalDeliveryRaceMechanism': ('test-only scheduling wrapper reaps a real owned child before forwarding real pidfd_send_signal; no synthesized syscall result'
                                       if args.include_v2 else None),
        'sourceSha256': INPUT_HASHES[SOURCE],
        'runnerSha256': INPUT_HASHES[pathlib.Path(__file__).resolve()],
        'fixtureSha256': INPUT_HASHES[FIXTURE],
        'inputsUnchanged': inputs_unchanged,
        'toolsUnchanged': tools_unchanged,
        'binariesUnchanged': binaries_unchanged,
        'bwrapSha256': TOOLCHAIN['bwrap']['sha256'],
        'build': BUILD,
        'toolchain': TOOLCHAIN,
        'rejectedPreliminaryControl': {
            'streamBytes': 65536,
            'senderBackpressureMillis': 0,
            'result': 'assertion-failed; replaced by 1 MiB sustained control',
        },
        'bounds': {
            'fileDescriptors': 128,
            'addressSpaceBytes': 2 * 1024 ** 3,
            'fixtureMaximumTasks': 8,
            'productionTaskCapUnchanged': 32,
            'cgroupAdmissionQualified': False,
        },
        'completed': (failure_type is None and not cleanup_failures and len(RESULTS) == 42
                      and (not args.include_v2 or len(V2_RESULTS) == 21)
                      and (not args.include_v2 or len(REVIEW_RESULTS) == 18)
                      and (not args.compare_prior_guardian or len(PRIOR_RESULTS) == 2)
                      and inputs_unchanged and tools_unchanged and binaries_unchanged),
        'expectedControlCount': 42,
        'failureType': None if failure_type is None else failure_type.__name__,
        'cleanupFailures': cleanup_failures,
        'passed': len(RESULTS),
        'results': RESULTS,
        'v2ExpectedControlCount': 21 if args.include_v2 else 0,
        'v2Passed': len(V2_RESULTS),
        'v2Results': V2_RESULTS,
        'reviewRegressionExpectedCount': 18 if args.include_v2 else 0,
        'reviewRegressionPassed': len(REVIEW_RESULTS),
        'reviewRegressionResults': REVIEW_RESULTS,
        'priorRegressionResults': PRIOR_RESULTS,
        'priorGuardianSha256': INPUT_HASHES.get(PRIOR_GUARDIAN),
        'v2CleanupCommitmentGolden': {'domainHex': CLEANUP_DOMAIN.hex(), 'sha256': CLEANUP_GOLDEN},
    }
    (RUN / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(RUN / 'verification.json'), 'passed': len(RESULTS)}), flush=True)
if not report['completed']:
    raise SystemExit(1)
