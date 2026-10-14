#!/usr/bin/env python3
"""Run the 42 credential-free native provider guardian controls.

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
args = parser.parse_args()
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

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

INPUT_HASHES = {path: digest(path) for path in (SOURCE, FIXTURE, pathlib.Path(__file__).resolve())}
TOOLCHAIN = {
    name: {
        'path': str(pathlib.Path('/usr/bin') / name),
        'resolvedPath': str((pathlib.Path('/usr/bin') / name).resolve()),
        'sha256': digest((pathlib.Path('/usr/bin') / name).resolve()),
    }
    for name in ('cc', 'bwrap', 'readelf')
}

def frame(tag, seq=0, payload=b''):
    return struct.pack('!4sBBQI', b'ACPP', 1, tag, seq, len(payload)) + payload

def setup(limits=LIMITS, times=(3000, 750, 500)):
    return CAP + bytes([0x11]) * 32 + bytes([0x22]) * 32 + struct.pack('!8I3Q', *limits, *times)

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
for binary in ('guardian', 'fixture'):
    p = subprocess.run(['/usr/bin/readelf', '-l', '-d', str(RUN / binary)], capture_output=True, env=ENV, timeout=5)
    assert p.returncode == 0 and b'INTERP' not in p.stdout and (b'NEEDED' not in p.stdout)
    (RUN / f'{binary}-elf.txt').write_bytes(p.stdout)
CHILDREN = []

class Case:

    def __init__(self, name, mode='success', initial=None, limits=LIMITS, times=(3000, 750, 500)):
        self.name = name
        self.dir = RUN / name
        self.dir.mkdir(mode=0o700)
        self.state = self.dir / 'state'
        self.state.mkdir(mode=0o700)
        command = [str(BWRAP), '--unshare-all', '--new-session', '--die-with-parent', '--ro-bind', str(RUN / 'guardian'), '/guardian', '--ro-bind', str(RUN / 'fixture'), '/fixture']
        for path in reversed(self.state.parents):
            if str(path) != '/':
                command += ['--dir', str(path)]
        command += ['--bind', str(self.state), str(self.state), '--proc', '/proc', '--dev', '/dev', '--chdir', str(self.state), '--', '/fixture', 'supervise', '/guardian', '--state-root', str(self.state), '--codex-path', '/fixture', '--', '/fixture', mode]
        self.command = command
        self.started = time.monotonic()
        self.p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, bufsize=0)
        CHILDREN.append(self.p)
        os.set_blocking(self.p.stdin.fileno(), False)
        self.raw = bytearray()
        self.stderr = bytearray()
        self.frames = []
        self.acp = bytearray()
        self.requests = []
        self.guardian = None
        self.send(frame(7, payload=setup(limits, times)) if initial is None else initial)

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
                        assert magic == b'ACPP' and ver == 1 and (tag in (1, 2, 6)) and (n <= 8 * 1024 * 1024)
                        if len(self.raw) < 18 + n:
                            break
                        payload = bytes(self.raw[18:18 + n])
                        del self.raw[:18 + n]
                        self.frames.append((tag, seq, payload))
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
            self.send(b'X')
            self.p.stdin.close()
        self.p.wait(timeout=2)
        assert self.p.returncode == 0
        assert CAP.hex().encode() not in self.stderr and CAP not in self.stderr
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
        (self.dir / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
        RESULTS.append(record)
RESULTS = []
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
                      and inputs_unchanged and tools_unchanged and binaries_unchanged),
        'expectedControlCount': 42,
        'failureType': None if failure_type is None else failure_type.__name__,
        'cleanupFailures': cleanup_failures,
        'passed': len(RESULTS),
        'results': RESULTS,
    }
    (RUN / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(RUN / 'verification.json'), 'passed': len(RESULTS)}), flush=True)
if not report['completed']:
    raise SystemExit(1)
