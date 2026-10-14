# Private v2 copy of prepare_fixture.py bounded execution primitives.
# Source SHA256: bd95a3afd9e8563cb63ea90ae1bedf894e2238a7225f1e7172976724c52c28c1
"""Private, bounded reference fixture preparation; no provider or auth access."""
from __future__ import annotations

import hashlib
import errno
import json
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import subprocess
import time
import uuid

REPO = Path('/home/june/decomp_thing').resolve()
BASE = Path(__file__).resolve().parent
SOURCE = REPO / 'src/test/fixtures/c/stdin_branching.c'
SOURCE_SHA = 'c7fcf34c4041f5a16c1106e3f8cd5f67dacb4754a8c00f2e1e0bc149ab8d9d6a'
CASES = [
    ('default', [], b'', b'DEFAULT\n', 0),
    ('arg-secret', ['secret'], b'', b'ARG_SECRET\n', 2),
    ('stdin-open', [], b'open\n', b'STDIN_OPEN\n', 3),
    ('arg-overrides-stdin', ['secret'], b'open\n', b'ARG_SECRET\n', 2),
    ('other-arg-stdin', ['other'], b'open\n', b'STDIN_OPEN\n', 3),
    ('no-newline', [], b'open', b'DEFAULT\n', 0),
    ('crlf', [], b'open\r\n', b'DEFAULT\n', 0),
    ('first-line', [], b'open\nignored\n', b'STDIN_OPEN\n', 3),
]


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private_directory(path: Path) -> Path:
    assert path.resolve().is_relative_to(BASE), 'directory outside owned benchmark root'
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def write_json(path: Path, value: object) -> None:
    assert path.resolve().is_relative_to(BASE)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
    path.chmod(0o600)


def process_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024,) * 2)


def process_identity(pid: int) -> dict | None:
    try:
        value = Path(f'/proc/{pid}/stat').read_text()
        fields = value[value.rfind(')') + 2:].split()
        return {'pid': pid, 'start': int(fields[19]), 'pgid': int(fields[2]), 'sid': int(fields[3])}
    except (FileNotFoundError, ProcessLookupError):
        return None


def owned_processes(leader: int, root_start: int | None) -> list[dict]:
    current = process_identity(leader)
    if current and root_start is not None and current['start'] != root_start:
        raise RuntimeError('owned subprocess root PID reused')
    records = []
    for entry in Path('/proc').iterdir():
        if entry.name.isdecimal():
            record = process_identity(int(entry.name))
            if record and (record['sid'] == leader or record['pgid'] == leader):
                records.append(record)
    return records


def kill_exact(record: dict) -> None:
    current = process_identity(record['pid'])
    if current is None or current['start'] != record['start']:
        return
    try:
        descriptor = os.pidfd_open(record['pid'])
    except ProcessLookupError:
        return
    try:
        current = process_identity(record['pid'])
        if current and current['start'] == record['start']:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
    finally:
        os.close(descriptor)


def scope_processes(evidence: dict | None) -> list[dict]:
    if evidence is None:
        return []
    cgroup = Path(evidence['cgroup'])
    try:
        metadata = cgroup.stat()
    except FileNotFoundError:
        return []  # Kernel cannot remove a cgroup containing live processes.
    assert (metadata.st_dev, metadata.st_ino) == (evidence['device'], evidence['inode']), 'scope identity changed'
    records = []
    try:
        pids = (cgroup / 'cgroup.procs').read_text().split()
    except OSError as failure:
        if failure.errno not in (errno.ENOENT, errno.ENODEV):
            raise
        # --collect can remove the empty cgroup between stat and the read.
        # Accept only actual path absence; unreadable retained state is unknown.
        try:
            cgroup.stat()
        except FileNotFoundError:
            return []
        raise
    for pid in map(int, pids):
        record = process_identity(pid)
        if record:
            records.append(record)
    return records


def bounded_run(argv: list[str], cwd: Path, environment: dict[str, str], stdin: bytes = b'',
                timeout: float = 15, output_limit: int = 64 * 1024,
                managed_scope: bool = False) -> dict:
    """Capture bounded bytes, reap the process group on any incomplete execution."""
    began = time.monotonic()
    scope_evidence = None
    scope_gate = None
    command = argv
    actual_environment = dict(environment)
    if managed_scope:
        scope_gate = private_directory(cwd / ('scope-' + uuid.uuid4().hex))
        unit = 'decomp-acp-efficacy-' + scope_gate.name[6:] + '.scope'
        actual_environment['DBUS_SESSION_BUS_ADDRESS'] = f'unix:path=/run/user/{os.getuid()}/bus'
        command = ['/usr/bin/systemd-run', '--user', '--scope', '--quiet', '--collect', '--no-ask-password',
                   '--unit=' + unit, '--property=TasksMax=32', '--property=MemoryMax=536870912',
                   '--property=MemorySwapMax=0', '/usr/bin/python3', '-B', str(BASE / 'scope_gate.py'),
                   str(scope_gate), *argv]
    process = subprocess.Popen(command, cwd=cwd, env=actual_environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, preexec_fn=process_limits)
    captured = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = None
    root_start = None
    try:
        root = process_identity(process.pid)
        root_start = root['start'] if root else None
        selector = selectors.DefaultSelector()
        assert len(stdin) <= 4096
        process.stdin.write(stdin)
        process.stdin.close()
        for label, stream in [('stdout', process.stdout), ('stderr', process.stderr)]:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = timeout - (time.monotonic() - began)
            if remaining <= 0:
                raise TimeoutError('bounded fixture subprocess deadline')
            if scope_gate and scope_evidence is None and (scope_gate / 'gate.json').exists():
                gate = json.loads((scope_gate / 'gate.json').read_bytes())
                child = process_identity(gate['pid'])
                assert child and child['start'] == gate['start']
                cgroup_record = Path(f"/proc/{gate['pid']}/cgroup").read_text().strip()
                assert cgroup_record.startswith('0::/') and cgroup_record.count('\n') == 0
                relative = cgroup_record[4:]
                cgroup = Path('/sys/fs/cgroup') / relative
                assert cgroup.resolve().is_relative_to(Path('/sys/fs/cgroup')) and cgroup.name == unit
                values = {name: (cgroup / name).read_text().strip() for name in ('pids.max', 'memory.max', 'memory.swap.max')}
                assert values == {'pids.max': '32', 'memory.max': '536870912', 'memory.swap.max': '0'}
                metadata = cgroup.stat()
                scope_evidence = {'unit': unit, 'cgroup': str(cgroup), 'device': metadata.st_dev,
                                  'inode': metadata.st_ino, 'gateIdentity': gate, 'kernelLimits': values,
                                  'systemdRunSha256': digest(Path('/usr/bin/systemd-run')),
                                  'scopeGateSha256': digest(BASE / 'scope_gate.py')}
                (scope_gate / 'admit').write_bytes(b'1\n')
            for key, _ in selector.select(min(remaining, 0.1)):
                block = os.read(key.fileobj.fileno(), 8192)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                available = output_limit - len(captured[key.data])
                captured[key.data].extend(block[:available])
                if len(block) > available:
                    raise ValueError('bounded fixture subprocess output exceeded limit')
        code = process.wait(timeout=max(0.001, timeout - (time.monotonic() - began)))
        assert not managed_scope or scope_evidence is not None, 'candidate scope was never kernel-verified'
        return {'argv': argv, 'exitCode': code, 'stdout': bytes(captured['stdout']),
                'stderr': bytes(captured['stderr']), 'elapsedSeconds': round(time.monotonic() - began, 6),
                'rootPid': process.pid, 'rootReaped': True, 'kernelScope': scope_evidence}
    except Exception as failure:
        # Preserve already-written trusted caller markers even when stdout floods first.
        for label, stream in [('stdout',process.stdout),('stderr',process.stderr)]:
            try:
                block=os.read(stream.fileno(),8192)
                available=max(0,output_limit-len(captured[label]))
                captured[label].extend(block[:available])
            except (BlockingIOError,OSError):
                pass
        failure.bounded_result = {'argv': argv, 'exitCode': None,
            'stdout': bytes(captured['stdout']), 'stderr': bytes(captured['stderr']),
            'failureClass': type(failure).__name__, 'reason': str(failure)[:300],
            'elapsedSeconds': round(time.monotonic()-began, 6),
            'rootPid': process.pid, 'rootReaped': False, 'kernelScope': scope_evidence}
        raise
    finally:
        if selector:
            selector.close()
        try:
            for record in scope_processes(scope_evidence) + owned_processes(process.pid, root_start):
                kill_exact(record)
            process.wait(timeout=5)
            deadline = time.monotonic() + 5
            while (scope_processes(scope_evidence) or owned_processes(process.pid, root_start)) and time.monotonic() < deadline:
                for record in scope_processes(scope_evidence) + owned_processes(process.pid, root_start):
                    kill_exact(record)
                time.sleep(0.02)
            assert not scope_processes(scope_evidence), 'owned candidate cgroup survives cleanup'
            assert not owned_processes(process.pid, root_start), 'owned subprocess session/group survives cleanup'
            if scope_evidence is not None:
                scope_evidence['finalAbsenceVerified'] = True
            # Failure receipts retain cleanup proof after the finally block.
            import sys
            active_failure = sys.exc_info()[1]
            if active_failure is not None and hasattr(active_failure, 'bounded_result'):
                active_failure.bounded_result['rootReaped'] = True
                active_failure.bounded_result['finalAbsenceVerified'] = True
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream:
                    stream.close()


def public_result(result: dict) -> dict:
    return {**{k: v for k, v in result.items() if k not in ('stdout', 'stderr')},
            'stdoutHex': result['stdout'].hex(), 'stderrHex': result['stderr'].hex()}

