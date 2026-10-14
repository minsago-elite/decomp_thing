"""Bounded v3 process runner; declared bounds are separate from observed process facts."""
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

BASE = Path(__file__).resolve().parent

from build_contract import load_profile_with_digest, enforced_process_limits


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


def execution_bounds(timeout=None, output_limit=None, managed_scope=False, phase='unspecified', snapshot=None):
    """Declared limits, not proof of kernel enforcement or application/API execution."""
    profile, profile_sha = snapshot if snapshot is not None else load_profile_with_digest()
    b = profile['bounds']
    phases = {name: {'wallSeconds': b[wall], 'outputBytesPerStream': b[output]} for name, wall, output in [
        ('compiler','compilerSeconds','outputBytesPerStream'), ('probe','probeSeconds','helperOutputBytesPerStream'),
        ('runtime','runtimeSeconds','outputBytesPerStream'), ('elf-inspection','elfInspectionSeconds','outputBytesPerStream'),
        ('caller-build','callerBuildSeconds','outputBytesPerStream'), ('helper-build','helperBuildSeconds','helperOutputBytesPerStream'),
        ('toolchain-inspection','toolchainInspectionSeconds','helperOutputBytesPerStream')]}
    if phase != 'unspecified' and phase not in phases:
        raise ValueError('unknown execution phase')
    ceiling = phases.get(phase, {'wallSeconds': b['helperBuildSeconds'], 'outputBytesPerStream': b['helperOutputBytesPerStream']})
    timeout = (ceiling['wallSeconds'] if phase != 'unspecified' else b['defaultWallSeconds']) if timeout is None else timeout
    output_limit = (ceiling['outputBytesPerStream'] if phase != 'unspecified' else b['outputBytesPerStream']) if output_limit is None else output_limit
    import math
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= ceiling['wallSeconds']:
        raise ValueError('wall deadline outside declared phase bound')
    if type(output_limit) is not int or not 0 < output_limit <= ceiling['outputBytesPerStream']:
        raise ValueError('stream output outside declared phase bound')
    limits = enforced_process_limits()
    return {'schemaVersion': 3, 'profileSha256': profile_sha, 'phase': phase,
        'wallSeconds': timeout, 'outputBytesPerStream': output_limit, 'perProcessRlimits': limits,
        'cgroup': {'requested': bool(managed_scope), 'memoryBytes': b['memoryBytes'], 'swapBytes': b['swapBytes'],
                   'tasks': b['tasks'], 'aggregateCpuLimit': None, 'aggregateCpuLimitEnforced': False},
        'supervisor': {key: b[key] for key in ['stdinBytes','cleanupWaitSeconds','cleanupVerificationSeconds',
            'selectorPollSeconds','cleanupPollSeconds','scopeAdmissionSeconds','scopeAdmissionPollSeconds',
            'captureReadBytes','waitFloorSeconds','temporaryFilesystemBytes']},
        'phaseLimits': phases, 'helperGraph': {key: b[key] for key in ['helperInputBytes','helperGraphNodes','helperGraphDepth']}}


def process_limits(limits=None) -> None:
    expected = enforced_process_limits()
    selected = expected if limits is None else limits
    if json.dumps(selected, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True):
        raise ValueError('process limits differ from immutable profile')
    for name in ('RLIMIT_CORE','RLIMIT_CPU','RLIMIT_AS','RLIMIT_NOFILE','RLIMIT_FSIZE'):
        value = selected[name]
        resource.setrlimit(getattr(resource, name), (value['soft'], value['hard']))


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
                timeout: float | None = None, output_limit: int | None = None,
                managed_scope: bool = False, phase: str = 'unspecified') -> dict:
    """Capture bounded bytes, reap the process group on any incomplete execution."""
    bounds = execution_bounds(timeout, output_limit, managed_scope, phase)
    timeout = bounds['wallSeconds']; output_limit = bounds['outputBytesPerStream']
    supervisor = bounds['supervisor']
    if len(stdin) > supervisor['stdinBytes']:
        raise ValueError('bounded subprocess stdin exceeds profile')
    observation = {'launcherCreated': False, 'launcherPidIdentityVerified': False,
                   'scopeVerified': False, 'scopeAdmitted': False, 'captureComplete': False,
                   'waitComplete': False, 'cleanupVerified': False, 'timedOut': False,
                   'outputExceeded': False, 'infrastructureFailure': False,
                   'infrastructureReason': None, 'bounds': bounds}
    result = None
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
                   '--unit=' + unit, '--property=TasksMax=' + str(bounds['cgroup']['tasks']),
                   '--property=MemoryMax=' + str(bounds['cgroup']['memoryBytes']),
                   '--property=MemorySwapMax=' + str(bounds['cgroup']['swapBytes']), '/usr/bin/python3', '-B', str(BASE / 'scope_gate.py'),
                   str(scope_gate), *argv]
    process = subprocess.Popen(command, cwd=cwd, env=actual_environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True,
                               preexec_fn=lambda: process_limits(bounds['perProcessRlimits']))
    observation['launcherCreated'] = True
    captured = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = None
    root_start = None
    try:
        root = process_identity(process.pid)
        root_start = root['start'] if root else None
        observation['launcherPidIdentityVerified'] = root is not None
        selector = selectors.DefaultSelector()
        process.stdin.write(stdin)
        process.stdin.close()
        for label, stream in [('stdout', process.stdout), ('stderr', process.stderr)]:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = timeout - (time.monotonic() - began)
            if remaining <= 0:
                observation['timedOut'] = True
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
                assert values == {'pids.max': str(bounds['cgroup']['tasks']), 'memory.max': str(bounds['cgroup']['memoryBytes']), 'memory.swap.max': str(bounds['cgroup']['swapBytes'])}
                metadata = cgroup.stat()
                scope_evidence = {'unit': unit, 'cgroup': str(cgroup), 'device': metadata.st_dev,
                                  'inode': metadata.st_ino, 'gateIdentity': gate, 'kernelLimits': values,
                                  'systemdRunSha256': digest(Path('/usr/bin/systemd-run')),
                                  'scopeGateSha256': digest(BASE / 'scope_gate.py')}
                observation['scopeVerified'] = True
                (scope_gate / 'admit').write_bytes(b'1\n')
                observation['scopeAdmitted'] = True
            for key, _ in selector.select(min(remaining, supervisor['selectorPollSeconds'])):
                block = os.read(key.fileobj.fileno(), supervisor['captureReadBytes'])
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                available = output_limit - len(captured[key.data])
                captured[key.data].extend(block[:available])
                if len(block) > available:
                    observation['outputExceeded'] = True
                    raise ValueError('bounded fixture subprocess output exceeded limit')
        observation['captureComplete'] = True
        code = process.wait(timeout=max(supervisor['waitFloorSeconds'], timeout - (time.monotonic() - began)))
        observation['waitComplete'] = True
        assert not managed_scope or scope_evidence is not None, 'candidate scope was never kernel-verified'
        result = {**observation, 'argv': argv, 'exitCode': code, 'stdout': bytes(captured['stdout']),
                'stderr': bytes(captured['stderr']), 'elapsedSeconds': round(time.monotonic() - began, 6),
                'rootPid': process.pid, 'rootReaped': True, 'kernelScope': scope_evidence}
        return result
    except Exception as failure:
        # Preserve bounded untrusted behavior bytes verbatim; marker strings have no authority.
        observation['timedOut'] = observation['timedOut'] or isinstance(failure, (TimeoutError, subprocess.TimeoutExpired))
        if managed_scope and not observation['scopeVerified'] and isinstance(failure, AssertionError):
            observation['infrastructureFailure'] = True
            observation['infrastructureReason'] = 'scope-or-launcher-verification-failed' 
        for label, stream in [('stdout',process.stdout),('stderr',process.stderr)]:
            try:
                block=os.read(stream.fileno(),supervisor['captureReadBytes'])
                available=max(0,output_limit-len(captured[label]))
                captured[label].extend(block[:available])
            except (BlockingIOError,OSError):
                pass
        result = {**observation, 'argv': argv, 'exitCode': None,
            'stdout': bytes(captured['stdout']), 'stderr': bytes(captured['stderr']),
            'failureClass': type(failure).__name__, 'reason': str(failure)[:300],
            'elapsedSeconds': round(time.monotonic()-began, 6),
            'rootPid': process.pid, 'rootReaped': False, 'kernelScope': scope_evidence}
        failure.bounded_result = result
        raise
    finally:
        if selector:
            selector.close()
        try:
            for record in scope_processes(scope_evidence) + owned_processes(process.pid, root_start):
                kill_exact(record)
            process.wait(timeout=supervisor['cleanupWaitSeconds'])
            deadline = time.monotonic() + supervisor['cleanupVerificationSeconds']
            while (scope_processes(scope_evidence) or owned_processes(process.pid, root_start)) and time.monotonic() < deadline:
                for record in scope_processes(scope_evidence) + owned_processes(process.pid, root_start):
                    kill_exact(record)
                time.sleep(supervisor['cleanupPollSeconds'])
            assert not scope_processes(scope_evidence), 'owned candidate cgroup survives cleanup'
            assert not owned_processes(process.pid, root_start), 'owned subprocess session/group survives cleanup'
            if scope_evidence is not None:
                scope_evidence['finalAbsenceVerified'] = True
            observation['cleanupVerified'] = True
            if result is not None:
                result['rootReaped'] = True
                result['finalAbsenceVerified'] = True
            # Failure receipts retain cleanup proof after the finally block.
            import sys
            active_failure = sys.exc_info()[1]
            if active_failure is not None and hasattr(active_failure, 'bounded_result'):
                active_failure.bounded_result['rootReaped'] = True
                active_failure.bounded_result['finalAbsenceVerified'] = True
        except Exception as cleanup_failure:
            observation['cleanupVerified'] = False
            if result is not None:
                cleanup_failure.bounded_result = result
            raise
        finally:
            close_failure = None
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream:
                    try:
                        stream.close()
                    except Exception as failure:
                        close_failure = close_failure or failure
            if close_failure is not None:
                observation['cleanupVerified'] = False
            if result is not None:
                result.update(observation)
            if close_failure is not None:
                close_failure.bounded_result = result
                raise close_failure


def public_result(result: dict) -> dict:
    return {**{k: v for k, v in result.items() if k not in ('stdout', 'stderr')},
            'stdoutHex': result['stdout'].hex(), 'stderrHex': result['stderr'].hex()}

