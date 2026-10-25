#!/usr/bin/python3
"""Closed hosted qualification driver for the trusted fixed-slot reset provisioner.

This is installation/qualification machinery. Its closed cases cannot grant an
oracle worker reset, process-kill, mount, or operation-release authority.
"""
import contextlib
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True

ROOT = Path('/var/lib/decomp-oracle-ext4-reset-ci')
PRIVATE = ROOT / 'private'
INSTALLED = PRIVATE / 'ci-oracle-ext4-reset.py'
CORE = PRIVATE / 'oracle-ext4-reset.py'
CASE_ROOT = PRIVATE / 'case-receipts'
CASES = tuple(f'K{i:02}' for i in range(1, 33))
ARTIFACTS = ('formatter.trace', 'events.json', 'manifest.json', 'service.properties')
MAX_JSON = 16384
MAX_FIXTURE = 65536
MAX_TRACE = 262144
MAX_ARTIFACT = 131072
CORE_PHASES = ('REGISTERED', 'INTENT', 'FENCED', 'UNMOUNTED', 'FORMAT_STARTED',
               'FORMATTED', 'MOUNT_INTENT', 'READY_PRIVATE', 'EXPOSURE_INTENT', 'PUBLISHED')
BARRIERS = {'K14': 'INTENT_FSYNC', 'K15': 'GATE_CLOSED', 'K16': 'MOUNT_MOVED',
            'K17': 'UNMOUNTED_BEFORE_COMMIT', 'K18': 'FORMAT_STARTED',
            'K19': 'FORMAT_FLUSHED', 'K20': 'READY_RENAMED_BEFORE_FSYNC',
            'K21': 'EXPOSURE_INTENT', 'K31': 'GATE_OPENED', 'K32': 'CANDIDATE_MOUNTED'}
EVENT_OPERATIONS = frozenset(('broker-request', 'broker-resume', 'broker-finalize', 'broker-status',
    'mount', 'umount', 'loop-allocate', 'namespace-holder', 'file-holder', 'fault-arm',
    'barrier-observe', 'signal', 'property-read', 'fixture-restore', 'fixture-teardown',
    'trace-read', 'state-read'))
_CORE_MODULE = None


class QualificationError(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise QualificationError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def core():
    global _CORE_MODULE
    if _CORE_MODULE is None:
        spec = importlib.util.spec_from_file_location('fixed_ext4_reset_core', CORE)
        require(spec is not None and spec.loader is not None, 'installed core is unavailable')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _CORE_MODULE = module
    return _CORE_MODULE


def read_regular(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 0,
                'qualification record is not an owned regular file')
        require(not before.st_mode & 0o022 and before.st_size <= maximum, 'qualification record exceeds its profile')
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        require(len(result) <= maximum, 'qualification record grew beyond its bound')
        after = os.fstat(descriptor)
        named = path.lstat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'qualification record changed while read')
        require((named.st_dev, named.st_ino) == (before.st_dev, before.st_ino), 'qualification record was replaced')
        return bytes(result)
    finally:
        os.close(descriptor)


def write_owned(path, payload, maximum=MAX_JSON):
    require(len(payload) <= maximum, 'qualification publication exceeds its bound')
    temporary = path.with_name(path.name + '.next')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            require(count > 0, 'short qualification publication')
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if path.exists():
        read_regular(path, maximum)
    os.rename(temporary, path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def load_fixture():
    value = core().parse_canonical(read_regular(PRIVATE / 'fixture.json', MAX_FIXTURE), MAX_FIXTURE)
    require(value.get('schemaVersion') == 1 and value.get('owner') == {'uid': 65534, 'gid': 65534, 'groups': []},
            'qualification installation differs')
    require(set(value) == {'schemaVersion', 'owner', 'sourceCommit', 'sourceHashes', 'profileSha256',
                          'installedManifestSha256', 'sessionId', 'active', 'completed'}, 'qualification fields differ')
    require(re.fullmatch(r'[0-9a-f]{64}', value['sessionId']) is not None, 'fixture session differs')
    require(len(value['completed']) <= 32, 'qualification completion bound exceeded')
    return value


@contextlib.contextmanager
def fixture_lock():
    descriptor = os.open(PRIVATE / 'fixture.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        value = os.fstat(descriptor)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1 and
                stat.S_IMODE(value.st_mode) == 0o600, 'qualification lock identity differs')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def state():
    return core().parse_record(read_regular(PRIVATE / 'state.json', MAX_JSON))


def process_start(pid):
    return core().process_start(pid)


def snapshot(value=None):
    value = value or state()
    current = value['candidate'] if value['phase'] in ('READY_PRIVATE', 'EXPOSURE_INTENT', 'PUBLISHED') else value['old']
    require(current is not None, 'current generation observation is missing')
    scratch = core().generation_path(current['generation']) / 'scratch'
    capacity_path = scratch if scratch.is_mount() else PRIVATE / 'quarantine'
    capacity = os.statvfs(capacity_path)
    gate_mode = stat.S_IMODE(core().generation_path(current['generation']).stat().st_mode)
    mount_id = current['mount']['id'] if current['mount'] is not None else value['old']['mount']['id']
    return {'generation': str(current['generation']), 'filesystemUuid': current['uuid'], 'scratch': str(scratch),
            'phase': value['phase'], 'gateMode': gate_mode, 'mountId': mount_id,
            'loopRdev': value['loop']['rdev'], 'imageDevice': value['image']['device'],
            'imageInode': value['image']['inode'], 'imageBytes': value['image']['size'],
            'availableBytes': capacity.f_bavail * capacity.f_frsize, 'availableInodes': capacity.f_favail}


def empty_observations(case_id):
    return {'attempts': [], 'deaths': [], 'canaries': [], 'holders': [],
            'trace': {'artifact': f'raw/{case_id}/formatter.trace', 'sha256': digest(b''),
                      'exclusiveOpenFlags': [], 'exclusiveOpenErrno': None, 'deviceMutationCount': 0,
                      'mutationsBeforeExclusiveOpen': 0, 'truncated': False}, 'facts': {}}


def decode_trace(raw, loop_rdev, filesystem_uuid):
    """Use the installed, source-bound pure parser for the raw receipt summary.

    The offline report gate parses the retained bytes again; no success marker
    or producer-provided count can replace the kernel syscall evidence.
    """
    path = PRIVATE / 'verify-oracle-ext4-reset.py'
    manifest = core().parse_canonical(read_regular(PRIVATE / 'manifest.json', MAX_ARTIFACT), MAX_ARTIFACT)
    specification = manifest['files'][str(path)]
    payload = read_regular(path, 2 * 1024 * 1024)
    require(digest(payload) == specification['sha256'] and core().file_identity(path) == specification['identity'],
            'installed trace parser changed')
    spec = importlib.util.spec_from_file_location('fixed_ext4_reset_report_parser', path)
    require(spec is not None and spec.loader is not None, 'installed trace parser is unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.decode_formatter_trace(raw, loop_rdev, filesystem_uuid)


def collect_process(process, timeout=12, maximum=MAX_JSON + 1):
    selector = selectors.DefaultSelector()
    captured = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    reaped = False
    try:
        for index, stream in enumerate((process.stdout, process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        while selector.get_map():
            require(time.monotonic() < deadline, 'child exceeded its qualification deadline')
            for key, _ in selector.select(min(.05, max(0, deadline-time.monotonic()))):
                payload = os.read(key.fileobj.fileno(), min(4096, maximum + 1 - len(captured[key.data])))
                if not payload:
                    selector.unregister(key.fileobj)
                else:
                    captured[key.data].extend(payload)
                    require(len(captured[key.data]) <= maximum, 'child output exceeded its qualification bound')
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            require(time.monotonic() < deadline, 'child exit exceeded its qualification deadline')
            time.sleep(.01)
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        code = process.wait(timeout=2)
        reaped = True
        return code, bytes(captured[0]), bytes(captured[1])
    finally:
        if not reaped:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        selector.close()
        process.stdout.close()
        process.stderr.close()


class Case:
    def __init__(self, installation, case_id):
        self.installation = installation
        self.case_id = case_id
        self.active = installation['active']
        require(self.active is not None and self.active['caseId'] == case_id, 'case does not own the fixture')
        self.events = self.active['events']
        self.observations = self.active['observations']
        self.children = []

    def save(self):
        write_owned(PRIVATE / 'fixture.json', canonical(self.installation), MAX_FIXTURE)

    def event(self, operation, started, code, **details):
        require(operation in EVENT_OPERATIONS and len(self.events) < 64, 'qualification event bound exceeded')
        self.events.append({'operation': operation, 'startMonotonicNs': started,
                            'endMonotonicNs': time.monotonic_ns(), 'exitCode': code, 'details': details})

    def command(self, role, arguments, *, pass_fds=(), timeout=10, expected_failure=False):
        manifest = core().parse_canonical(read_regular(PRIVATE / 'manifest.json', MAX_ARTIFACT), MAX_ARTIFACT)
        require(role in manifest['tools'], 'tool is not in the installed closure')
        path = manifest['tools'][role]
        specification = manifest['files'][path]
        require(core().file_identity(specification['resolved']) == specification['identity'], 'installed tool changed')
        return core().run_process([path, *map(str, arguments)], pass_fds=pass_fds, timeout=timeout)

    def broker(self, action, argument=None, *, refuse=False):
        require(action in ('request', 'resume', 'finalize', 'status'), 'unknown broker action')
        before = state()
        if action in ('request', 'resume'):
            pace_submission()
        started = time.monotonic_ns()
        argv = ['/usr/bin/python3', '-I', '-S', str(CORE), action]
        if argument is not None:
            argv.append(str(argument))
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True, process_group=0,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        code, stdout, stderr = collect_process(process)
        after = state()
        self.observations['attempts'].append({'action': action, 'exitCode': process.returncode,
            'phaseBefore': before['phase'], 'phaseAfter': after['phase'],
            'invocationId': after['submission']['invocation'], 'formatterCount': self.active['formatterCount']})
        self.event('broker-' + action, started, process.returncode,
                   phaseBefore=before['phase'], phaseAfter=after['phase'], invocationId=after['submission']['invocation'])
        if refuse:
            require(process.returncode != 0, 'unsafe broker action unexpectedly succeeded')
        else:
            require(process.returncode == 0, 'required broker action refused: ' + stderr[:512].decode('utf-8', 'replace'))
        return after

    def manager(self, *, require_empty=False):
        store = core().Store()
        try:
            properties = core().manager_snapshot(store)
            retention = core().retention_snapshot(store)
        finally:
            store.close()
        path = Path('/sys/fs/cgroup') / core().CGROUP.lstrip('/')
        if path.exists():
            identity = core().file_identity(path)
            require(identity['uid'] == 0 and not identity['mode'] & 0o022, 'qualification cgroup is delegated')
            entries = []
            with os.scandir(path) as iterator:
                for entry in iterator:
                    entries.append(entry)
                    require(len(entries) <= 256, 'cgroup directory exceeds bound')
            require(len(entries) <= 256, 'cgroup directory exceeds bound')
            children = [entry.name for entry in entries if entry.is_dir(follow_symlinks=False)]
            require(not children, 'unexpected child cgroup')
            descriptor = os.open(path / 'cgroup.procs', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                raw = os.read(descriptor, 4097)
            finally:
                os.close(descriptor)
            require(len(raw) <= 4096 and re.fullmatch(rb'(?:[1-9][0-9]{0,9}\n)*', raw), 'invalid cgroup process census')
            pids = [int(value) for value in raw.splitlines()]
            require(len(pids) <= 32 and len(pids) == len(set(pids)), 'cgroup population exceeds profile')
            require(core().file_identity(path) == identity, 'cgroup changed during census')
        else:
            identity, pids, children = None, [], []
        if require_empty:
            require(not pids and not children and properties['Job'] in ('', '0') and
                    properties['ActiveState'] in ('inactive', 'failed'), 'service still owns live work')
        return {'schemaVersion': 1, 'unit': core().UNIT, 'properties': {
                key: properties.get(key, '') for key in ('ActiveState', 'SubState', 'ControlGroup',
                'MainPID', 'InvocationID', 'Result', 'Job', 'ExecMainPID', 'ExecMainCode', 'ExecMainStatus',
                'StartLimitIntervalUSec', 'StartLimitBurst', 'StartLimitAction')},
                'cgroup': {'path': core().CGROUP, 'exists': identity is not None,
                           'pids': pids, 'children': children, 'identity': None if identity is None else {
                               key: identity[key] for key in ('device', 'inode', 'mountId', 'uid', 'gid', 'mode', 'kind')}},
                'bootId': core().boot_id(), 'retentionTarget': retention,
                'completedInvocationId': properties['InvocationID'], 'startBudget': load_summary()['startBudget']}

    def terminal(self, *, success=True, seconds=75):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            started = time.monotonic_ns()
            observed = self.manager()
            properties = observed['properties']
            require(properties['Result'] != 'start-limit-hit', 'service start rate limit refused; qualification cannot retry')
            if properties['ActiveState'] in ('inactive', 'failed') and not observed['cgroup']['pids'] and properties['Job'] in ('', '0'):
                if success:
                    require(properties['Result'] == 'success' and state()['phase'] == 'READY_PRIVATE',
                            'custodian did not prepare the requested generation')
                record_terminal()
                self.event('property-read', started, 0, reason='terminal-empty',
                           invocationId=properties['InvocationID'] or None)
                return observed
            time.sleep(.1)
        raise QualificationError('custodian did not reach a bounded terminal observation')

    def save_trace(self, *, refusal=False):
        raw = read_regular(PRIVATE / 'formatter.trace', MAX_TRACE)
        value = state()
        measured = decode_trace(raw, value['loop']['rdev'], value['targetUuid'])
        if refusal:
            require(measured['exclusiveOpenErrno'] == 'EBUSY' and measured['deviceMutationCount'] == 0,
                    'busy filesystem trace did not refuse without mutation')
        else:
            require(measured['exclusiveOpenFlags'] == ['O_RDWR', 'O_EXCL'] and
                    measured['exclusiveOpenErrno'] is None and measured['deviceMutationCount'] > 0 and
                    measured['mutationsBeforeExclusiveOpen'] == 0, 'formatter did not prove exclusive-before-write')
        write_owned(CASE_ROOT / 'current' / 'formatter.trace', raw, MAX_TRACE)
        self.observations['trace'].update(measured, sha256=digest(raw))
        self.active['formatterCount'] += 1
        return measured

    def reset(self, *, preserve_trace=False):
        current = state()
        if current['phase'] in ('REGISTERED', 'PUBLISHED'):
            current = self.broker('request', current['generation'])
        else:
            current = self.broker('resume', current['intentId'])
        self.terminal()
        if not preserve_trace:
            self.save_trace()
        result = self.broker('finalize', state()['intentId'])
        require(result['phase'] == 'PUBLISHED', 'reset was not published')
        self.observations['facts'].update(oldTreeEntriesVisited=0, oldContentBytesRead=0,
                                         mutatorCount=self.active['formatterCount'])
        return result

    def arm(self, barrier):
        require(barrier in tuple(BARRIERS.values()) + ('FORMAT_RUNNING',), 'unknown fault barrier')
        current = state()
        generation = current['generation'] if current['phase'] in ('REGISTERED', 'PUBLISHED') else current['previousGeneration']
        fault = {'version': 1, 'id': os.urandom(32).hex(), 'generation': generation, 'barrier': barrier}
        write_owned(PRIVATE / 'fault.json', canonical(fault), 4096)
        self.active['fault'] = fault
        self.event('fault-arm', time.monotonic_ns(), 0, barrier=barrier)
        return fault

    def disarm(self):
        path = PRIVATE / 'fault.json'
        if path.exists():
            value = core().parse_canonical(read_regular(path, 4096), 4096)
            require(value == self.active.get('fault'), 'fault control was replaced')
            path.unlink()
        self.active.pop('fault', None)

    def spawn_broker(self, action, argument):
        before = state()
        if action in ('request', 'resume'):
            pace_submission()
        process = subprocess.Popen(['/usr/bin/python3', '-I', '-S', str(CORE), action, str(argument)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
            process_group=0, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        self.children.append(process)
        return process, before, time.monotonic_ns()

    def collect_broker(self, child, action, *, expected_kill=False):
        process, before, started = child
        code, out, err = collect_process(process)
        after = state()
        require(code == -signal.SIGKILL if expected_kill else code == 0,
                'asynchronous broker outcome differs: ' + err[:512].decode('utf-8', 'replace'))
        self.observations['attempts'].append({'action': action, 'exitCode': code,
            'phaseBefore': before['phase'], 'phaseAfter': after['phase'],
            'invocationId': after['submission']['invocation'], 'formatterCount': self.active['formatterCount']})
        self.event('broker-' + action, started, code,
                   phaseBefore=before['phase'], phaseAfter=after['phase'], invocationId=after['submission']['invocation'])
        return after

    def barrier(self, fault, seconds=20):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            path = PRIVATE / 'barrier.json'
            if path.exists():
                observed = core().parse_canonical(read_regular(path, 4096), 4096)
                if observed.get('id') == fault['id']:
                    require(observed['barrier'] == fault['barrier'] and observed['bootId'] == core().boot_id() and
                            observed['intentId'] == state()['intentId'], 'fault barrier is not the current transaction')
                    require(process_start(observed['pid']) == observed['startTicks'], 'fault barrier process identity drifted')
                    self.event('barrier-observe', time.monotonic_ns(), 0, pid=observed['pid'],
                               startTicks=observed['startTicks'], barrier=observed['barrier'])
                    return observed
            time.sleep(.02)
        raise QualificationError('required real fault barrier was not reached')

    def signal_owned(self, pid, start, sig, *, role, barrier, reap=False):
        descriptor = os.pidfd_open(pid, 0)
        started = time.monotonic_ns()
        try:
            require(process_start(pid) == start, 'owned process identity changed after pidfd_open')
            signal.pidfd_send_signal(descriptor, sig, None, 0)
            self.event('signal', started, 0, pid=pid, startTicks=start, signal=int(sig), barrier=barrier)
            if sig == signal.SIGKILL:
                selector = selectors.DefaultSelector()
                try:
                    selector.register(descriptor, selectors.EVENT_READ)
                    require(bool(selector.select(8)), 'owned killed process did not exit')
                finally:
                    selector.close()
                if reap:
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        try:
                            if process_start(pid) != start:
                                break
                        except FileNotFoundError:
                            break
                        time.sleep(.02)
                    else:
                        raise QualificationError('owned killed process was not reaped')
                self.observations['deaths'].append({'role': role, 'pid': pid, 'startTicks': start,
                    'signal': 9, 'reaped': True, 'barrier': barrier})
        finally:
            os.close(descriptor)

    def crash_barrier(self, barrier, *, publication=False, stop_after=False):
        fault = self.arm(barrier)
        if publication:
            current = self.broker('request', state()['generation'])
            self.terminal()
            self.save_trace()
            child = self.spawn_broker('finalize', current['intentId'])
            observed = self.barrier(fault)
            require(observed['pid'] == child[0].pid, 'publication barrier is not the owned broker')
            self.signal_owned(observed['pid'], observed['startTicks'], signal.SIGKILL,
                              role='controller', barrier=barrier)
            self.collect_broker(child, 'finalize', expected_kill=True)
            self.disarm()
            if not stop_after:
                self.broker('finalize', state()['intentId'])
        else:
            self.broker('request', state()['generation'])
            observed = self.barrier(fault)
            require(state()['custodian']['pid'] == observed['pid'], 'cutpoint is not the current custodian')
            self.signal_owned(observed['pid'], observed['startTicks'], signal.SIGKILL,
                              role='custodian', barrier=barrier, reap=True)
            self.terminal(success=False)
            self.disarm()
            self.reset()
        self.observations['facts'].update(oldTreeEntriesVisited=0, oldContentBytesRead=0,
                                         mutatorCount=self.active['formatterCount'])

    def no_oracle_probe(self):
        inspected = 0
        with os.scandir('/proc') as iterator:
            for entry in iterator:
                if not entry.name.isdecimal():
                    continue
                inspected += 1
                require(inspected <= 32768, 'process inventory exceeds qualification bound')
                try:
                    if entry.stat(follow_symlinks=False).st_uid != 65534:
                        continue
                    path = Path(entry.path)
                    before = process_start(int(entry.name))
                    fd = os.open(path / 'cmdline', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        command = os.read(fd, 8193)
                    finally:
                        os.close(fd)
                    require(len(command) <= 8192, 'oracle process command exceeds bound')
                    require(process_start(int(entry.name)) == before, 'oracle process identity changed')
                    raise QualificationError('oracle principal is still live at a fixture mutation boundary')
                except FileNotFoundError:
                    continue

    def mutations(self):
        self.no_oracle_probe()
        path = PRIVATE / 'oracle-ext4-reset-fixture-mutations.py'
        spec = importlib.util.spec_from_file_location('fixed_ext4_reset_mutations', path)
        require(spec is not None and spec.loader is not None, 'installed mutations are unavailable')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        manifest = core().parse_canonical(read_regular(PRIVATE / 'manifest.json', MAX_ARTIFACT), MAX_ARTIFACT)
        def runner(argv, *, pass_fds=(), timeout=10):
            roles = [role for role, value in manifest['tools'].items() if value == str(argv[0])]
            require(len(roles) == 1, 'mutation utility is not uniquely installed')
            return self.command(roles[0], argv[1:], pass_fds=pass_fds, timeout=timeout)
        return module.Mutations(core(), state(), runner, before_cleanup=self.no_oracle_probe)

    @contextlib.contextmanager
    def mutation(self, name):
        allowed = ('held_filesystem_file', 'owned_hidden_namespace_holder', 'unrelated_loop',
                   'mount_replacement', 'visible_alias', 'nested_mount', 'backing_path_replacement',
                   'gate_directory_replacement', 'candidate_intent_replacement')
        require(name in allowed, 'unknown physical mutation')
        module = self.mutations()
        with getattr(module, name)() as facts:
            try:
                yield facts
            finally:
                self.no_oracle_probe()
        require(facts.get('cleanup') is True, 'owned mutation did not finish its restoration')

    def record_canary(self, label, facts):
        before = facts['canaryBeforeSha256']
        after = facts['canaryAfterSha256']
        require(before == after, 'known alien canary changed')
        self.observations['canaries'].append({'label': label, 'beforeSha256': before, 'afterSha256': after})

    def stopped_formatter(self, seconds=20):
        manifest = core().parse_canonical(read_regular(PRIVATE / 'manifest.json', MAX_ARTIFACT), MAX_ARTIFACT)
        expected = manifest['files'][manifest['tools']['mke2fs']]['identity']
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            observed = self.manager()
            for pid in observed['cgroup']['pids']:
                descriptor = None
                retained = False
                try:
                    descriptor = os.pidfd_open(pid, 0)
                    start = process_start(pid)
                    executable = os.stat(f'/proc/{pid}/exe')
                    if (executable.st_dev, executable.st_ino) != (expected['device'], expected['inode']):
                        continue
                    status_fd = os.open(f'/proc/{pid}/status', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        status = os.read(status_fd, 65537).decode('ascii')
                    finally:
                        os.close(status_fd)
                    require(len(status) <= 65536 and re.search(r'^Uid:\s+0\s+0\s+0\s+0$', status, re.M),
                            'formatter principal differs')
                    if not re.search(r'^State:\s+[Tt]\b', status, re.M):
                        continue
                    fd = os.open(f'/proc/{pid}/cmdline', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        command = os.read(fd, 4097)
                    finally:
                        os.close(fd)
                    require(len(command) <= 4096, 'formatter command exceeds bound')
                    arguments = command.rstrip(b'\0').decode('ascii').split('\0')
                    target = arguments[-2]
                    match = re.fullmatch(r'/proc/self/fd/([0-9]+)', target)
                    require(match is not None and arguments[1:] == core().formatter_argv(int(match[1]), state()['targetUuid']),
                            'stopped formatter does not have the closed argv')
                    require(os.readlink(f'/proc/{pid}/fd/{match[1]}') == state()['loop']['path'],
                            'stopped formatter descriptor does not name the retained loop')
                    require(process_start(pid) == start, 'formatter identity changed during capture')
                    retained = True
                    return {'pid': pid, 'startTicks': start, 'pidfd': descriptor}
                except FileNotFoundError:
                    continue
                finally:
                    if descriptor is not None and not retained:
                        os.close(descriptor)
            time.sleep(.02)
        raise QualificationError('actual formatter did not reach its first-write stop')

    def resume_formatter(self, formatter):
        require(process_start(formatter['pid']) == formatter['startTicks'], 'formatter identity changed')
        signal.pidfd_send_signal(formatter['pidfd'], signal.SIGCONT, None, 0)
        os.close(formatter['pidfd'])

    def actual_utility_death(self, which):
        self.arm('FORMAT_RUNNING')
        self.broker('request', state()['generation'])
        formatter = self.stopped_formatter()
        if which == 'utility':
            self.signal_owned(formatter['pid'], formatter['startTicks'], signal.SIGKILL,
                              role='utility', barrier='FORMAT_RUNNING', reap=True)
        elif which == 'custodian':
            owner = state()['custodian']
            self.signal_owned(owner['pid'], owner['startTicks'], signal.SIGKILL,
                              role='custodian', barrier='SERVICE_RUNNING', reap=True)
            self.broker('resume', state()['intentId'], refuse=True)
            refusal = self.observations['attempts'][-1]['exitCode']
            self.signal_owned(formatter['pid'], formatter['startTicks'], signal.SIGKILL,
                              role='utility', barrier='FORMAT_RUNNING', reap=True)
            self.observations['holders'].append({'kind': 'utility', 'pid': formatter['pid'],
                'startTicks': formatter['startTicks'], 'reaped': True, 'refusalExitCode': refusal})
        elif which == 'timeout':
            owner = state()['custodian']
            self.signal_owned(owner['pid'], owner['startTicks'], signal.SIGSTOP,
                              role='custodian', barrier='ACTION_TIMEOUT')
            self.broker('resume', state()['intentId'], refuse=True)
            observed = self.terminal(success=False, seconds=75)
            require(observed['properties']['Result'] == 'timeout' and
                    observed['properties']['ExecMainCode'] == '2' and observed['properties']['ExecMainStatus'] == '9',
                    'manager runtime deadline did not kill the custodian with SIGKILL')
            require(not Path(f'/proc/{owner["pid"]}').exists(), 'timed-out custodian was not reaped')
            self.event('signal', time.monotonic_ns(), 0, pid=owner['pid'], startTicks=owner['startTicks'],
                       signal=9, barrier='ACTION_TIMEOUT')
            self.observations['deaths'].append({'role': 'custodian', 'pid': owner['pid'],
                'startTicks': owner['startTicks'], 'signal': 9, 'reaped': True, 'barrier': 'ACTION_TIMEOUT'})
        else:
            raise QualificationError('unknown owned utility-death case')
        os.close(formatter['pidfd'])
        self.terminal(success=False)
        self.disarm()
        self.reset()

    def controller_death(self):
        self.arm('FORMAT_RUNNING')
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_fd)
                null = os.open('/dev/null', os.O_RDWR | os.O_CLOEXEC)
                os.dup2(null, 1); os.dup2(null, 2); os.close(null)
                self.broker('request', state()['generation'])
                acknowledgement = canonical({'pid': os.getpid(), 'startTicks': process_start(os.getpid()),
                    'attempt': self.observations['attempts'][-1], 'event': self.events[-1]}) + b'\n'
                require(len(acknowledgement) <= 4096 and os.write(write_fd, acknowledgement) == len(acknowledgement),
                        'controller acknowledgement exceeds its bound')
                os.close(write_fd)
                self.terminal()
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(write_fd)
        child_fd = os.pidfd_open(pid, 0)
        try:
            selector = selectors.DefaultSelector()
            payload = bytearray()
            try:
                selector.register(read_fd, selectors.EVENT_READ)
                deadline = time.monotonic() + 15
                while b'\n' not in payload:
                    require(time.monotonic() < deadline, 'controller acknowledgement deadline')
                    if not selector.select(.1):
                        continue
                    chunk = os.read(read_fd, 4097 - len(payload))
                    require(chunk and len(payload) + len(chunk) <= 4096, 'controller acknowledgement is incomplete')
                    payload.extend(chunk)
            finally:
                selector.close(); os.close(read_fd)
            require(payload.endswith(b'\n') and payload.count(b'\n') == 1, 'controller acknowledgement is ambiguous')
            reply = core().parse_canonical(bytes(payload[:-1]), 4096)
            require(reply['pid'] == pid and process_start(pid) == reply['startTicks'], 'request controller identity differs')
            self.observations['attempts'].append(reply['attempt']); self.events.append(reply['event'])
            formatter = self.stopped_formatter()
            self.signal_owned(pid, reply['startTicks'], signal.SIGKILL, role='controller', barrier='SERVICE_RUNNING')
            waited, status = os.waitpid(pid, 0)
            require(waited == pid and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL,
                    'request controller was not actually killed and reaped')
            pid = None
            self.broker('resume', state()['intentId'], refuse=True)
            self.resume_formatter(formatter)
            self.terminal()
            self.disarm()
            self.save_trace()
            self.broker('finalize', state()['intentId'])
        finally:
            if pid is not None:
                with contextlib.suppress(ProcessLookupError):
                    signal.pidfd_send_signal(child_fd, signal.SIGKILL, None, 0)
                os.waitpid(pid, 0)
            os.close(child_fd)

    def fail_service_then_refuse_finalize(self):
        self.broker('request', state()['generation'])
        observed = self.terminal(success=False)
        require(observed['properties']['Result'] != 'success', 'unsafe mounted state was accepted')
        self.broker('finalize', state()['intentId'], refuse=True)
        return self.observations['attempts'][-1]['exitCode']

    def unsafe_before_request(self):
        return self.broker('request', state()['generation'], refuse=True)

    def missing_registration_refusal(self):
        """K27: invoke the real broker with only its exact registration absent.

        The fixture lock serializes this closed fault. Release the core lock
        during the subprocess so refusal must be caused by missing state, not
        by contention with the fault injector. Never overwrite an alien restore.
        """
        self.no_oracle_probe()
        module = core()
        original_path = PRIVATE / 'state.json'
        saved_path = PRIVATE / 'fixture-old-state'
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int

        def absent(path):
            try:
                path.lstat()
            except FileNotFoundError:
                return
            raise QualificationError('registration fault target is already occupied')

        def move(directory, source, target):
            if rename(directory, source, directory, target, 1):
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
            os.fsync(directory)

        def diagnostic_snapshot():
            result = {}
            for name, bound in (('diagnostic.json', MAX_JSON), ('diagnostic.next', MAX_JSON),
                                ('formatter.trace', MAX_TRACE), ('state.next', MAX_JSON)):
                path = PRIVATE / name
                try:
                    identity = module.file_identity(path)
                except FileNotFoundError:
                    result[name] = None
                else:
                    result[name] = (identity, digest(read_regular(path, bound)))
            return result

        descriptor = None
        moved = False
        try:
            with module.opened_store() as store:
                before = store.load()
                require(before['phase'] in ('REGISTERED', 'PUBLISHED'), 'registration fault requires an admitted empty generation')
                module.verify_base(store, before)
                service_before = module.inactive_snapshot(store, before)
                current = before['candidate'] if before['phase'] == 'PUBLISHED' else before['old']
                gate_path = module.generation_path(current['generation'])
                scratch_path = gate_path / 'scratch'
                gate_before = module.file_identity(gate_path)
                scratch_before = module.file_identity(scratch_path)
                scratch_fd = store.open_dir(scratch_path)
                require(not module._entries(scratch_fd), 'K27 old filesystem is not empty')
                store.drop(scratch_fd)
                absent(saved_path)
                require(not (PRIVATE / 'state.next').exists(), 'registration fault cannot cover a pending state publication')
                original = read_regular(original_path, MAX_JSON)
                require(module.parse_record(original) == before, 'registration changed before fault')
                descriptor = os.open(original_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                original_identity = module.fd_identity(descriptor)
                require(module.file_identity(original_path) == original_identity, 'registration descriptor differs')
                diagnostics = diagnostic_snapshot()
                move(store.private, b'state.json', b'fixture-old-state')
                moved = True
                require(module.file_identity(saved_path) == original_identity, 'retained registration inode differs')
            # No core lock is held here. The installed broker must get as far as
            # its actual state open and refuse before any StartUnit or mutation.
            pace_submission()
            started = time.monotonic_ns()
            process = subprocess.Popen(['/usr/bin/python3', '-I', '-S', str(CORE), 'request', str(before['generation'])],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                process_group=0, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
            code, stdout, stderr = collect_process(process)
            require(code == 1 and not stderr and stdout.endswith(b'\n') and stdout.count(b'\n') == 1,
                    'missing registration did not yield the actual bounded broker refusal')
            response = module.parse_canonical(stdout[:-1])
            require(set(response) == {'ok', 'error', 'disposition'} and response['ok'] is False and
                    response['disposition'] == 'RESERVED' and isinstance(response['error'], str) and
                    'No such file or directory' in response['error'] and response['error'].endswith(": 'state.json'"),
                    'broker refused for a reason other than the missing protected registration')
            self.event('broker-request', started, code, missingRegistration=True,
                       phaseBefore=before['phase'], phaseAfter=before['phase'], invocationId=before['submission']['invocation'])
        finally:
            try:
                if moved:
                    self.no_oracle_probe()
                    with module.opened_store() as store:
                        absent(original_path)
                        require(module.file_identity(saved_path) == original_identity and
                                module.fd_identity(descriptor) == original_identity and
                                read_regular(saved_path, MAX_JSON) == original and
                                os.pread(descriptor, MAX_JSON + 1, 0) == original,
                                'retained registration changed; preserve unknown state')
                        module.verify_base(store, before)
                        service_after = module.inactive_snapshot(store, before)
                        stable = ('ActiveState', 'SubState', 'Job', 'InvocationID', 'ExecMainPID',
                                  'ExecMainCode', 'ExecMainStatus', 'Result')
                        require(all(service_after[key] == service_before[key] for key in stable),
                                'missing registration started or changed a service invocation')
                        require(module.file_identity(gate_path) == gate_before and
                                module.file_identity(scratch_path) == scratch_before and
                                diagnostic_snapshot() == diagnostics,
                                'missing registration changed gate, mount or formatter evidence')
                        move(store.private, b'fixture-old-state', b'state.json')
                        require(module.file_identity(original_path) == original_identity and
                                read_regular(original_path, MAX_JSON) == original and store.load() == before,
                                'registration restoration changed its exact inode or bytes')
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        self.observations['attempts'].append({'action': 'request', 'exitCode': code,
            'phaseBefore': before['phase'], 'phaseAfter': before['phase'],
            'invocationId': before['submission']['invocation'], 'formatterCount': self.active['formatterCount']})
        self.observations['facts'].update(missingRegistrationRefused=True, registrationRestored=True,
            registrationBeforeSha256=digest(original), registrationAfterSha256=digest(read_regular(original_path, MAX_JSON)))

    def exercise(self):
        number = self.case_id
        outcome = 'reset'
        if number == 'K01':
            self.broker('request', state()['generation'] + 1, refuse=True)
            outcome = 'refused'
        elif number == 'K02':
            self.fail_service_then_refuse_finalize()
            outcome = 'refused'
        elif number in ('K03', 'K04', 'K05', 'K06', 'K26', 'K28'):
            self.reset()
        elif number == 'K27':
            self.missing_registration_refusal()
            self.reset()
        elif number == 'K07':
            with self.mutation('held_filesystem_file') as facts:
                refusal = self.fail_service_then_refuse_finalize()
            self.record_canary('file-holder', facts)
            require(facts.get('reaped') is True, 'file holder was not reaped')
            self.observations['holders'].append({'kind': 'file', 'pid': facts['holderPid'],
                'startTicks': facts['holderStartTicks'], 'reaped': True, 'refusalExitCode': refusal})
            self.reset()
        elif number == 'K08':
            with self.mutation('owned_hidden_namespace_holder') as facts:
                refusal = self.fail_service_then_refuse_finalize()
                self.save_trace(refusal=True)
            self.record_canary('namespace-holder', facts)
            require(facts.get('reaped') is True, 'namespace holder was not reaped')
            self.observations['holders'].append({'kind': 'namespace', 'pid': facts['holderPid'],
                'startTicks': facts['holderStartTicks'], 'reaped': True, 'refusalExitCode': refusal})
            self.reset(preserve_trace=True)
        elif number == 'K09':
            self.arm('FORMAT_RUNNING')
            self.broker('request', state()['generation'])
            formatter = self.stopped_formatter()
            self.broker('request', state()['generation'], refuse=True)
            self.resume_formatter(formatter)
            self.terminal(); self.disarm(); self.save_trace()
            self.broker('finalize', state()['intentId'])
        elif number == 'K10':
            with self.mutation('unrelated_loop') as facts:
                self.reset()
            self.observations['facts']['allocatedLoopRdev'] = facts['loop']['node']['rdev']
            require(facts.get('companionReserved') is True, 'qualification companion was not retained')
        elif number == 'K11':
            self.controller_death()
        elif number in ('K12', 'K13', 'K29'):
            self.actual_utility_death({'K12': 'custodian', 'K13': 'utility', 'K29': 'timeout'}[number])
        elif number in BARRIERS and number not in ('K31', 'K32'):
            self.crash_barrier(BARRIERS[number], publication=number == 'K21')
        elif number in ('K22', 'K24', 'K25'):
            method, label = {'K22': ('mount_replacement', 'mount-replacement'),
                             'K24': ('backing_path_replacement', 'image-replacement'),
                             'K25': ('gate_directory_replacement', 'anchor-replacement')}[number]
            with self.mutation(method) as facts:
                self.unsafe_before_request()
            self.record_canary(label, facts)
            self.observations['facts']['restored'] = True
            self.reset()
        elif number == 'K23':
            for method in ('visible_alias', 'nested_mount'):
                with self.mutation(method) as facts:
                    self.unsafe_before_request()
                self.record_canary('alias' if method == 'visible_alias' else 'nested-mount', facts)
            self.reset()
        elif number == 'K30':
            with self.mutation('mount_replacement') as facts:
                self.unsafe_before_request()
                try:
                    self.mutations().fence_and_unmount()
                except (RuntimeError, OSError, ValueError):
                    self.event('fixture-teardown', time.monotonic_ns(), 1, reason='owned mount was replaced')
                else:
                    raise QualificationError('teardown accepted an alien mount replacement')
            self.record_canary('teardown-replacement', facts)
            finished = self.mutations().fence_and_unmount()
            require(finished['disposition'] == 'RESERVED_UNMOUNTED', 'teardown released a reserved allocation')
            self.event('fixture-teardown', time.monotonic_ns(), 0, reason='public mount removed; allocation reserved')
            self.observations['facts'].update(restored=True, removedOwnedFixture=True, retainedReservation=True)
            outcome = 'teardown'
        elif number == 'K31':
            self.crash_barrier('GATE_OPENED', publication=True, stop_after=True)
            outcome = 'prepared'
        elif number == 'K32':
            fault = self.arm('CANDIDATE_MOUNTED')
            self.broker('request', state()['generation'])
            observed = self.barrier(fault)
            self.signal_owned(observed['pid'], observed['startTicks'], signal.SIGKILL,
                              role='custodian', barrier='CANDIDATE_MOUNTED', reap=True)
            self.terminal(success=False); self.disarm()
            with self.mutation('candidate_intent_replacement') as facts:
                self.broker('resume', state()['intentId'])
                self.terminal(success=False)
                self.broker('finalize', state()['intentId'], refuse=True)
            self.observations['facts']['restored'] = True
            self.reset()
        else:
            raise QualificationError('required physical case has no implementation')
        self.observations['facts'].update(oldTreeEntriesVisited=0, oldContentBytesRead=0,
                                         mutatorCount=self.active['formatterCount'])
        self.active['outcome'] = outcome
        if outcome == 'teardown':
            after = dict(self.active['before'], phase='RESERVED_UNMOUNTED', gateMode=0,
                         mountId=0, availableBytes=0, availableInodes=0)
            require(not any(row['path'] == after['scratch'] for row in core().mount_table()),
                    'teardown scratch is still mounted')
            require(core().loop_identity(state()['loop']['path'], state()['owner']) == state()['loop'],
                    'teardown changed the reserved loop')
            self.active['after'] = after
        else:
            self.active['after'] = snapshot()
        self.save()
        return self.reply()

    def reply(self):
        return {'schemaVersion': 1, 'caseId': self.case_id, 'sessionToken': self.active['sessionToken'],
                'outcome': self.active['outcome'], 'before': self.active['before'],
                'after': self.active['after'], 'observations': self.observations}

    def resume_case(self):
        require(self.case_id in ('K02', 'K31'), 'case has no external probe handoff')
        if self.case_id == 'K31':
            require(self.active['outcome'] == 'prepared', 'candidate is not prepared for probe handoff')
            canary = probe_canary(self.case_id, self.active['sessionToken'], 'hold-canary', snapshot()['scratch'])
            before = read_canary(canary)
            self.broker('finalize', state()['intentId'])
            after = read_canary(canary)
            require(before == after, 'admitted candidate lease canary changed during finalize')
            self.observations['canaries'].append({'label': 'candidate-lease', 'beforeSha256': digest(before),
                                                  'afterSha256': digest(after)})
        else:
            require(self.active['outcome'] == 'refused', 'held lease refusal was not observed')
            self.no_oracle_probe()
            self.reset()
        self.active.update(outcome='reset', after=snapshot())
        self.save()
        return self.reply()


def load_summary():
    value = core().parse_canonical(read_regular(CASE_ROOT / 'summary.json', MAX_JSON))
    require(set(value) == {'schemaVersion', 'completed', 'startBudget'} and value['schemaVersion'] == 1,
            'qualification summary differs')
    budget = value['startBudget']
    require(set(budget) == {'bootId', 'sessionId', 'timestampsMonotonicNs', 'lastTerminalMonotonicNs'} and budget['bootId'] == core().boot_id(),
            'start budget does not belong to this boot')
    require(budget['sessionId'] == load_fixture()['sessionId'], 'start budget does not belong to this installation session')
    require(type(budget['lastTerminalMonotonicNs']) is int and 0 <= budget['lastTerminalMonotonicNs'] < 2**63,
            'invalid terminal observation timestamp')
    stamps = budget['timestampsMonotonicNs']
    require(isinstance(stamps, list) and len(stamps) <= 64 and
            all(type(stamp) is int and 0 < stamp < 2**63 for stamp in stamps), 'invalid durable start budget')
    require(all(right-left >= 2_100_000_000 for left, right in zip(stamps, stamps[1:])),
            'durable submissions violate the declared spacing')
    return value


def pace_submission():
    # The fixture lock serializes this root-owned fsync across helper/controller
    # deaths. Charge the attempt before invoking the broker, even if it refuses
    # before StartUnit; no manager rate counter is cleared or reset.
    summary = load_summary()
    stamps = summary['startBudget']['timestampsMonotonicNs']
    require(len(stamps) < 64, 'finite qualification start budget exhausted')
    now = time.monotonic_ns()
    previous = max(stamps[-1] if stamps else 0, summary['startBudget']['lastTerminalMonotonicNs'])
    if previous:
        require(now >= previous, 'monotonic clock regressed')
        remaining = previous + 2_100_000_000 - now
        if remaining > 0:
            time.sleep(remaining / 1_000_000_000)
    observed = time.monotonic_ns()
    require(not previous or observed - previous >= 2_100_000_000, 'submission pacing was interrupted')
    stamps.append(observed)
    write_owned(CASE_ROOT / 'summary.json', canonical(summary))


def record_terminal():
    summary = load_summary()
    observed = time.monotonic_ns()
    require(observed >= summary['startBudget']['lastTerminalMonotonicNs'], 'terminal observation clock regressed')
    summary['startBudget']['lastTerminalMonotonicNs'] = observed
    write_owned(CASE_ROOT / 'summary.json', canonical(summary))


def probe_canary(case_id, token, mode, scratch):
    require(case_id in CASES and re.fullmatch(r'[0-9a-f]{64}', token) and mode == 'hold-canary',
            'probe canary identity differs')
    require(re.fullmatch(re.escape(str(ROOT / 'public')) + r'/g-[0-9a-f]{16}/scratch', scratch),
            'probe scratch is outside the fixed namespace')
    operation = digest(f'{case_id}:{token}:{mode}'.encode('utf-8'))
    return Path(scratch) / ('.decomp-oracle-lease-' + operation) / ('.function-observation-run-' + operation) / 'reset-probe-canary'


def read_canary(path):
    # The caller constructs the sole accepted path from the authenticated case.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 65534 and before.st_nlink == 1
                and before.st_size <= 256, 'probe canary identity differs')
        data = os.read(descriptor, 257)
        after = os.fstat(descriptor)
        require(len(data) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'probe canary changed while read')
        named = path.lstat()
        require((named.st_dev, named.st_ino) == (before.st_dev, before.st_ino), 'probe canary was replaced')
        return data
    finally:
        os.close(descriptor)


def prepare():
    require(Path(__file__).resolve() != INSTALLED, 'installed fixture cannot create another deployment')
    path = Path(__file__).resolve().with_name('oracle-ext4-reset-install.py')
    spec = importlib.util.spec_from_file_location('fixed_ext4_reset_install', path)
    require(spec is not None and spec.loader is not None, 'checked installer is unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    installed = module.install()
    # All runtime actions now use the immutable copy captured by that installer.
    require(digest(read_regular(INSTALLED, 2 * 1024 * 1024)) == installed['sourceHashes']['scripts/ci-oracle-ext4-reset.py'],
            'installed fixture differs from reviewed source')
    for path in (CASE_ROOT, CASE_ROOT / 'current'):
        path.mkdir(mode=0o700)
        require(path.stat().st_uid == 0 and stat.S_IMODE(path.stat().st_mode) == 0o700,
                'qualification directory is not private')
    lock = os.open(PRIVATE / 'fixture.lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    os.fsync(lock); os.close(lock)
    fixture = {key: installed[key] for key in ('schemaVersion', 'owner', 'sourceCommit', 'sourceHashes',
               'profileSha256', 'installedManifestSha256')}
    fixture.update(active=None, completed=[], sessionId=os.urandom(32).hex())
    write_owned(PRIVATE / 'fixture.json', canonical(fixture), MAX_FIXTURE)
    write_owned(CASE_ROOT / 'summary.json', canonical({'schemaVersion': 1, 'completed': [],
                'startBudget': {'bootId': core().boot_id(), 'sessionId': fixture['sessionId'],
                                'timestampsMonotonicNs': [], 'lastTerminalMonotonicNs': 0}}))
    return {'schemaVersion': 1, **{key: installed[key] for key in ('owner', 'sourceCommit', 'sourceHashes',
             'profileSha256', 'installedManifestSha256', 'loopNode')}, 'before': snapshot(installed['initialState']),
            'retainedReservation': True}


def prepare_case(installation, case_id):
    order = [case for case in CASES if case != 'K30'] + ['K30']
    completed = installation['completed']
    require(len(completed) < 32 and case_id == order[len(completed)], 'case order or completion differs')
    previous = installation['active']
    if previous is not None:
        require(previous.get('finished') is True and set(previous.get('retrieved', [])) == set(ARTIFACTS),
                'previous case evidence has not been delivered')
    current = CASE_ROOT / 'current'
    names = sorted(entry.name for entry in current.iterdir())
    require(set(names) <= set(ARTIFACTS) | {'receipt.json'}, 'unknown current-case artifact')
    for name in names:
        path = current / name
        read_regular(path, MAX_TRACE if name == 'formatter.trace' else MAX_ARTIFACT)
        path.unlink()
    before = snapshot()
    installation['active'] = {'caseId': case_id, 'sessionToken': os.urandom(32).hex(),
        'before': before, 'after': before, 'outcome': 'prepared', 'events': [],
        'observations': empty_observations(case_id), 'formatterCount': 0, 'finished': False, 'retrieved': []}
    case = Case(installation, case_id)
    case.save()
    return {**case.reply(), 'oracleUid': 65534, 'oracleGid': 65534, 'loopNode': state()['loop']['path']}


def finish_case(case):
    require(not case.active['finished'], 'case receipt is already frozen')
    expected = 'refused' if case.case_id == 'K01' else 'teardown' if case.case_id == 'K30' else 'reset'
    require(case.active['outcome'] == expected, 'case did not reach its required outcome')
    case.no_oracle_probe()
    # Every raw observation is captured before its receipt is frozen. No report
    # is synthesized for an incomplete case or an active service.
    service = case.manager(require_empty=True)
    case.event('property-read', time.monotonic_ns(), 0,
               invocationId=service['properties']['InvocationID'] or None)
    manifest = read_regular(PRIVATE / 'manifest.json', MAX_ARTIFACT)
    require(digest(manifest) == case.installation['installedManifestSha256'], 'installed manifest changed')
    if case.case_id in ('K01', 'K30'):
        trace = b''
        case.observations['trace'] = empty_observations(case.case_id)['trace']
    else:
        trace = read_regular(CASE_ROOT / 'current' / 'formatter.trace', MAX_TRACE)
        require(digest(trace) == case.observations['trace']['sha256'], 'captured formatter trace changed')
    payloads = {'formatter.trace': trace, 'manifest.json': manifest,
                'events.json': canonical({'schemaVersion': 1, 'caseId': case.case_id, 'events': case.events}),
                'service.properties': canonical(service)}
    artifacts = []
    for name in ARTIFACTS:
        payload = payloads[name]
        write_owned(CASE_ROOT / 'current' / name, payload, MAX_TRACE if name == 'formatter.trace' else MAX_ARTIFACT)
        artifacts.append({'name': name, 'path': f'raw/{case.case_id}/{name}', 'bytes': len(payload), 'sha256': digest(payload)})
    receipt = {**case.reply(), **{key: case.installation[key] for key in ('profileSha256', 'sourceCommit',
               'sourceHashes', 'installedManifestSha256')}, 'artifacts': artifacts}
    raw = canonical(receipt) + b'\n'
    write_owned(CASE_ROOT / 'current' / 'receipt.json', raw, MAX_ARTIFACT)
    case.active['finished'] = True
    case.installation['completed'].append({'caseId': case.case_id, 'receiptSha256': digest(raw)})
    summary = load_summary()
    summary['completed'] = case.installation['completed']
    write_owned(CASE_ROOT / 'summary.json', canonical(summary))
    case.save()
    return raw


def artifact(case, name):
    require(name in ARTIFACTS and case.active['finished'], 'artifact is unavailable')
    receipt = json.loads(read_regular(CASE_ROOT / 'current' / 'receipt.json', MAX_ARTIFACT))
    entry = next(item for item in receipt['artifacts'] if item['name'] == name)
    raw = read_regular(CASE_ROOT / 'current' / name, MAX_TRACE if name == 'formatter.trace' else MAX_ARTIFACT)
    require(digest(raw) == entry['sha256'] and len(raw) == entry['bytes'], 'frozen artifact changed')
    if name not in case.active['retrieved']:
        case.active['retrieved'].append(name)
        case.save()
    return raw


def inspect_retained():
    """Read-only failure evidence; never translate missing evidence into release."""
    result = {'schemaVersion': 1, 'root': str(ROOT), 'retainedReservation': True,
              'capacityReleased': False, 'disposition': 'RESERVED_AMBIGUOUS', 'observations': {}, 'errors': []}
    for name, path in (('root', ROOT), ('private', PRIVATE), ('image', PRIVATE / 'image')):
        try:
            result['observations'][name] = core().file_identity(path)
        except (OSError, RuntimeError, ValueError) as error:
            result['errors'].append({'observation': name, 'reason': str(error)[:256]})
    try:
        installation = load_fixture()
        result['sourceCommit'] = installation['sourceCommit']
        result['sourceHashes'] = installation['sourceHashes']
        result['completed'] = installation['completed']
        result['startBudget'] = load_summary()['startBudget']
        active = installation['active']
        if active is not None:
            case = Case(installation, active['caseId'])
            result['observations']['service'] = case.manager()
            if active.get('finished') and active.get('outcome') == 'teardown':
                result['disposition'] = 'RESERVED_UNMOUNTED'
        else:
            store = core().Store()
            try:
                result['observations']['service'] = core().manager_snapshot(store)
                result['observations']['retentionTarget'] = core().retention_snapshot(store)
            finally:
                store.close()
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        result['errors'].append({'observation': 'fixture-service', 'reason': str(error)[:256]})
    try:
        value = state()
        result['observations']['state'] = value
        result['observations']['loop'] = core().loop_identity(value['loop']['path'], value['owner'])
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        result['errors'].append({'observation': 'state-loop', 'reason': str(error)[:256]})
    require(len(canonical(result)) <= MAX_ARTIFACT, 'retained evidence exceeds bound')
    return result


def main(arguments=None):
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    try:
        require(os.geteuid() == 0, 'fixed hosted fixture requires root')
        require(arguments and arguments[0] in ('prepare', 'prepare-case', 'exercise', 'resume-case',
                'finish-case', 'artifact', 'inspect'), 'unknown qualification action')
        action = arguments[0]
        if action in ('prepare', 'inspect'):
            require(len(arguments) == 1, 'unexpected qualification arguments')
        else:
            require(len(arguments) == (3 if action == 'artifact' else 2) and arguments[1] in CASES,
                    'unknown case or argument count')
            if action == 'artifact':
                require(arguments[2] in ARTIFACTS, 'unknown artifact')
        if action == 'prepare':
            raw = canonical(prepare()) + b'\n'
        elif Path(__file__).resolve() != INSTALLED:
            # All post-install actions execute the root-private captured helper.
            require(INSTALLED.is_file() and not INSTALLED.is_symlink(), 'fixed installation is unavailable')
            os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', '-S', str(INSTALLED), *arguments],
                      {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'})
            raise QualificationError('installed helper did not execute')
        elif action == 'inspect':
            raw = canonical(inspect_retained()) + b'\n'
        else:
            with fixture_lock():
                installation = load_fixture()
                case_id = arguments[1]
                if action == 'prepare-case':
                    raw = canonical(prepare_case(installation, case_id)) + b'\n'
                else:
                    case = Case(installation, case_id)
                    if action == 'artifact':
                        raw = artifact(case, arguments[2])
                    elif action == 'finish-case':
                        raw = finish_case(case)
                    else:
                        require(not case.active['finished'], 'case is already frozen')
                        raw = canonical(case.exercise() if action == 'exercise' else case.resume_case()) + b'\n'
        sys.stdout.buffer.write(raw)
        return 0
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(str(error)[:2048], file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
