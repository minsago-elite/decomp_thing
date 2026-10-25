#!/usr/bin/python3
"""Closed physical fault contexts for the installed qualification profile only.

The trusted fixture serializes these contexts under its fixture lock. Oracle
processes cannot alter the root-owned namespace, mount table or block bindings.
The caller reaps all oracle probes before context entry/exit; only the bounded
probe itself may run while a context is yielded. Identity mismatches preserve
residue for VM disposal; there is no generic CLI,
recursive deletion, forced unmount or release of the provisioner's loop.
"""
import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import struct
import time

ROOT = Path('/var/lib/decomp-oracle-ext4-reset-ci')
PRIVATE = ROOT / 'private'
CANARY = b'owned-ext4-reset-qualification-canary-v1\n'
CANARY_SHA = hashlib.sha256(CANARY).hexdigest()
COMPANION_BYTES = 4096
TOOLS = {'mount': '/usr/bin/mount', 'umount': '/usr/bin/umount', 'losetup': '/usr/sbin/losetup'}
OBJECT_KEYS = ('device', 'inode', 'mountId', 'kind')


class MutationError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise MutationError(message)


def same_object(actual, expected):
    return all(actual.get(key) == expected.get(key) for key in OBJECT_KEYS)


def rename_noreplace(source, target):
    """Atomic no-clobber rename; only fixed trusted fixture paths call this."""
    libc = ctypes.CDLL(None, use_errno=True)
    fn = libc.renameat2
    fn.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    fn.restype = ctypes.c_int
    if fn(-100, os.fsencode(source), -100, os.fsencode(target), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def process_start(pid):
    raw = Path(f'/proc/{pid}/stat').read_bytes()
    require(len(raw) <= 4096 and b') ' in raw, 'holder process identity is malformed')
    return int(raw.rsplit(b') ', 1)[1].split()[19])


def companion_identity(core, fd, path):
    """Separate 4KiB companion contract, never weaken core's 64MiB check."""
    obj = core.fd_identity(fd)
    require(re.fullmatch(r'/dev/loop[0-9]{1,6}', str(path)) is not None and
            obj['kind'] == 'block' and os.major(obj['rdev']) == 7 and obj['uid'] == 0,
            'companion is not a root loop node')
    data = bytearray(232)
    fcntl.ioctl(fd, 0x4C05, data, True)
    values = struct.unpack_from('=QQQQQIIII', data)
    capacity = bytearray(8)
    fcntl.ioctl(fd, 0x80081272, capacity, True)
    require(values[3] == 0 and values[4] == COMPANION_BYTES and
            values[5] == int(str(path)[9:]) and not any(values[6:9]) and
            struct.unpack('=Q', capacity)[0] == COMPANION_BYTES,
            'companion loop association differs')
    return {'path': str(path), 'node': obj, 'backingDevice': values[0],
            'backingInode': values[1], 'sizeLimit': values[4], 'flags': values[8]}


class Mutations:
    def __init__(self, core, state, runner, *, before_cleanup=None):
        require(os.geteuid() == 0, 'physical qualification requires root')
        require(callable(before_cleanup), 'trusted no-oracle census guard is required')
        self.before_cleanup = before_cleanup
        self._guard()
        require(core.ROOT == ROOT and core.PRIVATE == PRIVATE, 'fixed deployment differs')
        profile = core.parse_canonical(core._read_root_file(PRIVATE / 'profile.json', 16384))
        require(profile == core.profile_document(True), 'physical faults require qualification profile')
        core.validate_state(state)
        require(state['phase'] in ('REGISTERED', 'PUBLISHED', 'MOUNT_INTENT'), 'fault requires an admitted mounted generation')
        self.core, self.state, self.runner = core, state, runner
        self.record = state['candidate'] if state['phase'] in ('PUBLISHED', 'MOUNT_INTENT') else state['old']
        self.gate = core.generation_path(self.record['generation'])
        self.scratch = self.gate / 'scratch'
        for name, path in (('root', ROOT), ('private', PRIVATE), ('public', ROOT / 'public')):
            require(core.file_identity(path) == state['anchors'][name], 'authority anchor differs')
        require(core.file_identity(PRIVATE / 'image') == state['image'], 'backing image differs')
        require(core.loop_identity(state['loop']['path'], state['owner']) == state['loop'], 'retained loop differs')
        if state['phase'] == 'MOUNT_INTENT':
            require(self.record['mount'] is None and self.record['root'] is None,
                    'candidate already has a committed mount identity')
            with core.opened_store() as store:
                require(store.load() == state, 'candidate intent changed')
                core.inactive_snapshot(store, state)
                _, loop_fd = core.verify_base(store, state)
                core.open_gate(store, self.record['generation'], self.record['gate'], (0,))
                root = self._id(self.scratch)
                row = self._row(self.scratch)
                core.verify_mount(row, root, state['loop'], self.scratch)
                core.current_inventory(state, {str(self.scratch): row['id']})
                require(row['parent'] == state['parentMount']['id'] and
                        core.superblock(loop_fd) == self.record['uuid'] == state['targetUuid'] and
                        root['uid'] == 0 and root['gid'] == 0,
                        'uncommitted candidate provenance differs')
                # This local observation is qualification evidence; it is never
                # inserted into the protected record or used as reset authority.
                self.record = dict(self.record, mount=row, root=root)
        self._original_mount(self.scratch)

    def _guard(self):
        # Must run inside each context's own finally. An outer with-wrapper
        # raising cannot suppress a generator context manager's cleanup.
        self.before_cleanup()

    def _run(self, role, *args, pass_fds=()):
        require(role in TOOLS, 'unknown physical fixture tool')
        result = self.runner([TOOLS[role], *map(str, args)], pass_fds=pass_fds, timeout=5)
        return result[0] if isinstance(result, tuple) else result

    def _id(self, path):
        return self.core.file_identity(path)

    def _absent(self, path):
        require(not os.path.lexists(path), 'owned fixture destination already exists')

    def _expect(self, path, identity):
        require(self._id(path) == identity, 'owned fixture object was replaced')

    def _row(self, path, expected=None):
        rows = self.core.mount_table()
        exact = [row for row in rows if row['path'] == str(path)]
        require(len(exact) == 1, 'mount target absent or stacked')
        require(not any(row['path'].startswith(str(path) + '/') for row in rows), 'unknown child mount')
        row = exact[0]
        if expected is not None:
            require(row == expected, 'owned mount changed')
        return row

    def _original_mount(self, path):
        row = self._row(path)
        require(all(row[key] == self.record['mount'][key] for key in
                    ('id', 'device', 'root', 'options', 'optional', 'type', 'source', 'superOptions')),
                'original filesystem mount differs')
        require(same_object(self._id(path), self.record['root']), 'original filesystem root differs')
        return row

    def _mkdir(self, path):
        self._absent(path)
        os.mkdir(path, 0o000)
        os.chmod(path, 0o000)
        return self._id(path)

    def _rmdir(self, path, identity):
        self._expect(path, identity)
        require(not any(row['path'] == str(path) or row['path'].startswith(str(path) + '/')
                        for row in self.core.mount_table()), 'directory still contains a mount')
        os.rmdir(path)  # Ordinary rmdir preserves unknown population.

    def _canary(self, directory_fd, name='fixture-canary'):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o400, dir_fd=directory_fd)
        try:
            require(os.write(fd, CANARY) == len(CANARY), 'short canary write')
            os.fsync(fd)
            return fd, self.core.fd_identity(fd)
        except BaseException:
            os.close(fd)
            raise

    def _check_canary(self, directory_fd, fd, identity, name='fixture-canary'):
        require(self.core.fd_identity(fd) == identity and os.pread(fd, len(CANARY) + 1, 0) == CANARY,
                'owned canary changed')
        named = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            require(self.core.fd_identity(named) == identity, 'owned canary was replaced')
        finally:
            os.close(named)
        return CANARY_SHA

    @contextlib.contextmanager
    def held_filesystem_file(self):
        self._original_mount(self.scratch)
        directory = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fd = None
        try:
            fd, identity = self._canary(directory)
            facts = {'kind': 'held-filesystem-file', 'holderPid': os.getpid(),
                     'holderStartTicks': process_start(os.getpid()), 'root': self.core.fd_identity(directory),
                     'file': identity, 'canaryBeforeSha256': CANARY_SHA, 'cleanup': False}
            try:
                yield facts
            finally:
                self._guard()
                facts['canaryAfterSha256'] = self._check_canary(directory, fd, identity)
                os.unlink('fixture-canary', dir_fd=directory)
                facts['cleanup'] = True
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)

    @contextlib.contextmanager
    def owned_hidden_namespace_holder(self):
        self._original_mount(self.scratch)
        directory = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fd, canary = self._canary(directory)
            os.close(fd)
        finally:
            os.close(directory)
        # No filesystem FD survives the fork: the retained namespace alone is
        # the holder between its bounded before/after canary observations.
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
        stop_r, stop_w = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            try:
                os.close(ready_r); os.close(stop_w)
                inherited = [int(name) for name in os.listdir('/proc/self/fd')]
                require(len(inherited) <= 256, 'inherited descriptor bound exceeded')
                for descriptor in inherited:
                    if descriptor > 2 and descriptor not in (ready_w, stop_r):
                        with contextlib.suppress(OSError):
                            os.close(descriptor)
                libc = ctypes.CDLL(None, use_errno=True)
                require(libc.unshare(0x00020000) == 0, 'mount namespace creation failed')
                row = self._row(self.scratch)
                require(row['device'] == self.record['mount']['device'] and row['root'] == '/',
                        'hidden namespace did not retain filesystem')
                def observe(remove=False):
                    root_fd = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        file_fd = os.open('fixture-canary', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                          dir_fd=root_fd)
                        try:
                            hidden = self.core.fd_identity(file_fd)
                            # Namespace cloning changes mountId; all other
                            # inode identity and bytes must remain exact.
                            require(all(hidden[key] == value for key, value in canary.items() if key != 'mountId'),
                                    'hidden canary identity differs')
                            result = self._check_canary(root_fd, file_fd, hidden)
                            if remove:
                                os.unlink('fixture-canary', dir_fd=root_fd)
                            return result
                        finally:
                            os.close(file_fd)
                    finally:
                        os.close(root_fd)
                message = json.dumps({'pid': os.getpid(), 'startTicks': process_start(os.getpid()),
                                      'namespaceInode': os.stat('/proc/self/ns/mnt').st_ino,
                                      'mount': row, 'canarySha256': observe()}, separators=(',', ':')).encode()
                require(len(message) <= 4096, 'holder receipt bound exceeded')
                require(os.write(ready_w, message) == len(message), 'short holder readiness')
                require(select.select([stop_r], [], [], 60)[0], 'holder lifetime exceeded')
                if os.read(stop_r, 1) == b'C':
                    result = observe(remove=True).encode('ascii')
                    require(os.write(ready_w, result) == len(result), 'short holder canary receipt')
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(ready_w); os.close(stop_r)
        pidfd = None
        facts = None
        try:
            pidfd = os.pidfd_open(pid, 0)
            start = process_start(pid)
            require(select.select([ready_r], [], [], 5)[0], 'namespace holder readiness deadline')
            raw = os.read(ready_r, 4097)
            require(raw and len(raw) <= 4096, 'namespace holder readiness failed')
            observed = json.loads(raw)
            require(observed['pid'] == pid and observed['startTicks'] == start and
                    observed['namespaceInode'] != os.stat('/proc/self/ns/mnt').st_ino and
                    os.stat(f'/proc/{pid}/ns/mnt').st_ino == observed['namespaceInode'] and
                    observed['canarySha256'] == CANARY_SHA,
                    'namespace holder identity differs')
            facts = {'kind': 'hidden-namespace', 'holderPid': pid, 'holderStartTicks': start,
                     'namespaceInode': observed['namespaceInode'], 'mount': observed['mount'],
                     'pidfdPinned': True, 'reaped': False, 'canaryBeforeSha256': CANARY_SHA, 'cleanup': False}
            try:
                yield facts
            finally:
                self._guard()
                require(os.write(stop_w, b'C') == 1, 'holder observation request failed')
                require(select.select([ready_r], [], [], 5)[0], 'holder canary observation deadline')
                require(os.read(ready_r, 65) == CANARY_SHA.encode('ascii'), 'hidden canary changed')
                facts['canaryAfterSha256'] = CANARY_SHA
        finally:
            os.close(stop_w); os.close(ready_r)
            if pidfd is not None:
                # Signal only the pinned direct child; never a guessed/reused PID.
                with contextlib.suppress(ProcessLookupError):
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                try:
                    require(select.select([pidfd], [], [], 5)[0], 'namespace holder death deadline')
                    waited, status = os.waitpid(pid, 0)
                finally:
                    os.close(pidfd)
                require(waited == pid, 'namespace holder reap differs')
                if facts is not None:
                    facts.update(reaped=True, cleanup='canaryAfterSha256' in facts, waitStatus=status)
            else:
                # It remains our unreaped direct child, so PID cannot be reused.
                os.kill(pid, signal.SIGKILL)
                deadline = time.monotonic() + 5
                while os.waitpid(pid, os.WNOHANG)[0] != pid:
                    require(time.monotonic() < deadline, 'namespace holder fallback death deadline')
                    time.sleep(0.01)

    @contextlib.contextmanager
    def unrelated_loop(self):
        path = PRIVATE / 'fixture-companion-image'
        self._absent(path)
        image_fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        loop_fd = None
        try:
            os.posix_fallocate(image_fd, 0, COMPANION_BYTES); os.fsync(image_fd)
            image = self.core.fd_identity(image_fd)
            raw = self._run('losetup', '--find', '--show', '--nooverlap', '--offset', '0',
                            '--sizelimit', str(COMPANION_BYTES), '--sector-size', '512',
                            f'/proc/self/fd/{image_fd}', pass_fds=(image_fd,))
            path_loop = raw.decode('ascii').removesuffix('\n')
            require(re.fullmatch(r'/dev/loop[0-9]{1,6}', path_loop) is not None, 'unknown companion loop allocation')
            loop_fd = os.open(path_loop, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            association = companion_identity(self.core, loop_fd, path_loop)
            require(association['node']['rdev'] != self.state['loop']['rdev'] and
                    (association['backingDevice'], association['backingInode']) == (image['device'], image['inode']),
                    'companion aliases the provisioner or another backing')
            facts = {'kind': 'unrelated-loop', 'image': image, 'loop': association,
                     'qualificationCompanionBytes': COMPANION_BYTES, 'qualificationCompanionInodes': 1,
                     'cleanup': False}
            try:
                yield facts
            finally:
                self._guard()
                self._expect(path, image)
                require(companion_identity(self.core, loop_fd, path_loop) == association, 'companion changed before retirement')
                require(self.core.loop_identity(self.state['loop']['path'], self.state['owner']) == self.state['loop'],
                        'provisioner association changed')
                # One 4KiB qualification companion remains bound and charged
                # through VM disposal. ENXIO after CLR_FD would not prove final
                # retirement (Lo_rundown); no detach/reuse is attempted at all.
                facts.update(cleanup=True, companionReserved=True)
        finally:
            if loop_fd is not None:
                os.close(loop_fd)
            os.close(image_fd)

    @contextlib.contextmanager
    def mount_replacement(self):
        original = self._original_mount(self.scratch)
        saved = PRIVATE / 'fixture-old-mount'
        underneath = self._mkdir(saved)
        self._run('mount', '--move', self.scratch, saved)
        moved = self._original_mount(saved)
        self._expect(self.scratch, self.record['underlying'])
        self._run('mount', '-t', 'tmpfs', '-o', 'rw,nodev,nosuid,noexec,size=1048576,nr_inodes=16,mode=0700',
                  'ext4-reset-owned-replacement', self.scratch)
        replacement = self._row(self.scratch)
        root = self._id(self.scratch)
        directory = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fd, identity = self._canary(directory)
        os.close(fd); os.close(directory)
        facts = {'kind': 'mount-replacement', 'originalMount': original, 'retainedMount': moved,
                 'replacementMount': replacement, 'replacementRoot': root, 'canaryBeforeSha256': CANARY_SHA,
                 'cleanup': False}
        try:
            yield facts
        finally:
            self._guard()
            self._row(self.scratch, replacement); self._expect(self.scratch, root)
            self._row(saved, moved); self._original_mount(saved)
            directory = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            fd = os.open('fixture-canary', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            try:
                require(sorted(os.listdir(directory)) == ['fixture-canary'], 'unknown replacement filesystem contents')
                facts['canaryAfterSha256'] = self._check_canary(directory, fd, identity)
            finally:
                os.close(fd); os.close(directory)
            self._run('umount', '--no-canonicalize', self.scratch)
            self._expect(self.scratch, self.record['underlying'])
            self._row(saved, moved)
            self._run('mount', '--move', saved, self.scratch)
            require(self._original_mount(self.scratch) == original, 'restored mount is not original identity')
            self._rmdir(saved, underneath)
            facts.update(cleanup=True, restoredMountId=original['id'])

    def candidate_intent_replacement(self):
        require(self.state['phase'] == 'MOUNT_INTENT', 'candidate replacement requires mount intent')
        return self.mount_replacement()

    @contextlib.contextmanager
    def _alias(self, nested):
        original = self._original_mount(self.scratch)
        target = self.scratch / 'fixture-nested' if nested else PRIVATE / 'fixture-alias'
        underneath = self._mkdir(target)
        self._run('mount', '--bind', self.scratch, target)
        row = self._row(target)
        require(row['device'] == original['device'] and row['id'] != original['id'], 'alias is not same-device distinct mount')
        root = self._id(target)
        facts = {'kind': 'nested-mount' if nested else 'visible-alias', 'mount': row, 'root': root, 'cleanup': False}
        try:
            yield facts
        finally:
            self._guard()
            self._row(target, row); self._expect(target, root)
            self._run('umount', '--no-canonicalize', target)
            self._rmdir(target, underneath)
            facts['cleanup'] = True

    def visible_alias(self):
        return self._alias(False)

    def nested_mount(self):
        return self._alias(True)

    @contextlib.contextmanager
    def _file_replacement(self, state_anchor):
        path = PRIVATE / ('state.json' if state_anchor else 'image')
        saved = PRIVATE / ('fixture-old-state' if state_anchor else 'fixture-old-image')
        self._absent(saved)
        original = self._id(path)
        if not state_anchor:
            require(original == self.state['image'], 'backing image differs before replacement')
        require(original['kind'] == 'file' and original['links'] == 1 and original['uid'] == 0,
                'replacement source is not owned regular data')
        rename_noreplace(path, saved)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        try:
            require(os.write(fd, CANARY) == len(CANARY), 'short replacement canary write'); os.fsync(fd)
            replacement = self.core.fd_identity(fd)
        finally:
            os.close(fd)
        facts = {'kind': 'state-anchor-replacement' if state_anchor else 'backing-path-replacement',
                 'original': original, 'replacement': replacement, 'canaryBeforeSha256': CANARY_SHA, 'cleanup': False}
        try:
            yield facts
        finally:
            self._guard()
            self._expect(saved, original); self._expect(path, replacement)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                require(self.core.fd_identity(fd) == replacement and os.pread(fd, len(CANARY) + 1, 0) == CANARY,
                        'replacement canary changed')
            finally:
                os.close(fd)
            # Root namespace is fixture-lock serialized. Remove only the exact
            # owned replacement, then no-clobber restore the retained inode.
            os.unlink(path)
            rename_noreplace(saved, path)
            self._expect(path, original)
            facts.update(cleanup=True, canaryAfterSha256=CANARY_SHA)

    def backing_path_replacement(self):
        return self._file_replacement(False)

    def state_anchor_replacement(self):
        return self._file_replacement(True)

    @contextlib.contextmanager
    def gate_directory_replacement(self):
        self._original_mount(self.scratch)
        saved = PRIVATE / 'fixture-old-gate'
        self._absent(saved)
        original = self._id(self.gate)
        require(original == self.record['gate'], 'original generation gate differs')
        rename_noreplace(self.gate, saved)
        moved = self._original_mount(saved / 'scratch')
        replacement = self._mkdir(self.gate)
        directory = os.open(self.gate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fd, identity = self._canary(directory)
        os.close(fd); os.close(directory)
        facts = {'kind': 'anchor-replacement', 'originalGate': original, 'replacementGate': replacement,
                 'retainedMount': moved, 'canaryBeforeSha256': CANARY_SHA, 'cleanup': False}
        try:
            yield facts
        finally:
            self._guard()
            self._expect(saved, original); self._expect(self.gate, replacement)
            self._row(saved / 'scratch', moved)
            directory = os.open(self.gate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            fd = os.open('fixture-canary', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            try:
                require(sorted(os.listdir(directory)) == ['fixture-canary'], 'replacement gate contains unknown state')
                facts['canaryAfterSha256'] = self._check_canary(directory, fd, identity)
                os.unlink('fixture-canary', dir_fd=directory)
            finally:
                os.close(fd); os.close(directory)
            self._rmdir(self.gate, replacement)
            rename_noreplace(saved, self.gate)
            self._expect(self.gate, original)
            self._original_mount(self.scratch)
            facts['cleanup'] = True

    def fence_and_unmount(self):
        """Final cleanup under production lock with no live custodian/cgroup."""
        self._guard()
        require(self.state['phase'] in ('REGISTERED', 'PUBLISHED'), 'final cleanup requires a published slot')
        with self.core.opened_store() as store:
            require(store.load() == self.state, 'final cleanup source state changed')
            self.core.inactive_snapshot(store, self.state)
            return self._fence_and_unmount(store.lock)

    def _fence_and_unmount(self, lock_fd):
        """No loop detach, image delete, unit stop or operation release."""
        require(self.core.loop_identity(self.state['loop']['path'], self.state['owner']) == self.state['loop'],
                'original loop changed before final fencing')
        self._expect(PRIVATE / 'image', self.state['image'])
        self._expect(self.gate, self.record['gate'])
        row = self._original_mount(self.scratch)
        self.core.current_inventory(self.state, {str(self.scratch): row['id']})
        descriptor = os.open(self.gate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            require(self.core.fd_identity(descriptor) == self.record['gate'], 'gate changed before final fence')
            os.fchmod(descriptor, 0); os.fsync(descriptor)
            fenced = self.core.fd_identity(descriptor)
        finally:
            os.close(descriptor)
        self._row(self.scratch, row)
        self._run('umount', '--no-canonicalize', self.scratch, pass_fds=(lock_fd,))
        self._expect(self.scratch, self.record['underlying'])
        require(not any(r['device'] == row['device'] for r in self.core.mount_table()), 'visible original filesystem remains mounted')
        self._expect(PRIVATE / 'image', self.state['image'])
        require(self.core.loop_identity(self.state['loop']['path'], self.state['owner']) == self.state['loop'],
                'reserved loop changed during final fencing')
        return {'kind': 'reserved-cleanup', 'disposition': 'RESERVED_UNMOUNTED', 'fencedGate': fenced,
                'unmountedMount': row, 'imageRetained': self.state['image'], 'loopRetained': self.state['loop'],
                'cleanup': True}
