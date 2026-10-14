"""Write-ahead admission/ownership journal, not an installed supervisor.

Only an independently approved root service may supply identities/held parent
FDs. This module neither creates job resources nor authenticates a deployment,
performs capture I/O, removes resources, or certifies cleanup. Until those
layers exist, unresolved resources remain quarantined and reserved.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import secrets
import re
import sqlite3
import stat
import time

APPLICATION_ID = 0x434C4A32
SCHEMA_VERSION = 2
RESERVATION = 20 * 1024**3


class Refusal(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise Refusal('invalid journal digest/identity')
    return value


def root_owned(metadata, directory=False):
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(metadata.st_mode) or metadata.st_uid != 0 or
            stat.S_IMODE(metadata.st_mode) & 0o077 or (not directory and metadata.st_nlink != 1)):
        raise Refusal('journal authority must be private root-owned storage')


def parent_identity(fd):
    metadata = os.fstat(fd)
    root_owned(metadata, directory=True)
    return {'device': metadata.st_dev, 'inode': metadata.st_ino}


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise Refusal('invalid journal identity shape')


def lifetime(value):
    """Validate/copy independently authenticated service facts, never wire claims."""
    exact(value, ('bootId', 'generation', 'supervisor', 'daemon'))
    if type(value['bootId']) is not str or re.fullmatch(
            r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['bootId']) is None:
        raise Refusal('invalid boot identity')
    digest(value['generation'])
    exact(value['supervisor'], ('pid', 'startTicks', 'uid', 'gid'))
    for field, entry in value['supervisor'].items():
        if type(entry) is not int or entry < (1 if field in ('pid', 'startTicks') else 0):
            raise Refusal('invalid supervisor lifetime identity')
    exact(value['daemon'], ('instance', 'serviceIdentitySha256', 'dataRootIdentitySha256'))
    for entry in value['daemon'].values():
        digest(entry)
    return canonical(value)


class Journal:
    """Exclusive journal beneath a held, previously authenticated state-parent FD.

    The genesis layer must authenticate the complete ancestor chain and approved
    source/deployment before constructing this object. Validating this immediate
    FD is additional defense, not genesis authorization. No checkout entrypoint
    constructs a production Journal.
    """
    def __init__(self, state_parent_fd, deployment_sha256, *, active_lifetime):
        # Frozen serialization prevents caller mutation of the active binding.
        # Genesis must obtain these facts from authenticated live kernel/service
        # identities; accepting a parameter is not itself that authentication.
        self._active_lifetime = lifetime(active_lifetime)
        self.deployment = digest(deployment_sha256)
        self.directory = os.dup(state_parent_fd)
        os.set_inheritable(self.directory, False)
        self.lock = None
        self.connection = None
        try:
            self.parent = parent_identity(self.directory)
            self.lock = self._file('journal.lock')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd = self._file('journal.sqlite3')
            os.close(fd)
            for name in ('journal.sqlite3-wal', 'journal.sqlite3-shm'):
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=self.directory)
                except FileNotFoundError:
                    continue
                try:
                    root_owned(os.fstat(fd))
                finally:
                    os.close(fd)
            # /proc resolves the held parent, not a caller-provided absolute path.
            self.connection = sqlite3.connect(f'/proc/self/fd/{self.directory}/journal.sqlite3',
                                              isolation_level=None, timeout=0)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute('PRAGMA foreign_keys=ON')
            self.connection.execute('PRAGMA synchronous=FULL')
            if self.connection.execute('PRAGMA journal_mode=WAL').fetchone()[0] != 'wal':
                raise Refusal('durable WAL unavailable')
            app = self.connection.execute('PRAGMA application_id').fetchone()[0]
            version = self.connection.execute('PRAGMA user_version').fetchone()[0]
            if app == 0 and version == 0:
                if self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                    raise Refusal('unknown existing journal schema')
                self._initialize()
            elif app != APPLICATION_ID or version != SCHEMA_VERSION:
                raise Refusal('unsupported journal schema')
            if self.connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise Refusal('journal integrity check failed')
            row = self.connection.execute('SELECT deployment FROM authority WHERE singleton=1').fetchone()
            if row is None or row['deployment'] != self.deployment:
                raise Refusal('journal deployment mismatch; reconciliation required')
            # No previous connection's active work becomes executable merely
            # because this process opened the same database. Persist before
            # returning the instance, including when supplied facts match.
            with self.transaction():
                self.connection.execute("UPDATE jobs SET recovery_required=1 WHERE state!='ABORTED'")
            os.fsync(self.directory)
        except BaseException:
            self.close()
            raise

    def _file(self, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     0o600, dir_fd=self.directory)
        try:
            root_owned(os.fstat(fd))
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _initialize(self):
        # executescript commits implicitly, so explicit SQL transaction delimiters
        # keep schema, authority and version installation atomic together.
        self.connection.executescript(f'''
            BEGIN IMMEDIATE;
            CREATE TABLE authority(singleton INTEGER PRIMARY KEY CHECK(singleton=1), deployment TEXT NOT NULL);
            CREATE TABLE jobs(id TEXT PRIMARY KEY, state TEXT NOT NULL, version INTEGER NOT NULL,
                identity TEXT NOT NULL, reservation INTEGER NOT NULL, deadline_ns INTEGER NOT NULL,
                stage_name TEXT UNIQUE NOT NULL, stage_token TEXT UNIQUE NOT NULL, reason TEXT,
                recovery_required INTEGER NOT NULL CHECK(recovery_required IN (0,1)));
            CREATE TABLE resources(id TEXT PRIMARY KEY, job TEXT NOT NULL REFERENCES jobs(id),
                ordinal INTEGER NOT NULL, kind TEXT NOT NULL, name TEXT UNIQUE NOT NULL,
                token TEXT UNIQUE NOT NULL, authority TEXT NOT NULL, state TEXT NOT NULL,
                version INTEGER NOT NULL, observed TEXT, UNIQUE(job,ordinal));
            INSERT INTO authority VALUES(1,'{self.deployment}');
            PRAGMA application_id={APPLICATION_ID};
            PRAGMA user_version={SCHEMA_VERSION};
            COMMIT;
        ''')

    @contextlib.contextmanager
    def transaction(self):
        self.connection.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.connection.execute('COMMIT')
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if getattr(self, 'directory', None) is not None:
            os.close(self.directory)
            self.directory = None

    def admit(self, identity, *, closure, stage_parent_fd, artifact_parent_fd, deadline_ns):
        """Commit ADMITTED+reservation before any per-job filesystem mutation.

        All inputs are independently authenticated service facts, not wire data.
        The input closure is the bounded transport-validated canonical manifest;
        its exact digest is included in the immutable request identity.
        """
        exact(identity, ('bootId', 'generation', 'peer', 'supervisor', 'daemon', 'request'))
        if lifetime({key: identity[key] for key in ('bootId', 'generation', 'supervisor', 'daemon')}) != self._active_lifetime:
            raise Refusal('admission does not match active service lifetime')
        for key in ('peer', 'supervisor'):
            exact(identity[key], ('pid', 'startTicks', 'uid', 'gid'))
            for field, value in identity[key].items():
                if type(value) is not int or value < (1 if field in ('pid', 'startTicks') else 0):
                    raise Refusal('invalid process lifetime identity')
        exact(identity['daemon'], ('instance', 'serviceIdentitySha256', 'dataRootIdentitySha256'))
        for value in identity['daemon'].values():
            digest(value)
        exact(identity['request'], ('action', 'approvalIndexSha256', 'lockSha256', 'actionManifestSha256',
                                    'transcriptSha256', 'closureSha256', 'clientNonce'))
        if identity['request']['action'] not in ('bootstrap-offline-v2', 'probe-compile-v2', 'driver-replay-v2',
                'runtime-replay-v2', 'probe-run-v2', 'loader-compile-v2', 'loader-run-v2', 'package-provenance-v2'):
            raise Refusal('invalid fixed journal action')
        for key, value in identity['request'].items():
            if key != 'action':
                digest(value)
        if type(closure) is not list or len(closure) > 1720:
            raise Refusal('invalid bounded approved closure')
        closure_bytes = canonical(closure).encode()
        if len(closure_bytes) > 1024 * 1024 or hashlib.sha256(closure_bytes).hexdigest() != identity['request']['closureSha256']:
            raise Refusal('approved closure digest mismatch')
        now = time.monotonic_ns()
        if type(deadline_ns) is not int or not now < deadline_ns <= now + 2100 * 10**9:
            raise Refusal('invalid aggregate job deadline')
        recorded = dict(identity, stateParent=self.parent,
                        stageParent=parent_identity(stage_parent_fd),
                        artifactParent=parent_identity(artifact_parent_fd), deployment=self.deployment,
                        approvedClosure=closure)
        job, token = secrets.token_hex(32), secrets.token_hex(32)
        name = 'stage-' + secrets.token_hex(32)
        with self.transaction():
            if self.connection.execute("SELECT 1 FROM jobs WHERE state!='ABORTED' LIMIT 1").fetchone():
                raise Refusal('unreconciled or retained job prevents new admission')
            if self.connection.execute('SELECT count(*) FROM jobs').fetchone()[0] >= 1024:
                raise Refusal('journal retention bound reached')
            self.connection.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,NULL,0)',
                                    (job, 'ADMITTED', 0, canonical(recorded), RESERVATION,
                                     deadline_ns, name, token,))
        return self.job(job)

    def job(self, job):
        row = self.connection.execute('SELECT * FROM jobs WHERE id=?', (digest(job),)).fetchone()
        if row is None:
            raise Refusal('unknown journal job')
        return dict(row)

    def intent(self, job, version, *, ordinal, kind, authority):
        """Commit random immutable operation identity before any resource create.

        Stage/spool/helper mutation is not implemented here. A future fixed
        broker must use this returned exact intent, never a requested name.
        """
        if kind not in ('stage', 'spool'):
            raise Refusal('unknown resource operation')
        if type(ordinal) is not int or not 0 <= ordinal < 1728:
            raise Refusal('invalid operation ordinal')
        exact(authority, ('parent', 'inputId', 'sha256', 'bytes', 'capBytes'))
        exact(authority['parent'], ('device', 'inode'))
        for value in authority['parent'].values():
            if type(value) is not int or value < 0:
                raise Refusal('invalid parent identity')
        digest(authority['inputId']); digest(authority['sha256'])
        if (type(authority['bytes']) is not int or type(authority['capBytes']) is not int or
                not 0 <= authority['bytes'] <= authority['capBytes'] <= RESERVATION):
            raise Refusal('invalid reserved operation bytes')
        if type(version) is not int or version < 0:
            raise Refusal('invalid job version')
        operation, token = secrets.token_hex(32), secrets.token_hex(32)
        name = kind + '-' + secrets.token_hex(32)
        with self.transaction():
            current = self.job(job)
            if current['state'] not in ('ADMITTED', 'INPUT_CAPTURING') or current['version'] != version:
                raise Refusal('stale or quarantined admission')
            if time.monotonic_ns() >= current['deadline_ns']:
                raise Refusal('expired admission cannot mutate resources')
            identity = json.loads(current['identity'])
            recorded_lifetime = {key: identity[key] for key in ('bootId', 'generation', 'supervisor', 'daemon')}
            if current['recovery_required'] or lifetime(recorded_lifetime) != self._active_lifetime:
                raise Refusal('old service lifetime requires startup reconciliation; fresh mutation forbidden')
            if authority['parent'] not in (identity['stageParent'], identity['artifactParent']):
                raise Refusal('operation parent differs from admitted authority')
            if kind == 'stage':
                if ordinal != 0 or current['state'] != 'ADMITTED' or self.connection.execute(
                        "SELECT 1 FROM resources WHERE job=? AND kind='stage'", (job,)).fetchone():
                    raise Refusal('stage intent must be unique first operation')
                name, token = current['stage_name'], current['stage_token']
            else:
                if not self.connection.execute(
                        "SELECT 1 FROM resources WHERE job=? AND kind='stage'", (job,)).fetchone():
                    raise Refusal('spool intent requires durable stage intent')
                rows = identity['approvedClosure']
                if authority['capBytes'] != authority['bytes']:
                    raise Refusal('spool capture cap must equal exact admitted byte length')
                if any(json.loads(row['authority'])['inputId'] == authority['inputId'] for row in
                       self.connection.execute("SELECT authority FROM resources WHERE job=? AND kind='spool'", (job,))):
                    raise Refusal('duplicate logical spool operation')
                if not any(type(row) is dict and row.get('inputId') == authority['inputId'] and
                           row.get('sha256') == authority['sha256'] and row.get('bytes') == authority['bytes']
                           for row in rows):
                    raise Refusal('spool authority differs from admitted closure')
            self.connection.execute('INSERT INTO resources VALUES(?,?,?,?,?,?,?,?,?,NULL)',
                (operation, job, ordinal, kind, name, token, canonical(authority), 'INTENT', 0,))
            self.connection.execute("UPDATE jobs SET state='INPUT_CAPTURING',version=version+1 WHERE id=?", (job,))
        return dict(self.connection.execute('SELECT * FROM resources WHERE id=?', (operation,)).fetchone())

    def quarantine(self, job, version, reason):
        """Monotonic unresolved state: no revival, quota release or deletion API."""
        if type(version) is not int or version < 0:
            raise Refusal('invalid job version')
        if type(reason) is not str or not 1 <= len(reason.encode()) <= 1024:
            raise Refusal('invalid bounded quarantine reason')
        with self.transaction():
            current = self.job(job)
            if current['version'] != version or current['state'] in ('ABORTED', 'QUARANTINED'):
                raise Refusal('stale/terminal quarantine transition')
            self.connection.execute("UPDATE jobs SET state='QUARANTINED',version=version+1,reason=? WHERE id=?",
                                    (reason, job))
        return self.job(job)

    def pending(self):
        """Startup reconciliation input only; never permission to resume/clean."""
        return [dict(row) for row in self.connection.execute("SELECT * FROM jobs WHERE state!='ABORTED' ORDER BY id")]
