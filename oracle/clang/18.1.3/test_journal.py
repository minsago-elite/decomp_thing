"""Actual local durability, inert UID ownership fixtures; no root deployment."""
import hashlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('clang_journal', ROOT / 'scripts/oracle/clang_18_1_3_journal.py')
j = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(j)
BUILD = ROOT / 'build/clang-remaining-review/journal-fixtures'


def inert_owned(metadata, directory=False):
    """Same mode/type/link checks, explicitly substitutes current UID for root."""
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(metadata.st_mode) or metadata.st_uid != os.getuid() or
            stat.S_IMODE(metadata.st_mode) & 0o077 or (not directory and metadata.st_nlink != 1)):
        raise j.Refusal('inert protected storage check failed')


def identity():
    closure = [{'inputId': 'a'*64, 'sha256': hashlib.sha256(b'abc').hexdigest(), 'bytes': 3}]
    process = {'pid': os.getpid(), 'startTicks': int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]), 'uid': os.getuid(), 'gid': os.getgid()}
    request = {key: 'b'*64 for key in ('approvalIndexSha256', 'lockSha256', 'actionManifestSha256',
                                    'transcriptSha256', 'closureSha256', 'clientNonce')}
    request.update(action='driver-replay-v2', closureSha256=hashlib.sha256(j.canonical(closure).encode()).hexdigest())
    return {'bootId': '00000000-0000-0000-0000-000000000001', 'generation': 'c'*64,
            'peer': process, 'supervisor': process,
            'daemon': dict.fromkeys(('instance', 'serviceIdentitySha256', 'dataRootIdentitySha256'), 'd'*64),
            'request': request}, closure


def active_lifetime():
    facts, _ = identity()
    return {key: facts[key] for key in ('bootId', 'generation', 'supervisor', 'daemon')}


def admit(journal, parent):
    facts, closure = identity()
    return journal.admit(facts, closure=closure, stage_parent_fd=parent,
                         artifact_parent_fd=parent, deadline_ns=time.monotonic_ns() + 60*10**9)


def authority(parent):
    _, closure = identity()
    return dict(closure[0], parent=j.parent_identity(parent), capBytes=3)


def crash_child(directory, point):
    # Explicitly inert policy in this test child, not a production API switch.
    j.root_owned = inert_owned
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    journal = j.Journal(parent, 'e'*64, active_lifetime=active_lifetime())
    if point == 'uncommitted':
        facts, closure = identity()
        # Inject process death at the actual transaction boundary before COMMIT.
        journal.connection.execute("CREATE TRIGGER crash_admission AFTER INSERT ON jobs BEGIN SELECT child_crash(); END")
        journal.connection.create_function('child_crash', 0, lambda: os._exit(73))
        admit(journal, parent)
    job = admit(journal, parent)
    if point == 'uncommitted-intent':
        journal.connection.execute("CREATE TRIGGER crash_intent AFTER INSERT ON resources BEGIN SELECT child_crash(); END")
        journal.connection.create_function('child_crash', 0, lambda: os._exit(73))
        journal.intent(job['id'], 0, ordinal=0, kind='stage', authority=authority(parent))
    if point in ('intent', 'unmarked'):
        operation = journal.intent(job['id'], 0, ordinal=0, kind='stage', authority=authority(parent))
        if point == 'unmarked':
            # Inert exclusive create only after committed operation. Production
            # marker/cleanup not implemented: recovery must preserve this entry.
            os.mkdir(operation['name'], 0o700, dir_fd=parent)
            os.fsync(parent)
    if point == 'quarantine':
        journal.quarantine(job['id'], 0, 'inert recovery ambiguity')
    os._exit(73)  # No close/checkpoint/destructors; exercise actual WAL recovery.


class JournalTests(unittest.TestCase):
    def setUp(self):
        BUILD.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=BUILD)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.parent = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(lambda: os.close(self.parent))
        self.policy = patch.object(j, 'root_owned', inert_owned)
        self.policy.start()
        self.addCleanup(self.policy.stop)

    def open(self, deployment='e'*64, active=None):
        journal = j.Journal(self.parent, deployment, active_lifetime=active if active is not None else active_lifetime())
        self.addCleanup(journal.close)
        return journal

    def child(self, point):
        result = subprocess.run([sys.executable, '-B', __file__, '--crash-child', str(self.path), point],
                                cwd=ROOT, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 73, result.stderr.decode())

    def test_durable_admission_intent_exact_owned_stage_and_reservation(self):
        journal = self.open()
        self.assertEqual(journal.connection.execute('PRAGMA synchronous').fetchone()[0], 2)
        self.assertEqual(journal.connection.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
        job = admit(journal, self.parent)
        self.assertEqual(job['state'], 'ADMITTED')
        self.assertEqual(job['reservation'], 20*1024**3)
        self.assertEqual(set(p.name for p in self.path.iterdir()),
                         {'journal.lock', 'journal.sqlite3', 'journal.sqlite3-wal', 'journal.sqlite3-shm'})
        operation = journal.intent(job['id'], 0, ordinal=0, kind='stage', authority=authority(self.parent))
        self.assertEqual((operation['name'], operation['token']), (job['stage_name'], job['stage_token']))
        self.assertEqual(operation['state'], 'INTENT')
        self.assertFalse((self.path / operation['name']).exists())
        self.assertEqual(journal.job(job['id'])['version'], 1)
        with self.assertRaises(j.Refusal):
            journal.intent(job['id'], 0, ordinal=1, kind='spool', authority=authority(self.parent))
        with self.assertRaises(j.Refusal):
            journal.intent(job['id'], 1, ordinal=1, kind='stage', authority=authority(self.parent))
        journal.close()
        reopened = self.open()
        self.assertEqual(reopened.pending()[0]['id'], job['id'])
        self.assertEqual(reopened.connection.execute('SELECT token FROM resources').fetchone()[0], operation['token'])

    def test_actual_process_crashes_reopen_admission_intent_and_quarantine(self):
        for point in ('admitted', 'intent', 'quarantine'):
            with self.subTest(point=point):
                # Separate state parents keep every crashed generation independent.
                sub = self.path / point
                sub.mkdir(mode=0o700)
                result = subprocess.run([sys.executable, '-B', __file__, '--crash-child', str(sub), point],
                                        cwd=ROOT, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 73, result.stderr.decode())
                fd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    reopened = j.Journal(fd, 'e'*64, active_lifetime=active_lifetime())
                    try:
                        job = reopened.pending()[0]
                        self.assertEqual(job['reservation'], j.RESERVATION)
                        self.assertEqual(job['state'], {'admitted':'ADMITTED', 'intent':'INPUT_CAPTURING',
                                                        'quarantine':'QUARANTINED'}[point])
                        with self.assertRaises(j.Refusal):
                            admit(reopened, fd)
                    finally:
                        reopened.close()
                finally:
                    os.close(fd)

    def test_uncommitted_admission_crash_creates_no_job_resource(self):
        self.child('uncommitted')
        journal = self.open()
        self.assertEqual(journal.pending(), [])
        self.assertFalse(any(p.name.startswith('stage-') for p in self.path.iterdir()))
        # Remove inert crash trigger before the new independent admission.
        journal.connection.execute('DROP TRIGGER crash_admission')
        self.assertEqual(admit(journal, self.parent)['state'], 'ADMITTED')

    def test_uncommitted_resource_intent_crash_retains_admission_and_quota(self):
        self.child('uncommitted-intent')
        journal = self.open()
        job = journal.pending()[0]
        self.assertEqual((job['state'], job['version'], job['reservation']), ('ADMITTED', 0, j.RESERVATION))
        self.assertEqual(journal.connection.execute('SELECT count(*) FROM resources').fetchone()[0], 0)
        self.assertFalse((self.path / job['stage_name']).exists())
        with self.assertRaises(j.Refusal):
            admit(journal, self.parent)

    def test_unmarked_creation_crash_preserves_entry_and_sticky_quarantine(self):
        self.child('unmarked')
        journal = self.open()
        job = journal.pending()[0]
        operation = journal.connection.execute('SELECT * FROM resources').fetchone()
        entry = self.path / operation['name']
        inode = entry.stat().st_ino
        quarantined = journal.quarantine(job['id'], job['version'], 'unmarked create result is ambiguous')
        self.assertEqual(quarantined['reservation'], j.RESERVATION)
        with self.assertRaises(j.Refusal):
            journal.intent(job['id'], quarantined['version'], ordinal=1, kind='spool', authority=authority(self.parent))
        with self.assertRaises(j.Refusal):
            journal.quarantine(job['id'], quarantined['version'], 'cannot revive')
        self.assertEqual(entry.stat().st_ino, inode)
        # A foreign replacement is likewise preserved: no cleanup API claims it.
        entry.rmdir()
        entry.write_bytes(b'foreign replacement')
        journal.close()
        reopened = self.open()
        self.assertEqual(reopened.pending()[0]['state'], 'QUARANTINED')
        self.assertEqual(entry.read_bytes(), b'foreign replacement')

    def test_exclusive_lock_symlink_mode_deployment_and_version_refusals(self):
        journal = self.open()
        with self.assertRaises(BlockingIOError):
            j.Journal(self.parent, 'e'*64, active_lifetime=active_lifetime())
        journal.close()
        with self.assertRaises(j.Refusal):
            self.open('f'*64)
        journal = self.open()
        journal.connection.execute('PRAGMA user_version=99')
        journal.close()
        with self.assertRaises(j.Refusal):
            self.open()
        self.path.joinpath('journal.sqlite3').unlink()
        self.path.joinpath('journal.sqlite3').symlink_to('foreign')
        with self.assertRaises(OSError):
            self.open()
        self.assertFalse(self.path.joinpath('foreign').exists())

    def test_root_ownership_real_validator_refuses_unprivileged_fixture(self):
        self.policy.stop()
        self.addCleanup(self.policy.start)
        if os.getuid() == 0:
            self.fail('this source checkpoint requires an unprivileged fixture runner')
        before = set(self.path.iterdir())
        with self.assertRaises(j.Refusal):
            j.Journal(self.parent, 'e'*64, active_lifetime=active_lifetime())
        self.assertEqual(set(self.path.iterdir()), before)

    def test_intents_are_immutable_unique_and_cap_exact_before_any_create(self):
        journal = self.open()
        job = admit(journal, self.parent)
        stage = journal.intent(job['id'], 0, ordinal=0, kind='stage', authority=authority(self.parent))
        spool = journal.intent(job['id'], 1, ordinal=1, kind='spool', authority=authority(self.parent))
        self.assertNotEqual(stage['token'], spool['token'])
        self.assertNotEqual(stage['name'], spool['name'])
        with self.assertRaises(j.Refusal):
            journal.intent(job['id'], 2, ordinal=2, kind='spool', authority=authority(self.parent))
        journal.quarantine(job['id'], 2, 'test cleanup unavailable')
        self.assertEqual(journal.connection.execute('SELECT count(*) FROM resources').fetchone()[0], 2)
        self.assertFalse((self.path / spool['name']).exists())
        stored = journal.connection.execute('SELECT * FROM resources WHERE id=?', (spool['id'],)).fetchone()
        self.assertEqual(dict(stored), spool)

    def test_bad_ownership_hardlink_corruption_and_invalid_digest_do_not_leak_fds(self):
        before = len(os.listdir('/proc/self/fd'))
        with self.assertRaises(j.Refusal):
            j.Journal(self.parent, 'invalid', active_lifetime=active_lifetime())
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        os.chmod(self.path, 0o750)
        with self.assertRaises(j.Refusal):
            self.open()
        os.chmod(self.path, 0o700)
        journal = self.open()
        journal.close()
        os.link(self.path / 'journal.sqlite3', self.path / 'foreign-link')
        with self.assertRaises(j.Refusal):
            self.open()
        (self.path / 'foreign-link').unlink()
        (self.path / 'journal.sqlite3').write_bytes(b'corrupt journal bytes')
        with self.assertRaises(sqlite3.DatabaseError):
            self.open()

    def test_distinct_boot_generation_supervisor_and_daemon_reopen_cannot_mutate(self):
        variants = ('boot', 'generation', 'supervisor', 'daemon', 'daemon-service', 'daemon-data-root')
        for variant in variants:
            with self.subTest(lifetime=variant):
                directory = self.path / variant
                directory.mkdir(mode=0o700)
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    original = active_lifetime()
                    journal = j.Journal(fd, 'e'*64, active_lifetime=original)
                    job = admit(journal, fd)
                    journal.close()
                    changed = copy.deepcopy(original)
                    if variant == 'boot':
                        changed['bootId'] = '00000000-0000-0000-0000-000000000002'
                    elif variant == 'generation':
                        changed['generation'] = 'f'*64
                    elif variant == 'supervisor':
                        changed['supervisor']['startTicks'] += 1
                    else:
                        key = {'daemon':'instance', 'daemon-service':'serviceIdentitySha256',
                               'daemon-data-root':'dataRootIdentitySha256'}[variant]
                        changed['daemon'][key] = 'f'*64
                    reopened = j.Journal(fd, 'e'*64, active_lifetime=changed)
                    try:
                        old = reopened.job(job['id'])
                        self.assertEqual(old['recovery_required'], 1)
                        self.assertEqual(old['reservation'], j.RESERVATION)
                        # A prior-boot monotonic deadline can appear future.
                        # This must not authorize resumed old-lifetime work.
                        with patch.object(j.time, 'monotonic_ns', return_value=job['deadline_ns'] - 1):
                            with self.assertRaises(j.Refusal):
                                reopened.intent(job['id'], 0, ordinal=0, kind='stage', authority=authority(fd))
                        self.assertEqual(reopened.connection.execute('SELECT count(*) FROM resources').fetchone()[0], 0)
                        self.assertEqual(reopened.job(job['id'])['version'], 0)
                        quarantined = reopened.quarantine(job['id'], 0, 'old lifetime requires reconciliation')
                        self.assertEqual((quarantined['state'], quarantined['reservation'], quarantined['recovery_required']),
                                         ('QUARANTINED', j.RESERVATION, 1))
                    finally:
                        reopened.close()
                    again = j.Journal(fd, 'e'*64, active_lifetime=original)
                    try:
                        self.assertEqual(again.pending()[0]['state'], 'QUARANTINED')
                        self.assertEqual(again.pending()[0]['recovery_required'], 1)
                        self.assertEqual(again.pending()[0]['reservation'], j.RESERVATION)
                    finally:
                        again.close()
                finally:
                    os.close(fd)

    def test_matching_reopen_still_requires_persisted_startup_reconciliation(self):
        active = active_lifetime()
        journal = self.open(active=active)
        job = admit(journal, self.parent)
        self.assertEqual(job['recovery_required'], 0)
        journal.close()
        reopened = self.open(active=active)
        with self.assertRaises(j.Refusal):
            reopened.intent(job['id'], 0, ordinal=0, kind='stage', authority=authority(self.parent))
        reopened.close()
        # Observe the committed flag without another Journal constructor that
        # could set it again: this is a durable gate, not an in-memory check.
        raw = sqlite3.connect(self.path / 'journal.sqlite3')
        try:
            self.assertEqual(raw.execute('SELECT recovery_required FROM jobs WHERE id=?', (job['id'],)).fetchone()[0], 1)
        finally:
            raw.close()
        again = self.open(active=active)
        self.assertEqual(again.job(job['id'])['recovery_required'], 1)
        with self.assertRaises(j.Refusal):
            again.intent(job['id'], 0, ordinal=0, kind='stage', authority=authority(self.parent))
        self.assertEqual(again.job(job['id'])['reservation'], j.RESERVATION)

    def test_admission_matches_current_frozen_binding_and_current_intent_positive(self):
        active = active_lifetime()
        original = copy.deepcopy(active)
        journal = self.open(active=active)
        # Mutating the supplying object's nested fields cannot change authority.
        active['supervisor']['startTicks'] += 1
        active['daemon']['instance'] = 'f'*64
        for variant in ('bootId', 'generation', 'supervisor', 'daemon'):
            facts, closure = identity()
            if variant == 'bootId':
                facts[variant] = '00000000-0000-0000-0000-000000000002'
            elif variant == 'generation':
                facts[variant] = 'f'*64
            elif variant == 'supervisor':
                facts[variant]['startTicks'] += 1
            else:
                facts[variant]['instance'] = 'f'*64
            with self.assertRaises(j.Refusal):
                journal.admit(facts, closure=closure, stage_parent_fd=self.parent, artifact_parent_fd=self.parent,
                              deadline_ns=time.monotonic_ns()+10**9)
        self.assertEqual(journal.pending(), [])
        self.assertEqual(json.loads(journal._active_lifetime), original)
        job = admit(journal, self.parent)
        stage = journal.intent(job['id'], 0, ordinal=0, kind='stage', authority=authority(self.parent))
        self.assertEqual(stage['state'], 'INTENT')
        self.assertEqual(journal.job(job['id'])['recovery_required'], 0)

    def test_bad_authority_closure_stale_bool_and_expiry_refuse_before_intent(self):
        journal = self.open()
        facts, closure = identity()
        closure[0]['bytes'] = 4
        with self.assertRaises(j.Refusal):
            journal.admit(facts, closure=closure, stage_parent_fd=self.parent, artifact_parent_fd=self.parent,
                          deadline_ns=time.monotonic_ns()+10**9)
        job = admit(journal, self.parent)
        journal.intent(job['id'], 0, ordinal=0, kind='stage', authority=authority(self.parent))
        for field, value in [('parent', {'device':0, 'inode':0}), ('inputId', 'f'*64), ('capBytes', 4)]:
            invalid = authority(self.parent)
            invalid[field] = value
            with self.assertRaises(j.Refusal):
                journal.intent(job['id'], 1, ordinal=1, kind='spool', authority=invalid)
        with self.assertRaises(j.Refusal):
            journal.intent(job['id'], False, ordinal=0, kind='stage', authority=authority(self.parent))
        with patch.object(j.time, 'monotonic_ns', return_value=job['deadline_ns']):
            with self.assertRaises(j.Refusal):
                journal.intent(job['id'], 1, ordinal=1, kind='spool', authority=authority(self.parent))
        self.assertEqual(journal.connection.execute('SELECT count(*) FROM resources').fetchone()[0], 1)
        self.assertEqual(journal.job(job['id'])['state'], 'INPUT_CAPTURING')


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--crash-child':
        crash_child(sys.argv[2], sys.argv[3])
    else:
        unittest.main()
