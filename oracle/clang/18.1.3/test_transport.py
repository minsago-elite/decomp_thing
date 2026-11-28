"""Unprivileged transport controls; no deployed root authority is exercised."""
import array
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import time
import unittest

SPEC = importlib.util.spec_from_file_location('clang_transport', Path(__file__).resolve().parents[3] / 'scripts/oracle/clang_18_1_3_transport.py')
t = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(t)

BEGIN = b'{"action":"driver-replay-v2","actionManifestSha256":"2222222222222222222222222222222222222222222222222222222222222222","approvalIndexSha256":"0000000000000000000000000000000000000000000000000000000000000000","clientNonce":"3333333333333333333333333333333333333333333333333333333333333333","counts":{"additional":0,"packagePayload":0,"recipeSource":1},"lockSha256":"1111111111111111111111111111111111111111111111111111111111111111","parentJobId":null,"protocolVersion":2,"totalBytes":3,"type":"BEGIN"}'
HEADER = b'{"firstOrdinal":0,"rowCount":1,"sequence":0,"type":"FD_BATCH"}'
ROW = b'{"bytes":3,"inputId":"4444444444444444444444444444444444444444444444444444444444444444","ordinal":0,"role":"recipe","sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}'
COMMIT = b'{"batchCount":1,"rowCount":1,"totalBytes":3,"type":"COMMIT_INPUTS"}'
GOLD = 'c180ad9f17f798417ebac6218e25ed42f991ab88c09124026e2aadd4d2a1841d'


def packet(connection, payload, fds=()):
    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))] if fds else []
    connection.sendmsg([payload], ancillary)


def feed(receiver, value, fds=()):
    parsed, nodes = t.parse(json.dumps(value).encode())
    receiver.accept(parsed, fds, nodes)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.left, self.right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(self.left.close)
        self.addCleanup(self.right.close)

    def receiver(self):
        receiver = t.InputTranscript(json.loads(BEGIN), [json.loads(ROW)])
        self.addCleanup(receiver.close)
        return receiver

    def begin(self, digest=GOLD):
        return dict(json.loads(BEGIN), transcriptSha256=digest)

    def batch(self):
        return {'type': 'FD_BATCH', 'sequence': 0, 'firstOrdinal': 0, 'rows': [json.loads(ROW)]}

    def commit(self, digest=GOLD):
        return dict(json.loads(COMMIT), transcriptSha256=digest)

    def fd(self):
        fd = os.memfd_create('inert-transport-fixture', os.MFD_CLOEXEC)
        os.write(fd, b'abc')
        self.addCleanup(lambda: os.close(fd))
        return fd

    def transfer(self, receiver, value, fds=()):
        packet(self.left, json.dumps(value).encode(), fds)
        message, owned, nodes = t.receive(self.right, time.monotonic() + 1)
        for fd in owned:
            self.assertFalse(os.get_inheritable(fd))
        receiver.accept(message, owned, nodes)

    def test_independent_golden_real_rights_and_kernel_peer(self):
        literals = [BEGIN, HEADER, ROW, COMMIT]
        self.assertEqual([len(x) for x in literals], [500, 62, 192, 67])
        preimage = b'decomp-thing:clang1813:fd-transcript:v2\0'
        for prefix, literal in zip(('000001f4', '0000003e', '000000c0', '00000043'), literals):
            preimage += bytes.fromhex(prefix) + literal
        self.assertEqual(len(preimage), 877)
        self.assertEqual(hashlib.sha256(preimage).hexdigest(), GOLD)
        self.assertEqual(t.peer_credentials(self.right, os.getuid()), (os.getpid(), os.getuid(), os.getgid()))
        with self.assertRaises(t.Refusal):
            t.peer_credentials(self.right, os.getuid() + 1)
        receiver = self.receiver()
        self.transfer(receiver, self.begin())
        self.transfer(receiver, self.batch(), [self.fd()])
        self.transfer(receiver, self.commit())
        self.assertEqual(receiver.state, 'COMMITTED')
        owned = receiver.fds[0]
        self.assertEqual(os.pread(owned, 3, 0), b'abc')
        receiver.close()
        with self.assertRaises(OSError):
            os.fstat(owned)

    def test_digest_only_changes_leave_preimage_but_refuse_and_close(self):
        for begin_hash, commit_hash in [('f'*64, GOLD), (GOLD, 'f'*64), ('f'*64, 'f'*64)]:
            with self.subTest(begin=begin_hash, commit=commit_hash):
                receiver = self.receiver()
                self.transfer(receiver, self.begin(begin_hash))
                self.transfer(receiver, self.batch(), [self.fd()])
                owned = receiver.fds[0]
                with self.assertRaises(t.Refusal):
                    self.transfer(receiver, self.commit(commit_hash))
                self.assertEqual(receiver.hash.hexdigest(), GOLD)
                with self.assertRaises(OSError):
                    os.fstat(owned)

    def test_duplicate_json_and_payload_truncation_close_actual_rights(self):
        for payload in (b'{"type":"BEGIN","type":"BEGIN"}', b'x' * (t.MAX_FRAME + 1), b'[]'):
            with self.subTest(size=len(payload)):
                fd = self.fd()
                before = len(os.listdir('/proc/self/fd'))
                packet(self.left, payload, [fd])
                with self.assertRaises(t.Refusal):
                    t.receive(self.right, time.monotonic() + 1)
                self.assertEqual(len(os.listdir('/proc/self/fd')), before)
                os.fstat(fd)  # Sender retains ownership.

    def test_ancillary_overflow_closes_delivered_descriptors(self):
        fd = self.fd()
        before = len(os.listdir('/proc/self/fd'))
        packet(self.left, b'{}', [fd] * 64)
        with self.assertRaises(t.Refusal):
            t.receive(self.right, time.monotonic() + 1)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_unexpected_credentials_ancillary_closes_rights(self):
        self.right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        before = len(os.listdir('/proc/self/fd'))
        fd = self.fd()
        before += 1
        packet(self.left, b'{}', [fd])
        with self.assertRaises(t.Refusal):
            t.receive(self.right, time.monotonic() + 1)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_bad_approved_closure_and_caller_mutation_cannot_change_binding(self):
        rows = [json.loads(ROW)]
        begin = json.loads(BEGIN)
        receiver = t.InputTranscript(begin, rows)
        self.addCleanup(receiver.close)
        begin['clientNonce'] = 'f' * 64
        rows[0]['inputId'] = 'f' * 64
        self.transfer(receiver, self.begin())
        self.transfer(receiver, self.batch(), [self.fd()])
        self.transfer(receiver, self.commit())
        self.assertEqual(receiver.state, 'COMMITTED')
        begin = json.loads(BEGIN)
        begin['counts']['recipeSource'] = True
        with self.assertRaises(t.Refusal):
            t.InputTranscript(begin, [json.loads(ROW)])
        begin = json.loads(BEGIN)
        begin['counts']['recipeSource'] = 2
        begin['totalBytes'] = 6
        duplicate = [json.loads(ROW), dict(json.loads(ROW), ordinal=1)]
        with self.assertRaises(t.Refusal):
            t.InputTranscript(begin, duplicate)

    def test_missing_duplicate_reordered_and_extra_rights_refuse(self):
        for mode in ('missing', 'duplicate', 'reordered', 'extra', 'row'):
            with self.subTest(mode=mode):
                receiver = self.receiver()
                self.transfer(receiver, self.begin())
                if mode in ('duplicate', 'missing'):
                    self.transfer(receiver, self.batch(), [self.fd()])
                batch = self.batch()
                if mode == 'reordered':
                    batch['sequence'] = 1
                if mode == 'row':
                    batch['rows'][0]['inputId'] = 'a' * 64
                with self.assertRaises(t.Refusal):
                    if mode == 'missing':
                        altered = self.commit()
                        altered['rowCount'] = 2
                        self.transfer(receiver, altered)
                    else:
                        self.transfer(receiver, batch, [self.fd()] * (2 if mode == 'extra' else 1))
                self.assertEqual(receiver.fds, [])

    def test_deadline_disconnect_depth_nodes_and_float_limits(self):
        start = time.monotonic()
        with self.assertRaises(t.Refusal):
            t.receive(self.right, start + .02)
        self.assertLess(time.monotonic() - start, 1)
        self.left.close()
        with self.assertRaises(t.Refusal):
            t.receive(self.right, time.monotonic() + 1)
        for payload in (b'{"x":1.0}', b'{"x":NaN}', b'{"x":' + b'[' * 17 + b'0' + b']' * 17 + b'}', json.dumps({'x': [0] * 4096}).encode()):
            with self.assertRaises(t.Refusal):
                t.parse(payload)

    def test_maximum_1720_descriptor_capacity_real_rights(self):
        import resource
        self.assertGreaterEqual(resource.getrlimit(resource.RLIMIT_NOFILE)[0], 3500,
                                'maximum-capacity deployment FD prerequisite unavailable')
        rows = []
        for index in range(1720):
            row = json.loads(ROW)
            row.update(ordinal=index, inputId=f'{index:064x}', bytes=0,
                       role='recipe' if index < 512 else 'payload' if index < 1712 else 'report')
            rows.append(row)
        begin = json.loads(BEGIN)
        begin.update(counts={'recipeSource': 512, 'packagePayload': 1200, 'additional': 8}, totalBytes=0)
        # Independent fixture oracle: explicit wire objects and stdlib framing,
        # never the receiver's canonical/add/hash implementation.
        objects = [begin]
        batches = []
        for sequence, offset in enumerate(range(0, 1720, 32)):
            part = rows[offset:offset+32]
            batches.append({'type': 'FD_BATCH', 'sequence': sequence, 'firstOrdinal': offset, 'rows': part})
            objects.append({'type': 'FD_BATCH', 'sequence': sequence, 'firstOrdinal': offset, 'rowCount': len(part)})
            objects.extend(part)
        commit = {'type': 'COMMIT_INPUTS', 'batchCount': 54, 'rowCount': 1720, 'totalBytes': 0}
        objects.append(commit)
        oracle = hashlib.sha256(b'decomp-thing:clang1813:fd-transcript:v2\0')
        for obj in objects:
            blob = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()
            oracle.update(len(blob).to_bytes(4, 'big'))
            oracle.update(blob)
        expected = oracle.hexdigest()
        receiver = t.InputTranscript(begin, rows)
        self.addCleanup(receiver.close)
        self.transfer(receiver, dict(begin, transcriptSha256=expected))
        # Distinct files; no file metadata inspection occurs in the dispatcher.
        for batch in batches:
            descriptors = [self.fd() for _ in batch['rows']]
            self.transfer(receiver, batch, descriptors)
        self.transfer(receiver, dict(commit, transcriptSha256=expected))
        self.assertEqual((receiver.rows, receiver.batches, receiver.messages), (1720, 54, 56))
        self.assertEqual(len(receiver.fds), 1720)
        self.assertLess(receiver.bytes, 1024 * 1024)
        self.assertLess(receiver.nodes, 65536)
        receiver.close()

    def test_timeout_and_disconnect_close_already_retained_rights(self):
        for mode in ('timeout', 'disconnect', 'malformed'):
            with self.subTest(mode=mode):
                left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                try:
                    receiver = self.receiver()
                    packet(left, json.dumps(self.begin()).encode())
                    receiver.receive(right, time.monotonic() + 1)
                    packet(left, json.dumps(self.batch()).encode(), [self.fd()])
                    receiver.receive(right, time.monotonic() + 1)
                    owned = receiver.fds[0]
                    if mode == 'disconnect':
                        left.close()
                    elif mode == 'malformed':
                        packet(left, b'not json', [self.fd()])
                    with self.assertRaises(t.Refusal):
                        receiver.receive(right, time.monotonic() + .01)
                    self.assertEqual(receiver.state, 'CLOSED')
                    with self.assertRaises(OSError):
                        os.fstat(owned)
                finally:
                    left.close()
                    right.close()

    def test_aggregate_budgets_and_covered_fields(self):
        for field, value in [('messages', 64), ('nodes', 65536), ('bytes', 1024 * 1024)]:
            receiver = self.receiver()
            setattr(receiver, field, value)
            with self.assertRaises(t.Refusal):
                self.transfer(receiver, self.begin())
            self.assertEqual(receiver.state, 'CLOSED')
        for key in ('clientNonce', 'approvalIndexSha256', 'actionManifestSha256'):
            receiver = self.receiver()
            altered = self.begin()
            altered[key] = 'f' * 64
            with self.assertRaises(t.Refusal):
                self.transfer(receiver, altered)

    def declared_closure(self, specifications):
        categories = {'recipe': 'recipeSource', 'source': 'recipeSource',
                      'payload': 'packagePayload', 'source-payload': 'packagePayload',
                      'record': 'additional', 'report': 'additional',
                      'rootfs': 'additional', 'oci': 'additional'}
        begin = json.loads(BEGIN)
        begin['counts'] = dict.fromkeys(('recipeSource', 'packagePayload', 'additional'), 0)
        rows = []
        for index, (role, size) in enumerate(specifications):
            row = json.loads(ROW)
            row.update(ordinal=index, inputId=f'{index:064x}', role=role, bytes=size)
            rows.append(row)
            begin['counts'][categories.get(role, 'recipeSource')] += 1
        begin['totalBytes'] = sum(row['bytes'] for row in rows)
        return begin, rows

    def test_fixed_roles_per_file_exact_boundary_and_overflow(self):
        # Independently specified policy oracle, not the module's policy table.
        cases = [('recipe', 16*1024**2), ('source', 16*1024**2),
                 ('payload', 1024**3), ('source-payload', 1024**3),
                 ('record', 1024**2), ('report', 1024**2),
                 ('rootfs', 2*1024**3), ('oci', 2*1024**3)]
        for role, cap in cases:
            with self.subTest(role=role):
                begin, rows = self.declared_closure([(role, cap)])
                receiver = t.InputTranscript(begin, rows)
                receiver.close()
                begin, rows = self.declared_closure([(role, cap + 1)])
                with self.assertRaises(t.Refusal):
                    t.InputTranscript(begin, rows)
        for role in ('unreviewed', 'artifact', 'Recipe', ''):
            begin, rows = self.declared_closure([(role, 0)])
            with self.assertRaises(t.Refusal):
                t.InputTranscript(begin, rows)

    def test_exact_category_counts_and_aggregate_bytes(self):
        for role, category, other in [('payload', 'packagePayload', 'recipeSource'),
                                      ('source', 'recipeSource', 'additional'),
                                      ('report', 'additional', 'packagePayload')]:
            begin, rows = self.declared_closure([(role, 0)])
            begin['counts'][category] = 0
            begin['counts'][other] = 1
            with self.assertRaises(t.Refusal):
                t.InputTranscript(begin, rows)
        for roles, per_file, number in [(['recipe', 'source'], 16*1024**2, 4),
                                        (['payload', 'source-payload'], 1024**3, 3)]:
            specs = [(roles[i % 2], per_file) for i in range(number)]
            begin, rows = self.declared_closure(specs)
            t.InputTranscript(begin, rows).close()
            # Individual rows remain legal, but one extra byte exceeds the
            # shared class total even when spread across two role aliases.
            begin, rows = self.declared_closure(specs + [(roles[0], 1)])
            with self.assertRaises(t.Refusal):
                t.InputTranscript(begin, rows)
        # Additional class reaches its exact eight-input/sixteen-GiB ceiling.
        begin, rows = self.declared_closure([('rootfs', 2*1024**3)] * 4 + [('oci', 2*1024**3)] * 4)
        t.InputTranscript(begin, rows).close()
        for role, count in [('source', 513), ('payload', 1201), ('report', 9)]:
            begin, rows = self.declared_closure([(role, 0)] * count)
            with self.assertRaises(t.Refusal):
                t.InputTranscript(begin, rows)
        begin, rows = self.declared_closure([('payload', 1024**3)])
        begin['totalBytes'] = 20*1024**3 + 1
        with self.assertRaises(t.Refusal):
            t.InputTranscript(begin, rows)

    def test_bool_count_and_unexpected_postcommit_close(self):
        receiver = self.receiver()
        self.transfer(receiver, self.begin())
        self.transfer(receiver, self.batch(), [self.fd()])
        commit = self.commit()
        commit['rowCount'] = True
        with self.assertRaises(t.Refusal):
            self.transfer(receiver, commit)
        self.assertEqual(receiver.fds, [])


if __name__ == '__main__':
    unittest.main()
