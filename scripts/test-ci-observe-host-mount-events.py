#!/usr/bin/env python3
"""Never launches an observer or reads a real mount table; checks own proc identity."""
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import signal
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('observer', REPO / 'scripts/ci-observe-host-mount-events.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def row(mid=10, target='/private/work', options='rw', optional='shared:1', root='/',
        fstype='ext4', source='/private/device', superopts='rw', parent=1, device='8:1'):
    return f'{mid} {parent} {device} {root} {target} {options} {optional} - {fstype} {source} {superopts}\n'.encode()


class Clock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def ns(self):
        return int(self.now * 1_000_000_000)

    def sleep(self, seconds):
        self.now += seconds


class ObserverControls(unittest.TestCase):
    def drive(self, tables, events, duration=1, stop_after=None):
        clock = Clock()
        stream = io.BytesIO()
        reader = Mock(side_effect=tables)
        opener, closer = Mock(return_value=37), Mock()
        poller = Mock()
        queue = list(events)
        calls = [0]
        def poll(ms):
            clock.now += max(.001, ms / 1000)
            calls[0] += 1
            return queue.pop(0) if queue else []
        poller.poll.side_effect = poll
        with patch.object(m.time, 'monotonic', clock.monotonic), \
             patch.object(m.time, 'monotonic_ns', clock.ns), \
             patch.object(m.time, 'time_ns', lambda: clock.ns() + 100_000_000_000):
            m.observe(m.Recorder(stream), ['/private'], '/repo', duration,
                      lambda: stop_after is not None and calls[0] >= stop_after,
                      open_fd=opener, close_fd=closer, read=reader,
                      poll_factory=lambda: poller, namespace=lambda: 123)
        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertLessEqual(len(stream.getvalue()), m.MAX_OUTPUT)
        self.assertLessEqual(len(records), m.MAX_RECORDS)
        self.assertEqual('START', records[0]['kind'])
        self.assertEqual('STOP', records[-1]['kind'])
        opener.assert_called_once_with('/proc/self/mountinfo', os.O_RDONLY | os.O_CLOEXEC)
        closer.assert_called_once_with(37)
        poller.register.assert_called_once_with(37, select.POLLPRI | select.POLLERR)
        self.assertTrue(all(call.args == (37,) for call in reader.call_args_list))
        return records, reader, stream.getvalue()

    def test_add_remove_and_all_canonical_fields(self):
        original = m.parse(row())
        records, _, _ = self.drive([original, m.parse(row(11))], [[(37, select.POLLPRI)]])
        self.assertEqual(['REMOVED', 'ADDED'], [r['kind'] for r in records if r['kind'] in ('REMOVED', 'ADDED')])
        for change in [dict(options='ro'), dict(target='/private/moved'), dict(optional='master:2'),
                       dict(root='/private/root'), dict(parent=2), dict(device='8:2'),
                       dict(fstype='tmpfs'), dict(source='/different'), dict(superopts='ro')]:
            with self.subTest(change=change):
                records, _, _ = self.drive([original, m.parse(row(**change))], [[(37, select.POLLERR)]])
                changes = [r for r in records if r['kind'] == 'CHANGED']
                self.assertEqual(1, len(changes))
                self.assertNotEqual(changes[0]['before']['rowHash'], changes[0]['after']['rowHash'])

    def test_timeout_never_event_or_no_net_delta(self):
        records, reader, _ = self.drive([m.parse(row())], [[], [], [], []])
        self.assertEqual(1, reader.call_count)
        self.assertEqual(['START', 'BASELINE', 'STOP'], [r['kind'] for r in records])
        self.assertEqual('DEADLINE', records[-1]['reason'])

    def test_positive_event_only_no_net_delta_and_rearm(self):
        table = m.parse(row())
        records, reader, _ = self.drive([table, table, table],
                                      [[(37, select.POLLPRI | select.POLLERR)], [], [(37, select.POLLPRI)]])
        self.assertEqual(3, reader.call_count)
        self.assertEqual(2, sum(r['kind'] == 'NO_NET_DELTA' for r in records))
        for r in records:
            if r['kind'] in ('NO_NET_DELTA', 'EVENT'):
                self.assertEqual('UNKNOWN', r['aba'])
                self.assertEqual('UNKNOWN', r['coalescing'])

    def test_unrelated_descriptor_and_pollin_are_not_events(self):
        records, reader, _ = self.drive([m.parse(row())], [[(38, select.POLLPRI)], [(37, select.POLLIN)]])
        self.assertEqual(1, reader.call_count)
        self.assertFalse(any(r['kind'] == 'EVENT' for r in records))

    def test_hup_nval_read_and_parse_failures_unavailable(self):
        for mask in (select.POLLHUP, select.POLLNVAL, select.POLLHUP | select.POLLPRI):
            records, reader, _ = self.drive([m.parse(row())], [[(37, mask)]])
            self.assertEqual(1, reader.call_count)
            self.assertEqual('UNAVAILABLE', records[-2]['kind'])
        for failure in (OSError('PRIVATE EXCEPTION'), m.Unavailable('PARSE'), m.Unavailable('TABLE_BYTES')):
            records, _, raw = self.drive([m.parse(row()), failure], [[(37, select.POLLERR)]])
            self.assertTrue(records[-1]['incomplete'])
            self.assertNotIn(b'PRIVATE EXCEPTION', raw)

    def test_initial_read_failure_and_namespace_failure(self):
        records, _, _ = self.drive([m.Unavailable('TABLE_INCOMPLETE')], [])
        self.assertEqual(['START', 'UNAVAILABLE', 'STOP'], [r['kind'] for r in records])
        out = io.BytesIO()
        with patch.object(m.os, 'open', side_effect=AssertionError('actual read')):
            m.observe(m.Recorder(out), [], '/repo', 1, lambda: False,
                      namespace=Mock(side_effect=OSError('private')))
        self.assertEqual('UNAVAILABLE', json.loads(out.getvalue().splitlines()[1])['kind'])

    def test_unexpected_failure_preserves_exception_and_incomplete_stop(self):
        out = io.BytesIO()
        poller = Mock()
        poller.poll.return_value = [(42, select.POLLPRI)]
        with self.assertRaisesRegex(RuntimeError, 'authored failure'):
            m.observe(m.Recorder(out), [], '/repo', 1, lambda: False,
                      open_fd=Mock(return_value=42), close_fd=Mock(),
                      read=Mock(side_effect=[m.parse(row()), RuntimeError('authored failure')]),
                      poll_factory=lambda: poller, namespace=lambda: 123)
        stop = json.loads(out.getvalue().splitlines()[-1])
        self.assertEqual('STOP', stop['kind'])
        self.assertTrue(stop['incomplete'])

    def test_full_table_changes_not_hidden_by_equal_target(self):
        table = m.parse(row())
        changed = m.parse(row(superopts='rw,private-option'))
        records, _, raw = self.drive([table, changed], [[(37, select.POLLPRI)]])
        self.assertFalse(any(r['kind'] == 'NO_NET_DELTA' for r in records))
        self.assertEqual(1, sum(r['kind'] == 'CHANGED' for r in records))
        self.assertNotIn(b'private-option', raw)

    def test_signal_stop(self):
        records, reader, _ = self.drive([m.parse(row()), m.parse(row(options='ro'))],
                                       [[], [(37, select.POLLPRI)]], stop_after=1)
        self.assertEqual(2, reader.call_count)
        self.assertTrue(any(r['kind'] == 'CHANGED' for r in records))
        self.assertEqual('SIGNAL', records[-1]['reason'])

    def test_stop_during_snapshot_or_recording_drains_second_event(self):
        for stop_at in ('read', 'EVENT', 'CHANGED'):
            with self.subTest(stop_at=stop_at):
                out = io.BytesIO()
                recorder = m.Recorder(out)
                stopping = [False]
                table = m.parse(row())
                tables = [table, m.parse(row(options='ro')), table]
                def read(_fd):
                    value = tables.pop(0)
                    if stop_at == 'read' and len(tables) == 1:
                        stopping[0] = True
                    return value
                write = recorder.write
                def record(kind, **values):
                    result = write(kind, **values)
                    if kind == stop_at:
                        stopping[0] = True
                    return result
                recorder.write = record
                poller = Mock()
                poller.poll.side_effect = [[(37, select.POLLPRI)], [(37, select.POLLERR)], []]
                m.observe(recorder, [], '/repo', 10, lambda: stopping[0],
                          open_fd=lambda *_: 37, close_fd=lambda _: None, read=read,
                          poll_factory=lambda: poller, namespace=lambda: 123)
                records = [json.loads(line) for line in out.getvalue().splitlines()]
                self.assertEqual(2, sum(r['kind'] == 'EVENT' for r in records))
                self.assertEqual(2, sum(r['kind'] == 'CHANGED' for r in records))
                self.assertEqual([0, 0], [c.args[0] for c in poller.poll.call_args_list[1:]])
                self.assertFalse(records[-1]['incomplete'])
                self.assertEqual('SIGNAL', records[-1]['reason'])
                self.assertLessEqual(records[-1]['coverageEnd']['monotonicAfterNs'],
                                     records[-1]['anchor']['monotonicBeforeNs'])

    def test_stop_drain_deadline_output_and_error_are_incomplete(self):
        table = m.parse(row())
        for name, tables, events, duration, count in [
                ('DEADLINE', [table, table], [[(37, select.POLLPRI)]], .25, m.MAX_RECORDS),
                ('OUTPUT_LIMIT', [table, table, table], [[(37, select.POLLPRI)]] * 2, 10, 7),
                ('POLL_UNAVAILABLE', [table, table], [[(37, select.POLLPRI)], [(37, select.POLLHUP)]], 10, m.MAX_RECORDS),
                ('PARSE', [table, table, m.Unavailable('PARSE')], [[(37, select.POLLPRI)]] * 2, 10, m.MAX_RECORDS),
                ('STOP_DRAIN_LIMIT', [table], [[(38, select.POLLPRI)]] * 20, 10, 8)]:
            with self.subTest(reason=name), patch.object(m, 'MAX_RECORDS', count):
                records, _, _ = self.drive(tables, events, duration=duration, stop_after=1)
                self.assertEqual(name, records[-1]['reason'])
                self.assertTrue(records[-1]['incomplete'])
                self.assertIsNone(records[-1]['coverageEnd'])

    def test_stop_drain_time_budget_is_incomplete(self):
        with patch.object(m, 'STOP_SECONDS', .001):
            records, _, _ = self.drive([m.parse(row())], [[]], duration=10, stop_after=1)
        self.assertEqual('STOP_DRAIN_LIMIT', records[-1]['reason'])
        self.assertTrue(records[-1]['incomplete'])

    def test_same_fd_seek_and_bounded_read_to_eof(self):
        data = row()
        with patch.object(m.os, 'lseek') as seek, \
             patch.object(m.os, 'read', side_effect=[data[:19], data[19:], b'', data, b'']) as read:
            self.assertEqual(m.read_table(42), m.read_table(42))
        self.assertEqual([(42, 0, os.SEEK_SET)] * 2, [x.args for x in seek.call_args_list])
        self.assertTrue(all(x.args[0] == 42 and 0 < x.args[1] <= 65536 for x in read.call_args_list))

    def test_table_byte_bound_does_not_read_forever(self):
        with patch.object(m, 'MAX_TABLE', 8), patch.object(m.os, 'lseek'), \
             patch.object(m.os, 'read', return_value=b'x' * 9) as read:
            with self.assertRaisesRegex(m.Unavailable, 'TABLE_BYTES'):
                m.read_table(42)
            read.assert_called_once_with(42, 9)

    def test_escapes_and_canonical_order(self):
        parsed = m.parse(row(target=r'/private/a\040b\011c\012d\134e'))[10]
        self.assertEqual('/private/a b\tc\nd\\e', parsed['target'])
        self.assertEqual('-', m.parse(row(source='-'))[10]['source'])
        self.assertEqual(m.parse(row(options='rw,noexec', optional='master:2 shared:1')),
                         m.parse(row(options='noexec,rw', optional='shared:1 master:2')))

    def test_kernel_root_labels_are_opaque_hashed_values(self):
        for root in ('net:[4026531840]', 'mnt:[4026531841]', '/x//deleted', '/..'):
            with self.subTest(root=root):
                parsed = m.parse(row(root=root, fstype='nsfs'))[10]
                self.assertEqual(root, parsed['root'])
                safe = m.safe_row(parsed, ['/private'], '/repo')
                self.assertNotIn(root.encode(), m.encoded(safe))

    def test_deadline_is_incomplete(self):
        records, _, _ = self.drive([m.parse(row())], [])
        self.assertTrue(records[-1]['incomplete'])

    def test_stop_does_not_drop_reported_event(self):
        records, reader, _ = self.drive([m.parse(row()), m.parse(row(options='ro'))],
                                       [[(37, select.POLLPRI)]], stop_after=1)
        self.assertEqual(2, reader.call_count)
        self.assertEqual('SIGNAL', records[-1]['reason'])
        self.assertTrue(any(r['kind'] == 'CHANGED' for r in records))
        self.assertFalse(records[-1]['incomplete'])

    def test_duplicate_malformed_truncated_and_bounds(self):
        invalid = [row() + row(), row()[:-1], b'', b'garbage\n', row().replace(b' - ', b' '),
                   row(target=r'/foo\777'), row(target=r'/foo\04'), row(target='/foo/../bar'),
                   row(mid=0), row().replace(b'8:1', b'invalid'), row() + b'\n',
                   row().replace(b' - ', b' - - '), row() + b'last truncated row',
                   row(target='/a\x00b'), row(options='rw,,noexec'), row(superopts='rw,'),
                   row(target='/' + 'x' * m.MAX_FIELD), row(optional=' '.join(['a'] * 64))]
        for value in invalid:
            with self.subTest(value=value[:60]), self.assertRaises(m.Unavailable):
                m.parse(value)
        with patch.object(m, 'MAX_ROWS', 1), self.assertRaisesRegex(m.Unavailable, 'TABLE_ROWS'):
            m.parse(row() + row(11))
        with patch.object(m, 'MAX_TABLE', 8), self.assertRaisesRegex(m.Unavailable, 'TABLE_BYTES'):
            m.parse(row())

    def test_redaction_and_closed_classes(self):
        cases = {'/run/credentials/unit': 'credentials', '/run/user/1000/key': 'user-runtime',
                 '/snap/x/1': 'snap', '/run/snapd/ns/x.mnt': 'snap', '/var/lib/docker/x': 'docker',
                 '/proc/sys/fs/binfmt_misc': 'binfmt', '/repo/build/x': 'decomp',
                 '/repo/x': 'workspace', '/proc': 'system', '/surprise/token': 'other',
                 '/private/docker-secrets': 'other', '/etc/not-public': 'other'}
        for target, expected in cases.items():
            output = m.safe_row(m.parse(row(target=target, source='/private-source', root='/private-root',
                                 fstype='private-fstype', optional='shared:1 private-optional'))[10], ['/private'], '/repo')
            self.assertEqual(expected, output['targetClass'])
            self.assertEqual(target if target in m.PUBLIC else None, output['target'])
            raw = m.encoded(output)
            for private in ('/private-source', '/private-root', 'private-fstype', 'private-optional'):
                self.assertNotIn(private.encode(), raw)
            if target not in m.PUBLIC:
                self.assertNotIn(target.encode(), raw)
            self.assertEqual(['shared'], output['propagation'])
            self.assertEqual('OTHER', output['fstype'])

    def test_root_relations_are_component_based(self):
        for target, root, expected in [('/a', '/a', 'AT'), ('/a/b', '/a', 'UNDER'),
                ('/a', '/a/b', 'ANCESTOR'), ('/ab', '/a', 'DISJOINT'), ('/', '/a', 'ANCESTOR'),
                ('/a', '/', 'UNDER'), ('/', '/', 'AT')]:
            self.assertEqual(expected, m.relation(target, root))

    def test_output_count_and_bytes_always_valid_with_reserved_markers(self):
        for payload in ('x', 'x' * 3000, 'x' * m.MAX_OUTPUT):
            out = io.BytesIO()
            recorder = m.Recorder(out)
            recorder.write('START')
            for _ in range(1000):
                if not recorder.write('CHANGED', payload=payload):
                    break
            recorder.write('UNAVAILABLE', reason='IO_UNAVAILABLE')
            recorder.write('STOP', incomplete=True)
            lines = out.getvalue().splitlines()
            self.assertLessEqual(len(lines), m.MAX_RECORDS)
            self.assertLessEqual(len(out.getvalue()), m.MAX_OUTPUT)
            records = [json.loads(x) for x in lines]
            self.assertEqual(['OVERFLOW', 'UNAVAILABLE', 'STOP'], [r['kind'] for r in records[-3:]])

    def test_large_diff_stops_at_output_bound(self):
        table = m.parse(b''.join(row(mid=i) for i in range(1, 1000)))
        records, _, _ = self.drive([m.parse(row()), table], [[(37, select.POLLPRI)]])
        self.assertEqual('OUTPUT_LIMIT', records[-1]['reason'])
        self.assertTrue(records[-1]['incomplete'])
        self.assertEqual(1, sum(r['kind'] == 'OVERFLOW' for r in records))

    def test_anchor_intervals_and_conditional_clock_join(self):
        records, _, _ = self.drive([m.parse(row())], [])
        self.assertEqual('CONDITIONAL_OR_UNKNOWN', records[0]['clocks']['jvmJoin'])
        for r in (records[0], records[-1]):
            a = r['anchor']
            self.assertLessEqual(a['monotonicBeforeNs'], a['monotonicAfterNs'])
            self.assertGreater(a['realtimeNs'], a['monotonicAfterNs'])


class LifecycleControls(unittest.TestCase):
    def setUp(self):
        parent = REPO / 'build/1799-passive-diagnostics/o1-controls'
        parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / '.git').mkdir()
        self.directory = self.root / m.DIRECTORY
        self.directory.parent.mkdir()
        self.directory.mkdir(mode=0o700)
        self.control = dict(token='test', sessionHash=m.digest('session'), workspaceIdentity=m.identity(self.root), uid=os.getuid(),
                            directoryIdentity=m.identity(self.directory), commandHash='expected')
        m.write_json(self.directory / 'control.json', self.control)
        self.owned = dict(pid=444, ticks=123, commandHash='expected', uid=os.getuid(),
                          workspaceIdentity=m.identity(self.root), token='test',
                          controlIdentity=m.identity(self.directory / 'control.json'))
        m.write_json(self.directory / 'owned.json', self.owned)
        self.current = {k: self.owned[k] for k in ('pid', 'ticks', 'commandHash', 'workspaceIdentity', 'uid')}

    def stop(self, current=None, events=None, pid_error=None):
        clock = Clock()
        poller = Mock()
        def poll(ms):
            clock.now += max(.001, ms / 1000)
            return [(77, select.POLLIN)] if events else []
        poller.poll.side_effect = poll
        real_close = os.close
        with patch.object(m.os, 'pidfd_open', return_value=77, side_effect=pid_error, create=True) as opened, \
             patch.object(m, 'process_identity', return_value=current or self.current), \
             patch.object(m.signal, 'pidfd_send_signal', create=True) as send, \
             patch.object(m.os, 'close', side_effect=lambda fd: None if fd == 77 else real_close(fd)) as close, patch.object(m.select, 'poll', return_value=poller), \
             patch.object(m.time, 'monotonic', clock.monotonic):
            try:
                result = m.stop_owned(self.root, self.directory, 'session')
            except m.Unavailable as e:
                result = str(e)
        return result, send, opened, close, clock.now

    def test_owned_stop_uses_pinned_pid_and_term_only(self):
        result, send, opened, close, _ = self.stop(events=True)
        self.assertEqual('EXITED_AFTER_SIGNAL', result)
        opened.assert_called_once_with(444, 0)
        send.assert_called_once_with(77, signal.SIGTERM)
        self.assertEqual(1, sum(c.args == (77,) for c in close.call_args_list))

    def test_pid_reuse_command_workspace_and_uid_mismatch_never_signal(self):
        for field, value in [('ticks', 124), ('commandHash', 'unrelated'), ('workspaceIdentity', [0, 0]),
                             ('uid', -1), ('pid', 445)]:
            current = dict(self.current, **{field: value})
            result, send, _, close, _ = self.stop(current=current)
            self.assertEqual('OWNERSHIP_MISMATCH', result)
            send.assert_not_called()
            self.assertEqual(1, sum(c.args == (77,) for c in close.call_args_list))

    def test_control_replaced_or_token_forged_never_signal(self):
        self.owned['controlIdentity'] = [0, 0]
        (self.directory / 'owned.json').unlink()
        m.write_json(self.directory / 'owned.json', self.owned)
        result, send, opened, _, _ = self.stop()
        self.assertEqual('OWNERSHIP_MISMATCH', result)
        send.assert_not_called()
        opened.assert_not_called()

    def test_wrong_session_and_forged_token_never_signal(self):
        with patch.object(m.os, 'pidfd_open', create=True) as opened, \
             self.assertRaisesRegex(m.Unavailable, 'OWNERSHIP_MISMATCH'):
            m.stop_owned(self.root, self.directory, 'another-session')
        opened.assert_not_called()
        self.owned['token'] = 'forged'
        (self.directory / 'owned.json').unlink()
        m.write_json(self.directory / 'owned.json', self.owned)
        result, send, opened, _, _ = self.stop()
        self.assertEqual('OWNERSHIP_MISMATCH', result)
        send.assert_not_called()
        opened.assert_not_called()

    def test_missing_pidfd_has_no_numerical_pid_signal_fallback(self):
        with patch.object(m.os, 'pidfd_open', side_effect=AttributeError(), create=True), \
             patch.object(m.os, 'kill', side_effect=AssertionError('numerical signal')):
            m.lifecycle_stop(self.root, self.directory, 'session')
        result = json.loads((self.directory / 'lifecycle.json').read_text())
        self.assertEqual('UNAVAILABLE', result['stop'])
        self.assertTrue(result['incomplete'])

    def test_lifecycle_preserves_observation_incomplete_and_survivor(self):
        m.write_json(self.directory / 'start.json', {'status': 'READY'})
        for incomplete, status, reason, expected in [(True, 'ALREADY_EXITED', 'SIGNAL', True),
                (False, 'ALREADY_EXITED', 'SIGNAL', True),
                (False, 'EXITED_AFTER_SIGNAL', 'DEADLINE', True),
                (False, 'SURVIVOR', 'SIGNAL', True),
                (False, 'EXITED_AFTER_SIGNAL', 'SIGNAL', False)]:
            (self.directory / 'observations.jsonl').write_bytes(m.encoded({'kind': 'START'}) +
                m.encoded({'kind': 'STOP', 'incomplete': incomplete, 'reason': reason}))
            with patch.object(m, 'stop_owned', return_value=status):
                m.lifecycle_stop(self.root, self.directory, 'session')
            result = json.loads((self.directory / 'lifecycle.json').read_text())
            self.assertEqual(expected, result['incomplete'])
            self.assertTrue(result['stopObserved'])
            self.assertFalse(result['qualified'])
            (self.directory / 'lifecycle.json').unlink()

    def test_control_replacement_between_validation_and_signal(self):
        changed = dict(self.control, token='replaced')
        with patch.object(m, 'load_owned', side_effect=[(self.control, self.owned['controlIdentity']),
                                                       (changed, self.owned['controlIdentity'])]), \
             patch.object(m.os, 'pidfd_open', return_value=77, create=True), \
             patch.object(m, 'process_identity', return_value=self.current), \
             patch.object(m.signal, 'pidfd_send_signal', create=True) as send, \
             patch.object(m.os, 'close'), self.assertRaisesRegex(m.Unavailable, 'OWNERSHIP_MISMATCH'):
            m.stop_owned(self.root, self.directory, 'session')
        send.assert_not_called()

    def test_survivor_deadline_no_escalation(self):
        result, send, _, _, elapsed = self.stop()
        self.assertEqual('SURVIVOR', result)
        self.assertLessEqual(elapsed, m.STOP_SECONDS + .001)
        send.assert_called_once_with(77, signal.SIGTERM)

    def test_exited_pid_not_signaled(self):
        result, send, _, close, _ = self.stop(pid_error=ProcessLookupError())
        self.assertEqual('ALREADY_EXITED', result)
        send.assert_not_called()
        self.assertFalse(any(c.args == (77,) for c in close.call_args_list))

    def test_absent_start_stop_and_survivor_are_explicit(self):
        for result in ('SURVIVOR', 'UNAVAILABLE', 'ALREADY_EXITED'):
            with patch.object(m, 'stop_owned', return_value=result):
                m.lifecycle_stop(self.root, self.directory, 'session')
            output = json.loads((self.directory / 'lifecycle.json').read_text())
            self.assertEqual('ABSENT_START', output['start'])
            self.assertFalse(output['stopObserved'])
            self.assertTrue(output['incomplete'])
            self.assertFalse(output['qualified'])
            (self.directory / 'lifecycle.json').unlink()

    def test_stop_without_any_start_creates_explicit_incomplete_receipt(self):
        fresh = self.root / 'build/never-started'
        with patch.object(m.os, 'pidfd_open', create=True) as opened:
            m.lifecycle_stop(self.root, fresh, 'session')
        opened.assert_not_called()
        result = json.loads((fresh / 'lifecycle.json').read_text())
        self.assertEqual('ABSENT_START', result['start'])
        self.assertEqual('UNAVAILABLE', result['stop'])
        self.assertFalse(result['stopObserved'])
        self.assertTrue(result['incomplete'])

    def test_start_no_adoption_and_no_pipe_inheritance(self):
        with patch.object(m.subprocess, 'Popen') as launch, self.assertRaises(FileExistsError):
            m.start(self.root, self.directory, 10, [], 'session')
        launch.assert_not_called()
        fresh = self.root / 'build/fresh'
        clock = Clock()
        with patch.object(m.subprocess, 'Popen') as launch, \
             patch.object(m.time, 'monotonic', clock.monotonic), patch.object(m.time, 'sleep', clock.sleep):
            m.start(self.root, fresh, 10, ['/repo'], 'session')
        kwargs = launch.call_args.kwargs
        for name in ('stdin', 'stdout', 'stderr'):
            self.assertEqual(m.subprocess.DEVNULL, kwargs[name])
        self.assertTrue(kwargs['close_fds'])
        self.assertTrue(kwargs['start_new_session'])
        self.assertEqual('START_UNCONFIRMED', json.loads((fresh / 'start.json').read_text())['status'])

    def test_worker_installs_signal_handlers_and_does_not_launch_real_observer(self):
        with patch.object(m, 'process_identity', return_value=self.current), \
             patch.object(m.signal, 'signal') as handlers, patch.object(m, 'observe') as observe:
            (self.directory / 'owned.json').unlink()
            m.run(self.root, self.directory, 'test', 10, [], 'session')
        self.assertEqual([signal.SIGTERM, signal.SIGINT], [x.args[0] for x in handlers.call_args_list])
        self.assertTrue((self.directory / 'owned.json').exists())
        self.assertFalse((self.directory / 'ready.json').exists())
        observe.call_args.kwargs['on_ready']()
        self.assertTrue(json.loads((self.directory / 'ready.json').read_text())['baselineRecorded'])
        stopped = observe.call_args.args[4]
        self.assertFalse(stopped())
        handlers.call_args_list[0].args[1](signal.SIGTERM, None)
        self.assertTrue(stopped())

    def run_baseline(self, outcome):
        (self.directory / 'owned.json').unlink()
        poller = Mock()
        handlers = {}
        def handler(number, callback):
            handlers[number] = callback
        def read(_fd):
            self.assertTrue((self.directory / 'owned.json').exists())
            self.assertFalse((self.directory / 'ready.json').exists())
            poller.register.assert_called_once_with(37, select.POLLPRI | select.POLLERR)
            if outcome == 'failure':
                raise m.Unavailable('PARSE')
            if outcome == 'stopped':
                handlers[signal.SIGTERM](signal.SIGTERM, None)
            return m.parse(row())
        def poll(_ms):
            if outcome == 'success':
                ready = json.loads((self.directory / 'ready.json').read_text())
                self.assertTrue(ready['baselineRecorded'])
                records = (self.directory / 'observations.jsonl').read_text().splitlines()
                self.assertEqual('BASELINE', json.loads(records[-1])['kind'])
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            return []
        poller.poll.side_effect = poll
        observe = m.observe
        def fake_observe(*args, **kwargs):
            return observe(*args, **kwargs, open_fd=lambda *_: 37, close_fd=lambda _: None,
                           read=read, poll_factory=lambda: poller, namespace=lambda: 123)
        with patch.object(m, 'process_identity', return_value=self.current), \
             patch.object(m.signal, 'signal', side_effect=handler), \
             patch.object(m, 'observe', side_effect=fake_observe):
            m.run(self.root, self.directory, 'test', 10, [], 'session')

    def test_worker_ready_only_after_recorded_baseline(self):
        self.run_baseline('success')
        self.assertTrue((self.directory / 'ready.json').exists())

    def test_baseline_failure_is_not_ready_but_owned_stop_remains_authenticated(self):
        self.run_baseline('failure')
        self.assertFalse((self.directory / 'ready.json').exists())
        result, send, opened, _, _ = self.stop(events=True)
        self.assertEqual('EXITED_AFTER_SIGNAL', result)
        opened.assert_called_once_with(444, 0)
        send.assert_called_once_with(77, signal.SIGTERM)

    def test_stop_during_baseline_does_not_publish_ready(self):
        self.run_baseline('stopped')
        self.assertFalse((self.directory / 'ready.json').exists())

    def test_start_waits_for_readiness_not_ownership(self):
        for ready in (False, True):
            fresh = self.root / 'build' / str(ready)
            clock = Clock()
            def launch(*_args, **_kwargs):
                m.write_json(fresh / 'owned.json', self.owned)
            def sleep(seconds):
                clock.sleep(seconds)
                self.assertFalse((fresh / 'start.json').exists())
                if ready and clock.now >= .1 and not (fresh / 'ready.json').exists():
                    m.write_json(fresh / 'ready.json', dict(self.owned, baselineRecorded=True))
            with patch.object(m.subprocess, 'Popen', side_effect=launch), \
                 patch.object(m.time, 'monotonic', clock.monotonic), \
                 patch.object(m.time, 'sleep', sleep):
                m.start(self.root, fresh, 10, [], 'session')
            self.assertEqual('READY' if ready else 'START_UNCONFIRMED',
                             json.loads((fresh / 'start.json').read_text())['status'])

    def test_baseline_reaching_deadline_never_calls_ready(self):
        out = io.BytesIO()
        ready = Mock()
        clock = Clock()
        def read(_fd):
            clock.now = 10
            return m.parse(row())
        with patch.object(m.time, 'monotonic', clock.monotonic):
            m.observe(m.Recorder(out), [], '/repo', 10, lambda: False, on_ready=ready,
                      open_fd=lambda *_: 37, close_fd=lambda _: None,
                      read=read, poll_factory=Mock, namespace=lambda: 123)
        ready.assert_not_called()
        stop = json.loads(out.getvalue().splitlines()[-1])
        self.assertEqual('DEADLINE', stop['reason'])
        self.assertTrue(stop['incomplete'])

    def test_baseline_output_failure_never_calls_ready(self):
        out = io.BytesIO()
        ready = Mock()
        with patch.object(m, 'MAX_RECORDS', 4):
            m.observe(m.Recorder(out), [], '/repo', 10, lambda: False, on_ready=ready,
                      open_fd=lambda *_: 37, close_fd=lambda _: None,
                      read=lambda _: m.parse(row()), poll_factory=Mock, namespace=lambda: 123)
        ready.assert_not_called()
        stop = json.loads(out.getvalue().splitlines()[-1])
        self.assertEqual('OUTPUT_LIMIT', stop['reason'])
        self.assertTrue(stop['incomplete'])

    def test_symlinks_and_oversized_controls_rejected(self):
        link = self.root / 'link'
        link.symlink_to(self.directory / 'control.json')
        with self.assertRaises(OSError):
            m.bounded_file(link)
        with self.assertRaises(m.Unavailable):
            m.bounded_file(self.directory / 'control.json', 1)
        self.directory.chmod(0o755)
        with self.assertRaises(m.Unavailable):
            m.load_owned(self.root, self.directory, 'session')

    def test_proc_stat_parser_handles_spaces_parentheses_without_proc_access(self):
        fields = [b'S'] + [b'0'] * 18 + [b'987']
        data = b'444 (name with ) parentheses) ' + b' '.join(fields)
        with patch.object(m, 'bounded_file', side_effect=[data, b'expected\0']), \
             patch.object(m.os, 'stat', return_value=Mock(st_uid=123, st_mode=stat.S_IFDIR,
                                                        st_dev=1, st_ino=2)):
            actual = m.process_identity(444)
        self.assertEqual(987, actual['ticks'])
        self.assertEqual(m.digest(b'expected\0'), actual['commandHash'])

    def test_process_workspace_identity_follows_kernel_cwd_link(self):
        actual = m.process_identity(os.getpid())
        self.assertEqual(m.identity(Path.cwd()), actual['workspaceIdentity'])
        self.assertNotEqual(m.identity(Path('/proc/self/cwd')), actual['workspaceIdentity'])


if __name__ == '__main__':
    unittest.main()
