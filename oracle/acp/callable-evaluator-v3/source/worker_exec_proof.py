"""Pure parser for the protected monitor channel, never for worker stdout/stderr.

Caller MUST first authenticate the retained private report FD and the immutable
monitor/parser/schema/dependency bindings. A nonce is correlation, not authority.
No host PID, internal API activity, or machine qualification is inferred here.
"""
from __future__ import annotations

import hashlib
import json
import re

PROTOCOL_VERSION = 1
MAX_RECORD_BYTES = 512
MAX_PROOF_BYTES = 1024
PHASES = ('compiler', 'probe', 'runtime', 'elf-inspection', 'caller-build',
          'helper-build', 'toolchain-inspection', 'unspecified')
ERROR_STAGES = ('arguments', 'protection', 'visibility', 'barrier', 'target',
                'fork', 'trace', 'exec', 'child-fds', 'detach', 'wait', 'channel', 'library')
EXPECTED_KEYS = ('attempt', 'phase', 'reportDevice', 'reportInode', 'reaperDevice',
                 'reaperInode', 'outerPidNsDevice', 'outerPidNsInode',
                 'targetDevice', 'targetInode')
EXEC_KEYS = ('v', 't', 's', 'a', 'p', 'c', 'ed', 'ei', 'od', 'oi', 'w', 'cf',
             'dp', 'rd', 'ri', 'b')
TERM_KEYS = ('v', 't', 's', 'a', 'p', 'c', 'r', 'k', 'n')
ERROR_KEYS = ('v', 't', 's', 'a', 'p', 'g', 'e')
EXEC_WAIT_STATUS = (4 << 16) | (5 << 8) | 0x7f  # Linux PTRACE_EVENT_EXEC/SIGTRAP.
U64 = (1 << 64) - 1
U32 = (1 << 32) - 1


def _int(value, lower=0, upper=U64):
    return type(value) is int and lower <= value <= upper


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate proof key')
        value[key] = item
    return value


def _expected(value):
    if type(value) is not dict or set(value) not in (set(EXPECTED_KEYS), set(EXPECTED_KEYS) | {'library'}):
        raise ValueError('closed expected proof binding required')
    if (type(value['attempt']) is not str or
            re.fullmatch('[0-9a-f]{32}', value['attempt']) is None or
            value['phase'] not in PHASES or type(value['phase']) is not str):
        raise ValueError('invalid attempt/phase binding')
    if any(not _int(value[k]) for k in EXPECTED_KEYS[2:]):
        raise ValueError('invalid physical identity binding')
    if 'library' in value:
        library = value['library']
        if (value['phase'] != 'runtime' or type(library) is not dict or set(library) != {'device','inode','size','sha256','sourcePath'} or
                not all(_int(library[k]) for k in ('device','inode','size')) or
                not 0 < library['size'] <= 16777216 or type(library['sha256']) is not str or
                re.fullmatch('[0-9a-f]{64}', library['sha256']) is None or
                type(library['sourcePath']) is not str or not library['sourcePath'].startswith('/') or
                len(library['sourcePath'].encode()) > 4096 or '\0' in library['sourcePath']):
            raise ValueError('closed sealed library binding required')
    # A report cannot also be the executable being accepted or the bootstrap.
    report = (value['reportDevice'], value['reportInode'])
    if report in [(value['targetDevice'], value['targetInode']),
                  (value['reaperDevice'], value['reaperInode'])]:
        raise ValueError('report/executable identity alias')


def _record(raw):
    if not raw.endswith(b'\n') or not 1 < len(raw) <= MAX_RECORD_BYTES:
        raise ValueError('record byte bound or truncation')
    text = raw[:-1].decode('ascii')
    value = json.loads(text, object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
    if type(value) is not dict:
        raise ValueError('proof record must be object')
    if json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False) != text:
        raise ValueError('noncanonical proof')
    if type(value.get('v')) is not int or value['v'] != 1:
        raise ValueError('protocol version')
    kind = value.get('t')
    keys = {'exec': EXEC_KEYS, 'term': TERM_KEYS, 'error': ERROR_KEYS}.get(kind)
    if keys is None or tuple(value) not in ((keys, keys + ('l',)) if kind == 'exec' else (keys,)):
        raise ValueError('closed ordered proof record required')
    return value


def _binding(record, expected, sequence):
    if (type(record['s']) is not int or record['s'] != sequence or
            record['a'] != expected['attempt'] or record['p'] != expected['phase']):
        raise ValueError('attempt/phase/sequence mismatch')


def _exec(record, expected):
    _binding(record, expected, 1)
    if not _int(record['c'], 1, (1 << 31) - 1):
        raise ValueError('invalid local child PID')
    for key in ('ed', 'ei', 'od', 'oi', 'rd', 'ri'):
        if not _int(record[key]):
            raise ValueError('invalid executable identity')
    if (record['ed'], record['ei'], record['od'], record['oi']) != (
            expected['targetDevice'], expected['targetInode'],
            expected['targetDevice'], expected['targetInode']):
        raise ValueError('target identity mismatch')
    if (record['rd'], record['ri']) != (expected['reaperDevice'], expected['reaperInode']):
        raise ValueError('reaper identity mismatch')
    if (type(record['w']) is not int or record['w'] != EXEC_WAIT_STATUS or
            type(record['cf']) is not int or record['cf'] != 1 or
            type(record['dp']) is not int or record['dp'] != 0):
        raise ValueError('exec event or protection mismatch')
    library = expected.get('library')
    if library is None:
        if 'l' in record: raise ValueError('unexpected library attestation')
    elif (type(record.get('l')) is not list or len(record['l']) != 3 or
          not all(_int(v) for v in record['l']) or
          record['l'] != [library['device'],library['inode'],library['size']]):
        raise ValueError('sealed runtime library identity mismatch')
    barrier = record['b']
    if (type(barrier) is not list or len(barrier) != 6 or
            not all(_int(v) for v in barrier) or barrier[0] != 1 or
            barrier[1] == 0 or not 1 <= barrier[4] <= 100 or
            not 3 <= barrier[5] <= 4):
        raise ValueError('invalid bounded pre-fork barrier binding')
    if tuple(barrier[2:4]) == (expected['outerPidNsDevice'], expected['outerPidNsInode']):
        raise ValueError('fresh PID namespace required')


def _terminal(record, expected, child):
    _binding(record, expected, 2)
    if type(record['c']) is not int or record['c'] != child or not _int(record['r'], 0, U32):
        raise ValueError('terminal child/wait mismatch')
    raw = record['r']
    if record['k'] == 'exit':
        if (not _int(record['n'], 0, 255) or raw != record['n'] << 8):
            raise ValueError('invalid exited wait word')
    elif record['k'] == 'signal':
        # Only the core flag may accompany the native terminal signal.
        if (not _int(record['n'], 1, 64) or raw & ~0xff or
                raw & 0x7f != record['n']):
            raise ValueError('invalid signaled wait word')
    else:
        raise ValueError('invalid terminal kind')
    return {'kind': record['k'], 'value': record['n'], 'rawWaitStatus': raw}


def _error(record, expected, sequence):
    _binding(record, expected, sequence)
    if record['g'] not in ERROR_STAGES or type(record['g']) is not str:
        raise ValueError('unknown monitor stage')
    if record['e'] is not None and not _int(record['e'], 1, (1 << 31) - 1):
        raise ValueError('invalid reported errno')
    return 'monitor-error:' + record['g']


def parse_proof(raw: bytes, expected: dict) -> dict:
    """Validate at most two records. Invalid expectations are programmer errors.

    Malformed/missing report data returns unknown; a valid authenticated first exec
    record is retained if only the later terminal is absent/bad. There is never a
    wrapper exit fallback. Report FD identity and immutable input authentication
    are the caller's precondition, not asserted by this pure byte parser.
    """
    _expected(expected)
    result = {'status': 'unknown', 'workerExecVerified': False,
              'workerTerminationVerified': False, 'workerTermination': None,
              'exitCode': None, 'proofSha256': None, 'reason': 'missing-proof'}
    if type(raw) is not bytes:
        result['reason'] = 'proof-must-be-bytes'
        return result
    if len(raw) > MAX_PROOF_BYTES:
        result['reason'] = 'proof-byte-bound'
        return result
    result['proofSha256'] = hashlib.sha256(raw).hexdigest()
    if not raw:
        return result
    # bounded split; reject unexpected record count before trusting any record.
    records = raw.splitlines(keepends=True)
    if not 1 <= len(records) <= 2:
        result['reason'] = 'proof-record-count'
        return result
    try:
        first = _record(records[0])
        if first['t'] == 'error':
            result['reason'] = _error(first, expected, 1)
            if len(records) != 1:
                result['reason'] = 'records-after-error'
            return result
        if first['t'] != 'exec':
            raise ValueError('exec record required first')
        _exec(first, expected)
        result['workerExecVerified'] = True
        if len(records) == 1:
            result['reason'] = 'missing-terminal'
            return result
        second = _record(records[1])
        if second['t'] == 'error':
            result['reason'] = _error(second, expected, 2)
            return result
        if second['t'] != 'term':
            raise ValueError('terminal record required second')
        termination = _terminal(second, expected, first['c'])
        result.update(status='verified', workerTerminationVerified=True,
                      workerTermination=termination,
                      exitCode=(termination['value'] if termination['kind'] == 'exit'
                                else -termination['value']), reason=None)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        result['reason'] = 'invalid-proof-record'
    return result
