"""Authored public minimal models of three withdrawn historical defects.

These functions are deliberately WRONG regression oracles, never production
helpers. They are not byte-identical historical modules. Provenance: evaluator
40dd84136ed4018b916eb5b461ed0ebb97a0701f0b724056d58f683a97d330fa;
freeze aaa3b29b7f35b3b90dd77dfeb8b6fb63504d9092937a366278e6e1bbe93389ca.
Only public process/schema/inventory logic is modeled. No original declaration,
caller, scenario input, expected native output, coordinator or private data is
included. Fixture source is hash-pinned and AST-loaded by static_test_support.
"""


def process_observation(result):
    result = result or {}
    code = result.get('exitCode')
    completed = (all(result.get(key) is True for key in PROOF_FLAGS)
                 and type(code) is int and result.get('rootReaped') is True
                 and result.get('finalAbsenceVerified') is True
                 and result.get('kernelScope', {}).get('finalAbsenceVerified') is True
                 and all(result.get(key) is False for key in
                         ('timedOut', 'outputExceeded', 'infrastructureFailure')))
    # Historical defect: absent captured streams become an asserted empty stream.
    return {'completed': completed,
            'termination': {'kind': 'signal' if code < 0 else 'exit', 'value': abs(code)} if type(code) is int else None,
            'stdoutHex': result.get('stdout', b'').hex(),
            'stderrHex': result.get('stderr', b'').hex()}


def compare_process(expected, result):
    actual = process_observation(result)
    if not actual['completed'] or not expected['completed']:
        return 'unknown', actual
    return ('matched' if all(expected[key] == actual[key] for key in
                             ('termination', 'stdoutHex', 'stderrHex')) else 'mismatched'), actual


def validate_exchange(name, report):
    if name != 'report':
        raise ValueError('minimal fixture models reports only')
    expected = summarize(report['scenarios'], report['admitted'])
    if any(report[key] != value for key, value in expected.items() if key != 'behaviorStatus'):
        raise ValueError('accounting disagreement')
    if report['phases']['behavior']['status'] != expected['behaviorStatus']:
        raise ValueError('behavior disagreement')
    phase = report['phases']['load']
    # Public, authored projection of the old permissive ordinary phase schema.
    # It checks the old shape/status but fails to reserve load for unverified.
    if (set(phase) != {'status', 'reason', 'evidenceSha256'}
            or phase['status'] not in ('passed', 'failed', 'refused', 'unknown', 'not-attempted')
            or type(phase['reason']) is not str
            or (phase['evidenceSha256'] is not None and
                (type(phase['evidenceSha256']) is not str or len(phase['evidenceSha256']) != 64))):
        raise ValueError('invalid historical phase projection')
    return report


def inventory(root, max_files=3, max_bytes=8):
    # Historical defect: materialize and sort the entire population before
    # inspecting the tiny equivalent limits. No real directory is used here.
    files = sorted(path for path in root.rglob('*') if path.is_file())
    result = {}
    total = 0
    for path in files:
        total += path.stat().st_size
        if len(result) >= max_files or total > max_bytes:
            raise ValueError('late historical inventory limit')
        result[str(path.relative_to(root))] = digest(path)
    return result
