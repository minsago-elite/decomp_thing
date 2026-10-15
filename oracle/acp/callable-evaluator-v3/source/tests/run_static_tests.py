"""Explicit public-only v3 Python gate. Never executes native qualification."""
import contextlib
import importlib.metadata
import json
import os
from pathlib import Path
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from static_test_support import REPOSITORY, SOURCE, static_temp

MODULES = (
    'test_identity_graph', 'test_builtin_types', 'test_contracts',
    'test_probe_isolation', 'test_profile_limits', 'test_link_inputs',
    'test_process_results', 'test_schema_migration',
    'test_runtime_worker_proof', 'test_worker_exec_proof',
    'test_worker_proof_consumers', 'test_execution_source_inventory',
    'test_candidate_leaf_lifecycle',
)


class ForbiddenStaticEffect(AssertionError):
    pass


class NativeDeny:
    """Fail before side effects, and remember swallowed unexpected attempts."""
    def __init__(self):
        self.events = []
        self.attempts = 0
        self.stack = contextlib.ExitStack()

    def refuse(self, event):
        self.attempts += 1
        if len(self.events) < 100:
            self.events.append(event)
        raise ForbiddenStaticEffect('static gate forbids ' + event)

    def audit(self, event, args):
        if (event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn',
                      'os.fork', 'os.forkpty', 'os.kill', 'os.killpg',
                      'resource.setrlimit', 'signal.pthread_kill')
                or event.startswith('socket.')):
            self.refuse(event)

    def install(self):
        sys.addaudithook(self.audit)
        for module, names in (
            (subprocess, ('Popen', 'run', 'call', 'check_call', 'check_output', 'getoutput', 'getstatusoutput')),
            (os, ('system', 'popen', 'fork', 'forkpty', 'posix_spawn', 'posix_spawnp',
                  'execv', 'execve', 'execvp', 'execvpe', 'execl', 'execle', 'execlp', 'execlpe',
                  'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'kill', 'killpg',
                  'pidfd_open', 'setsid', 'setpgid')),
            (resource, ('setrlimit', 'prlimit')),
            (signal, ('pthread_kill', 'pidfd_send_signal')),
        ):
            for name in names:
                if hasattr(module, name):
                    label = module.__name__ + '.' + name
                    self.stack.enter_context(patch.object(module, name,
                        side_effect=lambda *args, _label=label, **kwargs: self.refuse(_label)))
        # Synthetic audit events prove denial without requesting a real process,
        # network connection or resource-policy operation.
        for event in ('subprocess.Popen', 'socket.connect', 'resource.setrlimit'):
            try:
                sys.audit(event)
            except ForbiddenStaticEffect:
                pass
            else:
                raise AssertionError('static audit guard did not refuse ' + event)
        if self.attempts != 3:
            raise AssertionError('static guard self-test accounting')
        self.events.clear()
        self.attempts = 0

    def close(self):
        self.stack.close()
        # The audit hook deliberately remains installed until interpreter exit.


def main():
    guard = NativeDeny()
    guard.install()
    evidence = REPOSITORY / 'build/callable-evaluator-v3-static-ci'
    evidence.mkdir(parents=True, exist_ok=True)
    temporary = static_temp('static-ci/test-tmp')
    tempfile.tempdir = str(temporary)
    os.environ['TMPDIR'] = str(temporary)
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(SOURCE), str(SOURCE / 'tests')]
    counts = {}
    result = None
    try:
        if importlib.metadata.version('fastjsonschema') != '2.22.2':
            raise ValueError('static gate requires fastjsonschema==2.22.2')
        suite = unittest.TestSuite()
        for name in MODULES:
            tests = unittest.defaultTestLoader.loadTestsFromName(name)
            counts[name] = tests.countTestCases()
            if counts[name] == 0:
                raise AssertionError('empty required static suite: ' + name)
            suite.addTests(tests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        passed = result.wasSuccessful() and not result.skipped and guard.attempts == 0
        record = {'status': 'passed' if passed else 'failed',
                  'scope': 'public-source-static-only-no-native-qualification',
                  'modules': counts, 'testsRun': result.testsRun,
                  'failures': len(result.failures), 'errors': len(result.errors),
                  'skips': len(result.skipped), 'forbiddenAttempts': guard.attempts,
                  'forbiddenEvents': guard.events, 'python': sys.version,
                  'fastjsonschema': importlib.metadata.version('fastjsonschema')}
        (evidence / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
        return 0 if passed else 1
    finally:
        guard.close()


if __name__ == '__main__':
    raise SystemExit(main())
