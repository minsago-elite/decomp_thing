#!/usr/bin/env python3
"""Finite flag controls and actual credential-free disabled-userns setup regression.

No DNS/provider/model call. This does not authenticate the compiler closure or
replace the required owned-domain cancellation/deadline/cleanup qualification.
Missing compiler, static libraries, bubblewrap or namespace support is a failure.
All compiler scratch, executables and observations stay inside this checkout.
"""
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'src/test/provider-dns/native/provider_dns_loopback_fixture.c'
CONTROL = SOURCE.with_name('provider_dns_loopback_flags_test.c')
BASE = ROOT / 'build/provider-dns-loopback-controls'


def run(argv, directory, name):
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TMPDIR': str(directory)}
    process = subprocess.Popen(argv, cwd=directory, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    (directory / (name + '.stdout')).write_bytes(stdout)
    (directory / (name + '.stderr')).write_bytes(stderr)
    (directory / (name + '.argv.json')).write_text(json.dumps(list(map(str, argv))) + '\n')
    if process.returncode != 0:
        raise RuntimeError(f'{name} failed with exit {process.returncode}; see {directory}')
    return stdout


def main():
    BASE.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=BASE))
    flags = ['-std=c11', '-O2', '-static', '-Wall', '-Wextra', '-Werror', '-Wl,--build-id=none']
    for name, source in [('flags', CONTROL), ('helper', SOURCE)]:
        run(['/usr/bin/cc', *flags, str(source), '-o', str(directory / name)], directory, 'compile-' + name)
    result = run([str(directory / 'flags')], directory, 'flags')
    if result != b'10 loopback flag controls passed\n':
        raise RuntimeError('flag-control result mismatch')
    parent = []
    for kind in ('net', 'user'):
        identity = Path('/proc/self/ns/' + kind).stat()
        parent.extend((identity.st_dev, identity.st_ino))
    host_flags = Path('/sys/class/net/lo/flags').read_bytes()
    receipt = run(['/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--new-session',
                   '--die-with-parent', '--clearenv', '--disable-userns', '--assert-userns-disabled',
                   '--cap-drop', 'ALL', '--cap-add', 'CAP_NET_ADMIN', '--cap-add', 'CAP_NET_BIND_SERVICE',
                   '--uid', '0', '--gid', '0', '--as-pid-1', '--proc', '/proc', '--dev', '/dev',
                   '--ro-bind', str(directory / 'helper'), '/loopback-helper', '--',
                   '/loopback-helper', *map(str, parent)], directory, 'disabled-userns-setup')
    if len(receipt) != 48 or receipt[:8] != b'PDNSLO01':
        raise RuntimeError('loopback setup receipt framing mismatch')
    net_dev, net_ino, user_dev, user_ino, before, after = struct.unpack('!4Q2I', receipt[8:])
    if ((net_dev, net_ino) == tuple(parent[:2]) or (user_dev, user_ino) == tuple(parent[2:]) or
            not net_ino or not user_ino or before & 9 != 9 or after & 9 != 9):
        raise RuntimeError('disabled-userns setup did not preserve fresh namespaces and UP loopback')
    if Path('/sys/class/net/lo/flags').read_bytes() != host_flags:
        raise RuntimeError('host loopback state changed')
    summary = {'status': 'PASS', 'flagControls': 10, 'disabledUsernsSetupControls': 1,
               'beforeFlags': before, 'afterFlags': after, 'hostLoopbackUnchanged': True,
               'nativeDnsOwnedDomainQualified': False, 'compilerClosureAuthenticated': False}
    (directory / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))
    print('Evidence:', directory)


if __name__ == '__main__':
    main()
