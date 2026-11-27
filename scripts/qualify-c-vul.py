#!/usr/bin/env python3
"""Qualify authored C reference repairs, not production reconstruction or equivalence."""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MAX_STREAM_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 15
SYMBOLIZER = None


class QualificationFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class Case:
    number: str
    filename: str
    cwe: str
    kind: str
    diagnostic: str
    expected: str
    arguments: tuple = ()


CASES = (
    Case('01', '01_out_of_bounds_write.c', 'CWE-787', 'asan', r'AddressSanitizer: stack-buffer-overflow[\s\S]*WRITE of size', '[03] Alexandria Stone\n'),
    Case('02', '02_out_of_bounds_read.c', 'CWE-125', 'asan', r'AddressSanitizer: stack-buffer-overflow[\s\S]*READ of size', 'guest: invalid day\n'),
    Case('03', '03_use_after_free.c', 'CWE-416', 'asan', r'AddressSanitizer: heap-use-after-free', 'before = 12\nafter = 13\n'),
    Case('04', '04_double_invalid_free.c', 'CWE-415', 'asan', r'AddressSanitizer: attempting double-free', 'sample\n'),
    Case('05', '05_format_string.c', 'CWE-134', 'compiler', r'format string is not a string literal', '[info] hello %p %n %%\n', ('hello %p %n %%',)),
    Case('06', '06_integer_overflow.c', 'CWE-190', 'unsigned-overflow', r'runtime error: unsigned integer overflow:', 'count = 1073741825\nallocation size overflow\n'),
    Case('07', '07_null_pointer_deref.c', 'CWE-476', 'ubsan', r'runtime error: member access within null pointer of type', 'record not found: 200\n'),
    Case('08', '08_uninitialized_memory.c', 'CWE-908', 'compiler', r"variable 'mode' is (?:used )?uninitialized", 'default\n'),
    Case('09', '09_memory_leak.c', 'CWE-401', 'lsan', r'LeakSanitizer: detected memory leaks[\s\S]*Direct leak of 128 byte', 'guest: sample data\n'),
    Case('10', '10_command_injection.c', 'CWE-78', 'behavior', '', 'hello; printf CVUL_CANARY\n', ('hello; printf CVUL_CANARY',)),
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bounds(file_limit=MAX_STREAM_BYTES + 1):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    resource.setrlimit(resource.RLIMIT_CPU, (max(1, int(TIMEOUT_SECONDS)), max(1, int(TIMEOUT_SECONDS)) + 1))


def run(command, directory, label, compiler=False):
    """Bound files before exec; kill the whole process group on deadline."""
    out = directory / (label + '.stdout')
    err = directory / (label + '.stderr')
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                   'TMPDIR': str(directory), 'LC_ALL': 'C',
                   'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1',
                   'CCACHE_DISABLE': '1', 'CCACHE_DIR': str(directory / 'ccache'),
                   'LSAN_OPTIONS': 'exitcode=23', 'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
    if SYMBOLIZER is not None:
        environment['ASAN_SYMBOLIZER_PATH'] = str(SYMBOLIZER)
    with out.open('wb') as stdout, err.open('wb') as stderr:
        process = subprocess.Popen(command, cwd=directory, env=environment, stdout=stdout,
                                   stderr=stderr, start_new_session=True, preexec_fn=lambda: bounds(64 * 1024 * 1024 if compiler else MAX_STREAM_BYTES + 1))
        try:
            code = process.wait(timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise QualificationFailure(f'{label}: deadline exceeded') from None
    if out.stat().st_size > MAX_STREAM_BYTES or err.stat().st_size > MAX_STREAM_BYTES:
        raise QualificationFailure(f'{label}: output limit exceeded')
    if code < 0 or code in (124, 125, 126, 127, 137, 153):
        raise QualificationFailure(f'{label}: invocation incomplete ({code})')
    return {'argv': [str(arg) for arg in command], 'exitCode': code,
            'stdout': out.read_text(errors='replace'), 'stderr': err.read_text(errors='replace'),
            'stdoutSha256': sha256(out), 'stderrSha256': sha256(err)}


def require_success(result, label):
    if result['exitCode'] != 0:
        raise QualificationFailure(f'{label}: unexpected exit {result["exitCode"]}')


def require_reproduction(case, result):
    if case.kind == 'behavior':
        if result['exitCode'] != 0 or result['stdout'] != 'hello\nCVUL_CANARY' or result['stderr']:
            raise QualificationFailure(f'{case.cwe}: exact shell-canary reproduction absent')
    else:
        if result['exitCode'] == 0 or not re.search(case.diagnostic, result['stderr']):
            raise QualificationFailure(f'{case.cwe}: exact rejecting diagnostic absent')
        if not re.search(re.escape(case.filename) + r':\d+(?::\d+)?', result['stderr']):
            raise QualificationFailure(f'{case.cwe}: diagnostic is not mapped to the fixture source')


def require_repaired(case, result, expected=None):
    if result['exitCode'] != 0 or result['stdout'] != (case.expected if expected is None else expected) or result['stderr']:
        raise QualificationFailure(f'{case.cwe}: corrected regression did not pass')


def compiler_flags(case, corrected):
    flags = ['-std=c11', '-O1' if case.kind == 'lsan' else '-O0', '-g', '-Wall', '-Wextra', '-fno-omit-frame-pointer']
    if corrected:
        flags += ['-Werror', '-Wformat=2', '-Werror=format-security', '-Werror=uninitialized']
    if case.kind == 'compiler':
        flags += ['-Werror=format-security'] if case.number == '05' else ['-Werror=uninitialized', '-Werror=sometimes-uninitialized']
    if case.kind != 'compiler' or corrected:
        sanitizers = 'undefined' if case.kind == 'ubsan' else 'address,undefined'
        if case.kind == 'unsigned-overflow':
            sanitizers += ',unsigned-integer-overflow'
        flags += ['-fsanitize=' + sanitizers, '-fno-sanitize-recover=all']
    return flags


def qualify_case(case, clang, directory, readelf='readelf'):
    original = ROOT / 'benchmarks/fixtures/c-vul/src' / case.filename
    corrected = ROOT / 'benchmarks/fixtures/c-vul-repaired' / case.filename
    case_dir = directory / case.number
    case_dir.mkdir()
    rows = []
    vulnerable_binary = case_dir / 'vulnerable'
    result = run([clang, *compiler_flags(case, False), str(original), '-o', str(vulnerable_binary)], case_dir, 'vulnerable-build', compiler=True)
    rows.append(result)
    if case.kind == 'compiler':
        require_reproduction(case, result)
    else:
        require_success(result, case.cwe + ' vulnerable build')
        result['binarySha256'] = sha256(vulnerable_binary)
        result = run([str(vulnerable_binary), *case.arguments], case_dir, 'vulnerable-reproduction')
        rows.append(result)
        require_reproduction(case, result)
    for build_kind in ('sanitizer', 'hardened'):
        binary = case_dir / ('corrected-' + build_kind)
        flags = compiler_flags(case, True)
        if build_kind == 'hardened':
            flags = [f for f in flags if not f.startswith('-fsanitize=') and f != '-fno-sanitize-recover=all']
            flags += ['-O1', '-D_FORTIFY_SOURCE=2', '-fstack-protector-strong', '-fPIE', '-pie', '-Wl,-z,relro,-z,now']
        build = run([clang, *flags, str(corrected), '-o', str(binary)], case_dir, build_kind + '-build', compiler=True)
        rows.append(build)
        require_success(build, case.cwe + ' corrected ' + build_kind + ' build')
        build['binarySha256'] = sha256(binary)
        if build_kind == 'hardened':
            headers = run([readelf, '-W', '-h', '-l', '-d', str(binary)], case_dir, 'hardening-headers')
            rows.append(headers)
            require_success(headers, case.cwe + ' hardening inspection')
            if not re.search(r'Type:\s+DYN', headers['stdout']) or 'GNU_RELRO' not in headers['stdout'] or not re.search(r'BIND_NOW|FLAGS[^\n]*NOW', headers['stdout']):
                raise QualificationFailure(case.cwe + ': required PIE/RELRO/NOW hardening absent')
        result = run([str(binary), *case.arguments], case_dir, build_kind + '-regression')
        rows.append(result)
        require_repaired(case, result)
        if case.number in ('05', '10'):
            for name, text in [('benign', 'hello'), ('metacharacters', 'literal %s $(printf OTHER) ; | & `echo OTHER`')]:
                result = run([str(binary), text], case_dir, build_kind + '-' + name)
                rows.append(result)
                require_repaired(case, result, ('[info] ' if case.number == '05' else '') + text + '\n')
    return {'case': case.number, 'cwe': case.cwe, 'status': 'PASS', 'evidenceKind': case.kind,
            'originalSource': str(original.relative_to(ROOT)), 'originalSourceSha256': sha256(original),
            'correctedSource': str(corrected.relative_to(ROOT)), 'correctedSourceSha256': sha256(corrected),
            'commands': rows}


def main(arguments=None):
    global SYMBOLIZER
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--output', default='build/c-vul-qualification')
    args = parser.parse_args(arguments)
    directory = (ROOT / args.output).resolve()
    if not directory.is_relative_to(ROOT) or directory == ROOT:
        parser.error('output must be a child directory of the repository')
    directory.mkdir(parents=True, exist_ok=True)
    # Avoid ccache wrappers so the retained executable hash identifies the driver actually invoked.
    candidates = [Path(args.clang)] if '/' in args.clang else [Path(p) / args.clang for p in os.environ.get('PATH', '').split(os.pathsep) if p and 'ccache' not in p]
    clang = next((p.resolve() for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)
    if clang is None:
        parser.error('Clang is required; no compiler fallback or skipped cases are admitted')
    symbolizer = clang.parent / 'llvm-symbolizer'
    if not symbolizer.is_file():
        found = shutil.which('llvm-symbolizer')
        if not found:
            parser.error('llvm-symbolizer is required for exact runtime source mapping')
        symbolizer = Path(found)
    SYMBOLIZER = symbolizer.resolve()
    readelf = shutil.which('readelf')
    if readelf is None:
        parser.error('readelf is required for release hardening inspection')
    readelf = Path(readelf).resolve()
    report = {'symbolizer': str(SYMBOLIZER), 'symbolizerSha256': sha256(SYMBOLIZER), 'schemaVersion': 1, 'scope': 'authored-reference-repair-regression-only',
              'compiler': str(clang), 'compilerSha256': sha256(clang), 'readelf': str(readelf), 'readelfSha256': sha256(readelf),
              'requiredCases': len(CASES), 'cases': [], 'status': 'FAIL'}
    # Fresh per-invocation directories prevent old binaries or logs granting acceptance.
    with tempfile.TemporaryDirectory(prefix='run-', dir=directory) as scratch:
        work = Path(scratch)
        try:
            pinned = run(['git', '-C', str(ROOT), 'ls-files', '-s', 'benchmarks/fixtures/c-vul'], work, 'fixture-gitlink')
            actual = run(['git', '-C', str(ROOT / 'benchmarks/fixtures/c-vul'), 'rev-parse', 'HEAD'], work, 'fixture-revision')
            require_success(pinned, 'pinned fixture revision')
            require_success(actual, 'actual fixture revision')
            fields = pinned['stdout'].split()
            if len(fields) != 4 or fields[0] != '160000' or fields[1] != actual['stdout'].strip():
                raise QualificationFailure('fixture revision differs from the repository gitlink')
            clean = run(['git', '-C', str(ROOT / 'benchmarks/fixtures/c-vul'), 'status', '--porcelain'], work, 'fixture-clean')
            require_success(clean, 'fixture cleanliness')
            if clean['stdout']:
                raise QualificationFailure('fixture submodule contains uncommitted changes')
            report['fixtureRevision'] = fields[1]
            version = run([str(clang), '--version'], work, 'compiler-version')
            require_success(version, 'compiler identity')
            if 'clang version' not in version['stdout']:
                raise QualificationFailure('selected executable does not identify Clang')
            report['compilerVersion'] = version['stdout']
            symbolizer_version = run([str(SYMBOLIZER), '--version'], work, 'symbolizer-version')
            require_success(symbolizer_version, 'symbolizer identity')
            report['symbolizerVersion'] = symbolizer_version['stdout']
            readelf_version = run([str(readelf), '--version'], work, 'readelf-version')
            require_success(readelf_version, 'readelf identity')
            report['readelfVersion'] = readelf_version['stdout']
            for case in CASES:
                report['cases'].append(qualify_case(case, str(clang), work, str(readelf)))
                print(f'{case.number} {case.cwe}: PASS ({case.kind})', flush=True)
            report['status'] = 'PASS'
        except (QualificationFailure, OSError) as failure:
            report['failure'] = str(failure)
        finally:
            # Preserve bounded evidence files even on refusal; all paths stay in the repository.
            retained = directory / 'logs'
            if retained.exists():
                shutil.rmtree(retained)
            shutil.copytree(work, retained, ignore=shutil.ignore_patterns('vulnerable', 'corrected-*'))
            (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if report['status'] != 'PASS':
        print(report.get('failure', 'qualification incomplete'), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
