"""Cleanup ordering over toy files; no project import, manager or native runtime.

The actual Bash cleanup function runs with a closed DEBUG command gate, empty
PATH and readonly inert boundary functions. At the stage call those functions
freeze its ASCII fixture bytes. The actual Owner.stage_upload and inventory
definitions then consume that snapshot with fake absence/backend boundaries.
This is an ordering control, not evidence of real absence or upload custody.
"""
from __future__ import annotations

import ast
import builtins
import contextlib
import contextvars
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[2]
_ACTIVE = contextvars.ContextVar("gcc_final_evidence_control", default=None)


def _audit(event, args):
    policy = _ACTIVE.get()
    if policy is None:
        return
    if event in ("subprocess.Popen", "os.posix_spawn"):
        if policy.get("argv") == args[1] and args[0] == "/bin/bash":
            return
        raise RuntimeError("unregistered control process")
    if event == "open" and "root" in policy:
        path, mode, flags = args
        if not isinstance(path, (str, bytes, os.PathLike)):
            raise RuntimeError("unregistered inventory descriptor")
        Path(os.fsdecode(path)).resolve().relative_to(policy['root'])
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            raise RuntimeError("inventory writes are inert")
    if "root" in policy and (event == "import" or event in (
            "os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.link", "os.symlink",
            "os.chmod", "os.chown", "os.truncate")):
        raise RuntimeError("unregistered inventory effect: " + event)
    if event.startswith(("socket.", "ctypes.", "os.exec", "os.spawn", "os.posix_spawn",
                         "os.fork", "os.system", "os.unshare", "os.setns")):
        raise RuntimeError("forbidden final-evidence boundary: " + event)


sys.addaudithook(_audit)


@contextlib.contextmanager
def guarded(policy):
    token = _ACTIVE.set(policy)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def source(relative):
    with (ROOT / relative).open("rb") as stream:
        data = stream.read(512 * 1024 + 1)
    if len(data) > 512 * 1024:
        raise AssertionError("control source cap")
    return data.decode("utf-8")


def cleanup_function(builder):
    start = builder.index("cleanup() {\n")
    end = builder.index("\nmain() {", start)
    return builder[start:end]


# Exact commands admitted from cleanup, including its nested substitutions.
# Every path is derived from readonly fixture variables. Unknown commands,
# wrappers, absolute programs and altered redirects fail before execution.
COMMANDS = [
    'cleanup', 'local failure=0',
    '[[ -e "$job_root" ]]',
    '[[ -d "$job_root" && ! -L "$job_root" && -f "$job_root/owner.txt" && ! -L "$job_root/owner.txt" ]]',
    'grep -Fqx "run=$run_id" "$job_root/owner.txt"',
    'grep -Fqx "attempt=$run_attempt" "$job_root/owner.txt"',
    'grep -Fqx "revision=$(git rev-parse HEAD)" "$job_root/owner.txt"',
    'git rev-parse HEAD',
    '[[ -f "$job_root/owner.json" && ! -L "$job_root/owner.json" ]]',
    'owner_call stop --role buildkit', 'owner_call stop --role rootless',
    'failure=1', '(( failure == 0 ))', '(( failure != 0 ))',
    'need_owned_path "$job_root"',
    '[[ ! -f "$state/buildkitd.toml" ]]', '[[ ! -f "$state/docker-daemon.json" ]]',
    'cp "$state/buildkitd.toml" "$evidence/buildkitd.toml"',
    'cp "$state/docker-daemon.json" "$evidence/docker-daemon.json"',
    'find "$evidence" -type f -printf \'%P %s bytes\\n\'',
    'sort > "$evidence/file-inventory.txt"',
    'du -sb "$evidence" > "$evidence/evidence-byte-count.txt"',
    'evidence_bytes=$(cut -f1 "$evidence/evidence-byte-count.txt")',
    'cut -f1 "$evidence/evidence-byte-count.txt"',
    'evidence_files=$(find "$evidence" -type f | wc -l)',
    'find "$evidence" -type f', 'wc -l',
    '(( evidence_bytes > 13958643712 || evidence_files > 128 ))',
    'printf \'evidence budget exceeded bytes=%s files=%s maxBytes=13958643712 maxFiles=128\\n\' "$evidence_bytes" "$evidence_files" > "$evidence/artifact-budget-refusal.txt"',
    '[[ "${PRIMARY_STATUS:-}" == "success" ]]',
    'owner_call stage-upload --success', 'owner_call stage-upload', 'owner_call release',
    "echo 'owned cleanup could not prove process absence' 1>&2",
    "echo 'owned cleanup prerequisites failed; quarantine retained' 1>&2", 'return "$failure"',
    '[[ -L "$socket" || -L "$bk_socket" ]]', '[[ -e "$socket" ]]', '[[ -e "$bk_socket" ]]',
    '[[ -S "$socket" ]]', '[[ -S "$bk_socket" ]]',
    'rm -f -- "$socket"', 'sudo -n rm -f -- "$bk_socket"',
    '[[ -e "$state/buildkit-root" ]]', 'need_owned_path "$state/buildkit-root"',
    'sudo -n rm -rf -- "$state/buildkit-root"',
    'for item in "$state" "$tools" "$volume/docker-config" "$volume/home" "$job_root/r" "$job_root/x"',
    'need_owned_path "$item"', '[[ ! -L "$item" ]]', '[[ ! -e "$item" ]]',
    'rm -rf -- "$item"', 'for item in "$job_root/ambient-client"',
    'rmdir -- "$item"',
    # Only these outer probe assignments are admitted. Their nested executable
    # or wrapper must be rejected by the inherited gate before it can run.
    'gate_probe=$(/unregistered/command)',
    'gate_probe=$(command /unregistered/command)',
    'gate_probe=$(printf x | /unregistered/command)', 'printf x',
]


# No external command exists in these readonly functions. cp/find/du are toy
# data implementations; sudo/rm/rmdir record events and never remove anything.
# The production mount-check heredoc is consumed as text, never evaluated.
HELPERS = r'''
event() { printf '%s\n' "$*" >> "$fixture/events"; }
die() { event "die:$*"; return 1; }
need_owned_path() { [[ "$1" == "$job_root" || "$1" == "$job_root/"* ]]; }
git() { [[ "$*" == 'rev-parse HEAD' ]] || return 96; printf '%s\n' fixture-revision; }
grep() {
  [[ "$1" == -Fqx && "$3" == "$job_root/owner.txt" ]] || return 96
  local line
  while IFS= read -r line; do [[ "$line" != "$2" ]] || return 0; done < "$3"
  return 1
}
copy_text() {
  local contents=''
  IFS= read -r -d '' contents < "$1" || :
  printf '%s' "$contents" > "$2"
}
cp() {
  event "copy:${1##*/}"
  [[ "$fault" != copy ]] || return 1
  [[ "$1" == "$state/"* && "$2" == "$evidence/"* ]] || return 96
  copy_text "$1" "$2"
}
find() {
  [[ "$1" == "$evidence" && "$2" == -type && "$3" == f ]] || return 96
  [[ "$fault" != finalize ]] || return 1
  local f contents
  for f in "$evidence"/* "$evidence"/oci-manifests/* "$evidence"/provenance-statements/*; do
    [[ -f "$f" ]] || continue
    if (( $# == 5 )); then
      contents=''; IFS= read -r -d '' contents < "$f" || :
      printf '%s %s bytes\n' "${f#"$evidence/"}" "${#contents}"
    else printf '%s\n' "$f"; fi
  done
}
sort() {
  local -a rows=()
  local line i j swap
  while IFS= read -r line; do rows+=("$line"); done
  for ((i=0;i<${#rows[@]};i++)); do
    for ((j=i+1;j<${#rows[@]};j++)); do
      if [[ "${rows[i]}" > "${rows[j]}" ]]; then swap=${rows[i]}; rows[i]=${rows[j]}; rows[j]=$swap; fi
    done
  done
  (( ${#rows[@]} == 0 )) || printf '%s\n' "${rows[@]}"
}
du() {
  [[ "$*" == "-sb $evidence" ]] || return 96
  local f contents total=0
  for f in "$evidence"/* "$evidence"/oci-manifests/* "$evidence"/provenance-statements/*; do
    [[ -f "$f" ]] || continue
    contents=''; IFS= read -r -d '' contents < "$f" || :
    total=$((total+${#contents}))
  done
  [[ "$fault" != bytes ]] || total=13958643713
  printf '%s\t%s\n' "$total" "$evidence"
}
cut() {
  [[ "$1" == -f1 && "$2" == "$evidence/evidence-byte-count.txt" ]] || return 96
  local value rest
  IFS=$'\t' read -r value rest < "$2"
  printf '%s\n' "$value"
}
wc() { local line count=0; while IFS= read -r line; do count=$((count+1)); done; printf '%s\n' "$count"; }
owner_call() {
  event "owner:$*"
  case "$*" in
    'stop --role buildkit'|'stop --role rootless') [[ "$fault" != stop ]];;
    'stage-upload --success'|'stage-upload')
      [[ "$fault" != stage ]] || return 1
      local f
      for f in "$evidence"/* "$evidence"/oci-manifests/* "$evidence"/provenance-statements/*; do
        [[ -f "$f" ]] || continue
        copy_text "$f" "$fixture/snapshot/evidence/${f#"$evidence/"}"
      done
      printf '%s\n' absence-proved > "$fixture/stage-phase"
      ;;
    release) :;;
    *) return 96;;
  esac
}
python3() {
  [[ "$*" == "- $job_root" ]] || return 96
  local line
  while IFS= read -r line; do :; done
  event mount-check-inert
}
sudo() { event "physical:$*"; [[ "$fault" != physical ]]; }
rm() { event "physical:rm $*"; }
rmdir() { event "physical:rmdir $*"; }
echo() { event "message:$*"; }
'''


def shell_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def program(body, fixture, fault):
    # Admit the existing exact heredoc only; its body is inert in python3().
    start = body.index('python3 - "$job_root" <<\'PY\'')
    end = body.index('\nPY\n', start) + len('\nPY')
    allowed = COMMANDS + [body[start:end], body[start:end] + "\n"]
    # die messages are compile-time literals at the existing refusal sites.
    allowed += ["die '" + message + "'" for message in (
        'refuse cleanup without a regular owned marker', 'run ownership marker mismatch',
        'attempt ownership marker mismatch', 'source revision ownership marker mismatch',
        'refuse cleanup without the durable service owner', 'refuse linked owned socket path',
        'unexpected rootless endpoint leaf', 'unexpected BuildKit endpoint leaf',
        'refuse linked cleanup path', 'private client config is nonempty; cleanup retained',
        'owned cleanup or evidence budget failed')]
    case = '|'.join(shell_quote(command) for command in allowed)
    gate = '''
_gate() {
  case "${FUNCNAME[1]:-TOP}" in
    event|die|need_owned_path|git|grep|copy_text|cp|find|sort|du|cut|wc|owner_call|python3|sudo|rm|rmdir|echo) return 0;;
  esac
  case "$BASH_COMMAND" in
    COMMAND_CASE) return 0;;
    *) printf 'closed control gate refused: %s\\n' "$BASH_COMMAND" >&2; exit 97;;
  esac
}
'''.replace('COMMAND_CASE', case)
    return ('set -Eeuo pipefail\nshopt -s nullglob\n' + HELPERS + '\n' + body + '\n' + gate + '\n' +
            'readonly fixture=' + shell_quote(str(fixture)) + ' fault=' + shell_quote(fault) + '\n' +
            'readonly job_root="$fixture/job" volume="$fixture/job/v"\n' +
            'readonly state="$volume/s" tools="$volume/tools" evidence="$job_root/evidence"\n' +
            'readonly socket="$job_root/d.sock" bk_socket="$job_root/b.sock"\n' +
            'readonly run_id=fixture run_attempt=1 PRIMARY_STATUS=success\n' +
            'readonly -f _gate cleanup event die need_owned_path git grep copy_text cp find sort du cut wc owner_call python3 sudo rm rmdir echo\n' +
            'set -T\ntrap \'_gate\' DEBUG\ncleanup\n')


class BoundedOS:
    """Only read-only descriptor operations inside this control's snapshot."""
    def __init__(self, root):
        self.root = root
        self.fds = {}

    def __getattr__(self, key):
        if key.startswith('O_'):
            return getattr(os, key)
        raise AssertionError('unregistered OS operation: ' + key)

    def open(self, path, flags, *, dir_fd=None):
        target = Path(path) if dir_fd is None else self.fds[dir_fd] / path
        target = target.resolve()
        target.relative_to(self.root)
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            raise AssertionError('inventory write forbidden')
        fd = os.open(target, flags)
        self.fds[fd] = target
        return fd

    def fstat(self, fd):
        self.fds[fd]
        return os.fstat(fd)

    def scandir(self, fd):
        self.fds[fd]
        return os.scandir(fd)

    def read(self, fd, size):
        self.fds[fd]
        if not 0 <= size <= 1024 * 1024:
            raise AssertionError('inventory read cap')
        return os.read(fd, size)

    def close(self, fd):
        self.fds.pop(fd)
        os.close(fd)


def actual_stage(owner_source, snapshot):
    tree = ast.parse(owner_source)
    names = {'Refusal', '_upload_inventory', '_hash_upload_entry'}
    nodes = [node for node in tree.body if getattr(node, 'name', None) in names]
    owner = next(node for node in tree.body if getattr(node, 'name', None) == 'Owner')
    stage = next(node for node in owner.body if getattr(node, 'name', None) == 'stage_upload')
    assert len(nodes) == 3
    allowed_calls = {
        'getattr', 'os.open', 'os.fstat', 'stat.S_ISDIR', 'Refusal', 'os.scandir',
        'len', 'entry.stat', 'child.stat', 'stat.S_ISREG', '_hash_upload_entry',
        'files.sort', 'opened_dirs.append', 'type', 'reversed', 'os.close', 'hashlib.sha256', 'os.read',
        'min', 'digest.update', 'files.append', 'str', 'digest.hexdigest',
        '(base / relative).relative_to', 'self._manifest',
        'self._all_roles_absence_proved', 'record.get', 'self.backend.domain_empty',
        '_upload_inventory', 'atomic_json',
    }
    observed_calls = {ast.unparse(n.func) for node in nodes + [stage]
                      for n in ast.walk(node) if isinstance(n, ast.Call)}
    assert observed_calls <= allowed_calls, observed_calls - allowed_calls
    bounded = BoundedOS(snapshot)
    results = {}

    def atomic(path, value, *, limit):
        assert path == snapshot / 'control/upload-manifest.json'
        assert len(json.dumps(value).encode()) <= limit
        results.update(value)

    namespace = {'__name__': 'inert_inventory', 'Path': Path, 'os': bounded, 'stat': stat,
                 'hashlib': hashlib, 'MAX_FILES': 128, 'atomic_json': atomic,
                 '__builtins__': {n: getattr(builtins, n) for n in (
                     '__build_class__', 'RuntimeError', 'OSError', 'str', 'list', 'dict',
                     'tuple', 'int', 'bool', 'len', 'min', 'max', 'getattr', 'reversed', 'type')}}
    manifest = {'state': 'absence-proved', 'roles': {
        role: {'receipt': {'inert': True}} for role in ('buildkit', 'rootless')}}
    joins = []

    def domain(role, receipt, timeout):
        joins.append(role)
        assert receipt == {'inert': True} and timeout == 5
        return True

    fake = types.SimpleNamespace(root=snapshot, _manifest=lambda: manifest,
        _all_roles_absence_proved=lambda value: value is manifest,
        backend=types.SimpleNamespace(domain_empty=domain))
    with guarded({'root': snapshot}):
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes + [stage], type_ignores=[])),
                     '<actual-owner-inventory>', 'exec'), namespace)
        namespace['stage_upload'](fake, success=True)
    assert not bounded.fds
    assert joins == ['buildkit', 'rootless']
    return results


class FinalEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = source('scripts/ci-gcc-toolchain-builder.sh')
        cls.owner = source('scripts/ci-gcc-toolchain-owner.py')
        cls.tmp_parent = ROOT / 'build/test-tmp/gcc-final-evidence'
        cls.tmp_parent.mkdir(parents=True, exist_ok=True)

    def scenario(self, *, fault='', body=None, extra_files=0):
        with tempfile.TemporaryDirectory(dir=self.tmp_parent) as directory:
            fixture = Path(directory).resolve()
            job = fixture / 'job'
            for name in ['v/s/buildkit-root', 'v/tools', 'v/docker-config', 'v/home',
                         'r', 'x', 'ambient-client', 'control', 'evidence/oci-manifests',
                         'evidence/provenance-statements']:
                (job / name).mkdir(parents=True, exist_ok=True)
            for name in ['control', 'evidence/oci-manifests', 'evidence/provenance-statements']:
                (fixture / 'snapshot' / name).mkdir(parents=True, exist_ok=True)
            (fixture / 'events').write_text('')
            (job / 'owner.txt').write_text('run=fixture\nattempt=1\nrevision=fixture-revision\n')
            (job / 'owner.json').write_text('{}\n')
            (job / 'v/s/buildkitd.toml').write_text('fixture-buildkit-config\n')
            (job / 'v/s/docker-daemon.json').write_text('{"fixture":true}\n')
            for name, text in {'report.txt': 'fixture evidence\n', 'file-inventory.txt': 'old inventory\n',
                               'evidence-byte-count.txt': '0\told\n', 'oci-manifests/a.json': '{}\n',
                               'provenance-statements/b.json': '{}\n'}.items():
                (job / 'evidence' / name).write_text(text)
            for i in range(extra_files):
                (job / f'evidence/extra-{i:03}.txt').write_text('fixture\n')
            script = program(body or cleanup_function(self.builder), fixture, fault)
            argv = ['/bin/bash', '--noprofile', '--norc', '-c', script]
            with guarded({'argv': argv}):
                run = subprocess.run(argv, input=b'', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env={'PATH': '', 'LC_ALL': 'C'}, timeout=10)
            self.assertNotEqual(run.returncode, 97, run.stderr.decode())
            events = (fixture / 'events').read_text().splitlines()
            final = {'evidence/' + str(f.relative_to(job / 'evidence')): f.read_bytes()
                     for f in (job / 'evidence').rglob('*') if f.is_file()}
            snapshot = fixture / 'snapshot'
            staged = actual_stage(self.owner, snapshot) if (fixture / 'stage-phase').exists() else None
            return run.returncode, events, final, staged

    def test_success_hashes_exact_final_evidence_before_release(self):
        code, events, final, staged = self.scenario()
        self.assertEqual(code, 0)
        self.assertIsNotNone(staged)
        self.assertEqual({entry['path'] for entry in staged['files']}, set(final))
        for entry in staged['files']:
            raw = final[entry['path']]
            self.assertEqual((entry['bytes'], entry['sha256']), (len(raw), hashlib.sha256(raw).hexdigest()))
        self.assertEqual(staged['bytes'], sum(map(len, final.values())))
        self.assertTrue(staged['success'])
        self.assertIn('evidence/buildkitd.toml', final)
        self.assertIn('evidence/docker-daemon.json', final)
        stage = events.index('owner:stage-upload --success')
        release = events.index('owner:release')
        self.assertLess(stage, release)
        self.assertTrue(all(not e.startswith('copy:') for e in events[stage + 1:]))
        self.assertTrue(all(events.index(e) > release for e in events if e.startswith('physical:')))

    def test_failed_prerequisites_never_release_or_physically_delete(self):
        for fault in ['stop', 'copy', 'finalize', 'bytes', 'stage']:
            with self.subTest(fault=fault):
                code, events, final, staged = self.scenario(fault=fault)
                self.assertNotEqual(code, 0)
                self.assertNotIn('owner:release', events)
                self.assertFalse(any(e.startswith('physical:') for e in events))
                if fault != 'stage':
                    self.assertNotIn('owner:stage-upload --success', events)
                self.assertIsNone(staged)

    def test_file_budget_refuses_before_stage_and_release(self):
        code, events, final, staged = self.scenario(extra_files=129)
        self.assertNotEqual(code, 0)
        self.assertNotIn('owner:stage-upload --success', events)
        self.assertNotIn('owner:release', events)
        self.assertFalse(any(e.startswith('physical:') for e in events))
        self.assertIn('evidence/artifact-budget-refusal.txt', final)
        self.assertIsNone(staged)

    def test_physical_failure_remains_failure_after_staging(self):
        code, events, final, staged = self.scenario(fault='physical')
        self.assertNotEqual(code, 0)
        self.assertIn('owner:stage-upload --success', events)
        self.assertIn('owner:release', events)
        self.assertIsNotNone(staged)

    def test_nested_unknown_commands_are_refused_without_execution(self):
        # No unknown command is executed: DEBUG refuses inside substitutions,
        # wrappers and pipelines, and their failure must prevent a successful run.
        for command in ['$(/unregistered/command)', '$(command /unregistered/command)',
                        '$(printf x | /unregistered/command)']:
            with self.subTest(command=command):
                body = cleanup_function(self.builder).replace('local failure=0', 'local failure=0\n  gate_probe=' + command)
                with self.assertRaisesRegex(AssertionError, 'closed control gate refused: (?:command )?/unregistered/command') as caught:
                    self.scenario(body=body)
                self.assertNotIn('gate_probe=', str(caught.exception))
        self.assertIsNone(_ACTIVE.get())


if __name__ == '__main__':
    unittest.main()
