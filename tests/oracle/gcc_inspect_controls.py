"""Inert shell/metadata boundaries for the inspect producer tests; never runs Docker.

The real shell functions execute with PATH closed and a traced, read-only command gate.
Timeout/env/Docker operations are recorded Python effects, not subprocess execution.
Every Python descendant installs its own audit guard before executing metadata/consumer code.
"""
from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path
import re
import runpy
import shlex
import subprocess
import sys

CLIENT_PIN = "e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13"


def _record(context, kind, **fields):
    with Path(context["log"]).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"kind": kind, **fields}, sort_keys=True) + "\n")


def _guard(context):
    root = Path(context["root"]).resolve()
    repo = Path(context["repo"]).resolve()
    library = Path(sys.base_prefix).resolve()

    def allowed(path, writing=False):
        if isinstance(path, int):
            return
        path = Path(os.fsdecode(path)).resolve()
        if path == root or root in path.parents:
            return
        if not writing and (path == repo or repo in path.parents or library in path.parents):
            return
        raise RuntimeError("control filesystem boundary refused")

    def audit(event, arguments):
        if event.startswith(("socket.", "subprocess.", "_posixsubprocess.", "os.exec", "os.spawn", "os.posix_spawn", "ctypes.")) or event in {"os.system", "os.fork", "os.forkpty", "os.unshare", "os.setns"}:
            raise RuntimeError("control network/process/native boundary refused")
        if event == "open":
            path, mode, flags = arguments
            writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            allowed(path, writing)
        if event in {"os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.truncate"}:
            allowed(arguments[0], True)
        if event in {"os.rename", "os.link", "os.symlink"}:
            allowed(arguments[0], True); allowed(arguments[1], True)
        if event == "os.chdir":
            allowed(arguments[0])

    sys.addaudithook(audit)


def _client(context, argv, environment):
    if not argv or argv[0] != context["client"]:
        raise RuntimeError("unexpected client executable refused before dispatch")
    args = argv[1:]
    _record(context, "client", executable=argv[0], argv=args, environment=environment)
    options = context.get("options", {})
    if "version" in args:
        if options.get("version_exit"):
            sys.stdout.write("partial-version")
            return 41
        raw = base64.b64decode(context["version"])
        if options.get("derive_api", True):
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                value = None
            if isinstance(value, dict) and isinstance(value.get("Client"), dict):
                value["Client"]["ApiVersion"] = environment.get("DOCKER_API_VERSION", "1.55")
                raw = json.dumps(value).encode()
        sys.stdout.buffer.write(raw)
        return 0
    if "inspect" in args:
        for name, encoded in options.get("replace_during_inspect", {}).items():
            if name not in {"image-inspect-api-version.json", "executable-sha256.txt", "source-hashes.txt"}:
                raise RuntimeError("unexpected replacement fixture")
            (Path(context["root"]) / "evidence" / name).write_bytes(base64.b64decode(encoded))
        if options.get("inspect_exit"):
            sys.stdout.write("partial-inspect")
            return 42
        fixture = context["historical"] if environment.get("DOCKER_API_VERSION") == "1.49" else context["current"]
        if options.get("inspect_kind") == "current":
            fixture = context["current"]
        raw = base64.b64decode(options["inspect_bytes"]) if "inspect_bytes" in options else Path(fixture).read_bytes()
        sys.stdout.buffer.write(raw)
        return 0
    if "load" in args or "history" in args:
        return 0
    if "run" in args:
        _record(context, "live-sentinel")
        return 86
    raise RuntimeError("unexpected fake-client operation")


def _environment(context, args):
    environment = dict(context["environment"])
    while args and args[0] == "-u":
        if len(args) < 2:
            raise RuntimeError("malformed env effect")
        environment.pop(args[1], None); args = args[2:]
    while args and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*=.*", args[0], re.S):
        key, value = args[0].split("=", 1); environment[key] = value; args = args[1:]
    return _client(context, args, environment)


def _effect(context, args):
    kind, *args = args
    if kind == "rm":
        if args[:2] != ["-f", "--"]:
            raise RuntimeError("unexpected rm effect")
        for path in args[2:]:
            value = Path(path)
            if value.parent != Path(context["root"]) / "evidence" or value.name not in {"image-inspect.json", "image-inspect-api-version.json", "image-inspect-api-provenance.json"}:
                raise RuntimeError("unexpected removal target")
            value.unlink(missing_ok=True)
        return 0
    if kind == "timeout":
        _record(context, "timeout", argv=args)
        while args and args[0].startswith("--"):
            args = args[1:]
        if not args or not re.fullmatch(r"[0-9]+[sm]", args[0]):
            raise RuntimeError("unexpected timeout effect")
        args = args[1:]
        if args[:2] == ["python3", "scripts/ci-gcc-toolchain-archive.py"]:
            _record(context, "archive-sentinel")
            return 0
        return _environment(context, args[1:]) if args[:1] == ["env"] else _client(context, args, context["environment"])
    if kind == "env":
        _record(context, "unwrapped-env", argv=args)
        return _environment(context, args)
    raise RuntimeError("unexpected effect")


def _python(context, args):
    if not args:
        raise RuntimeError("missing Python control program")
    if args[0] == "-":
        text = sys.stdin.read(131073)
        if len(text) > 131072:
            raise RuntimeError("control code bound exceeded")
        # Failure injection is limited to this short-lived data-only Python process.
        failure = context.get("options", {}).get("sidecar_failure")
        if failure and len(args) == 16:
            original_open = Path.open
            original_replace = Path.replace

            class Writer:
                def __init__(self, stream): self.stream = stream
                def __enter__(self): self.stream.__enter__(); return self
                def __exit__(self, *exc): return self.stream.__exit__(*exc)
                def write(self, value):
                    if failure == "write": raise OSError("injected sidecar write failure")
                    return self.stream.write(value)
                def flush(self):
                    if failure == "flush": raise OSError("injected sidecar flush failure")
                    return self.stream.flush()

            def opened(path, *a, **kw):
                if str(path).endswith("image-inspect-api-provenance.json.tmp"):
                    if failure == "open": raise OSError("injected sidecar open failure")
                    return Writer(original_open(path, *a, **kw))
                return original_open(path, *a, **kw)

            def replaced(path, destination):
                if failure == "replace": raise OSError("injected sidecar rename failure")
                return original_replace(path, destination)

            Path.open = opened
            Path.replace = replaced
        sys.argv = args
        exec(compile(text, "<actual-inspect-metadata>", "exec"), {"__name__": "__main__"})
        return 0
    if args[0] == "-c":
        expected = 'import json,sys; print(json.load(open(sys.argv[1]))[0]["Id"])'
        if len(args) != 3 or args[1] != expected:
            raise RuntimeError("unexpected inline Python program")
        sys.argv = ["-c", args[2]]
        exec(compile(args[1], "<actual-observed-image-id>", "exec"), {"__name__": "__main__"})
        return 0
    path = (Path(context["repo"]) / args[0]).resolve()
    if path != Path(context["repo"]) / "scripts/verify-gcc-toolchain-reproduction.py":
        raise RuntimeError("unexpected Python script")
    _record(context, "strict", argv=args)
    sys.argv = [str(path), *args[1:]]
    runpy.run_path(str(path), run_name="__main__")
    return 0


SHELL_GUARD = r'''
python3() { /usr/bin/python3 -I -B "$CONTROL" python "$CONTEXT" "$@"; }
rm() { /usr/bin/python3 -I -B "$CONTROL" effect "$CONTEXT" rm "$@"; }
timeout() { /usr/bin/python3 -I -B "$CONTROL" effect "$CONTEXT" timeout "$@"; }
env() { /usr/bin/python3 -I -B "$CONTROL" effect "$CONTEXT" env "$@"; }
die() { printf '%s\n' "$*" >&2; exit 1; }
clean_environment() { :; }
preflight_recipe() { :; }
start_buildkit() { :; }
run_solve() { : > "$1"; : > "$2"; }
__gate() {
  case "$1" in
    python3\ *|rm\ *|timeout\ *|env\ *|die\ *|local\ *|read\ *|test\ *|printf\ *|return\ *|exit\ *|cd\ *|:\ *|:) return 0;;
    capture_toolchain_inspect|reproduce|clean_environment|preflight_recipe|start_buildkit|run_solve\ *) return 0;;
    '[['*) return 0;;
    '/usr/bin/python3 -I -B "$CONTROL" python "$CONTEXT" "$@"'|'/usr/bin/python3 -I -B "$CONTROL" effect "$CONTEXT" '* ) return 0;;
  esac
  if [[ "$1" =~ ^(admission|observed)=\$\(.+\)$ ]]; then return 0; fi
  printf '%s\n' 'unregistered nested shell command refused' >&2
  return 1
}
readonly -f python3 rm timeout env die clean_environment preflight_recipe start_buildkit run_solve __gate
readonly CONTROL CONTEXT PATH
set -T
trap '__gate "$BASH_COMMAND" || exit 125' DEBUG
'''


def run_control(root, repo, helper, fixtures, *, options=None, reproduce=False, source=None):
    """Run actual named bodies. All external effects are inert except guarded Python."""
    root = Path(root).resolve(); root.mkdir(parents=True)
    repo = Path(repo).resolve(); fixtures = Path(fixtures).resolve()
    evidence = root / "evidence"; evidence.mkdir()
    client = root / "tools/docker/docker"; client.parent.mkdir(parents=True)
    client.write_text("inert identity marker; never executable\n")
    source = Path(helper).read_text() if source is None else source
    start = source.index("capture_toolchain_inspect() {")
    end = source.index("\nreproduce() {", start)
    bodies = source[start:end]
    if reproduce:
        bodies += source[end:source.index("\nbuild_solve_argv() {", end)]
    options = options or {}
    version = (fixtures / "current-docker-version.json").read_bytes()
    if "version_bytes" in options:
        version = base64.b64decode(options["version_bytes"])
    fingerprint = (CLIENT_PIN + "  " + str(client) + "\n").encode()
    (evidence / "executable-sha256.txt").write_bytes(base64.b64decode(options["fingerprint_bytes"]) if "fingerprint_bytes" in options else fingerprint)
    (evidence / "source-hashes.txt").write_bytes(base64.b64decode(options["source_bytes"]) if "source_bytes" in options else b"source-hash-control\n")
    for name in ["image-inspect.json", "image-inspect-api-version.json", "image-inspect-api-provenance.json"]:
        (evidence / name).write_bytes(b"stale-control")
    if options.get("leftover_tmp"):
        (evidence / "image-inspect-api-provenance.json.tmp").write_bytes(b"earlier-unknown-control")
    environment = {"DOCKER_API_VERSION": "1.55", "DOCKER_HOST": "tcp://hostile.invalid", "DOCKER_CONTEXT": "hostile", "DOCKER_CONFIG": "/hostile/config"}
    context = {"root": str(root), "repo": str(repo), "log": str(root / "calls.jsonl"), "client": str(client),
               "version": base64.b64encode(version).decode(), "historical": str(fixtures / "historical-image-inspect.json"),
               "current": str(fixtures / "current-image-inspect.json"), "environment": environment, "options": options}
    # Data fixtures are copied into the read-only-source root for the Python audit boundary.
    context["historical"] = str(root / "historical.json"); Path(context["historical"]).write_bytes((fixtures / "historical-image-inspect.json").read_bytes())
    context["current"] = str(root / "current.json"); Path(context["current"]).write_bytes((fixtures / "current-image-inspect.json").read_bytes())
    context_path = root / "context.json"; context_path.write_text(json.dumps(context))
    control = Path(__file__).resolve()
    bindings = {"repo": str(repo), "job_root": str(root), "evidence": str(evidence), "tools": str(root / "tools"),
                "volume": str(root / "volume"), "state": str(root / "state"), "docker_bin": str(client),
                "socket": "/owned/service.sock", "bk_socket": "/owned/buildkit.sock", "tag": "decomp-gcc-oracle-toolchain:16.2.0",
                "DOCKER_CONFIG": "/private/docker-config", "GITHUB_ENV": str(root / "GITHUB_ENV"), "GITHUB_RUN_ID": "run-control", "GITHUB_RUN_ATTEMPT": "7",
                "CONTROL": str(control), "CONTEXT": str(context_path), "PATH": "/nonexistent"}
    script = "set -Eeuo pipefail\n" + bodies + "\n" + "\n".join(key + "=" + shlex.quote(value) for key, value in bindings.items()) + "\n" + SHELL_GUARD + "\n" + ("reproduce" if reproduce else "capture_toolchain_inspect")
    (root / "control.sh").write_text(script)
    result = subprocess.run(["/usr/bin/bash", "--noprofile", "--norc", "-c", script], cwd=repo,
                            env={"PATH": "/nonexistent", "TMPDIR": str(root), "LANG": "C.UTF-8", **environment}, capture_output=True, timeout=20)
    records = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()] if (root / "calls.jsonl").exists() else []
    return result, evidence, records


if __name__ == "__main__":
    mode, context_path, *arguments = sys.argv[1:]
    context = json.loads(Path(context_path).read_text())
    _guard(context)
    raise SystemExit(_python(context, arguments) if mode == "python" else _effect(context, arguments))
