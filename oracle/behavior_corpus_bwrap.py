"""Bubblewrap backend (``bubblewrap-v1``) for the program-agnostic behavior corpus runner.

This is a second, explicitly versioned sandbox backend beside the OCI backend in
``oracle.behavior_corpus``. It reuses that module's strict JSON primitives and evidence conventions
but has its own corpus and report schema, because the OCI schema hard-requires a pinned container
runtime, image and cgroup policy that a stock hosted runner cannot provide.

The identity and limit semantics are those of the issue97 ``bubblewrap-hosted-v1`` profile
(``oracle/llvm/produced_program_bwrap.py``): every sandboxed process runs under
``bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL --clearenv`` with an empty host
environment, ``RLIMIT_CPU``/``RLIMIT_AS``/``RLIMIT_NOFILE``/``RLIMIT_FSIZE``/``RLIMIT_CORE`` limits,
a wall-clock process-group kill and bounded stdout/stderr retention. Each case compiles inside a
sandbox that binds only the executable under test, its declared host tools and their recorded
shared-library closure, then optionally runs one produced static ELF artifact in a second sandbox
whose root contains nothing but that artifact.

Nothing here names a particular program: the executable, its argv, its inputs, the produced
artifact and the expected observations all come from the corpus.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from oracle.behavior_corpus import (
    MAX_ARGUMENTS,
    MAX_CASES,
    MAX_CATEGORIES,
    MAX_CORPUS_BYTES,
    MAX_EXECUTABLE_BYTES,
    MAX_REPORT_BYTES,
    BehaviorCorpusError,
    _absolute_path,
    _array,
    _decode_base64,
    _decode_json,
    _identifier,
    _integer,
    _mode,
    _object,
    _read_regular_snapshot,
    _relative_path,
    _sha256,
    _string,
    _validate_blob,
    _write_exclusive,
)

BACKEND = "bubblewrap-v1"
BASE_ARGV = ["--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"]
LIMIT_BOUNDS = {
    "wallSeconds": (1, 600),
    "cpuSeconds": (1, 600),
    "streamBytes": (1, 16 * 1024 * 1024),
    "artifactBytes": (1, 128 * 1024 * 1024),
    "compileAddressSpaceBytes": (16 * 1024 * 1024, 64 * 1024 ** 3),
    "executeAddressSpaceBytes": (1024 * 1024, 64 * 1024 ** 3),
    "openFiles": (16, 4096),
    "closureLibraries": (1, 256),
    "workspaceEntries": (1, 256),
}
MAX_HOST_TOOLS = 8
MAX_REPETITIONS = 4
MAX_NORMALIZATIONS = 16
MAX_PATTERN_CHARACTERS = 256
MAX_HOST_FILE_BYTES = 256 * 1024 * 1024
MAX_CLOSURE_LISTING_BYTES = 64 * 1024
HOST_PROBE_SECONDS = 10
# Wall time is measured outside the sandbox and includes bwrap setup and output staging.
WALL_SLACK_MILLISECONDS = 1000
_RESERVED_SANDBOX_PATHS = {"/proc", "/dev", "/tmp"}
_ELF_MACHINES = {"x86_64": 62, "amd64": 62, "aarch64": 183, "arm64": 183}
_LD_LIST_LINE = re.compile(r"^\s*(?:\S+\s+=>\s+)?(/\S+)\s+\(0x[0-9a-fA-F]+\)\s*$")
_VERSION_LINE_CHARACTERS = 512


# --------------------------------------------------------------------------------------------
# Shared value helpers
# --------------------------------------------------------------------------------------------


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def blob(payload: bytes) -> dict[str, Any]:
    return {
        "bytes": len(payload),
        "sha256": _sha(payload),
        "base64": base64.b64encode(payload).decode("ascii"),
    }


def _schema_version(value: Any, path: str) -> None:
    if isinstance(value, bool) or value != 1:
        raise BehaviorCorpusError(f"{path} must be the integer 1")


def _unique(values: Sequence[Any], path: str) -> None:
    if len(set(values)) != len(values):
        raise BehaviorCorpusError(f"{path} must not contain duplicates")


def _single_component(value: Any, path: str) -> str:
    text = _relative_path(value, path)
    if "/" in text:
        raise BehaviorCorpusError(f"{path} must be a single workspace entry name")
    return text


def _executable_identity(value: Any, path: str) -> dict[str, Any]:
    record = _object(value, path, {"bytes", "sha256"})
    _integer(record["bytes"], f"{path}.bytes", minimum=1, maximum=MAX_EXECUTABLE_BYTES)
    _sha256(record["sha256"], f"{path}.sha256")
    return record


# --------------------------------------------------------------------------------------------
# Corpus schema
# --------------------------------------------------------------------------------------------


def _validate_limits(value: Any, path: str) -> dict[str, int]:
    record = _object(value, path, LIMIT_BOUNDS)
    for name, (minimum, maximum) in LIMIT_BOUNDS.items():
        _integer(record[name], f"{path}.{name}", minimum=minimum, maximum=maximum)
    return record


def _validate_sandbox(value: Any, path: str) -> dict[str, Any]:
    sandbox = _object(
        value,
        path,
        {
            "backend",
            "profile",
            "baseArgv",
            "executablePath",
            "workspacePath",
            "programPath",
            "executeElfMachine",
            "hostTools",
        },
    )
    if sandbox["backend"] != BACKEND:
        raise BehaviorCorpusError(f"{path}.backend must be {BACKEND!r}")
    _identifier(sandbox["profile"], f"{path}.profile")
    if sandbox["baseArgv"] != BASE_ARGV:
        raise BehaviorCorpusError(f"{path}.baseArgv must be exactly {BASE_ARGV}")
    sandbox_paths = []
    for name in ("executablePath", "workspacePath", "programPath"):
        sandbox_paths.append(_absolute_path(sandbox[name], f"{path}.{name}"))
    _integer(sandbox["executeElfMachine"], f"{path}.executeElfMachine", minimum=1, maximum=0xFFFF)
    tools = _array(sandbox["hostTools"], f"{path}.hostTools", maximum=MAX_HOST_TOOLS)
    names = []
    for index, raw in enumerate(tools):
        label = f"{path}.hostTools[{index}]"
        tool = _object(raw, label, {"name", "hostSearchPath", "sandboxPath"})
        name = _string(tool["name"], f"{label}.name", maximum=128)
        if "/" in name or name in {".", ".."}:
            raise BehaviorCorpusError(f"{label}.name must be a bare command name")
        names.append(name)
        search = _string(tool["hostSearchPath"], f"{label}.hostSearchPath", maximum=4096)
        for index_entry, entry in enumerate(search.split(":")):
            _absolute_path(entry, f"{label}.hostSearchPath[{index_entry}]")
        sandbox_paths.append(_absolute_path(tool["sandboxPath"], f"{label}.sandboxPath"))
    _unique(names, f"{path}.hostTools names")
    _unique(sandbox_paths, f"{path} sandbox paths")
    for sandbox_path in sandbox_paths:
        parts = PurePosixPath(sandbox_path).parts
        if "/" + parts[1] in _RESERVED_SANDBOX_PATHS:
            raise BehaviorCorpusError(f"{path} sandbox path {sandbox_path} is reserved")
    for first in sandbox_paths:
        for second in sandbox_paths:
            if first != second and PurePosixPath(second).is_relative_to(first):
                raise BehaviorCorpusError(f"{path} sandbox paths must not nest")
    return sandbox


def _validate_environment(value: Any, path: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise BehaviorCorpusError(f"{path} must be an object")
    if len(value) > 64:
        raise BehaviorCorpusError(f"{path} exceeds the limit of 64 variables")
    for name, text in value.items():
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
            raise BehaviorCorpusError(f"{path} contains an invalid variable name")
        if name.startswith("LD_"):
            # LD_LIBRARY_PATH is derived from the recorded closure; no other loader control is allowed.
            raise BehaviorCorpusError(f"{path}.{name} is reserved for the backend")
        _string(text, f"{path}.{name}", allow_empty=True, maximum=4096)
    if list(value) != sorted(value):
        raise BehaviorCorpusError(f"{path} keys must be sorted")
    return value


def _validate_normalizations(value: Any, path: str) -> dict[str, tuple[re.Pattern[bytes], bytes]]:
    entries = _array(value, path, maximum=MAX_NORMALIZATIONS)
    result: dict[str, tuple[re.Pattern[bytes], bytes]] = {}
    for index, raw in enumerate(entries):
        label = f"{path}[{index}]"
        entry = _object(raw, label, {"id", "pattern", "replacementBase64"})
        identifier = _identifier(entry["id"], f"{label}.id")
        if identifier in result:
            raise BehaviorCorpusError(f"{path} ids must be unique")
        pattern_text = _string(entry["pattern"], f"{label}.pattern", maximum=MAX_PATTERN_CHARACTERS)
        if not pattern_text.isascii():
            raise BehaviorCorpusError(f"{label}.pattern must be ASCII")
        try:
            pattern = re.compile(pattern_text.encode("ascii"))
        except re.error as error:
            raise BehaviorCorpusError(f"{label}.pattern is not a valid expression") from error
        if pattern.groups or pattern.match(b"") is not None:
            raise BehaviorCorpusError(f"{label}.pattern must not capture or match empty input")
        replacement = _decode_base64(
            entry["replacementBase64"], f"{label}.replacementBase64", maximum=MAX_PATTERN_CHARACTERS
        )
        result[identifier] = (pattern, replacement)
    return result


def normalize_artifact(
    payload: bytes,
    names: Sequence[str],
    normalizations: Mapping[str, tuple[re.Pattern[bytes], bytes]],
    label: str,
) -> bytes:
    """Apply each named rule; every rule must match exactly once so nothing else is masked."""
    result = payload
    for name in names:
        pattern, replacement = normalizations[name]
        result, count = pattern.subn(lambda _match: replacement, result)
        if count != 1:
            raise BehaviorCorpusError(
                f"{label} normalization {name} matched {count} times instead of exactly once"
            )
    return result


def _validate_expected_streams(value: Any, path: str, limits: Mapping[str, int], extra: set[str]) -> dict[str, Any]:
    expected = _object(value, path, {"exitCode", "stdout", "stderr", *extra})
    _integer(expected["exitCode"], f"{path}.exitCode", minimum=0, maximum=255)
    for stream in ("stdout", "stderr"):
        _validate_blob(expected[stream], f"{path}.{stream}", maximum=limits["streamBytes"])
    return expected


def validate_corpus(value: dict[str, Any]) -> dict[str, Any]:
    corpus = _object(
        value,
        "corpus",
        {
            "schemaVersion",
            "scope",
            "id",
            "executable",
            "sandbox",
            "environment",
            "limits",
            "artifactNormalizations",
            "cases",
        },
    )
    _schema_version(corpus["schemaVersion"], "corpus.schemaVersion")
    if corpus["scope"] not in {"fixture", "production"}:
        raise BehaviorCorpusError("corpus.scope must be fixture or production")
    _identifier(corpus["id"], "corpus.id")
    _executable_identity(corpus["executable"], "corpus.executable")
    sandbox = _validate_sandbox(corpus["sandbox"], "corpus.sandbox")
    _validate_environment(corpus["environment"], "corpus.environment")
    limits = _validate_limits(corpus["limits"], "corpus.limits")
    normalizations = _validate_normalizations(
        corpus["artifactNormalizations"], "corpus.artifactNormalizations"
    )
    cases = _array(corpus["cases"], "corpus.cases", nonempty=True, maximum=MAX_CASES)
    _unique([case.get("id") if isinstance(case, dict) else None for case in cases], "corpus.cases ids")
    used_normalizations: set[str] = set()
    for index, raw in enumerate(cases):
        label = f"corpus.cases[{index}]"
        case = _object(
            raw,
            label,
            {"id", "categories", "repetitions", "arguments", "inputs", "expected", "execute"},
        )
        _identifier(case["id"], f"{label}.id")
        categories = _array(case["categories"], f"{label}.categories", nonempty=True, maximum=MAX_CATEGORIES)
        for category_index, category in enumerate(categories):
            _identifier(category, f"{label}.categories[{category_index}]")
        _unique(categories, f"{label}.categories")
        _integer(case["repetitions"], f"{label}.repetitions", minimum=1, maximum=MAX_REPETITIONS)
        arguments = _array(case["arguments"], f"{label}.arguments", maximum=MAX_ARGUMENTS)
        for argument_index, argument in enumerate(arguments):
            _string(argument, f"{label}.arguments[{argument_index}]", allow_empty=True, maximum=4096)
        inputs = _array(case["inputs"], f"{label}.inputs", maximum=limits["workspaceEntries"])
        names: list[str] = []
        total = 0
        for input_index, raw_input in enumerate(inputs):
            input_label = f"{label}.inputs[{input_index}]"
            record, payload = _validate_blob(
                raw_input, input_label, maximum=limits["artifactBytes"], extra_fields=("path", "mode")
            )
            names.append(_single_component(record["path"], f"{input_label}.path"))
            _mode(record["mode"], f"{input_label}.mode")
            total += len(payload)
        if total > limits["artifactBytes"]:
            raise BehaviorCorpusError(f"{label}.inputs exceed the artifact byte limit")
        expected = _validate_expected_streams(
            case["expected"], f"{label}.expected", limits, {"artifacts"}
        )
        artifacts = _array(
            expected["artifacts"], f"{label}.expected.artifacts", maximum=limits["workspaceEntries"]
        )
        artifact_names: list[str] = []
        for artifact_index, raw_artifact in enumerate(artifacts):
            artifact_label = f"{label}.expected.artifacts[{artifact_index}]"
            artifact = _object(raw_artifact, artifact_label, {"path", "mode", "normalizations"})
            artifact_names.append(_single_component(artifact["path"], f"{artifact_label}.path"))
            _mode(artifact["mode"], f"{artifact_label}.mode")
            rules = _array(
                artifact["normalizations"], f"{artifact_label}.normalizations", maximum=MAX_NORMALIZATIONS
            )
            for rule in rules:
                if rule not in normalizations:
                    raise BehaviorCorpusError(f"{artifact_label}.normalizations names an unknown rule")
            _unique(rules, f"{artifact_label}.normalizations")
            used_normalizations.update(rules)
        _unique(names + artifact_names, f"{label} workspace entries")
        if len(names) + len(artifact_names) > limits["workspaceEntries"]:
            raise BehaviorCorpusError(f"{label} exceeds the workspace entry limit")
        if case["execute"] is not None:
            execute = _object(case["execute"], f"{label}.execute", {"artifact", "arguments", "expected"})
            if execute["artifact"] not in artifact_names:
                raise BehaviorCorpusError(f"{label}.execute.artifact must name an expected artifact")
            if int(artifacts[artifact_names.index(execute["artifact"])]["mode"], 8) & 0o111 == 0:
                raise BehaviorCorpusError(f"{label}.execute.artifact must have an executable mode")
            execute_arguments = _array(execute["arguments"], f"{label}.execute.arguments", maximum=MAX_ARGUMENTS)
            for argument_index, argument in enumerate(execute_arguments):
                _string(argument, f"{label}.execute.arguments[{argument_index}]", allow_empty=True, maximum=4096)
            _validate_expected_streams(execute["expected"], f"{label}.execute.expected", limits, set())
    if unused := sorted(set(normalizations) - used_normalizations):
        raise BehaviorCorpusError(f"corpus.artifactNormalizations are unused: {unused}")
    del sandbox
    return corpus


def corpus_json_bytes(corpus: Mapping[str, Any]) -> bytes:
    return (json.dumps(corpus, indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_corpus(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular_snapshot(path, "bubblewrap behavior corpus", MAX_CORPUS_BYTES)
    corpus = validate_corpus(_decode_json(payload, "bubblewrap behavior corpus"))
    if payload != corpus_json_bytes(corpus):
        raise BehaviorCorpusError("bubblewrap behavior corpus must use canonical JSON")
    return corpus, payload


def _replace_atomically(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_corpus(path: Path, corpus: Mapping[str, Any]) -> None:
    payload = corpus_json_bytes(validate_corpus(json.loads(corpus_json_bytes(corpus))))
    if len(payload) > MAX_CORPUS_BYTES:
        raise BehaviorCorpusError("bubblewrap behavior corpus exceeds its output limit")
    _replace_atomically(path, payload)


# --------------------------------------------------------------------------------------------
# Host facts and closures
# --------------------------------------------------------------------------------------------


def parse_ld_list(output: str, maximum: int) -> list[str]:
    """Absolute loader-closure paths from ``ld.so --list``; a missing library is a failure."""
    paths: list[str] = []
    for line in output.splitlines():
        if "not found" in line:
            raise BehaviorCorpusError("a required shared library is not available on this host")
        match = _LD_LIST_LINE.match(line)
        if match and match.group(1) not in paths:
            paths.append(match.group(1))
    if not paths or len(paths) > maximum:
        raise BehaviorCorpusError("shared-library closure is empty or exceeds its bound")
    return paths


def elf_interpreter(binary: Path) -> str:
    with binary.open("rb") as handle:
        header = handle.read(4096)
    if len(header) < 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise BehaviorCorpusError(f"{binary.name} is not an ELF64 little-endian executable")
    phoff, = struct.unpack_from("<Q", header, 32)
    phsize, phcount = struct.unpack_from("<HH", header, 54)
    for index in range(min(phcount, 64)):
        if phsize < 56 or phoff + (index + 1) * phsize > len(header):
            break
        typ, _, offset, _, _, size, _, _ = struct.unpack_from("<IIQQQQQQ", header, phoff + index * phsize)
        if typ == 3:
            if size > 4096:
                break
            with binary.open("rb") as handle:
                handle.seek(offset)
                text = handle.read(size)
            return text.split(b"\0", 1)[0].decode("ascii")
    raise BehaviorCorpusError(f"{binary.name} has no ELF interpreter")


def _closure(binary: Path, maximum: int) -> list[str]:
    interpreter = elf_interpreter(binary)
    result = subprocess.run(
        [interpreter, "--list", os.fspath(binary)],
        env={},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=HOST_PROBE_SECONDS,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) > MAX_CLOSURE_LISTING_BYTES:
        raise BehaviorCorpusError(f"cannot resolve the shared-library closure of {binary.name}")
    paths = parse_ld_list(result.stdout.decode("utf-8", "replace"), maximum)
    if interpreter not in paths:
        paths.append(interpreter)
    return paths


def _file_identity(path: str) -> dict[str, Any]:
    payload = _read_regular_snapshot(
        Path(os.path.realpath(path)), "bound host file", MAX_HOST_FILE_BYTES
    )
    return {"path": path, "bytes": len(payload), "sha256": _sha(payload)}


def _first_line(command: Sequence[str]) -> str:
    result = subprocess.run(
        list(command),
        env={},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=HOST_PROBE_SECONDS,
        check=False,
    )
    lines = result.stdout[:MAX_CLOSURE_LISTING_BYTES].decode("utf-8", "replace").splitlines()
    if result.returncode != 0 or not lines or not lines[0].strip():
        raise BehaviorCorpusError(f"{os.path.basename(command[0])} did not report a version")
    return lines[0].strip()[:_VERSION_LINE_CHARACTERS]


def host_facts(bwrap: Path) -> dict[str, Any]:
    release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            key, _, value = line.partition("=")
            if key in {"ID", "VERSION_ID"}:
                release[key] = value.strip("\"'")
    except OSError:
        pass
    return {
        "kernelRelease": platform.release(),
        "machine": platform.machine(),
        "osId": release.get("ID", ""),
        "osVersionId": release.get("VERSION_ID", ""),
        "bubblewrap": _first_line([os.fspath(bwrap), "--version"]),
    }


def _resolve_host_tools(sandbox: Mapping[str, Any]) -> list[dict[str, Any]]:
    tools = []
    for tool in sandbox["hostTools"]:
        found = shutil.which(tool["name"], path=tool["hostSearchPath"])
        if found is None:
            raise BehaviorCorpusError(f"host tool {tool['name']} is not available")
        real = os.path.realpath(found)
        identity = _file_identity(real)
        tools.append(
            {
                "name": tool["name"],
                "path": found,
                "realPath": real,
                "sandboxPath": tool["sandboxPath"],
                "versionLine": _first_line([real, "--version"]),
                "bytes": identity["bytes"],
                "sha256": identity["sha256"],
            }
        )
    return tools


# --------------------------------------------------------------------------------------------
# Bounded sandboxed processes
# --------------------------------------------------------------------------------------------


def _limit_setter(limits: Mapping[str, int], address_space: int, *, artifacts: bool):
    def apply() -> None:
        os.umask(0o022)
        resource.setrlimit(resource.RLIMIT_CPU, (limits["cpuSeconds"], limits["cpuSeconds"]))
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
        resource.setrlimit(resource.RLIMIT_NOFILE, (limits["openFiles"], limits["openFiles"]))
        size = limits["artifactBytes"] if artifacts else limits["streamBytes"]
        resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return apply


def _run_sandboxed(
    command: Sequence[str],
    scratch: Path,
    limits: Mapping[str, int],
    address_space: int,
    *,
    artifacts: bool,
) -> tuple[int, bytes, bytes, int]:
    """One bounded process: wall-clock group kill, bounded streams, no inherited environment."""
    out_path, err_path = scratch / "stdout", scratch / "stderr"
    for path in (out_path, err_path):
        path.unlink(missing_ok=True)
    started = time.monotonic()
    with out_path.open("xb") as out, err_path.open("xb") as err:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            env={},
            close_fds=True,
            start_new_session=True,
            preexec_fn=_limit_setter(limits, address_space, artifacts=artifacts),
        )
        try:
            code = process.wait(timeout=limits["wallSeconds"])
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise BehaviorCorpusError("sandboxed process exceeded its wall-clock limit") from None
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    elapsed = int((time.monotonic() - started) * 1000)
    streams = []
    for path in (out_path, err_path):
        streams.append(
            _read_regular_snapshot(path, "sandboxed process stream", limits["streamBytes"])
        )
    if code < 0:
        raise BehaviorCorpusError(f"sandboxed process was killed by signal {-code}")
    return code, streams[0], streams[1], elapsed


def _base(bwrap: Path) -> list[str]:
    return [os.fspath(bwrap), *BASE_ARGV]


def _compile_command(
    bwrap: Path,
    corpus: Mapping[str, Any],
    executable: Path,
    tools: Sequence[Mapping[str, Any]],
    libraries: Sequence[str],
    workspace: Path,
    arguments: Sequence[str],
) -> list[str]:
    sandbox = corpus["sandbox"]
    command = _base(bwrap) + ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    command += ["--ro-bind", os.fspath(executable), sandbox["executablePath"]]
    for tool in tools:
        command += ["--ro-bind", tool["realPath"], tool["sandboxPath"]]
    for library in libraries:
        command += ["--ro-bind", library, library]
    command += ["--bind", os.fspath(workspace), sandbox["workspacePath"], "--chdir", sandbox["workspacePath"]]
    for name, value in corpus["environment"].items():
        command += ["--setenv", name, value]
    directories = sorted({os.path.dirname(path) for path in libraries if "/ld-linux" not in path})
    command += ["--setenv", "LD_LIBRARY_PATH", ":".join(directories)]
    return command + [sandbox["executablePath"], *arguments]


def _execute_command(bwrap: Path, corpus: Mapping[str, Any], program: Path, arguments: Sequence[str]) -> list[str]:
    # The produced static ELF is the only file in an otherwise empty root: no /proc, /dev,
    # libraries, network or environment.
    path = corpus["sandbox"]["programPath"]
    return _base(bwrap) + ["--ro-bind", os.fspath(program), path, "--chdir", "/", path, *arguments]


def require_static_elf(payload: bytes, machine: int, label: str) -> None:
    """Bounded header inspection only; the artifact is never loaded or run on the host."""
    if len(payload) < 64 or payload[:7] != b"\x7fELF\x02\x01\x01":
        raise BehaviorCorpusError(f"{label} must be ELF64 little-endian")
    kind, actual_machine, version, entry, phoff = struct.unpack_from("<HHIQQ", payload, 16)
    ehsize, phsize, phcount = struct.unpack_from("<HHH", payload, 52)
    if (kind, actual_machine, version, ehsize, phsize) != (2, machine, 1, 64, 56) or not 1 <= phcount <= 64:
        raise BehaviorCorpusError(f"{label} must be a bounded static ET_EXEC for machine {machine}")
    if phoff < 64 or phoff + phsize * phcount > len(payload):
        raise BehaviorCorpusError(f"{label} program headers exceed its snapshot")
    executable_entry = False
    for index in range(phcount):
        typ, flags, offset, address, _, size, memory, _ = struct.unpack_from(
            "<IIQQQQQQ", payload, phoff + index * phsize
        )
        if typ in (2, 3):
            raise BehaviorCorpusError(f"{label} must have no interpreter or dynamic section")
        if offset + size > len(payload) or size > memory:
            raise BehaviorCorpusError(f"{label} segment exceeds its snapshot")
        if typ == 1 and flags & 1 and address <= entry < address + size:
            executable_entry = True
    if not executable_entry:
        raise BehaviorCorpusError(f"{label} entry is not in file-backed executable bytes")


def _short(payload: bytes) -> str:
    text = payload[:512].decode("utf-8", "replace")
    return repr(text) + ("..." if len(payload) > 512 else "")


def _check_streams(
    label: str, code: int, stdout: bytes, stderr: bytes, expected: Mapping[str, Any]
) -> None:
    if code != expected["exitCode"]:
        raise BehaviorCorpusError(
            f"{label} exited {code}, expected {expected['exitCode']}; stderr={_short(stderr)}"
        )
    for stream, actual in (("stdout", stdout), ("stderr", stderr)):
        if _sha(actual) != expected[stream]["sha256"] or len(actual) != expected[stream]["bytes"]:
            raise BehaviorCorpusError(f"{label} {stream} differs from the corpus: {_short(actual)}")


def _collect_workspace(
    workspace: Path,
    case: Mapping[str, Any],
    limits: Mapping[str, int],
    normalizations: Mapping[str, tuple[re.Pattern[bytes], bytes]],
    label: str,
) -> list[tuple[dict[str, Any], bytes]]:
    expected_artifacts = case["expected"]["artifacts"]
    inputs = {item["path"]: item for item in case["inputs"]}
    expected_names = sorted([*inputs, *(item["path"] for item in expected_artifacts)])
    names = []
    for entry in os.scandir(workspace):
        names.append(entry.name)
        if len(names) > limits["workspaceEntries"]:
            raise BehaviorCorpusError(f"{label} workspace exceeds its entry limit")
    if sorted(names) != expected_names:
        raise BehaviorCorpusError(f"{label} produced an unexpected workspace population: {sorted(names)}")
    for name, item in inputs.items():
        payload = _read_regular_snapshot(workspace / name, f"{label} input {name}", limits["artifactBytes"])
        if _sha(payload) != item["sha256"]:
            raise BehaviorCorpusError(f"{label} modified its input {name}")
    collected = []
    for artifact in expected_artifacts:
        path = workspace / artifact["path"]
        metadata = path.lstat()
        mode = f"0o{stat.S_IMODE(metadata.st_mode):03o}"
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BehaviorCorpusError(f"{label} artifact {artifact['path']} is not a single-link regular file")
        if mode != artifact["mode"]:
            raise BehaviorCorpusError(f"{label} artifact {artifact['path']} has mode {mode}, expected {artifact['mode']}")
        payload = _read_regular_snapshot(path, f"{label} artifact {artifact['path']}", limits["artifactBytes"])
        normalized = normalize_artifact(payload, artifact["normalizations"], normalizations, f"{label} artifact {artifact['path']}")
        collected.append(
            (
                {
                    "path": artifact["path"],
                    "mode": mode,
                    **blob(payload),
                    "normalizations": list(artifact["normalizations"]),
                    "normalizedSha256": _sha(normalized),
                },
                payload,
            )
        )
    return collected


def _observation(code: int, stdout: bytes, stderr: bytes, wall: int) -> dict[str, Any]:
    return {"exitCode": code, "stdout": blob(stdout), "stderr": blob(stderr), "wallMillis": wall}


def run_corpus(
    corpus: dict[str, Any],
    executable_path: Path,
    *,
    corpus_payload: bytes | None = None,
    bwrap: Path,
    temporary_root: Path,
) -> dict[str, Any]:
    """Run every case under bubblewrap and return a report validated against the corpus."""
    validated = validate_corpus(corpus)
    if corpus_payload is None:
        corpus_payload = corpus_json_bytes(validated)
    if _decode_json(corpus_payload, "bubblewrap behavior corpus") != validated or corpus_payload != corpus_json_bytes(validated):
        raise BehaviorCorpusError("corpus payload does not encode the validated corpus canonically")
    limits = validated["limits"]
    normalizations = _validate_normalizations(validated["artifactNormalizations"], "corpus.artifactNormalizations")
    # Only the hashed bytes are trusted; they are restaged 0o755 inside the private root, so the
    # source file's own mode (artifact downloads drop the executable bit) is irrelevant.
    executable_bytes = _read_regular_snapshot(executable_path, "executable under test", MAX_EXECUTABLE_BYTES)
    if {"bytes": len(executable_bytes), "sha256": _sha(executable_bytes)} != validated["executable"]:
        raise BehaviorCorpusError("executable under test does not match the corpus identity")
    bwrap_metadata = bwrap.lstat() if bwrap.is_absolute() else None
    if bwrap_metadata is None or not stat.S_ISREG(os.stat(bwrap).st_mode):
        raise BehaviorCorpusError("bubblewrap must be an absolute path to a regular file")
    temporary_metadata = temporary_root.lstat()
    if not stat.S_ISDIR(temporary_metadata.st_mode):
        raise BehaviorCorpusError("temporary root must be an existing non-symlink directory")
    host = host_facts(bwrap)
    tools = _resolve_host_tools(validated["sandbox"])
    case_reports = []
    with tempfile.TemporaryDirectory(prefix="behavior-bwrap-", dir=temporary_root) as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        staged = root / "executable"
        _write_exclusive(staged, executable_bytes, 0o755)
        os.chmod(staged, 0o755)
        library_set = set(_closure(staged, limits["closureLibraries"]))
        for tool in tools:
            library_set.update(_closure(Path(tool["realPath"]), limits["closureLibraries"]))
        libraries = sorted(library_set)
        library_identities = [_file_identity(path) for path in libraries]
        for case_index, case in enumerate(validated["cases"]):
            runs = []
            for repetition in range(case["repetitions"]):
                label = f"case {case['id']} run {repetition}"
                run_root = root / f"case{case_index}-run{repetition}"
                workspace, scratch = run_root / "work", run_root / "scratch"
                for path in (run_root, workspace, scratch):
                    path.mkdir(mode=0o700)
                for item in case["inputs"]:
                    target = workspace / item["path"]
                    _write_exclusive(target, base64.b64decode(item["base64"]), 0o600)
                    os.chmod(target, int(item["mode"], 8))
                code, stdout, stderr, wall = _run_sandboxed(
                    _compile_command(bwrap, validated, staged, tools, libraries, workspace, case["arguments"]),
                    scratch,
                    limits,
                    limits["compileAddressSpaceBytes"],
                    artifacts=True,
                )
                _check_streams(f"{label} compile", code, stdout, stderr, case["expected"])
                compile_observation = _observation(code, stdout, stderr, wall)
                collected = _collect_workspace(workspace, case, limits, normalizations, label)
                execution = None
                if case["execute"] is not None:
                    execute = case["execute"]
                    payload = next(data for record, data in collected if record["path"] == execute["artifact"])
                    require_static_elf(payload, validated["sandbox"]["executeElfMachine"], f"{label} artifact {execute['artifact']}")
                    program = scratch / "program"
                    _write_exclusive(program, payload, 0o700)
                    os.chmod(program, 0o755)
                    code, stdout, stderr, wall = _run_sandboxed(
                        _execute_command(bwrap, validated, program, execute["arguments"]),
                        scratch,
                        limits,
                        limits["executeAddressSpaceBytes"],
                        artifacts=False,
                    )
                    _check_streams(f"{label} execution", code, stdout, stderr, execute["expected"])
                    execution = _observation(code, stdout, stderr, wall)
                runs.append(
                    {
                        "compile": compile_observation,
                        "artifacts": [record for record, _ in collected],
                        "execution": execution,
                    }
                )
            case_reports.append({"id": case["id"], "categories": list(case["categories"]), "runs": runs})
    categories: dict[str, int] = {}
    for case in validated["cases"]:
        for category in case["categories"]:
            categories[category] = categories.get(category, 0) + 1
    report = {
        "schemaVersion": 1,
        "backend": BACKEND,
        "corpus": {"id": validated["id"], "scope": validated["scope"], "sha256": _sha(corpus_payload)},
        "executable": dict(validated["executable"]),
        "sandbox": validated["sandbox"],
        "environment": validated["environment"],
        "limits": limits,
        "artifactNormalizations": validated["artifactNormalizations"],
        "host": host,
        "hostTools": tools,
        "libraries": library_identities,
        "summary": {"cases": len(case_reports), "passed": len(case_reports), "categories": dict(sorted(categories.items()))},
        "cases": case_reports,
    }
    return validate_corpus_report_pair(validated, corpus_payload, json.loads(json.dumps(report)))


# --------------------------------------------------------------------------------------------
# Report schema and offline replay
# --------------------------------------------------------------------------------------------


def _validate_observation(value: Any, path: str, limits: Mapping[str, int]) -> dict[str, Any]:
    record = _object(value, path, {"exitCode", "stdout", "stderr", "wallMillis"})
    _integer(record["exitCode"], f"{path}.exitCode", minimum=0, maximum=255)
    for stream in ("stdout", "stderr"):
        _validate_blob(record[stream], f"{path}.{stream}", maximum=limits["streamBytes"])
    _integer(
        record["wallMillis"],
        f"{path}.wallMillis",
        minimum=0,
        maximum=limits["wallSeconds"] * 1000 + WALL_SLACK_MILLISECONDS,
    )
    return record


def _validate_file_identity(value: Any, path: str) -> dict[str, Any]:
    record = _object(value, path, {"path", "bytes", "sha256"})
    _absolute_path(record["path"], f"{path}.path")
    _integer(record["bytes"], f"{path}.bytes", minimum=1, maximum=MAX_HOST_FILE_BYTES)
    _sha256(record["sha256"], f"{path}.sha256")
    return record


def validate_report(value: dict[str, Any]) -> dict[str, Any]:
    report = _object(
        value,
        "report",
        {
            "schemaVersion",
            "backend",
            "corpus",
            "executable",
            "sandbox",
            "environment",
            "limits",
            "artifactNormalizations",
            "host",
            "hostTools",
            "libraries",
            "summary",
            "cases",
        },
    )
    _schema_version(report["schemaVersion"], "report.schemaVersion")
    if report["backend"] != BACKEND:
        raise BehaviorCorpusError(f"report.backend must be {BACKEND!r}")
    corpus = _object(report["corpus"], "report.corpus", {"id", "scope", "sha256"})
    _identifier(corpus["id"], "report.corpus.id")
    if corpus["scope"] not in {"fixture", "production"}:
        raise BehaviorCorpusError("report.corpus.scope must be fixture or production")
    _sha256(corpus["sha256"], "report.corpus.sha256")
    _executable_identity(report["executable"], "report.executable")
    sandbox = _validate_sandbox(report["sandbox"], "report.sandbox")
    _validate_environment(report["environment"], "report.environment")
    limits = _validate_limits(report["limits"], "report.limits")
    normalizations = _validate_normalizations(report["artifactNormalizations"], "report.artifactNormalizations")
    host = _object(report["host"], "report.host", {"kernelRelease", "machine", "osId", "osVersionId", "bubblewrap"})
    for name in ("kernelRelease", "machine", "bubblewrap"):
        _string(host[name], f"report.host.{name}", maximum=_VERSION_LINE_CHARACTERS)
    for name in ("osId", "osVersionId"):
        _string(host[name], f"report.host.{name}", allow_empty=True, maximum=_VERSION_LINE_CHARACTERS)
    if _ELF_MACHINES.get(host["machine"]) != sandbox["executeElfMachine"]:
        raise BehaviorCorpusError("report.host.machine does not run the declared execute ELF machine")
    tools = _array(report["hostTools"], "report.hostTools", maximum=MAX_HOST_TOOLS)
    if len(tools) != len(sandbox["hostTools"]):
        raise BehaviorCorpusError("report.hostTools must cover every declared host tool")
    for index, (raw, declared) in enumerate(zip(tools, sandbox["hostTools"])):
        label = f"report.hostTools[{index}]"
        tool = _object(raw, label, {"name", "path", "realPath", "sandboxPath", "versionLine", "bytes", "sha256"})
        if tool["name"] != declared["name"] or tool["sandboxPath"] != declared["sandboxPath"]:
            raise BehaviorCorpusError(f"{label} does not match the declared host tool")
        path = _absolute_path(tool["path"], f"{label}.path")
        if os.path.dirname(path) not in declared["hostSearchPath"].split(":"):
            raise BehaviorCorpusError(f"{label}.path is outside the declared search path")
        _absolute_path(tool["realPath"], f"{label}.realPath")
        _string(tool["versionLine"], f"{label}.versionLine", maximum=_VERSION_LINE_CHARACTERS)
        _integer(tool["bytes"], f"{label}.bytes", minimum=1, maximum=MAX_HOST_FILE_BYTES)
        _sha256(tool["sha256"], f"{label}.sha256")
    libraries = _array(
        report["libraries"],
        "report.libraries",
        nonempty=True,
        maximum=limits["closureLibraries"] * (1 + len(tools)),
    )
    library_paths = [_validate_file_identity(item, f"report.libraries[{index}]")["path"] for index, item in enumerate(libraries)]
    if library_paths != sorted(set(library_paths)):
        raise BehaviorCorpusError("report.libraries must be sorted and unique")
    cases = _array(report["cases"], "report.cases", nonempty=True, maximum=MAX_CASES)
    categories: dict[str, int] = {}
    for index, raw in enumerate(cases):
        label = f"report.cases[{index}]"
        case = _object(raw, label, {"id", "categories", "runs"})
        _identifier(case["id"], f"{label}.id")
        case_categories = _array(case["categories"], f"{label}.categories", nonempty=True, maximum=MAX_CATEGORIES)
        for category in case_categories:
            _identifier(category, f"{label}.categories[]")
            categories[category] = categories.get(category, 0) + 1
        _unique(case_categories, f"{label}.categories")
        runs = _array(case["runs"], f"{label}.runs", nonempty=True, maximum=MAX_REPETITIONS)
        for run_index, raw_run in enumerate(runs):
            run_label = f"{label}.runs[{run_index}]"
            run = _object(raw_run, run_label, {"compile", "artifacts", "execution"})
            _validate_observation(run["compile"], f"{run_label}.compile", limits)
            artifacts = _array(run["artifacts"], f"{run_label}.artifacts", maximum=limits["workspaceEntries"])
            for artifact_index, raw_artifact in enumerate(artifacts):
                artifact_label = f"{run_label}.artifacts[{artifact_index}]"
                record, payload = _validate_blob(
                    raw_artifact,
                    artifact_label,
                    maximum=limits["artifactBytes"],
                    extra_fields=("path", "mode", "normalizations", "normalizedSha256"),
                )
                _single_component(record["path"], f"{artifact_label}.path")
                _mode(record["mode"], f"{artifact_label}.mode")
                rules = _array(record["normalizations"], f"{artifact_label}.normalizations", maximum=MAX_NORMALIZATIONS)
                if any(rule not in normalizations for rule in rules):
                    raise BehaviorCorpusError(f"{artifact_label}.normalizations names an unknown rule")
                normalized = normalize_artifact(payload, rules, normalizations, artifact_label)
                if _sha256(record["normalizedSha256"], f"{artifact_label}.normalizedSha256") != _sha(normalized):
                    raise BehaviorCorpusError(f"{artifact_label}.normalizedSha256 does not match its content")
            if run["execution"] is not None:
                _validate_observation(run["execution"], f"{run_label}.execution", limits)
    _unique([case["id"] for case in cases], "report.cases ids")
    summary = _object(report["summary"], "report.summary", {"cases", "passed", "categories"})
    if summary != {"cases": len(cases), "passed": len(cases), "categories": dict(sorted(categories.items()))}:
        raise BehaviorCorpusError("report.summary does not match the reported cases")
    if list(summary["categories"]) != sorted(summary["categories"]):
        raise BehaviorCorpusError("report.summary.categories must be sorted")
    return report


def _expect_streams(observation: Mapping[str, Any], expected: Mapping[str, Any], label: str) -> None:
    if observation["exitCode"] != expected["exitCode"]:
        raise BehaviorCorpusError(f"{label} exit code differs from the corpus")
    for stream in ("stdout", "stderr"):
        if observation[stream] != expected[stream]:
            raise BehaviorCorpusError(f"{label} {stream} differs from the corpus")


def validate_corpus_report_pair(
    corpus: dict[str, Any], corpus_payload: bytes, report: dict[str, Any]
) -> dict[str, Any]:
    """Offline replay: the report is exactly what this corpus requires, with no host access."""
    validated = validate_corpus(corpus)
    if corpus_payload != corpus_json_bytes(validated) or _decode_json(corpus_payload, "corpus") != validated:
        raise BehaviorCorpusError("corpus payload does not encode the validated corpus canonically")
    checked = validate_report(report)
    if checked["corpus"] != {"id": validated["id"], "scope": validated["scope"], "sha256": _sha(corpus_payload)}:
        raise BehaviorCorpusError("report.corpus does not identify this corpus")
    for field in ("executable", "sandbox", "environment", "limits", "artifactNormalizations"):
        if checked[field] != validated[field]:
            raise BehaviorCorpusError(f"report.{field} differs from the corpus")
    if [case["id"] for case in checked["cases"]] != [case["id"] for case in validated["cases"]]:
        raise BehaviorCorpusError("report.cases do not match the corpus cases in order")
    for expected_case, reported in zip(validated["cases"], checked["cases"]):
        label = f"report case {reported['id']}"
        if reported["categories"] != expected_case["categories"]:
            raise BehaviorCorpusError(f"{label} categories differ from the corpus")
        if len(reported["runs"]) != expected_case["repetitions"]:
            raise BehaviorCorpusError(f"{label} has {len(reported['runs'])} runs, expected {expected_case['repetitions']}")
        normalized_by_run = []
        for run_index, run in enumerate(reported["runs"]):
            run_label = f"{label} run {run_index}"
            expected = expected_case["expected"]
            _expect_streams(run["compile"], expected, f"{run_label} compile")
            shape = [
                {"path": item["path"], "mode": item["mode"], "normalizations": item["normalizations"]}
                for item in run["artifacts"]
            ]
            if shape != expected["artifacts"]:
                raise BehaviorCorpusError(f"{run_label} artifacts differ from the corpus")
            normalized_by_run.append([item["normalizedSha256"] for item in run["artifacts"]])
            execute = expected_case["execute"]
            if execute is None:
                if run["execution"] is not None:
                    raise BehaviorCorpusError(f"{run_label} reports an execution the corpus did not request")
                continue
            if run["execution"] is None:
                raise BehaviorCorpusError(f"{run_label} is missing its execution")
            artifact = next(item for item in run["artifacts"] if item["path"] == execute["artifact"])
            require_static_elf(
                base64.b64decode(artifact["base64"]),
                validated["sandbox"]["executeElfMachine"],
                f"{run_label} artifact {artifact['path']}",
            )
            _expect_streams(run["execution"], execute["expected"], f"{run_label} execution")
        if any(item != normalized_by_run[0] for item in normalized_by_run):
            raise BehaviorCorpusError(f"{label} normalized artifacts differ between repetitions")
    return checked


def report_json_bytes(report: Mapping[str, Any]) -> bytes:
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_report(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular_snapshot(path, "bubblewrap behavior report", MAX_REPORT_BYTES)
    report = validate_report(_decode_json(payload, "bubblewrap behavior report"))
    if payload != report_json_bytes(report):
        raise BehaviorCorpusError("bubblewrap behavior report must use canonical JSON")
    return report, payload


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    payload = report_json_bytes(validate_report(json.loads(report_json_bytes(report))))
    if len(payload) > MAX_REPORT_BYTES:
        raise BehaviorCorpusError("bubblewrap behavior report exceeds its output limit")
    _replace_atomically(path, payload)
