"""Issue97 supplemental produced-program observation on a stock bubblewrap host.

This is a NEW, separately pinned reference profile. It does not reuse, relabel or replace the
historical OCI profile in ``produced_program.py`` (pinned Docker client and image, which cannot be
re-acquired). It runs the same locked Clang on the same reviewed ``_start`` fixture and then runs the
produced static ELF, using only bubblewrap, ``RLIMIT_*`` limits and a wall-clock kill, so it needs no
provisioned container runtime, image, subordinate IDs or cgroup delegation. It grants no candidate,
Kotlin-runtime, effectiveness or release authority.
"""
from __future__ import annotations

import argparse
import base64
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
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from oracle.behavior_corpus import BehaviorCorpusError, _decode_json, _read_regular_snapshot, _write_exclusive
from oracle.llvm.produced_program import (
    ARGUMENTS, CLANG, MANIFEST_SHA256, MARKER, MAX_EVIDENCE_BYTES, PROFILE, SOURCE_SHA256, _locked_inputs,
    _require_static_amd64, _sha,
)

PROFILE_ID = "bubblewrap-hosted-v1"
AUTHORITY = {"kind": "python-compatibility-reference-observation", "supplementalBubblewrapProfile": True,
             "historicalOciProfileReused": False, "candidateExecuted": False,
             "kotlinRuntimeQualified": False, "effectivenessQualified": False, "releaseQualified": False}
# Per-target limits mirror the historical profile's wall/CPU/stream/artifact caps; memory and process
# caps are expressed as RLIMIT_AS / bwrap pid-namespace teardown because no cgroup delegation is used.
LIMITS = {"wallSeconds": 10, "cpuSeconds": 10, "streamBytes": 1024 * 1024, "artifactBytes": 16 * 1024 * 1024,
          "compileAddressSpaceBytes": 4 * 1024 ** 3, "executeAddressSpaceBytes": 64 * 1024 * 1024,
          "openFiles": 128, "closureLibraries": 64, "workspaceEntries": 2}
EXPECTED_EXIT = 42
# The sandbox deliberately contains no GCC installation for the driver to probe, so Clang's only diagnostic is
# this warning; the reviewed argv is pinned and is not changed to suppress it.
COMPILE_STDERR = b"clang: warning: argument unused during compilation: '-no-pie' [-Wunused-command-line-argument]\n"
# Clang names its temporary object with random hex and GNU ld records that name once in .strtab (a FILE symbol),
# so two otherwise identical links differ in exactly those six characters. The reviewed argv is pinned and cannot
# avoid the intermediate object, so the contract normalizes that single name explicitly and nothing else.
TEMP_OBJECT = re.compile(rb"start-[0-9a-f]{6}\.o\x00")
TEMP_OBJECT_NORMAL = b"start-XXXXXX.o\x00"
LD_LINE = re.compile(r"^\s*(?:\S+\s+=>\s+)?(/\S+)\s+\(0x[0-9a-fA-F]+\)\s*$")
_RUN_FIELDS = {"compile", "artifact", "execution"}
_RESULT_FIELDS = {"exitCode", "stdout", "stderr", "wallMillis"}
_BLOB_FIELDS = {"bytes", "sha256", "base64"}


def normalize_program(payload: bytes) -> bytes:
    """Replace the single random temporary-object name; any other population is refused."""
    if len(TEMP_OBJECT.findall(payload)) != 1:
        raise BehaviorCorpusError("produced program must contain exactly one temporary object name")
    return TEMP_OBJECT.sub(TEMP_OBJECT_NORMAL, payload)


def _blob(payload: bytes) -> dict[str, Any]:
    return {"bytes": len(payload), "sha256": _sha(payload), "base64": base64.b64encode(payload).decode("ascii")}


def _check_blob(value: Any, label: str, maximum: int) -> bytes:
    if not isinstance(value, dict) or set(value) != _BLOB_FIELDS:
        raise BehaviorCorpusError(f"{label} blob fields changed")
    size, encoded = value["bytes"], value["base64"]
    if type(size) is not int or not 0 <= size <= maximum or not isinstance(encoded, str):
        raise BehaviorCorpusError(f"{label} blob size is malformed or exceeds its bound")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise BehaviorCorpusError(f"{label} blob is not canonical base64") from error
    if len(payload) != size or _sha(payload) != value["sha256"] or base64.b64encode(payload).decode("ascii") != encoded:
        raise BehaviorCorpusError(f"{label} blob identity mismatch")
    return payload


def parse_ld_list(output: str) -> list[str]:
    """Absolute loader-closure paths from ``ld.so --list``; a missing library is a failure."""
    paths: list[str] = []
    for line in output.splitlines():
        if "not found" in line:
            raise BehaviorCorpusError("a required shared library is not available on this host")
        match = LD_LINE.match(line)
        if match and match.group(1) not in paths:
            paths.append(match.group(1))
    if not paths or len(paths) > LIMITS["closureLibraries"]:
        raise BehaviorCorpusError("shared-library closure is empty or exceeds its bound")
    return paths


def _interpreter(binary: Path) -> str:
    with binary.open("rb") as handle:
        header = handle.read(4096)
    if len(header) < 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise BehaviorCorpusError(f"{binary.name} is not an ELF64 little-endian executable")
    phoff, = struct.unpack_from("<Q", header, 32)
    phsize, phcount = struct.unpack_from("<HH", header, 54)
    for index in range(min(phcount, 64)):
        typ, _, offset, _, _, size, _, _ = struct.unpack_from("<IIQQQQQQ", header, phoff + index * phsize) \
            if phoff + (index + 1) * phsize <= len(header) else (0,) * 8
        if typ == 3:
            with binary.open("rb") as handle:
                handle.seek(offset)
                text = handle.read(size)
            return text.split(b"\0", 1)[0].decode("ascii")
    raise BehaviorCorpusError(f"{binary.name} has no ELF interpreter")


def _closure(binary: Path) -> list[str]:
    interpreter = _interpreter(binary)
    result = subprocess.run([interpreter, "--list", os.fspath(binary)], env={}, capture_output=True, timeout=10, check=False)
    if result.returncode != 0 or len(result.stdout) > 64 * 1024:
        raise BehaviorCorpusError(f"cannot resolve the shared-library closure of {binary.name}")
    paths = parse_ld_list(result.stdout.decode("utf-8", "replace"))
    if interpreter not in paths:
        paths.append(interpreter)
    return paths


def _file_identity(path: str) -> dict[str, Any]:
    real = Path(os.path.realpath(path))
    payload = _read_regular_snapshot(real, "bound host file", 256 * 1024 * 1024)
    return {"path": path, "bytes": len(payload), "sha256": _sha(payload)}


def _limit_setter(address_space: int, *, artifacts: bool):
    def apply() -> None:
        os.umask(0o022)
        resource.setrlimit(resource.RLIMIT_CPU, (LIMITS["cpuSeconds"], LIMITS["cpuSeconds"]))
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
        resource.setrlimit(resource.RLIMIT_NOFILE, (LIMITS["openFiles"], LIMITS["openFiles"]))
        size = LIMITS["artifactBytes"] if artifacts else LIMITS["streamBytes"]
        resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def _run(command: Sequence[str], scratch: Path, address_space: int, *, artifacts: bool) -> dict[str, Any]:
    """One bounded sandboxed process: wall-clock kill, bounded streams, no inherited environment."""
    out_path, err_path = scratch / "stdout", scratch / "stderr"
    started = time.monotonic()
    with out_path.open("wb") as out, err_path.open("wb") as err:
        process = subprocess.Popen(list(command), stdin=subprocess.DEVNULL, stdout=out, stderr=err, env={},
                                   close_fds=True, start_new_session=True,
                                   preexec_fn=_limit_setter(address_space, artifacts=artifacts))
        try:
            code = process.wait(timeout=LIMITS["wallSeconds"])
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise BehaviorCorpusError("sandboxed process exceeded its wall-clock limit")
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    elapsed = int((time.monotonic() - started) * 1000)
    streams = []
    for path in (out_path, err_path):
        size = path.stat().st_size
        if size > LIMITS["streamBytes"]:
            raise BehaviorCorpusError("sandboxed process stream exceeded its retention bound")
        streams.append(path.read_bytes())
    return {"exitCode": code, "stdout": _blob(streams[0]), "stderr": _blob(streams[1]), "wallMillis": elapsed}


def _base(bwrap: str) -> list[str]:
    return [bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"]


def _compile(bwrap: str, clang: Path, linker: str, libraries: Sequence[str], workspace: Path, scratch: Path) -> dict[str, Any]:
    command = _base(bwrap) + ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                              "--ro-bind", os.fspath(clang), "/oracle/clang", "--ro-bind", linker, "/usr/bin/ld"]
    for library in libraries:
        command += ["--ro-bind", library, library]
    directories = sorted({os.path.dirname(path) for path in libraries if "/ld-linux" not in path})
    command += ["--bind", os.fspath(workspace), "/work", "--chdir", "/work", "--setenv", "PATH", "/usr/bin",
                "--setenv", "LC_ALL", "C", "--setenv", "TMPDIR", "/tmp", "--setenv", "LD_LIBRARY_PATH", ":".join(directories),
                "/oracle/clang"] + list(ARGUMENTS)
    return _run(command, scratch, LIMITS["compileAddressSpaceBytes"], artifacts=True)


def _execute(bwrap: str, program: Path, scratch: Path) -> dict[str, Any]:
    # The produced static ELF is the only file in an otherwise empty root: no /proc, /dev, libraries or network.
    command = _base(bwrap) + ["--ro-bind", os.fspath(program), "/oracle/program", "--chdir", "/", "/oracle/program"]
    return _run(command, scratch, LIMITS["executeAddressSpaceBytes"], artifacts=False)


def _collect_program(workspace: Path) -> tuple[dict[str, Any], bytes]:
    names = sorted(entry.name for entry in workspace.iterdir())
    if names != ["program", "start.s"] or len(names) > LIMITS["workspaceEntries"]:
        raise BehaviorCorpusError("compilation produced an unexpected workspace population")
    program = workspace / "program"
    metadata = program.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o755:
        raise BehaviorCorpusError("produced program must be a single-link regular file with mode 0755")
    payload = _read_regular_snapshot(program, "produced program", LIMITS["artifactBytes"], require_executable=True)
    _require_static_amd64(payload)
    return {"path": "program", "mode": "0o755", "normalizedSha256": _sha(normalize_program(payload)), **_blob(payload)}, payload


def _host_facts(bwrap: str) -> dict[str, Any]:
    release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            key, _, value = line.partition("=")
            if key in {"ID", "VERSION_ID"}:
                release[key] = value.strip('"\'')
    except OSError:
        pass
    version = subprocess.run([bwrap, "--version"], env={}, capture_output=True, timeout=10, check=False).stdout.decode().strip()
    return {"kernelRelease": platform.release(), "machine": platform.machine(), "osId": release.get("ID", ""),
            "osVersionId": release.get("VERSION_ID", ""), "bubblewrap": version}


def observe(manifest_path: Path, artifact_root: Path, temporary_root: Path, bwrap: Path) -> dict[str, Any]:
    manifest_payload = _read_regular_snapshot(manifest_path, "locked LLVM manifest", 1024 * 1024)
    if _sha(manifest_payload) != MANIFEST_SHA256:
        raise BehaviorCorpusError("LLVM manifest identity mismatch")
    relative = json.loads(manifest_payload)["artifacts"]["stripped"]["path"]
    clang_bytes = _read_regular_snapshot(artifact_root / relative, "locked Clang", CLANG["bytes"])
    if len(clang_bytes) != CLANG["bytes"] or _sha(clang_bytes) != CLANG["sha256"]:
        raise BehaviorCorpusError("locked Clang identity mismatch")
    _, source = _locked_inputs()
    linker = shutil.which("ld", path="/usr/bin:/bin")
    if linker is None or not bwrap.is_file():
        raise BehaviorCorpusError("host has no GNU ld or bubblewrap")
    linker_real = os.path.realpath(linker)
    version = subprocess.run([linker_real, "--version"], env={}, capture_output=True, timeout=10, check=False)
    first_line = version.stdout.decode("utf-8", "replace").splitlines()[:1]
    if version.returncode != 0 or not first_line:
        raise BehaviorCorpusError("host linker did not report a version")
    runs = []
    with tempfile.TemporaryDirectory(prefix="issue97-bwrap-", dir=temporary_root) as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        snapshot = root / "clang"
        _write_exclusive(snapshot, clang_bytes, 0o755)
        libraries = sorted(set(_closure(snapshot)) | set(_closure(Path(linker_real))))
        identities = [_file_identity(path) for path in libraries]
        for index in range(2):
            run_root = root / f"run{index}"
            workspace, scratch = run_root / "work", run_root / "scratch"
            for path in (run_root, workspace, scratch):
                path.mkdir(mode=0o700)
            _write_exclusive(workspace / "start.s", source, 0o644)
            compile_result = _compile(os.fspath(bwrap), snapshot, linker_real, libraries, workspace, scratch)
            artifact, payload = _collect_program(workspace)
            program = scratch / "program"
            _write_exclusive(program, payload, 0o755)
            execution = _execute(os.fspath(bwrap), program, scratch)
            runs.append({"compile": compile_result, "artifact": artifact, "execution": execution})
    return verify_observation({
        "schemaVersion": 1, "profile": PROFILE_ID, "authority": dict(AUTHORITY), "limits": dict(LIMITS),
        "manifestSha256": MANIFEST_SHA256, "sourceSha256": SOURCE_SHA256, "clang": dict(CLANG),
        "argv": list(ARGUMENTS), "host": _host_facts(os.fspath(bwrap)),
        "linker": {"path": linker, "realPath": linker_real, "versionLine": first_line[0], **{
            key: value for key, value in _file_identity(linker_real).items() if key != "path"}},
        "libraries": identities, "runs": runs})


def _verify_result(value: Any, label: str, *, exit_code: int, stdout: bytes, stderr: bytes = b"") -> None:
    if not isinstance(value, dict) or set(value) != _RESULT_FIELDS:
        raise BehaviorCorpusError(f"{label} result fields changed")
    if value["exitCode"] != exit_code or type(value["exitCode"]) is not int:
        raise BehaviorCorpusError(f"{label} exit status is not the expected value")
    if type(value["wallMillis"]) is not int or not 0 <= value["wallMillis"] <= LIMITS["wallSeconds"] * 1000:
        raise BehaviorCorpusError(f"{label} wall time is malformed or exceeds its limit")
    if _check_blob(value["stdout"], f"{label} stdout", LIMITS["streamBytes"]) != stdout:
        raise BehaviorCorpusError(f"{label} stdout is not the expected stream")
    if _check_blob(value["stderr"], f"{label} stderr", LIMITS["streamBytes"]) != stderr:
        raise BehaviorCorpusError(f"{label} stderr is not the expected stream")


def verify_observation(document: dict[str, Any]) -> dict[str, Any]:
    """Strict offline cross-binding of the supplied bytes; not attestation that the execution happened."""
    fields = {"schemaVersion", "profile", "authority", "limits", "manifestSha256", "sourceSha256", "clang",
              "argv", "host", "linker", "libraries", "runs"}
    if not isinstance(document, dict) or set(document) != fields or type(document["schemaVersion"]) is not int \
            or document["schemaVersion"] != 1 or document["profile"] != PROFILE_ID:
        raise BehaviorCorpusError("observation envelope changed")
    if (document["authority"] != AUTHORITY or document["limits"] != LIMITS or document["clang"] != CLANG
            or document["manifestSha256"] != MANIFEST_SHA256 or document["sourceSha256"] != SOURCE_SHA256
            or document["argv"] != list(ARGUMENTS)):
        raise BehaviorCorpusError("observation authority, limits, source or Clang binding changed")
    host = document["host"]
    if not isinstance(host, dict) or set(host) != {"kernelRelease", "machine", "osId", "osVersionId", "bubblewrap"} \
            or host["machine"] not in {"x86_64", "amd64"} or not all(isinstance(v, str) for v in host.values()):
        raise BehaviorCorpusError("host facts are malformed")
    linker = document["linker"]
    if not isinstance(linker, dict) or set(linker) != {"path", "realPath", "versionLine", "bytes", "sha256"} \
            or not linker["versionLine"].startswith("GNU ld") or not re.fullmatch(r"[0-9a-f]{64}", linker["sha256"]):
        raise BehaviorCorpusError("linker identity is malformed or not GNU ld")
    libraries = document["libraries"]
    if not isinstance(libraries, list) or not 1 <= len(libraries) <= LIMITS["closureLibraries"] + 8:
        raise BehaviorCorpusError("library closure is malformed or exceeds its bound")
    for item in libraries:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"} or not str(item["path"]).startswith("/") \
                or not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
            raise BehaviorCorpusError("library identity is malformed")
    runs = document["runs"]
    if not isinstance(runs, list) or len(runs) != 2:
        raise BehaviorCorpusError("exactly two complete observations are required")
    programs = []
    for index, run in enumerate(runs):
        if not isinstance(run, dict) or set(run) != _RUN_FIELDS:
            raise BehaviorCorpusError("observation run fields changed")
        _verify_result(run["compile"], f"run {index} compilation", exit_code=0, stdout=b"", stderr=COMPILE_STDERR)
        artifact = run["artifact"]
        if not isinstance(artifact, dict) or set(artifact) != {"path", "mode", "normalizedSha256", *_BLOB_FIELDS} \
                or artifact["path"] != "program" or artifact["mode"] != "0o755":
            raise BehaviorCorpusError("produced artifact fields changed")
        payload = _check_blob({key: artifact[key] for key in _BLOB_FIELDS}, "produced program", LIMITS["artifactBytes"])
        _require_static_amd64(payload)
        if artifact["normalizedSha256"] != _sha(normalize_program(payload)):
            raise BehaviorCorpusError("normalized program identity mismatch")
        _verify_result(run["execution"], f"run {index} execution", exit_code=EXPECTED_EXIT, stdout=MARKER)
        programs.append(payload)
    if normalize_program(programs[0]) != normalize_program(programs[1]):
        raise BehaviorCorpusError("the two compilations differ beyond the one normalized temporary-object name")
    return document


def load_observation(path: Path) -> dict[str, Any]:
    payload = _read_regular_snapshot(path, "observation", MAX_EVIDENCE_BYTES)
    document = _decode_json(payload, "observation")
    if payload != (json.dumps(document, sort_keys=True, indent=2) + "\n").encode():
        raise BehaviorCorpusError("observation must be canonical JSON")
    return verify_observation(document)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=PROFILE / "oracle-manifest.json")
    parser.add_argument("--verify-observation", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--temporary-root", type=Path)
    parser.add_argument("--bwrap", type=Path, default=Path("/usr/bin/bwrap"))
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    if args.verify_observation is not None:
        if any((args.artifact_root, args.temporary_root, args.json_output)):
            parser.error("offline verification does not accept execution arguments")
        try:
            load_observation(args.verify_observation)
        except (BehaviorCorpusError, OSError, ValueError) as error:
            print(f"observation verification failed: {error}", file=sys.stderr)
            return 1
        print("Supplemental bubblewrap observation cross-binding verified; no execution or attestation inferred")
        return 0
    if any(value is None for value in (args.artifact_root, args.temporary_root, args.json_output)):
        parser.error("execution requires artifact-root, temporary-root and json-output")
    repository = Path(__file__).resolve().parents[2]
    root = args.temporary_root.absolute()
    if not root.is_dir() or root.is_symlink() or not root.resolve().is_relative_to(repository):
        parser.error("temporary root must be an existing directory inside the repository")
    try:
        document = observe(args.manifest, args.artifact_root, root, args.bwrap)
        payload = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
        if len(payload) > MAX_EVIDENCE_BYTES:
            raise BehaviorCorpusError("evidence exceeds its fixed retention bound")
        if not args.json_output.absolute().parent.resolve(strict=True).is_relative_to(repository):
            raise BehaviorCorpusError("observation output must remain inside the repository")
        _write_exclusive(args.json_output, payload, 0o600)
    except (BehaviorCorpusError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"produced-program observation failed: {error}", file=sys.stderr)
        return 1
    print("Supplemental bubblewrap observation passed: locked Clang compilation + exact produced-program execution, twice")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
