#!/usr/bin/env python3
"""Bounded, exact-byte GCC inspect adapter. Receipts are descriptive, not authority.

The Linux setup-docker v5 sock output is already a unix:// URI (pinned action
7ec28a010822b4626af4874f9448a4b05ac6f3e5, actions-toolkit 0.107.0).
No image response is repaired and no alternate lock or endpoint is attempted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "decomp-gcc-oracle-toolchain:16.2.0"
SCRATCH = "build/gcc-reproduction-adapter"
RUNTIME_BASE = ".d"
# Linux sockaddr_un reserves one of its 108 bytes for the terminating NUL.
SOCKET_PATH_BYTES = 107
LOCK = "oracle/gcc/16.2.0/toolchain-reproduction.json"
RECORD = "oracle/gcc/16.2.0/build-record.json"
VERIFIER = "scripts/verify-gcc-toolchain-reproduction.py"
SOURCES = (".github/workflows/gcc-oracle-model.yml", __file__, VERIFIER,
           "oracle/gcc/toolchain_reproduction.py", LOCK, RECORD,
           "scripts/verify-gcc-oracle-build-record.py",
           "oracle/gcc/16.2.0/source-lock.json",
           "oracle/gcc/16.2.0/build-toolchain.Dockerfile")
STDOUT_CAP = 1024 * 1024
STDERR_CAP = 64 * 1024
CALL_SECONDS = 30
TOTAL_SECONDS = 120
CLEANUP_SECONDS = 5


class Refusal(Exception):
    def __init__(self, message, *, code=1, stdout=b"", stderr=b"", cleanup=()):
        super().__init__(message)
        self.code, self.stdout, self.stderr = code, stdout, stderr
        self.cleanup = list(cleanup)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refusal(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def constant(value):
        raise Refusal(f"non-JSON constant: {value}")

    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=constant)


def check_deadline(clock, end):
    if clock() >= end:
        raise Refusal("capture deadline exceeded", code=124)


class Child:
    """Only ordinary CLI children; never manages or attests a Docker service."""
    def __init__(self, argv, env, cwd):
        self.selector = None
        self.process = subprocess.Popen(argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True)

    @property
    def pending(self):
        return self.selector is None or bool(self.selector.get_map())

    def read(self, timeout):
        # Initialize inside the transport's protected region: registration errors
        # still follow the same bounded TERM/KILL/reap path and retain their cause.
        if self.selector is None:
            self.selector = selectors.DefaultSelector()
            for stream, pipe in (("stdout", self.process.stdout),
                                 ("stderr", self.process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                self.selector.register(pipe, selectors.EVENT_READ, stream)
        chunks = []
        for key, _ in self.selector.select(timeout):
            data = os.read(key.fileobj.fileno(), 65536)
            if not data:
                self.selector.unregister(key.fileobj)
            else:
                chunks.append((key.data, data))
        return chunks

    def send(self, sig):
        # The process is not polled/reaped until after both output pipes close,
        # or after TERM/KILL. The group belongs to this freshly spawned CLI.
        try:
            os.killpg(self.process.pid, sig)
        except ProcessLookupError:
            pass

    def wait(self, timeout):
        return self.process.wait(timeout=max(0, timeout))

    def close(self):
        errors = []
        for resource in (self.selector, self.process.stdout, self.process.stderr):
            if resource is not None:
                try:
                    resource.close()
                except BaseException as error:
                    errors.append(f"{type(error).__name__}: {error}")
        if errors:
            raise Refusal("; ".join(errors))


def run_cli(argv, env, cwd, end, *, clock=time.monotonic, spawn=Child):
    """Injectable streaming transport; caps are enforced during reading, not after."""
    operation_end = min(clock() + CALL_SECONDS, end)
    call_end = operation_end - CLEANUP_SECONDS
    check_deadline(clock, call_end)
    child = None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    primary = None
    reaped = False
    cleanup = []
    try:
        child = spawn(argv, env, cwd)
        while child.pending:
            check_deadline(clock, call_end)
            for stream, chunk in child.read(min(0.1, max(0, call_end - clock()))):
                cap = STDOUT_CAP if stream == "stdout" else STDERR_CAP
                room = cap - len(output[stream])
                output[stream].extend(chunk[:room])
                if len(chunk) > room:
                    raise Refusal(f"{stream} exceeded {cap} byte cap", code=125)
            check_deadline(clock, call_end)
        status = child.wait(max(0, call_end - clock()))
        reaped = True
        check_deadline(clock, call_end)
        if status:
            raise Refusal(f"CLI exited {status}: " + output["stderr"].decode("utf-8", errors="replace"),
                          code=status if 0 < status < 126 else 1)
    except BaseException as error:
        primary = error
    finally:
        if child is not None:
            if not reaped:
                cleanup_end = min(operation_end, clock() + CLEANUP_SECONDS)
                # TERM then KILL before wait/reap avoids reusing a reaped PID.
                # No grace sleep: these capture CLIs have no state to flush.
                for sig in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        child.send(sig)
                    except BaseException as error:
                        cleanup.append(f"{signal.Signals(sig).name}: {type(error).__name__}: {error}")
                try:
                    child.wait(max(0, cleanup_end - clock()))
                    if clock() > cleanup_end:
                        raise Refusal("cleanup exceeded deadline")
                except BaseException as error:
                    cleanup.append(f"reap: {type(error).__name__}: {error}")
            try:
                child.close()
            except BaseException as error:
                cleanup.append(f"close: {type(error).__name__}: {error}")
    if primary is not None or cleanup:
        error = primary or Refusal("CLI cleanup failed")
        code = error.code if isinstance(error, Refusal) else (
            124 if isinstance(error, subprocess.TimeoutExpired) else 1)
        raise Refusal(f"{type(error).__name__}: {error}", code=code,
                      stdout=bytes(output["stdout"]), stderr=bytes(output["stderr"]),
                      cleanup=cleanup) from primary
    return bytes(output["stdout"]), bytes(output["stderr"])


class Evidence:
    """Exclusive output directory, anchored with no-follow directory descriptors."""
    def __init__(self, root, relative):
        parts = relative.split("/")
        if not parts or any(p in ("", ".", "..") for p in parts):
            raise Refusal("output directory must be a normalized repository-relative path")
        if parts[:2] != ["build", "gcc-reproduction-adapter"]:
            raise Refusal("output directory must be under build/gcc-reproduction-adapter")
        self.path = root / relative
        self.root, self.parts = root, parts
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(root, flags)
        try:
            for index, part in enumerate(parts):
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    if index == len(parts) - 1:
                        raise Refusal("output directory already exists; refusing reuse or overwrite")
                new = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = new
            self.fd = fd
            self.identity = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        except BaseException:
            os.close(fd)
            raise

    def write(self, name, data):
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", name):
            raise Refusal("invalid evidence filename")
        temporary = "." + name + ".partial"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        primary = None
        cleanup = []
        linked = False
        try:
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("output write made no progress")
                view = view[count:]
            os.fsync(fd)
            os.close(fd)
            fd = None
            # link() is atomic and fails if the destination exists, unlike replace().
            os.link(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd,
                    follow_symlinks=False)
            linked = True
            os.unlink(temporary, dir_fd=self.fd)
            os.fsync(self.fd)
        except BaseException as error:
            primary = error
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as error:
                    cleanup.append(f"close partial: {error}")
            if primary is not None:
                for entry in ([name] if linked else []) + [temporary]:
                    try:
                        os.unlink(entry, dir_fd=self.fd)
                    except FileNotFoundError:
                        pass
                    except OSError as error:
                        cleanup.append(f"remove {entry}: {error}")
        if primary is not None:
            raise Refusal(f"{type(primary).__name__}: {primary}", cleanup=cleanup) from primary

    def remove(self, name):
        # Reopen without following symlinks after close/late-deadline failure.
        # Compare the original directory identity before removing our receipt.
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(self.root, flags)
        try:
            for part in self.parts:
                new = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = new
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self.identity:
                raise Refusal("evidence directory changed; refusing receipt removal")
            os.unlink(name, dir_fd=fd)
        finally:
            os.close(fd)

    def close(self):
        os.close(self.fd)


def runtime_socket_paths(root, run_id="run-00000000"):
    # Pinned setup action uses run-<8 hex>/execroot for managed containerd.
    # Check the deeper sockets too: checking docker.sock alone is insufficient.
    if not re.fullmatch(r"run-[0-9a-f]{8}", run_id):
        raise Refusal("invalid setup-action run identity")
    base = root / RUNTIME_BASE / run_id
    paths = tuple(base / suffix for suffix in (
        "docker.sock", "execroot/containerd/containerd.sock",
        "execroot/containerd/containerd.sock.ttrpc",
        "execroot/containerd/containerd-debug.sock"))
    if any(len(os.fsencode(path)) > SOCKET_PATH_BYTES for path in paths):
        raise Refusal("repository-local Docker runtime socket exceeds Linux path limit")
    return paths


def selected_endpoint(value, root):
    # The action runtime-basedir is explicitly bound by the workflow. Accept its
    # exact Linux URI, without conversion, context discovery or socket fallback.
    prefix = "unix://" + str(root / RUNTIME_BASE) + "/"
    if not value.startswith(prefix) or not re.fullmatch(
            r"run-[0-9a-f]{8}/docker\.sock", value[len(prefix):]):
        raise Refusal("endpoint is not the selected setup-action Linux socket URI")
    runtime_socket_paths(root, value[len(prefix):].split("/", 1)[0])
    return value


def api(value):
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*\.[0-9]+", value):
        raise Refusal(f"invalid API version: {value!r}")
    return tuple(int(v) for v in value.split("."))


def admit_version(version, *, scoped=False):
    if version["Server"]["Version"] != "29.7.2":
        raise Refusal("actual Docker engine must be 29.7.2")
    if not (api(version["Server"]["MinAPIVersion"]) <= (1, 49)
            <= api(version["Server"]["ApiVersion"])):
        raise Refusal("server does not support API 1.49")
    if scoped and version["Client"]["ApiVersion"] != "1.49":
        raise Refusal("effective client API must be exactly 1.49")


def admit_store(info):
    if info["ServerVersion"] != "29.7.2" or info["Driver"] != "overlay2":
        raise Refusal("actual engine/store must be 29.7.2/classic overlay2")
    status = info["DriverStatus"]
    if not isinstance(status, list) or not status:
        raise Refusal("missing actual storage driver status")
    seen = set()
    for row in status:
        if (not isinstance(row, list) or len(row) != 2
                or not all(isinstance(v, str) for v in row) or row[0] in seen):
            raise Refusal("malformed or duplicate storage driver status")
        seen.add(row[0])
        if row[0] == "driver-type" or "io.containerd.snapshotter.v1" in row:
            raise Refusal("containerd snapshotter is not the classic image store")


def capture(endpoint, output_dir, provenance, *, root=ROOT, clock=time.monotonic,
            transport=run_cli, environment=None, sources=SOURCES):
    end = clock() + TOTAL_SECONDS
    receipt = {"schemaVersion": 1, "authority": "descriptive only; no service or hosted qualification",
               "status": "rejected", "provenance": provenance, "endpoint": endpoint,
               "commands": [], "sourceSha256": {}, "verifierExit": None,
               "primaryError": None, "secondaryErrors": []}
    evidence = None
    primary = None
    receipt_written = False
    env = dict(os.environ if environment is None else environment)
    # A --host argument plus clearing ambient context/TLS/API state prevents a
    # user context or job-level API override from redirecting these captures.
    for key in list(env):
        if key.startswith("DOCKER_"):
            del env[key]
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["TMPDIR"] = str(root / SCRATCH / "tmp")

    def command(name, args, *, scoped=False, verifier=False):
        command_env = dict(env)
        if scoped:
            command_env["DOCKER_API_VERSION"] = "1.49"
        argv = args if verifier else ["docker", "--host", endpoint, *args]
        started = clock()
        facts = {"name": name, "argv": argv, "api": "1.49" if scoped else "default",
                 "exit": None, "startedSeconds": started - (end - TOTAL_SECONDS)}
        receipt["commands"].append(facts)
        failure = None
        try:
            out, err = transport(argv, command_env, root, end, clock=clock)
            facts["exit"] = 0
        except Refusal as error:
            out, err, failure = error.stdout, error.stderr, error
            facts.update(exit=error.code, error=str(error), cleanupErrors=error.cleanup)
        facts.update(stdoutBytes=len(out), stdoutSha256=digest(out),
                     stderrBytes=len(err), stderrSha256=digest(err),
                     elapsedSeconds=clock() - started)
        if verifier:
            receipt["verifierExit"] = facts["exit"]
        try:
            suffix = ".partial" if failure else ""
            evidence.write(name + ".stdout" + suffix, out)
            evidence.write(name + ".stderr" + suffix, err)
        except BaseException as error:
            if failure is None:
                raise
            receipt["secondaryErrors"].append(f"retaining failed command: {error}")
        if failure:
            raise failure
        check_deadline(clock, end)
        return out

    try:
        endpoint = selected_endpoint(endpoint, root)
        evidence = Evidence(root, output_dir)
        os.mkdir("docker-config", mode=0o700, dir_fd=evidence.fd)
        os.mkdir("tmp", mode=0o700, dir_fd=evidence.fd)
        env["TMPDIR"] = str(evidence.path / "tmp")
        env["DOCKER_CONFIG"] = str(evidence.path / "docker-config")
        for name in sources:
            path = Path(name)
            if not path.is_absolute():
                path = root / path
            receipt["sourceSha256"][str(path.relative_to(root))] = digest(path.read_bytes())
        version = strict_json(command("default-version", ["version", "--format", "{{json .}}"]))
        info = strict_json(command("default-info", ["info", "--format", "{{json .}}"]))
        admit_version(version)
        admit_store(info)
        # Diagnostic bytes remain separate, never used as the strict verifier input.
        strict_json(command("default-inspect", ["image", "inspect", IMAGE]))
        scoped_version = strict_json(command("api149-version", ["version", "--format", "{{json .}}"], scoped=True))
        admit_version(scoped_version, scoped=True)
        raw = command("api149-inspect", ["image", "inspect", IMAGE], scoped=True)
        strict_json(raw)  # Reject duplicate/malformed JSON; never serialize this value.
        receipt["inspectSha256"] = digest(raw)
        evidence.write("image-inspect.json", raw)
        check_deadline(clock, end)
        command("strict-verifier", [sys.executable, "-B", str(root / VERIFIER),
                                   "--lock", str(root / LOCK),
                                   "--build-record", str(root / RECORD),
                                   "--inspect-json", str(evidence.path / "image-inspect.json")], verifier=True)
        check_deadline(clock, end)
        receipt["status"] = "strict-verified-only"
    except BaseException as error:
        primary = error
        receipt["primaryError"] = f"{type(error).__name__}: {error}"
        if isinstance(error, Refusal):
            receipt["secondaryErrors"].extend(error.cleanup)
    if evidence is not None:
        try:
            if primary is None:
                check_deadline(clock, end)
            evidence.write("receipt.json", (json.dumps(receipt, indent=2) + "\n").encode())
            receipt_written = True
            if primary is None:
                check_deadline(clock, end)
        except BaseException as error:
            if primary is None:
                primary = error
                receipt["primaryError"] = f"{type(error).__name__}: {error}"
                receipt["status"] = "rejected"
            else:
                receipt["secondaryErrors"].append(f"receipt write: {type(error).__name__}: {error}")
            if receipt_written:
                try:
                    evidence.remove("receipt.json")
                except BaseException as cleanup_error:
                    receipt["secondaryErrors"].append(f"receipt removal: {cleanup_error}")
        try:
            evidence.close()
            if primary is None:
                check_deadline(clock, end)
        except BaseException as error:
            if primary is None:
                primary = error
                receipt["primaryError"] = f"evidence close: {error}"
            else:
                receipt["secondaryErrors"].append(f"evidence close: {error}")
            receipt["status"] = "rejected"
            if receipt_written:
                try:
                    evidence.remove("receipt.json")
                except BaseException as cleanup_error:
                    receipt["secondaryErrors"].append(f"receipt removal: {cleanup_error}")
    if primary is not None:
        # The primary failure is never replaced by evidence/cleanup failure.
        print(json.dumps(receipt, indent=2), file=sys.stderr)
        return primary.code if isinstance(primary, Refusal) else 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-runtime-root", action="store_true")
    parser.add_argument("--endpoint")
    parser.add_argument("--output-dir", default=SCRATCH + "/capture")
    parser.add_argument("--executed-commit")
    parser.add_argument("--executed-tree")
    args = parser.parse_args()
    if args.check_runtime_root:
        if args.endpoint or args.executed_commit or args.executed_tree:
            parser.error("runtime preflight does not accept capture arguments")
        try:
            runtime_socket_paths(ROOT)
        except Refusal as error:
            parser.error(str(error))
        return 0
    if not args.endpoint:
        parser.error("explicit selected endpoint is required")
    provenance = {"run": os.environ.get("GITHUB_RUN_ID"),
                  "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                  "headCommit": os.environ.get("GCC_REPRODUCTION_HEAD"),
                  "executedCommit": args.executed_commit, "executedTree": args.executed_tree}
    if (not all(isinstance(provenance[k], str) and re.fullmatch(r"[0-9a-f]{40}", provenance[k])
                for k in ("headCommit", "executedCommit", "executedTree"))
            or not all(isinstance(provenance[k], str) and re.fullmatch(r"[1-9][0-9]*", provenance[k])
                       for k in ("run", "attempt"))):
        parser.error("complete run/attempt/head/executed commit/tree provenance is required")
    return capture(args.endpoint, args.output_dir, provenance)


if __name__ == "__main__":
    raise SystemExit(main())
