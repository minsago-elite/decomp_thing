from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import subprocess
import tempfile
from typing import Any
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.behavior_corpus import (  # noqa: E402
    BehaviorCorpusError,
    ExactExecutorProfileMismatch,
    PYTHON_PREEXEC_ENFORCER_V1,
    _engine_components_sha256,
    corpus_json_bytes,
    load_corpus,
    load_report,
    report_json_bytes,
    run_corpus,
    validate_corpus,
    validate_corpus_report_pair,
    validate_report,
)


CORPUS_SCHEMA = REPOSITORY_ROOT / "oracle/behavior-corpus.schema.json"
REPORT_SCHEMA = REPOSITORY_ROOT / "oracle/behavior-corpus-report.schema.json"

DEFAULT_FIXTURE_IMAGE_ENVIRONMENT = ["PATH=/usr/bin:/bin"]
DEFAULT_FIXTURE_ENGINE_PROFILE = {
    "product": "Docker Engine - Community",
    "serverVersion": "29.7.2",
    "serverCommit": "6a43e3d",
    "apiVersion": "1.55",
    "operatingSystem": "linux",
    "architecture": "amd64",
    "kernelVersion": "7.1.8-gentoo-dist-hardened",
    "componentsSha256": (
        "53eac8fe100341b65c87b5840bbf271f1d471f6b74553ba8d410156ebaaab011"
    ),
    "cgroupVersion": 2,
    "cgroupDriver": "systemd",
    "storageDriver": "overlay2",
    "securityOptions": [
        "name=cgroupns",
        "name=rootless",
        "name=seccomp,profile=builtin",
    ],
    "containerRuntime": "runc",
    "containerRuntimePath": "runc",
    "containerRuntimeVersion": "1.4.3",
    "containerRuntimeCommit": "v1.4.3-0-gbb14dab",
    "containerRuntimeFeaturesSha256": (
        "c41c71ffb7a88612341e64b88f053f6b3f18832a9563efab0a5be8d4e664cd2c"
    ),
    "volumePlugin": "local",
}
FIXTURE_SETUP_PROGRAM = r'''import os, stat
stack = [("/case-inputs", "/workspace")]
maximum_bytes = int(os.environ["WORKSPACE_BYTES"]); maximum_entries = int(os.environ["WORKSPACE_ENTRIES"])
target_uid = int(os.environ["TARGET_UID"]); target_gid = int(os.environ["TARGET_GID"])
records = [line.split() for line in open("/proc/self/mountinfo") if " /workspace " in line]
if len(records) != 1: raise RuntimeError("ambiguous mount")
record = records[0]; separator = record.index("-"); mount_options = set(record[5].split(",")); super_options = set(record[separator + 3].split(","))
if record[separator + 1] != "tmpfs" or not {"rw", "nosuid", "nodev"}.issubset(mount_options) or "rw" not in super_options: raise RuntimeError("invalid tmpfs")
filesystem = os.statvfs("/workspace"); capacity = filesystem.f_blocks * filesystem.f_frsize; metadata = os.stat("/workspace", follow_symlinks=False)
if capacity < maximum_bytes or capacity >= maximum_bytes + filesystem.f_frsize or filesystem.f_files != maximum_entries: raise RuntimeError("invalid quota")
if metadata.st_uid != target_uid or metadata.st_gid != target_gid or metadata.st_mode & 0o7777 != 0o700: raise RuntimeError("invalid owner")
while stack:
    source, target = stack.pop()
    for entry in sorted(os.scandir(source), key=lambda item: item.name):
        destination = os.path.join(target, entry.name)
        metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            os.mkdir(destination, 0o700); stack.append((entry.path, destination)); continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1: raise RuntimeError("invalid input")
        mode = 0o500 if metadata.st_mode & 0o111 else 0o400
        source_fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW)
        target_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            while True:
                chunk = os.read(source_fd, 65536)
                if not chunk: break
                os.write(target_fd, chunk)
            os.fchmod(target_fd, mode)
        finally: os.close(source_fd); os.close(target_fd)
'''
FIXTURE_COLLECTOR_PROGRAM = r'''import os, stat
maximum_bytes = int(os.environ["WORKSPACE_BYTES"]); maximum_entries = int(os.environ["WORKSPACE_ENTRIES"])
records = []; stack = [("", "/workspace")]; logical = allocated = 0
while stack:
    prefix, root = stack.pop()
    for entry in sorted(os.scandir(root), key=lambda item: item.name):
        relative = entry.name if not prefix else prefix + "/" + entry.name
        metadata = entry.stat(follow_symlinks=False); records.append((relative, metadata))
        logical += metadata.st_size; allocated += metadata.st_blocks * 512
        if len(records) > maximum_entries or logical > maximum_bytes or allocated > maximum_bytes: raise RuntimeError("workspace bound exceeded")
        if metadata.st_mode & 0o7000: raise RuntimeError("forbidden special mode")
        if stat.S_ISDIR(metadata.st_mode): stack.append((relative, entry.path))
        elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or not metadata.st_mode & 0o400: raise RuntimeError("invalid file")
for relative, metadata in sorted(records, key=lambda item: (item[0].count("/"), item[0])):
    source = os.path.join("/workspace", *relative.split("/")); destination = os.path.join("/case-results", *relative.split("/"))
    if stat.S_ISDIR(metadata.st_mode): os.mkdir(destination, 0o700); continue
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW); target_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(source_fd, min(remaining, 65536))
            if not chunk: raise RuntimeError("changed file")
            os.write(target_fd, chunk); remaining -= len(chunk)
        os.fchmod(target_fd, metadata.st_mode & 0o777)
    finally: os.close(source_fd); os.close(target_fd)
'''


def blob(payload: bytes) -> dict[str, object]:
    return {
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "base64": base64.b64encode(payload).decode("ascii"),
    }


def artifact(path: str, payload: bytes, *, mode: str = "0o600") -> dict[str, object]:
    return {
        "path": path,
        "present": True,
        **blob(payload),
        "mode": mode,
    }


def absent_artifact(path: str) -> dict[str, object]:
    return {
        "path": path,
        "present": False,
        "bytes": None,
        "sha256": None,
        "base64": None,
        "mode": None,
    }


def stream(payload: bytes, *normalizations: str) -> dict[str, object]:
    return {**blob(payload), "normalizations": list(normalizations)}


class BehaviorCorpusTest(unittest.TestCase):
    image_digest = "sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248"
    executable: Path
    executable_payload: bytes
    runtime: Path | None
    runtime_environment: dict[str, str]
    runtime_payload: bytes
    runtime_version: str
    engine_profile: dict[str, object]
    image_environment: list[str]
    image_environment_sentinel: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine_profile = copy.deepcopy(DEFAULT_FIXTURE_ENGINE_PROFILE)
        cls.image_environment = list(DEFAULT_FIXTURE_IMAGE_ENVIRONMENT)
        cls.image_environment_sentinel = "UNDECLARED_IMAGE_VALUE"
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("generic behavior-corpus tests require a C compiler")
        fixture_directory = tempfile.TemporaryDirectory(prefix="behavior-fixture-")
        cls.addClassCleanup(fixture_directory.cleanup)
        cls.executable = Path(fixture_directory.name) / "fixture"
        source = r'''
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void write_file(const char *path, const unsigned char *data, size_t size) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, data, size) != (ssize_t)size || close(fd) != 0) _exit(70);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    if (strcmp(mode, "binary") == 0) {
        char cwd[4096];
        if (!getcwd(cwd, sizeof(cwd))) return 71;
        fwrite(argv[0], 1, strlen(argv[0]), stdout);
        fwrite("\0raw", 1, 4, stdout);
        fwrite(cwd, 1, strlen(cwd), stderr);
        write_file("result.bin", (const unsigned char *)"\0artifact", 9);
        return 0;
    }
    if (strcmp(mode, "env") == 0) {
        const char *path = getenv("PATH");
        const char *image_sentinel = getenv("IMAGE_ENVIRONMENT_SENTINEL");
        return getenv("BEHAVIOR_CORPUS_SECRET") || !image_sentinel ||
               getenv(image_sentinel) || !path || strcmp(path, "/usr/bin:/bin") != 0 ? 9 : 0;
    }
    if (strcmp(mode, "extra") == 0) {
        write_file("surprise.bin", (const unsigned char *)"extra", 5); return 0;
    }
    if (strcmp(mode, "special-mode") == 0) {
        write_file("result.bin", (const unsigned char *)"special", 7);
        return chmod("result.bin", 04600) == 0 ? 0 : 76;
    }
    if (strcmp(mode, "directory") == 0) return mkdir("surprise-dir", 0700) == 0 ? 0 : 75;
    if (strcmp(mode, "mutate") == 0) {
        chmod("input.bin", 0600);
        write_file("input.bin", (const unsigned char *)"changed", 7); return 0;
    }
    if (strcmp(mode, "hang") == 0) for (;;) { }
    if (strcmp(mode, "noisy") == 0) for (;;) fwrite("xxxxxxxx", 1, 8, stdout);
    if (strcmp(mode, "stable") == 0) { fwrite("stable", 1, 6, stdout); return 0; }
    if (strcmp(mode, "spoof") == 0) {
        static const unsigned char fake[] = "\0behavior-preexec-v1:target:00000000000000000000000000000000\n";
        fwrite(fake, 1, sizeof(fake) - 1, stdout); return 0;
    }
    if (strcmp(mode, "secret") == 0) {
        if (argc != 3) return 72;
        int fd = open(argv[2], O_RDONLY);
        if (fd >= 0) { close(fd); return 9; }
        return 0;
    }
    if (strcmp(mode, "network") == 0) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_port = htons(80);
        inet_pton(AF_INET, "1.1.1.1", &address.sin_addr);
        int connected = fd >= 0 ? connect(fd, (struct sockaddr *)&address, sizeof(address)) : -1;
        if (fd >= 0) close(fd);
        return connected == 0 ? 9 : 0;
    }
    if (strcmp(mode, "daemon") == 0) {
        pid_t child = fork();
        if (child < 0) return 73;
        if (child == 0) { sleep(1); write_file("daemon.bin", (const unsigned char *)"escaped", 7); _exit(0); }
        return 0;
    }
    return 74;
}
'''
        subprocess.run(
            [
                compiler,
                "-static",
                "-s",
                "-Wl,--build-id=none",
                "-x",
                "c",
                "-o",
                os.fspath(cls.executable),
                "-",
            ],
            input=source.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        cls.executable_payload = cls.executable.read_bytes()
        configured_runtime = os.environ.get("DOCKER")
        fallback_runtime = Path("/tmp/decomp-docker/bin/docker")
        discovered_runtime = (
            configured_runtime
            or shutil.which("docker")
            or (os.fspath(fallback_runtime) if fallback_runtime.is_file() else None)
        )
        cls.runtime = Path(discovered_runtime) if discovered_runtime else None
        configured_host = os.environ.get("DOCKER_HOST")
        fallback_socket = Path("/tmp/decomp-docker/runtime/docker.sock")
        if configured_host:
            cls.runtime_environment = {"DOCKER_HOST": configured_host}
        elif fallback_socket.exists():
            cls.runtime_environment = {"DOCKER_HOST": f"unix://{fallback_socket}"}
        else:
            cls.runtime_environment = {}
        if cls.runtime is not None:
            try:
                image_records = json.loads(
                    subprocess.run(
                        [os.fspath(cls.runtime), "image", "inspect", cls.image_digest],
                        env=cls.runtime_environment,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                        check=True,
                    ).stdout.decode("utf-8")
                )
                if not isinstance(image_records, list) or len(image_records) != 1:
                    raise ValueError("malformed fixture image")
                image_environment = image_records[0]["Config"].get("Env") or []
                if not isinstance(image_environment, list) or not all(
                    isinstance(entry, str) for entry in image_environment
                ):
                    raise ValueError("malformed fixture image environment")
                cls.image_environment = list(image_environment)
                declared_names = [entry.partition("=")[0] for entry in image_environment]
                cls.image_environment_sentinel = next(
                    (name for name in declared_names if name != "PATH"),
                    "UNDECLARED_IMAGE_VALUE",
                )
            except (
                KeyError,
                OSError,
                TypeError,
                ValueError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                subprocess.SubprocessError,
            ) as error:
                raise RuntimeError(
                    "configured generic OCI executor discovery failed"
                ) from error
        if cls.runtime is not None:
            cls.runtime_payload = cls.runtime.read_bytes()
            cls.runtime_version = subprocess.run(
                [os.fspath(cls.runtime), "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=True,
            ).stdout.decode("utf-8")
            try:
                server = json.loads(
                    subprocess.run(
                        [
                            os.fspath(cls.runtime),
                            "version",
                            "--format",
                            "{{json .Server}}",
                        ],
                        env=cls.runtime_environment,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                        check=True,
                    ).stdout.decode("utf-8")
                )
                info_lines = (
                    subprocess.run(
                        [
                            os.fspath(cls.runtime),
                            "info",
                            "--format",
                            (
                                "{{json .SecurityOptions}}\n"
                                "{{.CgroupVersion}}\n"
                                "{{.CgroupDriver}}\n"
                                "{{.Driver}}\n"
                                "{{json .Plugins.Volume}}\n"
                                "{{json .Runtimes}}"
                            ),
                        ],
                        env=cls.runtime_environment,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                        check=True,
                    )
                    .stdout.decode("utf-8")
                    .strip()
                    .splitlines()
                )
                if len(info_lines) != 6:
                    raise ValueError("malformed engine information")
                security_options = sorted(json.loads(info_lines[0]))
                mandatory_options = {
                    "name=cgroupns",
                    "name=rootless",
                    "name=seccomp,profile=builtin",
                }
                if not mandatory_options.issubset(security_options):
                    raise ValueError("engine lacks mandatory rootless isolation")
                volume_plugins = json.loads(info_lines[4])
                if "local" not in volume_plugins:
                    raise ValueError("engine lacks the local volume plugin")
                runtimes = json.loads(info_lines[5])
                runtime_name = "runc"
                runtime_record = runtimes[runtime_name]
                runtime_features = runtime_record["status"][
                    "org.opencontainers.runtime-spec.features"
                ]
                runtime_components = [
                    component
                    for component in server["Components"]
                    if component["Name"] == runtime_name
                ]
                if len(runtime_components) != 1:
                    raise ValueError("engine lacks one runc component")
                runtime_component = runtime_components[0]
                cls.engine_profile = {
                    "product": server["Platform"]["Name"],
                    "serverVersion": server["Version"],
                    "serverCommit": server["GitCommit"],
                    "apiVersion": server["ApiVersion"],
                    "operatingSystem": server["Os"],
                    "architecture": server["Arch"],
                    "kernelVersion": server["KernelVersion"],
                    "componentsSha256": _engine_components_sha256(
                        server["Components"]
                    ),
                    "cgroupVersion": int(info_lines[1]),
                    "cgroupDriver": info_lines[2],
                    "storageDriver": info_lines[3],
                    "securityOptions": security_options,
                    "containerRuntime": runtime_name,
                    "containerRuntimePath": runtime_record["path"],
                    "containerRuntimeVersion": runtime_component["Version"],
                    "containerRuntimeCommit": runtime_component["Details"][
                        "GitCommit"
                    ],
                    "containerRuntimeFeaturesSha256": hashlib.sha256(
                        runtime_features.encode("utf-8")
                    ).hexdigest(),
                    "volumePlugin": "local",
                }
            except (
                KeyError,
                OSError,
                TypeError,
                ValueError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                subprocess.SubprocessError,
            ) as error:
                raise RuntimeError(
                    "configured generic OCI executor profile discovery failed"
                ) from error
        else:
            cls.runtime_payload = b"fixture-control-client"
            cls.runtime_version = "fixture control client\n"

    def run_fixture_corpus(
        self, corpus: dict[str, object], *, payload: bytes | None = None
    ) -> dict[str, object]:
        if self.runtime is None:
            self.skipTest("generic execution tests require the locked OCI sandbox image")
        return run_corpus(
            corpus,
            self.executable,
            corpus_payload=payload,
            container_runtime=self.runtime,
            container_runtime_environment=self.runtime_environment,
        )

    def corpus(self, mode: str = "binary") -> dict[str, object]:
        stdin_payload = b"\x00stdin\xff"
        input_payload = b"\x00input\xff"
        return {
            "schemaVersion": 1,
            "scope": "fixture",
            "id": "opaque-program-fixture",
            "executable": {
                "bytes": len(self.executable_payload),
                "sha256": hashlib.sha256(self.executable_payload).hexdigest(),
            },
            "sandbox": {
                "backend": "oci-container-v1",
                "resourcePolicyVersion": 1,
                "oomScoreAdjustment": 500,
                "imageDigest": self.image_digest,
                "platform": "linux/amd64",
                "isolation": "network-none-readonly-root-cap-drop-all-no-new-privileges-pid-ipc-private-cgroup-bounds",
                "imageEnvironment": list(self.image_environment),
                "preExecArgv": [
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    PYTHON_PREEXEC_ENFORCER_V1,
                ],
                "environmentLauncher": "/usr/bin/env",
                "keeperArgv": ["/usr/bin/sleep", "infinity"],
                "setupArgv": ["/usr/bin/python3", "-I", "-S", "-B", "-c", FIXTURE_SETUP_PROGRAM],
                "collectorArgv": ["/usr/bin/python3", "-I", "-S", "-B", "-c", FIXTURE_COLLECTOR_PROGRAM],
                "targetUser": "65534:65534",
                "controlClient": {
                    "bytes": len(self.runtime_payload),
                    "sha256": hashlib.sha256(self.runtime_payload).hexdigest(),
                    "version": self.runtime_version,
                },
                "engineProfile": copy.deepcopy(self.engine_profile),
            },
            "environment": {
                "clearInherited": True,
                "variables": {
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                    "TMPDIR": "{workspace}/tmp",
                },
            },
            "limits": {
                "timeoutMilliseconds": 5000,
                "stdoutBytes": 4096,
                "stderrBytes": 4096,
                "artifactBytes": 4096,
                "memoryBytes": 268435456,
                "fileBytes": 4096,
                "openFiles": 32,
                "processes": 4096,
                "cpuSeconds": 2,
                "workspaceBytes": 1048576,
                "workspaceEntries": 128,
            },
            "directories": ["tmp"],
            "normalizations": [
                {
                    "id": "stderr-workspace",
                    "field": "stderr",
                    "operation": "replace-runtime-path",
                    "runtimePath": "workspace",
                    "replacement": "<WORKSPACE>",
                },
                {
                    "id": "stdout-oracle",
                    "field": "stdout",
                    "operation": "replace-runtime-path",
                    "runtimePath": "oracle",
                    "replacement": "<ORACLE>",
                },
            ],
            "cases": [
                {
                    "id": "binary-round-trip",
                    "categories": ["artifact", "binary", "stdin"],
                    "arguments": [mode],
                    "environment": {},
                    "stdin": blob(stdin_payload),
                    "inputs": [
                        {
                            "path": "input.bin",
                            **blob(input_payload),
                            "executable": False,
                        }
                    ],
                    "expected": {
                        "exitCode": 0,
                        "stdout": stream(b"<ORACLE>\x00raw", "stdout-oracle"),
                        "stderr": stream(b"<WORKSPACE>", "stderr-workspace"),
                        "artifacts": [artifact("result.bin", b"\x00artifact")],
                    },
                }
            ],
        }

    def test_binary_observations_and_runtime_path_normalization_are_deterministic(self) -> None:
        corpus = self.corpus()
        payload = corpus_json_bytes(corpus)
        first = self.run_fixture_corpus(corpus, payload=payload)
        second = self.run_fixture_corpus(corpus, payload=payload)

        self.assertEqual(report_json_bytes(first), report_json_bytes(second))
        self.assertEqual(1, first["summary"]["passed"])
        self.assertEqual(1, first["sandbox"]["resourcePolicyVersion"])
        self.assertEqual(500, first["sandbox"]["oomScoreAdjustment"])
        case = first["cases"][0]
        self.assertEqual(base64.b64encode(b"<ORACLE>\x00raw").decode(), case["stdout"]["base64"])
        self.assertEqual(base64.b64encode(b"\x00artifact").decode(), case["artifacts"][0]["base64"])

    def test_recorder_preserves_authored_absence_and_discovers_only_undeclared_paths(self) -> None:
        from oracle.behavior_corpus import record_corpus_expectations

        if self.runtime is None:
            self.skipTest("recorder checks require the locked OCI sandbox image")
        contradicted = self.corpus("binary")
        contradicted["cases"][0]["expected"]["artifacts"] = [
            absent_artifact("result.bin")
        ]
        with self.assertRaisesRegex(BehaviorCorpusError, "authored-absent artifact appeared"):
            record_corpus_expectations(
                contradicted,
                self.executable,
                container_runtime=self.runtime,
                container_runtime_environment=self.runtime_environment,
            )

        discover = self.corpus("extra")
        discover["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b""),
            "stderr": stream(b""),
            "artifacts": [absent_artifact("result.bin")],
        }
        recorded = record_corpus_expectations(
            discover,
            self.executable,
            container_runtime=self.runtime,
            container_runtime_environment=self.runtime_environment,
        )
        artifacts = {
            item["path"]: item
            for item in recorded["cases"][0]["expected"]["artifacts"]
        }
        self.assertFalse(artifacts["result.bin"]["present"])
        self.assertTrue(artifacts["surprise.bin"]["present"])

    def test_environment_is_exact_and_clears_host_and_image_values(self) -> None:
        corpus = self.corpus("env")
        corpus["cases"][0]["environment"] = {
            "IMAGE_ENVIRONMENT_SENTINEL": self.image_environment_sentinel
        }
        corpus["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b""),
            "stderr": stream(b""),
            "artifacts": [absent_artifact("result.bin")],
        }
        import os

        previous = os.environ.get("BEHAVIOR_CORPUS_SECRET")
        os.environ["BEHAVIOR_CORPUS_SECRET"] = "must-not-leak"
        try:
            report = self.run_fixture_corpus(corpus)
        finally:
            if previous is None:
                os.environ.pop("BEHAVIOR_CORPUS_SECRET", None)
            else:
                os.environ["BEHAVIOR_CORPUS_SECRET"] = previous
        self.assertEqual("passed", report["cases"][0]["status"])

    def test_executable_hash_is_authenticated_before_execution(self) -> None:
        corpus = self.corpus()
        corpus["executable"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(BehaviorCorpusError, "executable SHA-256"):
            self.run_fixture_corpus(corpus)

    def test_expected_stream_mutation_fails_closed(self) -> None:
        corpus = self.corpus()
        corpus["cases"][0]["expected"]["stdout"] = stream(
            b"wrong", "stdout-oracle"
        )
        with self.assertRaisesRegex(BehaviorCorpusError, "stdout byte length mismatch"):
            self.run_fixture_corpus(corpus)

    def test_unobserved_artifact_fails_closed(self) -> None:
        corpus = self.corpus("extra")
        corpus["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b""),
            "stderr": stream(b""),
            "artifacts": [absent_artifact("result.bin")],
        }
        with self.assertRaisesRegex(BehaviorCorpusError, "unobserved artifacts"):
            self.run_fixture_corpus(corpus)

    def test_unobserved_directory_fails_closed(self) -> None:
        corpus = self.corpus("directory")
        corpus["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b""),
            "stderr": stream(b""),
            "artifacts": [absent_artifact("result.bin")],
        }
        with self.assertRaisesRegex(BehaviorCorpusError, "unobserved directory"):
            self.run_fixture_corpus(corpus)

    def test_missing_image_and_symlinked_control_client_fail_before_execution(self) -> None:
        corpus = self.corpus("stable")
        corpus["sandbox"]["imageDigest"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(BehaviorCorpusError, "image inspection failed"):
            self.run_fixture_corpus(corpus)

        if self.runtime is None:
            self.skipTest("control-client symlink check requires a container runtime")
        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / "runtime"
            link.symlink_to(self.runtime)
            with self.assertRaisesRegex(BehaviorCorpusError, "container runtime client"):
                run_corpus(
                    self.corpus(),
                    self.executable,
                    container_runtime=link,
                    container_runtime_environment=self.runtime_environment,
                )

        identity = self.corpus()
        identity["sandbox"]["controlClient"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(BehaviorCorpusError, "client identity"):
            self.run_fixture_corpus(identity)

    def test_image_declared_volumes_are_rejected_by_runtime_authentication(self) -> None:
        from oracle.behavior_corpus import (
            _engine_components_sha256,
            _verify_oci_runtime,
        )

        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            runtime.write_bytes(b"fixture-runtime")
            runtime.chmod(0o500)
            sandbox = copy.deepcopy(self.corpus()["sandbox"])
            sandbox["controlClient"] = {
                "bytes": len(b"fixture-runtime"),
                "sha256": hashlib.sha256(b"fixture-runtime").hexdigest(),
                "version": "fixture version\n",
            }
            engine = sandbox["engineProfile"]
            runtime_features = "fixture runtime features"
            engine["containerRuntimeFeaturesSha256"] = hashlib.sha256(
                runtime_features.encode("utf-8")
            ).hexdigest()
            mock_components = [
                {
                    "Name": "Engine",
                    "Version": engine["serverVersion"],
                    "Details": {
                        "GitCommit": engine["serverCommit"],
                        "KernelVersion": engine["kernelVersion"],
                    },
                },
                {
                    "Name": engine["containerRuntime"],
                    "Version": engine["containerRuntimeVersion"],
                    "Details": {"GitCommit": engine["containerRuntimeCommit"]},
                }
            ]
            engine["componentsSha256"] = _engine_components_sha256(mock_components)
            image = [
                {
                    "Id": sandbox["imageDigest"],
                    "Os": "linux",
                    "Architecture": "amd64",
                    "Config": {
                        "Env": sandbox["imageEnvironment"],
                        "Volumes": {"/implicit": {}},
                    },
                }
            ]
            outputs = [
                b"fixture version\n",
                json.dumps(
                    {
                        "Platform": {"Name": engine["product"]},
                        "Version": engine["serverVersion"],
                        "GitCommit": engine["serverCommit"],
                        "ApiVersion": engine["apiVersion"],
                        "Os": engine["operatingSystem"],
                        "Arch": engine["architecture"],
                        "KernelVersion": engine["kernelVersion"],
                        "Components": mock_components,
                    }
                ).encode("utf-8"),
                (
                    json.dumps(engine["securityOptions"])
                    + f"\n{engine['cgroupVersion']}"
                    + f"\n{engine['cgroupDriver']}"
                    + f"\n{engine['storageDriver']}"
                    + f"\n{json.dumps([engine['volumePlugin']])}"
                    + "\n"
                    + json.dumps(
                        {
                            engine["containerRuntime"]: {
                                "path": engine["containerRuntimePath"],
                                "status": {
                                    "org.opencontainers.runtime-spec.features": runtime_features
                                },
                            }
                        }
                    )
                ).encode("utf-8"),
                json.dumps(image).encode("utf-8"),
            ]
            with mock.patch(
                "oracle.behavior_corpus._run_control_command", side_effect=outputs
            ):
                with self.assertRaisesRegex(BehaviorCorpusError, "implicit volumes"):
                    _verify_oci_runtime(runtime, {}, sandbox)

            image[0]["Config"] = {
                "Env": [*sandbox["imageEnvironment"], "UNDECLARED_IMAGE_VALUE=leak"],
                "Volumes": None,
            }
            outputs[-1] = json.dumps(image).encode("utf-8")
            with mock.patch(
                "oracle.behavior_corpus._run_control_command", side_effect=outputs
            ):
                with self.assertRaisesRegex(
                    BehaviorCorpusError, "prelaunch environment"
                ):
                    _verify_oci_runtime(runtime, {}, sandbox)

            image[0]["Config"] = {
                "Env": sandbox["imageEnvironment"],
                "Volumes": None,
            }
            baseline_identity = outputs[1]
            baseline_security = outputs[2]
            mismatched_identity = json.loads(baseline_identity.decode("utf-8"))
            mismatched_identity["KernelVersion"] = "different-kernel"
            next(
                component
                for component in mismatched_identity["Components"]
                if component["Name"] == "Engine"
            )["Details"]["KernelVersion"] = "different-kernel"
            outputs[1] = json.dumps(mismatched_identity).encode("utf-8")
            outputs[-1] = json.dumps(image).encode("utf-8")
            with mock.patch(
                "oracle.behavior_corpus._run_control_command", side_effect=outputs
            ):
                with self.assertRaises(ExactExecutorProfileMismatch):
                    _verify_oci_runtime(runtime, {}, sandbox)

            inconsistent_kernel = json.loads(baseline_identity.decode("utf-8"))
            next(
                component
                for component in inconsistent_kernel["Components"]
                if component["Name"] == "Engine"
            )["Details"]["KernelVersion"] = "contradictory-component-kernel"
            outputs[1] = json.dumps(inconsistent_kernel).encode("utf-8")
            with mock.patch(
                "oracle.behavior_corpus._run_control_command", side_effect=outputs
            ):
                with self.assertRaises(BehaviorCorpusError) as inconsistent:
                    _verify_oci_runtime(runtime, {}, sandbox)
            self.assertNotIsInstance(
                inconsistent.exception, ExactExecutorProfileMismatch
            )

            missing_engine = json.loads(baseline_identity.decode("utf-8"))
            missing_engine["Components"] = [
                component
                for component in missing_engine["Components"]
                if component["Name"] != "Engine"
            ]
            outputs[1] = json.dumps(missing_engine).encode("utf-8")
            with mock.patch(
                "oracle.behavior_corpus._run_control_command", side_effect=outputs
            ):
                with self.assertRaises(BehaviorCorpusError) as missing_engine_error:
                    _verify_oci_runtime(runtime, {}, sandbox)
            self.assertNotIsInstance(
                missing_engine_error.exception, ExactExecutorProfileMismatch
            )

            wrong_operating_system = json.loads(baseline_identity.decode("utf-8"))
            wrong_operating_system["Os"] = "windows"
            outputs[1] = json.dumps(wrong_operating_system).encode("utf-8")
            with mock.patch(
                "oracle.behavior_corpus._run_control_command", side_effect=outputs
            ):
                with self.assertRaises(BehaviorCorpusError) as missing_linux:
                    _verify_oci_runtime(runtime, {}, sandbox)
            self.assertNotIsInstance(
                missing_linux.exception, ExactExecutorProfileMismatch
            )

            outputs[1] = b"not-json"
            with mock.patch(
                "oracle.behavior_corpus._run_control_command", side_effect=outputs
            ):
                with self.assertRaises(BehaviorCorpusError) as malformed:
                    _verify_oci_runtime(runtime, {}, sandbox)
            self.assertNotIsInstance(
                malformed.exception, ExactExecutorProfileMismatch
            )

            outputs[1] = baseline_identity
            security_lines = baseline_security.decode("utf-8").splitlines()
            security_lines[0] = json.dumps(
                [
                    option
                    for option in engine["securityOptions"]
                    if option != "name=seccomp,profile=builtin"
                ]
            )
            outputs[2] = ("\n".join(security_lines) + "\n").encode("utf-8")
            with mock.patch(
                "oracle.behavior_corpus._run_control_command", side_effect=outputs
            ):
                with self.assertRaises(BehaviorCorpusError) as missing_security:
                    _verify_oci_runtime(runtime, {}, sandbox)
            self.assertNotIsInstance(
                missing_security.exception, ExactExecutorProfileMismatch
            )

            security_lines = baseline_security.decode("utf-8").splitlines()
            security_lines[1] = "1"
            outputs[2] = ("\n".join(security_lines) + "\n").encode("utf-8")
            with mock.patch(
                "oracle.behavior_corpus._run_control_command", side_effect=outputs
            ):
                with self.assertRaises(BehaviorCorpusError) as missing_cgroup_v2:
                    _verify_oci_runtime(runtime, {}, sandbox)
            self.assertNotIsInstance(
                missing_cgroup_v2.exception, ExactExecutorProfileMismatch
            )

            security_lines = baseline_security.decode("utf-8").splitlines()
            security_lines[4] = "[]"
            outputs[2] = ("\n".join(security_lines) + "\n").encode("utf-8")
            with mock.patch(
                "oracle.behavior_corpus._run_control_command", side_effect=outputs
            ):
                with self.assertRaises(BehaviorCorpusError) as missing_volume:
                    _verify_oci_runtime(runtime, {}, sandbox)
            self.assertNotIsInstance(
                missing_volume.exception, ExactExecutorProfileMismatch
            )
            outputs[2] = baseline_security

            with mock.patch(
                "oracle.behavior_corpus._run_control_command",
                side_effect=BehaviorCorpusError("daemon unavailable"),
            ):
                with self.assertRaises(BehaviorCorpusError) as daemon_failure:
                    _verify_oci_runtime(runtime, {}, sandbox)
            self.assertNotIsInstance(
                daemon_failure.exception, ExactExecutorProfileMismatch
            )

    def test_engine_component_digest_excludes_only_declared_volatile_fields(self) -> None:
        first = [
            {
                "Name": "Engine",
                "Version": "1",
                "Details": {
                    "GitCommit": "abc",
                    "KernelVersion": "kernel-a",
                },
            },
            {
                "Name": "rootlesskit",
                "Version": "2",
                "Details": {"StateDir": "/volatile/a"},
            },
            {"Name": "runc", "Version": "3", "Details": {}},
        ]
        reordered = copy.deepcopy(list(reversed(first)))
        next(item for item in reordered if item["Name"] == "Engine")["Details"][
            "KernelVersion"
        ] = "kernel-b"
        next(
            item for item in reordered if item["Name"] == "rootlesskit"
        )["Details"]["StateDir"] = "/volatile/b"
        self.assertEqual(
            _engine_components_sha256(first),
            _engine_components_sha256(reordered),
        )
        changed = copy.deepcopy(first)
        changed[0]["Details"]["GitCommit"] = "different"
        self.assertNotEqual(
            _engine_components_sha256(first),
            _engine_components_sha256(changed),
        )
        wrong_component_kernel = copy.deepcopy(first)
        wrong_component_kernel[2]["Details"]["KernelVersion"] = "not-excluded"
        self.assertNotEqual(
            _engine_components_sha256(first),
            _engine_components_sha256(wrong_component_kernel),
        )
        wrong_component_state = copy.deepcopy(first)
        wrong_component_state[0]["Details"]["StateDir"] = "not-excluded"
        self.assertNotEqual(
            _engine_components_sha256(first),
            _engine_components_sha256(wrong_component_state),
        )
        for malformed_details in ([], "", 0):
            malformed = copy.deepcopy(first)
            malformed[0]["Details"] = malformed_details
            with self.subTest(malformed_details=malformed_details):
                with self.assertRaisesRegex(BehaviorCorpusError, "must be an object"):
                    _engine_components_sha256(malformed)
        malformed_excluded_value = copy.deepcopy(first)
        malformed_excluded_value[0]["Details"]["KernelVersion"] = 7
        with self.assertRaisesRegex(BehaviorCorpusError, "KernelVersion"):
            _engine_components_sha256(malformed_excluded_value)
        duplicate_engine = copy.deepcopy(first)
        duplicate_engine.append(copy.deepcopy(first[0]))
        with self.assertRaisesRegex(BehaviorCorpusError, "duplicate names"):
            _engine_components_sha256(duplicate_engine)

    def test_tmpfs_volume_quota_options_are_exact_and_inspected(self) -> None:
        from oracle.behavior_corpus import _create_workspace_volume, _limits

        limits = _limits(self.corpus()["limits"])
        name = "behavior-corpus-volume-" + ("1" * 32)
        expected_option = (
            f"size={limits.workspace_bytes},nr_inodes={limits.workspace_entries},"
            "nosuid,nodev,uid=65534,gid=65534,mode=0700"
        )
        record = {
            "Name": name,
            "Driver": "local",
            "Scope": "local",
            "Options": {
                "type": "tmpfs",
                "device": "tmpfs",
                "o": expected_option.replace(",nodev", ""),
            },
            "Labels": None,
            "Mountpoint": "/authenticated/runtime/volume",
        }
        commands: list[list[str]] = []

        def result(
            arguments: list[str], _environment: dict[str, str], _label: str
        ) -> bytes:
            commands.append(list(arguments))
            if arguments[1:3] == ["volume", "create"]:
                return (name + "\n").encode("ascii")
            return json.dumps([record]).encode("utf-8")

        with mock.patch(
            "oracle.behavior_corpus._run_control_command", side_effect=result
        ):
            with self.assertRaisesRegex(BehaviorCorpusError, "exact bounded tmpfs"):
                _create_workspace_volume(
                    Path("/runtime"), {}, name, limits, 65534, 65534
                )
        create = commands[0]
        self.assertIn("--opt=type=tmpfs", create)
        self.assertIn("--opt=device=tmpfs", create)
        self.assertIn(f"--opt=o={expected_option}", create)

    def test_artifact_special_mode_bits_are_rejected(self) -> None:
        corpus = self.corpus("special-mode")
        corpus["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b""),
            "stderr": stream(b""),
            "artifacts": [artifact("result.bin", b"special")],
        }
        with self.assertRaisesRegex(BehaviorCorpusError, "forbidden special mode"):
            self.run_fixture_corpus(corpus)

    def test_mutated_input_fails_closed(self) -> None:
        corpus = self.corpus("mutate")
        corpus["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b""),
            "stderr": stream(b""),
            "artifacts": [absent_artifact("result.bin")],
        }
        with self.assertRaisesRegex(BehaviorCorpusError, "staged input was mutated"):
            self.run_fixture_corpus(corpus)

    def test_timeout_and_capture_limits_terminate_the_process(self) -> None:
        timed = self.corpus("hang")
        timed["limits"]["timeoutMilliseconds"] = 500
        timed["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b""),
            "stderr": stream(b""),
            "artifacts": [absent_artifact("result.bin")],
        }
        cleanup_token = "a" * 32
        with mock.patch(
            "oracle.behavior_corpus.secrets.token_hex", return_value=cleanup_token
        ):
            with self.assertRaisesRegex(BehaviorCorpusError, "exceeded"):
                self.run_fixture_corpus(timed)
        if self.runtime is not None:
            for role in ("keeper", "setup", "target", "collector"):
                inspected = subprocess.run(
                    [
                        os.fspath(self.runtime),
                        "container",
                        "inspect",
                        f"behavior-corpus-{role}-{cleanup_token}",
                    ],
                    env=self.runtime_environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(0, inspected.returncode)
            inspected_volume = subprocess.run(
                [
                    os.fspath(self.runtime),
                    "volume",
                    "inspect",
                    f"behavior-corpus-volume-{cleanup_token}",
                ],
                env=self.runtime_environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(0, inspected_volume.returncode)

        noisy = self.corpus("noisy")
        noisy["limits"]["stdoutBytes"] = 8
        noisy["cases"][0]["expected"] = copy.deepcopy(timed["cases"][0]["expected"])
        with self.assertRaisesRegex(BehaviorCorpusError, "exceeded"):
            self.run_fixture_corpus(noisy)

    def test_normalization_must_be_field_scoped_and_match(self) -> None:
        from oracle.behavior_corpus import _Normalization, _normalize_stream

        corpus = self.corpus("stable")
        corpus["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b"stable", "stdout-oracle"),
            "stderr": stream(b""),
            "artifacts": [absent_artifact("result.bin")],
        }
        with self.assertRaisesRegex(BehaviorCorpusError, "did not match stdout"):
            self.run_fixture_corpus(corpus)

        wrong_field = self.corpus()
        wrong_field["cases"][0]["expected"]["stdout"]["normalizations"] = [
            "stderr-workspace"
        ]
        with self.assertRaisesRegex(BehaviorCorpusError, "wrong-field normalization"):
            validate_corpus(wrong_field)

        with self.assertRaisesRegex(BehaviorCorpusError, "normalized stdout exceeded"):
            _normalize_stream(
                b"/oracle/oracle",
                "stdout",
                ["expand"],
                {
                    "expand": _Normalization(
                        identifier="expand",
                        field="stdout",
                        runtime_path="oracle",
                        replacement=b"x" * 16,
                    )
                },
                {"oracle": Path("/oracle")},
                16,
            )

    def test_preexec_control_frames_are_nonce_bound_and_unobservable(self) -> None:
        from oracle.behavior_corpus import (
            _PreexecFrameReader,
            _consume_preexec_frame,
            _limits,
            _preexec_frame,
            _wrapped_command,
        )

        nonce = "1" * 32
        marker = _preexec_frame("target", nonce)
        reader = _PreexecFrameReader("target", nonce)
        for index, byte in enumerate(marker):
            complete = reader.feed(bytes([byte]))
            self.assertEqual(index == len(marker) - 1, complete)
        self.assertEqual(b"payload", _consume_preexec_frame(marker + b"payload", "target", nonce))

        malformed = {
            "missing": b"target output",
            "duplicate": marker + marker,
            "wrong role": _preexec_frame("setup", nonce),
            "wrong nonce": _preexec_frame("target", "2" * 32),
            "target spoof": marker + b"target" + _preexec_frame("target", "3" * 32),
        }
        for label, payload in malformed.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(BehaviorCorpusError, "pre-exec frame"):
                    _consume_preexec_frame(payload, "target", nonce)

        corpus = self.corpus()
        wrapped = _wrapped_command(
            corpus["sandbox"],
            "target",
            nonce,
            _limits(corpus["limits"]),
            ["-i", "VISIBLE=value", "/oracle", "stable"],
        )
        exec_index = wrapped.index("--") + 1
        self.assertIn(nonce, wrapped[:exec_index])
        self.assertNotIn(nonce, wrapped[exec_index:])

        spoof = self.corpus("spoof")
        spoof["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b""),
            "stderr": stream(b""),
            "artifacts": [absent_artifact("result.bin")],
        }
        with self.assertRaisesRegex(BehaviorCorpusError, "spoofed pre-exec frame"):
            self.run_fixture_corpus(spoof)

        import oracle.behavior_corpus as runner

        real_wrapped_command = runner._wrapped_command

        def wrong_target_memory(
            sandbox: dict[str, object],
            role: str,
            launch_nonce: str,
            limits: object,
            command: list[str],
        ) -> list[str]:
            result = real_wrapped_command(
                sandbox, role, launch_nonce, limits, command
            )
            if role == "target":
                contract = result.index("behavior-preexec-v1")
                result[contract + 3] = str(int(result[contract + 3]) + 1)
            return result

        with mock.patch.object(
            runner, "_wrapped_command", side_effect=wrong_target_memory
        ):
            with self.assertRaisesRegex(BehaviorCorpusError, "pre-exec frame"):
                self.run_fixture_corpus(self.corpus("stable"))

        def wrong_target_oom_adjustment(
            sandbox: dict[str, object],
            role: str,
            launch_nonce: str,
            limits: object,
            command: list[str],
        ) -> list[str]:
            result = real_wrapped_command(
                sandbox, role, launch_nonce, limits, command
            )
            if role == "target":
                contract = result.index("behavior-preexec-v1")
                result[contract + 11] = str(int(result[contract + 11]) + 1)
            return result

        with mock.patch.object(
            runner, "_wrapped_command", side_effect=wrong_target_oom_adjustment
        ):
            with self.assertRaisesRegex(BehaviorCorpusError, "pre-exec frame"):
                self.run_fixture_corpus(self.corpus("stable"))

    def test_paths_placeholders_ordering_and_absence_shapes_are_strict(self) -> None:
        traversal = self.corpus()
        traversal["cases"][0]["inputs"][0]["path"] = "../escape"
        with self.assertRaisesRegex(BehaviorCorpusError, "normalized relative"):
            validate_corpus(traversal)

        placeholder = self.corpus()
        placeholder["cases"][0]["arguments"].append("{home}")
        with self.assertRaisesRegex(BehaviorCorpusError, "unknown runtime placeholder"):
            validate_corpus(placeholder)

        malformed_absence = self.corpus()
        malformed_absence["cases"][0]["expected"]["artifacts"] = [
            {**absent_artifact("missing"), "bytes": 0}
        ]
        with self.assertRaisesRegex(BehaviorCorpusError, "must use null"):
            validate_corpus(malformed_absence)

        unreadable = self.corpus()
        unreadable["cases"][0]["expected"]["artifacts"] = [
            artifact("result.bin", b"payload", mode="0o000")
        ]
        with self.assertRaisesRegex(BehaviorCorpusError, "owner-readable"):
            validate_corpus(unreadable)

        wrong_resource_policy = self.corpus()
        wrong_resource_policy["sandbox"]["resourcePolicyVersion"] = 2
        with self.assertRaisesRegex(BehaviorCorpusError, "resourcePolicyVersion"):
            validate_corpus(wrong_resource_policy)

        wrong_oom_adjustment = self.corpus()
        wrong_oom_adjustment["sandbox"]["oomScoreAdjustment"] = 0
        with self.assertRaisesRegex(BehaviorCorpusError, "oomScoreAdjustment"):
            validate_corpus(wrong_oom_adjustment)

    def test_prelaunch_environment_and_global_category_bound_fail_closed(self) -> None:
        dangerous = self.corpus()
        dangerous["sandbox"]["imageEnvironment"].append("LD_PRELOAD=/tmp/hook.so")
        with self.assertRaisesRegex(BehaviorCorpusError, "forbidden prelaunch"):
            validate_corpus(dangerous)

        duplicated = self.corpus()
        duplicated["sandbox"]["imageEnvironment"].append("PATH=/different")
        with self.assertRaisesRegex(BehaviorCorpusError, "duplicate variable"):
            validate_corpus(duplicated)

        categories = self.corpus("stable")
        template = categories["cases"][0]
        categories["cases"] = []
        for case_index in range(9):
            record = copy.deepcopy(template)
            record["id"] = f"case-{case_index:03d}"
            record["categories"] = [
                f"category-{case_index:03d}-{index:03d}" for index in range(32)
            ]
            categories["cases"].append(record)
        with self.assertRaisesRegex(BehaviorCorpusError, "global limit"):
            validate_corpus(categories)

        oversized_input = self.corpus()
        oversized_input["cases"][0]["inputs"][0].update(blob(b"x" * 4097))
        with self.assertRaisesRegex(BehaviorCorpusError, "limits.fileBytes"):
            validate_corpus(oversized_input)

        oversized_expectation = self.corpus()
        oversized_expectation["limits"]["stdoutBytes"] = 1
        with self.assertRaisesRegex(BehaviorCorpusError, "between 0 and 1"):
            validate_corpus(oversized_expectation)

    def test_workspace_traversal_enforces_entry_and_byte_budgets_incrementally(self) -> None:
        from oracle.behavior_corpus import _limits, _verify_workspace_tree

        entry_limits = copy.deepcopy(self.corpus()["limits"])
        entry_limits["workspaceEntries"] = 2
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            for name in ("one", "two", "three"):
                (workspace / name).write_bytes(b"")
            with self.assertRaisesRegex(BehaviorCorpusError, "workspaceEntries"):
                _verify_workspace_tree(
                    workspace,
                    {},
                    None,
                    set(),
                    _limits(entry_limits),
                )

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            names = {"one", "two", "three"}
            for name in names:
                (workspace / name).mkdir()
            with self.assertRaisesRegex(BehaviorCorpusError, "workspaceEntries"):
                _verify_workspace_tree(
                    workspace,
                    {},
                    None,
                    names,
                    _limits(entry_limits),
                )

        byte_limits = copy.deepcopy(self.corpus()["limits"])
        byte_limits.update(
            {"artifactBytes": 4096, "fileBytes": 4096, "workspaceBytes": 4096}
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            oversized = workspace / "sparse"
            with oversized.open("wb") as output:
                output.truncate(8192)
            with self.assertRaisesRegex(BehaviorCorpusError, "workspaceBytes"):
                _verify_workspace_tree(
                    workspace,
                    {},
                    None,
                    set(),
                    _limits(byte_limits),
                )

    def test_reports_are_closed_and_cross_validated_before_serialization(self) -> None:
        corpus = self.corpus("stable")
        case = corpus["cases"][0]
        corpus_payload = corpus_json_bytes(corpus)
        report = {
            "schemaVersion": 1,
            "corpus": {
                "id": corpus["id"],
                "sha256": hashlib.sha256(corpus_payload).hexdigest(),
            },
            "executable": copy.deepcopy(corpus["executable"]),
            "sandbox": copy.deepcopy(corpus["sandbox"]),
            "limits": copy.deepcopy(corpus["limits"]),
            "summary": {
                "cases": 1,
                "passed": 1,
                "categories": copy.deepcopy(case["categories"]),
            },
            "cases": [
                {
                    "id": case["id"],
                    "status": "passed",
                    "exitCode": case["expected"]["exitCode"],
                    "stdout": copy.deepcopy(case["expected"]["stdout"]),
                    "stderr": copy.deepcopy(case["expected"]["stderr"]),
                    "artifacts": copy.deepcopy(case["expected"]["artifacts"]),
                }
            ],
        }
        self.assertIs(report, validate_report(report))
        self.assertIs(
            report,
            validate_corpus_report_pair(
                corpus,
                report,
                corpus_payload=corpus_payload,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            canonical_report = report_json_bytes(report)
            report_path.write_bytes(canonical_report)
            loaded_report, loaded_payload = load_report(report_path)
            self.assertEqual(report, loaded_report)
            self.assertEqual(canonical_report, loaded_payload)
            report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(BehaviorCorpusError, "must use canonical"):
                load_report(report_path)
        malformed = copy.deepcopy(report)
        malformed["summary"]["passed"] = 2
        with self.assertRaisesRegex(BehaviorCorpusError, "summary counts"):
            report_json_bytes(malformed)
        too_many_categories = copy.deepcopy(report)
        too_many_categories["summary"]["categories"] = [
            f"category-{index:03d}" for index in range(257)
        ]
        with self.assertRaisesRegex(BehaviorCorpusError, "limit of 256"):
            report_json_bytes(too_many_categories)

        stream_limit = copy.deepcopy(report)
        stream_limit["limits"]["stdoutBytes"] = (
            stream_limit["cases"][0]["stdout"]["bytes"] - 1
        )
        with self.assertRaisesRegex(BehaviorCorpusError, "between 0 and"):
            validate_report(stream_limit)

        artifact_limit = copy.deepcopy(report)
        artifact_limit["limits"]["artifactBytes"] = (
            artifact_limit["cases"][0]["artifacts"][0]["bytes"] - 1
        )
        with self.assertRaisesRegex(BehaviorCorpusError, "between 0 and"):
            validate_report(artifact_limit)

        for label, mutate, pattern in (
            (
                "corpus bytes",
                lambda item: item["corpus"].update({"sha256": "f" * 64}),
                "exact reviewed corpus bytes",
            ),
            (
                "executable",
                lambda item: item["executable"].update({"sha256": "e" * 64}),
                "executable does not match",
            ),
            (
                "sandbox",
                lambda item: item["sandbox"].update({"platform": "linux/arm64"}),
                "sandbox does not match",
            ),
            (
                "limits",
                lambda item: item["limits"].update({"stdoutBytes": 4095}),
                "limits does not match",
            ),
            (
                "case IDs",
                lambda item: item["cases"][0].update({"id": "different-case"}),
                "ordered case IDs",
            ),
            (
                "categories",
                lambda item: item["summary"].update(
                    {"categories": ["different-category"]}
                ),
                "category union",
            ),
            (
                "observation",
                lambda item: item["cases"][0].update({"exitCode": 1}),
                "exitCode does not match",
            ),
        ):
            with self.subTest(label=label):
                changed = copy.deepcopy(report)
                mutate(changed)
                with self.assertRaisesRegex(BehaviorCorpusError, pattern):
                    validate_corpus_report_pair(
                        corpus,
                        changed,
                        corpus_payload=corpus_payload,
                    )

    def test_control_capture_is_bounded_while_the_command_runs(self) -> None:
        from oracle.behavior_corpus import _run_control_command

        with tempfile.TemporaryDirectory() as temporary:
            command = Path(temporary) / "noisy-control"
            command.write_text(
                "#!/usr/bin/python3\nimport os\nwhile True: os.write(1, b'x' * 65536)\n",
                encoding="utf-8",
            )
            command.chmod(0o500)
            with self.assertRaisesRegex(BehaviorCorpusError, "exceeded"):
                _run_control_command([os.fspath(command)], {}, "noisy control")

    def test_post_spawn_io_failure_reaps_the_control_process(self) -> None:
        from oracle.behavior_corpus import _control_limits, _execute_bounded

        real_popen = subprocess.Popen
        spawned: list[subprocess.Popen[bytes]] = []

        def capture_popen(*arguments: object, **keywords: object) -> subprocess.Popen[bytes]:
            process = real_popen(*arguments, **keywords)
            spawned.append(process)
            return process

        with mock.patch(
            "oracle.behavior_corpus.subprocess.Popen", side_effect=capture_popen
        ), mock.patch(
            "oracle.behavior_corpus.os.set_blocking",
            side_effect=OSError("simulated pipe setup failure"),
        ):
            with self.assertRaisesRegex(
                BehaviorCorpusError, "simulated pipe setup failure"
            ) as caught:
                _execute_bounded(
                    ["/usr/bin/python3", "-c", "while True: pass"],
                    cwd=Path("/"),
                    environment={},
                    stdin=b"",
                    limits=_control_limits(),
                    apply_process_limits=False,
                )
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertEqual(1, len(spawned))
        self.assertIsNotNone(spawned[0].returncode)

    def test_cleanup_retries_after_a_control_timeout_and_proves_absence(self) -> None:
        from oracle.behavior_corpus import (
            _ControlOperationUncertain,
            _create_workspace_volume,
            _limits,
            _remove_container,
            _remove_volume,
        )

        calls: list[list[str]] = []
        failed_once = False

        def container_result(
            arguments: list[str], _environment: dict[str, str], _label: str
        ) -> tuple[int, bytes, bytes]:
            nonlocal failed_once
            calls.append(list(arguments))
            if arguments[1:3] == ["rm", "--force"] and not failed_once:
                failed_once = True
                raise BehaviorCorpusError("simulated timeout")
            if arguments[1:3] == ["container", "inspect"]:
                return 1, b"", b"No such container"
            return 0, b"", b""

        with mock.patch(
            "oracle.behavior_corpus._run_control_command_result",
            side_effect=container_result,
        ):
            _remove_container(Path("/runtime"), {}, "f" * 64, "fallback-name")
        self.assertTrue(any(command[-1] == "fallback-name" for command in calls))
        self.assertTrue(any(command[1:3] == ["container", "inspect"] for command in calls))

        def volume_result(
            arguments: list[str], _environment: dict[str, str], _label: str
        ) -> tuple[int, bytes, bytes]:
            if arguments[1:3] == ["volume", "rm"]:
                raise BehaviorCorpusError("simulated timeout")
            return 1, b"", b"No such volume"

        with mock.patch(
            "oracle.behavior_corpus._run_control_command_result",
            side_effect=volume_result,
        ):
            _remove_volume(Path("/runtime"), {}, "fallback-volume")

        class Clock:
            now = 0.0

            def monotonic(self) -> float:
                return self.now

            def sleep(self, duration: float) -> None:
                self.now += duration

        for kind in ("container", "volume"):
            with self.subTest(delayed_kind=kind):
                clock = Clock()
                inspections = 0
                appeared = False
                removed_after_appearance = False

                def delayed_result(
                    arguments: list[str],
                    _environment: dict[str, str],
                    _label: str,
                ) -> tuple[int, bytes, bytes]:
                    nonlocal inspections, appeared, removed_after_appearance
                    is_inspect = (
                        arguments[1:3] == ["container", "inspect"]
                        if kind == "container"
                        else arguments[1:3] == ["volume", "inspect"]
                    )
                    if is_inspect:
                        inspections += 1
                        if inspections == 3:
                            appeared = True
                            return 0, b"[]", b""
                        marker = (
                            b"No such container"
                            if kind == "container"
                            else b"No such volume"
                        )
                        return 1, b"", marker
                    if appeared:
                        removed_after_appearance = True
                        appeared = False
                    return 0, b"", b""

                with mock.patch(
                    "oracle.behavior_corpus._run_control_command_result",
                    side_effect=delayed_result,
                ), mock.patch(
                    "oracle.behavior_corpus.time.monotonic",
                    side_effect=clock.monotonic,
                ), mock.patch(
                    "oracle.behavior_corpus.time.sleep",
                    side_effect=clock.sleep,
                ):
                    if kind == "container":
                        _remove_container(
                            Path("/runtime"),
                            {},
                            None,
                            "delayed-container",
                            settle_until=1.0,
                        )
                    else:
                        _remove_volume(
                            Path("/runtime"),
                            {},
                            "delayed-volume",
                            settle_until=1.0,
                        )
                self.assertGreaterEqual(clock.now, 1.0)
                self.assertTrue(removed_after_appearance)

        failed_clock = Clock()
        with mock.patch(
            "oracle.behavior_corpus._run_control_command_result",
            side_effect=BehaviorCorpusError("control client unavailable"),
        ), mock.patch(
            "oracle.behavior_corpus.time.monotonic",
            side_effect=failed_clock.monotonic,
        ), mock.patch(
            "oracle.behavior_corpus.time.sleep",
            side_effect=failed_clock.sleep,
        ):
            with self.assertRaisesRegex(BehaviorCorpusError, "did not prove"):
                _remove_volume(Path("/runtime"), {}, "uninspectable-volume")
        self.assertLess(failed_clock.now, 1.0)

        create_uncertain = _ControlOperationUncertain("timed out create")
        with mock.patch(
            "oracle.behavior_corpus._run_control_command",
            side_effect=create_uncertain,
        ):
            with self.assertRaises(_ControlOperationUncertain) as uncertain:
                _create_workspace_volume(
                    Path("/runtime"),
                    {},
                    "uncertain-volume",
                    _limits(self.corpus()["limits"]),
                    65534,
                    65534,
                )
        self.assertIs(uncertain.exception, create_uncertain)

    def test_every_interrupted_create_gets_a_full_residue_settlement_window(self) -> None:
        from oracle.behavior_corpus import (
            CREATE_PUBLICATION_SETTLEMENT_SECONDS,
            _RetentionBudget,
            _limits,
            _normalization_map,
            _run_case,
        )

        corpus = validate_corpus(self.corpus("stable"))
        for kind, primary in (
            ("volume", KeyboardInterrupt("cancelled volume create")),
            ("container", SystemExit(73)),
        ):
            with self.subTest(kind=kind):
                container_deadlines: list[float | None] = []
                volume_deadlines: list[float | None] = []

                def create_volume(*_args: object, **_kwargs: object) -> str:
                    if kind == "volume":
                        raise primary
                    return "/run/user/1000/docker/volumes/fixture/_data"

                def create_container(*_args: object, **_kwargs: object) -> str:
                    raise primary

                def remove_container(
                    *_args: object, settle_until: float | None = None, **_kwargs: object
                ) -> None:
                    container_deadlines.append(settle_until)

                def remove_volume(
                    *_args: object, settle_until: float | None = None, **_kwargs: object
                ) -> None:
                    volume_deadlines.append(settle_until)

                with mock.patch(
                    "oracle.behavior_corpus._create_workspace_volume",
                    side_effect=create_volume,
                ), mock.patch(
                    "oracle.behavior_corpus._create_container",
                    side_effect=create_container,
                ), mock.patch(
                    "oracle.behavior_corpus._remove_container",
                    side_effect=remove_container,
                ), mock.patch(
                    "oracle.behavior_corpus._remove_volume",
                    side_effect=remove_volume,
                ), mock.patch(
                    "oracle.behavior_corpus.time.monotonic", return_value=10.0
                ):
                    with self.assertRaises(type(primary)) as caught:
                        _run_case(
                            corpus,
                            corpus["cases"][0],
                            self.executable_payload,
                            _limits(corpus["limits"]),
                            _normalization_map(corpus),
                            Path("/runtime"),
                            {},
                            _RetentionBudget(),
                        )
                self.assertIs(caught.exception, primary)
                expected_deadline = 10.0 + CREATE_PUBLICATION_SETTLEMENT_SECONDS
                self.assertEqual([expected_deadline] * 4, container_deadlines)
                self.assertEqual([expected_deadline], volume_deadlines)

    def test_create_exception_handler_cannot_take_a_second_cancellation(self) -> None:
        from oracle.behavior_corpus import (
            CREATE_PUBLICATION_SETTLEMENT_SECONDS,
            _ControlOperationUncertain,
            _RetentionBudget,
            _limits,
            _normalization_map,
            _run_case,
        )

        corpus = validate_corpus(self.corpus("stable"))
        primary = _ControlOperationUncertain("first create cancellation")
        clock = mock.Mock(
            side_effect=[10.0, SystemExit("second cancellation in old handler")]
        )
        cleanup_deadlines: list[float | None] = []
        cleanup_targets: list[str] = []

        def remove_container(
            _runtime: Path,
            _environment: dict[str, str],
            _container_id: str | None,
            container_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            cleanup_targets.append(container_name)
            cleanup_deadlines.append(settle_until)

        def remove_volume(
            _runtime: Path,
            _environment: dict[str, str],
            volume_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            cleanup_targets.append(volume_name)
            cleanup_deadlines.append(settle_until)

        with mock.patch(
            "oracle.behavior_corpus._run_control_command", side_effect=primary
        ), mock.patch(
            "oracle.behavior_corpus._remove_container", side_effect=remove_container
        ), mock.patch(
            "oracle.behavior_corpus._remove_volume", side_effect=remove_volume
        ), mock.patch("oracle.behavior_corpus.time.monotonic", side_effect=clock):
            with self.assertRaises(_ControlOperationUncertain) as caught:
                _run_case(
                    corpus,
                    corpus["cases"][0],
                    self.executable_payload,
                    _limits(corpus["limits"]),
                    _normalization_map(corpus),
                    Path("/runtime"),
                    {},
                    _RetentionBudget(),
                )
        self.assertIs(caught.exception, primary)
        self.assertEqual(1, clock.call_count)
        self.assertEqual(5, len(cleanup_targets))
        self.assertEqual(
            [10.0 + CREATE_PUBLICATION_SETTLEMENT_SECONDS] * 5,
            cleanup_deadlines,
        )

    def test_cleanup_cancellation_is_deferred_without_replacing_primary(self) -> None:
        from oracle.behavior_corpus import (
            _RetentionBudget,
            _limits,
            _normalization_map,
            _run_case,
            behavior_error_notes,
        )

        corpus = validate_corpus(self.corpus("stable"))
        primary = BehaviorCorpusError("primary execution failure")
        cleanup_cancel = KeyboardInterrupt("cleanup cancellation")
        container_calls: list[str] = []
        cancelled = False

        def remove_container(
            _runtime: Path,
            _environment: dict[str, str],
            _container_id: str | None,
            container_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            del settle_until
            nonlocal cancelled
            container_calls.append(container_name)
            if not cancelled:
                cancelled = True
                raise cleanup_cancel

        with mock.patch(
            "oracle.behavior_corpus._create_workspace_volume", side_effect=primary
        ), mock.patch(
            "oracle.behavior_corpus._remove_container", side_effect=remove_container
        ), mock.patch("oracle.behavior_corpus._remove_volume") as remove_volume:
            with self.assertRaises(BehaviorCorpusError) as caught:
                _run_case(
                    corpus,
                    corpus["cases"][0],
                    self.executable_payload,
                    _limits(corpus["limits"]),
                    _normalization_map(corpus),
                    Path("/runtime"),
                    {},
                    _RetentionBudget(),
                )
        self.assertIs(caught.exception, primary)
        self.assertEqual(5, len(container_calls))
        remove_volume.assert_called_once()
        self.assertTrue(
            any("cleanup cancellation was deferred" in note for note in behavior_error_notes(primary))
        )

    def test_cleanup_note_and_between_object_cancellation_cannot_escape(self) -> None:
        import inspect
        import sys

        import oracle.behavior_corpus as runner

        corpus = validate_corpus(self.corpus("stable"))
        primary = BehaviorCorpusError("primary execution failure")
        between_objects = SystemExit(81)
        calls: list[str] = []
        source, start_line = inspect.getsourcelines(runner._run_case)
        boundary_lines = [
            start_line + offset
            for offset, line in enumerate(source)
            if line.strip() == "while cleanup_index < len(cleanup_targets):"
        ]
        self.assertEqual(1, len(boundary_lines))
        boundary_hits = 0

        def interrupt_second_boundary(
            frame: Any, event: str, _argument: Any
        ) -> Any:
            nonlocal boundary_hits
            if (
                frame.f_code is runner._run_case.__code__
                and event == "line"
                and frame.f_lineno == boundary_lines[0]
            ):
                boundary_hits += 1
                if boundary_hits == 2:
                    raise between_objects
            return interrupt_second_boundary

        def remove_container(
            _runtime: Path,
            _environment: dict[str, str],
            _container_id: str | None,
            container_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            del settle_until
            role = next(
                role
                for role in ("collector", "target", "setup", "keeper")
                if f"-{role}-" in container_name
            )
            calls.append(role)

        def remove_volume(*_args: object, **_kwargs: object) -> None:
            calls.append("volume")

        try:
            with mock.patch.object(
                runner, "_create_workspace_volume", side_effect=primary
            ), mock.patch.object(
                runner, "_remove_container", side_effect=remove_container
            ), mock.patch.object(
                runner, "_remove_volume", side_effect=remove_volume
            ), mock.patch.object(
                runner,
                "_add_exception_note_no_throw",
                side_effect=KeyboardInterrupt("note bookkeeping cancellation"),
            ):
                sys.settrace(interrupt_second_boundary)
                with self.assertRaises(BehaviorCorpusError) as caught:
                    runner._run_case(
                        corpus,
                        corpus["cases"][0],
                        self.executable_payload,
                        runner._limits(corpus["limits"]),
                        runner._normalization_map(corpus),
                        Path("/runtime"),
                        {},
                        runner._RetentionBudget(),
                    )
        finally:
            sys.settrace(None)
        self.assertIs(caught.exception, primary)
        self.assertEqual(
            ["collector", "target", "setup", "keeper", "volume"],
            calls,
        )
        self.assertEqual(2, boundary_hits)
        self.assertTrue(
            any(
                "target container: SystemExit: 81" in note
                for note in runner.behavior_error_notes(primary)
            )
        )

    def test_repeated_cleanup_bookkeeping_cancellation_is_bounded(self) -> None:
        import inspect
        import sys

        import oracle.behavior_corpus as runner

        corpus = validate_corpus(self.corpus("stable"))
        primary = BehaviorCorpusError("primary execution failure")
        first = KeyboardInterrupt("first bookkeeping cancellation")
        second = SystemExit(98)
        calls: list[str] = []
        injected_count = 0
        source, start_line = inspect.getsourcelines(runner._run_case)
        bookkeeping_lines = [
            start_line + offset
            for offset, line in enumerate(source)
            if line.strip() == "remember_cleanup_exception(label, error)"
        ]
        self.assertEqual(1, len(bookkeeping_lines))

        def interrupt_bookkeeping(
            frame: Any, event: str, _argument: Any
        ) -> Any:
            nonlocal injected_count
            if (
                frame.f_code is runner._run_case.__code__
                and event == "line"
                and frame.f_lineno == bookkeeping_lines[0]
            ):
                sys.settrace(None)
                frame.f_trace = None
                injected_count += 1
                raise second
            return interrupt_bookkeeping

        def remove_container(
            _runtime: Path,
            _environment: dict[str, str],
            _container_id: str | None,
            container_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            del settle_until
            role = next(
                role
                for role in ("collector", "target", "setup", "keeper")
                if f"-{role}-" in container_name
            )
            calls.append(role)
            if (
                role == "collector"
                and injected_count
                < runner.MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT + 4
            ):
                run_case_frame = sys._getframe()
                while (
                    run_case_frame is not None
                    and run_case_frame.f_code is not runner._run_case.__code__
                ):
                    run_case_frame = run_case_frame.f_back
                if run_case_frame is None:
                    raise RuntimeError("could not find cleanup driver frame")
                run_case_frame.f_trace = interrupt_bookkeeping
                sys.settrace(interrupt_bookkeeping)
                raise first

        def remove_volume(*_args: object, **_kwargs: object) -> None:
            calls.append("volume")

        try:
            with mock.patch.object(
                runner, "_create_workspace_volume", side_effect=primary
            ), mock.patch.object(
                runner, "_remove_container", side_effect=remove_container
            ), mock.patch.object(
                runner, "_remove_volume", side_effect=remove_volume
            ):
                with self.assertRaises(BehaviorCorpusError) as caught:
                    runner._run_case(
                        corpus,
                        corpus["cases"][0],
                        self.executable_payload,
                        runner._limits(corpus["limits"]),
                        runner._normalization_map(corpus),
                        Path("/runtime"),
                        {},
                        runner._RetentionBudget(),
                    )
        finally:
            sys.settrace(None)
        self.assertIs(caught.exception, primary)
        self.assertEqual(
            runner.MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT,
            injected_count,
        )
        self.assertEqual(
            ["collector"] * runner.MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT
            + ["target", "setup", "keeper", "volume"],
            calls,
        )
        notes = runner.behavior_error_notes(primary)
        self.assertTrue(
            any("first bookkeeping cancellation" in note for note in notes), notes
        )
        self.assertTrue(
            any(
                "collector container: residue absence proof was not established"
                in note
                for note in notes
            ),
            notes,
        )

    def test_actual_sigint_during_cleanup_is_deferred_through_all_targets(self) -> None:
        from oracle.behavior_corpus import (
            _RetentionBudget,
            _limits,
            _normalization_map,
            _run_case,
            behavior_error_notes,
        )

        corpus = validate_corpus(self.corpus("stable"))
        primary = BehaviorCorpusError("primary execution failure")
        calls = 0
        sent_sigint = False

        def remove_container(*_args: object, **_kwargs: object) -> None:
            nonlocal calls, sent_sigint
            calls += 1
            if not sent_sigint:
                sent_sigint = True
                os.kill(os.getpid(), signal.SIGINT)

        def remove_volume(*_args: object, **_kwargs: object) -> None:
            nonlocal calls
            calls += 1

        with mock.patch(
            "oracle.behavior_corpus._create_workspace_volume", side_effect=primary
        ), mock.patch(
            "oracle.behavior_corpus._remove_container", side_effect=remove_container
        ), mock.patch(
            "oracle.behavior_corpus._remove_volume", side_effect=remove_volume
        ):
            with self.assertRaises(BehaviorCorpusError) as caught:
                _run_case(
                    corpus,
                    corpus["cases"][0],
                    self.executable_payload,
                    _limits(corpus["limits"]),
                    _normalization_map(corpus),
                    Path("/runtime"),
                    {},
                    _RetentionBudget(),
                )
        self.assertIs(caught.exception, primary)
        self.assertEqual(5, calls)
        self.assertTrue(
            any("SIGINT received" in note for note in behavior_error_notes(primary))
        )

    def test_sigint_setup_and_restoration_cannot_replace_primary(self) -> None:
        import oracle.behavior_corpus as runner

        corpus = validate_corpus(self.corpus("stable"))
        for phase in ("setup", "restoration"):
            with self.subTest(phase=phase):
                primary = BehaviorCorpusError(f"primary before {phase}")
                cancellation = SystemExit(84 if phase == "setup" else 85)
                cleanup_targets: list[str] = []
                real_getsignal = runner._ORIGINAL_GETSIGNAL
                real_signal = runner._ORIGINAL_SIGNAL
                prior_handler = real_getsignal(signal.SIGINT)
                signal_calls = 0

                def controlled_signal(signum: int, handler: Any) -> Any:
                    nonlocal signal_calls
                    signal_calls += 1
                    if phase == "setup" and signal_calls == 1:
                        raise cancellation
                    if phase == "restoration" and signal_calls == 2:
                        raise cancellation
                    return real_signal(signum, handler)

                def remove_container(
                    _runtime: Path,
                    _environment: dict[str, str],
                    _container_id: str | None,
                    container_name: str,
                    *,
                    settle_until: float | None = None,
                ) -> None:
                    del settle_until
                    role = next(
                        role
                        for role in ("collector", "target", "setup", "keeper")
                        if f"-{role}-" in container_name
                    )
                    cleanup_targets.append(role)

                def remove_volume(*_args: object, **_kwargs: object) -> None:
                    cleanup_targets.append("volume")

                try:
                    with mock.patch.object(
                        runner, "_create_workspace_volume", side_effect=primary
                    ), mock.patch.object(
                        runner, "_remove_container", side_effect=remove_container
                    ), mock.patch.object(
                        runner, "_remove_volume", side_effect=remove_volume
                    ), mock.patch.object(
                        runner, "_ORIGINAL_SIGNAL", side_effect=controlled_signal
                    ):
                        with self.assertRaises(BehaviorCorpusError) as caught:
                            runner._run_case(
                                corpus,
                                corpus["cases"][0],
                                self.executable_payload,
                                runner._limits(corpus["limits"]),
                                runner._normalization_map(corpus),
                                Path("/runtime"),
                                {},
                                runner._RetentionBudget(),
                            )
                finally:
                    real_signal(signal.SIGINT, prior_handler)
                self.assertIs(caught.exception, primary)
                self.assertEqual(
                    ["collector", "target", "setup", "keeper", "volume"],
                    cleanup_targets,
                )
                notes = runner.behavior_error_notes(primary)
                self.assertTrue(
                    any(f"SIGINT deferral {phase}" in note for note in notes),
                    notes,
                )

    def test_sigint_setup_and_restoration_bookkeeping_cannot_escape(self) -> None:
        import inspect
        import sys

        import oracle.behavior_corpus as runner

        corpus = validate_corpus(self.corpus("stable"))
        source, start_line = inspect.getsourcelines(runner._run_case)
        real_getsignal = runner._ORIGINAL_GETSIGNAL
        real_signal = runner._ORIGINAL_SIGNAL
        for phase in ("setup", "restoration"):
            with self.subTest(phase=phase):
                primary = BehaviorCorpusError(f"primary before {phase} bookkeeping")
                first = SystemExit(86 if phase == "setup" else 87)
                second = KeyboardInterrupt(f"second {phase} bookkeeping cancellation")
                cleanup_targets: list[str] = []
                prior_handler = real_getsignal(signal.SIGINT)
                signal_calls = 0
                trace_hits = 0
                marker = f'"SIGINT deferral {phase}", error'
                bookkeeping_lines = [
                    start_line + offset
                    for offset, line in enumerate(source)
                    if marker in line
                ]
                self.assertEqual(1, len(bookkeeping_lines))

                def interrupt_bookkeeping(
                    frame: Any, event: str, _argument: Any
                ) -> Any:
                    nonlocal trace_hits
                    if (
                        frame.f_code is runner._run_case.__code__
                        and event == "line"
                        and frame.f_lineno == bookkeeping_lines[0]
                    ):
                        sys.settrace(None)
                        frame.f_trace = None
                        trace_hits += 1
                        raise second
                    return interrupt_bookkeeping

                def controlled_signal(signum: int, handler: Any) -> Any:
                    nonlocal signal_calls
                    signal_calls += 1
                    if phase == "setup":
                        raise first
                    if signal_calls == 2:
                        raise first
                    return real_signal(signum, handler)

                def remove_container(
                    _runtime: Path,
                    _environment: dict[str, str],
                    _container_id: str | None,
                    container_name: str,
                    *,
                    settle_until: float | None = None,
                ) -> None:
                    del settle_until
                    role = next(
                        role
                        for role in ("collector", "target", "setup", "keeper")
                        if f"-{role}-" in container_name
                    )
                    cleanup_targets.append(role)

                def remove_volume(*_args: object, **_kwargs: object) -> None:
                    cleanup_targets.append("volume")

                try:
                    with mock.patch.object(
                        runner, "_create_workspace_volume", side_effect=primary
                    ), mock.patch.object(
                        runner, "_remove_container", side_effect=remove_container
                    ), mock.patch.object(
                        runner, "_remove_volume", side_effect=remove_volume
                    ), mock.patch.object(
                        runner, "_ORIGINAL_SIGNAL", side_effect=controlled_signal
                    ):
                        sys.settrace(interrupt_bookkeeping)
                        with self.assertRaises(BehaviorCorpusError) as caught:
                            runner._run_case(
                                corpus,
                                corpus["cases"][0],
                                self.executable_payload,
                                runner._limits(corpus["limits"]),
                                runner._normalization_map(corpus),
                                Path("/runtime"),
                                {},
                                runner._RetentionBudget(),
                            )
                finally:
                    sys.settrace(None)
                    real_signal(signal.SIGINT, prior_handler)
                self.assertIs(caught.exception, primary)
                self.assertEqual(1, trace_hits)
                self.assertEqual(
                    ["collector", "target", "setup", "keeper", "volume"],
                    cleanup_targets,
                )
                notes = runner.behavior_error_notes(primary)
                self.assertTrue(
                    any(f"SIGINT deferral {phase}" in note for note in notes),
                    notes,
                )
                self.assertTrue(
                    any(str(second) in note for note in notes),
                    notes,
                )

    def test_sigint_restoration_failure_without_primary_has_nonempty_detail(self) -> None:
        import oracle.behavior_corpus as runner

        if self.runtime is None:
            self.skipTest("restoration-only failure requires the locked OCI sandbox")
        real_remove_container = runner._remove_container
        real_remove_volume = runner._remove_volume
        real_getsignal = runner._ORIGINAL_GETSIGNAL
        real_signal = runner._ORIGINAL_SIGNAL
        prior_handler = real_getsignal(signal.SIGINT)
        cleanup_targets: list[str] = []
        signal_calls = 0

        def fail_first_restoration(signum: int, handler: Any) -> Any:
            nonlocal signal_calls
            signal_calls += 1
            if signal_calls == 2:
                raise RuntimeError("injected SIGINT restoration failure")
            return real_signal(signum, handler)

        def capture_container(
            runtime: Path,
            environment: dict[str, str],
            container_id: str | None,
            container_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            role = next(
                role
                for role in ("collector", "target", "setup", "keeper")
                if f"-{role}-" in container_name
            )
            cleanup_targets.append(role)
            real_remove_container(
                runtime,
                environment,
                container_id,
                container_name,
                settle_until=settle_until,
            )

        def capture_volume(
            runtime: Path,
            environment: dict[str, str],
            volume_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            cleanup_targets.append("volume")
            real_remove_volume(
                runtime,
                environment,
                volume_name,
                settle_until=settle_until,
            )

        try:
            with mock.patch.object(
                runner, "_ORIGINAL_SIGNAL", side_effect=fail_first_restoration
            ), mock.patch.object(
                runner, "_remove_container", side_effect=capture_container
            ), mock.patch.object(
                runner, "_remove_volume", side_effect=capture_volume
            ):
                with self.assertRaisesRegex(
                    BehaviorCorpusError,
                    "SIGINT deferral restoration: RuntimeError: "
                    "injected SIGINT restoration failure",
                ) as caught:
                    self.run_fixture_corpus(self.corpus("stable"))
        finally:
            real_signal(signal.SIGINT, prior_handler)
        self.assertTrue(str(caught.exception))
        self.assertEqual(
            ["collector", "target", "setup", "keeper", "volume"],
            cleanup_targets[-5:],
        )

    def test_worker_thread_skips_signal_install_and_cleans_all_targets(self) -> None:
        import threading

        import oracle.behavior_corpus as runner

        if self.runtime is None:
            self.skipTest("worker cleanup requires the locked OCI sandbox")
        real_remove_container = runner._remove_container
        real_remove_volume = runner._remove_volume
        cleanup_targets: list[str] = []
        results: list[dict[str, object]] = []
        failures: list[BaseException] = []
        worker_corpus = self.corpus("stable")
        worker_corpus["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b"stable"),
            "stderr": stream(b""),
            "artifacts": [],
        }

        def capture_container(
            runtime: Path,
            environment: dict[str, str],
            container_id: str | None,
            container_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            role = next(
                role
                for role in ("collector", "target", "setup", "keeper")
                if f"-{role}-" in container_name
            )
            cleanup_targets.append(role)
            real_remove_container(
                runtime,
                environment,
                container_id,
                container_name,
                settle_until=settle_until,
            )

        def capture_volume(
            runtime: Path,
            environment: dict[str, str],
            volume_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            cleanup_targets.append("volume")
            real_remove_volume(
                runtime,
                environment,
                volume_name,
                settle_until=settle_until,
            )

        def run_in_worker() -> None:
            try:
                results.append(self.run_fixture_corpus(worker_corpus))
            except BaseException as error:
                failures.append(error)

        with mock.patch.object(
            runner,
            "_ORIGINAL_SIGNAL",
            side_effect=AssertionError("worker cleanup must not install a handler"),
        ), mock.patch.object(
            runner, "_remove_container", side_effect=capture_container
        ), mock.patch.object(
            runner, "_remove_volume", side_effect=capture_volume
        ):
            worker = threading.Thread(target=run_in_worker, daemon=True)
            worker.start()
            worker.join(timeout=30)
        self.assertFalse(worker.is_alive())
        self.assertEqual([], failures)
        self.assertEqual(1, len(results))
        self.assertEqual(
            ["collector", "target", "setup", "keeper", "volume"],
            cleanup_targets[-5:],
        )

    def test_cleanup_only_system_exit_is_raised_after_all_live_residue_attempts(self) -> None:
        import oracle.behavior_corpus as runner

        if self.runtime is None:
            self.skipTest("cleanup-only cancellation requires the locked OCI sandbox")
        real_remove_container = runner._remove_container
        real_remove_volume = runner._remove_volume
        first_cleanup_cancellation = SystemExit(82)
        container_calls = 0
        volume_calls = 0

        def cancel_first_final_container(
            runtime: Path,
            environment: dict[str, str],
            container_id: str | None,
            container_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            nonlocal container_calls
            container_calls += 1
            if container_calls == 4:
                raise first_cleanup_cancellation
            real_remove_container(
                runtime,
                environment,
                container_id,
                container_name,
                settle_until=settle_until,
            )

        def capture_volume(
            runtime: Path,
            environment: dict[str, str],
            volume_name: str,
            *,
            settle_until: float | None = None,
        ) -> None:
            nonlocal volume_calls
            volume_calls += 1
            real_remove_volume(
                runtime,
                environment,
                volume_name,
                settle_until=settle_until,
            )

        with mock.patch.object(
            runner, "_remove_container", side_effect=cancel_first_final_container
        ), mock.patch.object(
            runner, "_remove_volume", side_effect=capture_volume
        ):
            with self.assertRaises(SystemExit) as caught:
                self.run_fixture_corpus(self.corpus("stable"))
        self.assertIs(caught.exception, first_cleanup_cancellation)
        self.assertEqual(8, container_calls)
        self.assertEqual(1, volume_calls)
        self.assertTrue(
            any(
                "cleanup cancellation was deferred" in note
                for note in runner.behavior_error_notes(first_cleanup_cancellation)
            )
        )

    def test_repeated_cleanup_cancellation_is_finite_and_reports_unproved_residue(self) -> None:
        from oracle.behavior_corpus import (
            MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT,
            _RetentionBudget,
            _limits,
            _normalization_map,
            _run_case,
            behavior_error_notes,
        )

        corpus = validate_corpus(self.corpus("stable"))
        primary = BehaviorCorpusError("primary execution failure")
        container_calls = 0
        volume_calls = 0

        def interrupt_container(*_args: object, **_kwargs: object) -> None:
            nonlocal container_calls
            container_calls += 1
            raise KeyboardInterrupt("repeated container cancellation")

        def interrupt_volume(*_args: object, **_kwargs: object) -> None:
            nonlocal volume_calls
            volume_calls += 1
            raise SystemExit(91)

        with mock.patch(
            "oracle.behavior_corpus._create_workspace_volume", side_effect=primary
        ), mock.patch(
            "oracle.behavior_corpus._remove_container", side_effect=interrupt_container
        ), mock.patch(
            "oracle.behavior_corpus._remove_volume", side_effect=interrupt_volume
        ):
            with self.assertRaises(BehaviorCorpusError) as caught:
                _run_case(
                    corpus,
                    corpus["cases"][0],
                    self.executable_payload,
                    _limits(corpus["limits"]),
                    _normalization_map(corpus),
                    Path("/runtime"),
                    {},
                    _RetentionBudget(),
                )
        self.assertIs(caught.exception, primary)
        self.assertEqual(
            4 * MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT, container_calls
        )
        self.assertEqual(MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT, volume_calls)
        notes = behavior_error_notes(primary)
        self.assertTrue(any("cleanup cancellation was deferred" in note for note in notes))
        self.assertTrue(any("residue absence proof was not established" in note for note in notes))

    def test_cleanup_failure_does_not_replace_the_primary_execution_error(self) -> None:
        from oracle.behavior_corpus import (
            _RetentionBudget,
            _limits,
            _normalization_map,
            _run_case,
        )

        corpus = validate_corpus(self.corpus("stable"))
        with mock.patch(
            "oracle.behavior_corpus._create_workspace_volume",
            side_effect=BehaviorCorpusError("primary execution failure"),
        ), mock.patch(
            "oracle.behavior_corpus._remove_container"
        ), mock.patch(
            "oracle.behavior_corpus._remove_volume",
            side_effect=BehaviorCorpusError("cleanup failure"),
        ):
            with self.assertRaisesRegex(
                BehaviorCorpusError, "primary execution failure"
            ) as caught:
                _run_case(
                    corpus,
                    corpus["cases"][0],
                    self.executable_payload,
                    _limits(corpus["limits"]),
                    _normalization_map(corpus),
                    Path("/runtime"),
                    {},
                    _RetentionBudget(),
                )
        notes = getattr(caught.exception, "__notes__", [])
        self.assertTrue(any("cleanup also failed" in note for note in notes))

    def test_both_clis_render_cleanup_notes_without_changing_primary_text(self) -> None:
        for script_name, callable_name in (
            ("run-behavior-corpus.py", "run_corpus_file"),
            ("run-gcc-behavior-corpus.py", "run_gcc_behavior_corpus"),
        ):
            with self.subTest(script=script_name):
                namespace = runpy.run_path(
                    os.fspath(REPOSITORY_ROOT / "scripts" / script_name)
                )
                main = namespace["main"]
                primary = BehaviorCorpusError("primary execution failure")
                primary.add_note("sandbox cleanup also failed: residue not disproved")
                primary.add_note("sandbox cleanup cancellation was deferred: KeyboardInterrupt")
                stderr = io.StringIO()
                argv = [
                    script_name,
                    "--corpus",
                    "/tmp/corpus.json",
                    "--json-output",
                    "/tmp/report.json",
                    "--container-runtime",
                    "/bin/true",
                ]
                if script_name == "run-behavior-corpus.py":
                    argv.extend(["--executable", "/tmp/executable"])
                with mock.patch.dict(
                    main.__globals__,
                    {callable_name: mock.Mock(side_effect=primary)},
                ), mock.patch("sys.argv", argv), contextlib.redirect_stderr(stderr):
                    self.assertEqual(1, main())
                self.assertEqual(
                    [
                        "verification failed: primary execution failure",
                        "verification detail: sandbox cleanup also failed: residue not disproved",
                        "verification detail: sandbox cleanup cancellation was deferred: KeyboardInterrupt",
                    ],
                    stderr.getvalue().splitlines(),
                )

    def test_container_configuration_tampering_and_keeper_exit_fail_closed(self) -> None:
        import oracle.behavior_corpus as runner

        if self.runtime is None:
            self.skipTest("container configuration checks require the locked runtime")
        real_control = runner._run_control_command
        changed = False

        def tamper_configuration(
            arguments: list[str], environment: dict[str, str], label: str
        ) -> bytes:
            nonlocal changed
            payload = real_control(arguments, environment, label)
            if label == "sandbox container configuration inspection" and not changed:
                changed = True
                records = json.loads(payload.decode("utf-8"))
                records[0]["HostConfig"]["NetworkMode"] = "default"
                return json.dumps(records).encode("utf-8")
            return payload

        with mock.patch.object(
            runner, "_run_control_command", side_effect=tamper_configuration
        ):
            with self.assertRaisesRegex(BehaviorCorpusError, "NetworkMode"):
                self.run_fixture_corpus(self.corpus())
        self.assertTrue(changed)

        for expected_field, injected_option in (
            ("CpuShares", "--cpu-shares=2"),
            ("MemoryReservation", "--memory-reservation=134217728"),
            ("OomScoreAdj", "--oom-score-adj=600"),
        ):
            with self.subTest(real_host_option=expected_field):

                def inject_real_host_option(
                    arguments: list[str], environment: dict[str, str], label: str
                ) -> bytes:
                    if label != "sandbox container creation":
                        return real_control(arguments, environment, label)
                    changed_arguments = list(arguments)
                    image_index = changed_arguments.index(self.image_digest)
                    changed_arguments.insert(image_index, injected_option)
                    return real_control(changed_arguments, environment, label)

                with mock.patch.object(
                    runner,
                    "_run_control_command",
                    side_effect=inject_real_host_option,
                ):
                    with self.assertRaisesRegex(BehaviorCorpusError, expected_field):
                        self.run_fixture_corpus(self.corpus())

        advertised_cpu_burst = False

        def advertise_cpu_burst(
            arguments: list[str], environment: dict[str, str], label: str
        ) -> bytes:
            nonlocal advertised_cpu_burst
            payload = real_control(arguments, environment, label)
            if label == "sandbox container configuration inspection" and not advertised_cpu_burst:
                advertised_cpu_burst = True
                records = json.loads(payload.decode("utf-8"))
                records[0]["HostConfig"]["CpuBurst"] = 1
                return json.dumps(records).encode("utf-8")
            return payload

        with mock.patch.object(
            runner, "_run_control_command", side_effect=advertise_cpu_burst
        ):
            with self.assertRaisesRegex(BehaviorCorpusError, "CpuBurst"):
                self.run_fixture_corpus(self.corpus())
        self.assertTrue(advertised_cpu_burst)

        real_keeper_check = runner._verify_keeper_running
        for failed_check in (2, 3):
            with self.subTest(keeper_check=failed_check):
                checks = 0

                def fail_keeper_handoff(
                    *arguments: object, **keywords: object
                ) -> None:
                    nonlocal checks
                    checks += 1
                    if checks == failed_check:
                        raise BehaviorCorpusError(
                            "workspace keeper did not remain running"
                        )
                    real_keeper_check(*arguments, **keywords)

                with mock.patch.object(
                    runner,
                    "_verify_keeper_running",
                    side_effect=fail_keeper_handoff,
                ):
                    with self.assertRaisesRegex(
                        BehaviorCorpusError, "keeper did not remain"
                    ):
                        self.run_fixture_corpus(self.corpus())
                self.assertEqual(failed_check, checks)

    def test_container_exit_must_be_bound_to_pid_one_state(self) -> None:
        from oracle.behavior_corpus import _verify_container_exit

        container_id = "a" * 64
        state = {
            "Status": "exited",
            "Running": False,
            "Paused": False,
            "Restarting": False,
            "OOMKilled": True,
            "Dead": False,
            "Pid": 0,
            "ExitCode": 137,
            "Error": "",
        }
        payload = json.dumps(
            [{"Id": container_id, "Name": "/sandbox", "State": state}]
        ).encode("utf-8")
        with mock.patch(
            "oracle.behavior_corpus._run_control_command", return_value=payload
        ):
            with self.assertRaisesRegex(BehaviorCorpusError, "process exit state"):
                _verify_container_exit(
                    Path("/runtime"), {}, container_id, "sandbox", 137
                )

    def test_target_has_no_read_write_host_bind_and_roles_are_separated(self) -> None:
        import oracle.behavior_corpus as runner

        if self.runtime is None:
            self.skipTest("container mount checks require the locked runtime")
        real_control = runner._run_control_command
        configurations: list[dict[str, object]] = []

        def capture_configuration(
            arguments: list[str], environment: dict[str, str], label: str
        ) -> bytes:
            payload = real_control(arguments, environment, label)
            if label == "sandbox container configuration inspection":
                configurations.append(json.loads(payload.decode("utf-8"))[0])
            return payload

        with mock.patch.object(
            runner, "_run_control_command", side_effect=capture_configuration
        ):
            self.run_fixture_corpus(self.corpus())
        self.assertEqual(4, len(configurations))
        by_role = {
            role: next(
                record
                for record in configurations
                if f"behavior-corpus-{role}-" in str(record["Name"])
            )
            for role in ("keeper", "setup", "target", "collector")
        }
        target = by_role["target"]
        self.assertEqual("65534:65534", target["Config"]["User"])
        target_mounts = target["HostConfig"]["Mounts"]
        self.assertEqual(
            [("volume", "/workspace", False)],
            [
                (mount["Type"], mount["Target"], mount.get("ReadOnly", False))
                for mount in target_mounts
                if not mount.get("ReadOnly", False)
            ],
        )
        self.assertFalse(
            any(
                mount["Type"] == "bind" and not mount.get("ReadOnly", False)
                for mount in target_mounts
            )
        )
        collector_mounts = by_role["collector"]["HostConfig"]["Mounts"]
        self.assertEqual(
            [("bind", "/case-results")],
            [
                (mount["Type"], mount["Target"])
                for mount in collector_mounts
                if not mount.get("ReadOnly", False)
            ],
        )
        self.assertEqual(
            ["CAP_DAC_OVERRIDE"], by_role["collector"]["HostConfig"]["CapAdd"]
        )
        setup_mounts = by_role["setup"]["HostConfig"]["Mounts"]
        self.assertTrue(
            any(
                mount["Target"] == "/case-inputs" and mount["ReadOnly"] is True
                for mount in setup_mounts
            )
        )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "corpus.json"
            path.write_text('{"schemaVersion":1,"schemaVersion":1}\n', encoding="utf-8")
            with self.assertRaisesRegex(BehaviorCorpusError, "duplicate JSON object key"):
                load_corpus(path)

    def test_noncanonical_json_bytes_are_rejected(self) -> None:
        corpus = self.corpus()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "corpus.json"
            path.write_text(json.dumps(corpus) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(BehaviorCorpusError, "must use canonical"):
                load_corpus(path)

    def test_sandbox_hides_host_paths_and_denies_external_network(self) -> None:
        empty_expected = {
            "exitCode": 0,
            "stdout": stream(b""),
            "stderr": stream(b""),
            "artifacts": [absent_artifact("result.bin")],
        }
        with tempfile.TemporaryDirectory(prefix="host-secret-") as temporary:
            secret = Path(temporary) / "secret.txt"
            secret.write_bytes(b"must-not-enter-container")
            secret_case = self.corpus("secret")
            secret_case["cases"][0]["arguments"].append(os.fspath(secret))
            secret_case["cases"][0]["expected"] = copy.deepcopy(empty_expected)
            self.assertEqual(
                "passed",
                self.run_fixture_corpus(secret_case)["cases"][0]["status"],
            )

        network_case = self.corpus("network")
        network_case["cases"][0]["expected"] = copy.deepcopy(empty_expected)
        self.assertEqual(
            "passed",
            self.run_fixture_corpus(network_case)["cases"][0]["status"],
        )

    def test_sandbox_reaps_background_processes_before_artifact_verification(self) -> None:
        corpus = self.corpus("daemon")
        corpus["cases"][0]["expected"] = {
            "exitCode": 0,
            "stdout": stream(b""),
            "stderr": stream(b""),
            "artifacts": [
                absent_artifact("daemon.bin"),
                absent_artifact("result.bin"),
            ],
        }
        report = self.run_fixture_corpus(corpus)
        self.assertEqual("passed", report["cases"][0]["status"])

    def test_formal_schemas_are_closed_and_cover_runtime_roots(self) -> None:
        corpus_schema = json.loads(CORPUS_SCHEMA.read_text(encoding="utf-8"))
        report_schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
        corpus = self.corpus()
        report = self.run_fixture_corpus(corpus)

        self.assertFalse(corpus_schema["additionalProperties"])
        self.assertEqual(set(corpus), set(corpus_schema["required"]))
        self.assertEqual(set(corpus), set(corpus_schema["properties"]))
        self.assertFalse(report_schema["additionalProperties"])
        self.assertEqual(set(report), set(report_schema["required"]))
        self.assertEqual(set(report), set(report_schema["properties"]))
        self.assertEqual(
            corpus_schema["$defs"]["sandbox"], report_schema["$defs"]["sandbox"]
        )
        self.assertEqual(
            corpus_schema["$defs"]["limits"], report_schema["$defs"]["limits"]
        )


if __name__ == "__main__":
    unittest.main()
