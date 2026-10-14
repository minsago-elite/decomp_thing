"""Pure capture controls. These tests must never launch a host/OCI process."""
from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "oracle/llvm/capture_reference_runtime.py"
capture = types.ModuleType("capture_llvm_reference_runtime_test_subject")
capture.__file__ = str(SOURCE)
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), capture.__dict__)

FORBIDDEN_ATTEMPTS = []
GUARD_ACTIVE = False


def audit(event, arguments):
    if GUARD_ACTIVE and (event in {"subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.posix_spawn",
                                  "os.exec", "ctypes.dlopen"} or event.startswith("socket.")):
        FORBIDDEN_ATTEMPTS.append(event)
        raise AssertionError("native/process/network execution forbidden in capture pure controls")


sys.addaudithook(audit)


def engine():
    server = {"Os": "linux", "Arch": "amd64", "Version": "29.7.2", "GitCommit": "6a43e3d",
              "ApiVersion": "1.55", "KernelVersion": "authored-kernel", "Platform": {"Name": "Docker Engine"},
              "Components": [{"Name": "Engine", "Version": "29.7.2", "Details": {"KernelVersion": "authored-kernel"}},
                             {"Name": "runc", "Version": "1.4.3", "Details": {"GitCommit": "authored-commit"}},
                             {"Name": "rootlesskit", "Version": "3.0.2", "Details": {"StateDir": "/owned/state"}}]}
    info = [["name=rootless", "name=cgroupns", "name=seccomp,profile=builtin"], "2", "systemd", "overlay2", ["local"],
            {"runc": {"path": "runc", "status": {"org.opencontainers.runtime-spec.features": '{"authored":true}'}}}]
    return server, info


class CaptureRuntimeTest(unittest.TestCase):
    def setUp(self):
        global GUARD_ACTIVE
        GUARD_ACTIVE = True
        def release_guard():
            global GUARD_ACTIVE
            GUARD_ACTIVE = False
        self.addCleanup(release_guard)
        self.parent = ROOT / "build/issue97-runtime-capture-pure"
        self.parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="case-", dir=self.parent)
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()
        self.assertEqual([], FORBIDDEN_ATTEMPTS)

    def refuse(self, code, action):
        with self.assertRaises(capture.CaptureFailure) as caught:
            action()
        self.assertEqual(code, caught.exception.code)

    def test_dispatch_metadata_is_closed_and_does_not_copy_unknown_environment(self):
        env = {key: "authored" for key in capture.PUBLIC_ENV}
        env.update(GITHUB_REPOSITORY="minsago-elite/decomp_thing", GITHUB_SHA="a" * 40,
                   GITHUB_WORKFLOW_SHA="b" * 40, GITHUB_RUN_ID="12", GITHUB_RUN_ATTEMPT="1",
                   GITHUB_EVENT_NAME="workflow_dispatch", RUNNER_OS="Linux", RUNNER_ARCH="X64",
                   GITHUB_WORKFLOW_REF="minsago-elite/decomp_thing/" + capture.WORKFLOW + "@refs/heads/authored",
                   AUTHORED_SECRET_CANARY="never-retain-this")
        with patch.object(capture.os, "environ", env):
            observed = capture.public_environment()
            self.assertEqual(set(capture.PUBLIC_ENV), set(observed))
            self.assertNotIn("never-retain-this", json.dumps(observed))
            os.environ["GITHUB_EVENT_NAME"] = "pull_request"
            self.refuse("DISPATCH_PLATFORM", capture.public_environment)

    def test_json_duplicate_nonfinite_malformed_and_size_refuse(self):
        for raw, code in ((b'{"a":1,"a":2}', "DUPLICATE_JSON_FIELD"),
                          (b'{"a":NaN}', "NONFINITE_JSON"), (b'{', "MALFORMED_JSON"),
                          (b' ' * (capture.MAX_JSON + 1), "JSON_LIMIT")):
            self.refuse(code, lambda: capture.strict_json(raw))

    def test_engine_exact_tuple_and_component_kernel_agreement(self):
        server, info = engine()
        actual = capture.engine_tuple(server, info, "authored-kernel")
        self.assertEqual("authored-kernel", actual["kernelVersion"])
        self.assertEqual(hashlib.sha256(b'{"authored":true}').hexdigest(), actual["containerRuntimeFeaturesSha256"])
        server["Components"][0]["Details"]["KernelVersion"] = "wrong"
        self.refuse("ENGINE_COMPONENT_KERNEL", lambda: capture.engine_tuple(server, info, "authored-kernel"))

    def test_engine_security_cgroup_and_malformed_runtime_refuse(self):
        for field, value, code in ((0, ["name=rootless"], "MISSING_SECURITY"),
                                   (1, "1", "MISSING_RESOURCE_CAPABILITY"),
                                   (5, {"runc": {"status": None}}, "RUNC_STATUS")):
            server, info = engine()
            info[field] = value
            self.refuse(code, lambda: capture.engine_tuple(server, info, "authored-kernel"))
        server, info = engine()
        server["Platform"] = None
        self.refuse("ENGINE_RECORD", lambda: capture.engine_tuple(server, info, "authored-kernel"))

    def test_components_match_canonical_algorithm_and_only_declared_exclusions(self):
        server, _ = engine()
        before = capture.components_hash(server["Components"])
        server["Components"][0]["Details"]["KernelVersion"] = "other"
        server["Components"][2]["Details"]["StateDir"] = "/other"
        self.assertEqual(before, capture.components_hash(server["Components"]))
        server["Components"][1]["Version"] = "other"
        self.assertNotEqual(before, capture.components_hash(server["Components"]))
        server["Components"].append(copy.deepcopy(server["Components"][0]))
        self.refuse("DUPLICATE_COMPONENT", lambda: capture.components_hash(server["Components"]))

    def test_image_drift_retains_actual_identity_and_lock_is_not_mutated(self):
        image = {"Id": "sha256:" + "a" * 64, "Os": "linux", "Architecture": "amd64",
                 "Created": "authored-created", "Config": {"Env": ["PATH=/usr/bin"]},
                 "RootFS": {"Layers": ["sha256:" + "b" * 64]}}
        expected = {"imageDigest": image["Id"], "created": image["Created"],
                    "configSha256": hashlib.sha256(json.dumps(image["Config"], sort_keys=True,
                                            separators=(",", ":")).encode()).hexdigest(),
                    "rootfsDiffIds": image["RootFS"]["Layers"]}
        lock = {"reproducedImage": expected}
        self.assertEqual([], capture.image_tuple([image], lock)[2])
        original = copy.deepcopy(lock)
        image["Id"] = "sha256:" + "c" * 64
        runtime, observed, drift = capture.image_tuple([image], lock)
        self.assertEqual(image["Id"], runtime["imageDigest"])
        self.assertEqual(["imageDigest"], drift)
        self.assertEqual(original, lock)
        self.assertNotIn("approved", runtime)

    def test_image_implicit_volume_duplicate_env_and_malformed_layers_refuse(self):
        image = {"Id": "sha256:" + "a" * 64, "Os": "linux", "Architecture": "amd64",
                 "Config": {"Volumes": {"/implicit": {}}}}
        self.refuse("IMPLICIT_IMAGE_VOLUMES", lambda: capture.image_tuple([image], {}))
        image["Config"] = {"Env": ["PATH=a", "PATH=b"]}
        image["RootFS"] = {}
        self.refuse("IMAGE_ENVIRONMENT_DUPLICATE", lambda: capture.image_tuple([image], {}))
        image["Config"] = {}
        image["RootFS"] = None
        self.refuse("IMAGE_LAYERS", lambda: capture.image_tuple([image], {}))

    def test_file_pin_refuses_symlink_fifo_and_preopen_size_limit(self):
        regular = self.directory / "regular"
        regular.write_bytes(b"authored")
        link = self.directory / "symlink"
        link.symlink_to(regular)
        with self.assertRaises(OSError):
            capture.file_pin(link)
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        self.refuse("FILE_KIND_OR_LIMIT", lambda: capture.file_pin(fifo))
        self.refuse("FILE_KIND_OR_LIMIT", lambda: capture.file_pin(regular, maximum=3))
        self.assertEqual(hashlib.sha256(b"authored").hexdigest(), capture.file_pin(regular)["sha256"])

    def test_atomic_receipt_never_replaces_earlier_generation(self):
        receipt = self.directory / "receipt.json"
        capture.save(receipt, {"approved": False})
        before = receipt.read_bytes()
        with self.assertRaises(FileExistsError):
            capture.save(receipt, {"approved": True})
        self.assertEqual(before, receipt.read_bytes())

    def test_distribution_duplicate_members_and_total_directory_count_refuse(self):
        for duplicate in (True, False):
            archive = self.directory / ("duplicate.tgz" if duplicate else "many.tgz")
            with tarfile.open(archive, "w:gz") as out:
                for number in range(2 if duplicate else 65):
                    member = tarfile.TarInfo("same" if duplicate else "dir" + str(number))
                    member.type = tarfile.DIRTYPE
                    out.addfile(member)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.refuse("DISTRIBUTION_PATH" if duplicate else "DISTRIBUTION_LIMIT",
                        lambda: capture.archive_inventory(archive, self.directory, digest))

    def test_environment_omits_caller_auth_proxy_and_configuration(self):
        with patch.object(capture.os, "environ", {"AUTHORED_TOKEN": "canary", "HTTPS_PROXY": "authored-proxy"}):
            env = capture.environment(self.directory)
        self.assertNotIn("AUTHORED_TOKEN", env)
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertEqual(str(self.directory / "home/.docker"), env["DOCKER_CONFIG"])
        self.assertIn(str(self.directory / "run/docker.sock"), env["DOCKER_HOST"])

    def test_workflow_pr_pure_only_dispatch_capture_no_host_install(self):
        raw = (ROOT / capture.WORKFLOW).read_text()
        self.assertEqual(str(SOURCE.relative_to(ROOT)), capture.SCRIPT)
        self.assertIn(capture.SCRIPT, raw)
        self.assertIn("workflow_dispatch:", raw)
        self.assertIn("pull_request:", raw)
        self.assertIn("if: github.event_name == 'pull_request'", raw)
        self.assertIn("if: github.event_name == 'workflow_dispatch'", raw)
        self.assertNotIn("docker run", raw)
        self.assertNotIn("generate-behavior", raw)
        self.assertIn("persist-credentials: false", raw)
        self.assertIn("build/r97/artifacts/", raw)
        for forbidden in ("sudo", "doas", "apt-get", "loginctl", "enable-linger", "apparmor_parser", "sysctl -w"):
            self.assertNotIn(forbidden, raw)
        self.assertIn("--preflight", raw)
        self.assertIn(str(self.directory / "tools/docker-rootless-extras"), capture.environment(self.directory)["PATH"])

    @contextmanager
    def mocked_command(self, stdout, *, code=0, fail_after=None, cap=4):
        class Pipe:
            def __init__(self, number):
                self.number, self.closed = number, False
            def fileno(self):
                return self.number
            def close(self):
                self.closed = True
        class Process:
            def __init__(self):
                self.stdout, self.stderr = Pipe(101), Pipe(102)
                self.returncode, self.killed = None, False
            def poll(self):
                return self.returncode
            def kill(self):
                self.killed = True
            def wait(self, timeout):
                self.returncode = code
                return code
        class Selector:
            def __init__(self):
                self.rows = {}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def register(self, pipe, event, label):
                self.rows[pipe] = types.SimpleNamespace(fileobj=pipe, data=label)
            def unregister(self, pipe):
                del self.rows[pipe]
            def get_map(self):
                return self.rows
            def select(self, timeout):
                return [(row, 1) for row in list(self.rows.values())]
        process = Process()
        pending = {101: bytearray(stdout), 102: bytearray()}
        consumed = 0
        def read(fd, size):
            nonlocal consumed
            if fd == 101 and fail_after is not None and consumed >= fail_after:
                raise OSError("authored read failure")
            block = bytes(pending[fd][:min(size, 2)])
            del pending[fd][:len(block)]
            if fd == 101:
                consumed += len(block)
            return block
        with patch.object(capture.subprocess, "Popen", return_value=process), \
             patch.object(capture.selectors, "DefaultSelector", Selector), \
             patch.object(capture.os, "set_blocking"), patch.object(capture.os, "read", side_effect=read), \
             patch.object(capture, "MAX_IMAGE", cap):
            yield process

    def streamed_receipt(self):
        receipt = json.loads((self.directory / "raw/image-save.json").read_bytes())
        archive = self.directory / "runtime-image.tar"
        actual = capture.file_pin(archive)
        stream = receipt["stdoutArtifact"]
        self.assertEqual("streamed-file", receipt["stdoutCapture"])
        self.assertEqual(actual["bytes"], receipt["stdoutBytes"])
        self.assertEqual(actual["sha256"], receipt["stdoutSha256"])
        self.assertTrue(stream["identityVerified"])
        self.assertTrue(all(stream[key] == value for key, value in actual.items()))
        self.assertFalse((self.directory / "raw/image-save.stdout").exists())
        return receipt

    def run_streamed_command(self):
        (self.directory / "raw").mkdir()
        return capture.control_command(Path("authored-no-exec"), {}, self.directory, {}, "image-save",
                                       ["image", "save", "authored-image"],
                                       stdout_path=self.directory / "runtime-image.tar")

    def test_streamed_command_success_receipt_binds_actual_archive_not_empty_stdout(self):
        with self.mocked_command(b"1234") as process:
            self.assertEqual(b"", self.run_streamed_command())
        receipt = self.streamed_receipt()
        self.assertEqual(4, receipt["stdoutBytes"])
        self.assertNotEqual(hashlib.sha256(b"").hexdigest(), receipt["stdoutSha256"])
        self.assertTrue(receipt["stdoutArtifact"]["eofObserved"])
        self.assertIsNone(receipt["failureCode"])
        self.assertEqual(0, receipt["exitCode"])
        self.assertFalse(process.killed)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_streamed_command_limit_receipt_binds_only_retained_prefix(self):
        with self.mocked_command(b"12345") as process:
            self.refuse("COMMAND_OUTPUT_LIMIT", self.run_streamed_command)
        receipt = self.streamed_receipt()
        self.assertEqual(4, receipt["stdoutBytes"])
        self.assertFalse(receipt["stdoutArtifact"]["eofObserved"])
        self.assertEqual("COMMAND_OUTPUT_LIMIT", receipt["failureCode"])
        self.assertTrue(process.killed)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_streamed_command_io_failure_receipt_retains_actual_prefix_and_primary_error(self):
        with self.mocked_command(b"12345", fail_after=2) as process:
            self.refuse("COMMAND_IO", self.run_streamed_command)
        receipt = self.streamed_receipt()
        self.assertEqual(2, receipt["stdoutBytes"])
        self.assertFalse(receipt["stdoutArtifact"]["eofObserved"])
        self.assertEqual("COMMAND_IO", receipt["failureCode"])
        self.assertTrue(process.killed)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_streamed_command_nonzero_exit_retains_full_bytes_without_success_claim(self):
        with self.mocked_command(b"1234", code=7) as process:
            self.refuse("COMMAND_EXIT", self.run_streamed_command)
        receipt = self.streamed_receipt()
        self.assertEqual(4, receipt["stdoutBytes"])
        self.assertTrue(receipt["stdoutArtifact"]["eofObserved"])
        self.assertEqual("COMMAND_EXIT", receipt["failureCode"])
        self.assertEqual(7, receipt["exitCode"])
        self.assertFalse(process.killed)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_controller_never_signals_directory_before_scope_admission(self):
        (self.directory / "artifacts").mkdir()
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        unit = "i97-capture-12-1.service"
        admitted = {"LoadState": "loaded", "InvocationID": "a" * 32,
                    "ControlGroup": "/user.slice/authored/" + unit, "ActiveState": "active"}
        changed = {**admitted, "InvocationID": "b" * 32}
        real_open = os.open
        opens = []
        def tracked_open(path, *args, **kwargs):
            opens.append(str(path))
            return real_open(path, *args, **kwargs)
        with patch.object(capture, "public_environment", return_value={"GITHUB_RUN_ID": "12", "GITHUB_RUN_ATTEMPT": "1"}), \
             patch.object(capture, "command", return_value=(b"", b"", 0, None)), \
             patch.object(capture, "service_properties", side_effect=[admitted, changed]), \
             patch.object(capture, "directory_fd", return_value=fd), \
             patch.object(capture.os, "open", side_effect=tracked_open):
            self.refuse("SERVICE_ADMISSION_CHANGED", lambda: capture.controller(ROOT, self.directory))
        receipt = json.loads((self.directory / "artifacts/controller-result.json").read_bytes())
        self.assertFalse(receipt["scopeAdmitted"])
        self.assertFalse(receipt["cleanupVerified"])
        self.assertNotIn("cgroup.kill", opens)
        self.assertNotIn("cgroup.events", opens)

    def test_preflight_refuses_restricted_userns_without_host_mutation_or_commands(self):
        with patch.object(capture, "public_environment", return_value={}), \
             patch.object(capture.Path, "exists", return_value=True), \
             patch.object(capture.Path, "open", return_value=io.BytesIO(b"1\n")), \
             patch.object(capture, "command") as command, patch.object(capture, "save") as save:
            self.refuse("HOST_USERNS_POLICY_UNSUPPORTED", lambda: capture.preflight(self.directory))
        command.assert_not_called()
        save.assert_not_called()

    def test_preflight_requires_existing_user_bus_without_starting_one(self):
        with patch.object(capture, "public_environment", return_value={}), \
             patch.object(capture.Path, "exists", return_value=False), \
             patch.object(capture.Path, "lstat", side_effect=FileNotFoundError), \
             patch.object(capture, "command") as command:
            self.refuse("EXISTING_USER_BUS_REQUIRED", lambda: capture.preflight(self.directory))
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
