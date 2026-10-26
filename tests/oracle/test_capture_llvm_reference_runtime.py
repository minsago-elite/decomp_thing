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
import time
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


def package_stdout(*, include_optional=True):
    # Public metadata retained by actual read-only run38593975791; no runtime execution.
    rows = [b"dbus-user-session\t1.12.20-2ubuntu4.1\tamd64\n",
            b"slirp4netns\t1.0.1-2\tamd64\n", b"systemd\t249.11-0ubuntu3.22\tamd64\n",
            b"uidmap\t1:4.8.1-2ubuntu2.2\tamd64\n"]
    if include_optional:
        rows.append(b"rootlesskit\t3.0.2\tamd64\n")  # Authored positive, not observed installed.
    return b"".join(rows)


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

    def test_inspection_context_does_not_broaden_capture_context(self):
        env = {key: "authored" for key in capture.PUBLIC_ENV}
        env.update(GITHUB_REPOSITORY="minsago-elite/decomp_thing", GITHUB_SHA="a" * 40,
                   GITHUB_WORKFLOW_SHA="b" * 40, GITHUB_RUN_ID="12", GITHUB_RUN_ATTEMPT="1",
                   GITHUB_EVENT_NAME="workflow_dispatch", RUNNER_OS="Linux", RUNNER_ARCH="X64")
        with patch.object(capture.os, "environ", env):
            env["GITHUB_WORKFLOW_REF"] = env["GITHUB_REPOSITORY"] + "/" + capture.INSPECT_WORKFLOW + "@refs/heads/authored"
            self.assertEqual(env, capture.public_environment(inspect_host=True))
            self.refuse("WORKFLOW_IDENTITY", capture.public_environment)
            env["GITHUB_WORKFLOW_REF"] = env["GITHUB_REPOSITORY"] + "/" + capture.WORKFLOW + "@refs/heads/authored"
            self.assertEqual(env, capture.public_environment())
            self.refuse("WORKFLOW_IDENTITY", lambda: capture.public_environment(inspect_host=True))

    def test_inspection_file_limits_deadline_fifo_and_aggregate_work_refuse(self):
        path = self.directory / "metadata"
        path.write_bytes(b"12345")
        budget = {"end": time.monotonic() + 30, "bytes": 0}
        row, raw = capture._inspect_read(path, budget, maximum=4)
        self.assertEqual("INSPECT_FILE_KIND_OR_LIMIT", row["code"])
        self.assertEqual(b"", raw)
        fifo = self.directory / "metadata-fifo"
        os.mkfifo(fifo)
        self.assertEqual("INSPECT_FILE_KIND_OR_LIMIT", capture._inspect_read(fifo, budget)[0]["code"])
        self.assertEqual("INSPECT_DEADLINE", capture._inspect_read(path, {"end": 0, "bytes": 0})[0]["code"])
        with patch.object(capture, "INSPECT_READ_BUDGET", 4):
            self.assertEqual("INSPECT_READ_LIMIT", capture._inspect_read(path, budget)[0]["code"])
            self.assertEqual("INSPECT_READ_LIMIT", capture._inspect_read(path, budget)[0]["code"])

    def test_subordinate_metadata_only_selects_numeric_caller_or_declared_runner(self):
        result = capture._inspect_allocations(b"runner:100000:65536\n1001:200000:65536\nOTHER_OWNER_CANARY:300000:65536\n", 1001)
        self.assertEqual(2, len(result["selectedRows"]))
        self.assertFalse(result["callerNameBindingVerified"])
        self.assertNotIn("OTHER_OWNER_CANARY", json.dumps(result))
        for raw, code in ((b"runner:4294967295:2\n", "INSPECT_SUBID_RANGE"),
                          (b"runner:no:2\n", "INSPECT_SUBID_RECORD"),
                          (b"\n" * 1025, "INSPECT_SUBID_LIMIT")):
            self.refuse(code, lambda: capture._inspect_allocations(raw, 1001))

    def test_inspection_query_argv_is_closed_read_only_and_has_no_helper_version_probe(self):
        budget = {"end": time.monotonic() + 30, "bytes": 0}
        with patch.object(capture, "command", return_value=(b"authored", b"", 0, None)) as command:
            for label in ("packages", "user-manager", "user-service"):
                command.return_value = (package_stdout() if label == "packages" else b"authored", b"", 0, None)
                self.assertEqual("observed", capture._inspect_query(label, 1001, self.directory, budget)["status"])
            calls = command.call_args_list
            self.assertEqual(3, len(calls))
            for call in calls:
                argv, env = call.args[:2]
                self.assertIn(argv[0], ("/usr/bin/dpkg-query", "/usr/bin/systemctl"))
                self.assertNotIn("--version", argv)
                self.assertNotIn("DOCKER_HOST", env)
                self.assertLessEqual(call.kwargs["seconds"], 8)
                self.assertEqual(8192, call.kwargs["limit"])
            self.refuse("INSPECT_QUERY", lambda: capture._inspect_query("start", 1001, self.directory, budget))
            self.assertEqual(3, command.call_count)

    def test_optional_package_absence_preserves_exact_mixed_query_evidence(self):
        out = package_stdout(include_optional=False)
        err = b"dpkg-query: no packages found matching rootlesskit\n"
        with patch.object(capture, "command", return_value=(out, err, 1, None)):
            row = capture._inspect_query("packages", 1001, self.directory,
                                         {"end": time.monotonic() + 30, "bytes": 0})
        self.assertEqual("observed", row["status"])
        self.assertEqual(1, row["exitCode"])
        self.assertEqual(out.decode("ascii"), row["stdout"])
        for stream, raw in (("stdout", out), ("stderr", err)):
            self.assertEqual(len(raw), row[stream + "Bytes"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row[stream + "Sha256"])
        self.assertEqual("399b526f433dbd5df1180ddf3bf733736fcfc5c9b8d1f51fc775fd05e67cc4b5", row["stderrSha256"])
        self.assertEqual("observed-unqualified", row["packageFacts"]["status"])
        self.assertEqual(["rootlesskit"], row["packageFacts"]["optionalAbsent"])
        self.assertIs(False, row["packageFacts"]["capturePrerequisitesQualified"])
        self.assertEqual({"dbus-user-session", "slirp4netns", "systemd", "uidmap"},
                         {item["name"] for item in row["packageFacts"]["installed"]})
        with self.mocked_host_inspection() as queries:
            previous = queries.side_effect
            queries.side_effect = lambda name, *args: row if name == "packages" else previous(name, *args)
            self.assertTrue(capture.inspect_host(ROOT, self.directory))
        receipt = json.loads((self.directory / "artifacts/host-inspection.json").read_bytes())
        self.assertEqual("observed-unqualified", receipt["status"])
        self.assertEqual(row, receipt["facts"]["queries"]["packages"])
        for flag in ("approved", "supportedBaseline", "captureRouteAdmitted", "workerStarted",
                     "targetExecuted", "referenceExecutionQualified"):
            self.assertIs(False, receipt[flag])

    def test_package_query_only_accepts_complete_exact_supported_outcomes(self):
        absent = package_stdout(include_optional=False)
        present = package_stdout()
        canonical = b"dpkg-query: no packages found matching rootlesskit\n"
        cases = [
            (absent.replace(b"uidmap\t1:4.8.1-2ubuntu2.2\tamd64\n", b""), canonical, 1),
            (absent, b"dpkg-query: no packages found matching uidmap\n", 1),
            (absent, canonical + b"another error\n", 1),
            (absent, canonical.rstrip(b"\n"), 1),
            (absent, b"", 1), (absent, canonical, 2), (present, canonical, 1),
            (present, b"unexpected warning\n", 0), (absent, b"", 0),
            (present + b"uidmap\t1:4.8.1-2ubuntu2.2\tamd64\n", b"", 0),
            (present + b"unexpected\t1.0\tamd64\n", b"", 0),
            (present.replace(b"amd64", b"bad arch", 1), b"", 0),
            (present.replace(b"1.0.1-2", b"not-a-version"), b"", 0),
            (present.replace(b"\n", b"\r\n"), b"", 0),
            (present.rstrip(b"\n"), b"", 0), (present + b"\n", b"", 0),
        ]
        for out, err, code in cases:
            with self.subTest(out=out, err=err, code=code), \
                 patch.object(capture, "command", return_value=(out, err, code, None)):
                row = capture._inspect_query("packages", 1001, self.directory,
                                             {"end": time.monotonic() + 30, "bytes": 0})
                self.assertEqual("refused", row["status"])
                self.assertEqual("INSPECT_PACKAGE_RESULT_UNSUPPORTED", row["code"])
                self.assertNotIn("packageFacts", row)
                self.assertEqual(code, row["exitCode"])
                self.assertEqual(hashlib.sha256(out).hexdigest(), row["stdoutSha256"])
                self.assertEqual(hashlib.sha256(err).hexdigest(), row["stderrSha256"])
        with patch.object(capture, "command", return_value=(present, b"", 0, None)):
            row = capture._inspect_query("packages", 1001, self.directory,
                                         {"end": time.monotonic() + 30, "bytes": 0})
        self.assertEqual("observed", row["status"])
        self.assertEqual([], row["packageFacts"]["optionalAbsent"])

    @contextmanager
    def mocked_host_inspection(self, *, missing_bus=False):
        (self.directory / "artifacts").mkdir()
        values = {"os-release": b'ID=ubuntu\nVERSION_ID="22.04"\n',
                  "apparmor_restrict_unprivileged_userns": b"0\n", "unprivileged_userns_clone": b"1\n",
                  "max_user_namespaces": b"1234\n", "cgroup": b"0::/authored/caller\n",
                  "subuid": b"runner:100000:65536\n", "subgid": b"runner:100000:65536\n",
                  "cgroup.controllers": b"cpu memory pids\n", "cgroup.subtree_control": b"cpu memory pids\n",
                  "cgroup.type": b"domain\n"}
        def read(path, budget, **kwargs):
            return {"path": str(path), "status": "observed", "bytes": 1, "sha256": "a" * 64}, values.get(path.name, b"authored")
        def query(name, uid, root, budget):
            return {"status": "observed", "stdout": {"packages": "uidmap\tauthored\tamd64\n",
                "user-manager": "Version=authored\nControlGroup=/authored/manager\n",
                "user-service": "Delegate=yes\nControlGroup=/authored/manager\nUser=1001\nActiveState=active\n"}[name]}
        metadata = types.SimpleNamespace(st_uid=1001, st_gid=1001, st_mode=0o140600, st_dev=1, st_ino=2)
        uname = types.SimpleNamespace(sysname="Linux", release="authored-kernel", version="authored-version", machine="x86_64")
        with patch.object(capture, "public_environment", return_value={"ImageOS": "authored", "ImageVersion": "authored"}), \
             patch.object(capture, "_inspect_read", side_effect=read), \
             patch.object(capture, "_inspect_query", side_effect=query) as queries, \
             patch.object(capture.Path, "resolve", lambda path, strict=False: path), \
             patch.object(capture.Path, "lstat", side_effect=FileNotFoundError if missing_bus else lambda path=None: metadata), \
             patch.object(capture.os, "uname", return_value=uname), \
             patch.object(capture.os, "getuid", return_value=1001), patch.object(capture.os, "geteuid", return_value=1001), \
             patch.object(capture.os, "getgid", return_value=1001), patch.object(capture.os, "getegid", return_value=1001), \
             patch.object(capture.os, "getgroups", return_value=[1001]), patch.object(capture.os, "getpid", return_value=12345), \
             patch.object(capture, "directory_fd", side_effect=lambda path: os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)), \
             patch.object(capture, "controller") as controller, patch.object(capture, "worker") as worker, \
             patch.object(capture, "prepare_inputs") as prepare, patch.object(capture, "preflight") as preflight:
            yield queries
        for effectful in (controller, worker, prepare, preflight):
            effectful.assert_not_called()

    def test_host_inspection_observed_receipt_never_approves_or_enters_capture_route(self):
        with self.mocked_host_inspection():
            self.assertTrue(capture.inspect_host(ROOT, self.directory))
        receipt = json.loads((self.directory / "artifacts/host-inspection.json").read_bytes())
        self.assertEqual("observed-unqualified", receipt["status"])
        self.assertEqual("2027-04-17", receipt["facts"]["runnerCandidate"]["expires"])
        for flag in ("approved", "supportedBaseline", "captureRouteAdmitted", "workerStarted", "targetExecuted", "referenceExecutionQualified"):
            self.assertIs(False, receipt[flag])

    def test_host_inspection_missing_bus_retains_refusal_without_start_or_query(self):
        with self.mocked_host_inspection(missing_bus=True) as queries:
            self.assertFalse(capture.inspect_host(ROOT, self.directory))
        self.assertEqual(["packages", "user-service"], [call.args[0] for call in queries.call_args_list])
        receipt = json.loads((self.directory / "artifacts/host-inspection.json").read_bytes())
        self.assertEqual("refused-unqualified", receipt["status"])
        self.assertIn("READ_ONLY_QUERY_REFUSED_OR_UNKNOWN", receipt["refusals"])

    def test_inspect_main_routes_only_inspection_and_returns_refusal_code(self):
        root = self.directory / "build/issue97-host-inspect"
        root.mkdir(mode=0o700, parents=True)
        with patch.object(capture.os, "environ", {"GITHUB_WORKSPACE": str(self.directory)}), \
             patch.object(capture.sys, "argv", ["capture", "--root", str(root), "--inspect-host"]), \
             patch.object(capture, "inspect_host", return_value=False) as inspect, \
             patch.object(capture, "controller") as controller, patch.object(capture, "worker") as worker, \
             patch.object(capture, "preflight") as preflight, patch.object(capture, "prepare_inputs") as prepare:
            self.assertEqual(78, capture.main())
        inspect.assert_called_once_with(self.directory, root)
        for effectful in (controller, worker, preflight, prepare):
            effectful.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
