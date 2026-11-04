"""Pure controls: injected CLI children only; no Docker endpoint is contacted."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/oracle/fixtures/gcc-reproduction-inspect.json"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = load("gcc_capture_adapter", ROOT / "scripts/capture-gcc-reproduction-inspect.py")
verifier = load("gcc_original_verifier", ROOT / "scripts/verify-gcc-toolchain-reproduction.py")
BUNDLE = json.loads(FIXTURE.read_bytes())


def original(name):
    return BUNDLE["originals"][name]["utf8"].encode()


def encoded(data):
    return (json.dumps(data, indent=2) + "\n").encode()


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class FakeChild:
    """No pipes, subprocess, socket, proc, manager, signal, or network operations."""
    def __init__(self, clock, chunks=(), *, status=0, stall=False, read_advance=0,
                 wait_advance=0, wait_error=False, cleanup_fail=False, close_fail=False):
        self.clock = clock
        self.chunks = list(chunks)
        self.status, self.stall = status, stall
        self.read_advance, self.wait_advance = read_advance, wait_advance
        self.wait_error = wait_error
        self.cleanup_fail, self.close_fail = cleanup_fail, close_fail
        self.events = []

    @property
    def pending(self):
        return bool(self.chunks) or self.stall

    def read(self, timeout):
        self.clock.now += self.read_advance or (timeout if self.stall else 0)
        return [self.chunks.pop(0)] if self.chunks else []

    def send(self, sig):
        self.events.append(("signal", sig))
        if self.cleanup_fail:
            raise OSError("injected signal failure")

    def wait(self, timeout):
        self.events.append(("wait", timeout))
        self.clock.now += self.wait_advance
        if self.wait_error:
            self.clock.now += timeout
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.status

    def close(self):
        self.events.append(("close",))
        if self.close_fail:
            raise OSError("injected close failure")


class InjectedCLI:
    def __init__(self, clock, inspect=None):
        self.clock = clock
        self.calls = []
        self.inputs = []
        self.raw = original("historical") if inspect is None else inspect
        self.default = original("pr1864")
        self.version = copy.deepcopy(BUNDLE["derived"]["version"])
        self.info = copy.deepcopy(BUNDLE["derived"]["info"])
        self.scoped = copy.deepcopy(BUNDLE["derived"]["scopedVersion"])
        self.override = {}

    def spawn(self, argv, env, cwd):
        self.calls.append((list(argv), dict(env)))
        index = len(self.calls) - 1
        if index in self.override:
            return self.override[index]
        if argv[0] == "docker":
            body = [encoded(self.version), encoded(self.info), self.default,
                    encoded(self.scoped), self.raw][index]
            return FakeChild(self.clock, [("stdout", body)])
        # Execute the real existing verifier entry point against the retained path.
        # Its parser and byte-loading are unchanged; only process transport is fake.
        self.inputs.append(Path(argv[-1]).read_bytes())
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.argv", argv[2:]), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = verifier.main()
        return FakeChild(self.clock, [("stdout", stdout.getvalue().encode()),
                                      ("stderr", stderr.getvalue().encode())], status=status)

    def __call__(self, argv, env, cwd, end, *, clock):
        return adapter.run_cli(argv, env, cwd, end, clock=clock, spawn=self.spawn)


class CaptureTest(unittest.TestCase):
    def setUp(self):
        # Deliberately create all test scratch under the repo even without TMPDIR.
        base = ROOT / "build/gcc-reproduction-adapter/tmp"
        # The CI control step creates this. Local evidence uses its own TMPDIR.
        base = Path(os.environ.get("TMPDIR", str(base)))
        self.assertTrue(base.resolve().is_relative_to(ROOT))
        base.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="gcc-inspect-", dir=base)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.clock = Clock()
        self.cli = InjectedCLI(self.clock)
        self.endpoint_root = Path("/home/runner/work/decomp_thing/decomp_thing")
        self.endpoint = "unix://" + str(self.endpoint_root / adapter.RUNTIME_BASE / "run-1234abcd/docker.sock")
        self.output = adapter.SCRATCH + "/capture"
        self.stderr = io.StringIO()
        self.provenance = {"run": "1", "attempt": "2", "headCommit": "a" * 40,
                           "executedCommit": "b" * 40, "executedTree": "c" * 40,
                           "classification": "FAKE pure control"}
        # Real verifier receives immutable repository inputs, while output is private.
        (self.root / "source-control.py").write_bytes(b"pure fake source bytes\n")

    def capture(self, **kw):
        # Tests substitute only file path roots for the three immutable verifier
        # inputs; no lock, recipe, historical record or verification logic changes.
        # Transport is inert. Validate the real workspace endpoint while retaining
        # evidence in the longer per-test directory, which is not a daemon root.
        validate_endpoint = adapter.selected_endpoint
        with patch.object(adapter, "selected_endpoint", side_effect=lambda value, root: validate_endpoint(value, self.endpoint_root)), \
             patch.object(adapter, "VERIFIER", str(ROOT / "scripts/verify-gcc-toolchain-reproduction.py")), \
             patch.object(adapter, "LOCK", str(ROOT / "oracle/gcc/16.2.0/toolchain-reproduction.json")), \
             patch.object(adapter, "RECORD", str(ROOT / "oracle/gcc/16.2.0/build-record.json")), \
             patch("subprocess.Popen", side_effect=AssertionError("real child forbidden")), \
             contextlib.redirect_stderr(self.stderr):
            return adapter.capture(kw.get("endpoint", self.endpoint), kw.get("output", self.output),
                                   self.provenance, root=self.root, clock=self.clock,
                                   transport=self.cli, environment={"DOCKER_HOST": "tcp://ambient:2375",
                                   "DOCKER_CONTEXT": "ambient", "DOCKER_API_VERSION": "1.55",
                                   "DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": "/untrusted"},
                                   sources=("source-control.py",))

    def receipt(self):
        return json.loads((self.root / self.output / "receipt.json").read_bytes())

    def assert_refused(self, **kw):
        self.assertNotEqual(0, self.capture(**kw))
        path = self.root / self.output / "receipt.json"
        if path.exists():
            self.assertEqual("rejected", self.receipt()["status"])
        self.assertFalse(any("GITHUB_ENV" in str(call) for call in self.cli.calls))

    def test_historical_bytes_exact_endpoint_api_and_real_verifier(self):
        self.assertEqual(0, self.capture(), self.stderr.getvalue())
        receipt = self.receipt()
        self.assertEqual("strict-verified-only", receipt["status"])
        self.assertEqual(0, receipt["verifierExit"])
        self.assertEqual({"source-control.py": hashlib.sha256(b"pure fake source bytes\n").hexdigest()}, receipt["sourceSha256"])
        self.assertEqual(self.provenance, receipt["provenance"])
        self.assertEqual(original("historical"), (self.root / self.output / "image-inspect.json").read_bytes())
        self.assertEqual([original("historical")], self.cli.inputs)
        self.assertEqual(original("pr1864"), (self.root / self.output / "default-inspect.stdout").read_bytes())
        self.assertEqual(hashlib.sha256(original("historical")).hexdigest(), receipt["inspectSha256"])
        self.assertEqual(6, len(self.cli.calls))
        for index, (argv, env) in enumerate(self.cli.calls):
            self.assertNotIn("DOCKER_HOST", env)
            self.assertNotIn("DOCKER_CONTEXT", env)
            self.assertNotIn("DOCKER_TLS_VERIFY", env)
            self.assertNotIn("DOCKER_CERT_PATH", env)
            self.assertEqual("1.49" if index in (3, 4) else None, env.get("DOCKER_API_VERSION"))
            if index < 5:
                self.assertEqual(["docker", "--host", self.endpoint], argv[:3])
            else:
                self.assertIn("-B", argv)
        self.assertIn("no service", receipt["authority"])

    def test_original_attribution_hashes_and_distinct_refusals(self):
        for name, item in BUNDLE["originals"].items():
            self.assertEqual(item["sha256"], hashlib.sha256(original(name)).hexdigest())
            self.assertTrue(item["source"].startswith("https://github.com/"))
        historical = json.loads(original("historical"))[0]
        faf = json.loads(original("faf"))[0]
        pr = json.loads(original("pr1864"))[0]
        self.assertEqual(historical["Config"], faf["Config"])
        self.assertEqual(historical["RootFS"]["Layers"][:8], faf["RootFS"]["Layers"][:8])
        self.assertNotEqual(historical["RootFS"]["Layers"][8], faf["RootFS"]["Layers"][8])
        self.assertEqual(historical["RootFS"]["Layers"], pr["RootFS"]["Layers"])
        self.assertEqual(pr["Id"], pr["Descriptor"]["digest"])
        self.assertEqual("application/vnd.oci.image.index.v1+json", pr["Descriptor"]["mediaType"])
        self.assertEqual(15, len(set(historical["Config"]) - set(pr["Config"])))
        for name in ("faf", "pr1864"):
            with self.subTest(name=name):
                self.output = adapter.SCRATCH + "/" + name
                self.cli = InjectedCLI(self.clock, original(name))
                self.assert_refused()
                self.assertEqual(1, self.receipt()["verifierExit"])
                self.assertIn("imageDigest mismatch", (self.root / self.output / "strict-verifier.stderr.partial").read_text())
                self.assertEqual([original(name)], self.cli.inputs)

    def test_identity_created_platform_config_removals_and_all_nine_layers(self):
        base = json.loads(original("historical"))
        mutations = []
        for field, value in (("Id", "sha256:" + "0" * 64), ("Created", "2000-01-01T00:00:00Z"),
                             ("Architecture", "arm64"), ("Os", "other"), ("Config", {})):
            mutant = copy.deepcopy(base); mutant[0][field] = value
            mutations.append(("change-" + field, mutant))
        for field in ("Id", "Created", "Architecture", "Os", "Config", "RootFS"):
            mutant = copy.deepcopy(base); del mutant[0][field]
            mutations.append(("remove-" + field, mutant))
        for mode in ("change", "remove"):
            mutant = copy.deepcopy(base)
            if mode == "change":
                mutant[0]["Config"]["User"] = "nobody"
            else:
                del mutant[0]["Config"]["User"]
            mutations.append((mode + "-Config-User", mutant))
        for index in range(9):
            mutant = copy.deepcopy(base); mutant[0]["RootFS"]["Layers"][index] = "sha256:" + "0" * 64
            mutations.append(("layer-" + str(index), mutant))
        for name, mutant in mutations:
            with self.subTest(name=name):
                self.output = adapter.SCRATCH + "/" + name
                self.cli = InjectedCLI(self.clock, encoded(mutant))
                self.assert_refused()
                self.assertEqual(1, self.receipt()["verifierExit"])
                self.assertEqual(6, len(self.cli.calls))

    def test_wrong_engine_store_api_and_range_stop_before_inspect_or_verifier(self):
        changes = [
            ("engine", "version", lambda x: x["Server"].update(Version="28.0.4"), 2),
            ("info-engine", "info", lambda x: x.update(ServerVersion="29.7.1"), 2),
            ("store", "info", lambda x: x.update(Driver="overlayfs"), 2),
            ("snapshotter", "info", lambda x: x.update(DriverStatus=[["driver-type", "io.containerd.snapshotter.v1"]]), 2),
            ("missing-status", "info", lambda x: x.pop("DriverStatus"), 2),
            ("malformed-status", "info", lambda x: x.update(DriverStatus="overlay2"), 2),
            ("duplicate-status", "info", lambda x: x.update(DriverStatus=[["x", "1"], ["x", "2"]]), 2),
            ("min-api", "version", lambda x: x["Server"].update(MinAPIVersion="1.50"), 2),
            ("max-api", "version", lambda x: x["Server"].update(ApiVersion="1.48"), 2),
            ("malformed-api", "version", lambda x: x["Server"].update(ApiVersion="1.49suffix"), 2),
            ("effective-api", "scoped", lambda x: x["Client"].update(ApiVersion="1.55"), 4),
            ("scoped-engine", "scoped", lambda x: x["Server"].update(Version="29.7.1"), 4),
            ("scoped-min", "scoped", lambda x: x["Server"].update(MinAPIVersion="1.50"), 4),
        ]
        for name, target, change, calls in changes:
            with self.subTest(name=name):
                self.output = adapter.SCRATCH + "/" + name
                self.cli = InjectedCLI(self.clock)
                change(getattr(self.cli, target))
                self.assert_refused()
                self.assertEqual(calls, len(self.cli.calls))
                self.assertEqual([], self.cli.inputs)

    def test_endpoint_rejections_never_invoke_transport(self):
        for endpoint in ("", "/var/run/docker.sock", "unix:///var/run/docker.sock", "default",
                         "tcp://localhost:2375", self.endpoint + "?x=1", self.endpoint + "\n",
                         self.endpoint.replace("run-1234abcd", "../run-1234abcd"),
                         self.endpoint.replace("unix:///", "unix:////")):
            with self.subTest(endpoint=endpoint):
                self.assert_refused(endpoint=endpoint)
                self.assertEqual([], self.cli.calls)

    def test_malformed_duplicate_nonfinite_and_invalid_utf8_json(self):
        for index in (0, 1, 2, 3, 4):
            for number, payload in enumerate((b'{', b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff')):
                with self.subTest(index=index, payload=payload):
                    self.output = adapter.SCRATCH + f"/bad-json-{index}-{number}"
                    self.cli = InjectedCLI(self.clock)
                    self.cli.override[index] = FakeChild(self.clock, [("stdout", payload)])
                    self.assert_refused()
                    self.assertEqual([], self.cli.inputs)
                    self.assertIsNone(self.receipt()["verifierExit"])
        self.output = adapter.SCRATCH + "/nested-duplicate"
        self.cli = InjectedCLI(self.clock, b'[{"Config":{"User":"","User":""}}]')
        self.assert_refused()
        self.assertIn("duplicate JSON", self.receipt()["primaryError"])

    def test_empty_or_multiple_inspect_images_rejected_by_real_verifier(self):
        for count in (0, 2):
            self.output = adapter.SCRATCH + f"/count-{count}"
            self.cli = InjectedCLI(self.clock, encoded(json.loads(original("historical")) * count))
            self.assert_refused()
            self.assertEqual(1, self.receipt()["verifierExit"])

    def test_cli_failure_and_partial_capture_do_not_leave_complete_input(self):
        for index in range(5):
            self.output = adapter.SCRATCH + f"/failure-{index}"
            self.cli = InjectedCLI(self.clock)
            self.cli.override[index] = FakeChild(self.clock, [("stdout", b'partial'), ("stderr", b'primary details')], status=17)
            self.assertEqual(17, self.capture())
            self.assertEqual("rejected", self.receipt()["status"])
            self.assertFalse((self.root / self.output / "image-inspect.json").exists())
            self.assertEqual([], self.cli.inputs)

    def test_existing_output_and_symlink_are_never_reused_or_overwritten(self):
        self.assertEqual(0, self.capture())
        before = {p.name: p.read_bytes() for p in (self.root / self.output).iterdir() if p.is_file()}
        count = len(self.cli.calls)
        self.assertNotEqual(0, self.capture())
        self.assertEqual(count, len(self.cli.calls))
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / self.output).iterdir() if p.is_file()})
        linked = self.root / adapter.SCRATCH / "linked"
        linked.symlink_to(self.root / self.output, target_is_directory=True)
        self.assertNotEqual(0, self.capture(output=adapter.SCRATCH + "/linked"))
        self.assertNotEqual(0, self.capture(output=adapter.SCRATCH + "/linked/nested"))
        self.assertFalse((self.root / self.output / "nested").exists())
        self.assertEqual(count, len(self.cli.calls))

    def test_output_escape_rejected(self):
        for output in ("/tmp/output", "build/../escape", "build/gcc-reproduction-adapter/../escape",
                       "build/gcc-reproduction-adapter//escape"):
            self.assert_refused(output=output)
        self.assertEqual([], self.cli.calls)

    def test_failure_evidence_error_preserves_primary_exit(self):
        self.cli.override[0] = FakeChild(self.clock, [("stderr", b'original')], status=23)
        with patch.object(adapter.Evidence, "write", side_effect=OSError("disk full")):
            self.assertEqual(23, self.capture())
        report = json.loads(self.stderr.getvalue())
        self.assertIn("CLI exited 23", report["primaryError"])
        self.assertTrue(any("disk full" in item for item in report["secondaryErrors"]))
        self.assertFalse((self.root / self.output / "receipt.json").exists())

    def test_evidence_close_failure_revokes_success_receipt(self):
        close = adapter.Evidence.close
        def broken_close(evidence):
            raise OSError("injected directory close failure")
        instances = []
        original_init = adapter.Evidence.__init__
        def record_init(evidence, *args):
            original_init(evidence, *args)
            instances.append(evidence)
        try:
            with patch.object(adapter.Evidence, "__init__", record_init), patch.object(adapter.Evidence, "close", broken_close):
                self.assert_refused()
                self.assertFalse((self.root / self.output / "receipt.json").exists())
        finally:
            for instance in instances:
                close(instance)

    def test_late_directory_close_revokes_receipt_using_original_directory(self):
        close = adapter.Evidence.close
        def late(evidence):
            close(evidence)
            self.clock.now = 120
        with patch.object(adapter.Evidence, "close", late):
            self.assertEqual(124, self.capture())
        self.assertFalse((self.root / self.output / "receipt.json").exists())

    def test_multi_call_total_deadline_and_output_cap_fail_closed(self):
        for mode in ("total", "stdout", "stderr"):
            self.output = adapter.SCRATCH + "/" + mode
            self.clock = Clock(); self.cli = InjectedCLI(self.clock)
            if mode == "total":
                spawn = self.cli.spawn
                def slow(*args):
                    child = spawn(*args)
                    child.read_advance = 24
                    return child
                self.cli.spawn = slow
            else:
                cap = adapter.STDOUT_CAP if mode == "stdout" else adapter.STDERR_CAP
                self.cli.override[4] = FakeChild(self.clock, [(mode, b'x' * (cap + 1))])
            self.assert_refused()
            self.assertEqual([], self.cli.inputs)
            self.assertFalse((self.root / self.output / "image-inspect.json").exists())

    def test_late_verifier_or_receipt_cannot_return_success(self):
        real = adapter.Evidence.write
        for name in ("image-inspect.json", "strict-verifier.stdout", "receipt.json"):
            self.output = adapter.SCRATCH + "/late-" + name
            self.clock = Clock(); self.cli = InjectedCLI(self.clock)
            def late(evidence, filename, data):
                real(evidence, filename, data)
                if filename == name:
                    self.clock.now = 120
            with patch.object(adapter.Evidence, "write", late):
                self.assert_refused()
            if name == "image-inspect.json":
                self.assertEqual([], self.cli.inputs)


class TransportTest(unittest.TestCase):
    def run_child(self, child, end=120):
        return adapter.run_cli(["fake"], {}, ROOT, end, clock=child.clock,
                               spawn=lambda *_: child)

    def test_production_child_wrapper_uses_only_injected_process_and_pipe_operations(self):
        pipes = [MagicMock(), MagicMock()]
        pipes[0].fileno.return_value = 101
        pipes[1].fileno.return_value = 102
        process = MagicMock(pid=123)
        process.stdout, process.stderr = pipes
        process.wait.return_value = 0
        selector = MagicMock()
        registered = {}
        def register(pipe, events, stream):
            registered[pipe] = SimpleNamespace(fileobj=pipe, data=stream)
        selector.register.side_effect = register
        selector.get_map.side_effect = lambda: registered
        selector.select.side_effect = lambda timeout: [(key, 1) for key in list(registered.values())]
        selector.unregister.side_effect = lambda pipe: registered.pop(pipe)
        payload = {101: [b'exact stdout', b''], 102: [b'exact stderr', b'']}
        with patch.object(adapter.subprocess, "Popen", return_value=process) as popen, \
             patch.object(adapter.selectors, "DefaultSelector", return_value=selector), \
             patch.object(adapter.os, "set_blocking") as nonblocking, \
             patch.object(adapter.os, "read", side_effect=lambda fd, size: payload[fd].pop(0)) as read, \
             patch.object(adapter.os, "killpg") as kill:
            result = adapter.run_cli(["docker", "--host", "unix:///fake", "version"],
                                     {"FAKE": "1"}, ROOT, 120, clock=Clock())
        self.assertEqual((b'exact stdout', b'exact stderr'), result)
        self.assertEqual(2, nonblocking.call_count)
        self.assertTrue(all(call.args[1] == 65536 for call in read.call_args_list))
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(subprocess.DEVNULL, popen.call_args.kwargs["stdin"])
        kill.assert_not_called()
        for pipe in pipes:
            pipe.close.assert_called_once()
        selector.close.assert_called_once()

    def test_registration_failure_uses_same_cleanup_and_preserves_cause(self):
        process = MagicMock(pid=123)
        process.stdout.fileno.return_value = 101
        process.wait.return_value = 0
        selector = MagicMock()
        selector.register.side_effect = OSError("registration failed")
        with patch.object(adapter.subprocess, "Popen", return_value=process), \
             patch.object(adapter.selectors, "DefaultSelector", return_value=selector), \
             patch.object(adapter.os, "set_blocking"), \
             patch.object(adapter.os, "killpg") as kill:
            with self.assertRaisesRegex(adapter.Refusal, "registration failed"):
                adapter.run_cli(["fake"], {}, ROOT, 120, clock=Clock())
        self.assertEqual([(123, signal.SIGTERM), (123, signal.SIGKILL)],
                         [call.args for call in kill.call_args_list])
        process.wait.assert_called_once()
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()
        selector.close.assert_called_once()

    def test_output_caps_are_active_and_cleanup_is_term_kill_reap(self):
        for stream, cap in (("stdout", adapter.STDOUT_CAP), ("stderr", adapter.STDERR_CAP)):
            with self.subTest(stream=stream):
                child = FakeChild(Clock(), [(stream, b'x' * cap), (stream, b'x'), (stream, b'NEVER READ')])
                with self.assertRaisesRegex(adapter.Refusal, "byte cap") as caught:
                    self.run_child(child)
                self.assertEqual(cap, len(getattr(caught.exception, stream)))
                self.assertEqual(1, len(child.chunks))
                self.assertEqual([("signal", signal.SIGTERM), ("signal", signal.SIGKILL)], child.events[:2])
                self.assertLessEqual(child.events[2][1], 5)
                self.assertEqual(("close",), child.events[-1])

    def test_exact_output_caps_are_accepted(self):
        child = FakeChild(Clock(), [("stdout", b'x' * adapter.STDOUT_CAP), ("stderr", b'x' * adapter.STDERR_CAP)])
        out, err = self.run_child(child)
        self.assertEqual(adapter.STDOUT_CAP, len(out))
        self.assertEqual(adapter.STDERR_CAP, len(err))
        self.assertFalse(any(event[0] == "signal" for event in child.events))

    def test_stalled_and_progressing_deadlines_and_late_eof(self):
        for child in (FakeChild(Clock(), stall=True),
                      FakeChild(Clock(), [("stdout", b'x')] * 100, read_advance=1),
                      FakeChild(Clock(), [("stdout", b'x')], read_advance=31),
                      FakeChild(Clock(), wait_advance=31)):
            with self.subTest(child=child):
                with self.assertRaisesRegex(adapter.Refusal, "deadline"):
                    self.run_child(child)
                self.assertEqual(("close",), child.events[-1])

    def test_total_budget_reserves_cleanup_and_prevents_next_spawn(self):
        clock = Clock(); clock.now = 110
        child = FakeChild(clock, stall=True, wait_error=True)
        with self.assertRaises(adapter.Refusal) as caught:
            self.run_child(child)
        self.assertLessEqual(clock.now, 120.00001)
        self.assertEqual(124, caught.exception.code)
        self.assertTrue(caught.exception.cleanup)
        with self.assertRaises(adapter.Refusal):
            adapter.run_cli(["fake"], {}, ROOT, 120, clock=clock,
                            spawn=lambda *_: self.fail("expired operation spawned child"))

    def test_spawn_error_and_signal_reap_close_errors_preserve_primary(self):
        with self.assertRaisesRegex(adapter.Refusal, "spawn failed"):
            adapter.run_cli(["fake"], {}, ROOT, 120, clock=Clock(),
                            spawn=lambda *_: (_ for _ in ()).throw(OSError("spawn failed")))
        child = FakeChild(Clock(), [("stderr", b'x' * (adapter.STDERR_CAP + 1))],
                          cleanup_fail=True, wait_error=True, close_fail=True)
        with self.assertRaisesRegex(adapter.Refusal, "stderr exceeded") as caught:
            self.run_child(child)
        self.assertEqual(125, caught.exception.code)
        self.assertEqual(4, len(caught.exception.cleanup))
        self.assertEqual(5, child.clock.now)

    def test_wait_timeout_terminates_and_reaps(self):
        child = FakeChild(Clock(), wait_error=True)
        with self.assertRaises(adapter.Refusal) as caught:
            self.run_child(child)
        self.assertEqual(124, caught.exception.code)
        self.assertEqual(("signal", signal.SIGTERM), child.events[1])
        self.assertEqual(("signal", signal.SIGKILL), child.events[2])
        self.assertLessEqual(child.clock.now, 30)


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ.get("TMPDIR", str(ROOT / "build/gcc-reproduction-adapter/tmp")))
        self.assertTrue(base.resolve().is_relative_to(ROOT)); base.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=base); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evidence = adapter.Evidence(self.root, adapter.SCRATCH + "/capture")
        self.addCleanup(self.evidence.close)

    def test_existing_file_symlink_and_partial_are_exclusive(self):
        self.evidence.write("existing", b'original')
        with self.assertRaises(adapter.Refusal):
            self.evidence.write("existing", b'replacement')
        self.assertEqual(b'original', (self.evidence.path / "existing").read_bytes())
        (self.evidence.path / "linked").symlink_to(self.evidence.path / "existing")
        with self.assertRaises(adapter.Refusal):
            self.evidence.write("linked", b'replacement')
        self.assertEqual(b'original', (self.evidence.path / "existing").read_bytes())
        (self.evidence.path / ".reserved.partial").write_bytes(b'prior partial')
        with self.assertRaises(FileExistsError):
            self.evidence.write("reserved", b'new')
        self.assertEqual(b'prior partial', (self.evidence.path / ".reserved.partial").read_bytes())

    def test_short_writes_complete_exactly(self):
        write = os.write
        with patch.object(adapter.os, "write", lambda fd, data: write(fd, data[:3])):
            self.evidence.write("short", b'0123456789')
        self.assertEqual(b'0123456789', (self.evidence.path / "short").read_bytes())

    def test_partial_write_and_fsync_failure_never_publish_complete_file(self):
        write = os.write
        for mode in ("partial", "zero", "fsync"):
            count = 0
            def broken(fd, data):
                nonlocal count
                count += 1
                if mode == "zero":
                    return 0
                if count > 1:
                    raise OSError("primary write error")
                return write(fd, data[:2])
            with self.subTest(mode=mode):
                context = patch.object(adapter.os, "fsync", side_effect=OSError("fsync failed")) if mode == "fsync" else patch.object(adapter.os, "write", broken)
                with context, self.assertRaises(adapter.Refusal):
                    self.evidence.write(mode, b'12345678')
                self.assertFalse((self.evidence.path / mode).exists())
                self.assertFalse((self.evidence.path / ("." + mode + ".partial")).exists())

    def test_cleanup_error_does_not_replace_primary_write_failure(self):
        with patch.object(adapter.os, "write", side_effect=OSError("primary disk failure")), \
             patch.object(adapter.os, "unlink", side_effect=OSError("cleanup failed")):
            with self.assertRaisesRegex(adapter.Refusal, "primary disk failure") as caught:
                self.evidence.write("broken", b'data')
        self.assertIn("cleanup failed", caught.exception.cleanup[0])
        self.assertFalse((self.evidence.path / "broken").exists())


class SocketBoundsTest(unittest.TestCase):
    def test_all_derived_socket_paths_fit_hosted_workspace(self):
        root = Path("/home/runner/work/decomp_thing/decomp_thing")
        paths = adapter.runtime_socket_paths(root, "run-1234abcd")
        self.assertEqual(4, len(paths))
        self.assertTrue(all(len(os.fsencode(p)) <= 107 for p in paths))
        self.assertEqual("containerd-debug.sock", paths[-1].name)
        endpoint = "unix://" + str(paths[0])
        self.assertEqual(endpoint, adapter.selected_endpoint(endpoint, root))
        with self.assertRaises(adapter.Refusal):
            adapter.selected_endpoint("unix://" + str(root / adapter.SCRATCH / "docker/run-1234abcd/docker.sock"), root)

    def test_exact_byte_limit_and_one_over_include_internal_socket(self):
        suffix = "/.d/run-1234abcd/execroot/containerd/containerd-debug.sock"
        root = Path("/" + "a" * (107 - len(suffix) - 1))
        paths = adapter.runtime_socket_paths(root, "run-1234abcd")
        self.assertEqual(107, len(os.fsencode(paths[-1])))
        too_long = Path(str(root) + "a")
        self.assertLess(len(os.fsencode(too_long / ".d/run-1234abcd/docker.sock")), 107)
        with self.assertRaises(adapter.Refusal):
            adapter.runtime_socket_paths(too_long, "run-1234abcd")
        with self.assertRaises(adapter.Refusal):
            adapter.selected_endpoint("unix://" + str(too_long / ".d/run-1234abcd/docker.sock"), too_long)

    def test_utf8_path_uses_bytes_and_preflight_starts_nothing(self):
        suffix = "/.d/run-00000000/execroot/containerd/containerd-debug.sock"
        root = Path("/" + "a" * (107 - len(suffix) - 2) + "é")
        self.assertLess(len(str(root) + suffix), 108)
        with self.assertRaises(adapter.Refusal):
            adapter.runtime_socket_paths(root)
        with patch.object(adapter, "ROOT", Path("/repo")), patch("sys.argv", ["capture", "--check-runtime-root"]), \
                patch.object(adapter, "capture", side_effect=AssertionError("capture forbidden")), \
                patch("subprocess.Popen", side_effect=AssertionError("child forbidden")):
            self.assertEqual(0, adapter.main())
        with patch.object(adapter, "ROOT", root), patch("sys.argv", ["capture", "--check-runtime-root"]), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                adapter.main()
            self.assertEqual(2, caught.exception.code)


class WorkflowTest(unittest.TestCase):
    """The head-owned rootless producer is selected; the setup-action adapter route
    remains a standalone tested utility and is inactive in this workflow."""

    def test_owned_producer_scoping_and_strict_live_publication_order(self):
        source = (ROOT / ".github/workflows/gcc-oracle-model.yml").read_text()
        job = source.split("  provenance-and-elf-verifier:\n", 1)[1].split(
            "  driver-dwarf-interfaces:\n", 1
        )[0]
        builder = (ROOT / "scripts/ci-gcc-toolchain-builder.sh").read_text()
        owner = (ROOT / "scripts/ci-gcc-toolchain-owner.py").read_text()

        def fn(name, nxt):
            start = builder.index("\n" + name + "() {\n")
            end = builder.index("\n" + nxt + "() {", start)
            return builder[start:end]

        init = fn("init", "authenticate")
        start_rootless = fn("start_rootless", "start_buildkit")
        capture = fn("capture_toolchain_inspect", "reproduce")
        reproduce = fn("reproduce", "build_solve_argv")
        clean_start = builder.index("clean_environment() {")
        clean_end = builder.index("\nmonotonic_remaining() {", clean_start)
        clean_environment = builder[clean_start:clean_end]

        def assert_owned_docker_calls(region, expected_calls, data_uses=()):
            # These exact occurrences pass/print the pinned path as data, never execute it.
            # Account for them explicitly before checking every remaining variable use.
            for data_use in data_uses:
                self.assertEqual(1, region.count(data_use))
                region = region.replace(data_use, "", 1)
            self.assertEqual(expected_calls, region.count('"$docker_bin"'))
            self.assertEqual(expected_calls, region.count('"$docker_bin" --host "unix://$socket"'))

        # A1: builder script enforces shell failure behavior.
        self.assertTrue(builder.startswith("#!/usr/bin/env bash\n# "))
        self.assertIn("\nset -Eeuo pipefail\n", builder[:200])

        # A2: the owned builder alone provisions the selected behavior engine.
        self.assertNotIn("docker/setup-docker-action", job)
        self.assertIn("run: bash scripts/ci-gcc-toolchain-builder.sh authenticate", job)
        self.assertIn("run: bash scripts/ci-gcc-toolchain-builder.sh start-rootless", job)
        self.assertEqual(1, job.count("ci-gcc-toolchain-builder.sh start-rootless"))
        self.assertEqual(1, job.count("ci-gcc-toolchain-builder.sh authenticate"))
        self.assertNotIn("dockerd-rootless.sh", job)

        # A3: exact Docker archive, executable and client/server identities are pinned.
        self.assertIn("docker-29.7.2.tgz", builder)
        self.assertIn("docker_hash=803d433f226db4776e1768fd319fc6c6e4935a456acf84fcc0080818b854bc8f", builder)
        self.assertIn("check_executable \"$docker_bin\" 42677472 e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13", builder)
        self.assertIn("= 29.7.2", start_rootless)
        self.assertIn("= 6a43e3d", start_rootless)
        self.assertIn("'29.7.2'", capture)
        self.assertIn("'6a43e3d'", capture)
        self.assertIn("'a7dcaa6'", capture)
        self.assertIn("e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13", capture)

        # A4: repo-relative socket root and every reserved Unix endpoint fit 107 bytes.
        self.assertIn('build_root="$repo/build/g"', builder)
        self.assertIn('socket="$job_root/d.sock"', builder)
        self.assertIn("(( ${#path} <= 107 ))", builder)

        # A5: validate socket bounds before reservation and before rootless launch.
        self.assertLess(init.index("validate_socket_inventory"), init.index("owner_call reserve"))
        self.assertLess(start_rootless.index("validate_socket_inventory"), start_rootless.index("owner_call launch-rootless"))
        self.assertLess(job.index("ci-gcc-toolchain-builder.sh init"), job.index("ci-gcc-toolchain-builder.sh start-rootless"))
        self.assertLess(job.index("ci-gcc-toolchain-builder.sh start-rootless"), job.index("ci-gcc-toolchain-builder.sh reproduce"))

        # A6: each Docker CLI invocation in the relevant producer functions has an explicit owned host.
        assert_owned_docker_calls(start_rootless, 5)
        assert_owned_docker_calls(capture, 2, (
            "admission=$(python3 - \"$version_file\" \"$inspect_api\" \"$fingerprint_file\" \"$docker_bin\" \"$source_file\" <<'PYVERSION'",
            'python3 - "$inspect_file" "$version_file" "$provenance_file" "$docker_bin" ' + chr(92),
        ))
        assert_owned_docker_calls(reproduce, 3, (
            'printf \'DOCKER=%s\\nDOCKER_HOST=unix://%s\\n\' "$docker_bin" "$socket" >> "$GITHUB_ENV"',
        ))
        self.assertEqual(2, capture.count("env -u DOCKER_HOST -u DOCKER_CONTEXT"))
        self.assertIn("unset DOCKER_HOST DOCKER_CONTEXT", clean_environment)
        self.assertIn("reproduce() {\n  clean_environment\n", reproduce)

        # A7: classic store selection and overlay2 are independently guarded by owner source.
        self.assertIn("printf '{\"features\":{\"containerd-snapshotter\":false}}\\n' > \"$state/docker-daemon.json\"", start_rootless)
        self.assertIn('"--storage-driver=overlay2"', owner)
        self.assertIn('info.get("Driver") != "overlay2"', owner)
        self.assertIn('version != ["29.7.2", "6a43e3d"]', owner)

        # A8: published Docker selection comes from the same owned producer socket.
        self.assertIn('printf \'DOCKER=%s\\nDOCKER_HOST=unix://%s\\n\' "$docker_bin" "$socket" >> "$GITHUB_ENV"', reproduce)
        reproduce_step = job.index("ci-gcc-toolchain-builder.sh reproduce")
        self.assertNotIn("DOCKER_HOST:", job[:reproduce_step])

        # A9: no double-wrapped URI or adapter output is selected.
        self.assertNotIn("unix://unix://", builder)
        self.assertNotIn("steps.gcc-reproduction-docker", job)
        self.assertIn('socket="$job_root/d.sock"', builder)

        # A10: API 1.49 stays local to inspect capture, never in workflow ambient env.
        self.assertNotIn("DOCKER_API_VERSION", job)
        self.assertEqual(2, builder.count("DOCKER_API_VERSION"))
        self.assertEqual(2, capture.count("DOCKER_API_VERSION"))
        self.assertIn("local inspect_api=1.49", capture)
        self.assertIn("if effective != selected:", capture)
        self.assertIn("if not minimum <= selected <= maximum:", capture)

        # A11: clean-merged pure controls still run before source fetching.
        self.assertLess(job.index("tests.oracle.test_gcc_reproduction_inspect"), job.index("Fetch and fully verify"))

        # A12: capture precedes strict verification on the complete, unmodified response.
        self.assertLess(reproduce.index("capture_toolchain_inspect"), reproduce.index("scripts/verify-gcc-toolchain-reproduction.py"))
        self.assertLess(reproduce.index("scripts/verify-gcc-toolchain-reproduction.py"), reproduce.index("scripts/verify-gcc-oracle-build-record.py"))
        self.assertIn('< "$evidence/image-inspect.json"', reproduce)
        self.assertIn("'strictVerifierInput': 'complete unmodified image-inspect.json bytes'", capture)

        # A13: the contained live check must succeed before IDs or Docker selection publish.
        self.assertLess(reproduce.index("verify-gcc-oracle-build-record.py"), reproduce.index("GCC_TOOLCHAIN_IMAGE_ID=%s"))
        self.assertLess(reproduce.index("GCC_TOOLCHAIN_IMAGE_ID=%s"), reproduce.index("DOCKER_HOST=unix://%s"))
        self.assertIn("|| die 'contained live GCC build-record verifier failed'", reproduce)
        self.assertNotIn('echo "GCC_TOOLCHAIN_IMAGE_ID=', job)
        self.assertIn("--network none --read-only --cap-drop ALL", reproduce)

        # A14: source epoch is pinned in both solve construction and admission.
        self.assertIn("--opt build-arg:SOURCE_DATE_EPOCH=1786060800", builder)
        self.assertIn(" build-arg:SOURCE_DATE_EPOCH=1786060800 ", builder)

        # A15: capture provenance and evidence remain attached to the owned run.
        self.assertIn("build/g/*/evidence", job)
        self.assertIn("image-inspect-api-provenance.json", capture)
        self.assertIn("gcc-inspect-api-provenance/v1", capture)

        # A16: master setup-action route remains explicitly inactive in the selected workflow.
        self.assertNotIn("capture-gcc-reproduction-inspect.py --endpoint", job)
        self.assertNotIn("--check-runtime-root", job)


if __name__ == "__main__":
    unittest.main()
