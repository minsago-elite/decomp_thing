from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNER_PATH = ROOT / "scripts/ci-gcc-toolchain-owner.py"
spec = importlib.util.spec_from_file_location("gcc_owner", OWNER_PATH)
owner_module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(owner_module)


class FakeBackend:
    def __init__(self, *, fail_reserve=False, empty=True, missing_stop=False):
        self.fail_reserve = fail_reserve
        self.empty = empty
        self.missing_stop = missing_stop
        self.calls = []

    def manager_reserve(self, role, manifest):
        self.calls.append(("reserve", role))
        if self.fail_reserve:
            raise owner_module.Refusal("authored manager denial")
        return {"ownerToken": manifest["ownerToken"], "role": role, "unit": "test.scope",
                "controlGroup": "/test/owned", "device": 1, "inode": 2, "invocationId": "fixture"}

    def manager_prepare_gate(self, role, manifest):
        self.calls.append(("prepare-gate", role))
        return {"ownerToken": manifest["ownerToken"], "role": role, "pidfdHeld": True,
                "daemonCgroup": "/test/owned/daemon"}

    def manager_gate(self, role, manifest):
        self.calls.append(("gate", role))
        return {"ownerToken": manifest["ownerToken"], "role": role, "unit": "test.scope",
                "controlGroup": "/test/owned", "device": 1, "inode": 2,
                "exec": {"pidfdHeld": True, "identity": {"exe": "/pinned/buildkitd"}}}

    def manager_stop(self, role, receipt, timeout):
        self.calls.append(("stop", role, timeout))
        if self.missing_stop:
            return {"ownerToken": receipt["ownerToken"], "role": role, "status": "stopped"}
        return {"ownerToken": receipt["ownerToken"], "role": role, "status": "stopped",
                "preKillReceipt": {"ownerToken": receipt["ownerToken"], "role": role, "pidfdHeld": True},
                "killReceipt": {"ownerToken": receipt["ownerToken"], "role": role, "empty": True},
                "cgroupEmpty": True}

    def domain_empty(self, role, receipt, timeout):
        self.calls.append(("empty", role, timeout))
        return self.empty

    def release_domains(self, manifest, timeout):
        return {"released": [{"role": "buildkit", "inactive": True}]}


class FakeCommandRunner:
    """Authored command responder; it never starts an operating-system process."""
    def __init__(self, token, role="buildkit"):
        self.token = token
        self.role = role
        self.calls = []
        self.stopped = set()

    def run(self, argv, timeout, *, input_data=None, env=None):
        self.calls.append((list(argv), timeout, env))
        if argv[0] == "/usr/bin/systemctl" and "--version" in argv:
            return 0, b"systemd 255 (255.4)\n", b""
        if argv[0] == "/usr/bin/systemctl" and "show" in argv:
            unit = argv[-1]
            is_slice = unit.endswith(".slice")
            prefix = "dgb" if self.role == "buildkit" else "dgr"
            cgroup = f"/system.slice/{unit}" if is_slice else f"/system.slice/{prefix}{self.token}.slice/{unit}"
            inactive = unit in self.stopped
            values = [
                ("Slice", "" if is_slice else f"{prefix}{self.token}.slice"),
                ("ControlGroup", cgroup),
                ("InvocationID", "invocation-fixture"),
                ("SubState", "dead" if inactive else ("active" if is_slice else "running")),
                ("ActiveState", "inactive" if inactive else "active"),
                ("Description", f"decomp-gcc-owner:{self.token}:{self.role}"),
                ("Id", unit),
            ]
            return 0, ("\n".join(f"{name}={value}" for name, value in values) + "\n").encode(), b""
        if "StopUnit" in argv:
            self.stopped.add(argv[-2])
            return 0, b'{"type":"o","data":"/org/freedesktop/systemd1/job/78"}', b""
        if "StartTransientUnit" in argv:
            return 0, b'{"type":"o","data":["/org/freedesktop/systemd1/job/77"]}', b""
        if "GetUnit" in argv:
            return 0, b'{"type":"o","data":["/org/freedesktop/systemd1/unit/fixture"]}', b""
        return 1, b"", b"unrecognized authored fixture argv"


class FakeAuthority:
    def __init__(self, *, empty=False):
        self.empty = empty

    def capabilities(self, root, role, timeout):
        return {"unified": True, "controllers": ["memory", "pids"], "events": True,
                "cgroupKill": True, "bootId": "boot-fixture", "userManager": True}

    def inspect(self, root, role, timeout):
        receipt = json.loads((root / "control" / f"manager-receipt-{role}.json").read_text())
        return {"ownerToken": receipt["ownerToken"], "role": role,
                "bootId": "boot-fixture", "currentBootId": "boot-fixture",
                "sliceControlGroup": receipt["sliceControlGroup"],
                "serviceControlGroup": receipt["controlGroup"], "sliceDevice": 4, "sliceInode": 5,
                "serviceDevice": 4, "serviceInode": 6,
                "limits": {"memory.max": str(4 * 1024**3), "memory.swap.max": "0", "pids.max": "1024"},
                "populated": 0 if self.empty else 1, "allDescendantsEmpty": self.empty}

    def kill(self, root, role, timeout):
        receipt = json.loads((root / "control" / f"manager-receipt-{role}.json").read_text())
        return {"ownerToken": receipt["ownerToken"], "role": role,
                "bootId": "boot-fixture", "device": 4, "inode": 5, "empty": True}


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, duration):
        self.now += duration


class FakeCgroupIO:
    def __init__(self, *, frozen=True, empty=True, freeze_error=None):
        self.is_frozen = frozen
        self.is_empty = empty
        self.freeze_error = freeze_error
        self.calls = []

    def verify(self, path, device, inode):
        self.calls.append(("verify", path, device, inode))

    def write_control(self, path, name, value, device, inode):
        self.calls.append(("write", name, value))
        if name == "cgroup.freeze" and self.freeze_error:
            raise self.freeze_error

    def frozen(self, path, device, inode):
        self.calls.append(("frozen",))
        return self.is_frozen

    def empty(self, path, device, inode, deadline):
        self.calls.append(("empty",))
        return self.is_empty


class FakeProfileRunner:
    """Models only authored AppArmor parser/profile-list effects under the repo fixture."""
    def __init__(self, *, profiles=(), fail_add=False, fail_remove=False, timeout_after_remove=False,
                 timeout_after_add=False, omit_add_readback=False):
        self.profiles = set(profiles)
        self.fail_add = fail_add
        self.fail_remove = fail_remove
        self.timeout_after_remove = timeout_after_remove
        self.timeout_after_add = timeout_after_add
        self.omit_add_readback = omit_add_readback
        self.calls = []

    def run(self, argv, timeout, *, input_data=None, env=None):
        self.calls.append((list(argv), timeout))
        if argv[:5] == ["/usr/bin/sudo", "-n", "/usr/bin/cat", "/sys/kernel/security/apparmor/profiles"]:
            return 0, ("".join(name + " (unconfined)\n" for name in sorted(self.profiles))).encode(), b""
        if "/usr/sbin/apparmor_parser" in argv:
            profile = Path(argv[-1]).read_text()
            name = profile.split("profile ", 1)[1].split(" ", 1)[0]
            if "--add" in argv:
                if self.fail_add or name in self.profiles:
                    return 1, b"", b"add refused"
                if not self.omit_add_readback:
                    self.profiles.add(name)
                if self.timeout_after_add:
                    raise owner_module.Refusal("authored timeout after parser add effect")
                return 0, b"", b""
            if "--remove" in argv:
                if self.fail_remove:
                    return 1, b"", b"remove refused"
                self.profiles.discard(name)
                if self.timeout_after_remove:
                    raise owner_module.Refusal("authored timeout after parser effect")
                return 0, b"", b""
        return 1, b"", b"unrecognized fixture command"


class CompositeCommandRunner:
    def __init__(self, manager, profile):
        self.manager = manager
        self.profile = profile

    def run(self, argv, timeout, *, input_data=None, env=None):
        if "/usr/sbin/apparmor_parser" in argv or "/sys/kernel/security/apparmor/profiles" in argv:
            return self.profile.run(argv, timeout, input_data=input_data, env=env)
        return self.manager.run(argv, timeout, input_data=input_data, env=env)


class OwnerTest(unittest.TestCase):
    def setUp(self):
        root = ROOT / "build/pr-merge-audit/gcc-native-builder-repair-implementation/tests"
        root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=root, prefix="owner-")
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.root = self.repo / "build" / "g" / "owned"

    def make_owner(self, backend=None):
        return owner_module.Owner(self.root, backend, test_repo_root=self.repo)

    @staticmethod
    def fixture_tool_hashes():
        return {"rootlesskit": hashlib.sha256(b"authored rootlesskit stub").hexdigest(),
                "dockerd": owner_module.PINNED_TOOL_HASHES["dockerd"]}

    def tearDown(self):
        self.temp.cleanup()

    def reserve(self, owner):
        return owner.reserve({"run": "fixture", "revision": "abc"},
            ["/x/d.sock", "/x/r/api.sock"])

    def test_socket_admission_precedes_owner_directory_creation(self):
        owner = owner_module.Owner(self.repo / "build" / "g" / "malformed-journal",
                                   FakeBackend(), test_repo_root=self.repo)
        with self.assertRaises(owner_module.Refusal):
            owner.reserve({}, ["x" * 108])
        self.assertFalse(self.root.exists())

    def test_exact_107_byte_socket_path_is_admitted(self):
        owner = self.make_owner(FakeBackend())
        owner.reserve({}, ["x" * 107])
        self.assertEqual(owner._manifest()["socketPaths"], ["x" * 107])

    def test_socket_budget_counts_utf8_bytes_before_root_creation(self):
        owner = self.make_owner(FakeBackend())
        with self.assertRaisesRegex(owner_module.Refusal, "exceeds 107 bytes"):
            owner.reserve({}, ["é" * 54])
        self.assertFalse(self.root.exists())

    def test_fixed_rootless_profile_uses_short_owned_exec_and_state_roots(self):
        argv, env = owner_module.fixed_launch_profile(self.root, "rootless", "a" * 32, 1000)
        self.assertEqual(argv[0], str(self.root / "v/tools/docker-rootless-extras/dockerd-rootless.sh"))
        self.assertEqual(argv[argv.index("--exec-root") + 1], str(self.root / "x"))
        self.assertEqual(argv[argv.index("--cgroup-parent") + 1], "dgr" + "a" * 32 + ".slice")
        self.assertEqual(env["DOCKERD"], str(self.root / "v/tools/docker/dockerd"))
        self.assertEqual(env["DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR"], str(self.root / "r"))
        self.assertEqual(env["XDG_RUNTIME_DIR"], "/run/user/1000")
        self.assertNotEqual(env["DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR"], str(self.root / "control"))
        short_root = Path("/r/build/g/1234abcd")
        self.assertLessEqual(max(map(len, map(__import__("os").fsencode,
            owner_module.fixed_socket_inventory(short_root)))), 107)

    def test_supervisor_child_environment_rejects_ambient_docker_and_rootless_toggles(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        tools = self.root / "v/tools/docker-rootless-extras"
        tools.mkdir(parents=True)
        launcher = tools / "dockerd-rootless.sh"
        launcher.write_bytes(b"authored wrapper fixture")
        launcher.chmod(0o700)
        argv, env = owner_module.fixed_launch_profile(self.root, "rootless", manifest["ownerToken"], 1000)
        intent = {"argv": argv, "env": env, "launcherSha256": hashlib.sha256(launcher.read_bytes()).hexdigest()}
        manifest["roles"]["rootless"] = {"intent": intent}
        safe_argv, safe_env, expected_exe, _ = owner_module._fixed_child(manifest, "rootless")
        self.assertEqual(safe_argv, argv)
        self.assertEqual(expected_exe, str(self.root / "v/tools/docker-rootless-extras/rootlesskit"))
        self.assertEqual(safe_env["DOCKERD"], str(self.root / "v/tools/docker/dockerd"))
        self.assertEqual(safe_env["DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR"], str(self.root / "r"))
        self.assertIn(str(self.root / "v/tools/docker-rootless-extras"), safe_env["PATH"].split(":"))
        self.assertNotIn("DOCKER_HOST", safe_env)
        for key, value in (("DOCKER_HOST", "tcp://ambient"), ("DOCKERD", "/tmp/dockerd"),
                           ("ROOTLESSKIT_FLAGS", "--detach-netns"), ("_DOCKERD_ROOTLESS_CHILD", "1")):
            malicious = {**env, key: value}
            manifest["roles"]["rootless"]["intent"] = {**intent, "env": malicious}
            with self.assertRaises(owner_module.Refusal):
                owner_module._fixed_child(manifest, "rootless")

    def test_profile_path_with_unsupported_characters_is_rejected(self):
        spaced_root = self.repo / "build" / "g" / "with space"
        spaced_owner = owner_module.Owner(spaced_root, FakeBackend(), test_repo_root=self.repo)
        spaced_manifest = spaced_owner.reserve({"fixture": True}, ["x" * 100])
        tools = spaced_root / "v/tools/docker-rootless-extras"
        tools.mkdir(parents=True)
        (tools / "rootlesskit").write_bytes(b"authored rootlesskit stub")
        backend = owner_module.ProductionBackend(spaced_root, runner=FakeProfileRunner(), authority=FakeAuthority())
        with self.assertRaisesRegex(owner_module.Refusal, "cannot be represented safely"):
            backend._profile_identity(spaced_manifest)
        self.assertTrue((spaced_root / "control/apparmor-load-intent.json").exists() is False)

    def test_durable_intent_precedes_manager_reservation_and_missing_receipt_fails(self):
        backend = FakeBackend(fail_reserve=True)
        owner = self.make_owner(backend)
        self.reserve(owner)
        with self.assertRaisesRegex(owner_module.Refusal, "denial"):
            owner.begin_role("buildkit", ["/pinned/buildkitd"], {"PATH": "/bin"}, {"seconds": 2})
        events = [json.loads(line) for line in owner.journal_path.read_text().splitlines()]
        self.assertEqual([row["state"] for row in events], ["reserved", "launch-intent"])
        self.assertEqual(backend.calls, [("reserve", "buildkit")])
        with self.assertRaisesRegex(owner_module.Refusal, "lacks manager receipt; absence is unknown"):
            owner.seal_stop("buildkit")
        self.assertFalse(any(call[0] == "empty" for call in backend.calls),
                         "empty post-failure inventory cannot substitute for the missing reservation receipt")

    def test_owner_manifest_and_journal_shape_mutations_refuse(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        manifest["identity"] = []
        owner_module.atomic_json(owner.manifest_path, manifest)
        with self.assertRaisesRegex(owner_module.Refusal, "manifest shape"):
            owner._manifest()

        owner = owner_module.Owner(self.repo / "build" / "g" / "malformed-journal",
                                   FakeBackend(), test_repo_root=self.repo)
        self.reserve(owner)
        owner.journal_path.write_text("[]\n")
        with self.assertRaisesRegex(owner_module.Refusal, "sequence/token mismatch"):
            owner._manifest()

    def test_missing_durable_exec_observation_cannot_be_replaced_by_empty_cleanup(self):
        backend = FakeBackend(empty=True)
        owner = self.make_owner(backend)
        self.reserve(owner)
        owner.begin_role("buildkit", ["/pinned/buildkitd"], {"PATH": "/bin"}, {"seconds": 2})
        events = [json.loads(line) for line in owner.journal_path.read_text().splitlines()]
        events = [event for event in events if event["state"] != "exec-observed"]
        owner.journal_path.write_text("".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
                                            for event in events))
        with self.assertRaisesRegex(owner_module.Refusal, "sequence count differs"):
            owner._manifest()
        self.assertNotEqual(json.loads(owner.manifest_path.read_text())["state"], "absence-proved")

    def test_unknown_domain_absence_never_becomes_success(self):
        backend = FakeBackend(empty=False)
        owner = self.make_owner(backend)
        self.reserve(owner)
        owner.begin_role("buildkit", ["/pinned/buildkitd"], {"PATH": "/bin"}, {"seconds": 2})
        owner.ready("buildkit", {"pidfd": "test-pidfd", "identity": {"exe": "/pinned/buildkitd"}})
        with self.assertRaisesRegex(owner_module.Refusal, "absence is unknown"):
            owner.seal_stop("buildkit")
        self.assertNotEqual(owner._manifest()["state"], "absence-proved")
        self.assertNotIn("released", [json.loads(row)["state"] for row in owner.journal_path.read_text().splitlines()])

    def test_corrupt_or_partial_journal_is_unknown(self):
        owner = self.make_owner(FakeBackend())
        self.reserve(owner)
        with owner.journal_path.open("ab") as stream:
            stream.write(b'{"sequence":')
        with self.assertRaisesRegex(owner_module.Refusal, "incomplete record"):
            owner._manifest()

    def test_owner_token_and_root_inode_are_pinned(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        manifest["ownerToken"] = "0" * 32
        owner_module.atomic_json(owner.manifest_path, manifest)
        with self.assertRaisesRegex(owner_module.Refusal, "sequence/token mismatch"):
            owner._manifest()

    def test_production_backend_cannot_be_replaced_through_environment(self):
        backend = owner_module.ProductionBackend(ROOT)
        self.assertEqual(type(backend).__name__, "ProductionBackend")
        self.assertNotIn("backend", owner_module.cli.__code__.co_varnames)

    def test_capability_admission_checks_hierarchy_not_root_cgroup_files(self):
        class HierarchyOnlyAuthority:
            def capabilities(self, root, role, timeout):
                # Root cgroups do not expose cgroup.events/cgroup.kill; those
                # controls are checked after the owned slice has been created.
                return {"unified": True, "controllers": ["memory", "pids"],
                        "events": False, "cgroupKill": False, "userManager": True}

        caps = owner_module.require_capabilities(HierarchyOnlyAuthority(), self.root, "buildkit")
        self.assertTrue(caps["unified"])
        self.assertFalse(caps["events"])
        self.assertFalse(caps["cgroupKill"])

    def test_owned_cgroup_kill_control_must_exist_and_be_openable_for_write(self):
        cgroup = self.repo / "cgroup"
        cgroup.mkdir()
        directory_fd = os.open(cgroup, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            with self.assertRaisesRegex(owner_module.Refusal, "cgroup.kill"):
                owner_module.require_cgroup_kill(directory_fd)
            control = cgroup / "cgroup.kill"
            control.write_bytes(b"")
            control.chmod(0o200)
            owner_module.require_cgroup_kill(directory_fd)
            self.assertTrue(control.exists())
        finally:
            os.close(directory_fd)

    def test_production_backend_emits_fixed_transient_service_properties(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        runner = FakeCommandRunner(manifest["ownerToken"])
        backend = owner_module.ProductionBackend(self.root, runner=runner,
                                                   authority=FakeAuthority())
        receipt = backend.manager_reserve("buildkit", manifest)
        self.assertEqual(receipt["ownerToken"], manifest["ownerToken"])
        starts = [call[0] for call in runner.calls if "StartTransientUnit" in call[0]]
        self.assertEqual(len(starts), 2)
        self.assertTrue(all("fail" in command for command in starts))
        service = starts[1]
        joined = " ".join(service)
        for required in ("DelegateSubgroup", "control", "KillMode", "control-group",
                         "SendSIGKILL", "RuntimeMaxUSec", "RemainAfterExit"):
            self.assertIn(required, joined)
        self.assertEqual(receipt["device"], 4)

    def test_busctl_object_path_uses_the_json_argument_array(self):
        self.assertEqual(owner_module.ProductionBackend._busctl_object_path(
            b'{"type":"o","data":["/org/freedesktop/systemd1/job/77"]}',
            "/org/freedesktop/systemd1/job/", "fixture"),
            "/org/freedesktop/systemd1/job/77")
        with self.assertRaises(owner_module.Refusal):
            owner_module.ProductionBackend._busctl_object_path(
                b'{"type":"o","data":"/org/freedesktop/systemd1/job/77"}',
                "/org/freedesktop/systemd1/job/", "fixture")

    def test_production_gate_rechecks_pinned_manager_and_privileged_cgroup_receipts(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        runner = FakeCommandRunner(manifest["ownerToken"])
        backend = owner_module.ProductionBackend(self.root, runner=runner, authority=FakeAuthority())
        receipt = backend.manager_reserve("buildkit", manifest)
        manifest["roles"]["buildkit"] = {"status": "domain-reserved", "receipt": receipt,
            "intent": {"argv": ["/pinned/buildkitd"]}}
        owner_module.atomic_json(self.root / "control/child-ready-buildkit.json",
            {"ownerToken": manifest["ownerToken"], "role": "buildkit", "pid": 777,
             "pidfdHeld": True, "identity": {"startTicks": 55},
             "daemonCgroup": receipt["controlGroup"] + "/daemon"})
        prepared = backend.manager_prepare_gate("buildkit", manifest)
        self.assertTrue(prepared["pidfdHeld"])
        owner_module.atomic_json(self.root / "control/exec-observed-buildkit.json",
            {"ownerToken": manifest["ownerToken"], "role": "buildkit", "pid": 777,
             "pidfdHeld": True, "identity": {"exe": "/pinned/buildkitd", "startTicks": 55},
             "daemonCgroup": receipt["controlGroup"] + "/daemon"})
        gated = backend.manager_gate("buildkit", manifest)
        self.assertEqual(gated["exec"]["identity"]["exe"], "/pinned/buildkitd")
        self.assertTrue((self.root / "control/gate-buildkit.json").is_file())

    def test_complete_fake_system_manager_lifecycle_requires_receipts_before_release(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        binary = self.root / "v/tools/buildkit/bin/buildkitd"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"authored unprivileged buildkit executable stub")
        binary.chmod(0o700)
        runner = FakeCommandRunner(manifest["ownerToken"])
        authority = FakeAuthority(empty=False)
        backend = owner_module.ProductionBackend(self.root, runner=runner, authority=authority,
                                                  test_repo_root=self.repo)
        owner.backend = backend
        argv = [str(binary)]
        _, service_unit = owner_module.unit_names("buildkit", manifest["ownerToken"])
        service_cgroup = f"/system.slice/dgb{manifest['ownerToken']}.slice/{service_unit}"
        start_ticks = 99
        child_identity = {"startTicks": start_ticks, "uid": 1000, "exe": str(binary),
                          "exeDevice": 1, "exeInode": 2, "exeSha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                          "namespaces": {"mnt": 1}, "cgroup": "0::" + service_cgroup + "/daemon"}
        owner_module.atomic_json(self.root / "control/child-ready-buildkit.json",
            {"ownerToken": manifest["ownerToken"], "role": "buildkit", "pid": 99,
             "pidfdHeld": True, "identity": child_identity,
             "daemonCgroup": service_cgroup + "/daemon"})
        owner_module.atomic_json(self.root / "control/exec-observed-buildkit.json",
            {"ownerToken": manifest["ownerToken"], "role": "buildkit", "pid": 99,
             "pidfdHeld": True, "identity": child_identity,
             "daemonCgroup": service_cgroup + "/daemon"})
        owner.backend = backend
        # Exercise the real production manager gate against only fake manager,
        # authority, and authored receipt adapters.
        manifest = owner.begin_role("buildkit", argv, {"HOME": str(self.root / "v/home")},
                                    {"gateSeconds": 10, "runtimeSeconds": 1800})
        manifest = owner._manifest()
        authority.empty = True
        owner_module.atomic_json(self.root / "control/stop-receipt-buildkit.json",
            {"ownerToken": manifest["ownerToken"], "role": "buildkit", "daemonEmpty": True,
             "pidfdHeld": True, "cgroupNodes": 2})
        stopped = owner.seal_stop("buildkit")
        self.assertEqual(stopped["state"], "absence-proved")
        self.assertTrue(stopped["roles"]["buildkit"]["stopReceipt"]["killReceipt"]["empty"])
        released = backend.release_domains(stopped, 60)
        stop_calls = [call[0] for call in runner.calls if "StopUnit" in call[0]]
        self.assertEqual(len(stop_calls), 2)
        self.assertTrue(all(call[0] == "/usr/bin/sudo" for call in stop_calls))
        self.assertTrue(released["released"][0]["inactive"])

    def test_complete_fake_user_manager_profile_and_rootless_exec_lifecycle(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        tools = self.root / "v/tools/docker-rootless-extras"
        tools.mkdir(parents=True)
        wrapper = tools / "dockerd-rootless.sh"
        wrapper.write_bytes(b"authored wrapper transition stub")
        wrapper.chmod(0o700)
        rootlesskit = tools / "rootlesskit"
        rootlesskit.write_bytes(b"authored rootlesskit stub")
        rootlesskit.chmod(0o700)
        pins = self.fixture_tool_hashes()
        manager_runner = FakeCommandRunner(manifest["ownerToken"], role="rootless")
        profile_runner = FakeProfileRunner()
        runner = CompositeCommandRunner(manager_runner, profile_runner)
        authority = FakeAuthority(empty=False)
        backend = owner_module.ProductionBackend(self.root, runner=runner, authority=authority,
            fixture_tool_hashes=pins, test_repo_root=self.repo)
        owner.backend = backend
        _, service_unit = owner_module.unit_names("rootless", manifest["ownerToken"])
        service_cgroup = f"/system.slice/dgr{manifest['ownerToken']}.slice/{service_unit}"
        identity = {"startTicks": 123, "uid": 1000, "exe": str(rootlesskit),
            "exeDevice": 3, "exeInode": 4, "exeSha256": pins["rootlesskit"],
            "namespaces": {"mnt": 20, "pid": 21}, "cgroup": "0::" + service_cgroup + "/daemon"}
        owner_module.atomic_json(self.root / "control/child-ready-rootless.json",
            {"ownerToken": manifest["ownerToken"], "role": "rootless", "pid": 101,
             "pidfdHeld": True, "identity": identity, "daemonCgroup": service_cgroup + "/daemon"})
        dockerd = {"pid": 102, "parentPid": 101, "startTicks": 124, "uid": 1000,
            "exe": str(self.root / "v/tools/docker/dockerd"), "exeDevice": 3, "exeInode": 5,
            "exeSha256": pins["dockerd"], "namespaces": {"mnt": 20, "pid": 21},
            "cgroup": "0::" + service_cgroup + "/daemon", "pidfdHeld": True}
        owner_module.atomic_json(self.root / "control/exec-observed-rootless.json",
            {"ownerToken": manifest["ownerToken"], "role": "rootless", "pid": 101,
             "pidfdHeld": True, "identity": identity, "daemonCgroup": service_cgroup + "/daemon",
             "authenticatedDescendants": [dockerd]})
        argv, env = owner_module.fixed_launch_profile(self.root, "rootless", manifest["ownerToken"], 1000)
        manifest = owner.begin_role("rootless", argv, env, {"gateSeconds": 10, "runtimeSeconds": 10800})
        owner.ready("rootless", {"pidfd": "fake-pidfd", "identity": identity,
                                  "dockerInfo": {"CgroupDriver": "systemd", "CgroupVersion": "2"}})
        # Faithfully model RootlessKit InitStateDir and Parent removing r/.
        state_dir = self.root / "r"
        (state_dir / "lock").write_text("locked")
        (state_dir / "discarded-status").write_text("ephemeral")
        for item in state_dir.iterdir():
            if item.name != "lock":
                item.unlink()
        (state_dir / "lock").unlink()
        state_dir.rmdir()
        self.assertTrue(owner._manifest()["roles"]["rootless"]["intent"])
        self.assertTrue((self.root / "journal.jsonl").is_file())
        authority.empty = True
        owner_module.atomic_json(self.root / "control/stop-receipt-rootless.json",
            {"ownerToken": manifest["ownerToken"], "role": "rootless", "daemonEmpty": True,
             "pidfdHeld": True, "cgroupNodes": 2})
        stopped = owner.seal_stop("rootless")
        released = backend.release_domains(stopped, 60)
        profile_name = "decomp-gcc-owner-" + manifest["ownerToken"]
        self.assertNotIn(profile_name, profile_runner.profiles)
        self.assertTrue((self.root / "control/apparmor-absent.json").is_file())
        self.assertTrue(any("--user" in call[0] for call in manager_runner.calls))
        self.assertTrue(released["released"][-1]["inactive"])

    def test_missing_stop_receipt_cannot_be_replaced_by_empty_inventory(self):
        owner = self.make_owner(FakeBackend(empty=True, missing_stop=True))
        manifest = self.reserve(owner)
        owner.begin_role("buildkit", ["/pinned/buildkitd"], {"PATH": "/bin"}, {"seconds": 1})
        owner.ready("buildkit", {"pidfd": "fixture", "identity": {"exe": "/pinned/buildkitd"}})
        with self.assertRaisesRegex(owner_module.Refusal, "lacks supervisor and complete cgroup-kill receipts"):
            owner.seal_stop("buildkit")
        self.assertNotEqual(owner._manifest()["state"], "absence-proved")

    def test_command_runner_rejects_unlisted_binary_without_launch(self):
        runner = owner_module.CommandRunner()
        with self.assertRaisesRegex(owner_module.Refusal, "fixed argv allowlist"):
            runner.run(["/tmp/ambient-daemon", "--version"], 1)

    def test_cgroup_cleanup_freezes_then_kills_then_proves_recursive_absence(self):
        clock = FakeClock()
        io = FakeCgroupIO()
        receipt = owner_module.freeze_kill_prove(io, "/owned/slice", 7, 8,
            timeout=5, clock=clock, sleep=clock.sleep)
        self.assertTrue(receipt["frozen"] and receipt["empty"])
        names = [item[1] for item in io.calls if item[0] == "write"]
        self.assertEqual(names, ["cgroup.freeze", "cgroup.kill"])
        self.assertLess([i for i, row in enumerate(io.calls) if row[0] == "empty"][0], len(io.calls))

    def test_cgroup_cleanup_permission_and_absence_failures_never_succeed(self):
        clock = FakeClock()
        denied = FakeCgroupIO(freeze_error=PermissionError("authored EPERM"))
        with self.assertRaisesRegex(owner_module.Refusal, "freeze was denied"):
            owner_module.freeze_kill_prove(denied, "/owned/slice", 7, 8,
                timeout=5, clock=clock, sleep=clock.sleep)
        self.assertFalse(any(row[:2] == ("write", "cgroup.kill") for row in denied.calls))
        clock = FakeClock()
        unknown = FakeCgroupIO(empty=False)
        with self.assertRaisesRegex(owner_module.Refusal, "did not become empty"):
            owner_module.freeze_kill_prove(unknown, "/owned/slice", 7, 8,
                timeout=0.1, clock=clock, sleep=clock.sleep)

    def test_rootless_profile_load_and_removal_use_fixed_parser_and_repo_file(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        tools = self.root / "v/tools/docker-rootless-extras"
        tools.mkdir(parents=True)
        binary = tools / "rootlesskit"
        binary.write_bytes(b"authored rootlesskit stub")
        binary.chmod(0o700)
        runner = FakeProfileRunner()
        backend = owner_module.ProductionBackend(self.root, runner=runner, authority=FakeAuthority(),
                                                  fixture_tool_hashes=self.fixture_tool_hashes())
        backend._load_rootless_profile(manifest)
        name = "decomp-gcc-owner-" + manifest["ownerToken"]
        self.assertIn(name, runner.profiles)
        profile = self.root / "control" / f"apparmor-{manifest['ownerToken']}.profile"
        self.assertTrue(profile.is_file())
        body = profile.read_text()
        self.assertIn(f'"{binary}"', body)
        self.assertIn("userns,", body)
        self.assertTrue(all(call[0][0] == "/usr/bin/sudo" for call in runner.calls))
        backend._remove_rootless_profile({**manifest, "roles": {
            "rootless": {"status": "absence-proved"}}}, time.monotonic() + 10)
        self.assertNotIn(name, runner.profiles)
        self.assertTrue((self.root / "control/apparmor-absent.json").is_file())

    def test_rootless_profile_collision_and_remove_failure_fail_closed(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        tools = self.root / "v/tools/docker-rootless-extras"
        tools.mkdir(parents=True)
        (tools / "rootlesskit").write_bytes(b"authored rootlesskit stub")
        (tools / "rootlesskit").chmod(0o700)
        name = "decomp-gcc-owner-" + manifest["ownerToken"]
        runner = FakeProfileRunner(profiles=[name])
        backend = owner_module.ProductionBackend(self.root, runner=runner, authority=FakeAuthority(),
                                                  fixture_tool_hashes=self.fixture_tool_hashes())
        with self.assertRaisesRegex(owner_module.Refusal, "already exists"):
            backend._load_rootless_profile(manifest)
        self.assertFalse(any("--add" in call[0] for call in runner.calls))
        runner.profiles.clear()
        backend._load_rootless_profile(manifest)
        runner.fail_remove = True
        with self.assertRaisesRegex(owner_module.Refusal, "removal failed"):
            backend._remove_rootless_profile({**manifest, "roles": {
                "rootless": {"status": "absence-proved"}}}, time.monotonic() + 10)

    def test_profile_timeout_after_effect_remains_unknown(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        tools = self.root / "v/tools/docker-rootless-extras"
        tools.mkdir(parents=True)
        (tools / "rootlesskit").write_bytes(b"authored rootlesskit stub")
        (tools / "rootlesskit").chmod(0o700)
        runner = FakeProfileRunner(timeout_after_remove=True)
        backend = owner_module.ProductionBackend(self.root, runner=runner, authority=FakeAuthority(),
                                                  fixture_tool_hashes=self.fixture_tool_hashes())
        backend._load_rootless_profile(manifest)
        with self.assertRaisesRegex(owner_module.Refusal, "timeout after parser effect"):
            backend._remove_rootless_profile({**manifest, "roles": {
                "rootless": {"status": "absence-proved"}}}, time.monotonic() + 10)
        self.assertFalse((self.root / "control/apparmor-absent.json").exists())
        self.assertTrue((self.root / "control/apparmor-load-intent.json").exists())

    def test_profile_load_timeout_or_missing_readback_never_opens_gate(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        tools = self.root / "v/tools/docker-rootless-extras"
        tools.mkdir(parents=True)
        binary = tools / "rootlesskit"
        binary.write_bytes(b"authored rootlesskit stub")
        binary.chmod(0o700)
        pins = self.fixture_tool_hashes()
        timeout_runner = FakeProfileRunner(timeout_after_add=True)
        backend = owner_module.ProductionBackend(self.root, runner=timeout_runner, authority=FakeAuthority(),
            fixture_tool_hashes=pins)
        with self.assertRaisesRegex(owner_module.Refusal, "timeout after parser add effect"):
            backend._load_rootless_profile(manifest)
        self.assertTrue((self.root / "control/apparmor-load-intent.json").is_file())
        self.assertFalse((self.root / "control/apparmor-loaded.json").exists())
        self.assertTrue(timeout_runner.profiles)

        other_repo = self.repo / "other"
        other_repo.mkdir()
        other_root = other_repo / "build/g/owned"
        other_owner = owner_module.Owner(other_root, FakeBackend(), test_repo_root=other_repo)
        other_manifest = self.reserve(other_owner)
        other_tools = other_root / "v/tools/docker-rootless-extras"
        other_tools.mkdir(parents=True)
        other_binary = other_tools / "rootlesskit"
        other_binary.write_bytes(b"authored rootlesskit stub")
        other_binary.chmod(0o700)
        other_runner = FakeProfileRunner(omit_add_readback=True)
        other_backend = owner_module.ProductionBackend(other_root, runner=other_runner,
            authority=FakeAuthority(), fixture_tool_hashes=pins, test_repo_root=other_repo)
        with self.assertRaisesRegex(owner_module.Refusal, "without exact kernel readback"):
            other_backend._load_rootless_profile(other_manifest)
        self.assertFalse((other_root / "control/apparmor-loaded.json").exists())

    def test_rootless_exec_identity_requires_authenticated_stable_rootlesskit(self):
        stable = {"startTicks": 44, "exe": "/owned/rootlesskit", "exeSha256": "a" * 64,
                  "uid": 1000, "exeDevice": 2, "exeInode": 3,
                  "namespaces": {"mnt": 10, "pid": 11}, "cgroup": "0::/owned/daemon"}
        self.assertTrue(owner_module.stable_exec_identity("rootless", stable,
            "/owned/rootlesskit", "a" * 64, 44))
        self.assertFalse(owner_module.stable_exec_identity("rootless", {**stable, "exe": "/bin/bash"},
            "/owned/rootlesskit", "a" * 64, 44))
        self.assertFalse(owner_module.stable_exec_identity("rootless", {**stable, "startTicks": 45},
            "/owned/rootlesskit", "a" * 64, 44))
        self.assertFalse(owner_module.stable_exec_identity("rootless", {**stable, "exeSha256": "b" * 64},
            "/owned/rootlesskit", "a" * 64, 44))

    def test_fake_wrapper_transition_waits_for_authenticated_rootlesskit(self):
        clock = FakeClock()
        wrapper = {"startTicks": 44, "exe": "/usr/bin/bash", "exeSha256": "c" * 64,
                   "uid": 1000, "exeDevice": 1, "exeInode": 1,
                   "namespaces": {"mnt": 10}, "cgroup": "0::/owned/daemon"}
        rootlesskit = {**wrapper, "exe": "/owned/rootlesskit", "exeSha256": "a" * 64,
                       "exeDevice": 2, "exeInode": 3}
        samples = iter((wrapper, rootlesskit))
        final = owner_module.await_stable_exec(lambda: next(samples), lambda: True, "rootless",
            "/owned/rootlesskit", "a" * 64, 44, deadline=1, clock=clock, sleep=clock.sleep)
        self.assertEqual(final["exe"], "/owned/rootlesskit")
        clock = FakeClock()
        with self.assertRaisesRegex(owner_module.Refusal, "not observed before deadline"):
            owner_module.await_stable_exec(lambda: wrapper, lambda: True, "rootless",
                "/owned/rootlesskit", "a" * 64, 44, deadline=0.05,
                clock=clock, sleep=clock.sleep)

    def test_rootless_release_gate_requires_profile_readback(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        backend = owner_module.ProductionBackend(self.root, runner=FakeProfileRunner(), authority=FakeAuthority())
        with self.assertRaisesRegex(owner_module.Refusal, "profile is not present"):
            backend.manager_prepare_gate("rootless", manifest)


if __name__ == "__main__":
    unittest.main()
