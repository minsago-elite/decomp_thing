from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import socket
import secrets
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace

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

    def write_buildkit_config(self):
        state = self.root / "v" / "s"
        state.mkdir(parents=True, exist_ok=True)
        path = state / "buildkitd.toml"
        path.write_text('[worker.oci]\n  enabled = true\n  snapshotter = "native"\n'
            '  platforms = ["linux/amd64"]\n  max-parallelism = 1\n'
            "[worker.containerd]\n  enabled = false\n[grpc]\n"
            f'  address = ["unix://{self.root}/b.sock"]\n'
            f"  uid = {os.getuid()}\n  gid = {os.getgid()}\n")
        path.chmod(0o600)
        return path

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

    def test_buildkit_readiness_requires_pinned_sandboxed_worker(self):
        worker = {"executor": "oci", "snapshotter": "native", "process-mode": "sandbox",
                  "platforms": ["linux/amd64"]}
        info = {"version": "v0.20.2", "revision": "97437fdd7e32f29bb80288d800cd4ffcb34e1c15"}
        facts = owner_module.validate_buildkit_health(json.dumps([worker]).encode(), json.dumps(info).encode())
        self.assertEqual(facts["workerCount"], 1)
        worker["process-mode"] = "no-sandbox"
        with self.assertRaisesRegex(owner_module.Refusal, "not the admitted"):
            owner_module.validate_buildkit_health(json.dumps([worker]).encode(), json.dumps(info).encode())

    def test_docker_readiness_binds_pinned_server_data_root_and_owned_socket(self):
        base = ROOT / "build" / "g"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base, prefix="dr-") as temporary:
            root = Path(temporary) / "job"
            data = root / "v" / "s" / "docker-data"
            data.mkdir(parents=True)
            endpoint = root / "d.sock"
            server = socket.socket(socket.AF_UNIX)
            try:
                server.bind(str(endpoint))
                info = {"Driver": "overlay2", "DockerRootDir": str(data), "ServerVersion": "29.7.2"}
                facts = owner_module.validate_docker_health(json.dumps(info).encode(),
                    b"29.7.2 6a43e3d\n", root, endpoint)
                self.assertEqual(facts["serverCommit"], "6a43e3d")
                with self.assertRaisesRegex(owner_module.Refusal, "pinned runtime"):
                    owner_module.validate_docker_health(json.dumps({**info, "Driver": "vfs"}).encode(),
                        b"29.7.2 6a43e3d\n", root, endpoint)
            finally:
                server.close()

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

    def test_owner_can_launch_second_role_after_first_role_is_ready(self):
        owner = self.make_owner(FakeBackend())
        self.reserve(owner)
        owner.begin_role("buildkit", ["/pinned/buildkitd"], {}, {"seconds": 1})
        owner.ready("buildkit", {"pidfd": "buildkit", "identity": {"exe": "/pinned/buildkitd"}})
        owner.begin_role("rootless", ["/pinned/dockerd-rootless.sh"], {}, {"seconds": 1})
        owner.ready("rootless", {"pidfd": "rootless", "identity": {"exe": "/pinned/rootlesskit"}})
        manifest = owner._manifest()
        self.assertEqual(manifest["state"], "ready")
        self.assertEqual(manifest["roles"]["buildkit"]["status"], "ready")
        self.assertEqual(manifest["roles"]["rootless"]["status"], "ready")

    def test_global_absence_requires_both_roles_and_bound_stop_receipts(self):
        token = "a" * 32
        self.assertFalse(owner_module.Owner._all_roles_absence_proved({"ownerToken": token, "roles": {
            "buildkit": {"status": "ready"},
            "rootless": {"status": "absence-proved", "neverLaunched": True}}}))
        self.assertTrue(owner_module.Owner._all_roles_absence_proved({"ownerToken": token, "roles": {
            "buildkit": {"status": "absence-proved", "neverLaunched": True},
            "rootless": {"status": "absence-proved", "neverLaunched": True}}}))

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
        self.write_buildkit_config()
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

    def test_privileged_cgroup_target_must_match_current_systemd_control_groups(self):
        token = "a" * 32
        slice_name, service_name = owner_module.unit_names("buildkit", token)
        description = f"decomp-gcc-owner:{token}:buildkit"
        slice_group = f"/system.slice/{slice_name}"
        service_group = f"{slice_group}/{service_name}"
        receipt = {"ownerToken": token, "role": "buildkit", "manager": "system",
            "slice": slice_name, "unit": service_name, "description": description,
            "sliceControlGroup": slice_group, "controlGroup": service_group,
            "sliceInvocationId": "slice-invocation", "invocationId": "service-invocation"}
        manifest = {"ownerToken": token}
        slice_facts = {"id": slice_name, "description": description, "active": "active",
            "controlGroup": slice_group, "invocation": "slice-invocation"}
        service_facts = {"id": service_name, "description": description, "active": "active",
            "slice": slice_name, "controlGroup": service_group, "invocation": "service-invocation"}
        owner_module.require_manager_reservation_binding(receipt, "buildkit", manifest,
            slice_facts, service_facts)
        forged = {**receipt, "controlGroup": "/system.slice/unrelated.service"}
        with self.assertRaisesRegex(owner_module.Refusal, "current systemd unit identity"):
            owner_module.require_manager_reservation_binding(forged, "buildkit", manifest,
                slice_facts, service_facts)

    def test_production_gate_rechecks_pinned_manager_and_privileged_cgroup_receipts(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)
        self.write_buildkit_config()
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
        config = self.write_buildkit_config()
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
        self.assertIn(service_cgroup + "/daemon", config.read_text())
        manifest = owner._manifest()
        authority.empty = True
        owner_module.atomic_json(self.root / "control/stop-receipt-buildkit.json",
            {"ownerToken": manifest["ownerToken"], "role": "buildkit", "daemonEmpty": True,
             "pidfdHeld": True, "cgroupNodes": 2})
        stopped = owner.seal_stop("buildkit")
        stopped = owner.seal_stop("rootless")
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
        stopped = owner.seal_stop("buildkit")
        released = backend.release_domains(stopped, 60)
        profile_name = "decomp-gcc-owner-" + manifest["ownerToken"]
        self.assertNotIn(profile_name, profile_runner.profiles)
        self.assertTrue((self.root / "control/apparmor-absent.json").is_file())
        self.assertTrue(any("--user" in call[0] for call in manager_runner.calls))
        self.assertTrue(released["released"][-1]["inactive"])

    def test_identity_hashing_accepts_pinned_daemon_size_and_refuses_oversized_metadata_before_open(self):
        # Model proc metadata/stream in memory: no host process, proc read or executable runs.
        size = 99_870_816
        class Executable:
            def __init__(self):
                self.position = 0
                self.closed = False
            def read(self, count):
                count = min(count, size - self.position)
                self.position += count
                return b"x" * count
            def tell(self):
                return self.position
            def __enter__(self):
                return self
            def __exit__(self, *unused):
                self.closed = True
        fields = ["S", "1"] + ["0"] * 17 + ["777"]
        texts = {"/proc/123/stat": "123 (authored process) " + " ".join(fields),
                 "/proc/123/status": "Uid:\t1000\t1000\t1000\t1000\n",
                 "/proc/123/cgroup": "0::/authored/daemon\n"}
        def text(path, *args, **kwargs):
            return texts[str(path)]
        metadata = SimpleNamespace(st_dev=1, st_ino=2, st_size=size)
        stream = Executable()
        with mock.patch.object(Path, "read_text", text), \
                mock.patch.object(owner_module.os, "stat", return_value=metadata), \
                mock.patch.object(owner_module.os, "readlink", return_value="/authored/docker/dockerd"), \
                mock.patch("builtins.open", return_value=stream):
            try:
                identity = owner_module._read_proc_identity(123)
            except owner_module.Refusal as exc:
                self.fail(f"the pinned daemon size must fit the finite identity budget: {exc}")
        expected = hashlib.sha256()
        remaining = size
        while remaining:
            count = min(1024 * 1024, remaining)
            expected.update(b"x" * count)
            remaining -= count
        self.assertEqual(identity["exeSha256"], expected.hexdigest())
        self.assertEqual(stream.position, size)
        self.assertTrue(stream.closed)
        metadata.st_size = 128 * 1024 * 1024 + 1
        with mock.patch.object(Path, "read_text", text), \
                mock.patch.object(owner_module.os, "stat", return_value=metadata), \
                mock.patch.object(owner_module.os, "readlink", return_value="/authored/oversized"), \
                mock.patch("builtins.open", side_effect=AssertionError("oversized metadata must refuse before opening")):
            with self.assertRaisesRegex(owner_module.Refusal, "identity hash budget"):
                owner_module._read_proc_identity(123)

        metadata.st_size = 16
        for size, message in ((17, "identity hash budget"), (15, "size changed")):
            stream = Executable()
            with mock.patch.object(Path, "read_text", text), \
                    mock.patch.object(owner_module.os, "stat", return_value=metadata), \
                    mock.patch.object(owner_module.os, "readlink", return_value="/authored/changing"), \
                    mock.patch.object(owner_module, "MAX_EXECUTABLE_IDENTITY_BYTES", 16), \
                    mock.patch("builtins.open", return_value=stream):
                with self.assertRaisesRegex(owner_module.Refusal, message):
                    owner_module._read_proc_identity(123)
            self.assertLessEqual(stream.position, 17)
            self.assertTrue(stream.closed)

    def test_stop_coordinator_receives_remaining_outer_budget_without_five_second_truncation(self):
        for limit in (30.0, 5.0):
            clock = FakeClock()
            class SlowStop(FakeBackend):
                def manager_stop(self, role, receipt, timeout):
                    self.stop_timeout = timeout
                    if timeout < 8:
                        raise owner_module.Refusal("authored stop requires eight seconds")
                    clock.sleep(8)
                    return super().manager_stop(role, receipt, timeout)
            backend = SlowStop()
            owner = owner_module.Owner(self.repo / "build/g" / f"budget-{int(limit)}", backend,
                                       clock=clock, test_repo_root=self.repo)
            self.reserve(owner)
            owner.begin_role("buildkit", ["/pinned/buildkitd"], {"PATH": "/bin"}, {"seconds": 1})
            owner.ready("buildkit", {"pidfd": "fixture", "identity": {"exe": "/pinned/buildkitd"}})
            original_event = owner._event
            def event(manifest, state, **facts):
                result = original_event(manifest, state, **facts)
                if state == "sealed" and limit == 30:
                    clock.sleep(7)  # Authored preceding teardown work is charged to the same budget.
                return result
            owner._event = event
            if limit == 30:
                try:
                    stopped = owner.seal_stop("buildkit", timeout=limit)
                except owner_module.Refusal as exc:
                    self.fail(f"remaining outer budget permits the authored eight-second stop: {exc}")
                self.assertEqual(backend.stop_timeout, 23)
                self.assertEqual(clock.now, 15)
                self.assertEqual(stopped["roles"]["buildkit"]["status"], "absence-proved")
            else:
                with self.assertRaisesRegex(owner_module.Refusal, "requires eight seconds"):
                    owner.seal_stop("buildkit", timeout=limit)
                self.assertEqual(backend.stop_timeout, 5)
                self.assertEqual(owner._manifest()["roles"]["buildkit"]["status"], "quarantined-unknown")

    def test_missing_stop_receipt_cannot_be_replaced_by_empty_inventory(self):
        owner = self.make_owner(FakeBackend(empty=True, missing_stop=True))
        manifest = self.reserve(owner)
        owner.begin_role("buildkit", ["/pinned/buildkitd"], {"PATH": "/bin"}, {"seconds": 1})
        owner.ready("buildkit", {"pidfd": "fixture", "identity": {"exe": "/pinned/buildkitd"}})
        with self.assertRaisesRegex(owner_module.Refusal, "lacks supervisor and complete cgroup-kill receipts"):
            owner.seal_stop("buildkit")
        self.assertNotEqual(owner._manifest()["state"], "absence-proved")

    def test_missing_supervisor_receipt_still_runs_emergency_cgroup_kill(self):
        owner = self.make_owner(FakeBackend())
        manifest = self.reserve(owner)

        class KillRecordingAuthority(FakeAuthority):
            def __init__(self):
                super().__init__()
                self.kill_calls = []

            def kill(self, root, role, timeout):
                self.kill_calls.append((role, timeout))
                return super().kill(root, role, timeout)

        authority = KillRecordingAuthority()
        receipt = {"ownerToken": manifest["ownerToken"], "role": "buildkit", "manager": "system",
                   "bootId": "boot-fixture", "unit": "test.service", "slice": "test.slice",
                   "invocationId": "invocation-fixture", "controlGroup": "/test/service"}
        owner_module.atomic_json(self.root / "control/manager-receipt-buildkit.json", receipt)
        owner_module.atomic_json(self.root / "control/child-ready-buildkit.json",
            {"ownerToken": manifest["ownerToken"], "role": "buildkit", "pid": 123, "pidfdHeld": True})
        backend = owner_module.ProductionBackend(self.root,
            runner=FakeCommandRunner(manifest["ownerToken"]), authority=authority,
            test_repo_root=self.repo)
        with self.assertRaisesRegex(owner_module.Refusal, "after emergency cgroup.kill"):
            backend.manager_stop("buildkit", receipt, timeout=0.25)
        self.assertEqual(len(authority.kill_calls), 1)
        emergency = owner_module.read_json_bounded(
            self.root / "control/stop-emergency-kill-buildkit.json", 16 * 1024)
        self.assertEqual(emergency["ownerToken"], manifest["ownerToken"])
        self.assertTrue(emergency["killReceipt"]["empty"])

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

class UploadStageTest(unittest.TestCase):
    def setUp(self):
        owner_fixture_root = ROOT / "build/pr-merge-audit/1866-nested-evidence-inventory/tests/owner-fixtures"
        owner_fixture_root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=owner_fixture_root, prefix="stage-")
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.root = self.repo / "build" / "g" / "owned"

    def tearDown(self):
        self.temp.cleanup()

    def make_owner(self, backend=None):
        return owner_module.Owner(self.root, backend, test_repo_root=self.repo)

    def completed_no_launch_owner(self, backend=None):
        backend = backend or FakeBackend()
        owner_root = self.repo / "build" / "g" / ("owned-" + secrets.token_hex(4))
        owner = owner_module.Owner(owner_root, backend, test_repo_root=self.repo)
        owner.reserve({"run": "fixture", "revision": "abc"}, ["/x/d.sock", "/x/r.sock"])
        owner.seal_stop("buildkit")
        owner.seal_stop("rootless")
        return owner

    def test_actual_parser_nested_evidence_reaches_actual_stage_upload(self):
        fixture_path = ROOT / "tests/oracle/test_gcc_toolchain_builder.py"
        fixture_spec = importlib.util.spec_from_file_location("gcc_parser_fixture", fixture_path)
        fixture_module = importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixture_module)
        fixture_module.ARTIFACTS = ROOT / "build/pr-merge-audit/1866-nested-evidence-inventory/tests/parser-fixtures"
        fixture_module.ARTIFACTS.mkdir(parents=True, exist_ok=True)
        fixture = object.__new__(fixture_module.GccToolchainBuilderTest)
        fixture.setUp()
        try:
            parser_path = ROOT / "scripts/ci-gcc-toolchain-archive.py"
            parser_spec = importlib.util.spec_from_file_location("gcc_archive_parser", parser_path)
            parser = importlib.util.module_from_spec(parser_spec)
            parser_spec.loader.exec_module(parser)
            owner = self.completed_no_launch_owner()
            evidence = owner.root / "evidence"
            input_hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in (fixture.docker, fixture.oci)}
            parser.inspect(fixture.docker, fixture.oci, evidence, 4 * 1024 * 1024)
            self.assertEqual(input_hashes, {path: hashlib.sha256(path.read_bytes()).hexdigest()
                                            for path in (fixture.docker, fixture.oci)})
            self.assertTrue((evidence / "oci-manifests").is_dir())
            self.assertTrue((evidence / "provenance-statements").is_dir())
            staged = owner.stage_upload(success=True)
            rows = json.loads(staged.read_text())["files"]
            self.assertIn("evidence/oci-manifests/" + next((evidence / "oci-manifests").iterdir()).name,
                          [row["path"] for row in rows])
            self.assertIn("evidence/provenance-statements/" + next((evidence / "provenance-statements").iterdir()).name,
                          [row["path"] for row in rows])
            self.assertEqual(sum(row["bytes"] for row in rows), json.loads(staged.read_text())["bytes"])
            for row in rows:
                source = evidence / row["path"].removeprefix("evidence/")
                self.assertEqual(source.stat().st_size, row["bytes"])
                self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), row["sha256"])
        finally:
            fixture.tearDown()

    def test_stage_upload_accepts_exact_two_directories_and_refuses_unknown_or_deep(self):
        for invalid in ("unknown", "deeper"):
            owner = self.completed_no_launch_owner()
            evidence = owner.root / "evidence"
            evidence.mkdir(exist_ok=True)
            (evidence / "top.json").write_bytes(b"top")
            (evidence / "oci-manifests").mkdir()
            (evidence / "provenance-statements").mkdir()
            if invalid == "unknown":
                (evidence / "mystery").mkdir()
            else:
                (evidence / "oci-manifests" / "deep").mkdir()
            with self.assertRaises(owner_module.Refusal):
                owner.stage_upload(success=True)
        owner = self.completed_no_launch_owner()
        evidence = owner.root / "evidence"
        evidence.mkdir(exist_ok=True)
        (evidence / "top.json").write_bytes(b"top")
        with self.assertRaisesRegex(owner_module.Refusal, "missing a required parser directory"):
            owner.stage_upload(success=True)
        for dirname, filename, payload in (("oci-manifests", "sha.json", b"manifest"),
                                            ("provenance-statements", "statement.json", b"statement")):
            (evidence / dirname).mkdir()
            (evidence / dirname / filename).write_bytes(payload)
        rows = json.loads(owner.stage_upload(success=True).read_text())["files"]
        self.assertEqual([row["path"] for row in rows], [
            "evidence/oci-manifests/sha.json", "evidence/provenance-statements/statement.json", "evidence/top.json"])
        self.assertEqual({row["path"]: row["sha256"] for row in rows}["evidence/top.json"], hashlib.sha256(b"top").hexdigest())

    def test_stage_upload_refuses_symlinks_hardlinks_and_sparse_overbudget_before_hash(self):
        for kind in ("symlink-dir", "symlink-file", "hardlink", "sparse"):
            owner = self.completed_no_launch_owner()
            evidence = owner.root / "evidence"
            evidence.mkdir(exist_ok=True)
            canary = self.repo / "outside-canary"
            canary.write_bytes(b"never read")
            if kind == "symlink-dir":
                (evidence / "oci-manifests").symlink_to(self.repo, target_is_directory=True)
            elif kind == "symlink-file":
                (evidence / "escape").symlink_to(canary)
            elif kind == "hardlink":
                (evidence / "payload").write_bytes(b"x")
                os.link(evidence / "payload", evidence / "alias")
            else:
                with (evidence / "large").open("wb") as stream:
                    stream.seek(13 * 1024**3)
                    stream.write(b"x")
            with self.assertRaises(owner_module.Refusal):
                owner.stage_upload(success=True)
            self.assertTrue(canary.exists())

    def test_failure_control_staging_remains_flat_only(self):
        owner = self.completed_no_launch_owner()
        control = owner.root / "control"
        (control / "ordinary.txt").write_text("control")
        result = owner.stage_upload(success=False)
        self.assertEqual(json.loads(result.read_text())["files"][0]["path"], "control/ordinary.txt")
        (control / "nested").mkdir()
        with self.assertRaises(owner_module.Refusal):
            owner.stage_upload(success=False)


    def test_stage_upload_preopen_file_count_and_cumulative_byte_bounds(self):
        owner = self.completed_no_launch_owner()
        evidence = owner.root / "evidence"
        (evidence / "a").write_bytes(b"a")
        (evidence / "b").write_bytes(b"b")
        self.assertEqual(owner_module.MAX_FILES, 128)
        real_hash_entry = owner_module._hash_upload_entry
        with mock.patch.object(owner_module, "MAX_FILES", 0), mock.patch.object(
                owner_module, "_hash_upload_entry", wraps=real_hash_entry) as hash_entry:
            with self.assertRaisesRegex(owner_module.Refusal, "budget"):
                owner.stage_upload(success=True)
            hash_entry.assert_called_once()
        owner = self.completed_no_launch_owner()
        evidence = owner.root / "evidence"
        with (evidence / "sparse").open("wb") as stream:
            stream.seek(13 * 1024**3)
            stream.write(b"x")
        with mock.patch.object(owner_module, "_hash_upload_entry", wraps=real_hash_entry) as hash_entry:
            with self.assertRaisesRegex(owner_module.Refusal, "budget"):
                owner.stage_upload(success=True)
            hash_entry.assert_called_once()

    def test_inventory_closes_root_and_nested_directory_fds_after_refusal(self):
        owner = self.completed_no_launch_owner()
        evidence = owner.root / "evidence"
        (evidence / "oci-manifests").mkdir()
        (evidence / "provenance-statements").mkdir()
        target = self.repo / "outside-canary"
        target.write_bytes(b"not read")
        (evidence / "oci-manifests" / "escape").symlink_to(target)
        real_open = os.open
        opened = []
        def record_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            return fd
        with mock.patch.object(owner_module.os, "open", side_effect=record_open):
            with self.assertRaises(owner_module.Refusal):
                owner.stage_upload(success=True)
        self.assertGreaterEqual(len(opened), 2)
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertTrue(target.exists())

    def test_stream_growth_shrink_and_io_failure_refuse_and_close_file_fd(self):
        for mode in ("growth", "shrink", "io"):
            owner = self.completed_no_launch_owner()
            path = owner.root / "evidence" / "payload"
            path.write_bytes(b"ab")
            parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            before = path.stat(follow_symlinks=False)
            closed = []
            real_open = os.open
            real_close = os.close
            def record_open(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                if args[0] == "payload":
                    closed.append(fd)
                return fd
            def controlled_read(fd, count):
                if mode == "growth":
                    return b"abc"
                if mode == "shrink":
                    return b""
                raise OSError("authored read failure")
            try:
                with mock.patch.object(owner_module.os, "open", side_effect=record_open), \
                     mock.patch.object(owner_module.os, "read", side_effect=controlled_read):
                    with self.assertRaises(owner_module.Refusal):
                        owner_module._hash_upload_entry(parent_fd, "payload", before, path.parent,
                                                        "payload", [], 32, 0)
                self.assertEqual(len(closed), 1)
                with self.assertRaises(OSError):
                    os.fstat(closed[0])
            finally:
                real_close(parent_fd)

    def test_file_replaced_by_fifo_is_opened_nonblocking_and_refused(self):
        owner = self.completed_no_launch_owner()
        path = owner.root / "evidence" / "payload"
        path.write_bytes(b"ab")
        before = path.stat(follow_symlinks=False)
        path.unlink()
        os.mkfifo(path)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        real_open = os.open
        opened = []
        def guarded_open(name, flags, *args, **kwargs):
            if name == "payload":
                self.assertTrue(flags & os.O_NONBLOCK, "substituted FIFO must never block inventory")
            fd = real_open(name, flags, *args, **kwargs)
            opened.append(fd)
            return fd
        try:
            with mock.patch.object(owner_module.os, "open", side_effect=guarded_open):
                with self.assertRaises(owner_module.Refusal):
                    owner_module._hash_upload_entry(parent_fd, "payload", before, path.parent,
                                                    "payload", [], 32, 0)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])
        finally:
            os.close(parent_fd)

    def test_stage_upload_preserves_absence_state_precondition(self):
        owner = self.make_owner(FakeBackend())
        owner.reserve({"run": "fixture", "revision": "abc"}, ["/x/d.sock", "/x/r.sock"])
        with self.assertRaisesRegex(owner_module.Refusal, "complete process absence proof"):
            owner.stage_upload(success=True)


class BusctlArgumentBoundaryTest(unittest.TestCase):
    class RecordingRunner:
        def __init__(self, status=0):
            self.status = status
            self.calls = []

        def run(self, argv, timeout, *, input_data=None, env=None):
            import getopt
            self.calls.append((list(argv), timeout, env))
            bus = argv.index("/usr/bin/busctl")
            # Model the getopt_long option permutation in systemd v255 busctl.
            # No executable, manager, process, namespace or host query is run.
            with mock.patch.dict(os.environ, {}, clear=True):
                try:
                    _, tail = getopt.gnu_getopt(argv[bus + 1:], "hH:M:qjl",
                                                ["json=", "timeout=", "user", "system"])
                except getopt.GetoptError as exc:
                    return 1, b"", str(exc).encode()
            self.tail = tail
            if self.status:
                return self.status, b"", b"authored manager refusal"
            return 0, b'{"type":"o","data":["/org/freedesktop/systemd1/job/77"]}', b""

    def backend(self, runner):
        return owner_module.ProductionBackend(ROOT / "build/test-tmp/gcc-busctl-fixture",
            runner=runner, authority=FakeAuthority(), test_repo_root=ROOT)

    def test_transient_exec_arguments_are_not_busctl_options(self):
        for role in ("rootless", "buildkit"):
            runner = self.RecordingRunner()
            backend = self.backend(runner)
            command = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "/usr/bin/python3",
                       "owner.py", "supervisor", "--owner-root", "fixture", "--role", role]
            prop = backend._busctl_property("ExecStart", "a(sasb)", "1", command[0],
                                            str(len(command)), *command, "false")
            self.assertEqual(backend._start_transient(role, "fixture.service", [prop], 3.5),
                             "/org/freedesktop/systemd1/job/77")
            self.assertEqual(runner.tail, ["call", "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartTransientUnit",
                "ssa(sv)a(sa(sv))", "fixture.service", "fail", "1", *prop, "0"])
            self.assertIn("-i", runner.tail)
            self.assertIn("--owner-root", runner.tail)

    def test_manager_flags_environment_deadline_and_argument_tail_stay_exact(self):
        for role, scope in (("rootless", "--user"), ("buildkit", "--system")):
            runner = self.RecordingRunner()
            backend = self.backend(runner)
            args = ["call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                    "org.freedesktop.systemd1.Manager", "StopUnit", "ss", "fixture.service", "fail"]
            original = list(args)
            backend._run(role, args, 3.5)
            argv, timeout, env = runner.calls[0]
            prefix = [] if role == "rootless" else ["/usr/bin/sudo", "-n"]
            self.assertEqual(argv, prefix + ["/usr/bin/busctl", "--json=short", "--timeout=3s", scope, "--"] + original)
            self.assertEqual(args, original)
            self.assertEqual(timeout, 3.5)
            self.assertEqual(env, {"XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"} if role == "rootless" else None)

    def test_manager_failure_still_refuses_with_original_classification(self):
        runner = self.RecordingRunner(status=1)
        with self.assertRaisesRegex(owner_module.Refusal, "user systemd manager call failed: authored manager refusal"):
            self.backend(runner)._run("rootless", ["call", "fixture"], 2)


class ThreadChildCensusTest(unittest.TestCase):
    class Entry:
        def __init__(self, name, directory=True):
            self.name = str(name)
            self.directory = directory
        def is_dir(self, *, follow_symlinks):
            if follow_symlinks:
                raise AssertionError("task directory links must not be followed")
            return self.directory

    class Tasks:
        def __init__(self, entries):
            self.entries = entries
            self.closed = False
        def __enter__(self):
            return iter(self.entries)
        def __exit__(self, *args):
            self.closed = True

    def fixture(self, groups, lists, *, identities=None, pinned_change=False, short_reads=False):
        import io
        import contextlib
        root = ROOT / "build/test-tmp/gcc-thread-candidates"
        now = [0.0]
        opened, directories, closed, pidfds = [], [], [], []
        reads = []
        def children_path(path):
            return str(path)
        def scanner(path):
            parent = int(str(path).split('/')[2])
            entries = [e if isinstance(e, self.Entry) else self.Entry(e) for e in groups[parent]]
            value = self.Tasks(entries); directories.append(value); return value
        def source(path, *args, **kwargs):
            key = children_path(path)
            payload = lists[key]
            if isinstance(payload, Exception):
                raise payload
            class Stream(io.BytesIO):
                def read(self, size=-1):
                    reads.append(size)
                    self.test.assertGreater(size, 0)
                    self.test.assertLessEqual(size, 4097)
                    return super().read(min(size,1) if short_reads else size)
            value = Stream(payload);value.test = self;opened.append(value);return value
        def old_read(path):
            payload = lists[str(path)]
            if isinstance(payload, Exception):raise payload
            return payload
        calls = {}
        def identity(pid):
            calls[pid] = calls.get(pid, 0) + 1
            value = {"pid":pid,"parentPid":100 if pid==200 else 200,"uid":os.getuid(),
                "cgroup":"0::/owned\n","startTicks":pid,"exeDevice":1,"exeInode":pid,
                "namespaces":{"mnt":5},"exe":str(root / "v/tools/docker/dockerd") if pid==300 else "/pinned/intermediate",
                "exeSha256":owner_module.PINNED_TOOL_HASHES["dockerd"] if pid==300 else "x"}
            value.update((identities or {}).get(pid, {}))
            if pid==300 and calls[pid]>1 and pinned_change:value['startTicks']+=1
            return value
        def pin(pid, flags):
            pidfds.append((pid, flags));return 777
        def sleep(delay):
            self.assertEqual(delay,0.025);now[0]+=delay
        poller=mock.Mock();poller.poll.return_value=[]
        stack=contextlib.ExitStack()
        stack.enter_context(mock.patch.object(owner_module.os,'scandir',side_effect=scanner))
        stack.enter_context(mock.patch('builtins.open',side_effect=source))
        stack.enter_context(mock.patch.object(owner_module.Path,'read_bytes',old_read))
        stack.enter_context(mock.patch.object(owner_module,'_read_proc_identity',side_effect=identity))
        stack.enter_context(mock.patch.object(owner_module.os,'pidfd_open',side_effect=pin))
        stack.enter_context(mock.patch.object(owner_module.os,'close',side_effect=closed.append))
        stack.enter_context(mock.patch.object(owner_module.select,'poll',return_value=poller))
        stack.enter_context(mock.patch.object(owner_module.time,'monotonic',side_effect=lambda:now[0]))
        stack.enter_context(mock.patch.object(owner_module.time,'sleep',side_effect=sleep))
        return stack, root, opened, directories, closed, pidfds, reads

    @staticmethod
    def graph():
        return {100:[100,101],200:[200,201]}, {
            '/proc/100/task/100/children':b'', '/proc/100/task/101/children':b'200 ',
            '/proc/200/task/200/children':b'', '/proc/200/task/201/children':b'300 '}

    def test_nonleader_children_at_both_levels_reach_the_authenticated_dockerd(self):
        groups, lists = self.graph()
        stack,root,opened,dirs,closed,pidfds,reads = self.fixture(groups,lists)
        with stack:
            pid,fd,identity = owner_module._find_authenticated_dockerd(100,root,'/owned',0.05)
        self.assertEqual((pid,fd),(300,777))
        self.assertEqual(identity['startTicks'],300)
        self.assertEqual(pidfds,[(300,0)])
        self.assertEqual(closed,[])
        self.assertTrue(all(x.closed for x in opened+dirs))

    def test_thread_union_byte_node_and_directory_bounds(self):
        cases=[({100:[100,101]}, {'/proc/100/task/100/children':b'200 ', '/proc/100/task/101/children':b'200 300 '}, None),
               ({100:[100]}, {'/proc/100/task/100/children':b'1'*4097}, 'child list exceeds'),
               ({100:[100,101]}, {'/proc/100/task/100/children':b' '*4096, '/proc/100/task/101/children':b'1'}, 'child list exceeds'),
               ({100:[100]}, {'/proc/100/task/100/children':b' '.join(str(x).encode() for x in range(1,258))}, 'node budget'),
               ({100:[self.Entry('not-a-tid')]}, {}, 'directory is malformed'),
               ({100:[self.Entry(100,False)]}, {}, 'directory is malformed'),
               ({100:[]}, {}, 'census is empty'),
               ({100:[100]}, {'/proc/100/task/100/children':b'-1 '}, 'list is malformed')]
        for groups,lists,refusal in cases:
            stack,root,opened,dirs,closed,pidfds,reads=self.fixture(groups,lists,short_reads=True)
            with stack:
                if refusal:
                    with self.assertRaisesRegex(owner_module.Refusal,refusal):owner_module._read_thread_group_children(100,1024)
                else:self.assertEqual(owner_module._read_thread_group_children(100,1024),([200,300],2))
            self.assertTrue(all(x.closed for x in opened+dirs))
            self.assertEqual(pidfds,[])

    def test_task_limit_is_shared_by_the_whole_candidate_traversal(self):
        groups,lists=self.graph()
        groups[100]=[100,101]+list(range(1000,2021))
        for tid in groups[100]:lists.setdefault(f'/proc/100/task/{tid}/children',b'')
        stack,root,opened,dirs,closed,pidfds,reads=self.fixture(groups,lists)
        with stack:
            with self.assertRaisesRegex(owner_module.Refusal,'task budget'):
                owner_module._find_authenticated_dockerd(100,root,'/owned',0.05)
        self.assertEqual(len(opened),1024)
        self.assertTrue(all(x.closed for x in opened+dirs))
        self.assertEqual(pidfds,[])

    def test_inaccessible_thread_and_wrong_ancestry_uid_or_cgroup_refuse(self):
        for kind in ['unreadable','parent','uid','cgroup']:
            groups,lists=self.graph();identities={}
            if kind=='unreadable':lists['/proc/100/task/101/children']=OSError('authored vanished task')
            else:identities[200]={'parentPid':999} if kind=='parent' else {'uid':os.getuid()+1} if kind=='uid' else {'cgroup':'0::/elsewhere\n'}
            stack,root,opened,dirs,closed,pidfds,reads=self.fixture(groups,lists,identities=identities)
            with stack:
                with self.assertRaises(owner_module.Refusal):owner_module._find_authenticated_dockerd(100,root,'/owned',0.05)
            self.assertTrue(all(x.closed for x in opened+dirs))
            self.assertEqual(pidfds,[])

    def test_pidfd_identity_mismatch_keeps_the_existing_refusal_and_close(self):
        groups,lists=self.graph()
        stack,root,opened,dirs,closed,pidfds,reads=self.fixture(groups,lists,pinned_change=True)
        with stack:
            with self.assertRaisesRegex(owner_module.Refusal,'identity changed during pidfd'):
                owner_module._find_authenticated_dockerd(100,root,'/owned',0.05)
        self.assertEqual(pidfds,[(300,0)])
        self.assertEqual(closed,[777])

    def test_missing_candidate_retains_the_existing_exec_deadline(self):
        stack,root,opened,dirs,closed,pidfds,reads=self.fixture({100:[100]},{'/proc/100/task/100/children':b''})
        with stack:
            with self.assertRaisesRegex(owner_module.Refusal,'exec deadline'):
                owner_module._find_authenticated_dockerd(100,root,'/owned',0.05)
        self.assertEqual(pidfds,[])
        self.assertTrue(all(x.closed for x in opened+dirs))


if __name__ == "__main__":
    unittest.main()
