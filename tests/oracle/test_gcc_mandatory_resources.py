"""Actual readiness consumers, with inert boundaries and no project-module imports."""
from __future__ import annotations

import ast
import builtins
import contextlib
import contextvars
import json
from pathlib import Path
import stat
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[2]
_ACTIVE = contextvars.ContextVar("gcc_mandatory_resource_control", default=False)


def _audit(event, arguments):
    if _ACTIVE.get() and (event == "open" or event == "import" or event.startswith((
            "socket.", "subprocess.", "_posixsubprocess.", "ctypes.", "os.exec", "os.spawn",
            "os.posix_spawn", "os.fork", "os.system", "os.unshare", "os.setns"))):
        raise RuntimeError("inert readiness boundary refused: " + event)


# Inactive outside synchronous extracted-code calls; other unittest modules retain
# their own policies. No process-wide filesystem or execution policy is imposed.
sys.addaudithook(_audit)


@contextlib.contextmanager
def _guarded():
    token = _ACTIVE.set(True)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


_BUILTINS = {name: getattr(builtins, name) for name in (
    "__build_class__", "RuntimeError", "OSError", "SystemExit", "isinstance", "str", "dict",
    "list", "tuple", "bytes", "float", "int", "bool", "any", "all", "min", "max", "len", "UnicodeDecodeError")}


def _tree(relative):
    with (ROOT / relative).open("rb") as stream:
        data = stream.read(512 * 1024 + 1)
    if len(data) > 512 * 1024:
        raise AssertionError("readiness source exceeds control cap")
    return ast.parse(data, filename=relative)


def _top(tree, name):
    matches = [node for node in tree.body if getattr(node, "name", None) == name]
    if len(matches) != 1:
        raise AssertionError("expected one source definition: " + name)
    return matches[0]


def _compile(nodes, namespace):
    module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    namespace = {**namespace, "__name__": "inert_gcc_readiness", "__builtins__": _BUILTINS}
    with _guarded():
        exec(compile(module, "<actual-readiness-source>", "exec"), namespace)
    return namespace


def _call(function, *args, **kwargs):
    with _guarded():
        return function(*args, **kwargs)


class FakePath:
    def __init__(self, value, *, mode=stat.S_IFSOCK | 0o600, uid=1000, missing=False):
        self.value = str(value)
        self.mode = mode
        self.uid = uid
        self.missing = missing

    def __truediv__(self, value):
        return FakePath(self.value.rstrip("/") + "/" + str(value))

    def __str__(self):
        return self.value

    def __eq__(self, other):
        return isinstance(other, FakePath) and self.value == other.value

    def resolve(self):
        return self

    def lstat(self):
        if self.missing:
            raise OSError("inert missing endpoint")
        return types.SimpleNamespace(st_mode=self.mode, st_uid=self.uid)

    stat = lstat


class FakeInfo:
    def __init__(self, value):
        self.value = value

    def read_text(self):
        return json.dumps(self.value)


class ResourceAdmissionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        owner = _tree("scripts/ci-gcc-toolchain-owner.py")
        archive = _tree("scripts/ci-gcc-toolchain-archive.py")
        classes = [_top(owner, "Refusal")]
        unsupported = [x for x in owner.body if getattr(x, "name", None) == "MandatoryResourceUnsupported"]
        cls.declared_unsupported = len(unsupported) == 1
        # Retains a usable red baseline for the old functions without inventing a
        # production gate. Its absence is separately asserted below.
        classes += unsupported or [ast.ClassDef(name="MandatoryResourceUnsupported", bases=[ast.Name(id="Refusal", ctx=ast.Load())], keywords=[], body=[ast.Pass()], decorator_list=[])]
        cls.backend_type = type("ProductionBackend", (), {})
        cls.time = types.SimpleNamespace(sleep=lambda value: (_ for _ in ()).throw(AssertionError("unbound fake clock")))
        namespace = _compile(classes + [_top(owner, "validate_docker_health")], {
            "json": json, "Path": FakePath, "stat": stat,
            "os": types.SimpleNamespace(getuid=lambda: 1000),
        })
        cls.refusal = namespace["Refusal"]
        cls.unsupported = namespace["MandatoryResourceUnsupported"]
        cls.health = staticmethod(namespace["validate_docker_health"])
        owner_class = _top(owner, "Owner")
        ready = _top(owner_class, "ready_after_health")
        cls.ready = staticmethod(_compile([ready], {**namespace, "ProductionBackend": cls.backend_type, "time": cls.time})["ready_after_health"])
        cls.archive = staticmethod(_compile([_top(archive, "refuse"), _top(archive, "validate_docker_info")], {
            "json": json, "pathlib": types.SimpleNamespace(Path=FakePath), "stat": stat,
            "os": types.SimpleNamespace(getuid=lambda: 1000),
        })["validate_docker_info"])

    @staticmethod
    def healthy():
        return {"Driver": "overlay2", "DockerRootDir": "/job/v/s/docker-data", "ServerVersion": "29.7.2",
                "MemoryLimit": True, "SwapLimit": True, "CgroupDriver": "systemd", "CgroupVersion": "2",
                "SecurityOptions": ["name=rootless", "name=cgroupns", "name=seccomp,profile=builtin"]}

    def owner_health(self, info, *, endpoint=None, version=b"29.7.2 6a43e3d"):
        return _call(self.health, json.dumps(info).encode(), version, FakePath("/job"), endpoint or FakePath("/job/d.sock"))

    def archive_health(self, info, *, endpoint=None, root=None):
        return _call(self.archive, FakeInfo(info), root or FakePath("/job/v/s/docker-data"), endpoint or FakePath("/job/d.sock"), FakePath("/job"))

    def test_actual_consumers_accept_advertised_profile_without_enforcement_claim(self):
        facts = self.owner_health(self.healthy())
        self.assertEqual(facts["serverVersion"], "29.7.2")
        self.assertEqual(facts["endpointOwner"], 1000)
        self.assertEqual(facts["advertisedCapabilities"], {"memoryLimit": True, "swapLimit": True,
            "rootless": True, "cgroupDriver": "systemd", "cgroupVersion": "2"})
        self.assertIsNone(self.archive_health(self.healthy()))
        self.assertTrue(self.declared_unsupported)
        self.assertTrue(issubclass(self.unsupported, self.refusal))
        self.assertFalse(issubclass(self.unsupported, SystemExit))

    def test_both_consumers_reject_each_missing_or_non_boolean_capability(self):
        for flag in ["MemoryLimit", "SwapLimit"]:
            for value in [None, False, 0, 1, 1.0, "true", {}, []]:
                with self.subTest(flag=flag, value=value):
                    info = self.healthy(); info[flag] = value
                    with self.assertRaises(self.unsupported): self.owner_health(info)
                    with self.assertRaises(SystemExit): self.archive_health(info)
            info = self.healthy(); del info[flag]
            with self.assertRaises(self.unsupported): self.owner_health(info)
            with self.assertRaises(SystemExit): self.archive_health(info)

    def test_both_consumers_reject_wrong_cgroup_or_rootless_profile(self):
        for key, values in {"CgroupDriver": [None, "cgroupfs", "SYSTEMD", True], "CgroupVersion": [None, "1", 2, True],
                            "SecurityOptions": [None, [], "name=rootless", ["rootless"], ["NAME=ROOTLESS"], ["name=rootless", 1]]}.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    info = self.healthy(); info[key] = value
                    with self.assertRaises(self.unsupported): self.owner_health(info)
                    with self.assertRaises(SystemExit): self.archive_health(info)

    def test_prior_server_layout_and_endpoint_checks_remain(self):
        for key, value in [("Driver", "vfs"), ("DockerRootDir", "/wrong"), ("ServerVersion", "29.7.1")]:
            info = self.healthy(); info[key] = value
            with self.assertRaises(self.refusal): self.owner_health(info)
            if key != "ServerVersion":
                with self.assertRaises(SystemExit): self.archive_health(info)
        with self.assertRaises(self.refusal): self.owner_health(self.healthy(), version=b"29.7.2 wrong")
        for endpoint in [FakePath("/job/d.sock", missing=True), FakePath("/job/d.sock", mode=stat.S_IFREG | 0o600), FakePath("/job/d.sock", uid=0)]:
            with self.assertRaises(self.refusal): self.owner_health(self.healthy(), endpoint=endpoint)
            with self.assertRaises(SystemExit): self.archive_health(self.healthy(), endpoint=endpoint)
        with self.assertRaises(SystemExit): self.archive_health(self.healthy(), endpoint=FakePath("/job/v/d.sock"))
        with self.assertRaises(SystemExit): self.archive_health(self.healthy(), root=FakePath("/job/v/docker-data"))

    def test_malformed_metadata_and_unowned_endpoint_never_earn_admission(self):
        for info in [None, [], 1, "not an info object"]:
            with self.assertRaises(self.refusal): self.owner_health(info)
            with self.assertRaises(SystemExit): self.archive_health(info)
        for raw in [b"{", b"\xff"]:
            with self.assertRaises(self.refusal):
                _call(self.health, raw, b"29.7.2 6a43e3d", FakePath("/job"), FakePath("/job/d.sock"))
        with self.assertRaises(self.refusal):
            self.owner_health(self.healthy(), version=b"\xff")
        info = self.healthy(); info["SwapLimit"] = False
        with self.assertRaises(self.refusal) as caught:
            self.owner_health(info, endpoint=FakePath("/job/d.sock", uid=0))
        self.assertNotIsInstance(caught.exception, self.unsupported)

    def fake_owner(self, info, *, transient=False, reject_domain=False):
        events = []
        clock = types.SimpleNamespace(now=0.0)

        def sleep(amount):
            events.append("sleep"); clock.now += amount
            if events.count("sleep") > 2: raise AssertionError("deterministic readiness was retried")

        self.time.sleep = sleep

        def run(argv, timeout, env=None):
            events.append("info" if "info" in argv else "version")
            if len([x for x in events if x in ["info", "version"]]) > 5:
                raise AssertionError("unexpected health call count")
            self.assertGreater(timeout, 0); self.assertLessEqual(timeout, 5)
            self.assertEqual(argv[:3], ["/job/v/tools/docker/docker", "--host", "unix:///job/d.sock"])
            self.assertEqual(env, {"DOCKER_CONFIG": "/job/v/docker-config", "XDG_RUNTIME_DIR": "/run/user/1000"})
            if transient and events.count("info") == 1: return 1, b"", b"inert transient error"
            return 0, json.dumps(info).encode() if "info" in argv else b"29.7.2 6a43e3d", b""

        def domain(role, manifest, populated):
            events.append("domain")
            self.assertTrue(populated)
            if reject_domain: raise self.refusal("inert original-domain refusal")

        backend = self.backend_type()
        backend.runner = types.SimpleNamespace(run=run)
        backend._verify_live_domain = domain
        owner = types.SimpleNamespace(root=FakePath("/job"), backend=backend, clock=lambda: clock.now,
            _manifest=lambda: {"roles": {"rootless": {"status": "exec-observed"}}},
            ready=lambda role, facts: events.append(("ready", role, facts)))
        return owner, events

    def test_actual_owner_loop_refuses_once_without_ready_or_retry(self):
        info = self.healthy(); info["SwapLimit"] = False
        owner, events = self.fake_owner(info)
        with self.assertRaises(self.unsupported): _call(self.ready, owner, "rootless", timeout=10)
        self.assertEqual(events, ["info", "version"])

    def test_actual_owner_loop_checks_domain_before_ready(self):
        owner, events = self.fake_owner(self.healthy())
        facts = _call(self.ready, owner, "rootless", timeout=10)
        self.assertEqual(events[:3], ["info", "version", "domain"])
        self.assertEqual(len(events), 4)
        self.assertEqual(events[3], ("ready", "rootless", {"pidfd": True, "identity": True, **facts}))
        owner, events = self.fake_owner(self.healthy(), reject_domain=True)
        with self.assertRaisesRegex(self.refusal, "original-domain"): _call(self.ready, owner, "rootless", timeout=10)
        self.assertEqual(events, ["info", "version", "domain"])

    def test_transient_health_retry_retains_existing_flow(self):
        owner, events = self.fake_owner(self.healthy(), transient=True)
        _call(self.ready, owner, "rootless", timeout=10)
        self.assertEqual(events[:5], ["info", "sleep", "info", "version", "domain"])
        self.assertEqual(len(events), 6)

    def test_audit_guard_is_scoped_and_blocks_inert_boundary_probes(self):
        for event in ["open", "import", "socket.__new__", "subprocess.Popen", "os.exec", "os.fork", "ctypes.dlopen"]:
            sys.audit(event)
            with self.assertRaisesRegex(RuntimeError, "inert readiness boundary"):
                with _guarded(): sys.audit(event)
            sys.audit(event)
        self.assertFalse(_ACTIVE.get())
        control = _compile(ast.parse("def control():\n import os\n").body, {})["control"]
        with self.assertRaises(ImportError):
            _call(control)
        control = _compile(ast.parse("def control():\n open('/unregistered')\n").body, {})["control"]
        with self.assertRaises(NameError):
            _call(control)
        self.assertFalse(_ACTIVE.get())


if __name__ == "__main__":
    unittest.main()
