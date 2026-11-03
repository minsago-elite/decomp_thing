from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNER_PATH = ROOT / "scripts/ci-gcc-toolchain-owner.py"
spec = importlib.util.spec_from_file_location("gcc_owner", OWNER_PATH)
owner_module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(owner_module)


class FakeBackend:
    def __init__(self, *, fail_reserve=False, empty=True):
        self.fail_reserve = fail_reserve
        self.empty = empty
        self.calls = []

    def manager_reserve(self, role, manifest):
        self.calls.append(("reserve", role))
        if self.fail_reserve:
            raise owner_module.Refusal("authored manager denial")
        return {"ownerToken": manifest["ownerToken"], "role": role, "unit": "test.scope",
                "controlGroup": "/test/owned", "device": 1, "inode": 2, "invocationId": "fixture"}

    def manager_gate(self, role, manifest):
        self.calls.append(("gate", role))
        return {"ownerToken": manifest["ownerToken"], "role": role, "unit": "test.scope",
                "controlGroup": "/test/owned", "device": 1, "inode": 2,
                "exec": {"pidfd": "authored", "identity": "fixture"}}

    def manager_stop(self, role, receipt, timeout):
        self.calls.append(("stop", role, timeout))
        return {"ownerToken": receipt["ownerToken"], "role": role, "status": "stopped"}

    def domain_empty(self, role, receipt, timeout):
        self.calls.append(("empty", role, timeout))
        return self.empty

    def release_volume(self, manifest, timeout):
        return {"ownerToken": manifest["ownerToken"], "released": True}


class OwnerTest(unittest.TestCase):
    def setUp(self):
        root = ROOT / "build/pr-merge-audit/gcc-native-builder-repair-implementation/tests"
        root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=root, prefix="owner-")
        self.root = Path(self.temp.name) / "owned"

    def tearDown(self):
        self.temp.cleanup()

    def reserve(self, owner):
        return owner.reserve({"run": "fixture", "revision": "abc"},
            ["/x/d.sock", "/x/r/api.sock"])

    def test_socket_admission_precedes_owner_directory_creation(self):
        owner = owner_module.Owner(self.root, FakeBackend())
        with self.assertRaises(owner_module.Refusal):
            owner.reserve({}, ["x" * 108])
        self.assertFalse(self.root.exists())

    def test_durable_intent_precedes_manager_reservation_and_missing_receipt_fails(self):
        backend = FakeBackend(fail_reserve=True)
        owner = owner_module.Owner(self.root, backend)
        self.reserve(owner)
        with self.assertRaisesRegex(owner_module.Refusal, "denial"):
            owner.begin_role("buildkit", ["/pinned/buildkitd"], {"PATH": "/bin"}, {"seconds": 2})
        events = [json.loads(line) for line in owner.journal_path.read_text().splitlines()]
        self.assertEqual([row["state"] for row in events], ["reserved", "launch-intent"])
        self.assertEqual(backend.calls, [("reserve", "buildkit")])
        with self.assertRaisesRegex(owner_module.Refusal, "lacks manager receipt; absence is unknown"):
            owner.seal_stop("buildkit")

    def test_unknown_domain_absence_never_becomes_success(self):
        backend = FakeBackend(empty=False)
        owner = owner_module.Owner(self.root, backend)
        self.reserve(owner)
        owner.begin_role("buildkit", ["/pinned/buildkitd"], {"PATH": "/bin"}, {"seconds": 2})
        owner.ready("buildkit", {"pidfd": "test-pidfd", "identity": {"exe": "/pinned/buildkitd"}})
        with self.assertRaisesRegex(owner_module.Refusal, "absence is unknown"):
            owner.seal_stop("buildkit")
        self.assertNotEqual(owner._manifest()["state"], "absence-proved")
        self.assertNotIn("released", [json.loads(row)["state"] for row in owner.journal_path.read_text().splitlines()])

    def test_production_backend_cannot_be_replaced_through_environment(self):
        backend = owner_module.ProductionBackend()
        self.assertEqual(type(backend).__name__, "ProductionBackend")
        self.assertNotIn("backend", owner_module.cli.__code__.co_varnames)


if __name__ == "__main__":
    unittest.main()
