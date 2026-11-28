#!/usr/bin/env python3
"""Unprivileged parser, ownership-refusal and CLI controls; never mounts anything."""
from __future__ import annotations

import copy
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ext4_admission_fixture", ROOT / "scripts/ci-oracle-ext4-admission.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def state():
    images = {name: {"mountId": index, "loop": {"rdev": os.makedev(7, index)}}
              for name, index in (("original", 10), ("replacement", 11))}
    mounts = [{"id": index, "parent": 9, "device": f"7:{index}", "root": "/",
               "path": str(fixture.PATHS[path]), "options": sorted(fixture.BASE_OPTIONS.split(',')),
               "type": "ext4", "source": f"/dev/loop{index}", "superOptions": ["rw"]}
              for path, index in (("scratch", 10), ("replacement", 11))]
    parent = {"id": 9, "parent": 1, "device": "0:999", "root": "/", "path": str(fixture.PARENT),
              "options": sorted(fixture.BASE_OPTIONS.split(',')), "type": "tmpfs", "optional": [],
              "source": "tmpfs", "superOptions": ["rw"]}
    return {"mode": "ready", "images": images, "mounts": mounts + [parent], "parentMount": parent}


class CliTests(unittest.TestCase):
    def test_invalid_arguments_refuse_before_privilege_or_filesystem_access(self):
        for arguments in ([], ["unknown"], ["inspect", "/other"], ["prepare", "--path=/other"]):
            with self.subTest(arguments=arguments), patch.object(fixture.os, "geteuid", side_effect=AssertionError("privilege probe")), redirect_stderr(io.StringIO()):
                self.assertEqual(fixture.main(arguments), 64)

    def test_every_action_refuses_unprivileged_before_state_or_commands(self):
        for action in sorted(fixture.ACTIONS):
            with self.subTest(action=action), patch.object(fixture.os, "geteuid", return_value=1000), \
                 patch.object(fixture, "run", side_effect=AssertionError("utility ran")), \
                 patch.object(fixture, "load", side_effect=AssertionError("state read")), redirect_stderr(io.StringIO()):
                self.assertEqual(fixture.main([action]), 77)

    def test_real_cli_rejects_unknown_action(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/ci-oracle-ext4-admission.py"), "unknown"],
                                capture_output=True, timeout=5, env={})
        self.assertEqual(result.returncode, 64)
        self.assertEqual(result.stdout, b"")


class MountInventoryTests(unittest.TestCase):
    def test_parser_preserves_mount_identity_flags_and_escaped_paths(self):
        rows = fixture.mount_table("42 1 7:10 / /var/lib/with\\040space rw,nosuid,nodev,noexec,noatime shared:2 - ext4 /dev/loop10 rw\n")
        self.assertEqual(rows[0]["id"], 42)
        self.assertEqual(rows[0]["path"], "/var/lib/with space")
        self.assertEqual(rows[0]["root"], "/")
        self.assertEqual(rows[0]["options"], sorted(fixture.BASE_OPTIONS.split(',')))

    def test_duplicate_malformed_and_oversized_inventories_refuse(self):
        row = "42 1 7:10 / /root rw - ext4 /dev/loop10 rw\n"
        for text in (row + row, "no separator", "x" * (4 * 1024 * 1024 + 1)):
            with self.subTest(length=len(text)), self.assertRaises((fixture.FixtureError, ValueError)):
                fixture.mount_table(text)

    def test_ready_shape_requires_both_exact_ext4_mount_identities(self):
        fixture.verify_mount_shape(state())
        for field, value in (("id", 99), ("device", "7:99"), ("root", "/subtree"), ("type", "tmpfs"), ("path", "/unowned")):
            altered = state()
            altered["mounts"][0][field] = value
            with self.subTest(field=field), self.assertRaises(fixture.FixtureError):
                fixture.verify_mount_shape(altered)

    def test_missing_flags_require_the_declared_flag_to_actually_be_missing(self):
        for missing in ("nodev", "nosuid", "noexec", "noatime"):
            current = state()
            current["mode"] = f"missing-{missing}"
            with self.subTest(missing=missing), self.assertRaisesRegex(fixture.FixtureError, "was not established"):
                fixture.verify_mount_shape(current)
            current["mounts"][0]["options"].remove(missing)
            fixture.verify_mount_shape(current)
            current["mounts"][1]["options"].remove(missing)
            with self.assertRaises(fixture.FixtureError):
                fixture.verify_mount_shape(current)

    def test_readonly_requires_actual_ro_and_replacement_stays_rw(self):
        current = state()
        current["mode"] = "readonly"
        with self.assertRaises(fixture.FixtureError):
            fixture.verify_mount_shape(current)
        current["mounts"][0]["options"].remove("rw")
        current["mounts"][0]["options"].append("ro")
        fixture.verify_mount_shape(current)

    def test_replacement_moves_preserve_original_and_replacement_mount_ids(self):
        current = state()
        current["mode"] = "replace-root"
        current["mounts"][0]["path"] = str(fixture.PATHS["retained"])
        current["mounts"][1]["path"] = str(fixture.PATHS["scratch"])
        fixture.verify_mount_shape(current)
        current["mounts"][0]["id"], current["mounts"][1]["id"] = 11, 10
        with self.assertRaises(fixture.FixtureError):
            fixture.verify_mount_shape(current)

    def test_bind_subtree_and_alias_require_exact_owned_device_and_root(self):
        for mode, root in (("bind-subtree", "/subtree"), ("bind-alias", "/")):
            current = state()
            current["mode"] = mode
            extra = copy.deepcopy(current["mounts"][0])
            extra.update(id=12, root=root, path=str(fixture.PATHS["subtree" if mode == "bind-subtree" else "alias"]))
            current["mounts"].append(extra)
            fixture.verify_mount_shape(current)
            extra["device"] = "7:99"
            with self.subTest(mode=mode), self.assertRaises(fixture.FixtureError):
                fixture.verify_mount_shape(current)

    def test_tmpfs_and_nested_require_one_exact_extra_mount(self):
        for mode, path in (("tmpfs", fixture.PATHS["scratch"]), ("nested", fixture.PATHS["scratch"] / "nested")):
            current = state()
            current["mode"] = mode
            current["mounts"].append({"id": 12, "path": str(path), "type": "tmpfs", "root": "/"})
            fixture.verify_mount_shape(current)
            current["mounts"].append({"id": 13, "path": "/alien", "type": "tmpfs", "root": "/"})
            with self.subTest(mode=mode), self.assertRaises(fixture.FixtureError):
                fixture.verify_mount_shape(current)

    def test_shared_or_substituted_parent_mount_is_refused(self):
        current = state()
        current["parentMount"]["optional"] = ["shared:42"]
        with self.assertRaisesRegex(fixture.FixtureError, "private owned tmpfs"):
            fixture.verify_mount_shape(current)
        current = state()
        current["mounts"][0]["parent"] = 1
        with self.assertRaisesRegex(fixture.FixtureError, "mount shape"):
            fixture.verify_mount_shape(current)

    def test_extra_mount_in_ready_state_is_refused(self):
        current = state()
        current["mounts"].append({"id": 12})
        with self.assertRaisesRegex(fixture.FixtureError, "unexpected mount"):
            fixture.verify_mount_shape(current)


class OwnershipRefusalTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="ext4-admission-controls-", dir=ROOT / "build")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_canary_substitution_is_refused_without_modifying_it(self):
        replacement = self.root / "replacement"
        replacement.mkdir()
        canary = replacement / fixture.CANARY_NAME
        canary.write_text(fixture.CANARY_CONTENT, encoding="ascii")
        current = {"mode": "ready", "canary": fixture.identity(canary)}
        with patch.dict(fixture.PATHS, replacement=replacement):
            fixture.verify_canary(current)
            canary.write_bytes(b"alien replacement content")
            with self.assertRaisesRegex(fixture.FixtureError, "preserving residue"):
                fixture.verify_canary(current)
            self.assertEqual(canary.read_bytes(), b"alien replacement content")

    def test_cleanup_refuses_nonempty_companion_before_unmount_or_canary_removal(self):
        paths = {name: self.root / name for name in fixture.PATHS}
        for path in paths.values():
            path.mkdir()
        canary = paths["replacement"] / fixture.CANARY_NAME
        canary.write_text(fixture.CANARY_CONTENT, encoding="ascii")
        alien = paths["alias"] / "alien"
        alien.write_bytes(b"keep")
        with patch.dict(fixture.PATHS, paths), patch.object(fixture, "restore"), patch.object(fixture, "verify"), \
             patch.object(fixture, "run") as command:
            with self.assertRaises(fixture.FixtureError):
                fixture.cleanup({"mode": "ready"})
            command.assert_not_called()
        self.assertEqual(alien.read_bytes(), b"keep")
        self.assertEqual(canary.read_text(), fixture.CANARY_CONTENT)

    def test_backing_inode_substitution_refuses_before_any_utility(self):
        record = {"file": {"device": 1, "inode": 2}, "loop": {"path": "/dev/loop1", "backingDevice": 1, "backingInode": 2}}
        with patch.object(fixture, "identity", return_value=record["file"]), \
             patch.object(fixture, "loop_identity", return_value={**record["loop"], "backingInode": 3}), \
             patch.object(fixture, "run") as command:
            with self.assertRaises(fixture.FixtureError):
                fixture.verify_image("original", record)
            command.assert_not_called()

    def test_directory_enumeration_stops_at_population_bound(self):
        for index in range(3):
            (self.root / str(index)).write_bytes(b"keep")
        with self.assertRaisesRegex(fixture.FixtureError, "population bound"):
            fixture.entry_names(self.root, 2)
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["0", "1", "2"])


class UtilityTransportTests(unittest.TestCase):
    def test_expired_action_refuses_before_launch(self):
        with patch.object(fixture, "_deadline", time.monotonic() - 1), patch.dict(fixture.COMMANDS, probe=sys.executable), \
             patch.object(fixture.subprocess, "Popen") as child:
            with self.assertRaisesRegex(fixture.FixtureError, "before a utility launch"):
                fixture.run("probe", [])
            child.assert_not_called()

    def test_unprivileged_python_output_is_bounded_during_read(self):
        with patch.object(fixture, "_deadline", time.monotonic() + 5), patch.dict(fixture.COMMANDS, probe=sys.executable):
            with self.assertRaisesRegex(fixture.FixtureError, "output exceeds"):
                fixture.run("probe", ["-I", "-S", "-B", "-c", "import sys,time;sys.stdout.write('x'*8192);sys.stdout.flush();time.sleep(2)"])

    def test_exited_leader_cannot_leave_an_owned_child_after_success_or_failure(self):
        (ROOT / "build").mkdir(exist_ok=True)
        program = """import os,sys,time
child = os.fork()
if child == 0:
    for fd in (0, 1, 2):
        os.close(fd)
    time.sleep(0.2)
    with open(sys.argv[1], 'w') as out:
        out.write('child escaped cleanup')
    os._exit(0)
os._exit(int(sys.argv[2]))
"""
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as directory:
            for code in (0, 7):
                marker = Path(directory) / f"child-{code}"
                with self.subTest(code=code), patch.object(fixture, "_deadline", time.monotonic() + 5), \
                     patch.dict(fixture.COMMANDS, probe=sys.executable):
                    if code:
                        with self.assertRaisesRegex(fixture.FixtureError, "exit 7"):
                            fixture.run("probe", ["-I", "-S", "-B", "-c", program, str(marker), str(code)])
                    else:
                        self.assertEqual(fixture.run("probe", ["-I", "-S", "-B", "-c", program, str(marker), str(code)]), "")
                time.sleep(0.3)
                self.assertFalse(marker.exists(), "owned descendant survived utility completion")

    def test_unprivileged_python_timeout_terminates_and_reaps_owned_child(self):
        with patch.object(fixture, "_deadline", time.monotonic() + 0.05), patch.dict(fixture.COMMANDS, probe=sys.executable):
            started = time.monotonic()
            with self.assertRaisesRegex(fixture.FixtureError, "deadline"):
                fixture.run("probe", ["-I", "-S", "-B", "-c", "import time;time.sleep(10)"])
            self.assertLess(time.monotonic() - started, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
