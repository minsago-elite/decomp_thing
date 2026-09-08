#!/usr/bin/env python3
"""Small lifecycle regressions; no browser, JVM, native runtime or downloaded data."""

import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("install", Path(__file__).with_name("packaged-browser-install.py"))
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


class InstallationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="browser-helper-test-")
        self.root = Path(self.temporary.name)
        self.work = self.root / "work"
        self.work.mkdir()
        self.archive = self.root / "app.zip"
        jar = io.BytesIO()
        with zipfile.ZipFile(jar, "w") as output:
            output.writestr("decompengine/web/ui/asset-manifest.json", json.dumps({"buildId": "test"}))
        with zipfile.ZipFile(self.archive, "w") as output:
            for name, mode, data in (
                ("app/lib/llm-bin-patch-test.jar", 0o644, jar.getvalue()),
                ("app/runtimes/deep/native-helper", 0o755, b"native"),
                ("app/runtimes/deep/owner-executable", 0o744, b"owner"),
                ("app/bin/non-executable", 0o644, b"data"),
            ):
                entry = zipfile.ZipInfo(name)
                entry.external_attr = (stat.S_IFREG | mode) << 16
                output.writestr(entry, data)

    def tearDown(self):
        if (self.work / install.MARKER).exists():
            install.cleanup(self.work, "test-owner")
        self.temporary.cleanup()

    def test_nested_execute_bits_preserved_without_inventing_permission(self):
        result = install.prepare(self.archive, self.work, "test-owner")
        app = Path(result["app"])
        self.assertEqual((app / "runtimes/deep/native-helper").stat().st_mode & 0o777, 0o555)
        self.assertEqual((app / "runtimes/deep/owner-executable").stat().st_mode & 0o777, 0o544)
        self.assertEqual((app / "bin/non-executable").stat().st_mode & 0o777, 0o444)
        self.assertTrue(all(path.stat().st_mode & 0o222 == 0 for path in app.rglob("*")))
        self.assertEqual(result["jarSha256"], install.digest(app / "lib/llm-bin-patch-test.jar"))

    def test_cleanup_checks_owner_and_does_not_follow_external_symlink(self):
        install.prepare(self.archive, self.work, "test-owner")
        outside = self.root / "unowned"
        outside.mkdir()
        (outside / "keep").write_text("keep")
        (self.work / "external-link").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "ownership token"):
            install.cleanup(self.work, "wrong-owner")
        install.cleanup(self.work, "test-owner")
        self.assertFalse(self.work.exists())
        self.assertEqual((outside / "keep").read_text(), "keep")

    def test_resource_failure_precedes_archive_extraction(self):
        for bytes_available, inodes_available in ((1, 100000), (10**12, 1)):
            with self.subTest(bytes=bytes_available, inodes=inodes_available):
                capacity = types.SimpleNamespace(f_bavail=bytes_available, f_frsize=1, f_favail=inodes_available)
                with patch.object(install.os, "statvfs", return_value=capacity):
                    with self.assertRaisesRegex(RuntimeError, "--work-parent"):
                        install.prepare(self.archive, self.work, "test-owner")
                self.assertEqual(list(self.work.iterdir()), [self.work / install.MARKER])
                install.cleanup(self.work, "test-owner")
                self.work.mkdir()


if __name__ == "__main__":
    unittest.main()
