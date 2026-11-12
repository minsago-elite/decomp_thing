#!/usr/bin/env python3
"""Offline controls for the hash-locked Playwright browser installer."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("install-web-test-browser-engines.py")
SPEC = importlib.util.spec_from_file_location("install_web_test_browser_engines", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(installer)


class SymlinkTarget:
    def __init__(self, target: str) -> None:
        self.target = target


def make_archive(path: Path, members: dict[str, bytes | SymlinkTarget]) -> tuple[int, int, set[str]]:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            if name.endswith("/"):
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
                archive.writestr(info, b"")
            elif isinstance(data, SymlinkTarget):
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, data.target.encode("utf-8"))
            else:
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                archive.writestr(info, data)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        return len(entries), sum(entry.file_size for entry in entries), {
            entry.filename.rstrip("/").split("/", 1)[0] for entry in entries
        }


class PlaywrightBrowserInstallerTest(unittest.TestCase):
    def setUp(self) -> None:
        (Path.cwd() / "build").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="pw-installer-test-", dir=Path.cwd() / "build")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / "browsers"
        self.cache.mkdir()
        self.playwright = self.root / "playwright-core"
        self.playwright.mkdir()
        (self.playwright / "package.json").write_text(json.dumps({"version": "1.58.2"}))
        (self.playwright / "browsers.json").write_text(json.dumps({"browsers": [{
            "name": "firefox", "revision": "1509", "browserVersion": "146.0.1"
        }]}))
        self.archive = self.root / "fixture.zip"
        self.members = {"firefox/": b"", "firefox/firefox": b"mock executable"}
        entries, expanded, roots = make_archive(self.archive, self.members)
        self.spec = {
            "revision": "1509", "browserVersion": "146.0.1",
            "url": "https://cdn.playwright.dev/dbazure/download/playwright/builds/firefox/1509/firefox-ubuntu-24.04.zip",
            "bytes": self.archive.stat().st_size,
            "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "entries": entries, "expandedBytes": expanded,
            "roots": sorted(roots), "executable": "firefox/firefox",
        }
        self.lock = {"schemaVersion": 1, "product": "playwright", "platform": "ubuntu24.04-x64",
                     "playwrightCoreVersion": "1.58.2", "engines": {"firefox": self.spec}}

    def _run(self, spec: dict | None = None, fake_archive: Path | None = None) -> None:
        selected = spec or self.spec
        lock = {**self.lock, "engines": {"firefox": selected}}
        real_run = subprocess.run

        def run(command, **kwargs):
            if command[0] == "curl":
                target = Path(command[command.index("--output") + 1])
                target.write_bytes((fake_archive or self.archive).read_bytes())
                return subprocess.CompletedProcess(command, 0)
            return real_run(command, **kwargs)

        with patch.object(installer.platform, "system", return_value="Linux"), \
             patch.object(installer.platform, "machine", return_value="x86_64"), \
             patch.object(installer, "_load_lock", return_value=lock), \
             patch.object(installer, "_verify_playwright"), \
             patch.object(installer.shutil, "which", return_value="/usr/bin/tool"), \
             patch.object(installer.subprocess, "run", side_effect=run):
            installer.install(self.cache, self.playwright, ["firefox"])

    def test_installs_verified_archive_into_playwright_cache_layout(self) -> None:
        self._run()
        installed = self.cache / "firefox-1509"
        self.assertEqual((installed / "firefox/firefox").read_bytes(), b"mock executable")
        self.assertTrue((installed / "INSTALLATION_COMPLETE").is_file())
        record = json.loads((installed / "decomp-browser-lock.json").read_text())
        self.assertEqual((record["engine"], record["revision"], record["sha256"]),
                         ("firefox", "1509", self.spec["sha256"]))
        self.assertTrue((installed / "firefox/firefox").stat().st_mode & 0o111)

    def test_rejects_digest_mismatch_before_install(self) -> None:
        bad = {**self.spec, "sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "size/SHA-256 lock"):
            self._run(bad)
        self.assertFalse((self.cache / "firefox-1509").exists())

    def test_rejects_path_traversal_before_extraction(self) -> None:
        evil = self.root / "evil.zip"
        entries, expanded, roots = make_archive(evil, {"../escape": b"no", "firefox/firefox": b"x"})
        spec = {**self.spec, "bytes": evil.stat().st_size,
                "sha256": hashlib.sha256(evil.read_bytes()).hexdigest(),
                "entries": entries, "expandedBytes": expanded, "roots": sorted(roots)}
        with self.assertRaisesRegex(ValueError, "archive path"):
            self._run(spec, evil)
        self.assertFalse((self.root / "escape").exists())
        self.assertFalse((self.cache / "firefox-1509").exists())

    def test_rejects_symlink_members(self) -> None:
        evil = self.root / "symlink.zip"
        entries, expanded, roots = make_archive(evil, {
            "firefox/": b"", "firefox/firefox": b"mock executable",
            "firefox/lib/": b"", "firefox/lib/escape": SymlinkTarget("../../outside"),
        })
        spec = {**self.spec, "bytes": evil.stat().st_size,
                "sha256": hashlib.sha256(evil.read_bytes()).hexdigest(),
                "entries": entries, "expandedBytes": expanded, "roots": sorted(roots),
                "symlinks": [{"path": "firefox/lib/escape", "target": "../../outside"}]}
        with self.assertRaisesRegex(ValueError, "safe relative path"):
            self._run(spec, evil)
        self.assertFalse((self.cache / "firefox-1509").exists())

    def test_installs_only_locked_internal_symlinks(self) -> None:
        linked = self.root / "linked.zip"
        entries, expanded, roots = make_archive(linked, {
            "firefox/": b"", "firefox/firefox": b"mock executable",
            "firefox/lib/": b"", "firefox/lib/libfixture.so": SymlinkTarget("libfixture.so.1"),
            "firefox/lib/libfixture.so.1": b"library bytes",
        })
        link_record = {"path": "firefox/lib/libfixture.so", "target": "libfixture.so.1"}
        spec = {**self.spec, "bytes": linked.stat().st_size,
                "sha256": hashlib.sha256(linked.read_bytes()).hexdigest(),
                "entries": entries, "expandedBytes": expanded, "roots": sorted(roots),
                "symlinks": [link_record]}
        self._run(spec, linked)
        installed = self.cache / "firefox-1509/firefox/lib/libfixture.so"
        self.assertTrue(installed.is_symlink())
        self.assertEqual(installed.readlink().as_posix(), "libfixture.so.1")
        self.assertEqual(installed.read_bytes(), b"library bytes")

    def test_rejects_existing_revision_directory(self) -> None:
        (self.cache / "firefox-1509").mkdir()
        with self.assertRaisesRegex(ValueError, "Refusing to replace"):
            self._run()

    def test_playwright_metadata_must_match_lock(self) -> None:
        (self.playwright / "browsers.json").write_text(json.dumps({"browsers": [{
            "name": "firefox", "revision": "1510", "browserVersion": "146.0.1"
        }]}))
        with self.assertRaisesRegex(ValueError, "metadata differs"):
            installer._verify_playwright(self.playwright, self.lock, ["firefox"])


if __name__ == "__main__":
    # Temporary test fixtures are created under the repository build directory.
    (Path.cwd() / "build").mkdir(exist_ok=True)
    unittest.main(verbosity=2)
