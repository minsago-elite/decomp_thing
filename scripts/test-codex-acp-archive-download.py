#!/usr/bin/env python3
"""Exercise the real acquisition shell with inert bytes and a fake curl; no network or agent."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parent.parent
ARCHIVE = "codex-acp-0.16.0-x86_64-unknown-linux-gnu.tar.gz"
DIGEST = "0a9ad6c31ec9b2b87dccb7e9da3faf5d387e74470d24dbced75a160ed7b22d06"
FIXTURE = b"inert archive acquisition fixture"


class CodexArchiveDownloadTest(unittest.TestCase):
    def setUp(self):
        (REPOSITORY / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="codex-acp-acquisition-", dir=REPOSITORY / "build")
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        self.script = self.root / "scripts/ci-qualify-codex-acp.sh"
        source = (REPOSITORY / "scripts/ci-qualify-codex-acp.sh").read_text()
        self.assertEqual(1, source.count(f'CODEX_ACP_ARCHIVE_SHA256="{DIGEST}"'))
        self.assertEqual(1, source.count('CODEX_ACP_ARCHIVE_BYTES="74262216"'))
        self.script.write_text(source.replace(DIGEST, hashlib.sha256(FIXTURE).hexdigest())
                               .replace('CODEX_ACP_ARCHIVE_BYTES="74262216"', f'CODEX_ACP_ARCHIVE_BYTES="{len(FIXTURE)}"'))
        self.cache = self.root / "build/acp-codex-compatibility/download-cache" / ARCHIVE
        self.bin = self.root / "bin"
        self.bin.mkdir()
        curl = self.bin / "curl"
        curl.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ["CODEX_ACP_DOWNLOAD_TEST_ROOT"])
calls = root / "calls.jsonl"
index = len(calls.read_text().splitlines()) if calls.exists() else 0
with calls.open("a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
plan = json.loads((root / "plan.json").read_text())
if index >= len(plan):
    sys.exit(98)
item = plan[index]
Path(sys.argv[sys.argv.index("--output") + 1]).write_bytes(bytes.fromhex(item.get("hex", "")))
if "publish" in item:
    cache = root / "build/acp-codex-compatibility/download-cache/codex-acp-0.16.0-x86_64-unknown-linux-gnu.tar.gz"
    cache.write_bytes(bytes.fromhex(item["publish"]))
    (root / "published-inode").write_text(str(cache.stat().st_ino))
if "publishKind" in item:
    cache = root / "build/acp-codex-compatibility/download-cache/codex-acp-0.16.0-x86_64-unknown-linux-gnu.tar.gz"
    target = root / "retained-publication"
    target.mkdir()
    if item["publishKind"] == "directory":
        cache.mkdir()
    else:
        cache.symlink_to(target, target_is_directory=True)
    (root / "published-inode").write_text(str(cache.lstat().st_ino))
sys.exit(item.get("exit", 0))
''')
        curl.chmod(0o700)
        forbidden = '#!/bin/sh\nprintf invoked >"$CODEX_ACP_DOWNLOAD_TEST_ROOT/unexpected-runtime"\nexit 97\n'
        (self.root / "gradlew").write_text(forbidden)
        (self.root / "gradlew").chmod(0o700)
        for name in ("java", "javac", "gzip", "ldd", "tar"):
            tool = self.bin / name
            tool.write_text(forbidden)
            tool.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def run_plan(self, plan, success=True):
        (self.root / "plan.json").write_text(json.dumps(plan))
        calls = self.root / "calls.jsonl"
        calls.unlink(missing_ok=True)
        result = subprocess.run(["bash", str(self.script), "--fetch-archive"], cwd=self.root,
                                env={**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                                     "CODEX_ACP_DOWNLOAD_TEST_ROOT": str(self.root)},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        self.assertFalse((self.root / "unexpected-runtime").exists())
        self.assertEqual([], list((self.root / "build/acp-codex-compatibility/work").iterdir()))
        self.assertEqual([], list((self.root / "build/acp-codex-compatibility/results").iterdir()))
        return [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []

    def test_primary_http_refusal_uses_only_the_official_pinned_fallback_and_bounds(self):
        calls = self.run_plan([{"exit": 22, "hex": b"partial".hex()}, {"hex": FIXTURE.hex()}])
        self.assertEqual(2, len(calls))
        self.assertEqual("https://github.com/zed-industries/codex-acp/releases/download/v0.16.0/" + ARCHIVE, calls[0][-1])
        self.assertEqual("https://api.github.com/repos/zed-industries/codex-acp/releases/assets/441865401", calls[1][-1])
        for call in calls:
            for flag, value in (("--connect-timeout", "15"), ("--max-time", "120"),
                                ("--max-redirs", "3"), ("--retry", "0"),
                                ("--max-filesize", str(len(FIXTURE))), ("--proto", "=https"),
                                ("--proto-redir", "=https"), ("--header", "Accept: application/octet-stream")):
                self.assertEqual(value, call[call.index(flag) + 1])
        self.assertEqual(FIXTURE, self.cache.read_bytes())

    def test_all_endpoints_refuse_without_cache_or_runtime_execution(self):
        calls = self.run_plan([{"exit": 22}, {"exit": 22}], success=False)
        self.assertEqual(2, len(calls))
        self.assertFalse(self.cache.exists())

    def test_successful_but_corrupt_truncated_or_oversized_download_is_terminal(self):
        for payload in (b"x" * len(FIXTURE), FIXTURE[:-1], FIXTURE + b"x"):
            with self.subTest(payload=payload):
                calls = self.run_plan([{"hex": payload.hex()}], success=False)
                self.assertEqual(1, len(calls))
                self.assertFalse(self.cache.exists())

    def test_verified_cache_reuse_does_not_contact_any_endpoint(self):
        self.cache.parent.mkdir(parents=True)
        self.cache.write_bytes(FIXTURE)
        inode = self.cache.stat().st_ino
        self.assertEqual([], self.run_plan([]))
        self.assertEqual(FIXTURE, self.cache.read_bytes())
        self.assertEqual(inode, self.cache.stat().st_ino)

    def test_corrupt_cache_refuses_without_repair_or_download(self):
        self.cache.parent.mkdir(parents=True)
        for payload in (b"x" * len(FIXTURE), FIXTURE[:-1], FIXTURE + b"x"):
            with self.subTest(payload=payload):
                self.cache.write_bytes(payload)
                self.assertEqual([], self.run_plan([], success=False))
                self.assertEqual(payload, self.cache.read_bytes())

    def test_linked_cache_file_or_directory_is_not_followed(self):
        target = self.root / "retained"
        target.mkdir()
        (target / ARCHIVE).write_bytes(FIXTURE)
        self.cache.parent.mkdir(parents=True)
        self.cache.symlink_to(target / ARCHIVE)
        self.assertEqual([], self.run_plan([], success=False))
        self.cache.unlink()
        self.cache.parent.rmdir()
        self.cache.parent.symlink_to(target, target_is_directory=True)
        self.assertEqual([], self.run_plan([], success=False))
        self.assertEqual(FIXTURE, (target / ARCHIVE).read_bytes())

    def test_atomic_publication_never_replaces_an_existing_entry(self):
        for payload, success in ((FIXTURE, True), (b"x" * len(FIXTURE), False)):
            with self.subTest(success=success):
                calls = self.run_plan([{"hex": FIXTURE.hex(), "publish": payload.hex()}], success=success)
                self.assertEqual(1, len(calls))
                self.assertEqual(payload, self.cache.read_bytes())
                self.assertEqual(int((self.root / "published-inode").read_text()), self.cache.stat().st_ino)
                self.cache.unlink()

    def test_atomic_publication_refuses_directory_and_link_destinations(self):
        for kind in ("directory", "linked-directory"):
            with self.subTest(kind=kind):
                calls = self.run_plan([{"hex": FIXTURE.hex(), "publishKind": kind}], success=False)
                self.assertEqual(1, len(calls))
                self.assertEqual(int((self.root / "published-inode").read_text()), self.cache.lstat().st_ino)
                self.assertEqual([], list((self.root / "retained-publication").iterdir()))
                if self.cache.is_symlink():
                    self.cache.unlink()
                else:
                    self.assertEqual([], list(self.cache.iterdir()))
                    self.cache.rmdir()
                (self.root / "retained-publication").rmdir()

    def test_workflow_cache_key_keeps_the_unchanged_reviewed_content_pin(self):
        workflow = (REPOSITORY / ".github/workflows/ci.yml").read_text()
        source = (REPOSITORY / "scripts/ci-qualify-codex-acp.sh").read_text()
        self.assertIn('readonly CODEX_ACP_VERSION="0.16.0"', source)
        self.assertIn('CODEX_ACP_EXECUTABLE_SHA256="23a9f2af247fc61aa9a895d5ee91a62a35d05a883bddc2c85d1dc6b2be697087"', source)
        self.assertIn('CODEX_ACP_BUNDLED_BWRAP_SHA256="5a5104807cfbe9b509d0b9fa1c46054ff48dbed5393f30d261b34263ebf0e3fe"', source)
        self.assertIn('readonly CODEX_ACP_ARCHIVE_BYTES="74262216"', source)
        self.assertIn(f'CODEX_ACP_ARCHIVE_SHA256="{DIGEST}"', source)
        self.assertIn("key: codex-acp-archive-v1-${{ runner.os }}-${{ runner.arch }}-" + DIGEST, workflow)
        self.assertIn("path: ${{ github.workspace }}/build/acp-codex-compatibility/download-cache/" + ARCHIVE, workflow)


if __name__ == "__main__":
    unittest.main()
