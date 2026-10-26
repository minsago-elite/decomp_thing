"""Synthetic-distribution checks for scripts/release-artifacts.py; no Gradle build is needed."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_artifacts", REPOSITORY_ROOT / "scripts/release-artifacts.py")
release = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(release)

VERSION = "9.9.9"
ROOT = f"llm_bin_patch-{VERSION}/"


def application_jar(asset: bytes = b"console.log('ui')\n", tamper: bool = False, extra: bool = False) -> bytes:
    files = [{"path": "assets/index-A.js", "mediaType": "text/javascript; charset=utf-8", "sizeBytes": len(asset),
              "sha256": hashlib.sha256(asset).hexdigest(), "public": True}]
    payload = {"schemaVersion": 1, "applicationVersion": VERSION, "entryScript": "assets/index-A.js",
               "entryStyles": [], "files": files}
    build_id = hashlib.sha256((json.dumps(payload, separators=(",", ":")) + "\n").encode()).hexdigest()
    manifest = json.dumps({**payload, "buildId": build_id}, indent=2).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as jar:
        jar.writestr("decompengine/Main.class", b"\xca\xfe\xba\xbe")
        jar.writestr("decompengine/web/ui/asset-manifest.json", manifest)
        jar.writestr("decompengine/web/ui/assets/index-A.js", asset + (b"//changed" if tamper else b""))
        if extra:
            jar.writestr("decompengine/web/ui/assets/stale.js", b"old")
    return buffer.getvalue()


def members(**jar_options) -> dict[str, tuple[bytes, int]]:
    launcher = (f"#!/bin/sh\nCLASSPATH=$APP_HOME/lib/llm-bin-patch-{VERSION}.jar:$APP_HOME/lib/dep-1.0.jar\n").encode()
    return {
        "bin/llm_bin_patch": (launcher, 0o755),
        f"lib/llm-bin-patch-{VERSION}.jar": (application_jar(**jar_options), 0o644),
        "lib/dep-1.0.jar": (b"dependency", 0o644),
        "libexec/decomp-acp-gate-helper": (b"\x7fELF helper", 0o755),
        "libexec/ghidra/bundle.sha256": (b"0" * 64 + "  x\n".encode(), 0o644),
        "docs/frontend-THIRD_PARTY_NOTICES.txt": (b"Notices\n\nPreact 10.0.0\nMIT\n", 0o644),
    }


def write_distributions(directory: Path, zip_members: dict, tar_members: dict | None = None) -> None:
    directory.mkdir(parents=True)
    with zipfile.ZipFile(directory / f"llm_bin_patch-{VERSION}.zip", "w") as archive:
        for name, (data, mode) in zip_members.items():
            info = zipfile.ZipInfo(ROOT + name)
            info.external_attr = (0o100000 | mode) << 16
            archive.writestr(info, data)
    with tarfile.open(directory / f"llm_bin_patch-{VERSION}.tar", "w") as archive:
        for name, (data, mode) in (tar_members or zip_members).items():
            info = tarfile.TarInfo(ROOT + name)
            info.size, info.mode = len(data), mode
            archive.addfile(info, io.BytesIO(data))


class ReleaseArtifactsTest(unittest.TestCase):
    def setUp(self) -> None:
        (REPOSITORY_ROOT / "build").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="release-artifacts-", dir=REPOSITORY_ROOT / "build")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lockfile = self.root / "package-lock.json"
        self.lockfile.write_text(json.dumps({"packages": {
            "": {"name": "workbench"},
            "node_modules/preact": {"version": "10.0.0", "license": "MIT", "integrity": "sha512-x", "resolved": "https://registry.example/preact.tgz"},
            "node_modules/vite": {"version": "1.0.0", "dev": True},
        }}))
        self.composition = self.root / "bundle-composition.json"
        self.composition.write_text(json.dumps([{"chunk": "a.js", "owner": "application"}, {"chunk": "a.js", "owner": "preact"}]))

    def assemble(self, zip_members: dict, tar_members: dict | None = None) -> Path:
        self.assembled = getattr(self, "assembled", 0) + 1
        distributions = self.root / f"distributions-{self.assembled}"
        write_distributions(distributions, zip_members, tar_members)
        return release.assemble(distributions, self.root / "release", self.lockfile, self.composition)

    def test_assembled_release_verifies_against_archive_bytes(self) -> None:
        output = self.assemble(members())
        summary = release.verify(output, self.lockfile)
        self.assertEqual(6, summary["verifiedFiles"])
        record = json.loads((output / "release-record.json").read_text())
        jar = members()[f"lib/llm-bin-patch-{VERSION}.jar"][0]
        self.assertEqual(hashlib.sha256(jar).hexdigest(), record["applicationBuildId"])
        dependencies = json.loads((output / "frontend-dependencies.json").read_text())
        self.assertEqual(["preact"], [package["name"] for package in dependencies["packages"]])
        self.assertTrue(dependencies["packages"][0]["browserModules"])
        sums = (output / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(sorted(path.name for path in output.iterdir() if path.name != "SHA256SUMS"),
                         [line.split("  ", 1)[1] for line in sums])

    def test_changed_archive_or_unlisted_file_fails_verification(self) -> None:
        output = self.assemble(members())
        archive = output / f"llm_bin_patch-{VERSION}.tar"
        data = bytearray(archive.read_bytes())
        data[-1] ^= 1
        archive.write_bytes(bytes(data))
        with self.assertRaisesRegex(release.ReleaseError, "SHA256SUMS"):
            release.verify(output, None)
        output = self.assemble(members())
        (output / "unlisted.txt").write_text("x")
        with self.assertRaisesRegex(release.ReleaseError, "disagree"):
            release.verify(output, None)

    def test_inventory_is_checked_against_actual_members_even_with_matching_sums(self) -> None:
        output = self.assemble(members())
        inventory = json.loads((output / "release-inventory.json").read_text())
        inventory["files"][0]["sha256"] = "0" * 64
        (output / "release-inventory.json").write_text(json.dumps(inventory))
        release.write_checksums(output)
        with self.assertRaisesRegex(release.ReleaseError, "differs from the inventory"):
            release.verify(output, None)

    def test_zip_and_tar_must_ship_identical_bytes_and_modes(self) -> None:
        changed = members()
        changed["lib/dep-1.0.jar"] = (b"other", 0o644)
        with self.assertRaisesRegex(release.ReleaseError, "ZIP and TAR"):
            self.assemble(members(), changed)
        mode = members()
        mode["libexec/decomp-acp-gate-helper"] = (mode["libexec/decomp-acp-gate-helper"][0], 0o644)
        with self.assertRaisesRegex(release.ReleaseError, "ZIP and TAR"):
            self.assemble(members(), mode)

    def test_embedded_ui_resources_must_match_their_manifest(self) -> None:
        with self.assertRaisesRegex(release.ReleaseError, "differs from the embedded manifest"):
            self.assemble(members(tamper=True))
        with self.assertRaisesRegex(release.ReleaseError, "unlisted UI resources"):
            self.assemble(members(extra=True))

    def test_class_path_notices_and_lockfile_closure_are_enforced(self) -> None:
        orphan = members()
        orphan["lib/orphan-1.0.jar"] = (b"x", 0o644)
        with self.assertRaisesRegex(release.ReleaseError, "outside the launcher class path"):
            self.assemble(orphan)
        missing = members()
        missing["docs/frontend-THIRD_PARTY_NOTICES.txt"] = (b"Notices\n", 0o644)
        with self.assertRaisesRegex(release.ReleaseError, "notices omit preact"):
            self.assemble(missing)
        output = self.assemble(members())
        lock = json.loads(self.lockfile.read_text())
        lock["packages"]["node_modules/preact"]["version"] = "10.0.1"
        self.lockfile.write_text(json.dumps(lock))
        with self.assertRaisesRegex(release.ReleaseError, "package-lock"):
            release.verify(output, self.lockfile)
        self.composition.write_text(json.dumps([{"chunk": "a.js", "owner": "left-pad"}]))
        with self.assertRaisesRegex(release.ReleaseError, "outside the locked runtime set"):
            release.frontend_dependencies(self.lockfile, self.composition)


if __name__ == "__main__":
    unittest.main()
