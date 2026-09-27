#!/usr/bin/env python3
"""Install the reviewed test-only Chrome archive into a fresh directory.

The lock records bytes fetched from the version-specific official HTTPS URL;
its SHA-256 is our reviewed content lock, not an upstream signature. No browser
or browser dependency is added to the application distribution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import subprocess
import tempfile
import zipfile


def install(destination: Path) -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("The pinned web test browser supports Linux x86-64 hosts")
    if not destination.is_absolute() or destination.name in ("", ".", ".."):
        raise ValueError("Use an absolute, absent browser install directory")
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("The install directory must be absent and its parent must already exist")
    for tool in ("curl", "mv"):
        if shutil.which(tool) is None:
            raise ValueError(f"Browser installation requires {tool}")
    lock = json.loads(Path(__file__).with_name("web-test-browser.json").read_text())
    if (lock["schemaVersion"], lock["product"], lock["platform"]) != (1, "chrome", "linux64"):
        raise ValueError("Unsupported web test browser lock")
    expected_url = ("https://storage.googleapis.com/chrome-for-testing-public/"
                    f"{lock['version']}/linux64/chrome-linux64.zip")
    if lock["url"] != expected_url:
        raise ValueError("Browser URL must identify the pinned official version")
    required = lock["bytes"] + lock["expandedBytes"] + 32 * 1024 * 1024
    if shutil.disk_usage(destination.parent).free < required:
        raise ValueError(f"Browser installation needs at least {required} free bytes")
    with tempfile.TemporaryDirectory(prefix=".decomp-web-test-browser-", dir=destination.parent) as scratch:
        stage = Path(scratch)
        archive = stage / "chrome-linux64.zip"
        subprocess.run([
            "curl", "--fail", "--silent", "--show-error", "--location",
            "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
            "--connect-timeout", "15", "--max-time", "180",
            "--max-filesize", str(lock["bytes"]), lock["url"], "--output", str(archive),
        ], check=True, timeout=190)
        with archive.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if archive.stat().st_size != lock["bytes"] or digest != lock["sha256"]:
            raise ValueError("Browser archive differs from the reviewed size/SHA-256 lock")
        with zipfile.ZipFile(archive) as container:
            entries = container.infolist()
            if (len(entries) != lock["entries"] or
                    sum(entry.file_size for entry in entries) != lock["expandedBytes"] or
                    len({entry.filename for entry in entries}) != len(entries)):
                raise ValueError("Browser archive inventory differs from its lock")
            for entry in entries:
                relative = PurePosixPath(entry.filename)
                mode = entry.external_attr >> 16
                if (relative.is_absolute() or not relative.parts or relative.parts[0] != "chrome-linux64" or
                        any(part in (".", "..") for part in relative.parts) or "\\" in entry.filename or
                        stat.S_ISLNK(mode)):
                    raise ValueError("Unexpected browser archive member")
                target = stage.joinpath(*relative.parts)
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with container.open(entry) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output, 64 * 1024)
                    target.chmod(0o644 | (mode & 0o111))
        extracted = stage / "chrome-linux64"
        # Installation does not execute the browser. Ubuntu CI installs the
        # reviewed archive's deb.deps before browser use.
        (extracted / "decomp-browser-lock.json").write_text(json.dumps(lock, indent=2) + "\n")
        subprocess.run(["mv", "-T", "--no-clobber", "--", str(extracted), str(destination)], check=True)
        if extracted.exists():
            raise ValueError("Browser destination appeared during installation; existing state was preserved")
    print(f"Installed test-only Chrome {lock['version']} at {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    try:
        install(arguments.destination)
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as failure:
        parser.exit(1, f"Browser installation failed: {failure}\n")
