#!/usr/bin/env python3
"""Install hash-locked Firefox/WebKit builds into a fresh Playwright cache.

The SHA-256 values pin bytes downloaded from Playwright's official HTTPS CDN;
they are reviewed content locks, not upstream signatures. This installs only
the browser archives. Playwright, Ubuntu dependencies, and the test application
remain separate parts of the browser-engine workflow.
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


LOCK_PATH = Path(__file__).with_name("web-test-browser-engines.json")
MAX_ARCHIVE_SECONDS = 240


def _load_lock() -> dict:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    if (lock.get("schemaVersion"), lock.get("product"), lock.get("platform")) != (
        1, "playwright", "ubuntu24.04-x64"
    ):
        raise ValueError("Unsupported Playwright browser lock")
    if lock.get("playwrightCoreVersion") != "1.58.2":
        raise ValueError("Unsupported Playwright core version in browser lock")
    if lock.get("metadataUrl") != (
        "https://raw.githubusercontent.com/microsoft/playwright/v1.58.2/"
        "packages/playwright-core/browsers.json"
    ):
        raise ValueError("Unexpected Playwright browser metadata source")
    return lock


def _verify_playwright(playwright_root: Path, lock: dict, requested: list[str]) -> None:
    package = json.loads((playwright_root / "package.json").read_text(encoding="utf-8"))
    registry = json.loads((playwright_root / "browsers.json").read_text(encoding="utf-8"))
    if package.get("version") != lock["playwrightCoreVersion"]:
        raise ValueError("Installed playwright-core version differs from the browser lock")
    registry_browsers = {item["name"]: item for item in registry.get("browsers", [])}
    for name in requested:
        pinned = lock["engines"].get(name)
        descriptor = registry_browsers.get(name)
        if pinned is None or descriptor is None:
            raise ValueError(f"Unsupported or unpinned browser engine: {name}")
        revision = (descriptor.get("revisionOverrides") or {}).get(lock["platform"], descriptor.get("revision"))
        if revision != pinned["revision"] or descriptor.get("browserVersion") != pinned["browserVersion"]:
            raise ValueError(f"Playwright {name} metadata differs from its browser lock")


def _validate_archive(container: zipfile.ZipFile, spec: dict) -> tuple[list[zipfile.ZipInfo], dict[str, str]]:
    entries = container.infolist()
    names: set[str] = set()
    roots: set[str] = set()
    file_names: set[str] = set()
    symlinks: dict[str, str] = {}
    expanded = 0
    allowed_roots = set(spec["roots"])
    for entry in entries:
        raw = entry.filename
        path = PurePosixPath(raw)
        parts = raw.rstrip("/").split("/")
        mode = entry.external_attr >> 16
        file_type = stat.S_IFMT(mode)
        if (not raw or raw.startswith("/") or "\\" in raw or "\x00" in raw or
                any(part in ("", ".", "..") for part in parts) or
                path.is_absolute() or path.parts[0] not in allowed_roots):
            raise ValueError("Unexpected Playwright browser archive path")
        if raw in names:
            raise ValueError("Playwright browser archive contains duplicate paths")
        names.add(raw)
        roots.add(path.parts[0])
        if path.name in ("INSTALLATION_COMPLETE", "decomp-browser-lock.json"):
            raise ValueError("Playwright archive may not supply installer-owned metadata")
        if file_type not in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK):
            raise ValueError("Playwright browser archive contains a special file")
        if file_type == stat.S_IFLNK and entry.is_dir():
            raise ValueError("Playwright browser archive symlink has a directory name")
        if entry.is_dir() != (file_type == stat.S_IFDIR) and file_type != 0:
            raise ValueError("Playwright browser archive has inconsistent member types")
        if entry.file_size < 0:
            raise ValueError("Playwright browser archive has an invalid member size")
        if file_type == stat.S_IFLNK:
            try:
                target = container.read(entry).decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise ValueError("Playwright browser archive link target is not UTF-8") from error
            target_path = PurePosixPath(target)
            target_parts = target.split("/")
            if (not target or target_path.is_absolute() or "\\" in target or "\x00" in target or
                    any(part in ("", ".", "..") for part in target_parts)):
                raise ValueError("Playwright browser archive symlink target is not a safe relative path")
            resolved_target = path.parent.joinpath(*target_path.parts).as_posix()
            if PurePosixPath(resolved_target).parts[0] != path.parts[0]:
                raise ValueError("Playwright browser archive symlink leaves its archive tree")
            symlinks[raw] = target
        elif not entry.is_dir():
            file_names.add(raw)
        expanded += entry.file_size
    for link_path, target in symlinks.items():
        target_path = PurePosixPath(link_path).parent.joinpath(*PurePosixPath(target).parts).as_posix()
        if target_path not in file_names:
            raise ValueError("Playwright browser archive symlink target is not a regular archive file")
        if any(name.startswith(link_path + "/") for name in names):
            raise ValueError("Playwright browser archive uses a symlink as a parent directory")
    expected_link_list = spec.get("symlinks", [])
    expected_links = {item["path"]: item["target"] for item in expected_link_list}
    if len(expected_links) != len(expected_link_list):
        raise ValueError("Browser lock contains duplicate symlink paths")
    if symlinks != expected_links:
        raise ValueError("Playwright browser archive symlink inventory differs from its lock")
    if (len(entries) != spec["entries"] or expanded != spec["expandedBytes"] or
            roots != allowed_roots):
        raise ValueError("Playwright browser archive inventory differs from its lock")
    return entries, symlinks


def _extract_verified(
    container: zipfile.ZipFile,
    entries: list[zipfile.ZipInfo],
    symlinks: dict[str, str],
    destination: Path,
) -> None:
    for entry in entries:
        path = PurePosixPath(entry.filename)
        target = destination.joinpath(*path.parts)
        if entry.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(0o755)
            continue
        mode = entry.external_attr >> 16
        if stat.S_IFMT(mode) == stat.S_IFLNK:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with container.open(entry) as source, target.open("xb") as output:
            shutil.copyfileobj(source, output, 64 * 1024)
        target.chmod(0o644 | (mode & 0o111))
    for link_path, link_target in symlinks.items():
        link = destination.joinpath(*PurePosixPath(link_path).parts)
        resolved = link.parent.joinpath(*PurePosixPath(link_target).parts)
        if not resolved.is_file() or resolved.is_symlink():
            raise ValueError("Validated Playwright symlink target is absent after extraction")
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(link_target)


def install(browsers_path: Path, playwright_root: Path, requested: list[str]) -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Pinned Playwright browser archives support Linux x86-64 only")
    if not browsers_path.is_absolute() or browsers_path.name in ("", ".", ".."):
        raise ValueError("Use an absolute Playwright browsers path")
    if not browsers_path.is_dir() or browsers_path.is_symlink():
        raise ValueError("Playwright browsers path must be an existing real directory")
    if not playwright_root.is_absolute() or not playwright_root.is_dir() or playwright_root.is_symlink():
        raise ValueError("Use the absolute installed playwright-core package directory")
    if not requested or len(requested) != len(set(requested)):
        raise ValueError("Select one or more distinct browser engines")
    for tool in ("curl", "mv"):
        if shutil.which(tool) is None:
            raise ValueError(f"Playwright browser installation requires {tool}")

    lock = _load_lock()
    _verify_playwright(playwright_root, lock, requested)
    specs = lock["engines"]
    destinations: dict[str, Path] = {}
    for name in requested:
        spec = specs[name]
        if name not in ("firefox", "webkit"):
            raise ValueError(f"Unsupported browser engine: {name}")
        expected_url = (
            "https://cdn.playwright.dev/dbazure/download/playwright/builds/"
            f"{name}/{spec['revision']}/{name}-ubuntu-24.04.zip"
        )
        if spec.get("url") != expected_url:
            raise ValueError(f"Unexpected official archive URL for {name}")
        if len(spec.get("sha256", "")) != 64 or any(c not in "0123456789abcdef" for c in spec["sha256"]):
            raise ValueError(f"Invalid SHA-256 in browser lock for {name}")
        destination = browsers_path / f"{name}-{spec['revision']}"
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"Refusing to replace existing Playwright browser directory: {destination}")
        destinations[name] = destination

    required = sum(specs[name]["bytes"] + specs[name]["expandedBytes"] for name in requested) + 32 * 1024 * 1024
    if shutil.disk_usage(browsers_path).free < required:
        raise ValueError(f"Playwright browser installation needs at least {required} free bytes")

    for name in requested:
        spec = specs[name]
        destination = destinations[name]
        with tempfile.TemporaryDirectory(prefix=f".decomp-pw-{name}-", dir=browsers_path) as scratch:
            stage = Path(scratch)
            archive = stage / f"{name}-{spec['revision']}.zip"
            subprocess.run([
                "curl", "--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
                "--connect-timeout", "15", "--max-time", str(MAX_ARCHIVE_SECONDS),
                "--max-filesize", str(spec["bytes"]), spec["url"], "--output", str(archive),
            ], check=True, timeout=MAX_ARCHIVE_SECONDS + 10)
            with archive.open("rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            if archive.stat().st_size != spec["bytes"] or digest != spec["sha256"]:
                raise ValueError(f"{name} archive differs from the reviewed size/SHA-256 lock")
            with zipfile.ZipFile(archive) as container:
                entries, symlinks = _validate_archive(container, spec)
                extracted = stage / f"{name}-{spec['revision']}"
                extracted.mkdir()
                _extract_verified(container, entries, symlinks, extracted)
            executable = extracted.joinpath(*PurePosixPath(spec["executable"]).parts)
            if not executable.is_file() or executable.is_symlink():
                raise ValueError(f"Pinned {name} executable is missing from its archive")
            executable.chmod(executable.stat().st_mode | 0o111)
            (extracted / "decomp-browser-lock.json").write_text(
                json.dumps({"playwrightCoreVersion": lock["playwrightCoreVersion"], "engine": name, **spec}, indent=2) + "\n",
                encoding="utf-8",
            )
            (extracted / "INSTALLATION_COMPLETE").write_text("", encoding="ascii")
            subprocess.run(["mv", "-T", "--no-clobber", "--", str(extracted), str(destination)], check=True)
            if extracted.exists():
                raise ValueError(f"Playwright browser destination appeared during installation: {destination}")
        print(f"Installed hash-locked Playwright {name} {spec['browserVersion']} at {destination}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("browsers_path", type=Path)
    parser.add_argument("--playwright-core", required=True, type=Path)
    parser.add_argument("engines", nargs="+")
    args = parser.parse_args()
    try:
        install(args.browsers_path, args.playwright_core, args.engines)
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile, KeyError) as failure:
        parser.exit(1, f"Playwright browser installation failed: {failure}\n")


if __name__ == "__main__":
    main()
