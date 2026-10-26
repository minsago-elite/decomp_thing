#!/usr/bin/env python3
"""Assemble and verify a release directory from the built ZIP/TAR distributions.

`assemble` reads build/distributions/llm_bin_patch-<version>.{zip,tar}, requires both
archives to ship identical bytes and modes, and writes build/release/llm_bin_patch-<version>/:

  llm_bin_patch-<version>.zip / .tar   the shipped archives, copied byte for byte
  release-inventory.json               every shipped file: path, size, SHA-256, mode, role
  ui-manifest.json                     the embedded UI manifest read from the application JAR
  frontend-dependencies.json           non-development packages pinned in frontend/package-lock.json
  frontend-THIRD_PARTY_NOTICES.txt     the notices file shipped in the distribution
  release-record.json                  source revision, application/UI build IDs, archive digests
  SHA256SUMS                           sha256sum(1) lines for every file above

`verify` recomputes everything from the copied archives' actual bytes: every SHA256SUMS line,
every inventory entry in both archives, every UI manifest entry inside the application JAR,
the launcher class path, notices coverage and (optionally) the lockfile pins. It never trusts
the records it is checking. Python is a release driver only; nothing here runs the application.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile

REPOSITORY = Path(__file__).resolve().parent.parent
NAME = "llm_bin_patch"
UI_PREFIX = "decompengine/web/ui/"
NOTICES = "docs/frontend-THIRD_PARTY_NOTICES.txt"
MAX_MEMBER_BYTES = 1 << 31


class ReleaseError(Exception):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class Member:
    """One shipped file: its size, digest and mode, plus the bytes of the few members checked inside."""

    def __init__(self, size: int, digest: str, mode: int, data: bytes | None) -> None:
        self.size, self.digest, self.mode, self.data = size, digest, mode, data

    def same(self, other: "Member") -> bool:
        return (self.size, self.digest, self.mode) == (other.size, other.digest, other.mode)


def kept(name: str) -> bool:
    """Members whose contents are inspected: launchers, the application JAR and the shipped notices."""
    relative = name.split("/", 1)[-1]
    return relative == f"bin/{NAME}" or relative == NOTICES or re.fullmatch(r"lib/llm-bin-patch-[^/]+\.jar", relative) is not None


def digest_stream(stream, keep: bool) -> tuple[int, str, bytes | None]:
    digest, size, chunks = hashlib.sha256(), 0, []
    for block in iter(lambda: stream.read(1 << 20), b""):
        size += len(block)
        if size > MAX_MEMBER_BYTES:
            raise ReleaseError("a distribution member exceeds the size bound")
        digest.update(block)
        if keep:
            chunks.append(block)
    return size, digest.hexdigest(), b"".join(chunks) if keep else None


def read_zip(path: Path) -> dict[str, Member]:
    members: dict[str, Member] = {}
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            if entry.filename in members:
                raise ReleaseError(f"{path.name} repeats {entry.filename}")
            with archive.open(entry) as stream:
                size, digest, data = digest_stream(stream, kept(entry.filename))
            members[entry.filename] = Member(size, digest, (entry.external_attr >> 16) & 0o7777, data)
    return members


def read_tar(path: Path) -> dict[str, Member]:
    members: dict[str, Member] = {}
    with tarfile.open(path) as archive:
        for entry in archive:
            if entry.isdir():
                continue
            if not entry.isfile():
                raise ReleaseError(f"{path.name} contains a non-regular member {entry.name}")
            if entry.name in members:
                raise ReleaseError(f"{path.name} repeats {entry.name}")
            stream = archive.extractfile(entry)
            assert stream is not None
            size, digest, data = digest_stream(stream, kept(entry.name))
            members[entry.name] = Member(size, digest, entry.mode & 0o7777, data)
    return members


def role(relative: str, application_jar: str) -> str:
    if relative == application_jar:
        return "application-jar"
    if relative.startswith("bin/"):
        return "launcher"
    if relative.startswith("lib/") and relative.endswith(".jar"):
        return "dependency-jar"
    if relative.startswith("lib/"):
        return "runtime-reference"
    if relative.startswith("libexec/ghidra/"):
        return "bundled-ghidra"
    if relative.startswith("libexec/"):
        return "native-helper"
    if relative.startswith("docs/"):
        return "notice"
    return "resource"


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def distribution_pair(distributions: Path) -> tuple[Path, Path, str]:
    zips = sorted(distributions.glob(f"{NAME}-*.zip"))
    tars = sorted(distributions.glob(f"{NAME}-*.tar"))
    if len(zips) != 1 or len(tars) != 1:
        raise ReleaseError(f"expected one ZIP and one TAR distribution in {distributions}")
    version = zips[0].name[len(NAME) + 1:-len(".zip")]
    if tars[0].name != f"{NAME}-{version}.tar" or not re.fullmatch(r"[0-9A-Za-z.+-]{1,64}", version):
        raise ReleaseError("ZIP and TAR distributions name different versions")
    return zips[0], tars[0], version


def compare_archives(zip_members, tar_members) -> None:
    if zip_members.keys() != tar_members.keys():
        only = sorted(zip_members.keys() ^ tar_members.keys())[:5]
        raise ReleaseError(f"ZIP and TAR ship different files: {only}")
    for name, member in zip_members.items():
        if not member.same(tar_members[name]):
            raise ReleaseError(f"ZIP and TAR ship different bytes or modes for {name}")


def strip_root(members: dict[str, Member], version: str) -> dict[str, Member]:
    root = f"{NAME}-{version}/"
    if any(not name.startswith(root) for name in members):
        raise ReleaseError(f"a distribution member is outside {root}")
    return {name[len(root):]: value for name, value in members.items()}


def ui_manifest(application_jar: bytes) -> dict:
    """Checks the embedded UI closure inside the application JAR against its own manifest."""
    with zipfile.ZipFile(io.BytesIO(application_jar)) as jar:
        names = [entry.filename for entry in jar.infolist() if not entry.is_dir()]
        if len(names) != len(set(names)):
            raise ReleaseError("the application JAR repeats an entry")
        try:
            manifest_bytes = jar.read(UI_PREFIX + "asset-manifest.json")
        except KeyError as failure:
            raise ReleaseError("the application JAR omits the embedded UI manifest") from failure
        manifest = json.loads(manifest_bytes)
        payload = {key: value for key, value in manifest.items() if key != "buildId"}
        expected_build = sha256((json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n").encode())
        if manifest.get("buildId") != expected_build:
            raise ReleaseError("the embedded UI manifest build ID does not match its contents")
        listed = set()
        for item in manifest["files"]:
            entry = UI_PREFIX + item["path"]
            try:
                data = jar.read(entry)
            except KeyError as failure:
                raise ReleaseError(f"the application JAR omits UI resource {item['path']}") from failure
            if len(data) != item["sizeBytes"] or sha256(data) != item["sha256"]:
                raise ReleaseError(f"UI resource {item['path']} differs from the embedded manifest")
            listed.add(entry)
        extra = sorted(name for name in names if name.startswith(UI_PREFIX)
                       and name not in listed and name != UI_PREFIX + "asset-manifest.json")
        if extra:
            raise ReleaseError(f"the application JAR ships unlisted UI resources: {extra[:5]}")
        return manifest


def launcher_classpath(members: dict[str, Member], application_jar: str) -> list[str]:
    script = members.get(f"bin/{NAME}")
    if script is None or script.data is None:
        raise ReleaseError("the distribution omits the Unix launcher")
    lines = [line for line in script.data.decode().splitlines() if line.startswith("CLASSPATH=")]
    if len(lines) != 1:
        raise ReleaseError("the launcher does not declare exactly one class path")
    entries = [entry.removeprefix("$APP_HOME/") for entry in lines[0].removeprefix("CLASSPATH=").split(":")]
    missing = [entry for entry in entries if entry not in members]
    if missing:
        raise ReleaseError(f"the launcher class path names files the distribution omits: {missing[:5]}")
    if not entries or entries[0] != application_jar:
        raise ReleaseError("the launcher class path does not start with the application JAR")
    orphans = sorted(name for name in members if re.fullmatch(r"lib/[^/]+\.jar", name) and name not in entries)
    if orphans:
        raise ReleaseError(f"the distribution ships JARs outside the launcher class path: {orphans[:5]}")
    return entries


def frontend_dependencies(lockfile: Path, composition: Path | None) -> dict:
    lock = json.loads(lockfile.read_text())
    owners = None
    if composition is not None:
        owners = sorted({item["owner"] for item in json.loads(composition.read_text())} - {"application"})
    packages = []
    for key, value in sorted(lock["packages"].items()):
        if not key or value.get("dev"):
            continue
        name = key.removeprefix("node_modules/")
        packages.append({
            "name": name,
            "version": value["version"],
            "resolved": value.get("resolved"),
            "integrity": value.get("integrity"),
            "license": value.get("license"),
            "browserModules": None if owners is None else name in owners,
        })
    unknown = [owner for owner in owners or [] if owner not in {package["name"] for package in packages}]
    if unknown:
        raise ReleaseError(f"bundle modules come from packages outside the locked runtime set: {unknown}")
    return {"schemaVersion": 1, "lockfile": "frontend/package-lock.json",
            "lockfileSha256": file_sha256(lockfile), "browserModuleOwners": owners, "packages": packages}


def check_notices(notices: bytes, dependencies: dict) -> None:
    text = notices.decode().lower()
    for package in dependencies["packages"]:
        if package["browserModules"] and f"{package['name']} {package['version']}".lower() not in text:
            raise ReleaseError(f"shipped notices omit {package['name']} {package['version']}")


def source_revision() -> dict:
    def git(*arguments: str) -> str:
        return subprocess.run(["git", "-C", str(REPOSITORY), *arguments], check=True,
                              capture_output=True, text=True).stdout.strip()
    try:
        return {"commit": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain", "--untracked-files=no"))}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}


def assemble(distributions: Path, output: Path, lockfile: Path, composition: Path | None) -> Path:
    zip_path, tar_path, version = distribution_pair(distributions)
    zip_members = read_zip(zip_path)
    compare_archives(zip_members, read_tar(tar_path))
    members = strip_root(zip_members, version)
    application_jar = f"lib/llm-bin-patch-{version}.jar"
    if application_jar not in members:
        raise ReleaseError(f"the distribution omits {application_jar}")
    manifest = ui_manifest(members[application_jar].data)
    classpath = launcher_classpath(members, application_jar)
    dependencies = frontend_dependencies(lockfile, composition)
    if NOTICES not in members:
        raise ReleaseError(f"the distribution omits {NOTICES}")
    check_notices(members[NOTICES].data, dependencies)

    release = output / f"{NAME}-{version}"
    if release.exists():
        shutil.rmtree(release)
    release.mkdir(parents=True)
    for archive in (zip_path, tar_path):
        shutil.copyfile(archive, release / archive.name)
    inventory = {"schemaVersion": 1, "root": f"{NAME}-{version}/", "classPath": classpath, "files": [
        {"path": name, "sizeBytes": member.size, "sha256": member.digest, "mode": f"{member.mode:04o}", "role": role(name, application_jar)}
        for name, member in sorted(members.items())]}
    record = {
        "schemaVersion": 1,
        "application": NAME,
        "version": version,
        "source": source_revision(),
        # The server reports the SHA-256 of its own application JAR as applicationBuildId.
        "applicationBuildId": members[application_jar].digest,
        "uiBuildId": manifest["buildId"],
        "applicationJar": application_jar,
        "archives": {path.name: {"sizeBytes": path.stat().st_size, "sha256": file_sha256(path)} for path in (zip_path, tar_path)},
        "shippedFiles": len(members),
        "runtime": {"platform": "linux-x86_64", "java": "21", "node": "not required at run time"},
    }
    (release / "release-inventory.json").write_bytes(json_bytes(inventory))
    (release / "ui-manifest.json").write_bytes(json_bytes(manifest))
    (release / "frontend-dependencies.json").write_bytes(json_bytes(dependencies))
    (release / "frontend-THIRD_PARTY_NOTICES.txt").write_bytes(members[NOTICES].data)
    (release / "release-record.json").write_bytes(json_bytes(record))
    write_checksums(release)
    return release


def write_checksums(release: Path) -> None:
    lines = [f"{file_sha256(path)}  {path.name}\n" for path in sorted(release.iterdir()) if path.name != "SHA256SUMS"]
    (release / "SHA256SUMS").write_text("".join(lines))


def verify(release: Path, lockfile: Path | None) -> dict:
    sums = {}
    for line in (release / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/]+)", line)
        if not match or match.group(2) in sums:
            raise ReleaseError(f"malformed SHA256SUMS line: {line[:80]}")
        sums[match.group(2)] = match.group(1)
    present = {path.name for path in release.iterdir() if path.name != "SHA256SUMS"}
    if present != sums.keys():
        raise ReleaseError(f"SHA256SUMS and the release directory disagree: {sorted(present ^ sums.keys())}")
    for name, expected in sums.items():
        if file_sha256(release / name) != expected:
            raise ReleaseError(f"{name} does not match SHA256SUMS")

    record = json.loads((release / "release-record.json").read_text())
    inventory = json.loads((release / "release-inventory.json").read_text())
    version = record["version"]
    zip_path, tar_path = release / f"{NAME}-{version}.zip", release / f"{NAME}-{version}.tar"
    for path in (zip_path, tar_path):
        expected = record["archives"][path.name]
        if file_sha256(path) != expected["sha256"] or path.stat().st_size != expected["sizeBytes"]:
            raise ReleaseError(f"{path.name} differs from the release record")
    expected_files = {item["path"]: item for item in inventory["files"]}
    for archive, members in ((zip_path, read_zip(zip_path)), (tar_path, read_tar(tar_path))):
        members = strip_root(members, version)
        if members.keys() != expected_files.keys():
            raise ReleaseError(f"{archive.name} ships files absent from or missing in the inventory: "
                               f"{sorted(members.keys() ^ expected_files.keys())[:5]}")
        for name, member in members.items():
            item = expected_files[name]
            if member.size != item["sizeBytes"] or member.digest != item["sha256"] or f"{member.mode:04o}" != item["mode"]:
                raise ReleaseError(f"{archive.name} member {name} differs from the inventory")
        if launcher_classpath(members, record["applicationJar"]) != inventory["classPath"]:
            raise ReleaseError(f"{archive.name} launcher class path differs from the inventory")
        application_jar = members[record["applicationJar"]].data
        if sha256(application_jar) != record["applicationBuildId"]:
            raise ReleaseError("the application JAR differs from the recorded application build ID")
        manifest = ui_manifest(application_jar)
        if manifest != json.loads((release / "ui-manifest.json").read_text()) or manifest["buildId"] != record["uiBuildId"]:
            raise ReleaseError("the embedded UI manifest differs from the release record")
        if members[NOTICES].data != (release / "frontend-THIRD_PARTY_NOTICES.txt").read_bytes():
            raise ReleaseError("the shipped notices differ from the release copy")
    dependencies = json.loads((release / "frontend-dependencies.json").read_text())
    check_notices((release / "frontend-THIRD_PARTY_NOTICES.txt").read_bytes(), dependencies)
    if lockfile is not None:
        if file_sha256(lockfile) != dependencies["lockfileSha256"]:
            raise ReleaseError("frontend/package-lock.json differs from the one recorded for this release")
        current = frontend_dependencies(lockfile, None)["packages"]
        recorded = [{key: value for key, value in package.items() if key != "browserModules"} for package in dependencies["packages"]]
        if recorded != [{key: value for key, value in package.items() if key != "browserModules"} for package in current]:
            raise ReleaseError("the recorded frontend dependencies differ from the lockfile")
    return {"release": release.name, "verifiedFiles": len(expected_files), "archives": 2,
            "uiResources": len(json.loads((release / "ui-manifest.json").read_text())["files"]),
            "applicationBuildId": record["applicationBuildId"], "uiBuildId": record["uiBuildId"],
            "source": record["source"]}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("assemble")
    build.add_argument("--distributions", type=Path, default=REPOSITORY / "build/distributions")
    build.add_argument("--output", type=Path, default=REPOSITORY / "build/release")
    build.add_argument("--lockfile", type=Path, default=REPOSITORY / "frontend/package-lock.json")
    build.add_argument("--bundle-composition", type=Path, default=REPOSITORY / "build/frontend/bundle-composition.json")
    check = commands.add_parser("verify")
    check.add_argument("release", type=Path)
    check.add_argument("--lockfile", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "assemble":
            composition = arguments.bundle_composition if arguments.bundle_composition.is_file() else None
            release = assemble(arguments.distributions, arguments.output, arguments.lockfile, composition)
            print(release)
        else:
            print(json.dumps(verify(arguments.release, arguments.lockfile), sort_keys=True))
    except (ReleaseError, OSError, KeyError, ValueError) as failure:
        print(f"release verification failed: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
