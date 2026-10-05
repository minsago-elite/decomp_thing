#!/usr/bin/env python3
"""Acquire and qualify the pinned Ubuntu Noble Clang 18.1.3 toolchain profile.

The script deliberately separates authenticated candidate acquisition from
acceptance. It never writes a trusted package lock from network data; the
candidate manifests are CI artifacts that must be reviewed and pinned before
the build-record verifier can accept them.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import urllib.error
import zlib


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "oracle/clang/18.1.3/provisioning-contract.json"
DEFAULT_KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
RECIPE_FILES = {
    "contractSha256": CONTRACT_PATH,
    "schemaSha256": CONTRACT_PATH.parent / "build-record.schema.json",
    "provisionerSha256": ROOT / "scripts/oracle/provision_clang_18_1_3.py",
    "probeSha256": ROOT / "oracle/clang/18.1.3/libtooling-probe.cpp",
    "fixtureSha256": ROOT / "oracle/clang/18.1.3/fixtures/libtooling-positive.cpp",
    "aLoaderSmokeSha256": ROOT / "oracle/clang/18.1.3/Clang1813AProfileLoaderSmoke.java",
    "aLoaderInitSha256": ROOT / "oracle/clang/18.1.3/clang1813-loader-smoke.init.gradle",
    "workflowSha256": ROOT / ".github/workflows/generic-template-toolchain.yml",
}
MAX_DOWNLOAD_BYTES = 3 * 1024 * 1024 * 1024
MAX_SINGLE_DOWNLOAD = 1024 * 1024 * 1024
MAX_INDEX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_INDEX_LINE_BYTES = 16 * 1024 * 1024
MAX_DEB822_PARAGRAPH_BYTES = 16 * 1024 * 1024
MAX_SOURCE_DIAGNOSTIC_ROWS = 256
MAX_UPSTREAM_ARCHIVE_MEMBERS = 300_000
MAX_UPSTREAM_EXPANDED_BYTES = 3 * 1024 * 1024 * 1024
SNAPSHOT_METADATA_PROBE = "20240702T000000Z"
PAUSED_UPSTREAM_SIGNATURE_URL = (
    "https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.3/"
    "llvm-project-18.1.3.src.tar.xz.sig"
)
# Keep candidate acquisition disabled for this profile until the denied
# upstream signature source is explicitly resolved and the pause is reviewed.
UPSTREAM_SIGNATURE_ACCESS_ENABLED = False
MAX_SNAPSHOT_METADATA_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_INDEX_BYTES = 128 * 1024 * 1024
ALLOWED_REDIRECT_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


class ProvisionError(RuntimeError):
    pass


class LockedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin_netloc: str, allow_github_redirect: bool):
        super().__init__()
        self.origin_netloc = origin_netloc
        self.allow_github_redirect = allow_github_redirect

    def redirect_request(self, request, response, code, message, headers, new_url):
        target = urllib.parse.urlparse(new_url)
        permitted = target.scheme == "https" and (
            target.netloc == self.origin_netloc or
            (self.allow_github_redirect and target.hostname in ALLOWED_REDIRECT_HOSTS)
        )
        if not permitted:
            raise urllib.error.URLError("redirect destination is outside the pinned HTTPS host allowlist")
        return super().redirect_request(request, response, code, message, headers, new_url)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def recipe_identity() -> dict[str, str]:
    return {name: sha256_file(path) for name, path in RECIPE_FILES.items()}


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def read_contract(path: Path = CONTRACT_PATH) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    profile = value["profile"]
    if value.get("schemaVersion") != 1:
        raise ProvisionError("unsupported provisioning contract schema")
    if profile["snapshotBase"].rstrip("/") != f"https://snapshot.ubuntu.com/ubuntu/{profile['snapshot']}":
        raise ProvisionError("snapshot URL is not the exact pinned public Snapshot URL")
    if profile["architecture"] != "amd64" or profile["target"] != "x86_64-linux-gnu":
        raise ProvisionError("profile is not Linux x86-64")
    if profile["sourcePackage"] != {"name": "llvm-toolchain-18", "version": "1:18.1.3-1ubuntu1"}:
        raise ProvisionError("source package contract drift")
    roots = {item["name"]: item["version"] for item in profile["binaryRoots"]}
    required = {"clang-18", "llvm-18-dev", "libclang-18-dev", "libclang-cpp18-dev", "libclang-cpp18"}
    if set(roots) != required or len(set(roots.values())) != 1:
        raise ProvisionError("binary roots must include the exact compiler/development/runtime closure pins")
    lang = value["langOptions"]
    if lang.get("inventoryEvidence") != "authenticated-source-text-scan-of-LangOptions.def-and-LangOptions.h":
        raise ProvisionError("LangOptions inventory evidence type must identify its authenticated source-text scan")
    if lang.get("runtimeChecks") != [
        "LangOptions::CPlusPlus14=true",
        "LangOptions::CPlusPlus20=false",
        "LangOptions::DoubleSquareBracketAttributes=true",
        "LangOptions::Trigraphs=true",
    ]:
        raise ProvisionError("selected LangOptions runtime check contract drift")
    if sum(lang["familyCounts"].values()) != lang["generatedFieldCount"]:
        raise ProvisionError("LangOptions family counts do not sum to the pinned field count")
    if len(lang["manualFields"]) != lang["manualFieldsCount"] or len(set(lang["manualFields"])) != lang["manualFieldsCount"]:
        raise ProvisionError("manual LangOptions field manifest is incomplete or duplicated")
    if len(lang["callingConventions"]) != 22 or len(set(lang["callingConventions"])) != 22:
        raise ProvisionError("calling convention inventory is incomplete or duplicated")
    if lang["apiChecks"] != sorted(set(lang["apiChecks"])) or len(lang["apiChecks"]) != 22:
        raise ProvisionError("LibTooling API inventory is incomplete, duplicated, or unsorted")
    negative = value["negativeControl"]
    if negative != {
        "oracleId": "clang-driver-22.1.6",
        "artifactLock": "oracle/llvm/22.1.6/release-artifacts.json",
        "artifactRole": "full",
        "requiredVersion": "22.1.6",
        "fixture": "oracle/clang/18.1.3/fixtures/libtooling-positive.cpp",
    }:
        raise ProvisionError("negative Clang 22.1.6 comparator contract drift")
    lock = json.loads((ROOT / negative["artifactLock"]).read_text(encoding="utf-8"))
    artifact = lock.get("artifacts", {}).get(negative["artifactRole"], {})
    if lock.get("oracle", {}).get("id") != negative["oracleId"] or lock.get("oracle", {}).get("version") != negative["requiredVersion"]:
        raise ProvisionError("negative comparator does not reference the exact 22.1.6 oracle lock")
    if not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", ""))) or artifact.get("bytes", 0) < 1:
        raise ProvisionError("negative comparator lock has no immutable artifact byte identity")
    return value


def parse_deb822(payload: str) -> list[dict[str, str]]:
    """Parse a Debian control/index file with strict field and continuation rules."""
    return list(iter_deb822_lines(payload.splitlines()))


def deb822_multiline_rows(value: str) -> list[str]:
    """Remove only the empty field-value line preceding a normal continuation list."""
    rows = value.splitlines()
    if value.startswith("\n") and rows and rows[0] == "":
        return rows[1:]
    return rows


def iter_deb822_lines(lines, allow_empty: bool = False):
    """Yield strict Debian paragraphs without retaining a complete Packages index."""
    fields: dict[str, str] = {}
    last_key: str | None = None
    paragraph_count = 0
    paragraph_bytes = 0
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\r\n")
        if not line:
            if fields:
                yield fields
                paragraph_count += 1
                fields = {}
            paragraph_bytes = 0
            last_key = None
            continue
        paragraph_bytes += len(line.encode("utf-8"))
        if paragraph_bytes > MAX_DEB822_PARAGRAPH_BYTES:
            raise ProvisionError("Debian control paragraph exceeds its byte budget")
        if line.startswith((" ", "\t")):
            if last_key is None:
                raise ProvisionError(f"orphan continuation on Debian control line {line_number}")
            fields[last_key] += "\n" + line[1:]
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9-]*):(?: ?)(.*)", line)
        if match is None:
            raise ProvisionError(f"malformed Debian control field on line {line_number}")
        key, value = match.groups()
        if key in fields:
            raise ProvisionError(f"duplicate Debian control field {key}")
        fields[key] = value
        last_key = key
    if fields:
        yield fields
        paragraph_count += 1
    if not paragraph_count and not allow_empty:
        raise ProvisionError("empty Debian control/index document")


def iter_compressed_index(path: Path):
    """Stream a signed .gz/.xz index one Debian paragraph at a time."""
    def bounded_lines(stream):
        total = 0
        while True:
            raw_line = stream.readline(MAX_INDEX_LINE_BYTES + 1)
            if not raw_line:
                return
            if len(raw_line) > MAX_INDEX_LINE_BYTES:
                raise ProvisionError("signed package index contains an oversized control line")
            try:
                line = raw_line.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise ProvisionError("signed package index contains invalid UTF-8") from error
            size = len(raw_line)
            total += size
            if total > MAX_INDEX_UNCOMPRESSED_BYTES:
                raise ProvisionError("signed package index exceeds the decompressed byte budget")
            yield line

    try:
        if path.name.endswith(".gz"):
            with gzip.open(path, mode="rb") as stream:
                # A signed Release table may legitimately name an empty pocket
                # index. The caller authenticates the compressed bytes first;
                # malformed non-empty paragraphs still fail closed.
                yield from iter_deb822_lines(bounded_lines(stream), allow_empty=True)
            return
        if path.name.endswith(".xz"):
            with lzma.open(path, mode="rb") as stream:
                yield from iter_deb822_lines(bounded_lines(stream), allow_empty=True)
            return
    except ProvisionError as error:
        raise ProvisionError(f"could not parse signed index {path.name}: {error}") from error
    except (OSError, EOFError, lzma.LZMAError, zlib.error, UnicodeDecodeError) as error:
        raise ProvisionError(f"could not decode streamed signed index {path.name}: {error}") from error
    raise ProvisionError(f"unsupported signed index encoding: {path.name}")


def cleartext_body(inrelease: bytes) -> bytes:
    text = inrelease.decode("utf-8", errors="strict")
    lines = text.splitlines()
    if not lines or lines[0] != "-----BEGIN PGP SIGNED MESSAGE-----":
        raise ProvisionError("InRelease is not an OpenPGP clear-signed document")
    try:
        separator = lines.index("")
        signature = lines.index("-----BEGIN PGP SIGNATURE-----")
    except ValueError as error:
        raise ProvisionError("malformed InRelease clear-sign framing") from error
    if separator >= signature:
        raise ProvisionError("malformed InRelease clear-sign framing")
    body = lines[separator + 1:signature]
    # RFC 4880 dash-escaping is part of cleartext signature framing.
    body = [line[2:] if line.startswith("- ") else line for line in body]
    return ("\n".join(body) + "\n").encode("utf-8")


def verify_gpgv(data_path: Path, keyring: Path, allowed_fingerprints: set[str]) -> str:
    if not keyring.is_file():
        raise ProvisionError(f"required trusted keyring is missing: {keyring}")
    proc = subprocess.run(
        ["gpgv", "--status-fd", "1", "--keyring", str(keyring), str(data_path)],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if proc.returncode != 0:
        raise ProvisionError(f"OpenPGP verification failed: {proc.stderr.strip()}")
    fingerprints: list[str] = []
    rejected_statuses = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYREVOKED", "KEYEXPIRED", "NO_PUBKEY"}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "[GNUPG:]":
            if parts[1] in rejected_statuses:
                raise ProvisionError(f"OpenPGP document has a rejected or unknown signature status: {parts[1]}")
            if parts[1] == "VALIDSIG":
                fingerprints.append(valid_sig_primary_fingerprint(parts))
    allowed = {item.upper() for item in allowed_fingerprints}
    if len(fingerprints) != 1 or fingerprints[0] not in allowed:
        raise ProvisionError(
            "InRelease must have exactly one valid signature from an Ubuntu-allowlisted primary fingerprint"
        )
    return fingerprints[0]


def valid_sig_primary_fingerprint(status_fields: list[str]) -> str:
    """Return the primary-key fingerprint from a gpgv VALIDSIG status row."""
    if len(status_fields) < 11 or status_fields[:2] != ["[GNUPG:]", "VALIDSIG"]:
        raise ProvisionError("malformed gpgv VALIDSIG status row")
    signer = status_fields[2].upper()
    # GnuPG appends PRIMARY_KEY_FPR after the signature-class field. Older
    # gpg versions omit it when the signing key is the primary key itself.
    primary = status_fields[11].upper() if len(status_fields) > 11 else signer
    if not re.fullmatch(r"[0-9A-F]{40,64}", primary):
        raise ProvisionError("gpgv VALIDSIG row contains an invalid primary fingerprint")
    return primary


def verify_detached_signature(signature_path: Path, data_path: Path, keyring: Path,
                              expected_fingerprint: str) -> str:
    proc = subprocess.run(
        ["gpgv", "--status-fd", "1", "--keyring", str(keyring), str(signature_path), str(data_path)],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if proc.returncode != 0:
        raise ProvisionError(f"detached upstream signature verification failed: {proc.stderr.strip()}")
    fingerprints = []
    rejected_statuses = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYREVOKED", "KEYEXPIRED", "NO_PUBKEY"}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "[GNUPG:]":
            if parts[1] in rejected_statuses:
                raise ProvisionError(f"upstream signature has a rejected or unknown status: {parts[1]}")
            if parts[1] == "VALIDSIG":
                fingerprints.append(valid_sig_primary_fingerprint(parts))
    if len(fingerprints) != 1 or fingerprints[0] != expected_fingerprint.upper():
        raise ProvisionError("upstream source signature did not come from the pinned LLVM release key")
    return fingerprints[0]


def dearmor_release_key(key_path: Path, temporary_root: Path) -> bytes:
    """Convert the locked ASCII-armored release key to a bounded gpgv keyring."""
    key_bytes = key_path.read_bytes()
    if not key_bytes or len(key_bytes) > 1024 * 1024:
        raise ProvisionError("pinned LLVM release key is empty or exceeds its byte bound")
    temporary_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="llvm-key-dearmor-", dir=temporary_root) as homedir:
        proc = subprocess.run(
            ["gpg", "--batch", "--no-options", "--homedir", homedir, "--dearmor"],
            input=key_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
        )
    if proc.returncode != 0 or not proc.stdout or len(proc.stdout) > 1024 * 1024:
        raise ProvisionError("could not convert the pinned armored LLVM release key to a bounded gpgv keyring")
    return proc.stdout


def release_sha256_table(release: dict[str, str]) -> dict[str, tuple[int, str]]:
    rows = deb822_multiline_rows(release.get("SHA256", ""))
    result: dict[str, tuple[int, str]] = {}
    for row_number, row in enumerate(rows, start=1):
        parts = row.split()
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]) or not parts[1].isdigit():
            raise ProvisionError(f"malformed SHA256 row {row_number} in signed Release metadata")
        digest, length, name = parts
        if name.startswith("/") or ".." in PurePosixPath(name).parts or name in result:
            raise ProvisionError("unsafe or duplicate path in signed Release metadata")
        result[name] = (int(length), digest.lower())
    if not result:
        raise ProvisionError("signed Release metadata has no SHA256 index table")
    return result


def verify_release_identity(release: dict[str, str], suite: str, codename: str) -> None:
    if release.get("Codename") != codename or release.get("Suite") != suite:
        raise ProvisionError(f"Release identity mismatch for suite {suite}")
    if release.get("Architectures") and "amd64" not in release["Architectures"].split():
        raise ProvisionError(f"Release for {suite} excludes amd64")


def verify_release_profile(release: dict[str, str], suite: str, profile: dict) -> None:
    verify_release_identity(release, suite, profile["codename"])
    release_components = set(release.get("Components", "").split())
    if (release.get("Origin") != "Ubuntu" or release.get("Label") != "Ubuntu" or
            not set(profile["components"]).issubset(release_components)):
        raise ProvisionError(f"Release origin/label/components do not match the official Ubuntu profile for {suite}")


def index_path(table: dict[str, tuple[int, str]], component: str, kind: str, arch: str | None = None) -> str:
    base = f"{component}/{kind}/"
    for suffix in (".gz", ".xz"):
        candidate = base + ("Packages" if arch else "Sources") + suffix
        if candidate in table:
            return candidate
    raise ProvisionError(f"signed Release has no supported {kind} index for {component}/{arch or 'source'}")


class BoundedDownloader:
    def __init__(self, root: Path, total_limit: int = MAX_DOWNLOAD_BYTES):
        self.root = root
        self.total_limit = total_limit
        self.total = 0
        self.root.mkdir(parents=True, exist_ok=True)

    def _open_request(self, request, source_netloc: str, allow_github_redirect: bool):
        opener = urllib.request.build_opener(LockedRedirectHandler(source_netloc, allow_github_redirect))
        return opener.open(request, timeout=30)

    def get(self, url: str, expected_size: int | None = None, expected_sha256: str | None = None,
            max_bytes: int = MAX_SINGLE_DOWNLOAD, allow_github_redirect: bool = False) -> tuple[bytes, dict]:
        request = urllib.request.Request(url, headers={"Accept-Encoding": "identity", "User-Agent": "decomp-thing-clang-oracle/1"})
        source = urllib.parse.urlparse(url)
        try:
            with self._open_request(request, source.netloc, allow_github_redirect) as response:
                final_url = response.geturl()
                final = urllib.parse.urlparse(final_url)
                if final.scheme != "https":
                    raise ProvisionError("HTTPS acquisition redirected to a non-HTTPS URL")
                if final.netloc != source.netloc and not (allow_github_redirect and final.hostname in ALLOWED_REDIRECT_HOSTS):
                    raise ProvisionError(f"untrusted acquisition redirect: {source.netloc} -> {final.netloc}")
                if response.headers.get("Content-Encoding", "identity").lower() not in ("", "identity"):
                    raise ProvisionError("server applied content encoding to bytes whose digest is being checked")
                announced = response.headers.get("Content-Length")
                if announced is not None and int(announced) > max_bytes:
                    raise ProvisionError("remote object exceeds configured per-object byte ceiling")
                data = response.read(max_bytes + 1)
        except (OSError, ValueError) as error:
            raise ProvisionError(f"public HTTPS acquisition failed for {url}: {type(error).__name__}: {error}") from error
        if len(data) > max_bytes:
            raise ProvisionError("remote object exceeded configured per-object byte ceiling")
        self.total += len(data)
        if self.total > self.total_limit:
            raise ProvisionError("cumulative acquisition exceeds configured byte ceiling")
        if expected_size is not None and len(data) != expected_size:
            raise ProvisionError(f"length mismatch for {url}: expected {expected_size}, got {len(data)}")
        digest = sha256(data)
        if expected_sha256 is not None and digest != expected_sha256.lower():
            raise ProvisionError(f"SHA-256 mismatch for {url}: expected {expected_sha256}, got {digest}")
        public_final_url = urllib.parse.urlunparse((final.scheme, final.netloc, final.path, "", "", ""))
        return data, {"url": url, "finalUrl": public_final_url, "bytes": len(data), "sha256": digest}


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def source_file_rows(source: dict[str, str]) -> list[dict[str, str | int]]:
    raw = deb822_multiline_rows(source.get("Checksums-Sha256", ""))
    result: list[dict[str, str | int]] = []
    for row in raw:
        parts = row.split()
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]) or not parts[1].isdigit():
            raise ProvisionError("malformed source Checksums-Sha256 row")
        name = parts[2]
        if "/" in name or name in ("", ".", ".."):
            raise ProvisionError("unsafe source archive filename")
        result.append({"name": name, "bytes": int(parts[1]), "sha256": parts[0].lower()})
    if not result:
        raise ProvisionError("signed Sources entry has no SHA-256 files")
    if len({row["name"] for row in result}) != len(result):
        raise ProvisionError("signed Sources entry repeats a source filename")
    return result


def safe_extract_xz_tar(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    try:
        with tarfile.open(archive, mode="r:xz") as tar:
            members = []
            roots = set()
            names = set()
            expanded_bytes = 0
            for member in tar:
                if len(members) >= MAX_UPSTREAM_ARCHIVE_MEMBERS:
                    raise ProvisionError("upstream source archive exceeds the configured member-count limit")
                rel = PurePosixPath(member.name)
                if rel.is_absolute() or ".." in rel.parts or not rel.parts:
                    raise ProvisionError("upstream source archive contains an unsafe member path")
                normalized_name = rel.as_posix()
                if normalized_name in names:
                    raise ProvisionError("upstream source archive repeats a member path")
                names.add(normalized_name)
                roots.add(rel.parts[0])
                if member.isfile():
                    expanded_bytes += member.size
                    if expanded_bytes > MAX_UPSTREAM_EXPANDED_BYTES:
                        raise ProvisionError("upstream source archive exceeds the expanded-byte limit")
                if member.issym() or member.islnk():
                    target = PurePosixPath(member.linkname)
                    if target.is_absolute() or ".." in target.parts:
                        raise ProvisionError("upstream source archive contains an escaping link")
                members.append(member)
            if len(roots) != 1:
                raise ProvisionError("upstream source archive must contain one top-level root")
            # Python 3.12's data filter rejects device files and unsafe ownership.
            tar.extractall(destination, members=members, filter="data")
            return destination / next(iter(roots))
    except (OSError, tarfile.TarError) as error:
        raise ProvisionError(f"could not safely unpack upstream source archive: {error}") from error


def package_source_identity(package: dict[str, str]) -> tuple[str, str | None]:
    raw = package.get("Source", package.get("Package", ""))
    match = re.fullmatch(r"([^ ]+)(?: \(([^)]+)\))?", raw)
    if not match:
        raise ProvisionError(f"malformed package Source field: {raw!r}")
    return match.group(1), match.group(2)


def select_source_record(indexes: list[dict], package_name: str, version: str) -> dict:
    rows = [row for row in indexes if row.get("Package") == package_name and row.get("Version") == version]
    unique = {(row.get("Directory"), row.get("Checksums-Sha256")) for row in rows}
    if not rows or len(unique) != 1:
        observed = sorted({
            f"{row.get('Version', '<missing>')}@{row.get('_suite', '<unknown>')}/{row.get('_component', '<unknown>')}"
            for row in indexes if row.get("Package") == package_name
        })
        observed_text = ", ".join(observed) if observed else "none"
        raise ProvisionError(
            f"expected a unique signed source record for {package_name}={version}; "
            f"found {len(rows)} exact records; observed signed versions: {observed_text}"
        )
    return rows[0]


def source_index_diagnostic(profile: dict, repo_rows: list[dict], index_records: list[dict],
                            source_rows: list[dict], related_source_rows: list[dict],
                            related_source_record_count: int, binary_rows: list[dict]) -> dict:
    """Preserve the authenticated index coverage and package versions before selection."""
    source_records = [{
        "suite": row.get("_suite"),
        "component": row.get("_component"),
        "package": row.get("Package"),
        "version": row.get("Version"),
        "directory": row.get("Directory"),
        "checksumsSha256": row.get("Checksums-Sha256", ""),
    } for row in source_rows]
    source_records.sort(key=lambda row: (row["suite"] or "", row["component"] or "", row["version"] or ""))
    related_records = [{
        "suite": row.get("_suite"),
        "component": row.get("_component"),
        "package": row.get("Package"),
        "version": row.get("Version"),
        "directory": row.get("Directory"),
    } for row in related_source_rows]
    related_records.sort(key=lambda row: (
        row["suite"] or "", row["component"] or "", row["package"] or "", row["version"] or ""
    ))

    binary_records = [{
        "suite": row.get("_suite"),
        "component": row.get("_component"),
        "package": row.get("Package"),
        "version": row.get("Version"),
        "architecture": row.get("Architecture"),
        "source": row.get("Source"),
        "filename": row.get("Filename"),
        "bytes": row.get("Size"),
        "sha256": row.get("SHA256"),
    } for row in binary_rows]
    binary_records.sort(key=lambda row: (
        row["suite"] or "", row["component"] or "", row["package"] or "", row["version"] or ""
    ))

    source_indexes = [dict(row) for row in index_records if row.get("kind") == "source"]
    source_indexes.sort(key=lambda row: (row.get("suite", ""), row.get("component", "")))
    binary_indexes = [dict(row) for row in index_records if row.get("kind") == "binary-amd64"]
    binary_indexes.sort(key=lambda row: (row.get("suite", ""), row.get("component", "")))
    releases = [{
        "suite": row["suite"],
        "signerPrimaryFingerprint": row["signerPrimaryFingerprint"],
        "inRelease": row["inRelease"],
        "releaseIdentity": row["releaseIdentity"],
    } for row in repo_rows]
    releases.sort(key=lambda row: row["suite"])
    pin = profile["sourcePackage"]
    exact_rows = [row for row in source_records if row.get("version") == pin["version"]]
    exact_count = len(exact_rows)
    unique_exact_payloads = {
        (row.get("directory"), row.get("checksumsSha256")) for row in exact_rows
    }
    if not source_records:
        assessment = "package-name-not-found-in-selected-source-indexes"
    elif exact_count == 0:
        assessment = "package-found-but-exact-version-not-found"
    elif len(unique_exact_payloads) > 1:
        assessment = "exact-version-has-conflicting-source-records"
    elif exact_count > 1:
        assessment = "exact-version-has-duplicate-identical-source-records"
    else:
        assessment = "one-exact-package-and-version-record"
    serialized_source_records = source_records[:MAX_SOURCE_DIAGNOSTIC_ROWS]
    serialized_related_records = related_records[:MAX_SOURCE_DIAGNOSTIC_ROWS]
    matching_record_count = len(source_records) + related_source_record_count
    return {
        "schemaVersion": 1,
        "profileId": profile["id"],
        "snapshot": profile["snapshot"],
        "snapshotBase": profile["snapshotBase"],
        "expectedSource": dict(pin),
        "selectionSemantics": "exact Package and Version strings; no epoch or version normalization",
        "selectionAssessment": assessment,
        "releaseMetadata": releases,
        "sourceIndexes": source_indexes,
        "binaryIndexes": binary_indexes,
        "sourcePackageRecordCount": len(source_records),
        "sourcePackageRecords": serialized_source_records,
        "sourcePackageVersionsObserved": sorted({
            row["version"] for row in source_records if isinstance(row["version"], str)
        }),
        "exactSourceVersionRecordCount": exact_count,
        "uniqueExactSourcePayloadCount": len(unique_exact_payloads),
        "matchingPackageRecordCount": matching_record_count,
        "matchingPackageRecordsTruncated": matching_record_count > (
            len(serialized_source_records) + len(serialized_related_records)
        ),
        "matchingSourcePackageRecords": serialized_related_records,
        "binaryRootRecords": binary_records,
    }


def select_binary_record(indexes: list[dict], name: str, version: str, architecture: str = "amd64") -> dict:
    rows = [
        row for row in indexes
        if row.get("Package") == name and row.get("Version") == version
        and row.get("Architecture") in (architecture, "all")
    ]
    # A version may be present in more than one pocket; its signed archive bytes
    # must be identical in every record before one is selected.
    unique = {(row.get("Filename"), row.get("Size"), row.get("SHA256")) for row in rows}
    if not rows or len(unique) != 1:
        raise ProvisionError(f"expected a unique signed binary record for {name}={version}; found {len(rows)} records")
    selected = dict(rows[0])
    source_name, _ = package_source_identity(selected)
    if source_name != "llvm-toolchain-18" and name in {
        "clang-18", "llvm-18-dev", "libclang-18-dev", "libclang-cpp18-dev", "libclang-cpp18"
    }:
        raise ProvisionError(f"root binary {name} is not built from llvm-toolchain-18")
    return selected


def _metadata_source_row(row: dict) -> dict:
    return {
        "suite": row.get("_suite"), "component": row.get("_component"),
        "package": row.get("Package"), "version": row.get("Version"),
        "directory": row.get("Directory"), "checksumsSha256": row.get("Checksums-Sha256", ""),
    }


def _metadata_binary_row(row: dict) -> dict:
    return {
        "suite": row.get("_suite"), "component": row.get("_component"),
        "package": row.get("Package"), "version": row.get("Version"),
        "architecture": row.get("Architecture"), "source": row.get("Source"),
        "filename": row.get("Filename"), "bytes": row.get("Size"), "sha256": row.get("SHA256"),
    }


def snapshot_metadata_selection(contract: dict, profile: dict, repositories: list[dict], indexes: list[dict],
                                source_rows: list[dict], binary_rows: list[dict], metadata_bytes: int,
                                keyring: Path) -> dict:
    """Describe only the pinned source package and five binary roots from signed indexes."""
    source_pin = profile["sourcePackage"]
    roots = profile["binaryRoots"]
    exact_sources = [row for row in source_rows
                     if row.get("Package") == source_pin["name"] and row.get("Version") == source_pin["version"]]
    source_payloads = {(row.get("Directory"), row.get("Checksums-Sha256")) for row in exact_sources}
    source_status = (
        "exact-version-unique" if exact_sources and len(source_payloads) == 1 else
        "exact-version-conflict" if exact_sources else "exact-version-not-found"
    )

    root_reports = []
    all_roots_exact = True
    for pin in sorted(roots, key=lambda item: item["name"]):
        rows = [row for row in binary_rows if row.get("Package") == pin["name"]]
        exact = [row for row in rows if row.get("Version") == pin["version"]
                 and row.get("Architecture") in ("amd64", "all")]
        payloads = {(row.get("Filename"), row.get("Size"), row.get("SHA256")) for row in exact}
        if not exact:
            status = "exact-version-not-found"
            all_roots_exact = False
        elif len(payloads) != 1:
            status = "exact-version-conflict"
            all_roots_exact = False
        else:
            status = "exact-version-unique"
        exact_records = []
        for row in sorted(exact, key=lambda item: (item.get("_suite", ""), item.get("_component", ""))):
            source_name, source_version = package_source_identity(row)
            exact_records.append({**_metadata_binary_row(row),
                                  "sourceNameMatches": source_name == source_pin["name"],
                                  "sourceVersion": source_version})
            if source_name != source_pin["name"] or source_version not in (
                None, source_pin["version"].removeprefix("1:")
            ):
                all_roots_exact = False
                status = "source-identity-mismatch"
        root_reports.append({
            "package": pin["name"], "expectedVersion": pin["version"], "status": status,
            "observedVersions": sorted({str(row.get("Version")) for row in rows
                                         if isinstance(row.get("Version"), str)}),
            "exactRecords": exact_records,
        })

    if source_status != "exact-version-unique":
        selection_status = "source-" + source_status
    elif not all_roots_exact:
        selection_status = "binary-root-set-incomplete-or-mismatched"
    else:
        selection_status = "exact-contract-records-present"

    source_versions = sorted({str(row.get("Version")) for row in source_rows
                              if row.get("Package") == source_pin["name"] and
                              isinstance(row.get("Version"), str)})
    return {
        "schemaVersion": 1,
        "purpose": "authenticated-ubuntu-snapshot-index-metadata-only",
        "status": selection_status,
        "profileId": profile["id"],
        "candidateSnapshot": profile["snapshot"],
        "candidateSnapshotBase": profile["snapshotBase"],
        "configuredSnapshot": contract["profile"]["snapshot"],
        "contractSha256": sha256_file(CONTRACT_PATH),
        "recipe": recipe_identity(),
        "trustedUbuntuKeyring": {"bytes": keyring.stat().st_size, "sha256": sha256_file(keyring)},
        "repositories": repositories,
        "indexes": indexes,
        "acquiredMetadataBytes": metadata_bytes,
        "bounds": {"maxMetadataBytes": MAX_SNAPSHOT_METADATA_BYTES,
                   "maxSingleIndexBytes": MAX_SNAPSHOT_INDEX_BYTES,
                   "maxIndexCount": len(profile["suites"]) * len(profile["components"]) * 2},
        "payloadBytesDownloaded": 0,
        "expectedSource": dict(source_pin),
        "sourcePackage": {
            "status": source_status,
            "observedVersions": source_versions,
            "exactRecords": [{**_metadata_source_row(row),
                              "sourceFiles": source_file_rows(row)}
                             for row in sorted(exact_sources,
                                               key=lambda item: (item.get("_suite", ""), item.get("_component", "")))],
        },
        "binaryRoots": root_reports,
    }


def probe_snapshot_metadata(contract: dict, snapshot: str, output: Path, keyring: Path) -> dict:
    """Authenticate one approved Snapshot's signed indexes without fetching package payloads."""
    if snapshot != SNAPSHOT_METADATA_PROBE:
        raise ProvisionError(f"metadata-only probe is pinned to {SNAPSHOT_METADATA_PROBE}")
    if output.exists() and any(output.iterdir()):
        raise ProvisionError(f"output directory must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    original_profile = contract["profile"]
    profile = {**original_profile, "snapshot": snapshot,
               "snapshotBase": f"https://snapshot.ubuntu.com/ubuntu/{snapshot}/"}
    check_runner_bounds(output, profile)
    index_count = len(profile["suites"]) * len(profile["components"]) * 2
    if index_count != 12:
        raise ProvisionError("metadata-only probe requires the frozen three-suite/two-component index set")
    downloader = BoundedDownloader(output / "signed-index-metadata",
                                   min(profile["bounds"]["maxAcquisitionBytes"], MAX_SNAPSHOT_METADATA_BYTES))
    repositories: list[dict] = []
    source_rows: list[dict] = []
    binary_rows: list[dict] = []
    index_records: list[dict] = []
    binary_names = {row["name"] for row in profile["binaryRoots"]}

    for suite in profile["suites"]:
        inrelease_url = urllib.parse.urljoin(profile["snapshotBase"], f"dists/{suite}/InRelease")
        inrelease, release_download = downloader.get(inrelease_url, max_bytes=8 * 1024 * 1024)
        inrelease_path = output / "signed-index-metadata" / suite / "InRelease"
        atomic_write(inrelease_path, inrelease)
        signer = verify_gpgv(inrelease_path, keyring, set(profile["ubuntuArchivePrimaryFingerprints"]))
        release = parse_deb822(cleartext_body(inrelease).decode("utf-8"))[0]
        verify_release_profile(release, suite, profile)
        table = release_sha256_table(release)
        repositories.append({
            "suite": suite,
            "inRelease": {**release_download,
                          "path": str(inrelease_path.relative_to(output))},
            "signerPrimaryFingerprint": signer,
            "releaseIdentity": {key: release.get(key) for key in (
                "Origin", "Label", "Suite", "Codename", "Date", "Valid-Until",
                "Architectures", "Components")},
        })
        for component in profile["components"]:
            for kind in ("source", "binary-amd64"):
                relative_index = index_path(table, component, kind,
                                            "amd64" if kind == "binary-amd64" else None)
                expected_size, expected_hash = table[relative_index]
                index_url = urllib.parse.urljoin(profile["snapshotBase"],
                                                 f"dists/{suite}/{relative_index}")
                packed, download = downloader.get(index_url, expected_size, expected_hash,
                                                  max_bytes=MAX_SNAPSHOT_INDEX_BYTES)
                index_path_out = output / "signed-index-metadata" / suite / relative_index
                atomic_write(index_path_out, packed)
                for row in iter_compressed_index(index_path_out):
                    if kind == "source" and row.get("Package") == profile["sourcePackage"]["name"]:
                        selected = dict(row)
                        selected["_suite"], selected["_component"] = suite, component
                        source_rows.append(selected)
                    elif kind == "binary-amd64" and row.get("Package") in binary_names:
                        selected = dict(row)
                        selected["_suite"], selected["_component"] = suite, component
                        binary_rows.append(selected)
                index_records.append({
                    "suite": suite, "component": component, "kind": kind,
                    "signedReleasePath": relative_index,
                    "path": str(index_path_out.relative_to(output)),
                    "releaseExpectedBytes": expected_size,
                    "releaseExpectedSha256": expected_hash.lower(), **download,
                })

    evidence = snapshot_metadata_selection(contract, profile, repositories, index_records,
                                           source_rows, binary_rows, downloader.total, keyring)
    evidence["evidenceSha256"] = sha256(canonical_json(evidence))
    atomic_write(output / "snapshot-metadata-report.json", canonical_json(evidence))
    return evidence


def acquire_candidate(contract: dict, output: Path, keyring: Path) -> dict:
    if not UPSTREAM_SIGNATURE_ACCESS_ENABLED:
        raise ProvisionError(
            "Clang 18.1.3 candidate acquisition is paused pending explicit resolution of "
            "the denied upstream signature source; no acquisition requests were made. "
            f"Blocked target: {PAUSED_UPSTREAM_SIGNATURE_URL}"
        )
    if output.exists() and any(output.iterdir()):
        raise ProvisionError(f"output directory must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    profile = contract["profile"]
    check_runner_bounds(output, profile)
    downloader = BoundedDownloader(output / "downloads", contract["profile"]["bounds"]["maxAcquisitionBytes"])
    repo_rows: list[dict] = []
    all_sources: list[dict] = []
    related_source_rows: list[dict] = []
    related_source_record_count = 0
    all_binaries: list[dict] = []
    index_records: list[dict] = []
    source_pin = profile["sourcePackage"]
    binary_root_names = {row["name"] for row in profile["binaryRoots"]}

    for suite in profile["suites"]:
        inrelease_url = urllib.parse.urljoin(profile["snapshotBase"], f"dists/{suite}/InRelease")
        inrelease, release_download = downloader.get(inrelease_url, max_bytes=8 * 1024 * 1024)
        inrelease_path = output / "downloads" / suite / "InRelease"
        atomic_write(inrelease_path, inrelease)
        signer = verify_gpgv(inrelease_path, keyring, set(profile["ubuntuArchivePrimaryFingerprints"]))
        release = parse_deb822(cleartext_body(inrelease).decode("utf-8"))[0]
        verify_release_profile(release, suite, profile)
        table = release_sha256_table(release)
        repo_rows.append({
            "suite": suite,
            "inRelease": {**release_download, "path": str(inrelease_path.relative_to(output))},
            "signerPrimaryFingerprint": signer,
            "releaseIdentity": {key: release.get(key) for key in ("Origin", "Label", "Suite", "Codename", "Date", "Valid-Until", "Architectures", "Components")},
        })
        for component in profile["components"]:
            for kind in ("source", "binary-amd64"):
                index_name = index_path(table, component, kind, "amd64" if kind == "binary-amd64" else None)
                expected_size, expected_hash = table[index_name]
                url = urllib.parse.urljoin(profile["snapshotBase"], f"dists/{suite}/{index_name}")
                packed, info = downloader.get(url, expected_size, expected_hash, max_bytes=768 * 1024 * 1024)
                archive_path = output / "downloads" / suite / index_name
                atomic_write(archive_path, packed)
                for row in iter_compressed_index(archive_path):
                    if kind == "source":
                        package_name = row.get("Package", "")
                        if package_name == source_pin["name"]:
                            row = dict(row)
                            row["_suite"] = suite
                            row["_component"] = component
                            all_sources.append(row)
                        elif isinstance(package_name, str) and package_name.lower().startswith(("llvm", "clang")):
                            related_source_record_count += 1
                            if len(related_source_rows) < MAX_SOURCE_DIAGNOSTIC_ROWS:
                                row = dict(row)
                                row["_suite"] = suite
                                row["_component"] = component
                                related_source_rows.append(row)
                    elif row.get("Package") in binary_root_names:
                        row = dict(row)
                        row["_suite"] = suite
                        row["_component"] = component
                        all_binaries.append(row)
                index_records.append({"suite": suite, "component": component, "kind": kind,
                                      "path": str(archive_path.relative_to(output)), **info})

    diagnostic = source_index_diagnostic(profile, repo_rows, index_records, all_sources,
                                         related_source_rows, related_source_record_count, all_binaries)
    atomic_write(output / "source-selection-diagnostics.json", canonical_json(diagnostic))
    source = select_source_record(all_sources, source_pin["name"], source_pin["version"])
    source_files = source_file_rows(source)
    directory = source.get("Directory")
    if not directory or directory.startswith("/") or ".." in PurePosixPath(directory).parts:
        raise ProvisionError("signed source Directory field is missing or unsafe")
    source_artifacts = []
    for row in source_files:
        url = urllib.parse.urljoin(profile["snapshotBase"], f"{directory}/{row['name']}")
        data, info = downloader.get(url, int(row["bytes"]), str(row["sha256"]), max_bytes=1024 * 1024 * 1024)
        path = output / "downloads" / "source" / row["name"]
        atomic_write(path, data)
        source_artifacts.append({**row, **info, "path": str(path.relative_to(output))})
    dsc_rows = [row for row in source_artifacts if row["name"].endswith(".dsc")]
    if len(dsc_rows) != 1:
        raise ProvisionError("signed source record must provide exactly one .dsc")

    upstream = profile["upstream"]
    key_path = ROOT / upstream["keyFile"]
    key_bytes = key_path.read_bytes()
    if sha256(key_bytes) != upstream["keySha256"]:
        raise ProvisionError("pinned LLVM release key bytes changed")
    upstream_root = output / "downloads" / "upstream"
    upstream_root.mkdir(parents=True, exist_ok=True)
    upstream_keyring_bytes = dearmor_release_key(key_path, output)
    upstream_keyring_path = upstream_root / "llvm-release-keyring.gpg"
    atomic_write(upstream_keyring_path, upstream_keyring_bytes)
    upstream_archive_url = upstream["archiveUrl"]
    upstream_sig_url = upstream["signatureUrl"]
    archive_bytes, upstream_archive = downloader.get(
        upstream_archive_url, max_bytes=1024 * 1024 * 1024, allow_github_redirect=True
    )
    signature_bytes, upstream_signature = downloader.get(
        upstream_sig_url, max_bytes=1024 * 1024, allow_github_redirect=True
    )
    archive_name = Path(urllib.parse.urlparse(upstream_archive_url).path).name
    signature_name = Path(urllib.parse.urlparse(upstream_sig_url).path).name
    upstream_archive_path = upstream_root / archive_name
    upstream_signature_path = upstream_root / signature_name
    atomic_write(upstream_archive_path, archive_bytes)
    atomic_write(upstream_signature_path, signature_bytes)
    upstream_signer = verify_detached_signature(
        upstream_signature_path, upstream_archive_path, upstream_keyring_path, upstream["primaryFingerprint"]
    )

    distro_source_root = output / "source" / "package-source"
    distro_source_root.parent.mkdir(parents=True, exist_ok=True)
    dsc_path = output / dsc_rows[0]["path"]
    extract = subprocess.run(
        ["dpkg-source", "-x", str(dsc_path), str(distro_source_root)],
        cwd=dsc_path.parent, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        timeout=900,
    )
    if extract.returncode != 0:
        raise ProvisionError("dpkg-source rejected the signed .dsc/payload: " + extract.stdout[-4000:])
    upstream_source_root = safe_extract_xz_tar(upstream_archive_path, output / "source" / "upstream")
    patch_audit_path = output / "patch-audit.json"
    patch_audit = audit_patches(distro_source_root, upstream_source_root, patch_audit_path, contract)

    pinned_binaries = []
    for pin in profile["binaryRoots"]:
        row = select_binary_record(all_binaries, pin["name"], pin["version"])
        source_name, source_version = package_source_identity(row)
        if source_name != source_pin["name"] or source_version not in (None, source_pin["version"].removeprefix("1:")):
            raise ProvisionError(f"binary {pin['name']} source version does not match the pinned source package")
        pinned_binaries.append({
            "name": pin["name"], "version": pin["version"], "architecture": row["Architecture"],
            "suite": row["_suite"], "component": row["_component"], "filename": row["Filename"],
            "bytes": int(row["Size"]), "sha256": row["SHA256"].lower(),
        })
    dev = {row["name"]: row for row in pinned_binaries}["libclang-cpp18-dev"]
    runtime = {row["name"]: row for row in pinned_binaries}["libclang-cpp18"]
    if dev["version"] != runtime["version"]:
        raise ProvisionError("libclang-cpp18-dev and libclang-cpp18 must be locked at the same version")

    candidate = {
        "schemaVersion": 1,
        "status": "authenticated-candidate-awaiting-repository-lock-review",
        "profileId": profile["id"],
        "snapshot": profile["snapshot"],
        "trustedKeyring": {"bytes": keyring.stat().st_size, "sha256": sha256(keyring.read_bytes())},
        "repositories": repo_rows,
        "indexes": index_records,
        "source": {
            "name": source_pin["name"], "version": source_pin["version"],
            "directory": source["Directory"], "suite": source["_suite"], "component": source["_component"],
            "files": source_artifacts,
            "upstreamArchive": upstream_archive,
            "upstreamSignature": upstream_signature,
            "upstreamKeyring": {
                "path": str(upstream_keyring_path.relative_to(output)),
                "bytes": len(upstream_keyring_bytes), "sha256": sha256(upstream_keyring_bytes),
            },
            "upstreamArchivePath": str(upstream_archive_path.relative_to(output)),
            "upstreamSignaturePath": str(upstream_signature_path.relative_to(output)),
            "upstreamSignerPrimaryFingerprint": upstream_signer,
        },
        "patchAudit": {
            "status": patch_audit["status"],
            "patchCount": patch_audit["patchCount"],
            "patchInventorySha256": patch_audit["patchInventorySha256"],
            "relevantFileCount": patch_audit["relevantFileCount"],
            "relevantFileManifestSha256": patch_audit["relevantFileManifestSha256"],
        },
        "binaryRoots": sorted(pinned_binaries, key=lambda item: item["name"]),
        "downloadedBytes": downloader.total,
    }
    candidate["candidateSha256"] = sha256(canonical_json(candidate))
    atomic_write(output / "acquisition-candidate.json", canonical_json(candidate))
    return candidate


def ensure_source_artifact_contract(candidate: dict, contract: dict | None = None) -> None:
    if candidate.get("status") != "authenticated-candidate-awaiting-repository-lock-review":
        raise ProvisionError("candidate status field is invalid")
    contract = contract or read_contract()
    if candidate.get("profileId") != contract["profile"]["id"]:
        raise ProvisionError("candidate profile ID mismatch")
    keyring = candidate.get("trustedKeyring", {})
    if keyring.get("bytes", 0) < 1 or not re.fullmatch(r"[0-9a-f]{64}", str(keyring.get("sha256", ""))):
        raise ProvisionError("candidate does not bind the exact archive-verification keyring bytes")
    names = [row["name"] for row in candidate["binaryRoots"]]
    required = ["clang-18", "libclang-18-dev", "libclang-cpp18", "libclang-cpp18-dev", "llvm-18-dev"]
    if names != required:
        raise ProvisionError("candidate binary roots are missing, duplicated, or unsorted")
    if not any(row["name"].endswith(".dsc") for row in candidate["source"]["files"]):
        raise ProvisionError("candidate does not bind its .dsc")
    upstream_keyring = candidate["source"].get("upstreamKeyring", {})
    if (upstream_keyring.get("path") != "downloads/upstream/llvm-release-keyring.gpg" or
            upstream_keyring.get("bytes", 0) < 1 or
            not re.fullmatch(r"[0-9a-f]{64}", str(upstream_keyring.get("sha256", "")))):
        raise ProvisionError("candidate does not bind the derived, bounded upstream gpgv keyring")
    if len(candidate.get("repositories", [])) != 3 or len(candidate.get("indexes", [])) != 12:
        raise ProvisionError("candidate omits one or more signed suite/component indexes")
    if {row["suite"] for row in candidate["repositories"]} != set(contract["profile"]["suites"]):
        raise ProvisionError("candidate repository list differs from the pinned suite set")
    index_keys = [(row.get("suite"), row.get("component"), row.get("kind")) for row in candidate["indexes"]]
    expected_index_keys = {
        (suite, component, kind)
        for suite in contract["profile"]["suites"]
        for component in contract["profile"]["components"]
        for kind in ("source", "binary-amd64")
    }
    if len(set(index_keys)) != len(index_keys) or set(index_keys) != expected_index_keys:
        raise ProvisionError("candidate signed index inventory is duplicated or incomplete")
    if candidate["downloadedBytes"] > contract["profile"]["bounds"]["maxAcquisitionBytes"]:
        raise ProvisionError("candidate exceeds acquisition byte budget")
    without_self = dict(candidate)
    candidate_digest = without_self.pop("candidateSha256", None)
    if candidate_digest != sha256(canonical_json(without_self)):
        raise ProvisionError("candidate self-digest mismatch")


def verify_candidate_data(candidate_root: Path, candidate: dict, contract: dict, keyring: Path) -> list[dict]:
    """Recheck signed metadata and all acquired bytes before rootfs provisioning."""
    profile = contract["profile"]
    ensure_source_artifact_contract(candidate, contract)
    keyring_bytes = keyring.read_bytes()
    trusted_keyring = candidate["trustedKeyring"]
    if len(keyring_bytes) != trusted_keyring["bytes"] or sha256(keyring_bytes) != trusted_keyring["sha256"]:
        raise ProvisionError("Ubuntu archive keyring bytes changed after acquisition")
    parsed_indexes: list[dict] = []
    repos_by_suite = {row["suite"]: row for row in candidate["repositories"]}
    indexes_by_key = {(row["suite"], row["component"], row["kind"]): row for row in candidate["indexes"]}
    if set(repos_by_suite) != set(profile["suites"]):
        raise ProvisionError("candidate repository suite set differs from the pinned profile")
    for suite in profile["suites"]:
        repo = repos_by_suite[suite]
        inrelease = repo["inRelease"]
        expected_inrelease_url = urllib.parse.urljoin(profile["snapshotBase"], f"dists/{suite}/InRelease")
        if inrelease.get("path") != f"downloads/{suite}/InRelease" or inrelease.get("url") != expected_inrelease_url or inrelease.get("finalUrl") != expected_inrelease_url:
            raise ProvisionError(f"candidate InRelease path/URL is not the immutable suite URL for {suite}")
        inrelease_path = candidate_root / inrelease["path"]
        payload = inrelease_path.read_bytes()
        if len(payload) != inrelease["bytes"] or sha256(payload) != inrelease["sha256"]:
            raise ProvisionError(f"candidate InRelease bytes changed for {suite}")
        signer = verify_gpgv(inrelease_path, keyring, set(profile["ubuntuArchivePrimaryFingerprints"]))
        if signer != repo["signerPrimaryFingerprint"]:
            raise ProvisionError(f"candidate InRelease signer changed for {suite}")
        release = parse_deb822(cleartext_body(payload).decode("utf-8"))[0]
        verify_release_profile(release, suite, profile)
        table = release_sha256_table(release)
        for component in profile["components"]:
            for kind in ("source", "binary-amd64"):
                index = indexes_by_key.get((suite, component, kind))
                if not index:
                    raise ProvisionError(f"candidate omits signed {kind} index for {suite}/{component}")
                index_pathname = index["path"]
                expected_prefix = f"downloads/{suite}/{component}/"
                if not index_pathname.startswith(expected_prefix) or PurePosixPath(index_pathname).is_absolute() or ".." in PurePosixPath(index_pathname).parts:
                    raise ProvisionError("candidate signed package index path does not match its suite/component")
                # The signed-table key is relative to dists/<suite>, not the local artifact root.
                table_path = "/".join(PurePosixPath(index_pathname).parts[2:])
                expected = table.get(table_path)
                if expected is None:
                    raise ProvisionError(f"Release metadata does not bind candidate index {table_path}")
                packed = (candidate_root / index_pathname).read_bytes()
                if len(packed) != expected[0] or sha256(packed) != expected[1]:
                    raise ProvisionError(f"candidate package index hash/length mismatch for {suite}/{table_path}")
                if len(packed) != index["bytes"] or sha256(packed) != index["sha256"]:
                    raise ProvisionError(f"candidate index record changed for {suite}/{table_path}")
                wanted_source = profile["sourcePackage"]["name"]
                wanted_roots = {row["name"] for row in profile["binaryRoots"]}
                for row in iter_compressed_index(candidate_root / index_pathname):
                    if index["kind"] == "source" and row.get("Package") != wanted_source:
                        continue
                    if index["kind"] == "binary-amd64" and row.get("Package") not in wanted_roots:
                        continue
                    parsed_indexes.append(dict(row, _suite=suite, _component=component))

    source_pin = profile["sourcePackage"]
    source = select_source_record(parsed_indexes, source_pin["name"], source_pin["version"])
    authenticated_source_files = {
        str(row["name"]): (int(row["bytes"]), str(row["sha256"]))
        for row in source_file_rows(source)
    }
    candidate_source_files = {row["name"]: (row["bytes"], row["sha256"]) for row in candidate["source"]["files"]}
    if candidate_source_files != authenticated_source_files:
        raise ProvisionError("candidate source file list does not match signed Sources metadata")
    for row in candidate["source"]["files"]:
        expected_path = f"downloads/source/{row['name']}"
        if row.get("path") != expected_path or "/" in row["name"] or row["name"] in ("", ".", ".."):
            raise ProvisionError("candidate source payload path differs from the signed basename")
        expected_url = urllib.parse.urljoin(profile["snapshotBase"], f"{source['Directory']}/{row['name']}")
        if row.get("url") != expected_url or row.get("finalUrl") != expected_url:
            raise ProvisionError("candidate source payload URL differs from its signed Sources record")
    for row in candidate["source"]["files"]:
        path = candidate_root / row["path"]
        data = path.read_bytes()
        if len(data) != row["bytes"] or sha256(data) != row["sha256"]:
            raise ProvisionError(f"acquired source payload changed: {row['name']}")
    upstream = profile["upstream"]
    key = ROOT / upstream["keyFile"]
    if sha256(key.read_bytes()) != upstream["keySha256"]:
        raise ProvisionError("pinned LLVM release key bytes changed")
    upstream_keyring_record = candidate["source"]["upstreamKeyring"]
    upstream_keyring_path = candidate_root / upstream_keyring_record["path"]
    expected_keyring = dearmor_release_key(key, candidate_root)
    upstream_keyring_bytes = upstream_keyring_path.read_bytes()
    if (upstream_keyring_bytes != expected_keyring or
            len(upstream_keyring_bytes) != upstream_keyring_record["bytes"] or
            sha256(upstream_keyring_bytes) != upstream_keyring_record["sha256"]):
        raise ProvisionError("candidate-derived LLVM gpgv keyring differs from the locked armored public key")
    archive_path = candidate_root / candidate["source"]["upstreamArchivePath"]
    signature_path = candidate_root / candidate["source"]["upstreamSignaturePath"]
    expected_archive_path = "downloads/upstream/" + Path(urllib.parse.urlparse(upstream["archiveUrl"]).path).name
    expected_signature_path = "downloads/upstream/" + Path(urllib.parse.urlparse(upstream["signatureUrl"]).path).name
    if candidate["source"]["upstreamArchivePath"] != expected_archive_path or candidate["source"]["upstreamSignaturePath"] != expected_signature_path:
        raise ProvisionError("upstream LLVM source paths do not match the locked release asset basenames")
    for field, expected_url in (("upstreamArchive", upstream["archiveUrl"]), ("upstreamSignature", upstream["signatureUrl"])):
        artifact = candidate["source"][field]
        final = urllib.parse.urlparse(artifact.get("finalUrl", ""))
        if artifact.get("url") != expected_url or final.scheme != "https" or final.hostname not in ALLOWED_REDIRECT_HOSTS:
            raise ProvisionError("upstream release asset URL/redirect differs from its pinned GitHub source")
    if sha256(archive_path.read_bytes()) != candidate["source"]["upstreamArchive"]["sha256"]:
        raise ProvisionError("upstream LLVM source archive changed")
    if sha256(signature_path.read_bytes()) != candidate["source"]["upstreamSignature"]["sha256"]:
        raise ProvisionError("upstream LLVM source signature bytes changed")
    upstream_signer = verify_detached_signature(
        signature_path, archive_path, upstream_keyring_path, upstream["primaryFingerprint"],
    )
    if candidate["source"].get("upstreamSignerPrimaryFingerprint") != upstream_signer:
        raise ProvisionError("upstream LLVM signature signer changed after acquisition")
    for pin in profile["binaryRoots"]:
        row = select_binary_record(parsed_indexes, pin["name"], pin["version"])
        recorded = next(item for item in candidate["binaryRoots"] if item["name"] == pin["name"])
        if (row.get("SHA256", "").lower() != recorded["sha256"] or
                int(row.get("Size", "0")) != recorded["bytes"] or
                row.get("Version") != recorded["version"] or
                row.get("Architecture") != recorded["architecture"] or
                row.get("Filename") != recorded["filename"] or
                row.get("_suite") != recorded["suite"] or
                row.get("_component") != recorded["component"]):
            raise ProvisionError(f"signed binary index digest changed for {pin['name']}")
    if source.get("Version") != source_pin["version"]:
        raise ProvisionError("source record version changed")
    return parsed_indexes


def parse_invocations(text: str, forms: set[str]) -> list[tuple[str, list[str]]]:
    """Extract direct macro invocations, respecting strings, comments and nesting."""
    invocations: list[tuple[str, list[str]]] = []
    token_re = re.compile(r"(?m)^\s*(" + "|".join(sorted(forms, key=len, reverse=True)) + r")\s*\(")
    for match in token_re.finditer(text):
        form = match.group(1)
        open_paren = text.find("(", match.start())
        i = open_paren + 1
        depth = 1
        quote: str | None = None
        escaped = False
        line_comment = False
        block_comment = False
        start = i
        args: list[str] = []
        while i < len(text) and depth:
            char = text[i]
            next_char = text[i + 1] if i + 1 < len(text) else ""
            if line_comment:
                if char == "\n":
                    line_comment = False
            elif block_comment:
                if char == "*" and next_char == "/":
                    block_comment = False
                    i += 1
            elif quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char == "/" and next_char == "/":
                line_comment = True
                i += 1
            elif char == "/" and next_char == "*":
                block_comment = True
                i += 1
            elif char in ('"', "'"):
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    args.append(text[start:i].strip())
                    break
            elif char == "," and depth == 1:
                args.append(text[start:i].strip())
                start = i + 1
            i += 1
        if depth != 0:
            raise ProvisionError(f"unterminated {form} invocation")
        if not args or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args[0]):
            raise ProvisionError(f"invalid first argument to {form}")
        invocations.append((form, args))
    return invocations


def audit_langoptions(def_path: Path, header_path: Path, contract: dict) -> dict:
    spec = contract["langOptions"]
    text = def_path.read_text(encoding="utf-8")
    forms = set(spec["familyCounts"]) | set(spec["rejectedProductionFamilies"])
    first_production_field = text.find("LANGOPT(C99")
    if first_production_field < 0:
        raise ProvisionError("LangOptions.def has no pinned first production field")
    rows = parse_invocations(text[first_production_field:], forms)
    counts: dict[str, int] = {}
    names: list[str] = []
    for form, args in rows:
        counts[form] = counts.get(form, 0) + 1
        names.append(args[0])
    expected = spec["familyCounts"]
    if counts != expected:
        raise ProvisionError(f"LangOptions.def macro-family inventory mismatch: expected {expected}, got {counts}")
    if len(rows) != spec["generatedFieldCount"] or len(set(names)) != len(names):
        raise ProvisionError("LangOptions.def generated field count or uniqueness check failed")
    if any(form in counts for form in spec["rejectedProductionFamilies"]):
        raise ProvisionError("pinned LangOptions.def contains a rejected production macro family")
    header_text = header_path.read_text(encoding="utf-8")
    manual_start = header_text.find("class LangOptions : public LangOptionsBase")
    if manual_start < 0:
        raise ProvisionError("LangOptions.h does not contain the pinned LangOptions class")
    manual = header_text[manual_start:]
    missing = [name for name in spec["manualFields"] if re.search(r"\b" + re.escape(name) + r"\s*(?:[;{=])", manual) is None]
    if missing:
        raise ProvisionError("LangOptions.h manual member inventory is missing: " + ", ".join(missing))
    return {
        "inventoryEvidence": spec["inventoryEvidence"],
        "generatedFields": len(rows),
        "familyCounts": counts,
        "generatedFieldNames": names,
        "manualFields": spec["manualFields"],
        "manualFieldsCount": len(spec["manualFields"]),
        "definitionSha256": sha256(def_path.read_bytes()),
        "headerSha256": sha256(header_path.read_bytes()),
    }


def inventory_patch_files(source_root: Path) -> list[dict]:
    patches_root = source_root / "debian/patches"
    if not patches_root.is_dir():
        raise ProvisionError("extracted Ubuntu source has no debian/patches directory")
    rows = []
    for path in sorted(patches_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(source_root).as_posix()
        raw = path.read_bytes()
        touched: set[str] = set()
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if line.startswith(("--- ", "+++ ", "Index: ")):
                candidate = line.split(maxsplit=1)[1].split("\t", 1)[0].strip()
                candidate = candidate.removeprefix("a/").removeprefix("b/")
                if candidate not in ("/dev/null", "dev/null") and not candidate.startswith("/dev/null"):
                    touched.add(candidate)
        rows.append({"path": rel, "bytes": len(raw), "sha256": sha256(raw), "touchedPaths": sorted(touched)})
    series = patches_root / "series"
    if not series.is_file():
        raise ProvisionError("source package has no explicit quilt patch series")
    listed: list[str] = []
    for line in series.read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            patch_path = PurePosixPath(value.split()[0])
            if patch_path.is_absolute() or ".." in patch_path.parts:
                raise ProvisionError("unsafe path in quilt patch series")
            listed.append((PurePosixPath("debian/patches") / patch_path).as_posix())
    if len(set(listed)) != len(listed):
        raise ProvisionError("duplicate patch entry in quilt series")
    for rel in listed:
        if not (source_root / rel).is_file():
            raise ProvisionError(f"quilt series references a missing patch: {rel}")
    shipped_patches = {
        row["path"] for row in rows
        if row["path"].endswith((".patch", ".diff"))
    }
    if shipped_patches != set(listed):
        raise ProvisionError("complete patch inventory differs from the explicit quilt series")
    return rows


def audit_patches(source_root: Path, upstream_root: Path, output: Path, contract: dict) -> dict:
    patch_rows = inventory_patch_files(source_root)
    relevant = []
    differences = []
    relevant_set = set(contract["relevantFiles"])
    for rel in contract["relevantFiles"]:
        packaged = source_root / rel
        upstream = upstream_root / rel
        if not packaged.is_file() or not upstream.is_file():
            differences.append({"path": rel, "status": "missing", "packagedSha256": None, "upstreamSha256": None})
            continue
        packaged_bytes = packaged.read_bytes()
        upstream_bytes = upstream.read_bytes()
        row = {"path": rel, "bytes": len(packaged_bytes), "packagedSha256": sha256(packaged_bytes), "upstreamSha256": sha256(upstream_bytes)}
        row["status"] = "identical" if packaged_bytes == upstream_bytes else "different"
        row["patchesTouchingPath"] = [patch["path"] for patch in patch_rows if rel in patch["touchedPaths"]]
        relevant.append(row)
        if row["status"] != "identical":
            differences.append(row)
    if len(relevant_set) != 34:
        raise ProvisionError("the owned relevant-file audit list changed unexpectedly")
    patch_manifest = {"files": patch_rows}
    relevant_manifest = {"files": relevant}
    result = {
        "schemaVersion": 1,
        "status": "compatible" if not differences else "incompatible",
        "sourceRoot": "package-source",
        "upstreamRoot": "upstream-llvmorg-18.1.3",
        "patchCount": len([row for row in patch_rows if row["path"].endswith((".patch", ".diff"))]),
        "patchInventorySha256": sha256(canonical_json(patch_manifest)),
        "patchInventory": patch_rows,
        "relevantFileCount": len(relevant),
        "relevantFileManifestSha256": sha256(canonical_json(relevant_manifest)),
        "relevantFiles": relevant,
        "unresolvedContractRelevantDifferences": differences,
        "decision": "accept-distro-profile" if not differences else "reject-distro-profile",
    }
    atomic_write(output, canonical_json(result))
    if differences:
        raise ProvisionError("contract-relevant Ubuntu source differences detected; profile must be rejected")
    return result


def validate_probe_report(report: dict, inventory: dict, contract: dict) -> dict:
    spec = contract["langOptions"]
    if inventory.get("inventoryEvidence") != spec["inventoryEvidence"]:
        raise ProvisionError("LangOptions inventory is not labeled as the authenticated source-text scan")
    if inventory.get("generatedFields") != spec["generatedFieldCount"]:
        raise ProvisionError("probe LangOptions generated field count mismatch")
    if inventory.get("familyCounts") != spec["familyCounts"]:
        raise ProvisionError("probe LangOptions family counts mismatch")
    if inventory.get("manualFields") != spec["manualFields"] or inventory.get("manualFieldsCount") != spec["manualFieldsCount"]:
        raise ProvisionError("probe LangOptions manual fields mismatch")
    if report.get("callingConventions") != spec["callingConventions"]:
        raise ProvisionError("probe calling-convention inventory mismatch")
    if report.get("apiChecks") != spec["apiChecks"]:
        raise ProvisionError("probe API checks differ from the exact pinned LibTooling contract")
    if report.get("runtimeLangOptionsChecks") != spec["runtimeChecks"]:
        raise ProvisionError("probe did not observe the exact selected LangOptions runtime checks")
    macro_observations = report.get("macroObservations", {})
    if any(type(macro_observations.get(key)) is not int or macro_observations[key] < 1
           for key in ("expansionCount", "macroInfoChecks", "nonBuiltinClassifications")):
        raise ProvisionError("fixture did not observe bounded macro expansion and MacroInfo classification")
    validate_profile_compiler_identity(report.get("compilerVersion", ""), report.get("target", ""))
    return {
        "inventoryEvidence": inventory["inventoryEvidence"],
        "compilerVersion": report["compilerVersion"],
        "target": report["target"],
        "generatedFields": inventory["generatedFields"],
        "familyCounts": inventory["familyCounts"],
        "generatedFieldNames": inventory["generatedFieldNames"],
        "manualFields": inventory["manualFields"],
        "runtimeLangOptionsChecks": report["runtimeLangOptionsChecks"],
        "macroObservations": macro_observations,
        "callingConventions": report["callingConventions"],
        "apiChecks": report["apiChecks"],
        "definitionSha256": inventory["definitionSha256"],
        "headerSha256": inventory["headerSha256"],
    }


def validate_profile_compiler_identity(compiler_version: str, target: str) -> None:
    if re.match(r"^18\.1\.3(?:$|[ +\-])", str(compiler_version)) is None or target != "x86_64-pc-linux-gnu":
        raise ProvisionError("probe compiler version or target mismatch")


def command_acquire(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    candidate = acquire_candidate(contract, args.output, args.keyring)
    ensure_source_artifact_contract(candidate, contract)
    print(f"authenticated acquisition candidate sha256:{candidate['candidateSha256']}")
    print("candidate is not a locked or accepted Clang profile")
    return 0


def command_probe_snapshot_metadata(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    report = probe_snapshot_metadata(contract, args.snapshot, args.output, args.keyring)
    print(f"signed Snapshot metadata probe: {report['status']}")
    print(f"evidence sha256:{report['evidenceSha256']}")
    print(f"report: {args.output / 'snapshot-metadata-report.json'}")
    return 0


def command_audit_langoptions(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    inventory = audit_langoptions(args.definition, args.header, contract)
    atomic_write(args.output, canonical_json(inventory))
    print(
        f"source-scanned {inventory['generatedFields']} generated LangOptions fields and "
        f"{inventory['manualFieldsCount']} manual fields; runtime option assertions come from the LibTooling probe"
    )
    return 0


def command_audit_patches(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    try:
        result = audit_patches(args.package_source, args.upstream_source, args.output, contract)
    except ProvisionError as error:
        print(f"patch audit failed: {error}", file=sys.stderr)
        return 1
    print(f"verified complete patch inventory and {result['relevantFileCount']} contract-relevant files")
    return 0


def command_probe_report(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    report = json.loads(args.report.read_text(encoding="utf-8"))
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    checked = validate_probe_report(report, inventory, contract)
    checked["sourceSha256"] = sha256(args.source.read_bytes())
    checked["binarySha256"] = sha256(args.binary.read_bytes())
    atomic_write(args.output, canonical_json(checked))
    print("verified LibTooling probe report against the pinned 18.1.3 contract")
    return 0


def run_checked(command: list[str], *, timeout: int = 900, input_text: str | None = None,
                env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, input=input_text, timeout=timeout, env=env)
    if proc.returncode != 0:
        raise ProvisionError(f"command failed ({proc.returncode}): {command!r}\n{proc.stdout[-6000:]}")
    return proc


def memory_total_bytes() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return 0


def check_runner_bounds(workdir: Path, profile: dict) -> None:
    limits = profile["bounds"]
    if platform.machine() != "x86_64":
        raise ProvisionError(f"runner architecture must be x86_64, got {platform.machine()}")
    if shutil.disk_usage(workdir).free < limits["minFreeDiskBytes"]:
        raise ProvisionError("standard runner has less than the pinned free-disk budget")
    if memory_total_bytes() < limits["minMemoryBytes"]:
        raise ProvisionError("standard runner has less than the pinned memory budget")


def rootfs_env_args(contract: dict, extra: dict[str, str] | None = None) -> list[str]:
    child_environment = dict(contract["environment"])
    child_environment.update(extra or {})
    return ["/usr/bin/env", "-i", *[f"{key}={value}" for key, value in sorted(child_environment.items())]]


def rootfs_run(rootfs: Path, command: list[str], contract: dict, timeout: int = 300,
               environment: dict[str, str] | None = None) -> str:
    env_args = rootfs_env_args(contract, environment)
    return run_checked(
        ["sudo", "chroot", str(rootfs), *env_args, *command], timeout=timeout,
    ).stdout


def load_candidate(candidate_root: Path, contract: dict, keyring: Path) -> tuple[dict, list[dict]]:
    candidate_path = candidate_root / "acquisition-candidate.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    parsed = verify_candidate_data(candidate_root, candidate, contract, keyring)
    audit_path = candidate_root / "patch-audit.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    if audit.get("status") != "compatible" or candidate.get("patchAudit") != {
        key: audit[key] for key in ("status", "patchCount", "patchInventorySha256", "relevantFileCount", "relevantFileManifestSha256")
    }:
        raise ProvisionError("patch audit is missing, incompatible, or changed after acquisition")
    source_root = candidate_root / "source/package-source"
    upstream_root = candidate_root / "source/upstream/llvm-project-18.1.3.src"
    if not source_root.is_dir() and not upstream_root.exists():
        dsc_rows = [row for row in candidate["source"]["files"] if row["name"].endswith(".dsc")]
        if len(dsc_rows) != 1:
            raise ProvisionError("authenticated source inputs do not identify one .dsc for audit replay")
        dsc_path = candidate_root / dsc_rows[0]["path"]
        source_root.parent.mkdir(parents=True, exist_ok=True)
        extract = subprocess.run(
            ["dpkg-source", "-x", str(dsc_path), str(source_root)],
            cwd=dsc_path.parent, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=900,
        )
        if extract.returncode != 0:
            raise ProvisionError("dpkg-source rejected the authenticated .dsc/payload during audit replay: " + extract.stdout[-4000:])
        upstream_root = safe_extract_xz_tar(
            candidate_root / candidate["source"]["upstreamArchivePath"], candidate_root / "source/upstream",
        )
    elif not source_root.is_dir() or not upstream_root.is_dir():
        raise ProvisionError("only one audited source tree is present; refusing partial source state")
    reaudited_path = candidate_root / f"patch-audit.reverified-{os.getpid()}.json"
    reaudited = audit_patches(source_root, upstream_root, reaudited_path, contract)
    for key in ("patchCount", "patchInventorySha256", "relevantFileCount", "relevantFileManifestSha256"):
        if reaudited[key] != audit[key]:
            raise ProvisionError("patch audit inventory changed between acquisition and provisioning")
    return candidate, parsed


def package_metadata_map(indexes: list[dict]) -> dict[tuple[str, str, str], dict]:
    result: dict[tuple[str, str, str], dict] = {}
    for row in indexes:
        if not all(key in row for key in ("Package", "Version", "Architecture", "Filename", "Size", "SHA256")):
            continue
        if row["Architecture"] not in ("amd64", "all"):
            continue
        key = (row["Package"], row["Version"], row["Architecture"])
        entry = {
            "name": row["Package"], "version": row["Version"], "architecture": row["Architecture"],
            "suite": row["_suite"], "component": row["_component"], "file": row["Filename"],
            "bytes": int(row["Size"]), "sha256": row["SHA256"].lower(),
        }
        old = result.get(key)
        if old and (old["file"], old["bytes"], old["sha256"]) != (entry["file"], entry["bytes"], entry["sha256"]):
            raise ProvisionError(f"signed package indexes disagree for {key[0]}={key[1]}")
        if old is None:
            result[key] = entry
    return result


def package_metadata_for_keys(candidate_root: Path, candidate: dict,
                              wanted_keys: set[tuple[str, str, str]]) -> dict[tuple[str, str, str], dict]:
    if not wanted_keys:
        return {}
    wanted_names = {key[0] for key in wanted_keys}
    result: dict[tuple[str, str, str], dict] = {}
    for index in candidate["indexes"]:
        if index["kind"] != "binary-amd64":
            continue
        relative = PurePosixPath(index["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ProvisionError("candidate package index path is unsafe")
        path = candidate_root.joinpath(*relative.parts)
        packed = path.read_bytes()
        if len(packed) != index["bytes"] or sha256(packed) != index["sha256"]:
            raise ProvisionError("authenticated binary index changed before package closure extraction")
        for row in iter_compressed_index(path):
            if row.get("Package") not in wanted_names or row.get("Architecture") not in ("amd64", "all"):
                continue
            key = (row.get("Package", ""), row.get("Version", ""), row.get("Architecture", ""))
            if key not in wanted_keys:
                continue
            if not all(field in row for field in ("Filename", "Size", "SHA256")):
                raise ProvisionError(f"signed package row lacks file identity for {key[0]}={key[1]}")
            filename = PurePosixPath(row["Filename"])
            if (filename.is_absolute() or ".." in filename.parts or not filename.parts or
                    not row["Filename"].endswith(".deb") or not row["Size"].isdigit() or
                    not re.fullmatch(r"[0-9a-fA-F]{64}", row["SHA256"])):
                raise ProvisionError(f"signed package file identity is malformed for {key[0]}={key[1]}")
            entry = {
                "name": key[0], "version": key[1], "architecture": key[2],
                "suite": index["suite"], "component": index["component"], "file": row["Filename"],
                "bytes": int(row["Size"]), "sha256": row["SHA256"].lower(),
            }
            old = result.get(key)
            if old and (old["file"], old["bytes"], old["sha256"]) != (entry["file"], entry["bytes"], entry["sha256"]):
                raise ProvisionError(f"signed package indexes disagree for {key[0]}={key[1]}")
            if old is None:
                result[key] = entry
    missing = wanted_keys - set(result)
    if missing:
        raise ProvisionError("installed/downloaded package is absent from signed binary indexes: " + repr(sorted(missing)))
    return result


def installed_package_keys(rootfs: Path, contract: dict) -> set[tuple[str, str, str]]:
    out = rootfs_run(rootfs, ["/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"], contract)
    keys = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            raise ProvisionError(f"invalid dpkg-query row: {line!r}")
        name, version, architecture = parts
        key = (name, version, architecture)
        if key in keys:
            raise ProvisionError(f"duplicate installed package row: {key}")
        keys.add(key)
    return keys


def installed_packages(rootfs: Path, records: dict[tuple[str, str, str], dict],
                       expected_keys: set[tuple[str, str, str]], contract: dict) -> list[dict]:
    keys = installed_package_keys(rootfs, contract)
    if keys != expected_keys:
        missing = expected_keys - keys
        unexpected = keys - expected_keys
        raise ProvisionError(f"installed package closure differs from the authenticated expected set; missing={sorted(missing)}, unexpected={sorted(unexpected)}")
    if keys - set(records):
        raise ProvisionError("installed package is missing authenticated package metadata")
    result = [records[key] for key in sorted(keys)]
    result.sort(key=lambda row: (row["name"], row["architecture"], row["version"]))
    if not result or len(result) > contract["profile"]["bounds"]["maxPackageCount"]:
        raise ProvisionError("installed package closure is empty or exceeds package-count bound")
    by_name = {row["name"]: row for row in result}
    for pin in contract["profile"]["binaryRoots"]:
        actual = by_name.get(pin["name"])
        if not actual or actual["version"] != pin["version"]:
            raise ProvisionError(f"installed root package mismatch: {pin['name']} expected {pin['version']}")
    cpp_dev = by_name["libclang-cpp18-dev"]
    cpp_runtime = by_name["libclang-cpp18"]
    if cpp_dev["version"] != cpp_runtime["version"]:
        raise ProvisionError("installed libclang-cpp18-dev/runtime versions do not match")
    return result


def rootfs_path(rootfs: Path, absolute_path: str) -> Path:
    pure = PurePosixPath(absolute_path)
    if not pure.is_absolute() or ".." in pure.parts:
        raise ProvisionError(f"unsafe path reported by toolchain: {absolute_path}")
    result = rootfs.joinpath(*pure.parts[1:])
    resolved = result.resolve(strict=True)
    try:
        resolved.relative_to(rootfs.resolve(strict=True))
    except ValueError as error:
        raise ProvisionError(f"toolchain path escapes the authenticated rootfs: {absolute_path}") from error
    return result


def file_entry(rootfs: Path, absolute_path: str) -> dict:
    path = rootfs_path(rootfs, absolute_path)
    if path.is_symlink():
        target = os.readlink(path)
        data = b"symlink\0" + target.encode("utf-8")
        return {"path": absolute_path, "bytes": len(target.encode()), "sha256": sha256(data)}
    if not path.is_file():
        raise ProvisionError(f"expected regular runtime/resource file: {absolute_path}")
    data = path.read_bytes()
    return {"path": absolute_path, "bytes": len(data), "sha256": sha256(data)}


def manifest(entries: list[dict]) -> dict:
    entries.sort(key=lambda row: row["path"])
    content = canonical_json({"entries": entries})
    return {"entryCount": len(entries), "bytes": len(content), "sha256": sha256(content), "entries": entries}


def symlink_chain(rootfs: Path, logical_path: str) -> tuple[list[str], Path]:
    current = rootfs_path(rootfs, logical_path)
    chain = []
    visited = set()
    while current.is_symlink():
        rel = current.relative_to(rootfs).as_posix()
        if rel in visited or len(chain) > 16:
            raise ProvisionError(f"symlink cycle/depth overflow for {logical_path}")
        visited.add(rel)
        target = os.readlink(current)
        chain.append(f"/{rel} -> {target}")
        candidate = current.parent / target if not target.startswith("/") else rootfs / target.lstrip("/")
        resolved = candidate.resolve(strict=True)
        try:
            resolved.relative_to(rootfs.resolve(strict=True))
        except ValueError as error:
            raise ProvisionError(f"driver symlink chain escapes rootfs: {logical_path}") from error
        # Keep each lexical link above, but continue traversal from the
        # canonical in-root target so a relative target containing '..' does
        # not leak into the authenticated resolvedPath.
        current = resolved
    if not current.is_file():
        raise ProvisionError(f"driver resolves to non-regular file: {logical_path}")
    return chain, current


def driver_record(rootfs: Path, logical_path: str, role: str, version_output: str) -> dict:
    chain, binary = symlink_chain(rootfs, logical_path)
    payload = binary.read_bytes()
    if "18.1.3" not in version_output:
        raise ProvisionError(f"{role} version output does not identify Clang 18.1.3")
    return {
        "role": role, "path": logical_path, "symlinkChain": chain,
        "resolvedPath": "/" + binary.relative_to(rootfs).as_posix(),
        "bytes": len(payload), "sha256": sha256(payload),
        "mode": f"{binary.stat().st_mode & 0o7777:04o}", "versionOutput": version_output,
    }


def runtime_dependencies(rootfs: Path, logical_paths: list[str], contract: dict) -> list[dict]:
    paths: set[str] = set()
    for logical in logical_paths:
        output = rootfs_run(rootfs, ["/usr/bin/ldd", logical], contract)
        for line in output.splitlines():
            match = re.search(r"=>\s+(/\S+)", line)
            if match:
                paths.add(match.group(1))
            else:
                match = re.match(r"\s*(/\S+)\s+\(0x[0-9a-fA-F]+\)", line)
                if match:
                    paths.add(match.group(1))
    # The linker-facing C++ API is a separate authenticated shared-library input.
    paths.add("/usr/lib/llvm-18/lib/libclang-cpp.so")
    paths.add("/usr/lib/llvm-18/lib/libLLVM-18.so")
    entries = []
    for path in sorted(paths):
        chain, target = symlink_chain(rootfs, path)
        if target.is_file():
            content = target.read_bytes()
            target_path = "/" + target.relative_to(rootfs).as_posix()
            entries.append({"path": target_path, "bytes": len(content), "sha256": sha256(content)})
            for link in chain:
                entries.append(file_entry(rootfs, link.split(" -> ", 1)[0]))
    # Same file path can appear through multiple executable mappings; retain one row.
    by_path = {row["path"]: row for row in entries}
    return sorted(by_path.values(), key=lambda row: row["path"])


def resource_manifest(rootfs: Path, resource_dir: str) -> dict:
    root = rootfs_path(rootfs, resource_dir)
    if not root.is_dir():
        raise ProvisionError("Clang reported a missing resource-header directory")
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ProvisionError("Clang resource directory contains a symlink rejected by the A profile loader")
        if path.is_file():
            absolute = "/" + path.relative_to(rootfs).as_posix()
            entries.append(file_entry(rootfs, absolute))
        elif not path.is_dir():
            raise ProvisionError("Clang resource directory contains a non-regular entry")
    if not entries:
        raise ProvisionError("Clang resource directory has no files")
    return manifest(entries)


def frontend_resource_manifest_sha256(resource_dir: str, resource_record: dict) -> str:
    """Recompute A's domain-separated resource digest from the recorded files."""
    entries = resource_record.get("entries", [])
    prefix = resource_dir.rstrip("/") + "/"
    files = []
    for row in entries:
        path = row.get("path", "")
        if not isinstance(path, str) or not path.startswith(prefix) or path == prefix:
            raise ProvisionError("recorded resource file is outside its pinned resource directory")
        if not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))):
            raise ProvisionError("recorded resource file digest is malformed")
        files.append({"path": "toolchain" + path, "sha256": row["sha256"]})
    files.sort(key=lambda row: row["path"].encode("utf-8"))
    preimage = {"files": files, "resolvedResourceDirectory": "toolchain" + resource_dir}
    payload = canonical_json(preimage).removesuffix(b"\n")
    return sha256(b"decomp-thing/generic-template/resource-directory/v1\0" + payload)


def verify_recorded_resource_manifest(rootfs: Path, record: dict) -> dict:
    actual = resource_manifest(rootfs, record["resourceDirectory"])
    if actual != record.get("resources"):
        raise ProvisionError("resource-directory bytes differ from the authenticated build-record manifest")
    return actual


def normalize_rootfs(rootfs: Path, epoch: int) -> None:
    for rel in ("var/cache/apt/archives", "var/lib/apt/lists", "var/log/apt", "var/log/journal", "tmp", "var/tmp"):
        target = rootfs / rel
        if not target.exists() or target.is_symlink():
            continue
        run_checked(["sudo", "find", str(target), "-mindepth", "1", "-maxdepth", "1", "!", "-name", "partial", "-exec", "rm", "-rf", "--", "{}", "+"])
        partial = target / "partial"
        if partial.is_dir() and not partial.is_symlink():
            run_checked(["sudo", "find", str(partial), "-mindepth", "1", "-maxdepth", "1", "-exec", "rm", "-rf", "--", "{}", "+"])
    for rel in ("var/log/dpkg.log", "var/log/alternatives.log", "var/log/bootstrap.log", "var/lib/systemd/random-seed",
                "var/cache/ldconfig/aux-cache"):
        run_checked(["sudo", "rm", "-f", str(rootfs / rel)])
    run_checked(["sudo", "truncate", "-s", "0", str(rootfs / "etc/machine-id")])
    run_checked(["sudo", "find", str(rootfs), "-xdev", "-exec", "touch", "-h", "-d", f"@{epoch}", "{}", "+"], timeout=300)


def deterministic_rootfs_tar(rootfs: Path, destination: Path, epoch: int) -> dict:
    normalize_rootfs(rootfs, epoch)
    command = [
        "sudo", "env", "LC_ALL=C", "tar", "--sort=name", "--format=posix", "--numeric-owner", "--owner=0", "--group=0",
        f"--mtime=@{epoch}", "--pax-option=delete=atime,delete=ctime",
        "-cf", str(destination), "-C", str(rootfs), ".",
    ]
    run_checked(command, timeout=600)
    payload = destination.read_bytes()
    return {"bytes": len(payload), "sha256": sha256(payload)}


def create_oci_layout(rootfs_tar: Path, output: Path, profile_id: str, epoch: int) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    blobs = output / "blobs/sha256"
    blobs.mkdir(parents=True)
    rootfs_payload = rootfs_tar.read_bytes()
    diff_id = "sha256:" + sha256(rootfs_payload)
    layer = gzip.compress(rootfs_payload, compresslevel=9, mtime=0)
    layer_digest = sha256(layer)
    (blobs / layer_digest).write_bytes(layer)
    created = "2024-04-25T00:00:00Z"
    config = {
        "architecture": "amd64", "os": "linux", "created": created,
        "config": {
            "Env": [
                "LC_ALL=C", "TZ=UTC", "SOURCE_DATE_EPOCH=1714003200",
                "PATH=/usr/lib/llvm-18/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            ],
            "Labels": {"org.opencontainers.image.title": profile_id, "org.opencontainers.image.version": "18.1.3"},
            "WorkingDir": "/",
        },
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created": created, "created_by": "authenticated Noble snapshot package closure"}],
    }
    config_bytes = canonical_json(config)
    config_digest = sha256(config_bytes)
    (blobs / config_digest).write_bytes(config_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + config_digest, "size": len(config_bytes)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + layer_digest, "size": len(layer)}],
    }
    manifest_bytes = canonical_json(manifest)
    manifest_digest = sha256(manifest_bytes)
    (blobs / manifest_digest).write_bytes(manifest_bytes)
    (output / "oci-layout").write_bytes(canonical_json({"imageLayoutVersion": "1.0.0"}))
    index = {
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:" + manifest_digest, "size": len(manifest_bytes),
            "annotations": {"org.opencontainers.image.ref.name": "clang-18.1.3-noble-amd64"},
        }],
    }
    (output / "index.json").write_bytes(canonical_json(index))
    return {"format": "oci-image-layout-v1", "manifestSha256": manifest_digest, "imageDigest": "sha256:" + manifest_digest,
            "layerBytes": len(layer), "layerSha256": layer_digest, "configSha256": config_digest}


def verify_oci_archive(path: Path, record: dict, max_bytes: int) -> None:
    if path.stat().st_size > max_bytes:
        raise ProvisionError("OCI archive exceeds the configured artifact byte budget")
    if record.get("imageArtifact", {}) != {"bytes": path.stat().st_size, "sha256": sha256_file(path)}:
        raise ProvisionError("OCI archive bytes differ from the checksummed build-record artifact identity")
    try:
        with tarfile.open(path, mode="r:") as archive:
            members: dict[str, tarfile.TarInfo] = {}
            for member in archive:
                if len(members) >= 16:
                    raise ProvisionError("OCI archive contains too many members")
                name = member.name.removeprefix("./")
                pure = PurePosixPath(name)
                if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                    raise ProvisionError("OCI archive contains an unsafe member path")
                if not member.isfile() or member.issym() or member.islnk() or name in members:
                    raise ProvisionError("OCI archive contains a non-regular or duplicate member")
                members[name] = member
            required = {"oci-layout", "index.json"}
            if not required.issubset(members):
                raise ProvisionError("OCI archive is missing its layout or index")

            def read_small(name: str, maximum: int = 1024 * 1024) -> bytes:
                member = members.get(name)
                if member is None or member.size > maximum:
                    raise ProvisionError(f"OCI archive is missing or oversized {name}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ProvisionError(f"OCI archive member is unreadable: {name}")
                data = stream.read(maximum + 1)
                if len(data) != member.size:
                    raise ProvisionError(f"OCI archive member size changed: {name}")
                return data

            if json.loads(read_small("oci-layout")) != {"imageLayoutVersion": "1.0.0"}:
                raise ProvisionError("OCI layout version is unsupported")
            index = json.loads(read_small("index.json"))
            descriptors = index.get("manifests", [])
            if index.get("schemaVersion") != 2 or len(descriptors) != 1:
                raise ProvisionError("OCI index must contain exactly one image manifest")
            manifest_desc = descriptors[0]
            digest = record["image"]["imageDigest"]
            if manifest_desc.get("digest") != digest:
                raise ProvisionError("OCI index manifest digest differs from the build record")
            manifest_name = "blobs/sha256/" + digest.removeprefix("sha256:")
            manifest_bytes = read_small(manifest_name)
            if sha256(manifest_bytes) != digest.removeprefix("sha256:") or len(manifest_bytes) != manifest_desc.get("size"):
                raise ProvisionError("OCI manifest content does not match its index digest/size")
            manifest = json.loads(manifest_bytes)
            config_desc = manifest.get("config", {})
            layers = manifest.get("layers", [])
            if len(layers) != 1 or manifest.get("schemaVersion") != 2:
                raise ProvisionError("OCI manifest must contain exactly one rootfs layer")
            config_digest = config_desc.get("digest", "")
            config_name = "blobs/sha256/" + config_digest.removeprefix("sha256:")
            config_bytes = read_small(config_name)
            if type(config_desc.get("size")) is not int or config_desc["size"] != len(config_bytes):
                raise ProvisionError("OCI image config descriptor size differs from the config blob length")
            if not config_digest.startswith("sha256:") or sha256(config_bytes) != config_digest.removeprefix("sha256:"):
                raise ProvisionError("OCI image config content does not match its digest")
            config = json.loads(config_bytes)
            rootfs_identity = record["rootfs"]
            expected_diff_id = "sha256:" + rootfs_identity["sha256"]
            if config.get("rootfs", {}).get("diff_ids") != [expected_diff_id]:
                raise ProvisionError("OCI rootfs diff ID differs from the deterministic rootfs tar identity")
            layer = layers[0]
            layer_digest = layer.get("digest", "")
            layer_name = "blobs/sha256/" + layer_digest.removeprefix("sha256:")
            member = members.get(layer_name)
            if not layer_digest.startswith("sha256:") or member is None or member.size != layer.get("size"):
                raise ProvisionError("OCI rootfs layer descriptor is missing or malformed")
            stream = archive.extractfile(member)
            if stream is None:
                raise ProvisionError("OCI rootfs layer is unreadable")
            layer_hash = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                layer_hash.update(block)
            if layer_hash.hexdigest() != layer_digest.removeprefix("sha256:"):
                raise ProvisionError("OCI compressed layer bytes differ from the manifest digest")
            stream = archive.extractfile(member)
            if stream is None:
                raise ProvisionError("OCI rootfs layer is unreadable")
            expanded_hash = hashlib.sha256()
            expanded_bytes = 0
            with gzip.GzipFile(fileobj=stream, mode="rb") as expanded:
                for block in iter(lambda: expanded.read(1024 * 1024), b""):
                    expanded_bytes += len(block)
                    if expanded_bytes > rootfs_identity["bytes"]:
                        raise ProvisionError("OCI expanded layer exceeds the recorded rootfs byte count")
                    expanded_hash.update(block)
            if expanded_bytes != rootfs_identity["bytes"] or expanded_hash.hexdigest() != rootfs_identity["sha256"]:
                raise ProvisionError("OCI expanded layer differs from the deterministic rootfs tar")
            expected_names = {
                "oci-layout", "index.json", manifest_name, config_name, layer_name,
            }
            if set(members) != expected_names:
                raise ProvisionError("OCI archive contains unrecorded files or blobs")
    except (OSError, tarfile.TarError, EOFError, gzip.BadGzipFile, zlib.error, json.JSONDecodeError) as error:
        raise ProvisionError(f"could not verify OCI image artifact: {error}") from error


def provision_rootfs(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    profile = contract["profile"]
    args.workdir.mkdir(parents=True, exist_ok=True)
    if args.rootfs.exists() or args.output.exists():
        raise ProvisionError("rootfs and evidence output paths must not exist")
    candidate, indexes = load_candidate(args.acquisition, contract, args.keyring)
    shutil.rmtree(args.acquisition / "source/package-source")
    shutil.rmtree(args.acquisition / "source/upstream")
    check_runner_bounds(args.workdir, profile)
    profile_root = args.rootfs
    profile_root.parent.mkdir(parents=True, exist_ok=True)
    snapshot = profile["snapshotBase"]
    debootstrap_command = [
        "sudo", "env", "LC_ALL=C", "TZ=UTC", f"SOURCE_DATE_EPOCH={contract['environment']['SOURCE_DATE_EPOCH']}",
        "debootstrap", "--arch=amd64", "--variant=minbase", "--components=main,universe",
        f"--keyring={args.keyring}", "noble", str(profile_root), snapshot,
    ]
    run_checked(debootstrap_command, timeout=900)
    bootstrap_package_keys = installed_package_keys(profile_root, contract)

    sources = "\n".join(
        f"deb [check-valid-until=no signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] {snapshot} {suite} main universe"
        for suite in profile["suites"]
    ) + "\n"
    sources_path = args.workdir / f"clang-source-list-{args.label}.list"
    atomic_write(sources_path, sources.encode())
    run_checked(["sudo", "install", "-m", "0644", str(sources_path), str(profile_root / "etc/apt/sources.list")])
    apt_prefix = ["/usr/bin/apt-get", "-o", "Acquire::Check-Valid-Until=false", "-o", "Acquire::Retries=0",
                  "-o", "APT::Get::AllowUnauthenticated=false", "-o", "APT::Install-Recommends=false"]
    rootfs_run(profile_root, [*apt_prefix, "update"], contract, timeout=600,
               environment={"DEBIAN_FRONTEND": "noninteractive"})
    pinned_args = [f"{row['name']}={row['version']}" for row in profile["binaryRoots"]]
    rootfs_run(profile_root, [*apt_prefix, "install", "--yes", "--no-install-recommends", "--download-only", *pinned_args], contract, timeout=900,
               environment={"DEBIAN_FRONTEND": "noninteractive"})
    downloaded_debs = sorted((profile_root / "var/cache/apt/archives").glob("*.deb"))
    if not downloaded_debs:
        raise ProvisionError("APT download-only phase produced no package archives")
    downloaded_identities = []
    for deb in downloaded_debs:
        fields = run_checked(["dpkg-deb", "--field", str(deb), "Package", "Version", "Architecture"]).stdout.splitlines()
        if len(fields) != 3:
            raise ProvisionError(f"could not read package identity from {deb.name}")
        downloaded_identities.append((deb, tuple(fields)))
    downloaded_keys = {key for _, key in downloaded_identities}
    if len(downloaded_keys) != len(downloaded_identities):
        raise ProvisionError("APT download-only phase produced duplicate package identities")
    downloaded_slots = {(name, architecture) for name, _, architecture in downloaded_keys}
    expected_final_keys = {
        key for key in bootstrap_package_keys if (key[0], key[2]) not in downloaded_slots
    } | downloaded_keys
    metadata = package_metadata_for_keys(args.acquisition, candidate, bootstrap_package_keys | downloaded_keys)
    downloaded_rows = []
    for deb, key in downloaded_identities:
        expected = metadata[key]
        data = deb.read_bytes()
        if len(data) != expected["bytes"] or sha256(data) != expected["sha256"]:
            raise ProvisionError(f"downloaded .deb hash/length differs from signed Packages metadata: {key[0]}")
        downloaded_rows.append(expected)
    downloaded_names = {row["name"] for row in downloaded_rows}
    if not {row["name"] for row in profile["binaryRoots"]}.issubset(downloaded_names):
        raise ProvisionError("APT download-only phase did not acquire every explicitly pinned toolchain root package")
    rootfs_run(profile_root, [*apt_prefix, "install", "--yes", "--no-install-recommends", *pinned_args], contract, timeout=900,
               environment={"DEBIAN_FRONTEND": "noninteractive"})
    rootfs_run(profile_root, [*apt_prefix, "check"], contract, timeout=300,
               environment={"DEBIAN_FRONTEND": "noninteractive"})

    package_rows = installed_packages(profile_root, metadata, expected_final_keys, contract)
    package_total = sum(row["bytes"] for row in package_rows)
    if package_total > profile["bounds"]["maxAcquisitionBytes"]:
        raise ProvisionError("installed package closure exceeds cumulative package-byte budget")
    c_version = rootfs_run(profile_root, ["/usr/bin/clang-18", "--version"], contract).strip()
    cxx_version = rootfs_run(profile_root, ["/usr/bin/clang++-18", "--version"], contract).strip()
    tools = [
        driver_record(profile_root, "/usr/bin/clang-18", "c-driver", c_version),
        driver_record(profile_root, "/usr/bin/clang++-18", "cxx-driver", cxx_version),
    ]
    reported_resource_dir = rootfs_run(profile_root, ["/usr/bin/clang-18", "-print-resource-dir"], contract).strip()
    if not reported_resource_dir.startswith("/usr/lib/llvm-18/"):
        raise ProvisionError(f"Clang resource directory is outside the versioned LLVM 18 root: {reported_resource_dir}")
    resource_path = rootfs_path(profile_root, reported_resource_dir).resolve(strict=True)
    try:
        resource_dir = "/" + resource_path.relative_to(profile_root.resolve(strict=True)).as_posix()
    except ValueError as error:
        raise ProvisionError("resolved Clang resource directory escapes the authenticated rootfs") from error
    if not resource_dir.startswith("/usr/lib/llvm-18/") or not resource_path.is_dir():
        raise ProvisionError(f"resolved Clang resource directory is not a versioned LLVM 18 directory: {resource_dir}")
    resource_files = resource_manifest(profile_root, resource_dir)

    probe_source = ROOT / "oracle/clang/18.1.3/libtooling-probe.cpp"
    fixture = ROOT / "oracle/clang/18.1.3/fixtures/libtooling-positive.cpp"
    probe_in_root = profile_root / "tmp/clang18-libtooling-probe.cpp"
    fixture_in_root = profile_root / "tmp/clang18-positive.cpp"
    shutil.copyfile(probe_source, probe_in_root)
    shutil.copyfile(fixture, fixture_in_root)
    probe_in_root.chmod(0o444)
    fixture_in_root.chmod(0o444)
    libdir = rootfs_run(profile_root, ["/usr/bin/llvm-config-18", "--libdir"], contract).strip()
    cxxflags = shlex.split(rootfs_run(profile_root, ["/usr/bin/llvm-config-18", "--cxxflags"], contract).strip())
    probe_path = "/tmp/clang18-libtooling-probe"
    compile_command = ["/usr/bin/clang++-18", *cxxflags, "--target=x86_64-pc-linux-gnu", "-std=c++17", "/tmp/clang18-libtooling-probe.cpp",
                       f"-L{libdir}", f"-Wl,-rpath,{libdir}", "-lclang-cpp", "-lLLVM-18", "-o", probe_path]
    rootfs_run(profile_root, compile_command, contract, timeout=600)
    runtime_report = rootfs_run(profile_root, [probe_path, "/tmp/clang18-positive.cpp"], contract, timeout=120)
    runtime_json = json.loads(runtime_report)
    inventory = audit_langoptions(
        rootfs_path(profile_root, "/usr/lib/llvm-18/include/clang/Basic/LangOptions.def"),
        rootfs_path(profile_root, "/usr/lib/llvm-18/include/clang/Basic/LangOptions.h"), contract,
    )
    probe_checked = validate_probe_report(runtime_json, inventory, contract)
    probe_checked["sourceSha256"] = sha256(probe_source.read_bytes())
    probe_checked["binarySha256"] = sha256(rootfs_path(profile_root, probe_path).read_bytes())
    probe_checked["apiChecks"] = runtime_json["apiChecks"]
    probe_checked["fixtureSha256"] = sha256(fixture.read_bytes())

    runtime_files = runtime_dependencies(profile_root, ["/usr/bin/clang-18", "/usr/bin/clang++-18", probe_path], contract)
    runtime_manifest = manifest(runtime_files)
    epoch = int(contract["environment"]["SOURCE_DATE_EPOCH"])
    rootfs_tar_path = args.workdir / f"clang-rootfs-{args.label}.tar"
    rootfs_identity = deterministic_rootfs_tar(profile_root, rootfs_tar_path, epoch)
    if rootfs_identity["bytes"] > profile["bounds"]["maxArtifactBytes"]:
        raise ProvisionError("canonical rootfs tar exceeds the artifact byte budget")
    args.output.mkdir(parents=True, exist_ok=False)
    oci_path = args.output / "oci-layout"
    image_record = create_oci_layout(rootfs_tar_path, oci_path, profile["id"], epoch)
    oci_archive = args.output / "clang-18.1.3-noble-amd64.oci.tar"
    run_checked(["tar", "--sort=name", "--format=posix", "--numeric-owner", "--owner=0", "--group=0",
                 f"--mtime=@{epoch}", "--pax-option=delete=atime,delete=ctime", "-cf", str(oci_archive),
                 "-C", str(oci_path), "blobs/sha256/" + image_record["configSha256"],
                 "blobs/sha256/" + image_record["layerSha256"],
                 "blobs/sha256/" + image_record["manifestSha256"], "index.json", "oci-layout"], timeout=600)
    if oci_archive.stat().st_size > profile["bounds"]["maxArtifactBytes"]:
        raise ProvisionError("OCI image artifact exceeds the configured public-runner artifact cap")
    image_artifact_identity = {"bytes": oci_archive.stat().st_size, "sha256": sha256_file(oci_archive)}
    shutil.rmtree(oci_path)

    repos = []
    for row in candidate["repositories"]:
        rel = row["inRelease"]
        repos.append({
            "suite": row["suite"], "inRelease": rel["finalUrl"], "sha256": rel["sha256"],
            "bytes": rel["bytes"], "signerPrimaryFingerprint": row["signerPrimaryFingerprint"],
        })
    source_files = []
    dsc_entry = None
    for row in candidate["source"]["files"]:
        name = row["name"]
        role = "dsc" if name.endswith(".dsc") else ("debian-patches" if ".debian." in name else "upstream-source")
        converted = {"name": name, "bytes": row["bytes"], "sha256": row["sha256"], "role": role}
        source_files.append(converted)
        if role == "dsc":
            dsc_entry = {"bytes": row["bytes"], "sha256": row["sha256"]}
    record = {
        "schemaVersion": 1,
        "buildSystem": "ubuntu-snapshot-debootstrap-apt",
        "profile": {"id": profile["id"], "architecture": profile["architecture"], "target": profile["target"],
                    "snapshot": profile["snapshot"], "codename": profile["codename"]},
        "acquisition": {
            "repositories": repos,
            "ubuntuKeyring": candidate["trustedKeyring"],
            "candidateSha256": candidate["candidateSha256"],
            "sourceIndexesSha256": sha256(canonical_json([row for row in candidate["indexes"] if row["kind"] == "source"])),
            "binaryIndexesSha256": sha256(canonical_json([row for row in candidate["indexes"] if row["kind"] == "binary-amd64"])),
            "signatureFingerprints": [row["signerPrimaryFingerprint"] for row in candidate["repositories"]],
        },
        "source": {"package": "llvm-toolchain-18", "version": "1:18.1.3-1ubuntu1",
                   "upstreamTag": contract["profile"]["upstream"]["tag"], "dsc": dsc_entry,
                   "files": source_files,
                   "upstreamArchive": {"bytes": candidate["source"]["upstreamArchive"]["bytes"], "sha256": candidate["source"]["upstreamArchive"]["sha256"]},
                   "upstreamSignature": {"bytes": candidate["source"]["upstreamSignature"]["bytes"], "sha256": candidate["source"]["upstreamSignature"]["sha256"]},
                   "upstreamKeyring": {"bytes": candidate["source"]["upstreamKeyring"]["bytes"],
                                       "sha256": candidate["source"]["upstreamKeyring"]["sha256"]}},
        "patchAudit": candidate["patchAudit"],
        "packages": package_rows,
        "downloadedPackages": downloaded_rows,
        "tools": tools,
        "runtime": runtime_manifest,
        "resources": resource_files,
        "resourceDirectory": resource_dir,
        "probe": probe_checked,
        "recipe": recipe_identity(),
        "environment": contract["environment"],
        "commands": {
            "debootstrap": ["sudo", "env", "LC_ALL=C", "TZ=UTC",
             f"SOURCE_DATE_EPOCH={contract['environment']['SOURCE_DATE_EPOCH']}",
             "debootstrap", "--arch=amd64", "--variant=minbase", "--components=main,universe",
             "--keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg", "noble", "<PROFILE_ROOT>", snapshot],
            "writeAptSources": ["sudo", "install", "-m", "0644", "<SOURCE_LIST>",
                                 "<PROFILE_ROOT>/etc/apt/sources.list"],
            "aptUpdate": ["chroot", "<PROFILE_ROOT>",
                          *rootfs_env_args(contract, {"DEBIAN_FRONTEND": "noninteractive"}),
                          *apt_prefix, "update"],
            "aptDownloadOnly": ["chroot", "<PROFILE_ROOT>",
                                *rootfs_env_args(contract, {"DEBIAN_FRONTEND": "noninteractive"}),
                                *apt_prefix, "install", "--yes", "--no-install-recommends", "--download-only", *pinned_args],
            "aptInstall": ["chroot", "<PROFILE_ROOT>",
                           *rootfs_env_args(contract, {"DEBIAN_FRONTEND": "noninteractive"}),
                           *apt_prefix, "install", "--yes", "--no-install-recommends", *pinned_args],
            "clangCVersion": ["chroot", "<PROFILE_ROOT>", *rootfs_env_args(contract),
                              "/usr/bin/clang-18", "--version"],
            "clangCxxVersion": ["chroot", "<PROFILE_ROOT>", *rootfs_env_args(contract),
                                "/usr/bin/clang++-18", "--version"],
            "clangResourceDirectory": ["chroot", "<PROFILE_ROOT>", *rootfs_env_args(contract),
                                       "/usr/bin/clang-18", "-print-resource-dir"],
            "llvmConfigLibdir": ["chroot", "<PROFILE_ROOT>", *rootfs_env_args(contract),
                                 "/usr/bin/llvm-config-18", "--libdir"],
            "llvmConfigCxxflags": ["chroot", "<PROFILE_ROOT>", *rootfs_env_args(contract),
                                   "/usr/bin/llvm-config-18", "--cxxflags"],
            "probeCompile": ["chroot", "<PROFILE_ROOT>", *rootfs_env_args(contract), *compile_command],
            "probeRun": ["chroot", "<PROFILE_ROOT>", *rootfs_env_args(contract),
                         probe_path, "/tmp/clang18-positive.cpp"],
            "rootfsTar": ["sudo", "env", "LC_ALL=C", "tar", "--sort=name", "--format=posix",
                          "--numeric-owner", "--owner=0", "--group=0", f"--mtime=@{epoch}",
                          "--pax-option=delete=atime,delete=ctime", "-cf", "<ROOTFS_TAR>",
                          "-C", "<PROFILE_ROOT>", "."],
            "ociArchive": ["tar", "--sort=name", "--format=posix", "--numeric-owner", "--owner=0",
                           "--group=0", f"--mtime=@{epoch}", "--pax-option=delete=atime,delete=ctime",
                           "-cf", "<OCI_ARCHIVE>", "-C", "<OCI_LAYOUT>",
                           "blobs/sha256/<CONFIG_SHA256>", "blobs/sha256/<LAYER_SHA256>",
                           "blobs/sha256/<MANIFEST_SHA256>", "index.json", "oci-layout"],
        },
        "rootfs": rootfs_identity,
        "image": {"format": image_record["format"], "manifestSha256": image_record["manifestSha256"], "imageDigest": image_record["imageDigest"]},
        "imageArtifact": image_artifact_identity,
    }
    record_path = args.output / "build-record-fragment.json"
    atomic_write(record_path, canonical_json(record))
    atomic_write(args.output / "probe-report.json", canonical_json(probe_checked))
    if args.rootfs_tar_output is not None:
        if args.rootfs_tar_output.exists() or args.rootfs_tar_output.is_symlink():
            raise ProvisionError("verified rootfs tar output path must not already exist")
        output_parent = args.output.resolve(strict=True)
        if (args.rootfs_tar_output.parent != output_parent or
                args.rootfs_tar_output.parent.resolve(strict=True) != output_parent):
            raise ProvisionError("verified rootfs tar output must be inside the canonical run output directory")
        os.replace(rootfs_tar_path, args.rootfs_tar_output)
    else:
        rootfs_tar_path.unlink()
    if not args.keep_rootfs:
        run_checked(["sudo", "rm", "-rf", str(profile_root)])
    print(f"provisioned {profile['id']} rootfs sha256:{rootfs_identity['sha256']} image {image_record['imageDigest']}")
    return 0


def validate_build_record(record: dict, contract: dict) -> None:
    profile = contract["profile"]
    if record.get("schemaVersion") != 1 or record.get("buildSystem") != "ubuntu-snapshot-debootstrap-apt" or record.get("profile") != {
        "id": profile["id"], "architecture": "amd64", "target": "x86_64-linux-gnu",
        "snapshot": profile["snapshot"], "codename": "noble",
    }:
        raise ProvisionError("build record profile identity mismatch; Clang 22.1.6 and unregistered inputs reject")
    source = record.get("source", {})
    if (source.get("package") != "llvm-toolchain-18" or source.get("version") != "1:18.1.3-1ubuntu1" or
            source.get("upstreamTag") != contract["profile"]["upstream"]["tag"]):
        raise ProvisionError("build record source package/version mismatch")
    source_files = source.get("files", [])
    source_names = [row.get("name") for row in source_files]
    if not source_files or len(source_names) != len(set(source_names)):
        raise ProvisionError("build record source file identities are empty or duplicated")
    for row in source_files:
        if row.get("bytes", 0) < 1 or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))):
            raise ProvisionError("build record contains malformed authenticated source file metadata")
    dsc_rows = [row for row in source_files if row.get("role") == "dsc"]
    if len(dsc_rows) != 1 or source.get("dsc") != {
        "bytes": dsc_rows[0]["bytes"], "sha256": dsc_rows[0]["sha256"],
    }:
        raise ProvisionError("build record .dsc identity differs from its signed source file list")
    for field in ("upstreamArchive", "upstreamSignature", "upstreamKeyring"):
        value = source.get(field, {})
        if value.get("bytes", 0) < 1 or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", ""))):
            raise ProvisionError(f"build record is missing authenticated LLVM {field} bytes")
    audit = record.get("patchAudit", {})
    if audit.get("status") != "compatible" or audit.get("relevantFileCount") != len(contract["relevantFiles"]):
        raise ProvisionError("build record lacks a passing full patch/API source audit")
    for key in ("patchInventorySha256", "relevantFileManifestSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(audit.get(key, ""))):
            raise ProvisionError(f"build record patch audit has invalid {key}")

    package_rows = record.get("packages", [])
    package_by_name: dict[str, dict] = {}
    for row in package_rows:
        if row.get("name") in package_by_name:
            raise ProvisionError(f"duplicate package identity in build record: {row['name']}")
        if row.get("architecture") not in ("amd64", "all") or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))) or row.get("bytes", 0) < 1:
            raise ProvisionError("invalid installed package byte identity")
        if row.get("suite") not in profile["suites"] or row.get("component") not in profile["components"]:
            raise ProvisionError("installed package does not belong to the pinned Ubuntu snapshot")
        package_file = PurePosixPath(str(row.get("file", "")))
        if package_file.is_absolute() or ".." in package_file.parts or not str(package_file).endswith(".deb"):
            raise ProvisionError("installed package filename is unsafe or malformed")
        package_by_name[row["name"]] = row
    if not package_rows or len(package_rows) > profile["bounds"]["maxPackageCount"]:
        raise ProvisionError("build record package closure is empty or too large")
    for pin in profile["binaryRoots"]:
        row = package_by_name.get(pin["name"])
        if row is None or row.get("version") != pin["version"]:
            raise ProvisionError(f"build record is missing the pinned package {pin['name']}={pin['version']}")
    if package_by_name["libclang-cpp18-dev"]["version"] != package_by_name["libclang-cpp18"]["version"]:
        raise ProvisionError("build record libclang-cpp18-dev and runtime package versions differ")
    downloaded_rows = record.get("downloadedPackages", [])
    downloaded_list = [(row.get("name"), row.get("version"), row.get("architecture")) for row in downloaded_rows]
    downloaded = set(downloaded_list)
    if not downloaded_rows or len(downloaded_rows) > profile["bounds"]["maxPackageCount"] or len(downloaded) != len(downloaded_list):
        raise ProvisionError("build record repeats a downloaded package identity")
    installed_by_key = {(row["name"], row["version"], row["architecture"]): row for row in package_rows}
    for row in downloaded_rows:
        if (row.get("architecture") not in ("amd64", "all") or row.get("suite") not in profile["suites"] or
                row.get("component") not in profile["components"] or row.get("bytes", 0) < 1 or
                not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", "")))):
            raise ProvisionError("downloaded package has invalid signed byte metadata")
        package_file = PurePosixPath(str(row.get("file", "")))
        if package_file.is_absolute() or ".." in package_file.parts or not str(package_file).endswith(".deb"):
            raise ProvisionError("downloaded package filename is unsafe or malformed")
        key = (row["name"], row["version"], row["architecture"])
        if key in installed_by_key and installed_by_key[key] != row:
            raise ProvisionError("downloaded package identity differs from the installed signed package row")
    for pin in profile["binaryRoots"]:
        if (pin["name"], pin["version"], "amd64") not in downloaded:
            raise ProvisionError(f"build record omitted the verified downloaded root archive {pin['name']}")

    tools = record.get("tools", [])
    if len(tools) != 2 or {row.get("role") for row in tools} != {"c-driver", "cxx-driver"}:
        raise ProvisionError("build record must independently identify C and C++ driver executables")
    for row in tools:
        if not row.get("path", "").startswith("/usr/") or "18.1.3" not in row.get("versionOutput", ""):
            raise ProvisionError("tool version/path diagnostic is inconsistent with the pinned profile")
        if (not isinstance(row.get("symlinkChain"), list) or
                not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))) or row.get("bytes", 0) < 1 or
                not re.fullmatch(r"[0-7]{4}", str(row.get("mode", ""))) or
                int(row["mode"], 8) & 0o111 == 0):
            raise ProvisionError("tool executable byte identity or symlink-chain record is invalid")
        if not row.get("resolvedPath", "").startswith("/usr/") or ".." in PurePosixPath(row["resolvedPath"]).parts:
            raise ProvisionError("tool resolved executable path is outside the authenticated rootfs")

    probe = record.get("probe", {})
    spec = contract["langOptions"]
    validate_profile_compiler_identity(probe.get("compilerVersion", ""), probe.get("target", ""))
    if probe.get("inventoryEvidence") != spec["inventoryEvidence"]:
        raise ProvisionError("build record does not label the LangOptions inventory as a source-text scan")
    if probe.get("generatedFields") != 298 or probe.get("familyCounts") != spec["familyCounts"]:
        raise ProvisionError("build record LangOptions generated field inventory mismatch")
    generated_names = probe.get("generatedFieldNames", [])
    if (not isinstance(generated_names, list) or len(generated_names) != spec["generatedFieldCount"] or
            any(not isinstance(name, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
                for name in generated_names) or len(set(generated_names)) != spec["generatedFieldCount"]):
        raise ProvisionError("build record generated LangOptions name manifest is incomplete or duplicated")
    if probe.get("manualFields") != spec["manualFields"] or len(probe["manualFields"]) != 28:
        raise ProvisionError("build record manual LangOptions inventory mismatch")
    if probe.get("callingConventions") != spec["callingConventions"] or len(probe["callingConventions"]) != 22:
        raise ProvisionError("build record calling-convention inventory mismatch")
    if probe.get("apiChecks") != spec["apiChecks"]:
        raise ProvisionError("build record LibTooling API inventory mismatch")
    if probe.get("runtimeLangOptionsChecks") != spec["runtimeChecks"]:
        raise ProvisionError("build record lacks the exact selected LangOptions runtime checks")
    macro_observations = probe.get("macroObservations", {})
    if any(type(macro_observations.get(key)) is not int or macro_observations[key] < 1
           for key in ("expansionCount", "macroInfoChecks", "nonBuiltinClassifications")):
        raise ProvisionError("build record lacks observed macro callback and MacroInfo checks")
    if any(not re.fullmatch(r"[0-9a-f]{64}", str(probe.get(field, "")))
           for field in ("definitionSha256", "headerSha256", "binarySha256", "sourceSha256", "fixtureSha256")):
        raise ProvisionError("build record probe bytes are not authenticated")

    for name in ("runtime", "resources"):
        value = record.get(name, {})
        entries = value.get("entries", [])
        expected = manifest(list(entries))
        if not entries or any(value.get(key) != expected[key] for key in ("entryCount", "bytes", "sha256")):
            raise ProvisionError(f"build record {name} manifest digest/count mismatch")
        for row in entries:
            if not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))) or row.get("bytes", -1) < 0:
                raise ProvisionError(f"build record {name} manifest contains an invalid file row")

    resource_directory = record.get("resourceDirectory", "")
    if not resource_directory.startswith("/usr/lib/llvm-18/") or ".." in PurePosixPath(resource_directory).parts:
        raise ProvisionError("build record resolved resource directory is outside the versioned LLVM 18 root")

    rootfs = record.get("rootfs", {})
    image = record.get("image", {})
    if (rootfs.get("bytes", 0) < 1 or
            rootfs.get("bytes", 0) > profile["bounds"]["maxArtifactBytes"] or
            not re.fullmatch(r"[0-9a-f]{64}", str(rootfs.get("sha256", "")))):
        raise ProvisionError("build record rootfs identity is invalid")
    if image.get("format") != "oci-image-layout-v1" or image.get("imageDigest") != "sha256:" + str(image.get("manifestSha256", "")):
        raise ProvisionError("build record immutable image identity is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(image.get("manifestSha256", ""))):
        raise ProvisionError("build record OCI manifest digest is invalid")
    image_artifact = record.get("imageArtifact", {})
    if (image_artifact.get("bytes", 0) < 1 or
            image_artifact.get("bytes", 0) > profile["bounds"]["maxArtifactBytes"] or
            not re.fullmatch(r"[0-9a-f]{64}", str(image_artifact.get("sha256", "")))):
        raise ProvisionError("build record OCI archive checksum or size is invalid")
    if record.get("environment") != contract["environment"]:
        raise ProvisionError("build record environment differs from fixed UTC/source-date profile")
    if record.get("recipe") != recipe_identity():
        raise ProvisionError("build record recipe hashes do not match the reviewed contract, tooling, and workflow bytes")
    command_names = {
        "debootstrap", "writeAptSources", "aptUpdate", "aptDownloadOnly", "aptInstall",
        "clangCVersion", "clangCxxVersion", "clangResourceDirectory", "llvmConfigLibdir",
        "llvmConfigCxxflags", "probeCompile", "probeRun", "rootfsTar", "ociArchive",
    }
    commands = record.get("commands", {})
    if not isinstance(commands, dict) or set(commands) != command_names or any(
        not isinstance(value, list) or not value or any(not isinstance(part, str) for part in value)
        for value in commands.values()
    ):
        raise ProvisionError("build record command map is incomplete or malformed")
    repositories = record.get("acquisition", {}).get("repositories", [])
    if {row.get("suite") for row in repositories} != set(profile["suites"]):
        raise ProvisionError("build record does not bind every pinned signed repository suite")
    for row in repositories:
        if row.get("signerPrimaryFingerprint") not in profile["ubuntuArchivePrimaryFingerprints"]:
            raise ProvisionError("build record includes an untrusted Ubuntu archive signer")
        if row.get("bytes", 0) < 1 or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))):
            raise ProvisionError("build record has malformed signed InRelease identity")
        expected_url = urllib.parse.urljoin(profile["snapshotBase"], f"dists/{row['suite']}/InRelease")
        if row.get("inRelease") != expected_url:
            raise ProvisionError("build record InRelease URL differs from the pinned immutable Snapshot")
    keyring = record["acquisition"].get("ubuntuKeyring", {})
    if keyring.get("bytes", 0) < 1 or not re.fullmatch(r"[0-9a-f]{64}", str(keyring.get("sha256", ""))):
        raise ProvisionError("build record does not bind the archive-verification keyring")
    if not re.fullmatch(r"[0-9a-f]{64}", str(record["acquisition"].get("candidateSha256", ""))):
        raise ProvisionError("build record does not bind the authenticated acquisition candidate")
    if record["acquisition"].get("signatureFingerprints") != [row["signerPrimaryFingerprint"] for row in repositories]:
        raise ProvisionError("build record repository signer summary is inconsistent")


def compare_build_runs(first_path: Path, second_path: Path, output_path: Path, contract: dict) -> dict:
    first = json.loads(first_path.read_text(encoding="utf-8"))
    second = json.loads(second_path.read_text(encoding="utf-8"))
    validate_build_record(first, contract)
    validate_build_record(second, contract)
    if canonical_json(first) != canonical_json(second):
        raise ProvisionError("two clean rootfs/image/probe runs did not reproduce identical identity")
    record = dict(first)
    record["reproducibility"] = {
        "cleanBuilds": 2,
        "matchingRootfsSha256": True,
        "matchingImageDigest": True,
    }
    atomic_write(output_path, canonical_json(record))
    return record


def command_compare_runs(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    record = compare_build_runs(args.first, args.second, args.output, contract)
    print(f"two clean runs reproduced rootfs {record['rootfs']['sha256']} and image {record['image']['imageDigest']}")
    return 0


def command_verify_record(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    record = json.loads(args.record.read_text(encoding="utf-8"))
    validate_build_record(record, contract)
    if record.get("reproducibility") != {
        "cleanBuilds": 2, "matchingRootfsSha256": True, "matchingImageDigest": True,
    }:
        raise ProvisionError("build record does not contain two-run reproducibility evidence")
    if args.rootfs_tar:
        identity = record["rootfs"]
        if (args.rootfs_tar.stat().st_size != identity["bytes"] or
                sha256_file(args.rootfs_tar) != identity["sha256"]):
            raise ProvisionError("rootfs tar bytes differ from the pinned build record")
    print("verified the pinned Clang 18.1.3 profile/build-record contract")
    return 0


def command_write_loader_input(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    record = json.loads(args.record.read_text(encoding="utf-8"))
    validate_build_record(record, contract)
    if record.get("reproducibility") != {
        "cleanBuilds": 2, "matchingRootfsSha256": True, "matchingImageDigest": True,
    }:
        raise ProvisionError("A loader smoke input requires the final two-run build record")
    rootfs_dir = args.rootfs.resolve(strict=True)
    resource_record = verify_recorded_resource_manifest(rootfs_dir, record)
    expected_resource_sha256 = frontend_resource_manifest_sha256(record["resourceDirectory"], resource_record)
    tool = next(row for row in record["tools"] if row["role"] == "cxx-driver")
    actual_chain, actual_driver = symlink_chain(rootfs_dir, tool["path"])
    actual_resolved_path = "/" + actual_driver.relative_to(rootfs_dir).as_posix()
    if actual_chain != tool["symlinkChain"] or actual_resolved_path != tool["resolvedPath"]:
        raise ProvisionError("C++ driver symlink chain changed before A-loader smoke")
    chain = []
    for row in tool["symlinkChain"]:
        match = re.fullmatch(r"(/[^ ]+) -> (.+)", row)
        if match is None:
            raise ProvisionError("C++ driver symlink identity is malformed")
        link_path, target = match.groups()
        if "\n" in target or "\r" in target:
            raise ProvisionError("C++ driver symlink target contains a line break")
        chain.append(("toolchain" + link_path, sha256(target.encode("utf-8"))))
    resolved = rootfs_path(rootfs_dir, tool["resolvedPath"])
    actual = resolved.read_bytes()
    if len(actual) != tool["bytes"] or sha256(actual) != tool["sha256"]:
        raise ProvisionError("C++ driver executable bytes changed before A-loader smoke")
    mode = f"{resolved.stat().st_mode & 0o7777:04o}"
    if mode != tool["mode"]:
        raise ProvisionError("C++ driver executable mode changed before A-loader smoke")
    path_value = contract["environment"]["PATH"]
    profile_digest = sha256(canonical_json(record["profile"]))
    runtime_rows = []
    for row in record["runtime"]["entries"]:
        runtime_file = rootfs_path(rootfs_dir, row["path"])
        if runtime_file.is_symlink():
            actual = file_entry(rootfs_dir, row["path"])
            if actual["bytes"] != row["bytes"] or actual["sha256"] != row["sha256"]:
                raise ProvisionError(f"runtime symlink bytes changed before A-loader smoke: {row['path']}")
            continue
        if not runtime_file.is_file() or sha256_file(runtime_file) != row["sha256"]:
            raise ProvisionError(f"runtime library bytes changed before A-loader smoke: {row['path']}")
        normalized = "toolchain" + row["path"]
        if row["sha256"] != tool["sha256"]:
            runtime_rows.append((normalized, row["sha256"]))
    runtime_rows.sort(key=lambda row: row[0].encode("utf-8"))
    values = {
        "rootfs": str(rootfs_dir),
        "buildRecordSha256": sha256(args.record.read_bytes()),
        "containerImageDigest": record["image"]["imageDigest"],
        "configuredDriver": tool["path"],
        "configuredPathSha256": sha256(tool["path"].encode("utf-8")),
        "rawPath": path_value,
        "resolvedResourceDirectory": "toolchain" + record["resourceDirectory"],
        "smokeOutput": str(args.output),
        "resolvedDriverPath": "toolchain" + tool["resolvedPath"],
        "executableSha256": tool["sha256"],
        "executableBytes": str(tool["bytes"]),
        "executableMode": mode,
        "compilerSha256": tool["sha256"],
        "toolchainProfileSha256": profile_digest,
        "symlinkCount": str(len(chain)),
        "expectedResourceManifestSha256": expected_resource_sha256,
        "runtimeCount": str(len(runtime_rows)),
        "adapterSha256": sha256_file(ROOT / "oracle/clang/18.1.3/Clang1813AProfileLoaderSmoke.java"),
        "adapterSourceRevision": "0" * 40,
        "adapterApiVersion": "clang-libtooling-18.1.3-v1",
        "targetTriple": "x86_64-pc-linux-gnu",
    }
    for index, (link_path, target_sha) in enumerate(chain):
        values[f"symlink.{index}.path"] = link_path
        values[f"symlink.{index}.sha256"] = target_sha
    for index, (path, digest) in enumerate(runtime_rows):
        values[f"runtime.{index}.path"] = path
        values[f"runtime.{index}.sha256"] = digest
    encoded = "".join(f"{key}={value}\n" for key, value in sorted(values.items()))
    if any("\n" in value or "\r" in value for value in values.values()):
        raise ProvisionError("A-loader input contains a line break")
    atomic_write(args.output.with_suffix(".properties"), encoded.encode("utf-8"))
    return 0


def command_verify_image(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    record = json.loads(args.record.read_text(encoding="utf-8"))
    validate_build_record(record, contract)
    if record.get("reproducibility") != {
        "cleanBuilds": 2, "matchingRootfsSha256": True, "matchingImageDigest": True,
    }:
        raise ProvisionError("image verification requires the final reproducible build record")
    verify_oci_archive(args.oci_archive, record, contract["profile"]["bounds"]["maxArtifactBytes"])
    print(f"verified OCI image {record['image']['imageDigest']} and rootfs sha256:{record['rootfs']['sha256']}")
    return 0


def read_provenance_report(path: Path, label: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ProvisionError(f"{label} provenance report is not a regular file")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisionError(f"{label} provenance report is not valid UTF-8 JSON") from error
    if not isinstance(report, dict):
        raise ProvisionError(f"{label} provenance report must be a JSON object")
    return report


def validate_provenance_probe_report(report: dict, record: dict) -> None:
    if canonical_json(report) != canonical_json(record.get("probe")):
        raise ProvisionError("probe provenance report differs from the reproducible build-record probe")


def validate_provenance_loader_report(report: dict, record: dict, record_sha256: str) -> None:
    resources = record["resources"]
    expected_resource_sha = frontend_resource_manifest_sha256(record["resourceDirectory"], resources)
    if (report.get("scope") != "infrastructure-loader-smoke-only" or
            report.get("buildRecordSha256") != record_sha256 or
            report.get("imageDigest") != record["image"]["imageDigest"] or
            report.get("resourceDirectory") != "toolchain" + record["resourceDirectory"] or
            report.get("resourceManifestSha256") != expected_resource_sha or
            report.get("resourceFileCount") != resources.get("entryCount") or
            report.get("resourceTreeBytes") != sum(row["bytes"] for row in resources.get("entries", []))):
        raise ProvisionError("A-loader smoke report does not bind the build record, image, and resource manifest")
    for field in ("infrastructureProfileProjectionSha256", "pathTransformSha256", "cxxDriverIdentitySha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(report.get(field, ""))):
            raise ProvisionError(f"A-loader smoke report has an invalid {field}")
    for field in ("rejectedWrongImage", "rejectedWrongCxxDriverBytes", "rejectedChangedResourceIdentity",
                  "rejectedChangedRuntimeLibraryIdentity", "rejectedMissingResourceDirectory"):
        if report.get(field) is not True:
            raise ProvisionError(f"A-loader smoke report lacks the required negative check: {field}")


def validate_provenance_negative_report(report: dict, record: dict, contract: dict,
                                        artifact_lock_path: Path | None = None) -> None:
    negative = contract["negativeControl"]
    lock_path = artifact_lock_path or ROOT / negative["artifactLock"]
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    expected = lock["artifacts"][negative["artifactRole"]]
    fixture = ROOT / negative["fixture"]
    if (report.get("scope") != "negative-version-gate-only; not a Clang 18.1.3 identity" or
            report.get("artifactOracleId") != negative["oracleId"] or
            report.get("artifactLockSha256") != sha256_file(lock_path) or
            report.get("compilerBytes") != expected["bytes"] or
            report.get("compilerSha256") != expected["sha256"] or
            report.get("fixtureBytes") != fixture.stat().st_size or
            report.get("fixtureSha256") != record.get("probe", {}).get("fixtureSha256") or
            report.get("fixtureSha256") != sha256_file(fixture) or
            report.get("fixtureAcceptedByClang22") is not True or
            report.get("compiler18GateRejected") != "probe compiler version or target mismatch" or
            re.search(r"\bversion\s+22\.1\.6(?:\s|$)", report.get("compilerVersionOutput", "")) is None):
        raise ProvisionError("Clang 22.1.6 negative smoke report does not match the locked comparator and fixture")


def command_package_provenance(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    record = json.loads(args.record.read_text(encoding="utf-8"))
    validate_build_record(record, contract)
    if record.get("reproducibility") != {
        "cleanBuilds": 2, "matchingRootfsSha256": True, "matchingImageDigest": True,
    }:
        raise ProvisionError("provenance packaging requires a final reproducible build record")
    candidate = args.acquisition / "acquisition-candidate.json"
    patch_audit = args.acquisition / "patch-audit.json"
    if not candidate.is_file() or not patch_audit.is_file() or not (args.acquisition / "downloads").is_dir():
        raise ProvisionError("provenance package is missing authenticated acquisition inputs")
    record_sha256 = sha256_file(args.record)
    probe_report = read_provenance_report(args.probe_report, "LibTooling probe")
    loader_report = read_provenance_report(args.loader_report, "A-loader")
    negative_report = read_provenance_report(args.negative_report, "Clang 22.1.6 negative")
    validate_provenance_probe_report(probe_report, record)
    validate_provenance_loader_report(loader_report, record, record_sha256)
    validate_provenance_negative_report(negative_report, record, contract)
    expected_artifacts = [
        candidate, patch_audit, args.acquisition / "downloads",
        args.record, args.probe_report, args.loader_report, args.negative_report,
        args.contract, args.contract.parent / "build-record.schema.json",
        ROOT / "oracle/clang/18.1.3/libtooling-probe.cpp",
        ROOT / "oracle/clang/18.1.3/fixtures/libtooling-positive.cpp",
        ROOT / "scripts/oracle/provision_clang_18_1_3.py",
        ROOT / "oracle/clang/18.1.3/Clang1813AProfileLoaderSmoke.java",
        ROOT / "oracle/clang/18.1.3/clang1813-loader-smoke.init.gradle",
        ROOT / "oracle/clang/18.1.3/test_provisioning.py",
        ROOT / "oracle/clang/18.1.3/ACQUISITION_STATUS.md",
        ROOT / ".github/workflows/generic-template-toolchain.yml",
        ROOT / "oracle/llvm/22.1.6/release-artifacts.json",
        ROOT / "oracle/llvm/22.1.6/oracle-manifest.json",
        args.keyring, ROOT / contract["profile"]["upstream"]["keyFile"],
    ]
    if args.output.exists():
        raise ProvisionError("provenance archive output must not already exist")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    epoch = int(contract["environment"]["SOURCE_DATE_EPOCH"])
    try:
        with tarfile.open(args.output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for source in expected_artifacts:
                if not source.exists():
                    raise ProvisionError(f"provenance evidence file is missing: {source}")
                if source.is_dir():
                    root = source
                    for directory, dirnames, filenames in os.walk(root, followlinks=False):
                        dirnames.sort()
                        filenames.sort()
                        current = Path(directory)
                        for name in list(dirnames):
                            child = current / name
                            if child.is_symlink():
                                raise ProvisionError("provenance acquisition tree contains a symlink")
                        for name in filenames:
                            child = current / name
                            if child.is_symlink() or not child.is_file():
                                raise ProvisionError("provenance acquisition tree contains a non-regular file")
                            relative = child.relative_to(root).as_posix()
                            _add_provenance_file(archive, child, f"acquisition/downloads/{relative}", epoch)
                else:
                    if source.is_symlink() or not source.is_file():
                        raise ProvisionError(f"provenance input is not a regular file: {source}")
                    if source == candidate:
                        arcname = "acquisition/acquisition-candidate.json"
                    elif source == patch_audit:
                        arcname = "acquisition/patch-audit.json"
                    elif source == args.record:
                        arcname = "build-record.json"
                    elif source == args.probe_report:
                        arcname = "probe-report.json"
                    elif source == args.loader_report:
                        arcname = "a-loader-smoke.json"
                    elif source == args.negative_report:
                        arcname = "clang-22.1.6-negative-smoke.json"
                    elif source == args.contract:
                        arcname = "provisioning-contract.json"
                    elif source.name == "build-record.schema.json":
                        arcname = "build-record.schema.json"
                    elif source.name == "libtooling-probe.cpp":
                        arcname = "libtooling-probe.cpp"
                    elif source.name == "libtooling-positive.cpp":
                        arcname = "fixtures/libtooling-positive.cpp"
                    elif source == ROOT / "scripts/oracle/provision_clang_18_1_3.py":
                        arcname = "provision_clang_18_1_3.py"
                    elif source == ROOT / "oracle/clang/18.1.3/Clang1813AProfileLoaderSmoke.java":
                        arcname = "Clang1813AProfileLoaderSmoke.java"
                    elif source == ROOT / "oracle/clang/18.1.3/clang1813-loader-smoke.init.gradle":
                        arcname = "clang1813-loader-smoke.init.gradle"
                    elif source == ROOT / "oracle/clang/18.1.3/test_provisioning.py":
                        arcname = "test_provisioning.py"
                    elif source == ROOT / ".github/workflows/generic-template-toolchain.yml":
                        arcname = "generic-template-toolchain.yml"
                    elif source == ROOT / "oracle/clang/18.1.3/ACQUISITION_STATUS.md":
                        arcname = "ACQUISITION_STATUS.md"
                    elif source == ROOT / "oracle/llvm/22.1.6/release-artifacts.json":
                        arcname = "trusted_keys/clang-22.1.6-release-artifacts.json"
                    elif source == ROOT / "oracle/llvm/22.1.6/oracle-manifest.json":
                        arcname = "trusted_keys/clang-22.1.6-oracle-manifest.json"
                    elif source == args.keyring:
                        arcname = "trusted_keys/ubuntu-archive-keyring.gpg"
                    else:
                        arcname = "trusted_keys/llvm-release.asc"
                    _add_provenance_file(archive, source, arcname, epoch)
    except (OSError, tarfile.TarError) as error:
        raise ProvisionError(f"could not build provenance archive: {error}") from error
    if args.output.stat().st_size > contract["profile"]["bounds"]["maxArtifactBytes"]:
        args.output.unlink(missing_ok=True)
        raise ProvisionError("provenance archive exceeds the configured artifact byte budget")
    print(f"packaged authenticated provenance archive ({args.output.stat().st_size} bytes)")
    return 0


def command_negative_version_smoke(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    negative = contract["negativeControl"]
    lock = json.loads(args.artifact_lock.read_text(encoding="utf-8"))
    expected = lock["artifacts"][negative["artifactRole"]]
    if lock.get("oracle", {}).get("id") != negative["oracleId"] or lock.get("oracle", {}).get("version") != negative["requiredVersion"]:
        raise ProvisionError("22.1.6 negative compiler lock does not match the frozen comparator")
    if args.compiler.stat().st_size != expected["bytes"] or sha256_file(args.compiler) != expected["sha256"]:
        raise ProvisionError("22.1.6 negative compiler bytes differ from the existing immutable release-artifact lock")
    version_output = run_checked([str(args.compiler), "--version"], timeout=30).stdout
    first_line = version_output.splitlines()[0] if version_output.splitlines() else ""
    if re.search(r"\bversion\s+22\.1\.6(?:\s|$)", first_line) is None:
        raise ProvisionError(f"locked negative comparator did not execute as Clang 22.1.6: {first_line!r}")
    fixture = args.fixture
    if sha256_file(fixture) != sha256_file(ROOT / negative["fixture"]):
        raise ProvisionError("negative comparator fixture differs from the pinned positive fixture bytes")
    run_checked([
        str(args.compiler), "--no-default-config", "--target=x86_64-pc-linux-gnu",
        "-std=c++14", "-fsyntax-only", str(fixture),
    ], timeout=60)
    try:
        validate_profile_compiler_identity(first_line, "x86_64-pc-linux-gnu")
    except ProvisionError as error:
        if "compiler version or target mismatch" not in str(error):
            raise
        rejected = str(error)
    else:
        raise ProvisionError("negative comparator was accepted as the pinned Clang 18.1.3 profile")
    result = {
        "schemaVersion": 1,
        "scope": "negative-version-gate-only; not a Clang 18.1.3 identity",
        "artifactOracleId": negative["oracleId"],
        "artifactLockSha256": sha256_file(args.artifact_lock),
        "compilerBytes": expected["bytes"],
        "compilerSha256": expected["sha256"],
        "compilerVersionOutput": version_output,
        "fixtureBytes": fixture.stat().st_size,
        "fixtureSha256": sha256_file(fixture),
        "fixtureAcceptedByClang22": True,
        "compiler18GateRejected": rejected,
    }
    atomic_write(args.output, canonical_json(result))
    print("executed the locked Clang 22.1.6 negative fixture and confirmed 18.1.3 gate rejection")
    return 0


def _add_provenance_file(archive: tarfile.TarFile, source: Path, arcname: str, epoch: int) -> None:
    info = tarfile.TarInfo(arcname)
    info.size = source.stat().st_size
    info.mtime = epoch
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode = 0o444
    with source.open("rb") as stream:
        archive.addfile(info, stream)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    metadata = sub.add_parser(
        "probe-snapshot-metadata",
        help="authenticate one pinned Snapshot's indexes and inspect only the Clang 18 source and binary roots",
    )
    metadata.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    metadata.add_argument("--snapshot", choices=(SNAPSHOT_METADATA_PROBE,), required=True)
    metadata.add_argument("--output", type=Path, required=True)
    metadata.add_argument("--keyring", type=Path, default=DEFAULT_KEYRING)
    metadata.set_defaults(run=command_probe_snapshot_metadata)
    acquire = sub.add_parser("acquire", help="authenticate pinned Snapshot indexes and source artifacts")
    acquire.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    acquire.add_argument("--output", type=Path, required=True)
    acquire.add_argument("--keyring", type=Path, default=DEFAULT_KEYRING)
    acquire.set_defaults(run=command_acquire)
    lang = sub.add_parser("audit-langoptions", help="check installed Clang 18.1.3 field inventories")
    lang.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    lang.add_argument("--definition", type=Path, required=True)
    lang.add_argument("--header", type=Path, required=True)
    lang.add_argument("--output", type=Path, required=True)
    lang.set_defaults(run=command_audit_langoptions)
    patches = sub.add_parser("audit-patches", help="compare unpacked distro source with authenticated upstream source")
    patches.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    patches.add_argument("--package-source", type=Path, required=True)
    patches.add_argument("--upstream-source", type=Path, required=True)
    patches.add_argument("--output", type=Path, required=True)
    patches.set_defaults(run=command_audit_patches)
    probe = sub.add_parser("verify-probe", help="validate probe report against frozen inventory/API checks")
    probe.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    probe.add_argument("--report", type=Path, required=True)
    probe.add_argument("--inventory", type=Path, required=True)
    probe.add_argument("--source", type=Path, required=True)
    probe.add_argument("--binary", type=Path, required=True)
    probe.add_argument("--output", type=Path, required=True)
    probe.set_defaults(run=command_probe_report)
    provision = sub.add_parser("provision-rootfs", help="install and qualify the authenticated candidate in a minimal Noble rootfs")
    provision.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    provision.add_argument("--acquisition", type=Path, required=True)
    provision.add_argument("--keyring", type=Path, default=DEFAULT_KEYRING)
    provision.add_argument("--rootfs", type=Path, required=True)
    provision.add_argument("--workdir", type=Path, required=True)
    provision.add_argument("--output", type=Path, required=True)
    provision.add_argument("--label", choices=("run1", "run2"), required=True)
    provision.add_argument("--keep-rootfs", action="store_true", help="retain rootfs for the authenticated loader smoke step")
    provision.add_argument("--rootfs-tar-output", type=Path,
                           help="retain the canonical rootfs tar at this bounded, record-hashed artifact path")
    provision.set_defaults(run=provision_rootfs)
    compare = sub.add_parser("compare-runs", help="require two clean rootfs/image runs to reproduce exactly")
    compare.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    compare.add_argument("--first", type=Path, required=True)
    compare.add_argument("--second", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    compare.set_defaults(run=command_compare_runs)
    verify = sub.add_parser("verify-record", help="verify the final authenticated profile build record")
    verify.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    verify.add_argument("--record", type=Path, required=True)
    verify.add_argument("--rootfs-tar", type=Path)
    verify.set_defaults(run=command_verify_record)
    loader = sub.add_parser("write-loader-input", help="bind the final record to the real A profile/resource loader smoke")
    loader.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    loader.add_argument("--record", type=Path, required=True)
    loader.add_argument("--rootfs", type=Path, required=True)
    loader.add_argument("--output", type=Path, required=True)
    loader.set_defaults(run=command_write_loader_input)
    image = sub.add_parser("verify-image", help="verify OCI archive, manifest, config, layer, and recorded rootfs bytes")
    image.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    image.add_argument("--record", type=Path, required=True)
    image.add_argument("--oci-archive", type=Path, required=True)
    image.set_defaults(run=command_verify_image)
    provenance = sub.add_parser("package-provenance", help="package bounded signed acquisition, source-audit, and build evidence")
    provenance.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    provenance.add_argument("--acquisition", type=Path, required=True)
    provenance.add_argument("--record", type=Path, required=True)
    provenance.add_argument("--probe-report", type=Path, required=True)
    provenance.add_argument("--loader-report", type=Path, required=True)
    provenance.add_argument("--negative-report", type=Path, required=True)
    provenance.add_argument("--keyring", type=Path, default=DEFAULT_KEYRING)
    provenance.add_argument("--output", type=Path, required=True)
    provenance.set_defaults(run=command_package_provenance)
    negative = sub.add_parser("negative-version-smoke", help="execute the exact locked Clang 22.1.6 negative comparator")
    negative.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    negative.add_argument("--artifact-lock", type=Path, default=ROOT / "oracle/llvm/22.1.6/release-artifacts.json")
    negative.add_argument("--compiler", type=Path, required=True)
    negative.add_argument("--fixture", type=Path, default=ROOT / "oracle/clang/18.1.3/fixtures/libtooling-positive.cpp")
    negative.add_argument("--output", type=Path, required=True)
    negative.set_defaults(run=command_negative_version_smoke)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (ProvisionError, OSError, KeyError, ValueError, json.JSONDecodeError) as error:
        print(f"provisioning failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
