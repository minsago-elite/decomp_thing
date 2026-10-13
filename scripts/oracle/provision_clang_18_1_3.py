#!/usr/bin/env python3
"""Acquire and qualify the pinned Ubuntu Noble Clang 18.1.3 toolchain profile.

The script deliberately separates authenticated candidate acquisition from
acceptance. It never writes a trusted package lock from network data; the
candidate manifests are CI artifacts that must be reviewed and pinned before
the build-record verifier can accept them.
"""

from __future__ import annotations

import argparse
import datetime
import contextlib
import fcntl
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
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
APT_KEYRING_IN_ROOT = "/usr/share/keyrings/decomp-thing-ubuntu-archive-keyring.gpg"
PROBE_RETAIN_DIRECTORY = "/usr/local/libexec/decomp-thing/clang-18.1.3"
PROBE_SOURCE_IN_ROOT = PROBE_RETAIN_DIRECTORY + "/libtooling-probe.cpp"
PROBE_BINARY_IN_ROOT = PROBE_RETAIN_DIRECTORY + "/libtooling-probe"
PROBE_FIXTURE_IN_ROOT = PROBE_RETAIN_DIRECTORY + "/libtooling-positive.cpp"
PROBE_SANDBOX_BLOCK_REASON = (
    "Clang probe execution is disabled: this provisioning CLI has no reviewed unprivileged "
    "bubblewrap/cgroup-v2 adapter with capability dropping, CPU/RSS/process/disk/output/wall-time "
    "limits, and descendant cleanup; do not substitute sudo chroot"
)
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_GZIP_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
FRONTEND_RUNTIME_ROOTS = (
    "/usr/bin/clang-18",
    "/usr/bin/clang++-18",
    "/usr/lib/llvm-18/lib/libclang-cpp.so",
    "/usr/lib/llvm-18/lib/libLLVM-18.so",
)
RECIPE_FILES = {
    "contractSha256": CONTRACT_PATH,
    "schemaSha256": CONTRACT_PATH.parent / "build-record.schema.json",
    "provisionerSha256": ROOT / "scripts/oracle/provision_clang_18_1_3.py",
    "probeSha256": ROOT / "oracle/clang/18.1.3/libtooling-probe.cpp",
    "fixtureSha256": ROOT / "oracle/clang/18.1.3/fixtures/libtooling-positive.cpp",
    "aLoaderSha256": ROOT / "src/main/kotlin/decompengine/oracle/fulltree/FullTreeGenericTemplateFrontendProfileV1.kt",
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
ROOTFS_TAR_BUDGET_TIMEOUT_SECONDS = 120
SNAPSHOT_METADATA_PROBE = "20240702T000000Z"
PAUSED_UPSTREAM_SIGNATURE_URL = (
    "https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.3/"
    "llvm-project-18.1.3.src.tar.xz.sig"
)
# Keep candidate acquisition disabled for this profile until the denied
# upstream signature source is explicitly resolved and the pause is reviewed.
UPSTREAM_SIGNATURE_ACCESS_ENABLED = False
ACQUISITION_PAUSE_REASON = (
    "Clang 18.1.3 candidate acquisition is paused pending explicit resolution of "
    "the denied upstream signature source; no acquisition requests were made. "
    f"Blocked target: {PAUSED_UPSTREAM_SIGNATURE_URL}"
)
MAX_SNAPSHOT_METADATA_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_INDEX_BYTES = 128 * 1024 * 1024
ALLOWED_REDIRECT_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}
REVIEWED_RELEVANT_FILES = (
    "clang/include/clang/Basic/LangOptions.def",
    "clang/include/clang/Basic/LangOptions.h",
    "clang/include/clang/Basic/CommentOptions.h",
    "clang/include/clang/Basic/Specifiers.h",
    "clang/include/clang/Basic/Features.def",
    "clang/include/clang/Basic/TargetInfo.h",
    "clang/include/clang/Driver/Options.td",
    "clang/include/clang/Driver/Options.h",
    "clang/include/clang/Frontend/CompilerInvocation.h",
    "clang/include/clang/Frontend/CompilerInstance.h",
    "clang/include/clang/Tooling/Tooling.h",
    "clang/include/clang/AST/ASTContext.h",
    "clang/include/clang/AST/Decl.h",
    "clang/include/clang/AST/DeclTemplate.h",
    "clang/include/clang/AST/RecursiveASTVisitor.h",
    "clang/include/clang/AST/TemplateBase.h",
    "clang/include/clang/AST/Type.h",
    "clang/include/clang/Lex/Lexer.h",
    "clang/include/clang/Lex/PPCallbacks.h",
    "clang/include/clang/Lex/Preprocessor.h",
    "clang/include/clang/Lex/MacroInfo.h",
    "clang/lib/Basic/TargetInfo.cpp",
    "clang/lib/Driver/Driver.cpp",
    "clang/lib/Driver/ToolChains/Clang.cpp",
    "clang/lib/Frontend/CompilerInvocation.cpp",
    "clang/lib/Frontend/CompilerInstance.cpp",
    "clang/lib/Tooling/Tooling.cpp",
    "clang/lib/AST/ASTContext.cpp",
    "clang/lib/AST/DeclTemplate.cpp",
    "clang/lib/Lex/Lexer.cpp",
    "clang/lib/Lex/PPDirectives.cpp",
    "clang/lib/Lex/PPMacroExpansion.cpp",
    "clang/lib/Lex/Preprocessor.cpp",
    "clang/lib/Sema/SemaTemplate.cpp",
)


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


def read_regular_evidence(path: Path, maximum_bytes: int = MAX_SINGLE_DOWNLOAD) -> bytes:
    """Read one regular descriptor into immutable bytes, with a strict read cap."""
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ProvisionError(f"evidence input is not a regular file: {path}")
            payload = stream.read(maximum_bytes + 1)
    except OSError as error:
        raise ProvisionError(f"could not read regular evidence input: {path}: {error}") from error
    if len(payload) > maximum_bytes:
        raise ProvisionError(f"evidence input exceeds its byte budget: {path}")
    return payload


def captured_evidence(path: Path, captured: dict[Path, bytes] | None,
                      maximum_bytes: int = MAX_SINGLE_DOWNLOAD) -> bytes:
    if captured is None:
        return read_regular_evidence(path, maximum_bytes)
    if path not in captured:
        payload = read_regular_evidence(path, maximum_bytes)
        if len(payload) + sum(len(value) for value in captured.values()) > MAX_DOWNLOAD_BYTES:
            raise ProvisionError("captured provenance metadata exceeds its cumulative byte budget")
        captured[path] = payload
    if len(captured[path]) > maximum_bytes:
        raise ProvisionError(f"evidence input exceeds its byte budget: {path}")
    return captured[path]


def verify_regular_evidence_identity(path: Path, expected_bytes: int, expected_sha256: str) -> None:
    if (type(expected_bytes) is not int or expected_bytes < 0 or expected_bytes > MAX_SINGLE_DOWNLOAD or
            not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None):
        raise ProvisionError("authenticated evidence byte identity is malformed or exceeds its byte budget")
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ProvisionError(f"evidence input is not a regular file: {path}")
            remaining = expected_bytes
            digest = hashlib.sha256()
            while remaining:
                block = stream.read(min(remaining, 1024 * 1024))
                if not block:
                    break
                remaining -= len(block)
                digest.update(block)
            if remaining or stream.read(1) or digest.hexdigest() != expected_sha256:
                raise ProvisionError(f"authenticated evidence bytes changed: {path}")
    except OSError as error:
        raise ProvisionError(f"could not verify regular evidence input: {path}: {error}") from error


@contextlib.contextmanager
def sealed_evidence_fd(payload: bytes):
    """Expose immutable Python bytes to native consumers without a mutable path."""
    descriptor = os.memfd_create("clang1813-evidence", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:offset + 1024 * 1024])
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        yield descriptor, f"/proc/self/fd/{descriptor}"
    finally:
        os.close(descriptor)


def recipe_identity(contract_path: Path = CONTRACT_PATH,
                     captured: dict[Path, bytes] | None = None) -> dict[str, str]:
    files = {**RECIPE_FILES, "contractSha256": contract_path}
    return {name: (sha256_file(path) if captured is None else
                   sha256(captured_evidence(path, captured))) for name, path in files.items()}


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def strict_json_loads(payload: str | bytes) -> object:
    """Reject duplicate members, including nested and escaped-equivalent JSON keys."""
    def unique_object(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for name, value in pairs:
            if name in result:
                raise ProvisionError(f"JSON evidence contains a duplicate object member: {name[:120]!r}")
            result[name] = value
        return result

    return json.loads(payload, object_pairs_hook=unique_object)


def require_reviewed_relevant_files(contract: dict) -> None:
    if not isinstance(contract, dict):
        raise ProvisionError("provisioning contract must be a JSON object")
    files = contract.get("relevantFiles")
    if not isinstance(files, list):
        raise ProvisionError("relevantFiles must contain the canonical reviewed file policy")
    for value in files:
        if (not isinstance(value, str) or PurePosixPath(value).is_absolute() or
                any(part in ("", ".", "..") for part in value.split("/")) or
                PurePosixPath(value).as_posix() != value):
            raise ProvisionError("relevantFiles contains an absolute, dot-component or noncanonical path")
    if tuple(files) != REVIEWED_RELEVANT_FILES:
        raise ProvisionError("relevantFiles differs from the canonical reviewed 34-file policy")


def read_contract(path: Path = CONTRACT_PATH, *, captured: dict[Path, bytes] | None = None) -> dict:
    value = strict_json_loads(path.read_text(encoding="utf-8") if captured is None else
                              captured_evidence(path, captured).decode("utf-8"))
    require_reviewed_relevant_files(value)
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
    lock = strict_json_loads((ROOT / negative["artifactLock"]).read_text(encoding="utf-8"))
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


def iter_compressed_index(path: Path, payload: bytes | None = None):
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
            with (gzip.open(path, mode="rb") if payload is None else
                  gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb")) as stream:
                # A signed Release table may legitimately name an empty pocket
                # index. The caller authenticates the compressed bytes first;
                # malformed non-empty paragraphs still fail closed.
                yield from iter_deb822_lines(bounded_lines(stream), allow_empty=True)
            return
        if path.name.endswith(".xz"):
            with lzma.open(path if payload is None else io.BytesIO(payload), mode="rb") as stream:
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


def verify_gpgv(data_path: Path, keyring: Path, allowed_fingerprints: set[str], *,
                 data_payload: bytes | None = None, key_payload: bytes | None = None) -> str:
    if not keyring.is_file():
        raise ProvisionError(f"required trusted keyring is missing: {keyring}")
    payload = read_regular_evidence(data_path, 8 * 1024 * 1024) if data_payload is None else data_payload
    key_bytes = read_regular_evidence(keyring, 1024 * 1024) if key_payload is None else key_payload
    if len(payload) > 8 * 1024 * 1024 or len(key_bytes) > 1024 * 1024:
        raise ProvisionError("OpenPGP evidence input exceeds its byte budget")
    with sealed_evidence_fd(key_bytes) as (key_fd, key_path):
        proc = subprocess.run(
            ["gpgv", "--status-fd", "1", "--keyring", key_path, "-"],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=payload,
            pass_fds=(key_fd,),
        )
    proc.stdout = proc.stdout.decode("utf-8") if isinstance(proc.stdout, bytes) else proc.stdout
    proc.stderr = proc.stderr.decode("utf-8") if isinstance(proc.stderr, bytes) else proc.stderr
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
                              expected_fingerprint: str, *, data_payload: bytes | None = None,
                              signature_payload: bytes | None = None, key_payload: bytes | None = None) -> str:
    payload = read_regular_evidence(data_path) if data_payload is None else data_payload
    signature = read_regular_evidence(signature_path, 1024 * 1024) if signature_payload is None else signature_payload
    key_bytes = read_regular_evidence(keyring, 1024 * 1024) if key_payload is None else key_payload
    if len(payload) > MAX_SINGLE_DOWNLOAD or len(signature) > 1024 * 1024 or len(key_bytes) > 1024 * 1024:
        raise ProvisionError("OpenPGP evidence input exceeds its byte budget")
    with sealed_evidence_fd(payload) as (data_fd, data_name), \
            sealed_evidence_fd(key_bytes) as (key_fd, key_name):
        proc = subprocess.run(
            ["gpgv", "--status-fd", "1", "--keyring", key_name, "-", data_name],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=signature,
            pass_fds=(data_fd, key_fd),
        )
    proc.stdout = proc.stdout.decode("utf-8") if isinstance(proc.stdout, bytes) else proc.stdout
    proc.stderr = proc.stderr.decode("utf-8") if isinstance(proc.stderr, bytes) else proc.stderr
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


def dearmor_release_key(key_path: Path, temporary_root: Path, *, key_payload: bytes | None = None) -> bytes:
    """Convert the locked ASCII-armored release key to a bounded gpgv keyring."""
    key_bytes = key_path.read_bytes() if key_payload is None else key_payload
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
        if type(total_limit) is not int or total_limit < 1:
            raise ProvisionError("cumulative acquisition byte ceiling must be a positive integer")
        self.root = root
        self.total_limit = total_limit
        self.total = 0
        self.root.mkdir(parents=True, exist_ok=True)

    def _open_request(self, request, source_netloc: str, allow_github_redirect: bool):
        opener = urllib.request.build_opener(LockedRedirectHandler(source_netloc, allow_github_redirect))
        return opener.open(request, timeout=30)

    def get(self, url: str, expected_size: int | None = None, expected_sha256: str | None = None,
            max_bytes: int = MAX_SINGLE_DOWNLOAD, allow_github_redirect: bool = False) -> tuple[bytes, dict]:
        if type(max_bytes) is not int or max_bytes < 1:
            raise ProvisionError("per-object acquisition byte ceiling must be a positive integer")
        remaining = self.total_limit - self.total
        if remaining < 1:
            raise ProvisionError("cumulative acquisition exceeds configured byte ceiling")
        byte_limit = min(max_bytes, remaining)
        ceiling = ("cumulative acquisition exceeds configured byte ceiling" if remaining < max_bytes
                   else "remote object exceeds configured per-object byte ceiling")
        if expected_size is not None and expected_size > byte_limit:
            raise ProvisionError(ceiling)
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
                if announced is not None and int(announced) > byte_limit:
                    raise ProvisionError(ceiling)
                data = response.read(byte_limit + 1)
        except (OSError, ValueError) as error:
            raise ProvisionError(f"public HTTPS acquisition failed for {url}: {type(error).__name__}: {error}") from error
        self.total += len(data)
        if len(data) > byte_limit:
            raise ProvisionError(ceiling)
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


def source_location_identity(package_name: object, version: object, directory: object,
                             suite: object, component: object, profile: dict) -> dict[str, str]:
    """Validate and normalize the signed source row's complete location identity."""
    if package_name != profile["sourcePackage"]["name"] or version != profile["sourcePackage"]["version"]:
        raise ProvisionError("signed source package name/version differs from the pinned profile")
    if suite not in profile["suites"] or component not in profile["components"]:
        raise ProvisionError("signed source row suite/component is outside the pinned profile")
    if not isinstance(directory, str):
        raise ProvisionError("signed source Directory field is missing or unsafe")
    parts = PurePosixPath(directory).parts
    bucket = "lib" if str(package_name).startswith("lib") else str(package_name)[0].lower()
    if (directory != "/".join(parts) or len(parts) < 4 or parts[0] != "pool" or
            parts[1] != component or parts[2] != bucket or
            any(part in ("", ".", "..") or re.fullmatch(r"[A-Za-z0-9+._~-]+", part) is None
                for part in parts)):
        raise ProvisionError("signed source Directory does not identify the pinned component/package pool path")
    return {
        "name": str(package_name), "version": str(version), "directory": directory,
        "suite": str(suite), "component": str(component),
    }


def candidate_source_location_identity(source: dict, profile: dict) -> dict[str, str]:
    if not isinstance(source, dict):
        raise ProvisionError("candidate source location identity is malformed")
    return source_location_identity(
        source.get("name"), source.get("version"), source.get("directory"),
        source.get("suite"), source.get("component"), profile,
    )


def verify_candidate_source_identity(candidate_source: dict, signed_source: dict, profile: dict) -> None:
    expected = source_location_identity(
        signed_source.get("Package"), signed_source.get("Version"), signed_source.get("Directory"),
        signed_source.get("_suite"), signed_source.get("_component"), profile,
    )
    if candidate_source_location_identity(candidate_source, profile) != expected:
        raise ProvisionError("candidate source location identity differs from the selected signed source row")


def select_source_record(indexes: list[dict], package_name: str, version: str, profile: dict) -> dict:
    """Select identical signed copies by explicit pinned suite/component order."""
    rows = [row for row in indexes if row.get("Package") == package_name and row.get("Version") == version]
    identities = []
    for row in rows:
        identities.append(source_location_identity(
            row.get("Package"), row.get("Version"), row.get("Directory"),
            row.get("_suite"), row.get("_component"), profile,
        ))
        source_file_rows(row)
    unique_coordinates = {(row["suite"], row["component"]) for row in identities}
    payload_identities = {
        (row["directory"], tuple(sorted((item["name"], item["bytes"], item["sha256"])
                                         for item in source_file_rows(source))))
        for row, source in zip(identities, rows)
    }
    if not rows or len(unique_coordinates) != len(rows) or len(payload_identities) != 1:
        observed = sorted({
            f"{row.get('Version', '<missing>')}@{row.get('_suite', '<unknown>')}/{row.get('_component', '<unknown>')}"
            for row in indexes if row.get("Package") == package_name
        })
        observed_text = ", ".join(observed) if observed else "none"
        raise ProvisionError(
            f"expected a unique signed source record for {package_name}={version}; "
            f"found {len(rows)} exact records; observed signed versions: {observed_text}"
        )
    suite_order = {suite: index for index, suite in enumerate(profile["suites"])}
    component_order = {component: index for index, component in enumerate(profile["components"])}
    rows.sort(key=lambda row: (suite_order[row["_suite"]], component_order[row["_component"]]))
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
                                keyring: Path, contract_path: Path = CONTRACT_PATH) -> dict:
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
        "contractSha256": sha256_file(contract_path),
        "recipe": recipe_identity(contract_path),
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


def probe_snapshot_metadata(contract: dict, snapshot: str, output: Path, keyring: Path,
                            contract_path: Path = CONTRACT_PATH) -> dict:
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
        signer = verify_gpgv(inrelease_path, keyring, set(profile["ubuntuArchivePrimaryFingerprints"]),
                            data_payload=inrelease)
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
                for row in iter_compressed_index(index_path_out, payload=packed):
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
                                           source_rows, binary_rows, downloader.total, keyring, contract_path)
    evidence["evidenceSha256"] = sha256(canonical_json(evidence))
    atomic_write(output / "snapshot-metadata-report.json", canonical_json(evidence))
    return evidence


def acquisition_status() -> dict:
    """Read-only prerequisite state; acquisition permission is never qualification."""
    return {
        "schemaVersion": 1,
        "scope": "acquisition-prerequisite-status-only",
        "acquisitionEnabled": UPSTREAM_SIGNATURE_ACCESS_ENABLED,
        "acquisitionStatus": "available" if UPSTREAM_SIGNATURE_ACCESS_ENABLED else "paused",
        "nativeQualification": "not-run" if UPSTREAM_SIGNATURE_ACCESS_ENABLED else "skipped",
        "acceptanceStatus": "incomplete",
        "qualified": False,
        "reason": ("Acquisition prerequisite enabled; native qualification has not run."
                   if UPSTREAM_SIGNATURE_ACCESS_ENABLED else ACQUISITION_PAUSE_REASON),
    }


def require_acquisition_access() -> None:
    if not UPSTREAM_SIGNATURE_ACCESS_ENABLED:
        raise ProvisionError(ACQUISITION_PAUSE_REASON)


def acquire_candidate(contract: dict, output: Path, keyring: Path) -> dict:
    require_acquisition_access()
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
        signer = verify_gpgv(inrelease_path, keyring, set(profile["ubuntuArchivePrimaryFingerprints"]),
                            data_payload=inrelease)
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
                for row in iter_compressed_index(archive_path, payload=packed):
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
    source = select_source_record(all_sources, source_pin["name"], source_pin["version"], profile)
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
        upstream_signature_path, upstream_archive_path, upstream_keyring_path, upstream["primaryFingerprint"],
        data_payload=archive_bytes, signature_payload=signature_bytes, key_payload=upstream_keyring_bytes,
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
    candidate_source_location_identity(candidate.get("source"), contract["profile"])
    keyring = candidate.get("trustedKeyring", {})
    if (keyring.get("bytes", 0) < 1 or not isinstance(keyring.get("sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", keyring["sha256"])):
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


def verify_candidate_data(candidate_root: Path, candidate: dict, contract: dict, keyring: Path,
                          extra_binary_package_names: set[str] | None = None, *,
                          captured: dict[Path, bytes] | None = None) -> list[dict]:
    """Recheck signed metadata and all acquired bytes before rootfs provisioning."""
    profile = contract["profile"]
    ensure_source_artifact_contract(candidate, contract)
    keyring_bytes = captured_evidence(keyring, captured, 1024 * 1024)
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
        payload = read_regular_evidence(inrelease_path, 8 * 1024 * 1024)
        if len(payload) != inrelease["bytes"] or sha256(payload) != inrelease["sha256"]:
            raise ProvisionError(f"candidate InRelease bytes changed for {suite}")
        signer = verify_gpgv(inrelease_path, keyring, set(profile["ubuntuArchivePrimaryFingerprints"]),
                            data_payload=payload, key_payload=keyring_bytes)
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
                packed = read_regular_evidence(candidate_root / index_pathname)
                if len(packed) != expected[0] or sha256(packed) != expected[1]:
                    raise ProvisionError(f"candidate package index hash/length mismatch for {suite}/{table_path}")
                if len(packed) != index["bytes"] or sha256(packed) != index["sha256"]:
                    raise ProvisionError(f"candidate index record changed for {suite}/{table_path}")
                wanted_source = profile["sourcePackage"]["name"]
                wanted_roots = {row["name"] for row in profile["binaryRoots"]}
                wanted_roots.update(extra_binary_package_names or set())
                for row in iter_compressed_index(candidate_root / index_pathname, payload=packed):
                    if index["kind"] == "source" and row.get("Package") != wanted_source:
                        continue
                    if index["kind"] == "binary-amd64" and row.get("Package") not in wanted_roots:
                        continue
                    parsed_indexes.append(dict(row, _suite=suite, _component=component))

    source_pin = profile["sourcePackage"]
    source = select_source_record(parsed_indexes, source_pin["name"], source_pin["version"], profile)
    verify_candidate_source_identity(candidate["source"], source, profile)
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
        verify_regular_evidence_identity(path, row["bytes"], row["sha256"])
    upstream = profile["upstream"]
    key = ROOT / upstream["keyFile"]
    key_bytes = captured_evidence(key, captured, 1024 * 1024)
    if sha256(key_bytes) != upstream["keySha256"]:
        raise ProvisionError("pinned LLVM release key bytes changed")
    upstream_keyring_record = candidate["source"]["upstreamKeyring"]
    upstream_keyring_path = candidate_root / upstream_keyring_record["path"]
    expected_keyring = dearmor_release_key(key, candidate_root, key_payload=key_bytes)
    upstream_keyring_bytes = read_regular_evidence(upstream_keyring_path, 1024 * 1024)
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
    archive_bytes = read_regular_evidence(archive_path)
    signature_bytes = read_regular_evidence(signature_path, 1024 * 1024)
    if (len(archive_bytes) != candidate["source"]["upstreamArchive"]["bytes"] or
            sha256(archive_bytes) != candidate["source"]["upstreamArchive"]["sha256"]):
        raise ProvisionError("upstream LLVM source archive changed")
    if (len(signature_bytes) != candidate["source"]["upstreamSignature"]["bytes"] or
            sha256(signature_bytes) != candidate["source"]["upstreamSignature"]["sha256"]):
        raise ProvisionError("upstream LLVM source signature bytes changed")
    upstream_signer = verify_detached_signature(
        signature_path, archive_path, upstream_keyring_path, upstream["primaryFingerprint"],
        data_payload=archive_bytes, signature_payload=signature_bytes, key_payload=upstream_keyring_bytes,
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


def _mask_cxx_comments_and_literals(text: str) -> str:
    """Keep source layout while masking comments and quoted bytes from brace scanning."""
    output = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                output[index] = output[index + 1] = " "
                index += 1
                state = "code"
            elif char != "\n":
                output[index] = " "
        elif state == "literal":
            if char != "\n":
                output[index] = " "
            if char == "\\":
                if index + 1 < len(text) and text[index + 1] != "\n":
                    output[index + 1] = " "
                index += 1
            elif char == quote:
                state = "code"
        elif char == "/" and next_char == "/":
            output[index] = output[index + 1] = " "
            index += 1
            state = "line-comment"
        elif char == "/" and next_char == "*":
            output[index] = output[index + 1] = " "
            index += 1
            state = "block-comment"
        elif char in ('"', "'"):
            quote = char
            output[index] = " "
            state = "literal"
        index += 1
    return "".join(output)


def _cxx_template_close(tokens: list[str], start: int) -> int | None:
    """Return a plausible template-id's closing angle without treating nested commas as fields."""
    if start == 0 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[start - 1]):
        return None
    angle_depth = 1
    paren_depth = bracket_depth = brace_depth = 0
    for index in range(start + 1, len(tokens)):
        token = tokens[index]
        if token == "(":
            paren_depth += 1
        elif token == ")" and paren_depth:
            paren_depth -= 1
        elif token == "[":
            bracket_depth += 1
        elif token == "]" and bracket_depth:
            bracket_depth -= 1
        elif token == "{":
            brace_depth += 1
        elif token == "}" and brace_depth:
            brace_depth -= 1
        elif not (paren_depth or bracket_depth or brace_depth):
            if token == "<":
                angle_depth += 1
            elif token == ">":
                angle_depth -= 1
                if angle_depth == 0:
                    return index
    return None

_CXX_NON_FUNCTION_IDENTIFIERS = frozenset("""
alignas alignof asm auto bool break case catch char char8_t char16_t char32_t
class compl concept const consteval constexpr constinit const_cast continue
co_await co_return co_yield decltype default delete do double dynamic_cast else
enum explicit export extern false float for friend goto if inline int long
mutable namespace new noexcept not not_eq nullptr operator private protected
public register reinterpret_cast requires return short signed sizeof static
static_assert static_cast struct switch template this thread_local throw true
try typedef typeid typename union unsigned using virtual void volatile wchar_t
while typeof __typeof __typeof__ __alignof__ __attribute__ __declspec
""".split())

_CXX_DECLARATION_SPECIFIERS = frozenset("""
const consteval constexpr constinit explicit export extern friend inline
mutable register static thread_local typedef virtual
""".split())

def _cxx_prefix_has_method_parameter_list(prefix: str, class_name: str) -> bool:
    """Recognize only a supported function declarator before a member body.

    Parentheses inside a template-id (for example ``std::function<void()>``)
    are deliberately nested under angle delimiters and do not identify a
    method. A parameter-list pair must have a callable name and a preceding
    return type, constructor/destructor name, or operator name. This keeps
    type operators such as ``decltype(expr)`` and parenthesized fields such as
    ``int (field) {}`` out of the function-body path. Default-argument equals
    signs remain nested under the method's parameter parentheses.
    """
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|::|&&|->|<=|>=|==|!=|\S", prefix)
    paren_depth = bracket_depth = 0
    top_level_parens: list[tuple[int, int]] = []
    open_index: int | None = None
    top_level_initializer = False
    token_index = 0
    while token_index < len(tokens):
        token = tokens[token_index]
        if token == "<":
            template_close = _cxx_template_close(tokens, token_index)
            if template_close is not None:
                token_index = template_close + 1
                continue
        if token == "[":
            bracket_depth += 1
        elif token == "]" and bracket_depth:
            bracket_depth -= 1
        elif not bracket_depth and token == "(":
            if paren_depth == 0:
                open_index = token_index
            paren_depth += 1
        elif not bracket_depth and token == ")" and paren_depth:
            paren_depth -= 1
            if paren_depth == 0 and open_index is not None:
                top_level_parens.append((open_index, token_index))
                open_index = None
        elif not (paren_depth or bracket_depth) and token == "=":
            top_level_initializer = True
        token_index += 1
    if top_level_initializer or paren_depth or bracket_depth or not top_level_parens:
        return False

    # A trailing return type or noexcept expression can add more top-level
    # parenthesis pairs after the actual parameter list, so inspect every
    # candidate pair. Requiring a return type before the callable name avoids
    # interpreting decltype(expr), alignas(expr), or an unknown parenthesized
    # declarator as a method body.
    for signature_open, _ in top_level_parens:
        before = tokens[:signature_open]
        callable_name = before[-1] if before else ""
        if "operator" in before:
            return True
        if callable_name == class_name or (
                len(before) >= 2 and before[-2:] == ["~", class_name]):
            return True
        if (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", callable_name) is not None and
                callable_name not in _CXX_NON_FUNCTION_IDENTIFIERS and
                any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token) and
                    token not in _CXX_DECLARATION_SPECIFIERS
                    for token in before[:-1])):
            return True
    return False


def _cxx_member_declarator_names(statement: str, class_name: str) -> list[str]:
    """Scan the supported pinned-header declarators; reject ambiguous direct state."""
    statement = re.sub(r"\b(?:public|protected|private)\s*:\s*", " ", statement).strip()
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|::|&&|->|<=|>=|==|!=|\S", statement)
    if not tokens:
        return []
    templated = tokens[0] == "template"
    if templated:
        close = _cxx_template_close(tokens, 1) if len(tokens) > 1 and tokens[1] == "<" else None
        if close is None or close + 1 >= len(tokens):
            raise ProvisionError("unsupported direct template state declaration in pinned LangOptions header")
        tokens = tokens[close + 1:]
    identifier = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    reserved = {"void", "bool", "char", "short", "int", "long", "signed", "unsigned",
                "float", "double", "const", "volatile", "static", "constexpr", "mutable", "auto"}
    if tokens[0] in {"using", "typedef", "friend", "static_assert"}:
        return []
    if tokens[0] in {"class", "struct", "union", "enum"}:
        if len(tokens) == 2 and identifier.fullmatch(tokens[1]):
            return []  # A type-only forward declaration cannot add direct data state.
        raise ProvisionError("unsupported direct state declaration in pinned LangOptions header")
    if (any(token in {"__attribute__", "__declspec"} for token in tokens) or
            any(tokens[index:index + 2] == ["[", "["] for index in range(len(tokens)))):
        raise ProvisionError("unsupported direct state declaration in pinned LangOptions header")

    def supported_return_type(prefix: list[str]) -> bool:
        if prefix == ["decltype", "(", "auto", ")"]:
            return True
        qualifiers = {"const", "volatile", "static", "constexpr", "consteval", "inline", "virtual", "explicit", "typename"}
        builtin_types = {"void", "bool", "char", "short", "int", "long", "signed", "unsigned", "float", "double", "auto"}
        atoms = 0
        builtin = False
        index = 0
        while index < len(prefix):
            token = prefix[index]
            if token in qualifiers or token in {"*", "&", "&&"}:
                index += 1
            elif token in builtin_types:
                builtin = True
                index += 1
            elif identifier.fullmatch(token):
                atoms += 1
                index += 1
                while index + 1 < len(prefix) and prefix[index] == "::" and identifier.fullmatch(prefix[index + 1]):
                    index += 2
                if index < len(prefix) and prefix[index] == "<":
                    depth = 0
                    while index < len(prefix):
                        if prefix[index] == "<":
                            depth += 1
                        elif prefix[index] == ">":
                            depth -= 1
                        index += 1
                        if depth == 0:
                            break
                    if depth:
                        return False
            else:
                return False
        return (builtin and atoms == 0) or (not builtin and atoms == 1)

    if "operator" in tokens and _cxx_prefix_has_method_parameter_list(statement, class_name):
        if not supported_return_type(tokens[:tokens.index("operator")]):
            raise ProvisionError("unsupported direct operator/state declaration in pinned LangOptions header")
        # An operator such as '<' is punctuation in its name, not an unmatched template angle.
        nesting = {"(": 0, "[": 0, "{": 0}
        matching = {")": "(", "]": "[", "}": "{"}
        for token in tokens[tokens.index("operator") + 1:]:
            if token in nesting:
                nesting[token] += 1
            elif token in matching and nesting[matching[token]]:
                nesting[matching[token]] -= 1
            elif token == "," and not any(nesting.values()):
                raise ProvisionError("unsupported direct mixed method/state declaration in pinned LangOptions header")
        return []

    initializer_start = first_paren = len(tokens)
    angle_depth = bracket_depth = 0
    for index, token in enumerate(tokens):
        if not angle_depth and not bracket_depth:
            if token in ("=", "{"):
                initializer_start = index
                break
            if token == "(":
                first_paren = index
                break
        if token == "<":
            angle_depth += 1
        elif token == ">" and angle_depth:
            angle_depth -= 1
        elif token == "[":
            bracket_depth += 1
        elif token == "]" and bracket_depth:
            bracket_depth -= 1
    if first_paren < initializer_start:
        if tokens[:first_paren] == ["decltype"]:
            # Support the pinned method return spelling without treating a decltype field as a method.
            if tokens[first_paren:first_paren + 3] == ["(", "auto", ")"]:
                next_open = first_paren + 4
                if next_open < len(tokens) and tokens[next_open] == "(":
                    first_paren = next_open
        prefix = tokens[:first_paren]
        group_prefix = " ".join(tokens[first_paren + 1:])
        if re.match(r"^(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*[*&]", group_prefix):
            raise ProvisionError("unsupported direct parenthesized state declarator in pinned LangOptions header")
        if prefix in ([class_name], ["~", class_name]):
            return []
        if (prefix and identifier.fullmatch(prefix[-1]) and prefix[-1] not in reserved and
                supported_return_type(prefix[:-1])):
            nesting = {"<": 0, "(": 0, "[": 0, "{": 0}
            matching = {">": "<", ")": "(", "]": "[", "}": "{"}
            for token in tokens[first_paren:]:
                if token in nesting:
                    nesting[token] += 1
                elif token in matching and nesting[matching[token]]:
                    nesting[matching[token]] -= 1
                elif token == "," and not any(nesting.values()):
                    raise ProvisionError("unsupported direct mixed method/state declaration in pinned LangOptions header")
            return []  # Only a supported method prefix may discard a parameter list.
        raise ProvisionError("unsupported direct parenthesized state declarator in pinned LangOptions header")

    if templated:
        raise ProvisionError("unsupported direct template state declaration in pinned LangOptions header")

    # Split each declarator before stripping its own initializer. Nested initializer commas
    # and template arguments stay within their declarator rather than hiding later fields.
    chunks = []
    current = []
    depths = {"<": 0, "(": 0, "[": 0, "{": 0}
    closing = {">": "<", ")": "(", "]": "[", "}": "{"}
    for token in tokens:
        if token in depths:
            depths[token] += 1
        elif token in closing:
            opener = closing[token]
            if not depths[opener]:
                raise ProvisionError("unsupported direct unbalanced declarator in pinned LangOptions header")
            depths[opener] -= 1
        if token == "," and not any(depths.values()):
            chunks.append(current)
            current = []
        else:
            current.append(token)
    if any(depths.values()) or not current:
        raise ProvisionError("unsupported direct unbalanced declarator in pinned LangOptions header")
    chunks.append(current)

    names = []
    for index, chunk in enumerate(chunks):
        head = []
        angle_depth = 0
        for token in chunk:
            if not angle_depth and token in ("=", "{", "[", ":"):
                break
            if token == "<":
                angle_depth += 1
            elif token == ">":
                angle_depth -= 1
            head.append(token)
        root_identifiers = []
        angle_depth = 0
        for token in head:
            if token == "<":
                angle_depth += 1
            elif token == ">":
                angle_depth -= 1
            elif not angle_depth and identifier.fullmatch(token):
                root_identifiers.append(token)
            elif token not in {"::", "*", "&", "&&", ","} and not angle_depth:
                raise ProvisionError("unsupported direct state declarator in pinned LangOptions header")
        if (not head or not identifier.fullmatch(head[-1]) or head[-1] in reserved or
                len(root_identifiers) < (2 if index == 0 else 1) or
                (index > 0 and len(root_identifiers) != 1)):
            raise ProvisionError("unsupported direct state declarator in pinned LangOptions header")
        names.append(head[-1])
    return names


def extract_cxx_class_data_members(text: str, class_name: str) -> list[str]:
    """Enumerate supported pinned-header fields, rejecting unrecognized direct state."""
    # This exact pinned accessor block expands only methods. Other directives inside
    # the class remain unsupported rather than being silently omitted from the audit.
    accessor_block = r"""#define LANGOPT(Name, Bits, Default, Description)
#define ENUM_LANGOPT(Name, Type, Bits, Default, Description) \
  Type get##Name() const { return static_cast<Type>(Name); } \
  void set##Name(Type Value) { Name = static_cast<unsigned>(Value); }
#include "clang/Basic/LangOptions.def"
"""
    scanned_text = text.replace(accessor_block, "".join("\n" if char == "\n" else " " for char in accessor_block))
    masked = _mask_cxx_comments_and_literals(scanned_text)
    match = re.search(r"\bclass\s+" + re.escape(class_name) + r"\b[^;{}]*\{", masked)
    if match is None:
        raise ProvisionError(f"header does not contain the {class_name} class definition")
    open_brace = match.end() - 1
    depth = 1
    close_brace = open_brace + 1
    while close_brace < len(masked) and depth:
        if masked[close_brace] == "{":
            depth += 1
        elif masked[close_brace] == "}":
            depth -= 1
        close_brace += 1
    if depth:
        raise ProvisionError(f"header contains an unterminated {class_name} class definition")
    body = masked[open_brace + 1:close_brace - 1]
    if "#" in body:
        raise ProvisionError("unsupported direct preprocessor state declaration in pinned LangOptions header")
    names = []
    statement = []
    initializer_depth = 0
    index = 0
    while index < len(body):
        char = body[index]
        if char == "{" and initializer_depth == 0:
            prefix = "".join(statement)
            declaration_head = prefix.split("=", 1)[0]
            type_head = re.sub(r"\b(?:public|protected|private)\s*:\s*", " ", declaration_head).strip()
            is_type_body = re.match(r"^(?:class|struct|union|enum)\b", type_head)
            if is_type_body and re.fullmatch(
                    r"(?:class|struct|union|enum(?:\s+(?:class|struct))?)\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*:\s*[^{};]+)?",
                    type_head) is None:
                raise ProvisionError("unsupported direct anonymous or ambiguous type/state declaration in pinned LangOptions header")
            is_function_body = _cxx_prefix_has_method_parameter_list(prefix, class_name)
            if is_function_body and not is_type_body:
                # Do not discard an unrecognized state declarator as if it were a method body.
                is_function_body = not _cxx_member_declarator_names(prefix, class_name)
            if is_type_body or is_function_body:
                nested = 1
                index += 1
                while index < len(body) and nested:
                    if body[index] == "{":
                        nested += 1
                    elif body[index] == "}":
                        nested -= 1
                    index += 1
                if nested:
                    raise ProvisionError(f"header contains an unterminated {class_name} member body")
                statement = ["__nested_member_type "] if is_type_body else []
                continue
            initializer_depth = 1
            statement.append(char)
        elif char == "{" and initializer_depth:
            initializer_depth += 1
            statement.append(char)
        elif char == "}" and initializer_depth:
            initializer_depth -= 1
            statement.append(char)
        elif char == ";" and initializer_depth == 0:
            # An already scanned nested type body with no following instance adds no state.
            if "".join(statement).strip() != "__nested_member_type":
                names.extend(_cxx_member_declarator_names("".join(statement), class_name))
            statement = []
        else:
            statement.append(char)
        index += 1
    tail = re.sub(r"\b(?:public|protected|private)\s*:\s*", " ", "".join(statement)).strip()
    if tail:
        raise ProvisionError("unterminated direct state declaration in pinned LangOptions header")
    return names


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
    actual_manual_fields = extract_cxx_class_data_members(header_path.read_text(encoding="utf-8"), "LangOptions")
    expected_manual_fields = spec["manualFields"]
    if (len(actual_manual_fields) != spec["manualFieldsCount"] or
            len(set(actual_manual_fields)) != len(actual_manual_fields) or
            set(actual_manual_fields) != set(expected_manual_fields)):
        missing = sorted(set(expected_manual_fields) - set(actual_manual_fields))
        extra = sorted(set(actual_manual_fields) - set(expected_manual_fields))
        duplicates = sorted({name for name in actual_manual_fields
                             if actual_manual_fields.count(name) > 1})
        raise ProvisionError(
            "LangOptions.h direct manual member inventory mismatch: "
            f"count={len(actual_manual_fields)} expected={spec['manualFieldsCount']}, "
            f"duplicates={duplicates}, missing={missing}, extra={extra}"
        )
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


def read_audited_source_file(root_fd: int, relative: str) -> bytes:
    """Read only through no-follow component FDs below the retained source root."""
    if relative not in REVIEWED_RELEVANT_FILES:
        raise ProvisionError("audited source path is outside the canonical reviewed file policy")
    current = os.dup(root_fd)
    try:
        parts = relative.split("/")
        for component in parts[:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        with os.fdopen(os.open(parts[-1], flags, dir_fd=current), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ProvisionError("audited source input is not a regular file")
            payload = stream.read(MAX_SINGLE_DOWNLOAD + 1)
            after = os.fstat(stream.fileno())
            if len(payload) > MAX_SINGLE_DOWNLOAD:
                raise ProvisionError("audited source input exceeds its byte budget")
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
                    len(payload) != after.st_size):
                raise ProvisionError("audited source input changed during its descriptor read")
            return payload
    finally:
        os.close(current)


def audit_patches(source_root: Path, upstream_root: Path, output: Path, contract: dict) -> dict:
    require_reviewed_relevant_files(contract)
    patch_rows = inventory_patch_files(source_root)
    relevant = []
    differences = []
    root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        with contextlib.ExitStack() as roots:
            packaged_fd = os.open(source_root, root_flags)
            roots.callback(os.close, packaged_fd)
            upstream_fd = os.open(upstream_root, root_flags)
            roots.callback(os.close, upstream_fd)
            total = 0
            for rel in REVIEWED_RELEVANT_FILES:
                try:
                    packaged_bytes = read_audited_source_file(packaged_fd, rel)
                    upstream_bytes = read_audited_source_file(upstream_fd, rel)
                except FileNotFoundError:
                    differences.append({"path": rel, "status": "missing", "packagedSha256": None, "upstreamSha256": None})
                    continue
                total += len(packaged_bytes) + len(upstream_bytes)
                if total > MAX_DOWNLOAD_BYTES:
                    raise ProvisionError("audited source files exceed their cumulative byte budget")
                row = {"path": rel, "bytes": len(packaged_bytes), "packagedSha256": sha256(packaged_bytes), "upstreamSha256": sha256(upstream_bytes)}
                row["status"] = "identical" if packaged_bytes == upstream_bytes else "different"
                row["patchesTouchingPath"] = [patch["path"] for patch in patch_rows if rel in patch["touchedPaths"]]
                relevant.append(row)
                if row["status"] != "identical":
                    differences.append(row)
    except OSError as error:
        raise ProvisionError(f"could not read audited files beneath retained source roots: {error}") from error
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


def command_acquisition_status(args: argparse.Namespace) -> int:
    sys.stdout.write(canonical_json(acquisition_status()).decode("utf-8"))
    return 0


def command_acquire(args: argparse.Namespace) -> int:
    require_acquisition_access()
    contract = read_contract(args.contract)
    candidate = acquire_candidate(contract, args.output, args.keyring)
    ensure_source_artifact_contract(candidate, contract)
    print(f"authenticated acquisition candidate sha256:{candidate['candidateSha256']}")
    print("candidate is not a locked or accepted Clang profile")
    return 0


def command_probe_snapshot_metadata(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    report = probe_snapshot_metadata(contract, args.snapshot, args.output, args.keyring, args.contract)
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
    report = strict_json_loads(args.report.read_text(encoding="utf-8"))
    inventory = strict_json_loads(args.inventory.read_text(encoding="utf-8"))
    checked = validate_probe_report(report, inventory, contract)
    checked["sourceSha256"] = sha256(args.source.read_bytes())
    checked["binarySha256"] = sha256(args.binary.read_bytes())
    atomic_write(args.output, canonical_json(checked))
    print("verified LibTooling probe report against the pinned 18.1.3 contract")
    return 0


def run_checked(command: list[str], *, timeout: int = 900, input_text: str | None = None,
                env: dict[str, str] | None = None, stdout_file=None) -> subprocess.CompletedProcess:
    proc = subprocess.run(command, check=False,
                          stdout=subprocess.PIPE if stdout_file is None else stdout_file,
                          stderr=subprocess.STDOUT if stdout_file is None else subprocess.PIPE,
                          text=True, input=input_text, timeout=timeout, env=env)
    if proc.returncode != 0:
        diagnostic = proc.stdout if stdout_file is None else proc.stderr
        raise ProvisionError(f"command failed ({proc.returncode}): {command!r}\n{diagnostic[-6000:]}")
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


def rootfs_tar_budget_command(rootfs: Path, maximum_bytes: int) -> list[str]:
    if type(maximum_bytes) is not int or maximum_bytes < 1:
        raise ProvisionError("rootfs archive budget must be a positive integer")
    return ["sudo", "-n", "/usr/bin/python3", "-I", "-B", str(RECIPE_FILES["provisionerSha256"]),
            "check-rootfs-tar-budget", "--rootfs", str(rootfs.absolute()), "--max-bytes", str(maximum_bytes)]


def command_check_rootfs_tar_budget(args: argparse.Namespace) -> int:
    rootfs = args.rootfs
    if (not rootfs.is_absolute() or ".." in rootfs.parts or rootfs.is_symlink() or not rootfs.is_dir()):
        raise ProvisionError("rootfs budget inspection requires an absolute non-symlink directory")
    if type(args.max_bytes) is not int or args.max_bytes < 1:
        raise ProvisionError("rootfs archive budget must be a positive integer")
    check_rootfs_tar_budget(rootfs, args.max_bytes)
    print("read-only rootfs archive budget passed; native qualification remains incomplete")
    return 0


def check_rootfs_tar_budget(rootfs: Path, maximum_bytes: int) -> None:
    """Conservatively bound canonical tar input size and entry count before writing it."""
    # The canonical GNU tar command writes at least one default 20 x 512-byte record.
    if maximum_bytes < 20 * 512:
        raise ProvisionError("rootfs archive budget is below the minimum canonical tar record size")
    entry_count = 1  # tar includes the root directory as '.'
    payload_bytes = 0
    max_entries = maximum_bytes // 8192
    try:
        pending = [rootfs]
        while pending:
            current = pending.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    name = entry.name
                    if name in (".", ".."):
                        raise ProvisionError("rootfs contains an invalid directory entry")
                    entry_count += 1
                    if entry_count > max_entries:
                        raise ProvisionError("rootfs entry count exceeds the canonical archive budget")
                    metadata = entry.stat(follow_symlinks=False)
                    mode = metadata.st_mode
                    if stat.S_ISREG(mode):
                        payload_bytes += metadata.st_size
                    elif stat.S_ISDIR(mode):
                        pending.append(current / name)
                    elif not (stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or
                              stat.S_ISBLK(mode) or stat.S_ISFIFO(mode)):
                        raise ProvisionError("rootfs contains an unsupported filesystem entry")
                    if payload_bytes + entry_count * 8192 > maximum_bytes:
                        raise ProvisionError("rootfs contents exceed the canonical archive byte budget")
    except OSError as error:
        raise ProvisionError(f"could not inspect retained rootfs for archive bounds: {error}") from error


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


def run_probe_sandboxed(rootfs: Path, command: list[str], contract: dict,
                        timeout: int = 120) -> str:
    """Fail closed until the reviewed unprivileged resource-bounded adapter is available.

    This intentionally has no fallback to rootfs_run/run_checked: sudo chroot does not
    contain a candidate probe or descendants and their output is not bounded there.
    """
    raise ProvisionError(PROBE_SANDBOX_BLOCK_REASON)


def candidate_build_evidence(candidate: dict, contract: dict) -> dict:
    repositories = [{
        "suite": row["suite"], "inRelease": row["inRelease"]["finalUrl"],
        "sha256": row["inRelease"]["sha256"], "bytes": row["inRelease"]["bytes"],
        "signerPrimaryFingerprint": row["signerPrimaryFingerprint"],
    } for row in candidate["repositories"]]
    source_files = [{
        "name": row["name"], "bytes": row["bytes"], "sha256": row["sha256"],
        "role": "dsc" if row["name"].endswith(".dsc") else (
            "debian-patches" if ".debian." in row["name"] else "upstream-source"),
    } for row in candidate["source"]["files"]]
    dsc_rows = [row for row in source_files if row["role"] == "dsc"]
    if len(dsc_rows) != 1:
        raise ProvisionError("authenticated source inputs do not identify one .dsc")
    return {
        "acquisition": {
            "repositories": repositories,
            "ubuntuKeyring": candidate["trustedKeyring"],
            "candidateSha256": candidate["candidateSha256"],
            "sourceIndexesSha256": sha256(canonical_json([
                row for row in candidate["indexes"] if row["kind"] == "source"])),
            "binaryIndexesSha256": sha256(canonical_json([
                row for row in candidate["indexes"] if row["kind"] == "binary-amd64"])),
            "signatureFingerprints": [row["signerPrimaryFingerprint"] for row in candidate["repositories"]],
        },
        "source": {
            "package": candidate["source"]["name"], "version": candidate["source"]["version"],
            "upstreamTag": contract["profile"]["upstream"]["tag"],
            "dsc": {key: dsc_rows[0][key] for key in ("bytes", "sha256")},
            "files": source_files,
            **{field: {key: candidate["source"][field][key] for key in ("bytes", "sha256")}
               for field in ("upstreamArchive", "upstreamSignature", "upstreamKeyring")},
        },
        "patchAudit": candidate["patchAudit"],
    }


def candidate_download_rows(candidate: dict) -> list[dict]:
    source = candidate["source"]
    return [*[row["inRelease"] for row in candidate["repositories"]],
            *candidate["indexes"], *source["files"], source["upstreamKeyring"],
            {**source["upstreamArchive"], "path": source["upstreamArchivePath"]},
            {**source["upstreamSignature"], "path": source["upstreamSignaturePath"]}]


def verify_candidate_download_inventory(candidate_root: Path, candidate: dict) -> None:
    """Require every packaged download to have a unique candidate-bound identity."""
    rows = candidate_download_rows(candidate)
    expected_paths: set[str] = set()
    for row in rows:
        relative = PurePosixPath(row["path"])
        if (relative.is_absolute() or ".." in relative.parts or len(relative.parts) < 2 or
                relative.parts[0] != "downloads" or relative.as_posix() != row["path"] or
                row["path"] in expected_paths):
            raise ProvisionError("candidate download inventory contains an unsafe or duplicate path")
        expected_paths.add(row["path"])
        path = candidate_root.joinpath(*relative.parts)
        if (any(candidate_root.joinpath(*relative.parts[:index]).is_symlink()
                for index in range(1, len(relative.parts) + 1)) or not path.is_file()):
            raise ProvisionError("candidate download inventory contains a missing or non-regular file")
        verify_regular_evidence_identity(path, row["bytes"], row["sha256"])
    actual_paths: set[str] = set()
    for directory, dirnames, filenames in os.walk(candidate_root / "downloads", followlinks=False):
        current = Path(directory)
        if any((current / name).is_symlink() for name in dirnames):
            raise ProvisionError("candidate download inventory contains a symlink directory")
        for name in filenames:
            path = current / name
            if path.is_symlink() or not path.is_file():
                raise ProvisionError("candidate download inventory contains a non-regular file")
            actual_paths.add(path.relative_to(candidate_root).as_posix())
    if actual_paths != expected_paths:
        raise ProvisionError("candidate download inventory contains unrecorded files")


def copy_verified_source_payload(source: Path, destination: Path, expected_bytes: int,
                                 expected_sha256: str) -> None:
    """Copy one already-authenticated retained payload into fresh scratch, rechecking bytes."""
    if (type(expected_bytes) is not int or expected_bytes < 0 or not isinstance(expected_sha256, str) or
            not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
        raise ProvisionError("authenticated source payload identity is malformed")
    digest = hashlib.sha256()
    copied = 0
    try:
        source_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(source, source_flags), "rb") as incoming:
            if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):
                raise ProvisionError("authenticated source payload is not a regular file")
            with destination.open("xb") as outgoing:
                while True:
                    block = incoming.read(1024 * 1024)
                    if not block:
                        break
                    copied += len(block)
                    if copied > expected_bytes:
                        raise ProvisionError("verified source payload grew while copying to audit scratch")
                    digest.update(block)
                    outgoing.write(block)
    except ProvisionError:
        destination.unlink(missing_ok=True)
        raise
    except OSError as error:
        destination.unlink(missing_ok=True)
        raise ProvisionError(f"could not copy verified source payload to audit scratch: {error}") from error
    if copied != expected_bytes or digest.hexdigest() != expected_sha256:
        destination.unlink(missing_ok=True)
        raise ProvisionError("verified source payload changed while copying to audit scratch")


def audit_fresh_source_payloads(candidate_root: Path, candidate: dict,
                                scratch_root: Path, contract: dict) -> dict:
    """Recreate both source trees from verified payload bytes; never reuse caller-owned trees."""
    source = candidate.get("source")
    files = source.get("files") if isinstance(source, dict) else None
    if not isinstance(files, list):
        raise ProvisionError("authenticated source inputs are malformed for audit replay")
    dsc_rows = [row for row in files if isinstance(row, dict) and row.get("name", "").endswith(".dsc")]
    if len(dsc_rows) != 1:
        raise ProvisionError("authenticated source inputs do not identify one .dsc for audit replay")

    payload_dir = scratch_root / "verified-source-payloads"
    payload_dir.mkdir()
    dsc_path: Path | None = None
    seen_names: set[str] = set()
    for row in files:
        if (not isinstance(row, dict) or not isinstance(row.get("name"), str) or
                PurePosixPath(row["name"]).name != row["name"] or row["name"] in seen_names or
                not isinstance(row.get("path"), str)):
            raise ProvisionError("authenticated source payload inventory is malformed")
        seen_names.add(row["name"])
        relative = PurePosixPath(row["path"])
        if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("downloads",):
            raise ProvisionError("authenticated source payload path is unsafe")
        original = candidate_root.joinpath(*relative.parts)
        copied = payload_dir / row["name"]
        copy_verified_source_payload(original, copied, row.get("bytes"), row.get("sha256"))
        if row is dsc_rows[0]:
            dsc_path = copied
    if dsc_path is None:
        raise ProvisionError("authenticated source inputs do not contain their pinned .dsc")

    upstream_path = source.get("upstreamArchivePath")
    if not isinstance(upstream_path, str):
        raise ProvisionError("authenticated upstream source archive path is malformed")
    upstream_relative = PurePosixPath(upstream_path)
    upstream_identity = source.get("upstreamArchive")
    if (upstream_relative.is_absolute() or ".." in upstream_relative.parts or
            upstream_relative.parts[:1] != ("downloads",) or not isinstance(upstream_identity, dict)):
        raise ProvisionError("authenticated upstream source archive path is unsafe")
    copied_upstream = scratch_root / "upstream-source.tar.xz"
    copy_verified_source_payload(
        candidate_root.joinpath(*upstream_relative.parts), copied_upstream,
        upstream_identity.get("bytes"), upstream_identity.get("sha256"),
    )

    package_source = scratch_root / "package-source"
    extract = subprocess.run(
        ["dpkg-source", "-x", str(dsc_path), str(package_source)],
        cwd=payload_dir, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=900,
    )
    if extract.returncode != 0:
        raise ProvisionError(
            "dpkg-source rejected the verified .dsc/payload during audit replay: " + extract.stdout[-4000:]
        )
    upstream_root = safe_extract_xz_tar(copied_upstream, scratch_root / "upstream")
    return audit_patches(package_source, upstream_root, scratch_root / "patch-audit.json", contract)


def load_candidate(candidate_root: Path, contract: dict, keyring: Path,
                   build_record: dict | None = None, *,
                   captured: dict[Path, bytes] | None = None) -> tuple[dict, list[dict]]:
    candidate_path = candidate_root / "acquisition-candidate.json"
    candidate = read_provenance_report(candidate_path, "acquisition candidate", captured=captured)
    ensure_source_artifact_contract(candidate, contract)
    if build_record is not None:
        for section, expected in candidate_build_evidence(candidate, contract).items():
            if build_record.get(section) != expected:
                raise ProvisionError(f"acquisition candidate {section} differs from the build record")
    verify_candidate_download_inventory(candidate_root, candidate)
    extra_package_names = None
    if build_record is not None:
        extra_package_names = {
            row["name"]
            for section in ("packages", "downloadedPackages")
            for row in build_record.get(section, [])
            if isinstance(row, dict) and isinstance(row.get("name"), str)
        }
    parsed = verify_candidate_data(
        candidate_root, candidate, contract, keyring,
        extra_binary_package_names=extra_package_names,
        **({"captured": captured} if captured is not None else {}),
    )
    audit_path = candidate_root / "patch-audit.json"
    audit = read_provenance_report(audit_path, "patch audit", captured=captured)
    if audit.get("status") != "compatible" or candidate.get("patchAudit") != {
        key: audit[key] for key in ("status", "patchCount", "patchInventorySha256", "relevantFileCount", "relevantFileManifestSha256")
    }:
        raise ProvisionError("patch audit is missing, incompatible, or changed after acquisition")
    with tempfile.TemporaryDirectory(prefix="patch-audit-replay-", dir=candidate_root) as replay_root:
        reaudited = audit_fresh_source_payloads(candidate_root, candidate, Path(replay_root), contract)
        if canonical_json(reaudited) != canonical_json(audit):
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


def validate_record_package_metadata(record: dict, signed_metadata: dict[tuple[str, str, str], dict],
                                     installed_keys: set[tuple[str, str, str]] | None = None) -> None:
    """Bind every package row and the installed closure to authenticated Packages metadata."""
    package_rows = record.get("packages", [])
    downloaded_rows = record.get("downloadedPackages", [])
    package_keys = [(row.get("name"), row.get("version"), row.get("architecture"))
                    for row in package_rows if isinstance(row, dict)]
    downloaded_keys = [(row.get("name"), row.get("version"), row.get("architecture"))
                       for row in downloaded_rows if isinstance(row, dict)]
    if (len(package_keys) != len(package_rows) or len(set(package_keys)) != len(package_keys) or
            len(downloaded_keys) != len(downloaded_rows) or len(set(downloaded_keys)) != len(downloaded_keys)):
        raise ProvisionError("build record package closure contains malformed or duplicate identities")
    package_key_set = set(package_keys)
    if installed_keys is not None and package_key_set != installed_keys:
        raise ProvisionError("build record package closure differs from the installed rootfs package set")
    if not set(downloaded_keys).issubset(package_key_set):
        raise ProvisionError("downloaded package rows are outside the installed package closure")
    for section, rows in (("packages", package_rows), ("downloadedPackages", downloaded_rows)):
        for row in rows:
            key = (row["name"], row["version"], row["architecture"])
            expected = signed_metadata.get(key)
            if expected is None or row != expected:
                raise ProvisionError(
                    f"build record {section} tuple differs from signed Packages metadata: {key[0]}={key[1]}"
                )


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
        packed = read_regular_evidence(path)
        if len(packed) != index["bytes"] or sha256(packed) != index["sha256"]:
            raise ProvisionError("authenticated binary index changed before package closure extraction")
        for row in iter_compressed_index(path, payload=packed):
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


def rootfs_regular_file(rootfs: Path, absolute_path: str, *, executable: bool = False) -> tuple[Path, int]:
    """Require a non-symlink regular file at the exact in-root path."""
    try:
        path = rootfs_path(rootfs, absolute_path)
    except OSError as error:
        raise ProvisionError(f"retained rootfs file is unavailable: {absolute_path}") from error
    root = rootfs.resolve(strict=True)
    current = root
    parts = PurePosixPath(absolute_path).parts[1:]
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ProvisionError(f"retained rootfs file is unavailable: {absolute_path}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ProvisionError(f"retained rootfs file path contains a symlink: {absolute_path}")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise ProvisionError(f"retained rootfs file path contains a non-directory parent: {absolute_path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ProvisionError(f"retained rootfs path is not a regular file: {absolute_path}")
    mode = metadata.st_mode & 0o7777
    if executable and not (mode & 0o111):
        raise ProvisionError(f"retained rootfs executable lacks execute permission: {absolute_path}")
    return path, mode


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


def runtime_file_entry(rootfs: Path, absolute_path: str) -> dict:
    """Retain file kind and symlink bytes so the recorded closure is independently projectable."""
    _, path = symlink_chain(rootfs, absolute_path, follow_leaf=False)
    if path.is_symlink():
        # Interpret absolute targets in the rootfs, never against the host filesystem.
        symlink_chain(rootfs, absolute_path, allow_directory_target=True)
        target = os.readlink(path)
        try:
            target_bytes = target.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise ProvisionError("runtime symlink target is not valid UTF-8") from error
        if len(target_bytes) > 4096:
            raise ProvisionError("runtime symlink target is outside filesystem bounds")
        return {"path": absolute_path, "bytes": len(target_bytes), "sha256": sha256(b"symlink\0" + target_bytes),
                "kind": "symlink", "target": target}
    data = path.read_bytes()
    return {"path": absolute_path, "bytes": len(data), "sha256": sha256(data),
            "kind": "regular-file", "target": None}


def manifest(entries: list[dict]) -> dict:
    entries.sort(key=lambda row: row["path"])
    content = canonical_json({"entries": entries})
    return {"entryCount": len(entries), "bytes": len(content), "sha256": sha256(content), "entries": entries}


def validated_runtime_entries(runtime: object) -> list[dict]:
    if not isinstance(runtime, dict) or set(runtime) != {"entryCount", "bytes", "sha256", "entries"}:
        raise ProvisionError("build record runtime manifest is malformed")
    if (type(runtime["entryCount"]) is not int or runtime["entryCount"] < 1 or
            type(runtime["bytes"]) is not int or runtime["bytes"] < 1 or
            not isinstance(runtime["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", runtime["sha256"]) is None):
        raise ProvisionError("build record runtime manifest has invalid count or byte identity")
    entries = runtime.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ProvisionError("build record runtime manifest is empty or malformed")
    paths = []
    for row in entries:
        if isinstance(row, dict) and set(row) - {"path", "bytes", "sha256", "kind", "target"}:
            raise ProvisionError("build record violates checked-in schema at runtime entry: unknown field")
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256", "kind", "target"}:
            raise ProvisionError("build record runtime entry lacks exact file classification metadata")
        path, size, digest, kind, target = (row[key] for key in ("path", "bytes", "sha256", "kind", "target"))
        if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or
                any(part in ("", ".", "..") for part in path[1:].split("/")) or "\0" in path or "\\" in path or
                type(size) is not int or size < 0 or not isinstance(digest, str) or
                re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            raise ProvisionError("build record runtime entry has invalid file identity")
        try:
            path_bytes = path.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise ProvisionError("build record runtime path is not valid UTF-8") from error
        if len(path_bytes) > 4096 or any(len(part.encode("utf-8")) > 255 for part in path[1:].split("/")):
            raise ProvisionError("build record runtime path is outside filesystem bounds")
        if kind == "regular-file":
            if target is not None:
                raise ProvisionError("regular runtime file must not carry a symlink target")
            if len(b"toolchain") + len(path_bytes) > 4096:
                raise ProvisionError("regular runtime projection path is outside the A-loader bound")
        elif kind == "symlink":
            if not isinstance(target, str) or not target or "\0" in target:
                raise ProvisionError("runtime symlink target is malformed")
            try:
                target_bytes = target.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise ProvisionError("runtime symlink target is not valid UTF-8") from error
            if len(target_bytes) > 4096 or size != len(target_bytes) or digest != sha256(b"symlink\0" + target_bytes):
                raise ProvisionError("runtime symlink target differs from its recorded byte identity")
        else:
            raise ProvisionError("build record runtime file kind is unsupported")
        paths.append(path)
    if paths != sorted(set(paths), key=lambda path: path.encode("utf-8")):
        raise ProvisionError("build record runtime paths are duplicated or not in canonical order")
    expected = manifest(list(entries))
    if any(runtime[key] != expected[key] for key in ("entryCount", "bytes", "sha256")):
        raise ProvisionError("build record runtime manifest digest/count mismatch")
    return entries


def verify_recorded_runtime_manifest(rootfs: Path, record: dict) -> None:
    for row in validated_runtime_entries(record.get("runtime")):
        if runtime_file_entry(rootfs, row["path"]) != row:
            raise ProvisionError(f"runtime file classification or bytes changed before A-loader smoke: {row['path']}")


def symlink_chain(rootfs: Path, logical_path: str, follow_leaf: bool = True,
                  allow_directory_target: bool = False) -> tuple[list[str], Path]:
    rootfs = rootfs.resolve(strict=True)
    pure = PurePosixPath(logical_path)
    if not pure.is_absolute() or ".." in pure.parts:
        raise ProvisionError(f"unsafe path reported by toolchain: {logical_path}")
    current = rootfs
    pending = list(pure.parts[1:])
    chain = []
    visited = set()
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            if current == rootfs:
                raise ProvisionError(f"driver symlink chain escapes rootfs: {logical_path}")
            current = current.parent
            continue
        candidate = current / part
        if candidate.is_symlink() and (pending or follow_leaf):
            rel = candidate.relative_to(rootfs).as_posix()
            if rel in visited or len(chain) >= 16:
                raise ProvisionError(f"symlink cycle/depth overflow for {logical_path}")
            visited.add(rel)
            target = os.readlink(candidate)
            chain.append(f"/{rel} -> {target}")
            target_parts = PurePosixPath(target).parts
            if target.startswith("/"):
                current = rootfs
                target_parts = target_parts[1:]
            pending = list(target_parts) + pending
        else:
            current = candidate
            if pending and not current.is_dir():
                raise ProvisionError(f"driver symlink chain contains a missing/non-directory component: {logical_path}")
    if (not current.is_file() and not (not follow_leaf and current.is_symlink()) and
            not (allow_directory_target and current.is_dir())):
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
    roots = list(dict.fromkeys([*logical_paths,
                                "/usr/lib/llvm-18/lib/libclang-cpp.so",
                                "/usr/lib/llvm-18/lib/libLLVM-18.so"]))
    for logical in roots:
        output = rootfs_run(rootfs, ["/usr/bin/ldd", logical], contract)
        for line in output.splitlines():
            match = re.search(r"=>\s+(/\S+)", line)
            if match:
                paths.add(match.group(1))
            else:
                match = re.match(r"\s*(/\S+)\s+\(0x[0-9a-fA-F]+\)", line)
                if match:
                    paths.add(match.group(1))
    # Retain the direct linker-facing C++ API libraries even when their ldd
    # output reports only resolved dependency paths.
    paths.add("/usr/lib/llvm-18/lib/libclang-cpp.so")
    paths.add("/usr/lib/llvm-18/lib/libLLVM-18.so")
    entries = []
    for path in sorted(paths):
        chain, target = symlink_chain(rootfs, path)
        if target.is_file():
            target_path = "/" + target.relative_to(rootfs).as_posix()
            entries.append(runtime_file_entry(rootfs, target_path))
            for link in chain:
                entries.append(runtime_file_entry(rootfs, link.split(" -> ", 1)[0]))
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
    payload = frontend_canonical_json(preimage)
    return sha256(b"decomp-thing/generic-template/resource-directory/v1\0" + payload)


def frontend_canonical_json(value: object) -> bytes:
    """Match A's OracleJson indentation and final newline for frontend hashes."""
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def verify_recorded_resource_manifest(rootfs: Path, record: dict) -> dict:
    actual = resource_manifest(rootfs, record["resourceDirectory"])
    if actual != record.get("resources"):
        raise ProvisionError("resource-directory bytes differ from the authenticated build-record manifest")
    return actual


def verified_frontend_runtime_library_digests(rootfs: Path, record: dict) -> list[dict[str, str]]:
    """Recheck the exact typed runtime closure before projecting its authenticated regular files."""
    verify_recorded_runtime_manifest(rootfs, record)
    return frontend_runtime_library_digests(record)


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


def deterministic_rootfs_tar(rootfs: Path, destination: Path, epoch: int, *,
                              normalize: bool = True, max_bytes: int | None = None) -> dict:
    if destination.exists() or destination.is_symlink():
        raise ProvisionError("could not exclusively create rootfs archive destination: path already exists")
    if normalize:
        normalize_rootfs(rootfs, epoch)
    if max_bytes is not None:
        run_checked(rootfs_tar_budget_command(rootfs, max_bytes), timeout=ROOTFS_TAR_BUDGET_TIMEOUT_SECONDS)
    command = [
        "sudo", "env", "LC_ALL=C", "tar", "--sort=name", "--format=posix", "--numeric-owner",
        f"--mtime=@{epoch}", "--pax-option=delete=atime,delete=ctime",
        "-cf", "-", "-C", str(rootfs), ".",
    ]
    # Create an anonymous inode inside the caller's output directory as the
    # calling user. Failure closes that inode without unlinking any pathname.
    # The privileged child sees only stdout; successful publication uses an
    # exclusive link in the retained parent directory and cannot replace a link.
    try:
        parent_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ProvisionError(f"could not exclusively create rootfs archive destination: {error}") from error
    try:
        parent = os.fstat(parent_fd)
        if parent.st_uid != os.geteuid():
            raise ProvisionError("rootfs archive output directory must be owned by the calling user")
        try:
            descriptor = os.open(".", os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        except OSError as error:
            raise ProvisionError(f"could not create private rootfs archive inode: {error}") from error
        with os.fdopen(descriptor, "w+b") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise ProvisionError("rootfs archive destination is not a regular file")
            descriptor_path = f"/proc/self/fd/{stream.fileno()}"
            try:
                descriptor_identity = os.stat(descriptor_path)
            except OSError as error:
                raise ProvisionError("rootfs archive FD publication is unavailable") from error
            if ((descriptor_identity.st_dev, descriptor_identity.st_ino) !=
                    (metadata.st_dev, metadata.st_ino)):
                raise ProvisionError("rootfs archive FD publication identity changed")
            run_checked(command, timeout=600, stdout_file=stream)
            stream.flush()
            size = os.fstat(stream.fileno()).st_size
            if max_bytes is not None and size > max_bytes:
                raise ProvisionError("canonical rootfs tar exceeds the artifact byte budget")
            stream.seek(0)
            digest = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            current_parent = destination.parent.stat(follow_symlinks=False)
            if (current_parent.st_dev, current_parent.st_ino) != (parent.st_dev, parent.st_ino):
                raise ProvisionError("rootfs archive destination parent changed during creation")
            try:
                os.link(descriptor_path, destination.name,
                        dst_dir_fd=parent_fd, follow_symlinks=True)
            except OSError as error:
                raise ProvisionError(f"could not exclusively publish rootfs archive destination: {error}") from error
            current = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
            if (not stat.S_ISREG(current.st_mode) or
                    (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino)):
                raise ProvisionError("rootfs archive destination pathname changed during publication")
            return {"bytes": size, "sha256": digest.hexdigest()}
    finally:
        os.close(parent_fd)


def expected_oci_config(profile_id: str, environment: dict[str, str], rootfs_sha256: str) -> dict:
    try:
        created = datetime.datetime.fromtimestamp(
            int(environment["SOURCE_DATE_EPOCH"]), datetime.timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (KeyError, ValueError, OverflowError, OSError) as error:
        raise ProvisionError("OCI environment has an invalid SOURCE_DATE_EPOCH") from error
    if any(not isinstance(key, str) or not isinstance(value, str) or "=" in key or "\0" in key + value
           for key, value in environment.items()):
        raise ProvisionError("OCI environment has a malformed variable")
    return {
        "architecture": "amd64", "os": "linux", "created": created,
        "config": {
            "Env": [f"{key}={value}" for key, value in sorted(environment.items())],
            "Labels": {"org.opencontainers.image.title": profile_id, "org.opencontainers.image.version": "18.1.3"},
            "WorkingDir": "/",
        },
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + rootfs_sha256]},
        "history": [{"created": created, "created_by": "authenticated Noble snapshot package closure"}],
    }


def create_oci_layout(rootfs_tar: Path, output: Path, profile_id: str, environment: dict[str, str]) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    blobs = output / "blobs/sha256"
    blobs.mkdir(parents=True)
    rootfs_payload = rootfs_tar.read_bytes()
    layer = gzip.compress(rootfs_payload, compresslevel=9, mtime=0)
    layer_digest = sha256(layer)
    (blobs / layer_digest).write_bytes(layer)
    config = expected_oci_config(profile_id, environment, sha256(rootfs_payload))
    config_bytes = canonical_json(config)
    config_digest = sha256(config_bytes)
    (blobs / config_digest).write_bytes(config_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": OCI_CONFIG_MEDIA_TYPE, "digest": "sha256:" + config_digest, "size": len(config_bytes)},
        "layers": [{"mediaType": OCI_GZIP_LAYER_MEDIA_TYPE, "digest": "sha256:" + layer_digest, "size": len(layer)}],
    }
    manifest_bytes = canonical_json(manifest)
    manifest_digest = sha256(manifest_bytes)
    (blobs / manifest_digest).write_bytes(manifest_bytes)
    (output / "oci-layout").write_bytes(canonical_json({"imageLayoutVersion": "1.0.0"}))
    index = {
        "schemaVersion": 2, "mediaType": OCI_INDEX_MEDIA_TYPE,
        "manifests": [{
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
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

            if strict_json_loads(read_small("oci-layout")) != {"imageLayoutVersion": "1.0.0"}:
                raise ProvisionError("OCI layout version is unsupported")
            index = strict_json_loads(read_small("index.json"))
            descriptors = index.get("manifests", [])
            if (index.get("schemaVersion") != 2 or index.get("mediaType") != OCI_INDEX_MEDIA_TYPE or
                    len(descriptors) != 1 or not isinstance(descriptors[0], dict) or
                    descriptors[0].get("mediaType") != OCI_MANIFEST_MEDIA_TYPE):
                raise ProvisionError("OCI index or manifest descriptor has an invalid media type or shape")
            manifest_desc = descriptors[0]
            digest = record["image"]["imageDigest"]
            if manifest_desc.get("digest") != digest:
                raise ProvisionError("OCI index manifest digest differs from the build record")
            manifest_name = "blobs/sha256/" + digest.removeprefix("sha256:")
            manifest_bytes = read_small(manifest_name)
            if sha256(manifest_bytes) != digest.removeprefix("sha256:") or len(manifest_bytes) != manifest_desc.get("size"):
                raise ProvisionError("OCI manifest content does not match its index digest/size")
            manifest = strict_json_loads(manifest_bytes)
            config_desc = manifest.get("config", {})
            layers = manifest.get("layers", [])
            if (len(layers) != 1 or manifest.get("schemaVersion") != 2 or
                    manifest.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE or
                    not isinstance(config_desc, dict) or config_desc.get("mediaType") != OCI_CONFIG_MEDIA_TYPE or
                    not isinstance(layers[0], dict) or layers[0].get("mediaType") != OCI_GZIP_LAYER_MEDIA_TYPE):
                raise ProvisionError("OCI manifest, config, or rootfs layer descriptor has an invalid media type or shape")
            config_digest = config_desc.get("digest", "")
            config_name = "blobs/sha256/" + config_digest.removeprefix("sha256:")
            config_bytes = read_small(config_name)
            if type(config_desc.get("size")) is not int or config_desc["size"] != len(config_bytes):
                raise ProvisionError("OCI image config descriptor size differs from the config blob length")
            if not config_digest.startswith("sha256:") or sha256(config_bytes) != config_digest.removeprefix("sha256:"):
                raise ProvisionError("OCI image config content does not match its digest")
            config = strict_json_loads(config_bytes)
            rootfs_identity = record["rootfs"]
            expected_diff_id = "sha256:" + rootfs_identity["sha256"]
            if config.get("rootfs", {}).get("diff_ids") != [expected_diff_id]:
                raise ProvisionError("OCI rootfs diff ID differs from the deterministic rootfs tar identity")
            if config != expected_oci_config(record["profile"]["id"], record["environment"], rootfs_identity["sha256"]):
                raise ProvisionError("OCI config semantics differ from the selected build-record profile and environment")
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


def verify_retained_rootfs_and_image(rootfs: Path, oci_archive: Path,
                                     record: dict, contract: dict) -> None:
    """Independently bind the retained directory, deterministic tar, and OCI layer."""
    if rootfs.is_symlink() or not rootfs.is_dir():
        raise ProvisionError("provenance packaging requires a retained regular rootfs directory")
    if oci_archive.is_symlink() or not oci_archive.is_file():
        raise ProvisionError("provenance packaging requires the retained OCI image archive")
    limits = contract["profile"]["bounds"]
    expected = record.get("rootfs", {})
    if (type(expected.get("bytes")) is not int or expected["bytes"] < 1 or
            expected["bytes"] > limits["maxArtifactBytes"]):
        raise ProvisionError("build record rootfs identity exceeds the bounded artifact contract")
    epoch = int(contract["environment"]["SOURCE_DATE_EPOCH"])
    try:
        with tempfile.TemporaryDirectory(prefix="clang1813-rootfs-verify-", dir=rootfs.parent) as temporary:
            archive = Path(temporary) / "rootfs.tar"
            actual = deterministic_rootfs_tar(
                rootfs, archive, epoch, normalize=False, max_bytes=limits["maxArtifactBytes"],
            )
    except OSError as error:
        raise ProvisionError(f"could not create bounded rootfs verification archive: {error}") from error
    if actual != expected:
        raise ProvisionError("retained rootfs differs from the deterministic rootfs identity in the build record")
    verify_oci_archive(oci_archive, record, limits["maxArtifactBytes"])


def verify_recorded_runtime_closure(rootfs: Path, record: dict, contract: dict) -> dict:
    """Re-derive the complete compiler/API shared-library closure from the verified rootfs."""
    actual = manifest(runtime_dependencies(rootfs, list(FRONTEND_RUNTIME_ROOTS), contract))
    if actual != record.get("runtime"):
        raise ProvisionError("build record runtime closure differs from the retained rootfs dependency closure")
    return actual


def debootstrap_command(contract: dict, profile_root: str, keyring: Path) -> list[str]:
    return [
        "sudo", "env", "LC_ALL=C", "TZ=UTC", f"SOURCE_DATE_EPOCH={contract['environment']['SOURCE_DATE_EPOCH']}",
        "debootstrap", "--arch=amd64", "--variant=minbase", "--components=main,universe",
        "--include=ca-certificates",
        f"--keyring={keyring}", "noble", profile_root, contract["profile"]["snapshotBase"],
    ]


def apt_command_prefix() -> list[str]:
    return ["/usr/bin/apt-get", "-o", "Acquire::Check-Valid-Until=false", "-o", "Acquire::Retries=0",
            "-o", "APT::Get::AllowUnauthenticated=false", "-o", "APT::Install-Recommends=false"]


def apt_source_list(contract: dict) -> bytes:
    snapshot = contract["profile"]["snapshotBase"]
    suites = contract["profile"]["suites"]
    lines = [
        f"deb [check-valid-until=no signed-by={APT_KEYRING_IN_ROOT}] {snapshot} {suite} main universe"
        for suite in suites
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def install_selected_archive_keyring(rootfs: Path, keyring: Path, expected_sha256: str) -> Path:
    if keyring.is_symlink() or not keyring.is_file() or sha256_file(keyring) != expected_sha256:
        raise ProvisionError("selected Ubuntu archive keyring bytes differ from the authenticated candidate")
    parent = rootfs_path(rootfs, "/usr/share/keyrings")
    destination = parent / PurePosixPath(APT_KEYRING_IN_ROOT).name
    if destination.exists() or destination.is_symlink():
        raise ProvisionError("dedicated in-root Ubuntu archive keyring path already exists")
    run_checked(["sudo", "install", "-m", "0644", str(keyring), str(destination)])
    if destination.is_symlink() or not destination.is_file() or sha256_file(destination) != expected_sha256:
        raise ProvisionError("installed in-root Ubuntu archive keyring differs from authenticated candidate bytes")
    return destination


def probe_compile_command() -> list[str]:
    return ["/usr/bin/clang++-18", "-I/usr/lib/llvm-18/include", "--target=x86_64-pc-linux-gnu",
            "-std=c++17", "-fno-exceptions", "-fno-rtti", "-D_GNU_SOURCE", "-D__STDC_CONSTANT_MACROS",
            "-D__STDC_FORMAT_MACROS", "-D__STDC_LIMIT_MACROS",
            PROBE_SOURCE_IN_ROOT, "-L/usr/lib/llvm-18/lib",
            "-Wl,-rpath,/usr/lib/llvm-18/lib", "-lclang-cpp", "-lLLVM-18", "-o", PROBE_BINARY_IN_ROOT]


def stage_probe_inputs(rootfs: Path) -> tuple[Path, Path]:
    """Install immutable probe inputs under /usr/local so /tmp normalization cannot erase them."""
    if rootfs.is_symlink() or not rootfs.is_dir():
        raise ProvisionError("probe staging requires the fresh non-symlink rootfs")
    source = RECIPE_FILES["probeSha256"]
    fixture = RECIPE_FILES["fixtureSha256"]
    source_target = rootfs.joinpath(*PurePosixPath(PROBE_SOURCE_IN_ROOT).parts[1:])
    fixture_target = rootfs.joinpath(*PurePosixPath(PROBE_FIXTURE_IN_ROOT).parts[1:])
    run_checked(["sudo", "install", "-D", "-m", "0444", str(source), str(source_target)])
    run_checked(["sudo", "install", "-D", "-m", "0444", str(fixture), str(fixture_target)])
    return source_target, fixture_target


def verify_staged_probe_source(rootfs: Path, expected_recipe_sha256: str) -> str:
    """Bind the retained source bytes to the recipe before compiling the probe."""
    if (not isinstance(expected_recipe_sha256, str) or
            not re.fullmatch(r"[0-9a-f]{64}", expected_recipe_sha256)):
        raise ProvisionError("recipe has an invalid probe-source digest")
    source_path, _ = rootfs_regular_file(rootfs, PROBE_SOURCE_IN_ROOT)
    actual_sha256 = sha256_file(source_path)
    if actual_sha256 != expected_recipe_sha256:
        raise ProvisionError("staged probe source differs from the expected recipe source bytes")
    return actual_sha256


def canonical_commands(contract: dict, keyring_sha256: str) -> dict[str, list[str]]:
    """Reviewed argv with workspace paths and verified artifact paths normalized."""
    apt = apt_command_prefix()
    pinned = [f"{row['name']}={row['version']}" for row in contract["profile"]["binaryRoots"]]
    epoch = int(contract["environment"]["SOURCE_DATE_EPOCH"])
    source_list_sha256 = sha256(apt_source_list(contract))
    budget_command = rootfs_tar_budget_command(Path("<PROFILE_ROOT>"), contract["profile"]["bounds"]["maxArtifactBytes"])
    budget_command[5] = f"<PROVISIONER_SHA256:{sha256_file(RECIPE_FILES['provisionerSha256'])}>"
    budget_command[8] = "<PROFILE_ROOT>"

    def in_root(command: list[str], apt_environment: bool = False) -> list[str]:
        extra = {"DEBIAN_FRONTEND": "noninteractive"} if apt_environment else None
        return ["sudo", "chroot", "<PROFILE_ROOT>", *rootfs_env_args(contract, extra), *command]

    return {
        "debootstrap": debootstrap_command(
            contract, "<PROFILE_ROOT>", Path(f"<UBUNTU_ARCHIVE_KEYRING_SHA256:{keyring_sha256}>")),
        "installAptKeyring": ["sudo", "install", "-m", "0644",
                               f"<UBUNTU_ARCHIVE_KEYRING_SHA256:{keyring_sha256}>",
                               f"<PROFILE_ROOT>{APT_KEYRING_IN_ROOT}"],
        "writeAptSources": ["sudo", "install", "-m", "0644", f"<SOURCE_LIST_SHA256:{source_list_sha256}>",
                            "<PROFILE_ROOT>/etc/apt/sources.list"],
        "aptUpdate": in_root([*apt, "update"], True),
        "aptDownloadOnly": in_root([*apt, "install", "--yes", "--no-install-recommends", "--download-only", *pinned], True),
        "aptInstall": in_root([*apt, "install", "--yes", "--no-install-recommends", *pinned], True),
        "aptCheck": in_root([*apt, "check"], True),
        "clangCVersion": in_root(["/usr/bin/clang-18", "--version"]),
        "clangCxxVersion": in_root(["/usr/bin/clang++-18", "--version"]),
        "clangResourceDirectory": in_root(["/usr/bin/clang-18", "-print-resource-dir"]),
        "llvmConfigLibdir": in_root(["/usr/bin/llvm-config-18", "--libdir"]),
        "llvmConfigCxxflags": in_root(["/usr/bin/llvm-config-18", "--cxxflags"]),
        "probeCompile": in_root(probe_compile_command()),
        "probeRun": in_root([PROBE_BINARY_IN_ROOT, PROBE_FIXTURE_IN_ROOT]),
        "rootfsTarBudget": budget_command,
        "rootfsTar": ["sudo", "env", "LC_ALL=C", "tar", "--sort=name", "--format=posix",
                      "--numeric-owner", f"--mtime=@{epoch}",
                      "--pax-option=delete=atime,delete=ctime", "-cf", "-", "-C", "<PROFILE_ROOT>", "."],
        "ociArchive": ["tar", "--sort=name", "--format=posix", "--numeric-owner", "--owner=0",
                       "--group=0", f"--mtime=@{epoch}", "--pax-option=delete=atime,delete=ctime",
                       "-cf", "<OCI_ARCHIVE>", "-C", "<OCI_LAYOUT>", "blobs/sha256/<CONFIG_SHA256>",
                       "blobs/sha256/<LAYER_SHA256>", "blobs/sha256/<MANIFEST_SHA256>", "index.json", "oci-layout"],
    }


def require_bootstrap_ca_certificates(rootfs: Path, packages: set[tuple[str, str, str]]) -> None:
    if not any(name == "ca-certificates" for name, _, _ in packages):
        raise ProvisionError("bootstrap package closure is missing ca-certificates before HTTPS APT")
    try:
        bundle = rootfs_path(rootfs, "/etc/ssl/certs/ca-certificates.crt")
        available = bundle.is_file() and bundle.stat().st_size > 0
    except OSError as error:
        raise ProvisionError("bootstrap CA bundle is unavailable before HTTPS APT") from error
    if not available:
        raise ProvisionError("bootstrap CA bundle is unavailable before HTTPS APT")


def downloaded_package_key(deb: Path) -> tuple[str, str, str]:
    output = run_checked(["dpkg-deb", "--field", str(deb), "Package", "Version", "Architecture"]).stdout
    records = parse_deb822(output)
    names = ("Package", "Version", "Architecture")
    if len(records) != 1 or set(records[0]) != set(names) or any(not records[0][name] for name in names):
        raise ProvisionError(f"could not read package identity from {deb.name}")
    return tuple(records[0][name] for name in names)


def remove_optional_source_caches(acquisition: Path) -> None:
    """Remove only optional cached trees through an authenticated no-follow parent descriptor."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    acquisition_fd = os.open(acquisition, flags)
    try:
        acquisition_identity = os.fstat(acquisition_fd)

        def require_acquisition_binding() -> None:
            try:
                current_fd = os.open(acquisition, flags)
            except OSError as error:
                raise ProvisionError("acquisition source cache root pathname changed") from error
            try:
                current = os.fstat(current_fd)
                if (current.st_dev, current.st_ino) != (acquisition_identity.st_dev, acquisition_identity.st_ino):
                    raise ProvisionError("acquisition source cache root identity changed")
            finally:
                os.close(current_fd)

        require_acquisition_binding()
        try:
            expected_parent = os.stat("source", dir_fd=acquisition_fd, follow_symlinks=False)
        except FileNotFoundError:
            require_acquisition_binding()
            return
        if not stat.S_ISDIR(expected_parent.st_mode):
            raise ProvisionError("acquisition source cache parent must be a real directory")
        source_fd = os.open("source", flags, dir_fd=acquisition_fd)
        try:
            source_identity = os.fstat(source_fd)
            if (source_identity.st_dev, source_identity.st_ino) != (expected_parent.st_dev, expected_parent.st_ino):
                raise ProvisionError("acquisition source cache parent identity changed")

            def require_source_binding() -> None:
                require_acquisition_binding()
                current = os.stat("source", dir_fd=acquisition_fd, follow_symlinks=False)
                if (not stat.S_ISDIR(current.st_mode) or
                        (current.st_dev, current.st_ino) != (source_identity.st_dev, source_identity.st_ino)):
                    raise ProvisionError("acquisition source cache parent pathname changed")

            for name in ("package-source", "upstream"):
                require_source_binding()
                try:
                    metadata = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
                except FileNotFoundError:
                    require_source_binding()
                    continue
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ProvisionError("acquisition source cache must be a real directory")
                require_source_binding()
                shutil.rmtree(name, dir_fd=source_fd)
                require_source_binding()
        finally:
            os.close(source_fd)
    finally:
        os.close(acquisition_fd)


def provision_rootfs(args: argparse.Namespace) -> int:
    try:
        canonical_rootfs = args.rootfs.resolve()
        canonical_output = args.output.resolve()
        canonical_workdir = args.workdir.resolve()
    except (OSError, RuntimeError) as error:
        raise ProvisionError("could not resolve rootfs, evidence output and work directory paths") from error
    if (canonical_rootfs == canonical_output or canonical_rootfs in canonical_output.parents or
            canonical_output in canonical_rootfs.parents):
        raise ProvisionError("rootfs and evidence output trees must be disjoint")
    if canonical_output == canonical_workdir or canonical_output in canonical_workdir.parents:
        raise ProvisionError("evidence output must not equal or contain the work directory")
    if canonical_rootfs == canonical_workdir or canonical_rootfs in canonical_workdir.parents:
        raise ProvisionError("rootfs must not equal or contain the work directory")
    if (args.rootfs.exists() or args.rootfs.is_symlink() or
            args.output.exists() or args.output.is_symlink()):
        raise ProvisionError("rootfs and evidence output paths must not exist")
    contract = read_contract(args.contract)
    profile = contract["profile"]
    args.workdir.mkdir(parents=True, exist_ok=True)
    candidate, indexes = load_candidate(args.acquisition, contract, args.keyring)
    remove_optional_source_caches(args.acquisition)
    check_runner_bounds(args.workdir, profile)
    profile_root = args.rootfs
    profile_root.parent.mkdir(parents=True, exist_ok=True)
    run_checked(debootstrap_command(contract, str(profile_root), args.keyring), timeout=900)
    bootstrap_package_keys = installed_package_keys(profile_root, contract)
    require_bootstrap_ca_certificates(profile_root, bootstrap_package_keys)
    selected_keyring_sha256 = candidate["trustedKeyring"]["sha256"]
    install_selected_archive_keyring(profile_root, args.keyring, selected_keyring_sha256)

    sources = apt_source_list(contract)
    sources_path = args.workdir / f"clang-source-list-{args.label}.list"
    atomic_write(sources_path, sources)
    run_checked(["sudo", "install", "-m", "0644", str(sources_path), str(profile_root / "etc/apt/sources.list")])
    apt_prefix = apt_command_prefix()
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
        downloaded_identities.append((deb, downloaded_package_key(deb)))
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

    fixture = RECIPE_FILES["fixtureSha256"]
    expected_probe_source_sha256 = recipe_identity(args.contract)["probeSha256"]
    probe_in_root, fixture_in_root = stage_probe_inputs(profile_root)
    staged_probe_source_sha256 = verify_staged_probe_source(profile_root, expected_probe_source_sha256)
    libdir = rootfs_run(profile_root, ["/usr/bin/llvm-config-18", "--libdir"], contract).strip()
    if libdir != "/usr/lib/llvm-18/lib":
        raise ProvisionError("llvm-config library directory differs from the versioned probe recipe")
    # Retain the diagnostic command, but use the fixed reviewed probe arguments.
    # Tool-reported flags cannot inject additional compiler/linker operations.
    rootfs_run(profile_root, ["/usr/bin/llvm-config-18", "--cxxflags"], contract)
    probe_path = PROBE_BINARY_IN_ROOT
    compile_command = probe_compile_command()
    source_sha256_before_compile = staged_probe_source_sha256
    rootfs_run(profile_root, compile_command, contract, timeout=600)
    staged_probe_source_sha256 = verify_staged_probe_source(profile_root, expected_probe_source_sha256)
    if staged_probe_source_sha256 != source_sha256_before_compile:
        raise ProvisionError("staged probe source changed during compilation")
    runtime_report = run_probe_sandboxed(
        profile_root, [probe_path, PROBE_FIXTURE_IN_ROOT], contract, timeout=120,
    )
    runtime_json = strict_json_loads(runtime_report)
    inventory = audit_langoptions(
        rootfs_path(profile_root, "/usr/lib/llvm-18/include/clang/Basic/LangOptions.def"),
        rootfs_path(profile_root, "/usr/lib/llvm-18/include/clang/Basic/LangOptions.h"), contract,
    )
    probe_checked = validate_probe_report(runtime_json, inventory, contract)
    probe_checked["sourceSha256"] = staged_probe_source_sha256
    probe_checked["binarySha256"] = sha256(rootfs_path(profile_root, probe_path).read_bytes())
    probe_checked["apiChecks"] = runtime_json["apiChecks"]
    probe_checked["fixtureSha256"] = sha256(fixture.read_bytes())

    runtime_files = runtime_dependencies(profile_root, list(FRONTEND_RUNTIME_ROOTS), contract)
    runtime_manifest = manifest(runtime_files)
    epoch = int(contract["environment"]["SOURCE_DATE_EPOCH"])
    rootfs_tar_path = args.workdir / f"clang-rootfs-{args.label}.tar"
    rootfs_identity = deterministic_rootfs_tar(
        profile_root, rootfs_tar_path, epoch, max_bytes=profile["bounds"]["maxArtifactBytes"],
    )
    if rootfs_identity["bytes"] > profile["bounds"]["maxArtifactBytes"]:
        raise ProvisionError("canonical rootfs tar exceeds the artifact byte budget")
    args.output.mkdir(parents=True, exist_ok=False)
    oci_path = args.output / "oci-layout"
    image_record = create_oci_layout(rootfs_tar_path, oci_path, profile["id"], contract["environment"])
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

    record = {
        "schemaVersion": 1,
        "buildSystem": "ubuntu-snapshot-debootstrap-apt",
        "profile": {"id": profile["id"], "architecture": profile["architecture"], "target": profile["target"],
                    "snapshot": profile["snapshot"], "codename": profile["codename"]},
        **candidate_build_evidence(candidate, contract),
        "packages": package_rows,
        "downloadedPackages": downloaded_rows,
        "tools": tools,
        "runtime": runtime_manifest,
        "resources": resource_files,
        "resourceDirectory": resource_dir,
        "probe": probe_checked,
        "recipe": recipe_identity(args.contract),
        "environment": contract["environment"],
        "commands": canonical_commands(contract, candidate["trustedKeyring"]["sha256"]),
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


def reject_build_record_schema_unknown_fields(record: object, *,
                                                captured: dict[Path, bytes] | None = None) -> None:
    """Enforce every additionalProperties:false object boundary in the pinned schema."""
    try:
        schema = strict_json_loads(captured_evidence(RECIPE_FILES["schemaSha256"], captured).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisionError(f"could not read checked-in build-record schema: {error}") from error

    def validate(value: object, rule: dict, location: str) -> None:
        reference = rule.get("$ref")
        if reference is not None:
            match = re.fullmatch(r"#/(\$defs)/([^/]+)", str(reference))
            if match is None:
                raise ProvisionError(f"checked-in build-record schema has an unsupported reference at {location}")
            definition = schema.get(match.group(1), {}).get(match.group(2))
            if not isinstance(definition, dict):
                raise ProvisionError(f"checked-in build-record schema reference is missing at {location}")
            validate(value, definition, location)
            rule = {key: child for key, child in rule.items() if key != "$ref"}
            if not rule:
                return

        if isinstance(value, dict):
            properties = rule.get("properties", {})
            additional = rule.get("additionalProperties", True)
            for name, child in value.items():
                child_location = f"{location}.{name}"
                if name in properties:
                    validate(child, properties[name], child_location)
                elif additional is False:
                    raise ProvisionError(f"build record violates checked-in schema at {child_location}: unknown field")
                elif isinstance(additional, dict):
                    validate(child, additional, child_location)
        elif isinstance(value, list):
            item_rule = rule.get("items")
            if isinstance(item_rule, dict):
                for index, item in enumerate(value):
                    validate(item, item_rule, f"{location}[{index}]")

    validate(record, schema, "$")


def validate_build_record(record: dict, contract: dict, contract_path: Path = CONTRACT_PATH, *,
                            captured: dict[Path, bytes] | None = None) -> None:
    if not isinstance(record, dict):
        raise ProvisionError("build record must be a JSON object")
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
    if "ca-certificates" not in package_by_name:
        raise ProvisionError("build record package closure is missing bootstrap ca-certificates")
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
        if name == "runtime":
            validated_runtime_entries(record.get("runtime"))
            continue
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
    if record.get("recipe") != recipe_identity(contract_path, captured):
        raise ProvisionError("build record recipe hashes do not match the reviewed contract, tooling, and workflow bytes")
    if probe.get("sourceSha256") != record["recipe"].get("probeSha256"):
        raise ProvisionError("build record probe source digest differs from its recipe source bytes")
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
    if (keyring.get("bytes", 0) < 1 or not isinstance(keyring.get("sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", keyring["sha256"])):
        raise ProvisionError("build record does not bind the archive-verification keyring")
    if record.get("commands") != canonical_commands(contract, keyring["sha256"]):
        raise ProvisionError("build record command map differs from the reviewed canonical recipe")
    candidate_digest = record["acquisition"].get("candidateSha256")
    if not isinstance(candidate_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", candidate_digest):
        raise ProvisionError("build record does not bind the authenticated acquisition candidate")
    for field in ("sourceIndexesSha256", "binaryIndexesSha256"):
        digest = record["acquisition"].get(field)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ProvisionError(f"build record lacks a valid signed index digest: {field}")
    if record["acquisition"].get("signatureFingerprints") != [row["signerPrimaryFingerprint"] for row in repositories]:
        raise ProvisionError("build record repository signer summary is inconsistent")
    reject_build_record_schema_unknown_fields(record, captured=captured)


def compare_build_runs(first_path: Path, second_path: Path, output_path: Path, contract: dict,
                       contract_path: Path = CONTRACT_PATH) -> dict:
    try:
        if first_path.resolve(strict=True) == second_path.resolve(strict=True):
            raise ProvisionError("two clean runs require distinct record paths and files")
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
        with os.fdopen(os.open(first_path, flags), "rb") as first_file, \
                os.fdopen(os.open(second_path, flags), "rb") as second_file:
            first_identity = os.fstat(first_file.fileno())
            second_identity = os.fstat(second_file.fileno())
            if (not stat.S_ISREG(first_identity.st_mode) or not stat.S_ISREG(second_identity.st_mode) or
                    (first_identity.st_dev, first_identity.st_ino) ==
                    (second_identity.st_dev, second_identity.st_ino)):
                raise ProvisionError("two clean runs require distinct regular record files")
            first = strict_json_loads(first_file.read().decode("utf-8"))
            second = strict_json_loads(second_file.read().decode("utf-8"))
    except OSError as error:
        raise ProvisionError(f"could not inspect independent build records: {error}") from error
    validate_build_record(first, contract, contract_path)
    validate_build_record(second, contract, contract_path)
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
    record = compare_build_runs(args.first, args.second, args.output, contract, args.contract)
    print(f"two clean runs reproduced rootfs {record['rootfs']['sha256']} and image {record['image']['imageDigest']}")
    return 0


def command_verify_record(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    record = strict_json_loads(args.record.read_text(encoding="utf-8"))
    validate_build_record(record, contract, args.contract)
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
    record = strict_json_loads(args.record.read_text(encoding="utf-8"))
    validate_build_record(record, contract, args.contract)
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
    runtime_rows = verified_frontend_runtime_library_digests(rootfs_dir, record)
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
    for index, row in enumerate(runtime_rows):
        values[f"runtime.{index}.path"] = row["path"]
        values[f"runtime.{index}.sha256"] = row["sha256"]
    if any("\n" in value or "\r" in value for value in values.values()):
        raise ProvisionError("A-loader input contains a line break")
    # Properties.load(Reader) interprets escapes even with a UTF-8 reader. Keep
    # literal Unicode, but escape metacharacters and value whitespace so legal
    # Linux filenames (especially backslashes) retain their exact meaning.
    escapes = str.maketrans({"\\": "\\\\", "\t": "\\t", "\f": "\\f", " ": "\\ ",
                            "=": "\\=", ":": "\\:", "#": "\\#", "!": "\\!"})
    encoded = "".join(f"{key}={value.translate(escapes)}\n" for key, value in sorted(values.items()))
    atomic_write(args.output.with_suffix(".properties"), encoded.encode("utf-8"))
    return 0


def command_verify_image(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    record = strict_json_loads(args.record.read_text(encoding="utf-8"))
    validate_build_record(record, contract, args.contract)
    if record.get("reproducibility") != {
        "cleanBuilds": 2, "matchingRootfsSha256": True, "matchingImageDigest": True,
    }:
        raise ProvisionError("image verification requires the final reproducible build record")
    verify_oci_archive(args.oci_archive, record, contract["profile"]["bounds"]["maxArtifactBytes"])
    print(f"verified OCI image {record['image']['imageDigest']} and rootfs sha256:{record['rootfs']['sha256']}")
    return 0


def read_provenance_report(path: Path, label: str, *, captured: dict[Path, bytes] | None = None) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ProvisionError(f"{label} provenance report is not a regular file")
    try:
        report = strict_json_loads(captured_evidence(path, captured).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisionError(f"{label} provenance report is not valid UTF-8 JSON") from error
    if not isinstance(report, dict):
        raise ProvisionError(f"{label} provenance report must be a JSON object")
    return report


def preflight_provenance_output(output: Path, input_roots: list[Path], input_files: list[Path]) -> Path:
    """Resolve output aliases and reject all packaged-tree overlaps before creating paths."""
    if output.is_symlink() or output.exists():
        raise ProvisionError("provenance archive output must not already exist or be a symlink")
    try:
        canonical_output = output.resolve(strict=False)
        canonical_roots = []
        for root in input_roots:
            if root.is_symlink():
                raise ProvisionError("provenance input root must not be a symlink")
            canonical_roots.append(root.resolve(strict=True))
        canonical_files = []
        for path in input_files:
            if path.is_symlink():
                canonical_files.append(path.resolve(strict=True))
            elif path.exists():
                canonical_files.append(path.resolve(strict=True))
    except OSError as error:
        raise ProvisionError(f"could not resolve provenance output/input paths: {error}") from error
    for root in canonical_roots:
        if canonical_output == root or root in canonical_output.parents:
            raise ProvisionError("provenance archive output overlaps a recursively packaged input tree")
    if canonical_output in canonical_files:
        raise ProvisionError("provenance archive output overlaps a packaged input file")
    return canonical_output


def validate_provenance_probe_report(
        report: dict, record: dict, rootfs: Path, contract: dict) -> tuple[Path, Path, Path, int]:
    if canonical_json(report) != canonical_json(record.get("probe")):
        raise ProvisionError("probe provenance report differs from the reproducible build-record probe")
    probe_path, probe_mode = rootfs_regular_file(rootfs, PROBE_BINARY_IN_ROOT, executable=True)
    fixture_path, _ = rootfs_regular_file(rootfs, PROBE_FIXTURE_IN_ROOT)
    source_path, _ = rootfs_regular_file(rootfs, PROBE_SOURCE_IN_ROOT)
    expected_recipe_source = record.get("recipe", {}).get("probeSha256")
    source_digest = verify_staged_probe_source(rootfs, expected_recipe_source)
    if source_digest != record["probe"]["sourceSha256"]:
        raise ProvisionError("retained probe source bytes differ from the build-record sourceSha256")
    probe_digest = sha256_file(probe_path)
    expected_probe_digest = record["probe"]["binarySha256"]
    if probe_digest != expected_probe_digest:
        raise ProvisionError("retained probe executable bytes differ from the build-record binarySha256")
    fixture_digest = sha256_file(fixture_path)
    if (fixture_digest != record["probe"]["fixtureSha256"] or
            fixture_digest != record["recipe"]["fixtureSha256"]):
        raise ProvisionError("retained probe fixture bytes differ from the authenticated fixture identity")

    replay_output = run_probe_sandboxed(
        rootfs, [PROBE_BINARY_IN_ROOT, PROBE_FIXTURE_IN_ROOT], contract, timeout=120,
    )
    try:
        replay_report = strict_json_loads(replay_output)
    except (TypeError, json.JSONDecodeError) as error:
        raise ProvisionError("retained probe replay did not emit valid JSON") from error
    if not isinstance(replay_report, dict):
        raise ProvisionError("retained probe replay output must be a JSON object")
    inventory = audit_langoptions(
        rootfs_path(rootfs, "/usr/lib/llvm-18/include/clang/Basic/LangOptions.def"),
        rootfs_path(rootfs, "/usr/lib/llvm-18/include/clang/Basic/LangOptions.h"),
        contract,
    )
    checked = validate_probe_report(replay_report, inventory, contract)
    checked["sourceSha256"] = source_digest
    checked["binarySha256"] = probe_digest
    checked["fixtureSha256"] = fixture_digest
    if canonical_json(checked) != canonical_json(record["probe"]):
        raise ProvisionError("retained probe replay differs from the reproducible build-record probe")
    return probe_path, fixture_path, source_path, probe_mode


def frontend_cxx_driver_identity_sha256(record: dict, record_sha256: str) -> str:
    """Recompute A's C++ driver identity from the recorded executable and hops."""
    tool = next(row for row in record["tools"] if row["role"] == "cxx-driver")
    hops = []
    for row in tool["symlinkChain"]:
        match = re.fullmatch(r"(/[^ ]+) -> (.+)", row)
        if match is None:
            raise ProvisionError("C++ driver symlink identity is malformed")
        path, target = match.groups()
        hops.append({"path": "toolchain" + path, "targetBytesSha256": sha256(target.encode("utf-8"))})
    chain_payload = frontend_canonical_json(hops)
    chain_sha = sha256(b"decomp-thing/generic-template/cxx-driver-symlink-chain/v1\0" + chain_payload)
    preimage = {
        "buildRecordSha256": record_sha256,
        "compilerSha256": tool["sha256"],
        "containerImageDigest": record["image"]["imageDigest"],
        "configuredPathSha256": sha256(tool["path"].encode("utf-8")),
        "executableBytes": tool["bytes"],
        "executableMode": tool["mode"],
        "executableSha256": tool["sha256"],
        "resolvedDriverPath": "toolchain" + tool["resolvedPath"],
        "symlinkChainSha256": chain_sha,
        "toolchainProfileSha256": sha256(canonical_json(record["profile"])),
    }
    payload = frontend_canonical_json(preimage)
    return sha256(b"decomp-thing/generic-template/cxx-driver-identity/v1\0" + payload)


def frontend_path_transform_sha256(record: dict) -> str:
    """Recompute A's authenticated PATH transform from the build-record environment."""
    raw_path = record.get("environment", {}).get("PATH")
    if not isinstance(raw_path, str):
        raise ProvisionError("build record does not contain a string PATH for the A-loader projection")
    try:
        path_bytes = raw_path.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ProvisionError("build-record PATH is not valid UTF-8") from error
    entries = raw_path.split(":")
    if not path_bytes or len(path_bytes) > 4096 or not 1 <= len(entries) <= 64:
        raise ProvisionError("build-record PATH is outside the A-loader transform bounds")
    for entry in entries:
        try:
            encoded = entry.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise ProvisionError("build-record PATH contains a non-UTF-8 entry") from error
        components = [] if entry == "/" else entry[1:].split("/") if entry.startswith("/") else [""]
        if (not encoded or len(encoded) > 1024 or not entry.startswith("/") or entry.startswith("//") or
                "//" in entry or "\0" in entry or (entry != "/" and entry.endswith("/")) or
                any(part in ("", ".", "..") or len(part.encode("utf-8")) > 255 for part in components)):
            raise ProvisionError("build-record PATH contains a non-canonical entry")

    def domain_hash(domain: str, value: object) -> str:
        return sha256(domain.encode("ascii") + b"\0" + frontend_canonical_json(value))

    inert_digest = domain_hash(
        "decomp-thing/generic-template/path-directory/v1",
        {"entries": [], "mode": "0555"},
    )
    transform = {
        "containerImageDigest": record["image"]["imageDigest"],
        "environmentPathPolicy": "captured-posix-path-to-inert-virtual-directories-v1",
        "inertDirectorySha256": inert_digest,
        "rawPathSha256": sha256(path_bytes),
        "virtualPathEntries": [f"/__decomp/toolchain/path/{index:04d}" for index in range(len(entries))],
    }
    return domain_hash("decomp-thing/generic-template/path-transform/v1", transform)


def frontend_runtime_library_digests(record: dict) -> list[dict]:
    """Project the complete regular-file closure from authenticated classification metadata."""
    tool = next((row for row in record.get("tools", []) if row.get("role") == "cxx-driver"), None)
    if not isinstance(tool, dict):
        raise ProvisionError("build record has no C++ driver for the A-loader projection")
    rows = [{"path": "toolchain" + row["path"], "sha256": row["sha256"]}
            for row in validated_runtime_entries(record.get("runtime"))
            if row["kind"] == "regular-file" and row["sha256"] != tool["sha256"]]
    if not rows:
        raise ProvisionError("A-loader profile projection has no runtime-library rows")
    return rows


def frontend_profile_projection_preimage(record: dict, record_sha256: str) -> dict:
    """Build A's exact profile preimage independently of a supplied loader report."""
    tool = next((row for row in record.get("tools", []) if row.get("role") == "cxx-driver"), None)
    if not isinstance(tool, dict):
        raise ProvisionError("build record has no C++ driver for the A-loader projection")
    return {
        "adapterApiVersion": "clang-libtooling-18.1.3-v1",
        "adapterSha256": sha256_file(ROOT / "oracle/clang/18.1.3/Clang1813AProfileLoaderSmoke.java"),
        "adapterSourceRevision": "0" * 40,
        "compilerSha256": tool["sha256"],
        "cxxDriverIdentitySha256": frontend_cxx_driver_identity_sha256(record, record_sha256),
        "pathTransformSha256": frontend_path_transform_sha256(record),
        "resourceHeaderManifestSha256": frontend_resource_manifest_sha256(
            record["resourceDirectory"], record["resources"]),
        "resolvedResourceDirectory": "toolchain" + record["resourceDirectory"],
        "runtimeLibraryDigests": frontend_runtime_library_digests(record),
        "targetTriple": record["probe"]["target"],
        "toolchainProfileSha256": sha256(canonical_json(record["profile"])),
    }


def frontend_profile_projection_sha256(preimage: dict) -> str:
    return sha256(
        b"decomp-thing/generic-template/frontend-profile/v1\0" + frontend_canonical_json(preimage)
    )


def validate_provenance_loader_report(report: dict, record: dict, record_sha256: str,
                                      rootfs: Path) -> None:
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
    if report.get("cxxDriverIdentitySha256") != frontend_cxx_driver_identity_sha256(record, record_sha256):
        raise ProvisionError("A-loader smoke report C++ driver identity differs from the build record")
    expected_path_transform = frontend_path_transform_sha256(record)
    if report.get("pathTransformSha256") != expected_path_transform:
        raise ProvisionError("A-loader smoke report PATH transform differs from the build-record environment and image")
    projection = report.get("infrastructureProfileProjection")
    if not isinstance(projection, dict):
        raise ProvisionError("A-loader smoke report lacks its frontend profile projection preimage")
    verified_frontend_runtime_library_digests(rootfs, record)
    expected_projection = frontend_profile_projection_preimage(record, record_sha256)
    if projection != expected_projection:
        raise ProvisionError("A-loader smoke report frontend profile projection differs from the build record")
    if report.get("infrastructureProfileProjectionSha256") != frontend_profile_projection_sha256(expected_projection):
        raise ProvisionError("A-loader smoke report frontend profile projection digest is invalid")
    for field in ("rejectedWrongImage", "rejectedWrongCxxDriverBytes", "rejectedChangedResourceIdentity",
                  "rejectedChangedRuntimeLibraryIdentity", "rejectedMissingResourceDirectory"):
        if report.get(field) is not True:
            raise ProvisionError(f"A-loader smoke report lacks the required negative check: {field}")


def validate_locked_comparator_manifest(lock_path: Path, negative: dict, *,
                                        captured: dict[Path, bytes] | None = None) -> tuple[dict, Path, str, dict]:
    if lock_path.is_symlink() or not lock_path.is_file():
        raise ProvisionError("locked Clang 22.1.6 comparator release lock is not a regular file")
    try:
        lock = strict_json_loads(captured_evidence(lock_path, captured).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisionError(f"locked comparator release metadata is invalid: {error}") from error
    if not isinstance(lock, dict):
        raise ProvisionError("locked comparator release metadata must be a JSON object")
    oracle = lock.get("oracle", {})
    if not isinstance(oracle, dict):
        raise ProvisionError("locked comparator identity is malformed")
    expected_manifest_sha = oracle.get("artifactManifestSha256")
    if (oracle.get("id") != negative.get("oracleId") or oracle.get("version") != "22.1.6" or
            not isinstance(expected_manifest_sha, str) or
            not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha)):
        raise ProvisionError("locked comparator identity or artifact-manifest digest is invalid")
    manifest_name = PurePosixPath(str(oracle.get("artifactManifestPath", "")))
    if manifest_name.is_absolute() or len(manifest_name.parts) != 1 or manifest_name.name in ("", ".", ".."):
        raise ProvisionError("locked comparator artifact-manifest path is unsafe")
    manifest_path = lock_path.parent / manifest_name.name
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ProvisionError("locked comparator artifact manifest is not a regular file")
    try:
        manifest_bytes = captured_evidence(manifest_path, captured)
    except OSError as error:
        raise ProvisionError(f"could not read locked comparator artifact manifest: {error}") from error
    if sha256(manifest_bytes) != expected_manifest_sha:
        raise ProvisionError("comparator artifact manifest digest differs from the release-artifacts lock")
    try:
        manifest_data = strict_json_loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisionError(f"locked comparator artifact manifest is invalid: {error}") from error
    if not isinstance(manifest_data, dict):
        raise ProvisionError("locked comparator manifest must be a JSON object")
    manifest_oracle = manifest_data.get("oracle", {})
    if not isinstance(manifest_oracle, dict):
        raise ProvisionError("locked comparator manifest identity is malformed")
    if (manifest_data.get("schemaVersion") != lock.get("schemaVersion") or
            manifest_oracle.get("id") != oracle.get("id") or
            manifest_oracle.get("version") != oracle.get("version")):
        raise ProvisionError("comparator manifest oracle identity differs from the release-artifacts lock")
    role = negative.get("artifactRole")
    lock_artifacts = lock.get("artifacts", {})
    manifest_artifacts = manifest_data.get("artifacts", {})
    expected_artifact = lock_artifacts.get(role) if isinstance(lock_artifacts, dict) else None
    manifest_artifact = manifest_artifacts.get(role) if isinstance(manifest_artifacts, dict) else None
    if (not isinstance(expected_artifact, dict) or not isinstance(manifest_artifact, dict) or
            expected_artifact.get("bytes") != manifest_artifact.get("bytes") or
            expected_artifact.get("sha256") != manifest_artifact.get("sha256")):
        raise ProvisionError("comparator manifest artifact identity differs from the release-artifacts lock")
    return lock, manifest_path, expected_manifest_sha, expected_artifact


def validate_provenance_negative_report(report: dict, record: dict, contract: dict,
                                        artifact_lock_path: Path | None = None, *,
                                        captured: dict[Path, bytes] | None = None) -> tuple[Path, str]:
    negative = contract["negativeControl"]
    lock_path = artifact_lock_path or ROOT / negative["artifactLock"]
    _, manifest_path, manifest_sha256, expected = validate_locked_comparator_manifest(lock_path, negative,
                                                                                     captured=captured)
    fixture = ROOT / negative["fixture"]
    if (report.get("scope") != "negative-version-gate-only; not a Clang 18.1.3 identity" or
            report.get("artifactOracleId") != negative["oracleId"] or
            report.get("artifactLockSha256") != sha256(captured_evidence(lock_path, captured)) or
            report.get("compilerBytes") != expected["bytes"] or
            report.get("compilerSha256") != expected["sha256"] or
            report.get("fixtureBytes") != len(captured_evidence(fixture, captured)) or
            report.get("fixtureSha256") != record.get("probe", {}).get("fixtureSha256") or
            report.get("fixtureSha256") != sha256(captured_evidence(fixture, captured)) or
            report.get("fixtureAcceptedByClang22") is not True or
            report.get("compiler18GateRejected") != "probe compiler version or target mismatch" or
            re.search(r"\bversion\s+22\.1\.6(?:\s|$)", report.get("compilerVersionOutput", "")) is None):
        raise ProvisionError("Clang 22.1.6 negative smoke report does not match the locked comparator and fixture")
    return manifest_path, manifest_sha256


def command_package_provenance(args: argparse.Namespace) -> int:
    captured: dict[Path, bytes] = {}
    contract = read_contract(args.contract, captured=captured)
    record = read_provenance_report(args.record, "build record", captured=captured)
    validate_build_record(record, contract, args.contract, captured=captured)
    if record.get("reproducibility") != {
        "cleanBuilds": 2, "matchingRootfsSha256": True, "matchingImageDigest": True,
    }:
        raise ProvisionError("provenance packaging requires a final reproducible build record")
    initial_files = [
        args.record, args.oci_archive, args.probe_report, args.loader_report, args.negative_report,
        args.contract, args.keyring, *RECIPE_FILES.values(),
    ]
    preflight_provenance_output(args.output, [args.acquisition, args.rootfs], initial_files)
    candidate = args.acquisition / "acquisition-candidate.json"
    patch_audit = args.acquisition / "patch-audit.json"
    if not candidate.is_file() or not patch_audit.is_file() or not (args.acquisition / "downloads").is_dir():
        raise ProvisionError("provenance package is missing authenticated acquisition inputs")
    if args.rootfs.is_symlink() or not args.rootfs.is_dir():
        raise ProvisionError("provenance packaging requires the retained final rootfs directory")
    comparator_lock = ROOT / contract["negativeControl"]["artifactLock"]
    _, comparator_manifest, _, _ = validate_locked_comparator_manifest(
        comparator_lock, contract["negativeControl"], captured=captured,
    )
    expected_artifacts = [
        candidate, patch_audit, args.acquisition / "downloads",
        args.record, args.probe_report, args.loader_report, args.negative_report,
        args.contract, RECIPE_FILES["schemaSha256"],
        ROOT / "oracle/clang/18.1.3/libtooling-probe.cpp",
        ROOT / "oracle/clang/18.1.3/fixtures/libtooling-positive.cpp",
        ROOT / "scripts/oracle/provision_clang_18_1_3.py",
        RECIPE_FILES["aLoaderSha256"],
        ROOT / "oracle/clang/18.1.3/Clang1813AProfileLoaderSmoke.java",
        ROOT / "oracle/clang/18.1.3/clang1813-loader-smoke.init.gradle",
        ROOT / "oracle/clang/18.1.3/test_provisioning.py",
        ROOT / "oracle/clang/18.1.3/ACQUISITION_STATUS.md",
        ROOT / ".github/workflows/generic-template-toolchain.yml",
        comparator_lock, comparator_manifest,
        args.keyring, ROOT / contract["profile"]["upstream"]["keyFile"],
    ]
    preflight_provenance_output(args.output, [args.acquisition, args.rootfs], expected_artifacts)
    captured_evidence(candidate, captured)
    captured_evidence(patch_audit, captured)
    validated_candidate, parsed_indexes = load_candidate(args.acquisition, contract, args.keyring,
                                                         build_record=record, captured=captured)
    if args.oci_archive.is_symlink() or not args.oci_archive.is_file():
        raise ProvisionError("provenance packaging requires the retained run-two OCI image archive")
    verify_retained_rootfs_and_image(args.rootfs, args.oci_archive, record, contract)
    signed_package_metadata = package_metadata_map(parsed_indexes)
    validate_record_package_metadata(
        record, signed_package_metadata, installed_package_keys(args.rootfs, contract),
    )
    verify_recorded_runtime_closure(args.rootfs, record, contract)
    record_sha256 = sha256(captured[args.record])
    probe_report = read_provenance_report(args.probe_report, "LibTooling probe", captured=captured)
    loader_report = read_provenance_report(args.loader_report, "A-loader", captured=captured)
    negative_report = read_provenance_report(args.negative_report, "Clang 22.1.6 negative", captured=captured)
    probe_binary, probe_fixture, probe_source, probe_mode = validate_provenance_probe_report(
        probe_report, record, args.rootfs, contract,
    )
    validate_provenance_loader_report(loader_report, record, record_sha256, args.rootfs)
    comparator_manifest, comparator_manifest_sha256 = validate_provenance_negative_report(
        negative_report, record, contract, captured=captured,
    )
    comparator_lock_sha256 = negative_report["artifactLockSha256"]
    # Metadata already consumed by validators keeps its original immutable
    # snapshot. Capture the remaining informational files before opening output.
    for source in expected_artifacts:
        if source != args.acquisition / "downloads":
            captured_evidence(source, captured)
    output_path = preflight_provenance_output(args.output, [args.acquisition, args.rootfs], expected_artifacts)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if preflight_provenance_output(args.output, [args.acquisition, args.rootfs], expected_artifacts) != output_path:
        raise ProvisionError("provenance output path changed after its preflight")
    archive_created = False
    epoch = int(contract["environment"]["SOURCE_DATE_EPOCH"])
    try:
        with tarfile.open(output_path, mode="x", format=tarfile.PAX_FORMAT) as archive:
            archive_created = True
            for source in expected_artifacts:
                if not source.exists():
                    raise ProvisionError(f"provenance evidence file is missing: {source}")
                if source.is_dir():
                    if source != args.acquisition / "downloads":
                        raise ProvisionError("provenance contains an unexpected input directory")
                    for row in sorted(candidate_download_rows(validated_candidate), key=lambda row: row["path"]):
                        child = args.acquisition / row["path"]
                        _add_provenance_file(archive, child, "acquisition/" + row["path"], epoch,
                                             expected_sha256=row["sha256"], expected_bytes=row["bytes"])
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
                    elif source == RECIPE_FILES["aLoaderSha256"]:
                        arcname = "src/main/kotlin/decompengine/oracle/fulltree/FullTreeGenericTemplateFrontendProfileV1.kt"
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
                    elif source == comparator_lock:
                        arcname = "trusted_keys/clang-22.1.6-release-artifacts.json"
                    elif source == comparator_manifest:
                        arcname = "trusted_keys/clang-22.1.6-oracle-manifest.json"
                    elif source == args.keyring:
                        arcname = "trusted_keys/ubuntu-archive-keyring.gpg"
                    else:
                        arcname = "trusted_keys/llvm-release.asc"
                    _add_provenance_file(
                        archive, source, arcname, epoch,
                        expected_sha256=(
                            comparator_manifest_sha256 if source == comparator_manifest else
                            comparator_lock_sha256 if source == comparator_lock else sha256(captured[source])
                        ),
                        expected_bytes=len(captured[source]), payload=captured[source],
                    )
            current_probe_binary, current_probe_mode = rootfs_regular_file(
                args.rootfs, PROBE_BINARY_IN_ROOT, executable=True,
            )
            current_probe_fixture, _ = rootfs_regular_file(args.rootfs, PROBE_FIXTURE_IN_ROOT)
            current_probe_source, _ = rootfs_regular_file(args.rootfs, PROBE_SOURCE_IN_ROOT)
            if (current_probe_mode != probe_mode or sha256_file(current_probe_binary) != record["probe"]["binarySha256"] or
                    sha256_file(current_probe_fixture) != record["probe"]["fixtureSha256"] or
                    sha256_file(current_probe_source) != record["probe"]["sourceSha256"]):
                raise ProvisionError("retained probe source/binary/fixture changed after sandbox replay")
            _add_provenance_file(
                archive, probe_binary, "rootfs" + PROBE_BINARY_IN_ROOT, epoch,
                expected_sha256=record["probe"]["binarySha256"], mode=probe_mode,
            )
            _add_provenance_file(
                archive, probe_fixture, "rootfs" + PROBE_FIXTURE_IN_ROOT, epoch,
                expected_sha256=record["probe"]["fixtureSha256"], mode=0o444,
            )
            _add_provenance_file(
                archive, probe_source, "rootfs" + PROBE_SOURCE_IN_ROOT, epoch,
                expected_sha256=record["probe"]["sourceSha256"], mode=0o444,
            )
    except ProvisionError:
        if archive_created:
            output_path.unlink(missing_ok=True)
        raise
    except (OSError, tarfile.TarError) as error:
        if archive_created:
            output_path.unlink(missing_ok=True)
        raise ProvisionError(f"could not build provenance archive: {error}") from error
    if output_path.stat().st_size > contract["profile"]["bounds"]["maxArtifactBytes"]:
        output_path.unlink(missing_ok=True)
        raise ProvisionError("provenance archive exceeds the configured artifact byte budget")
    print(f"packaged authenticated provenance archive ({output_path.stat().st_size} bytes)")
    return 0


def command_negative_version_smoke(args: argparse.Namespace) -> int:
    contract = read_contract(args.contract)
    negative = contract["negativeControl"]
    lock = strict_json_loads(args.artifact_lock.read_text(encoding="utf-8"))
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


def _add_provenance_file(archive: tarfile.TarFile, source: Path, arcname: str, epoch: int,
                         expected_sha256: str | None = None, mode: int = 0o444, *,
                         expected_bytes: int | None = None, payload: bytes | None = None) -> None:
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ProvisionError(f"provenance input lacks its authenticated byte identity: {arcname}")
    info = tarfile.TarInfo(arcname)
    info.mtime = epoch
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode = mode & 0o7777
    if payload is not None:
        if sha256(payload) != expected_sha256 or (expected_bytes is not None and len(payload) != expected_bytes):
            raise ProvisionError(f"provenance input changed before packaging: {arcname}")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    else:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        with os.fdopen(os.open(source, flags), "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ProvisionError(f"provenance input is not a regular file: {arcname}")
            size = metadata.st_size if expected_bytes is None else expected_bytes
            if type(size) is not int or size < 0 or size > MAX_SINGLE_DOWNLOAD:
                raise ProvisionError(f"provenance input exceeds its byte budget: {arcname}")
            info.size = size
            digest = hashlib.sha256()
            copied = 0

            class HashingReader:
                def read(self, requested: int) -> bytes:
                    nonlocal copied
                    block = stream.read(min(requested, 1024 * 1024, size - copied))
                    copied += len(block)
                    digest.update(block)
                    return block

            archive.addfile(info, HashingReader())
            if copied != size or stream.read(1) or digest.hexdigest() != expected_sha256:
                raise ProvisionError(f"provenance input changed while packaging: {arcname}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    status = sub.add_parser("acquisition-status", help="print read-only acquisition prerequisite state as JSON")
    status.set_defaults(run=command_acquisition_status)
    metadata = sub.add_parser(
        "probe-snapshot-metadata",
        help="authenticate one pinned Snapshot's indexes and inspect only the Clang 18 source and binary roots",
    )
    metadata.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    metadata.add_argument("--snapshot", choices=(SNAPSHOT_METADATA_PROBE,), required=True)
    metadata.add_argument("--output", type=Path, required=True)
    metadata.add_argument("--keyring", type=Path, default=DEFAULT_KEYRING)
    metadata.set_defaults(run=command_probe_snapshot_metadata)
    budget = sub.add_parser("check-rootfs-tar-budget", help="read-only archive budget inspection; not native qualification")
    budget.add_argument("--rootfs", type=Path, required=True)
    budget.add_argument("--max-bytes", type=int, required=True)
    budget.set_defaults(run=command_check_rootfs_tar_budget)
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
    provenance.add_argument("--rootfs", type=Path, required=True,
                             help="retained final rootfs used to recheck package and runtime closure")
    provenance.add_argument("--oci-archive", type=Path, required=True,
                             help="retained run-two OCI image to bind to the verified rootfs")
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
