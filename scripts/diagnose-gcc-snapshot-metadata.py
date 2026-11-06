#!/usr/bin/env python3
"""Capture bounded, metadata-only diagnostics for the locked GCC Debian snapshot.

This tool never changes the production recipe or package trust policy.  Its
temporary BuildKit recipe is derived from the exact source-rewrite prefix of
the locked production Dockerfile and stops after one apt-get update attempt.
The receipt is diagnostic evidence, not a reproduction or an authority.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
GCC_ORACLE = ROOT / "oracle" / "gcc" / ("16" + ".2.0")
DOCKERFILE = GCC_ORACLE / "build-toolchain.Dockerfile"
LOCK = GCC_ORACLE / "toolchain-reproduction.json"
WORKFLOW = ROOT / ".github/workflows/gcc-oracle-model.yml"
BUILDER_EVIDENCE = ROOT / "build/gcc-toolchain-reproduction-diagnostics/builder.txt"
DEFAULT_OUTPUT = "build/gcc-snapshot-metadata-diagnostic"
TOTAL_SECONDS = 180
CLEANUP_SECONDS = 5
POSTPROCESS_SECONDS = 15
SEAL_SECONDS = 10
SEAL_CLEANUP_SECONDS = 5
RECIPE_PUBLISH_SECONDS = 5
CALL_SECONDS = 30
OUTPUT_CAP = 2 * 1024 * 1024
EVIDENCE_CAP = 8 * 1024 * 1024
APT_UPDATE_MARKER = b"    && apt-get -o Acquire::Check-Valid-Until=false update \\\n"
APT_DEBUG_OPTIONS = (
    "-o Acquire::Check-Valid-Until=false "
    "-o Acquire::Retries=0 "
    "-o Acquire::http::Timeout=30 "
    "-o Acquire::https::Timeout=30 "
    "-o Debug::Acquire::https=true "
    "-o Debug::Acquire::gpgv=true "
    "-o Debug::pkgAcquire::Auth=true"
)
SECRET_LINE = re.compile(
    r"(?i)(?:^|\s)(authorization|proxy-authorization|cookie|set-cookie|password|passwd|token|secret)\s*[:=].*"
)
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
REQUEST_TARGET = re.compile(
    r"(?i)(\b(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+)(\S+)(\s+HTTP/[0-9.]+)"
)
LOCATION = re.compile(r"(?i)(\bLocation\s*:\s*)(\S+)")


class Refusal(Exception):
    pass


SEALER_SOURCE = r'''import base64, hashlib, json, os, pathlib, stat, sys, time
root = pathlib.Path(sys.argv[1])
payload = json.load(sys.stdin)
files = payload["files"]
existing_files = payload["existingFiles"]
deadline = float(payload["deadline"])
cap = int(payload["cap"])
allowed = {"apt-diagnostic.log", "receipt.json"}
allowed.add("diagnostic.Dockerfile")
required_files = set(payload["requiredFiles"])
required_existing = set(payload["requiredExistingFiles"])
if set(files) != required_files or not required_files or not required_files <= allowed:
    raise SystemExit(64)
if set(existing_files) != required_existing or not required_existing <= allowed:
    raise SystemExit(64)
decoded = {}
for name, encoded in files.items():
    if name not in allowed or pathlib.PurePath(name).name != name:
        raise SystemExit(65)
    decoded[name] = base64.b64decode(encoded, validate=True)
for name, expected in existing_files.items():
    target = root / name
    st = os.lstat(target)
    if not stat.S_ISREG(st.st_mode) or st.st_size != int(expected["sizeBytes"]):
        raise SystemExit(66)
    with open(target, "rb") as stream:
        digest = hashlib.sha256(stream.read(cap + 1)).hexdigest()
    if digest != expected["sha256"]:
        raise SystemExit(66)
if sum(map(len, decoded.values())) + sum(int(item["sizeBytes"]) for item in existing_files.values()) > cap:
    raise SystemExit(66)
if time.monotonic() >= deadline:
    raise SystemExit(75)
items = []
for name, data in decoded.items():
    target = root / name
    temporary = root / (name + ".partial")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    items.append((name, temporary, target))
for name, temporary, target in items:
    if name == "receipt.json":
        continue
    if time.monotonic() >= deadline:
        raise SystemExit(75)
    os.link(temporary, target, follow_symlinks=False)
    os.unlink(temporary)
directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
receipt = next((item for item in items if item[0] == "receipt.json"), None)
if receipt is None:
    os._exit(0)
if time.monotonic() >= deadline - 0.05:
    raise SystemExit(75)
if os.path.lexists(receipt[2]):
    raise SystemExit(67)
os.rename(receipt[1], receipt[2])
os._exit(0)
'''


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_url(value: str) -> str:
    # Keep the endpoint and path, but never retain userinfo or query values.
    from urllib.parse import urlsplit, urlunsplit
    try:
        trimmed = value.rstrip(",;)]}")
        suffix = value[len(trimmed):]
        parsed = urlsplit(trimmed)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return "[REDACTED_URL]"
        host = parsed.hostname
        if parsed.port:
            host += f":{parsed.port}"
        safe = urlunsplit((parsed.scheme, host, parsed.path, "[REDACTED]" if parsed.query else "", ""))
        return safe + suffix
    except (ValueError, UnicodeError):
        return "[REDACTED_URL]"


def sanitize_output(raw: bytes) -> bytes:
    """Redact credentials and secret-bearing headers before evidence retention."""
    text = raw.decode("utf-8", errors="replace")
    text = _redact_private_key_blocks(text)
    lines = []
    for line in text.splitlines():
        line = REQUEST_TARGET.sub(
            lambda match: match.group(1) + _safe_target(match.group(2)) + match.group(3), line
        )
        line = LOCATION.sub(
            lambda match: match.group(1) + _safe_target(match.group(2)), line
        )
        line = URL.sub(lambda match: _safe_url(match.group(0)), line)
        if SECRET_LINE.search(line):
            lines.append("[REDACTED_SECRET_FIELD]")
            continue
        line = BEARER.sub("Bearer [REDACTED]", line)
        lines.append(line)
    return ("\n".join(lines) + ("\n" if text.endswith(("\n", "\r")) else "")).encode("utf-8")


def _safe_target(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return _safe_url(value)
    if value.startswith("//"):
        return _safe_url("https:" + value).removeprefix("https:")
    if "?" in value:
        return value.split("?", 1)[0] + "?[REDACTED]"
    if "#" in value:
        return value.split("#", 1)[0] + "#[REDACTED]"
    return value


def _redact_private_key_blocks(text: str) -> str:
    # Process all starts so a truncated final block is fail-closed too.
    starts = list(re.finditer(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----", text))
    if not starts:
        return text
    for start in reversed(starts):
        label = start.group(1)
        close = re.search(r"-----END " + re.escape(label) + r"-----", text[start.end():])
        end = start.end() + close.end() if close else len(text)
        text = text[:start.start()] + "[REDACTED_PRIVATE_KEY]" + text[end:]
    return text


def summarize_apt_transport(sanitized: bytes) -> dict:
    lines = sanitized.decode("utf-8", errors="replace").splitlines()
    statuses = []
    redirects = []
    for line in lines:
        if re.search(r"\bHTTP/[0-9.]+\s+[0-9]{3}(?:\s|$)", line):
            statuses.append(line[-240:])
        if re.search(r"(?i)\bLocation\s*:", line):
            redirects.append(line[-240:])
    return {
        "statusLinesFromAptDebug": statuses[:64],
        "redirectLinesFromAptDebug": redirects[:64],
        "statusLineCountObserved": len(statuses),
        "redirectLineCountObserved": len(redirects),
        "truncatedAt64": len(statuses) > 64 or len(redirects) > 64,
    }


def _block(sanitized: bytes, begin: bytes, end: bytes) -> bytes:
    lines = sanitized.splitlines()
    normalized = [
        _without_buildkit_prefix(line.decode("utf-8", errors="replace")).strip().encode("utf-8")
        for line in lines
    ]
    begins = [index for index, line in enumerate(normalized) if line == begin]
    ends = [index for index, line in enumerate(normalized) if line == end]
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise Refusal("required diagnostic block absent or ambiguous")
    return b"\n".join(lines[begins[0] + 1:ends[0]]) + b"\n"


def _without_buildkit_prefix(line: str) -> str:
    return re.sub(r"^\s*#\d+\s+(?:[0-9]+(?:\.[0-9]+)?\s+)?", "", line)


def parse_apt_metadata(sanitized: bytes) -> dict:
    apt_version = _block(sanitized, b"DIAG_APT_VERSION_BEGIN", b"DIAG_APT_VERSION_END")
    gpgv_version = _block(sanitized, b"DIAG_GPGV_VERSION_BEGIN", b"DIAG_GPGV_VERSION_END")
    package_versions = _block(sanitized, b"DIAG_PACKAGE_VERSIONS_BEGIN", b"DIAG_PACKAGE_VERSIONS_END")
    source_block = _block(sanitized, b"DIAG_SOURCE_STANZAS_BEGIN", b"DIAG_SOURCE_STANZAS_END")
    keyring_block = _block(sanitized, b"DIAG_KEYRINGS_BEGIN", b"DIAG_KEYRINGS_END")
    if not re.search(rb"\bapt\s+[0-9][^\r\n]*", apt_version, re.I):
        raise Refusal("APT version evidence missing")
    if not re.search(rb"\bgpgv\s+[^\r\n]*[0-9]", gpgv_version, re.I):
        raise Refusal("GPGV version evidence missing")
    versions = {}
    for package in (b"apt", b"gpgv", b"debian-archive-keyring"):
        match = re.search(rb"(?m)(?:^|\s)" + re.escape(package) + rb"=([^\s]+)\s*$", package_versions)
        if not match:
            raise Refusal(f"{package.decode()} package version evidence missing")
        versions[package.decode()] = match.group(1).decode("ascii", errors="strict")

    source_lines = [_without_buildkit_prefix(line) for line in source_block.decode("utf-8", errors="replace").splitlines()]
    if not any(line.startswith(("URIs:", "deb ", "deb-src ")) for line in source_lines):
        raise Refusal("APT source stanza evidence missing")
    signed_by = set()
    for line in source_lines:
        if line.startswith("Signed-By:"):
            signed_by.update(token for token in line.split(":", 1)[1].split() if token.startswith("/"))
        else:
            signed_by.update(re.findall(r"(?i)signed-by=(/[^,\]\s]+)", line))

    lines = [_without_buildkit_prefix(line) for line in keyring_block.decode("utf-8", errors="replace").splitlines()]
    keyrings = []
    active_path = None
    active_lines = []
    for line in lines:
        begin = re.fullmatch(r"KEYRING_BEGIN=(\S+)", line)
        end = re.fullmatch(r"KEYRING_END=(\S+)", line)
        if begin:
            if active_path is not None:
                raise Refusal("nested keyring evidence block")
            active_path, active_lines = begin.group(1), []
        elif end:
            if active_path != end.group(1):
                raise Refusal("keyring evidence block identity mismatch")
            metas = [re.fullmatch(r"KEYRING_META mode=([0-7]{3,4}) size=([0-9]+) uid=([0-9]+) gid=([0-9]+) path=(\S+)", x)
                     for x in active_lines if x.startswith("KEYRING_META ")]
            digests = [re.fullmatch(r"([0-9a-f]{64})\s+(.+)", x)
                       for x in active_lines if re.match(r"^[0-9a-f]{64}\s+", x)]
            meta = metas[0] if len(metas) == 1 else None
            digest = digests[0] if len(digests) == 1 else None
            fingerprints = [m.group(1) for x in active_lines
                            if (m := re.fullmatch(r"KEYRING_FPR=([0-9A-Fa-f]{40,64})", x))]
            if (not meta or not digest or meta.group(5) != active_path or digest.group(2) != active_path
                    or int(meta.group(2)) <= 0 or int(meta.group(3)) != 0
                    or int(meta.group(4)) != 0 or int(meta.group(1), 8) & 0o022
                    or not fingerprints):
                raise Refusal("keyring path, mode, digest, or fingerprint evidence missing")
            keyrings.append({"path": active_path, "mode": meta.group(1), "sizeBytes": int(meta.group(2)),
                             "uid": int(meta.group(3)), "gid": int(meta.group(4)),
                             "sha256": digest.group(1), "fingerprints": fingerprints})
            active_path, active_lines = None, []
        elif active_path is not None:
            active_lines.append(line)
    if active_path is not None:
        raise Refusal("unterminated keyring evidence block")
    by_path = {item["path"]: item for item in keyrings}
    if signed_by and any(path not in by_path for path in signed_by):
        raise Refusal("an APT Signed-By keyring lacks matching hash/fingerprint evidence")
    if not signed_by and not keyrings:
        raise Refusal("APT default trust keyring evidence missing")
    return {"packageVersions": versions, "sourceSignedByPaths": sorted(signed_by),
            "aptVersion": re.search(rb"\bapt\s+([^\r\n]+)", apt_version, re.I).group(1).decode("utf-8", errors="replace").strip(),
            "gpgvVersion": re.search(rb"\bgpgv\s+([^\r\n]+)", gpgv_version, re.I).group(1).decode("utf-8", errors="replace").strip(),
            "keyrings": keyrings}


def provenance_is_complete(provenance: dict, builder_hash: str | None) -> bool:
    requested = provenance.get("requestedHead")
    executed = provenance.get("executedCommit")
    workflow_sha = provenance.get("workflowSha")
    tree = provenance.get("executedTree")
    return (
        bool(GIT_SHA.fullmatch(requested or ""))
        and bool(GIT_SHA.fullmatch(executed or ""))
        and bool(GIT_SHA.fullmatch(workflow_sha or ""))
        and executed == workflow_sha
        and bool(GIT_SHA.fullmatch(tree or ""))
        and bool(re.fullmatch(r"[0-9]+", provenance.get("workflowRunId") or ""))
        and bool(re.fullmatch(r"[1-9][0-9]*", provenance.get("workflowRunAttempt") or ""))
        and bool(re.fullmatch(r"[a-z0-9_]{1,64}", provenance.get("workflowEvent") or ""))
        and provenance.get("worktreeClean") is True
        and bool(GIT_SHA.fullmatch(builder_hash or ""))
    )


def derive_diagnostic_recipe(dockerfile: bytes, lock: dict) -> tuple[bytes, str]:
    expected = lock.get("recipe", {}).get("dockerfileSha256")
    actual = sha256(dockerfile)
    if not isinstance(expected, str) or actual != expected:
        raise Refusal("production Dockerfile does not match the reproduction lock")
    marker_count = dockerfile.count(APT_UPDATE_MARKER)
    if marker_count != 1:
        raise Refusal("expected exactly one locked apt-get update boundary")
    prefix = dockerfile.split(APT_UPDATE_MARKER, 1)[0]
    if not prefix.endswith(b"\\\n") or b"FROM gcc@sha256:" not in prefix or b"/etc/apt/sources.list.d/debian.sources" not in prefix:
        raise Refusal("production extractor prefix is not the expected locked shape")
    suffix = f"""    && {{ \\
        set +e; \\
        apt-get {APT_DEBUG_OPTIONS} update; apt_status=$?; \\
        printf 'DIAG_APT_EXIT=%s\\n' "$apt_status"; \\
        printf 'DIAG_APT_VERSION_BEGIN\\n'; apt-get --version 2>&1 | head -n 2; printf 'DIAG_APT_VERSION_END\\n'; \\
        printf 'DIAG_GPGV_VERSION_BEGIN\\n'; gpgv --version 2>&1 | head -n 2; printf 'DIAG_GPGV_VERSION_END\\n'; \\
        printf 'DIAG_PACKAGE_VERSIONS_BEGIN\\n'; \\
          dpkg-query -W -f='${{binary:Package}}=${{Version}}\\n' apt gpgv debian-archive-keyring 2>&1 || true; \\
        printf 'DIAG_PACKAGE_VERSIONS_END\\n'; \\
        printf 'DIAG_GPG_TOOL='; if command -v gpg >/dev/null 2>&1; then echo available; else echo unavailable; fi; \\
        printf 'DIAG_SOURCE_STANZAS_BEGIN\\n'; \\
          for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do \\
            if [ -f "$f" ]; then \\
              awk '/^(Types|URIs|Suites|Components|Architectures|Signed-By|deb |deb-src )/ {{ print }}' "$f"; \\
            fi; \\
          done; \\
        printf 'DIAG_SOURCE_STANZAS_END\\n'; \\
        printf 'DIAG_KEYRINGS_BEGIN\\n'; \\
          for d in /etc/apt/keyrings /etc/apt/trusted.gpg.d /usr/share/keyrings; do \\
            if [ -d "$d" ]; then \\
                find "$d" -maxdepth 1 -type f \\
                \\( -path '/etc/apt/keyrings/*' -o -name '*.gpg' -o -name '*.pgp' -o -name '*.asc' \\) -print; \\
            fi; \\
          done | while IFS= read -r f; do \\
            fprs=$(gpg --batch --no-default-keyring --keyring "$f" --with-colons --fingerprint --list-keys 2>/dev/null | \\
              awk -F: '$1 == "fpr" {{ print "KEYRING_FPR=" $10 }}' || true); \\
            if [ -n "$fprs" ]; then \\
              printf 'KEYRING_BEGIN=%s\\n' "$f"; \\
              stat -c 'KEYRING_META mode=%a size=%s uid=%u gid=%g path=%n' "$f" 2>&1 || true; \\
              sha256sum "$f" 2>&1 || true; \\
              printf '%s\\n' "$fprs"; \\
              printf 'KEYRING_END=%s\\n' "$f"; \\
            fi; \\
          done; \\
        if [ -f /etc/apt/trusted.gpg ]; then \\
          f=/etc/apt/trusted.gpg; \\
          fprs=$(gpg --batch --no-default-keyring --keyring "$f" --with-colons --fingerprint --list-keys 2>/dev/null | \\
            awk -F: '$1 == "fpr" {{ print "KEYRING_FPR=" $10 }}' || true); \\
          if [ -n "$fprs" ]; then \\
            printf 'KEYRING_BEGIN=%s\\n' "$f"; \\
            stat -c 'KEYRING_META mode=%a size=%s uid=%u gid=%g path=%n' "$f" 2>&1 || true; \\
            sha256sum "$f" 2>&1 || true; \\
            printf '%s\\n' "$fprs"; \\
            printf 'KEYRING_END=%s\\n' "$f"; \\
          fi; \\
        fi; \\
        printf 'DIAG_KEYRINGS_END\\n'; \\
        exit 0; \\
    }}
""".encode()
    recipe = prefix + suffix
    if any(term in recipe.lower() for term in (b"apt-get download", b"dpkg-deb", b"--extract", b"--load")):
        raise Refusal("derived diagnostic recipe crossed the metadata-only boundary")
    if recipe.count(b"apt-get ") != 2:  # update + version query only
        raise Refusal("derived diagnostic recipe contains an unexpected apt invocation")
    return recipe, actual


def _git_value(*args: str, deadline: float | None = None,
               empty_ok: bool = False) -> str | None:
    try:
        timeout = 5.0
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
            if timeout <= 0:
                return None
        result = subprocess.run(["git", *args], cwd=ROOT, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=True, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        value = result.stdout.decode("ascii", errors="strict").strip()
        return value if value else ("" if empty_ok else None)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None


def _seal_files(output: Path, files: dict[str, bytes], *, existing_files: dict[str, dict], deadline: float,
                cleanup_deadline: float) -> tuple[bool, bool]:
    """Publish fixed-name files in an owned, deadline-bounded child."""
    if time.monotonic() >= deadline or cleanup_deadline <= deadline:
        return False, True
    encoded = {name: base64.b64encode(data).decode("ascii") for name, data in files.items()}
    payload = json.dumps({"files": encoded, "existingFiles": existing_files,
                          "requiredFiles": sorted(files),
                          "requiredExistingFiles": sorted(existing_files),
                          "deadline": deadline, "cap": EVIDENCE_CAP},
                         separators=(",", ":")).encode("ascii")
    process = None
    timed_out = False
    cleanup_confirmed = True
    try:
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", SEALER_SOURCE, str(output)],
            cwd=ROOT, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        remaining = max(0.0, deadline - time.monotonic())
        try:
            process.communicate(input=payload, timeout=remaining)
        except subprocess.TimeoutExpired:
            timed_out = True
        if timed_out or process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_confirmed = False
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_confirmed = False
            remaining = max(0.0, cleanup_deadline - time.monotonic())
            try:
                process.communicate(timeout=remaining)
            except subprocess.TimeoutExpired:
                cleanup_confirmed = False
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        except OSError:
            cleanup_confirmed = False
        else:
            cleanup_confirmed = False
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        ok = (not timed_out and cleanup_confirmed and process.returncode == 0
              and time.monotonic() <= deadline)
        return ok, cleanup_confirmed
    except BaseException:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            remaining = max(0.0, cleanup_deadline - time.monotonic())
            try:
                process.communicate(timeout=remaining)
            except BaseException:
                cleanup_confirmed = False
        return False, cleanup_confirmed


def _run_docker(argv: list[str], env: dict[str, str], cwd: Path, end: float):
    """One child, bounded streaming output, deadline and process-group cleanup."""
    operation_end = min(end, time.monotonic() + TOTAL_SECONDS)
    work_end = operation_end - CLEANUP_SECONDS - POSTPROCESS_SECONDS - SEAL_SECONDS - SEAL_CLEANUP_SECONDS
    if time.monotonic() >= work_end:
        raise Refusal("diagnostic deadline exhausted before Docker invocation")
    process = None
    selector = selectors.DefaultSelector()
    output = bytearray()
    overflow = False
    timed_out = False
    cleanup = []
    status = None
    child_error = None
    group_cleanup_confirmed = False
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        for label, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = work_end - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(0.2, remaining)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = OUTPUT_CAP - len(output)
                output.extend(chunk[:room])
                if len(chunk) > room:
                    overflow = True
                    break
            if overflow:
                break
        if not timed_out and not overflow:
            remaining = max(0, work_end - time.monotonic())
            try:
                status = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
    except BaseException as exc:
        child_error = f"{type(exc).__name__}: {exc}"
        cleanup.append(f"spawn/read={type(exc).__name__}")
    finally:
        if process is not None:
            # The leader may have exited after leaving descendants behind. The
            # owned process group is cleaned independently of leader status.
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(process.pid, sig)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    cleanup.append(f"{signal.Signals(sig).name}={type(exc).__name__}")
            if process.poll() is None:
                wait_budget = max(0.0, min(CLEANUP_SECONDS, end - time.monotonic()))
                try:
                    if wait_budget > 0:
                        process.wait(timeout=wait_budget)
                    else:
                        process.poll()
                except BaseException as exc:
                    cleanup.append(f"reap={type(exc).__name__}")
            cleanup_end = min(end - POSTPROCESS_SECONDS - SEAL_SECONDS - SEAL_CLEANUP_SECONDS,
                              time.monotonic() + CLEANUP_SECONDS)
            while time.monotonic() < cleanup_end:
                try:
                    os.killpg(process.pid, 0)
                    time.sleep(min(0.05, cleanup_end - time.monotonic()))
                except ProcessLookupError:
                    group_cleanup_confirmed = True
                    break
                except OSError as exc:
                    cleanup.append(f"group-check={type(exc).__name__}")
                    break
            if not group_cleanup_confirmed:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    group_cleanup_confirmed = True
                except OSError as exc:
                    cleanup.append(f"group-check={type(exc).__name__}")
                else:
                    cleanup.append("owned process group remained after SIGKILL")
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError as exc:
                        cleanup.append(f"close={type(exc).__name__}")
        selector.close()
    sanitized = sanitize_output(bytes(output))
    complete = (status == 0 and not timed_out and not overflow and not cleanup and group_cleanup_confirmed)
    return {
        "exitCode": status,
        "error": child_error,
        "timedOut": timed_out,
        "outputOverflow": overflow,
        "cleanup": cleanup,
        "groupCleanupConfirmed": group_cleanup_confirmed,
        "complete": complete,
        "rawOutputBytesObservedAtMost": len(output),
        "sanitizedOutput": sanitized,
    }


def _output_directory(relative: str) -> Path:
    parts = relative.split("/")
    if len(parts) < 2 or parts[0] != "build" or any(x in ("", ".", "..") for x in parts):
        raise Refusal("output must be a normalized repository-relative path under build/")
    build = ROOT / "build"
    if build.exists() and build.is_symlink():
        raise Refusal("build output root must not be a symlink")
    path = ROOT.joinpath(*parts)
    if not path.parent.resolve().is_relative_to(ROOT):
        raise Refusal("output parent escaped repository root")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(mode=0o700)
    if not path.resolve().is_relative_to(ROOT):
        raise Refusal("output path escaped repository root")
    return path


def _receipt_bytes(receipt: dict) -> bytes:
    return (json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def capture(output_relative: str, docker_host: str, environ: dict[str, str] | None = None) -> tuple[int, Path | None]:
    start = time.monotonic()
    end = start + TOTAL_SECONDS
    output = None
    recipe_bytes = b""
    sanitized = b""
    process = {"exitCode": None, "timedOut": False, "outputOverflow": False,
               "groupCleanupConfirmed": False,
               "cleanup": [], "complete": False, "rawOutputBytesObservedAtMost": 0}
    error = None
    apt_exit = None
    apt_metadata = None
    source_hashes = {}
    locked_build_inputs = None
    try:
        output = _output_directory(output_relative)
        raw_dockerfile = DOCKERFILE.read_bytes()
        lock = json.loads(LOCK.read_bytes())
        locked_build_inputs = {
            "baseImageDigest": lock["recipe"]["baseImageDigest"],
            "platform": lock["recipe"]["platform"],
            "sourceDateEpoch": lock["recipe"]["sourceDateEpoch"],
            "publishedImage": False,
        }
        recipe_bytes, production_hash = derive_diagnostic_recipe(raw_dockerfile, lock)
        preparation_end = min(
            start + RECIPE_PUBLISH_SECONDS,
            end - CLEANUP_SECONDS - POSTPROCESS_SECONDS - SEAL_SECONDS - SEAL_CLEANUP_SECONDS,
        )
        preparation_cleanup_end = min(
            end - POSTPROCESS_SECONDS - SEAL_SECONDS - SEAL_CLEANUP_SECONDS,
            preparation_end + CLEANUP_SECONDS,
        )
        recipe_published, recipe_cleanup_confirmed = _seal_files(
            output,
            {"diagnostic.Dockerfile": recipe_bytes},
            existing_files={},
            deadline=preparation_end,
            cleanup_deadline=preparation_cleanup_end,
        )
        if not recipe_published or not recipe_cleanup_confirmed:
            raise Refusal("locked diagnostic recipe publication failed or exceeded its deadline")
        source_hashes = {
            "dockerfileSha256": production_hash,
            "reproductionLockSha256": sha256(LOCK.read_bytes()),
            "buildRecordSha256": sha256((GCC_ORACLE / "build-record.json").read_bytes()),
            "sourceLockSha256": sha256((GCC_ORACLE / "source-lock.json").read_bytes()),
            "reproductionVerifierSha256": sha256((ROOT / "scripts/verify-gcc-toolchain-reproduction.py").read_bytes()),
            "workflowSha256": sha256(WORKFLOW.read_bytes()),
            "driverSha256": sha256(Path(__file__).read_bytes()),
            "derivedRecipeSha256": sha256(recipe_bytes),
        }
        endpoint_scheme = docker_host.partition(":")[0] if ":" in docker_host else "unknown"
        if endpoint_scheme not in ("unix", "tcp", "npipe", "ssh") or "\n" in docker_host:
            raise Refusal("unsupported Docker endpoint form")
        env_in = os.environ if environ is None else environ
        env = {k: env_in[k] for k in ("PATH", "HOME", "DOCKER_CONFIG", "DOCKER_CLI_PLUGIN_EXTRA_DIRS") if k in env_in}
        env.setdefault("PATH", "/usr/bin:/bin")
        argv = ["docker", "--host", docker_host, "buildx", "build", "--no-cache",
                "--platform", lock["recipe"]["platform"],
                "--build-arg", "SOURCE_DATE_EPOCH=" + lock["recipe"]["sourceDateEpoch"],
                "--progress=plain", "--output=type=cacheonly",
                "--file", "diagnostic.Dockerfile", "."]
        if time.monotonic() >= end - CLEANUP_SECONDS - POSTPROCESS_SECONDS - SEAL_SECONDS - SEAL_CLEANUP_SECONDS:
            raise Refusal("diagnostic deadline exhausted before Docker invocation")
        process = _run_docker(argv, env, output, end)
        sanitized = process.pop("sanitizedOutput")
        if len(sanitized) > OUTPUT_CAP:
            process["complete"] = False
            raise Refusal("sanitized diagnostic output exceeded its byte cap")
        marker = re.findall(rb"(?m)(?:^|\s)DIAG_APT_EXIT=([0-9]{1,3})\s*$", sanitized)
        if len(marker) == 1:
            apt_exit = int(marker[0])
        else:
            raise Refusal("APT exit marker absent or ambiguous")
        apt_metadata = parse_apt_metadata(sanitized)
        gpg_tools = re.findall(rb"(?m)(?:^|\s)DIAG_GPG_TOOL=(available|unavailable)\s*$", sanitized)
        if len(gpg_tools) != 1:
            raise Refusal("GnuPG tool availability evidence absent or ambiguous")
        if gpg_tools[0] != b"available":
            raise Refusal("keyring fingerprint evidence unavailable")
        if not process["complete"]:
            raise Refusal("Docker diagnostic was incomplete")
        if time.monotonic() >= end - SEAL_SECONDS - SEAL_CLEANUP_SECONDS:
            raise Refusal("diagnostic exceeded its post-processing deadline")
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
    if output is None:
        try:
            output = _output_directory(output_relative)
        except BaseException:
            return 1, None

    existing_builder = BUILDER_EVIDENCE
    builder_hash = sha256(existing_builder.read_bytes()) if existing_builder.is_file() else None
    env_receipt = environ or os.environ
    provenance = {
        "requestedHead": env_receipt.get("GCC_REPRODUCTION_HEAD"),
        "workflowSha": env_receipt.get("GITHUB_SHA"),
        "executedCommit": _git_value("rev-parse", "HEAD", deadline=end - SEAL_SECONDS - SEAL_CLEANUP_SECONDS),
        "executedTree": _git_value("rev-parse", "HEAD^{tree}", deadline=end - SEAL_SECONDS - SEAL_CLEANUP_SECONDS),
        "workflowRunId": env_receipt.get("GITHUB_RUN_ID"),
        "workflowRunAttempt": env_receipt.get("GITHUB_RUN_ATTEMPT"),
        "workflowEvent": env_receipt.get("GITHUB_EVENT_NAME"),
        "worktreeClean": _git_value("status", "--porcelain", deadline=end - SEAL_SECONDS - SEAL_CLEANUP_SECONDS,
                                     empty_ok=True) == "",
    }
    provenance_complete = provenance_is_complete(provenance, builder_hash)
    if not provenance_complete and error is None:
        error = "required clean-source or builder provenance evidence is missing"
    if time.monotonic() >= end - SEAL_SECONDS - SEAL_CLEANUP_SECONDS and error is None:
        error = "diagnostic exceeded its provenance deadline"
    status = ("complete" if error is None and process["complete"] and apt_exit is not None
              and provenance_complete else "incomplete")
    receipt = {
        "schemaVersion": 1,
        "kind": "gcc-debian-snapshot-metadata-diagnostic-only",
        "status": status,
        "limitations": [
            "This is not production image reproduction or package/ELF qualification.",
            "APT debug may expose selected status/location lines; it does not retain the complete response chain or APT-consumed body bytes.",
            "No independent direct HTTP request was performed; no response facts are inferred from APT progress labels.",
            "No package was downloaded, hash-checked, extracted, or published by this diagnostic recipe.",
        ],
        "provenance": provenance,
        "sourceSha256": source_hashes,
        "lockedBuildInputs": locked_build_inputs,
        "builderEvidenceSha256": builder_hash,
        "dockerEndpoint": {"scheme": docker_host.partition(":")[0],
                           "sha256": sha256(docker_host.encode("utf-8"))},
        "snapshotEndpoints": [
            "https://snapshot.debian.org/archive/debian/20260824T000000Z/dists/trixie/InRelease",
            "https://snapshot.debian.org/archive/debian/20260824T000000Z/dists/trixie/Release",
            "https://snapshot.debian.org/archive/debian/20260824T000000Z/dists/trixie/Release.gpg",
            "https://snapshot.debian.org/archive/debian/20260824T000000Z/dists/trixie-updates/InRelease",
            "https://snapshot.debian.org/archive/debian/20260824T000000Z/dists/trixie-updates/Release",
            "https://snapshot.debian.org/archive/debian/20260824T000000Z/dists/trixie-updates/Release.gpg",
            "https://snapshot.debian.org/archive/debian-security/20260824T000000Z/dists/trixie-security/InRelease",
            "https://snapshot.debian.org/archive/debian-security/20260824T000000Z/dists/trixie-security/Release",
            "https://snapshot.debian.org/archive/debian-security/20260824T000000Z/dists/trixie-security/Release.gpg",
        ],
        "aptObservation": {
            "updateExitCode": apt_exit,
            "aptProgressLinesAreNotHttpStatus": True,
            **summarize_apt_transport(sanitized),
            "httpStatuses": "only-explicit-lines-reported-by-APT-debug",
            "redirectChain": "APT debug lines only; ordering retained in apt-diagnostic.log",
            "aptConsumedBodyBytes": "unavailable-from-apt-capture",
            "retainedResponseBodies": 0,
            "debugOptions": ["Debug::Acquire::https", "Debug::Acquire::gpgv", "Debug::pkgAcquire::Auth"],
            "retryPolicy": "Acquire::Retries=0",
            "requestTimeoutSeconds": CALL_SECONDS,
            "directResponseProbe": "not-performed",
        },
        "aptMetadata": apt_metadata,
        "process": {k: v for k, v in process.items() if k != "sanitizedOutput"},
        "totalDeadlineSeconds": TOTAL_SECONDS,
        "cleanupReserveSeconds": CLEANUP_SECONDS + SEAL_CLEANUP_SECONDS,
        "dockerInvocationBudgetSeconds": TOTAL_SECONDS - RECIPE_PUBLISH_SECONDS - CLEANUP_SECONDS - POSTPROCESS_SECONDS - SEAL_SECONDS - SEAL_CLEANUP_SECONDS,
        "recipePublicationBudgetSeconds": RECIPE_PUBLISH_SECONDS,
        "postprocessReserveSeconds": POSTPROCESS_SECONDS,
        "evidenceSealReserveSeconds": SEAL_SECONDS,
        "evidenceSealCleanupReserveSeconds": SEAL_CLEANUP_SECONDS,
        "evidenceCapBytes": EVIDENCE_CAP,
        "error": error,
        "elapsedSeconds": round(time.monotonic() - start, 3),
    }
    evidence = {
        "diagnostic.Dockerfile": recipe_bytes,
        "apt-diagnostic.log": sanitized,
    }
    receipt["evidenceFiles"] = {
        name: {"sha256": sha256(data), "sizeBytes": len(data)}
        for name, data in sorted(evidence.items())
    }
    receipt_data = _receipt_bytes(receipt)
    try:
        if time.monotonic() >= end - SEAL_SECONDS - SEAL_CLEANUP_SECONDS and receipt["status"] == "complete":
            receipt["status"] = "incomplete"
            receipt["error"] = "diagnostic deadline exhausted before evidence sealing"
            receipt_data = _receipt_bytes(receipt)
        current_size = sum(map(len, evidence.values()))
        if current_size + len(receipt_data) > EVIDENCE_CAP:
            receipt["status"] = "incomplete"
            receipt["error"] = "evidence exceeded total size cap"
            receipt_data = _receipt_bytes(receipt)
        seal_deadline = end - SEAL_CLEANUP_SECONDS
        cleanup_deadline = end
        seal_ok, cleanup_confirmed = _seal_files(
            output,
            {"apt-diagnostic.log": sanitized, "receipt.json": receipt_data},
            existing_files={"diagnostic.Dockerfile": {"sha256": sha256(recipe_bytes),
                                                       "sizeBytes": len(recipe_bytes)}},
            deadline=seal_deadline,
            cleanup_deadline=cleanup_deadline,
        )
        if not seal_ok or not cleanup_confirmed:
            return 1, output
    except BaseException:
        return 1, output
    return (0 if receipt["status"] == "complete" else 1), output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker-host", default=os.environ.get("DOCKER_HOST", ""))
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    result, path = capture(args.output, args.docker_host)
    print(f"snapshot metadata diagnostic status={'complete' if result == 0 else 'incomplete'}")
    if path is not None:
        print(f"evidence={path.relative_to(ROOT)}")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
