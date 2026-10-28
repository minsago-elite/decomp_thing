#!/usr/bin/env python3
"""Bounded transport only. Kotlin must reauthenticate every fetched or cached byte."""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
DESTINATION = ROOT / "build/gcc-signed-source-inputs"
FILES = {
    "gcc-16.2.0.tar.xz": (107200820, "e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e"),
    "gcc-16.2.0.tar.xz.sig": (310, "43d73202dcede15d31001c6ba0d28723014ef57e4dc815631772daadbe23bcd2"),
}
BASE = "https://ftp.gnu.org/gnu/gcc/gcc-16.2.0/"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("canonical GCC source transport does not accept redirects")


def identity(path, expected):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != expected[0]:
        raise ValueError("GCC source transport input is not the exact single-link regular file")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        remaining = expected[0]
        while remaining:
            chunk = source.read(min(65536, remaining))
            if not chunk:
                raise ValueError("truncated transport input")
            digest.update(chunk)
            remaining -= len(chunk)
        if source.read(1):
            raise ValueError("oversized transport input")
    if digest.hexdigest() != expected[1]:
        raise ValueError("GCC source transport digest differs from the compiled pin")
    return {"bytes": expected[0], "sha256": expected[1]}


def deadline(signum, frame):
    raise TimeoutError("GCC source transport exceeded its 300 second deadline")


def main():
    started = time.monotonic()
    for parent in (ROOT / "build", DESTINATION):
        if parent.is_symlink():
            raise ValueError("transport destination must not be a symlink")
        parent.mkdir(exist_ok=True)
    evidence = ROOT / "build/gcc-signed-source-qualification"
    evidence.mkdir(exist_ok=True)
    receipt = evidence / "transport.json"
    receipt.unlink(missing_ok=True)
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(300)
    rows = []
    opener = urllib.request.build_opener(NoRedirect())
    try:
        for name, expected in FILES.items():
            target = DESTINATION / name
            existing = target.exists() or target.is_symlink()
            if not existing:
                temporary = DESTINATION / (name + ".part")
                created = False
                try:
                    with temporary.open("xb") as output:
                        created = True
                        os.chmod(temporary, 0o600)
                        request = urllib.request.Request(BASE + name, headers={"Accept-Encoding": "identity"})
                        with opener.open(request, timeout=30) as response:
                            if response.status != 200 or response.geturl() != BASE + name:
                                raise ValueError("unexpected canonical GCC response")
                            if response.headers.get("Content-Encoding", "identity") != "identity":
                                raise ValueError("encoded GCC source response refused")
                            content_length = response.headers.get("Content-Length")
                            if content_length is not None and int(content_length) != expected[0]:
                                raise ValueError("GCC source Content-Length differs")
                            remaining = expected[0]
                            while remaining:
                                chunk = response.read(min(65536, remaining))
                                if not chunk:
                                    raise ValueError("truncated GCC source response")
                                output.write(chunk)
                                remaining -= len(chunk)
                            if response.read(1):
                                raise ValueError("oversized GCC source response")
                        output.flush()
                        os.fsync(output.fileno())
                    identity(temporary, expected)
                    temporary.rename(target)
                finally:
                    if created:
                        temporary.unlink(missing_ok=True)
            rows.append({"name": name, **identity(target, expected),
                         "transport": "existing-workspace-cache" if existing else "canonical-fetch"})
        receipt.write_text(json.dumps({"schemaVersion": 1, "sourceAuthenticated": False,
            "cacheActionHit": os.environ.get("GCC_SOURCE_CACHE_HIT", "not-used"),
            "elapsedSeconds": time.monotonic() - started, "maximumWallSeconds": 300,
            "files": rows, "requiresKotlinReauthentication": True}, indent=2) + "\n")
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
