#!/usr/bin/env python3
"""HTTP smoke of our ZIP/TAR distributions; no analysis tools or model calls.

Python is a test driver only. The child application receives a PATH containing
launcher utilities, with Node/npm absent, and a read-only relocated installation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile


REPOSITORY = Path(__file__).resolve().parent.parent


def verify() -> list[dict]:
    if not __debug__:
        raise RuntimeError("Run this test driver without Python assertion optimization")
    java_home = os.environ.get("JAVA_HOME")
    if not java_home or not (Path(java_home) / "bin/java").is_file():
        raise RuntimeError("JAVA_HOME must select the JDK used for the packaged application")
    root = Path(tempfile.mkdtemp(prefix="decomp packaged web "))
    results = []
    try:
        bins = root / "runtime tools"
        bins.mkdir()
        for name in ("uname", "ls", "xargs", "sed", "tr"):
            executable = shutil.which(name)
            if executable is None:
                raise RuntimeError(f"Required POSIX launcher utility is missing: {name}")
            (bins / name).symlink_to(executable)
        environment = dict(os.environ, PATH=str(bins))
        for tool in ("node", "npm"):
            if subprocess.run(["/bin/sh", "-c", f"command -v {tool}"], env=environment,
                              stdout=subprocess.DEVNULL, check=False).returncode == 0:
                raise AssertionError(f"Runtime PATH unexpectedly contains {tool}")

        for suffix in ("zip", "tar"):
            candidates = sorted((REPOSITORY / "build/distributions").glob(f"llm_bin_patch-*.{suffix}"))
            if len(candidates) != 1:
                raise RuntimeError(f"Build exactly one current {suffix} distribution before this check")
            archive = candidates[0]
            unpack = root / f"read only {suffix}"
            unpack.mkdir()
            # These archives are build-produced inputs, never uploaded project archives.
            if suffix == "zip":
                with zipfile.ZipFile(archive) as container:
                    if len(container.namelist()) != len(set(container.namelist())):
                        raise AssertionError("Distribution contains duplicate ZIP entries")
                    container.extractall(unpack)
            else:
                with tarfile.open(archive) as container:
                    container.extractall(unpack, filter="data")
            installations = list(unpack.iterdir())
            if len(installations) != 1 or not installations[0].is_dir():
                raise AssertionError("Distribution must contain one application directory")
            app = installations[0]
            launcher = app / "bin/llm_bin_patch"
            application_jars = list((app / "lib").glob("llm-bin-patch-*.jar"))
            if len(application_jars) != 1:
                raise AssertionError("Distribution must contain one application JAR")
            with zipfile.ZipFile(application_jars[0]) as jar:
                namespace = "decompengine/web/ui/"
                manifest_bytes = jar.read(namespace + "asset-manifest.json")
                manifest = json.loads(manifest_bytes)
                actual = {name.removeprefix(namespace) for name in jar.namelist()
                          if name.startswith(namespace) and not name.endswith("/")}
                expected = {item["path"] for item in manifest["files"]} | {"asset-manifest.json"}
                if actual != expected:
                    raise AssertionError("Application JAR does not have the exact inventoried UI resource set")
                for item in manifest["files"]:
                    content = jar.read(namespace + item["path"])
                    if len(content) != item["sizeBytes"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
                        raise AssertionError("Application JAR asset digest/length differs from inventory")
            before = {path.relative_to(app): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in app.rglob("*") if path.is_file()}
            for path in app.rglob("*"):
                executable = path.parent.name in ("bin", "libexec") and not path.name.endswith(".sha256")
                path.chmod(0o555 if path.is_dir() or executable else 0o444)
            app.chmod(0o555)
            working = root / f"unrelated {suffix}"
            working.mkdir()
            data = working / "private jobs"
            process = subprocess.Popen(
                [str(launcher), "web", "--ui", "spa", "--port", "0", "--base-path", "/nested/",
                 "--data-dir", str(data)],
                cwd=working, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                deadline = time.monotonic() + 15
                line = ""
                while time.monotonic() < deadline:
                    if select.select([process.stdout], [], [], 0.2)[0]:
                        line = process.stdout.readline()
                        if "Serving decomp_engine" in line:
                            break
                    if process.poll() is not None:
                        raise AssertionError(f"Packaged server exited: {process.stderr.read()}")
                match = re.search(r"http://127\.0\.0\.1:\d+", line)
                if match is None:
                    raise AssertionError("Packaged server did not report its listening address within 15 s")
                origin = match.group(0)
                for item in manifest["files"]:
                    if not item["public"]:
                        continue
                    url = origin + "/nested/assets/ui/" + item["path"]
                    with urllib.request.urlopen(url, timeout=5) as response:
                        payload = response.read()
                        assert response.status == 200
                        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
                        assert len(payload) == item["sizeBytes"]
                        assert response.headers["Referrer-Policy"] == "no-referrer"
                    with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=5) as response:
                        assert response.status == 200 and response.read() == b""
                        assert int(response.headers["Content-Length"]) == item["sizeBytes"]
                    try:
                        urllib.request.urlopen(urllib.request.Request(url, headers={
                            "If-None-Match": f'"{item["sha256"]}"',
                        }), timeout=5)
                        raise AssertionError("Conditional asset read did not return 304")
                    except urllib.error.HTTPError as error:
                        assert error.code == 304
                with urllib.request.urlopen(origin + "/nested/runtime", timeout=5) as response:
                    html = response.read()
                    assert manifest["buildId"].encode() in html
                    assert b'decomp-application-version' in html
                for path in ("/nested/api/v1/missing", "/nested/assets/ui/asset-manifest.json", "/nested/jobs/fixture"):
                    try:
                        urllib.request.urlopen(origin + path, timeout=5)
                        raise AssertionError(f"Unknown/private path was served: {path}")
                    except urllib.error.HTTPError as error:
                        assert error.code == 404
                assert not data.exists(), "Public preview must not create/recover job state"
                assert (app / "docs/frontend-THIRD_PARTY_NOTICES.txt").is_file()
                results.append({"archive": archive.name, "buildId": manifest["buildId"],
                                "publicAssets": sum(item["public"] for item in manifest["files"]),
                                "nodeOnPath": False, "readOnlyInstallation": True})
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise AssertionError("Packaged server shutdown exceeded 5 s")
            after = {path.relative_to(app): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in app.rglob("*") if path.is_file()}
            assert before == after, "Application installation changed during runtime smoke"
        return results
    finally:
        for path in root.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
        shutil.rmtree(root)


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
