#!/usr/bin/env python3
"""Collect a redacted support bundle for the web workbench without exposing secrets or job content.

The bundle is built from allowlisted facts only:

  distribution.json  version, application build ID (application JAR SHA-256) and UI build ID
  java.txt           `java -version` of the selected runtime
  doctor.txt         `llm_bin_patch doctor --tools-only` status lines, host paths replaced
  storage.json       counts and byte totals under --data-dir; no names, job IDs or contents
  requests.txt       `web-http-failure request_id=... status=... code=...` lines from a server log
  runtime.json       an allowlisted projection of a saved /api/v1/session or /api/v1/bootstrap reply

It never copies binaries, job directories, reports, source, the launcher's session link, cookies,
CSRF tokens or environment values. Before it reports success it rescans every written file for the
data/installation/home paths, session links and cookies, and secret-looking environment values,
and deletes the bundle if any appear.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

REPOSITORY = Path(__file__).resolve().parent.parent
REQUEST_LINE = re.compile(r"web-http-failure request_id=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} status=[45][0-9]{2} code=[A-Z_]{1,64}")
DOCTOR_LINE = re.compile(r"\[(ok|failed|skipped|warning)\] .{0,400}|Environment check (passed|failed).{0,200}")
SECRET_NAME = re.compile(r"TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH|COOKIE|SESSION", re.IGNORECASE)
JOB_NAME = re.compile(r"[a-f0-9]{32}")
OWNER_LOCKS = (".web-owner.lock", ".workflow-owner.lock")
# The JVM echoes these option variables ("Picked up ...") and they can carry credentials.
JVM_OPTION_VARIABLES = ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")
JAVA_VERSION_LINE = re.compile(r"(?:openjdk|java) version \"[0-9A-Za-z._+-]{1,64}\"(?: [0-9-]{10})?(?: LTS)?"
                               r"|[A-Za-z0-9 ()._+-]{1,120}(?:Runtime Environment|VM) [A-Za-z0-9 ()._+,-]{1,160}")
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_STORAGE_ENTRIES = 200_000


class BundleError(Exception):
    pass


def secret_values(environment: dict[str, str]) -> list[str]:
    return sorted({value for name, value in environment.items() if SECRET_NAME.search(name) and len(value) >= 8}, key=len, reverse=True)


def redact(text: str, paths: list[str], secrets: list[str], other_paths: bool = True) -> str:
    for secret in secrets:
        text = text.replace(secret, "<redacted>")
    for path in sorted(paths, key=len, reverse=True):
        if path and path != "/":
            text = text.replace(path, "<path>")
    if not other_paths:
        return text
    # Any remaining multi-component absolute path is replaced too.
    return re.sub(r"(?<![\w<])/(?:[^\s/:'\"]+/)+[^\s/:'\"]*", "<path>", text)


def distribution(install: Path) -> dict:
    jars = sorted((install / "lib").glob("llm-bin-patch-*.jar"))
    if len(jars) != 1:
        raise BundleError("the installation does not contain exactly one application JAR")
    jar = jars[0]
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
    ui_build = None
    with zipfile.ZipFile(jar) as archive:
        try:
            ui_build = json.loads(archive.read("decompengine/web/ui/asset-manifest.json")).get("buildId")
        except KeyError:
            pass
    return {"version": jar.name.removeprefix("llm-bin-patch-").removesuffix(".jar"),
            "applicationBuildId": digest, "uiBuildId": ui_build}


def java_version(environment: dict[str, str]) -> str:
    home = environment.get("JAVA_HOME")
    java = str(Path(home) / "bin/java") if home else shutil.which("java", path=environment.get("PATH"))
    if not java:
        return "java: not found\n"
    probe = {name: value for name, value in environment.items() if name not in JVM_OPTION_VARIABLES}
    try:
        result = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=30, env=probe)
    except (OSError, subprocess.TimeoutExpired) as failure:
        return f"java: unavailable ({type(failure).__name__})\n"
    # Keep version facts only; any other line (including echoed options) is dropped.
    return "".join(f"{line}\n" for line in result.stderr.splitlines() if JAVA_VERSION_LINE.fullmatch(line.strip()))


def doctor(install: Path, environment: dict[str, str]) -> str:
    try:
        result = subprocess.run([str(install / "bin/llm_bin_patch"), "doctor", "--tools-only"],
                                capture_output=True, text=True, timeout=300, env=environment)
    except (OSError, subprocess.TimeoutExpired) as failure:
        return f"doctor: unavailable ({type(failure).__name__})\n"
    lines = [line for line in (result.stdout + result.stderr).splitlines() if DOCTOR_LINE.fullmatch(line)]
    return "".join(f"{line}\n" for line in lines) + f"exit status: {result.returncode}\n"


def storage(data_dir: Path) -> dict:
    if not data_dir.is_dir():
        return {"present": False}
    jobs = files = directories = total = pending = staging = symlinks = 0
    locks: set[str] = set()
    schemas: dict[str, int] = {}
    entries = 0
    for current, names, filenames in os.walk(data_dir, followlinks=False):
        here = Path(current)
        for name in list(names):
            entries += 1
            if (here / name).is_symlink():
                symlinks += 1
                names.remove(name)
                continue
            directories += 1
            if here == data_dir and JOB_NAME.fullmatch(name):
                jobs += 1
            if here == data_dir and not JOB_NAME.fullmatch(name):
                staging += 1
        for name in filenames:
            entries += 1
            path = here / name
            if path.is_symlink():
                symlinks += 1
                continue
            files += 1
            total += path.lstat().st_size
            # Only the application's own owner locks are named; other filenames are never copied.
            if name in OWNER_LOCKS and here == data_dir:
                locks.add(name)
            if "pending" in name:
                pending += 1
            if name == "workflow-state.json" and here.parent == data_dir and path.lstat().st_size <= 4 * 1024 * 1024:
                try:
                    version = json.loads(path.read_bytes()).get("schemaVersion")
                except (ValueError, AttributeError, OSError):
                    version = "unreadable"
                schemas[str(version)] = schemas.get(str(version), 0) + 1
        if entries > MAX_STORAGE_ENTRIES:
            return {"present": True, "complete": False, "reason": "entry limit reached"}
    return {"present": True, "complete": True, "jobDirectories": jobs, "otherTopLevelDirectories": staging,
            "regularFiles": files, "directories": directories, "symlinks": symlinks, "logicalBytes": total,
            "pendingRecords": pending, "ownerLocks": sorted(locks), "workflowStateSchemaVersions": schemas}


def request_lines(log: Path) -> str:
    if log.stat().st_size > MAX_LOG_BYTES:
        raise BundleError("the server log exceeds the 64 MiB collection bound; pass a recent excerpt")
    lines = []
    for line in log.read_text(errors="replace").splitlines():
        match = REQUEST_LINE.fullmatch(line.strip())
        if match:
            lines.append(match.group(0))
    return "".join(f"{line}\n" for line in lines[-1000:])


def runtime(reply: Path) -> dict:
    document = json.loads(reply.read_text())
    data = document.get("data", document)
    capabilities = [{key: capability.get(key) for key in ("id", "state", "reasonCode")}
                    for capability in data.get("capabilities", []) if isinstance(capability, dict)]
    source = data.get("runtime") or {}
    return {
        "applicationBuildId": data.get("applicationBuildId"),
        "uiBuildId": data.get("uiBuildId"),
        "apiVersions": data.get("apiVersions"),
        "basePath": data.get("basePath"),
        "readiness": data.get("readiness"),
        "capabilities": capabilities,
        "limits": data.get("limits"),
        "runtime": {key: source.get(key) for key in ("javaVersion", "osName", "architecture", "gitVersion", "scheduler", "progressRetention")},
    }


def scan(bundle: Path, forbidden: list[str]) -> None:
    patterns = [re.compile(r"#bootstrap=|bootstrap=[A-Za-z0-9_-]{16,}"), re.compile(r"decomp_session_[0-9a-f]{16}"),
                re.compile(r"csrfToken", re.IGNORECASE)]
    for path in bundle.iterdir():
        text = path.read_text(errors="replace")
        for value in forbidden:
            if value and value != "/" and value in text:
                raise BundleError(f"{path.name} would expose a host path or secret value")
        for pattern in patterns:
            if pattern.search(text):
                raise BundleError(f"{path.name} would expose a session credential")


def collect(install: Path, output: Path, data_dir: Path | None, log: Path | None, reply: Path | None,
            environment: dict[str, str], run_doctor: bool = True) -> Path:
    install = install.resolve()
    secrets = secret_values(environment)
    paths = [str(install), str(Path.home()), str(REPOSITORY), str(Path.cwd())]
    if data_dir is not None:
        paths.append(str(data_dir.resolve()))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle = output / f"support-bundle-{stamp}"
    bundle.mkdir(parents=True)
    try:
        included = ["distribution.json", "java.txt"]
        (bundle / "distribution.json").write_text(json.dumps(distribution(install), indent=2, sort_keys=True) + "\n")
        (bundle / "java.txt").write_text(redact(java_version(environment), paths, secrets))
        if run_doctor:
            (bundle / "doctor.txt").write_text(redact(doctor(install, environment), paths, secrets))
            included.append("doctor.txt")
        if data_dir is not None:
            (bundle / "storage.json").write_text(json.dumps(storage(data_dir), indent=2, sort_keys=True) + "\n")
            included.append("storage.json")
        if log is not None:
            (bundle / "requests.txt").write_text(request_lines(log))
            included.append("requests.txt")
        if reply is not None:
            (bundle / "runtime.json").write_text(redact(json.dumps(runtime(reply), indent=2, sort_keys=True), paths, secrets, other_paths=False) + "\n")
            included.append("runtime.json")
        (bundle / "README.txt").write_text(
            "Redacted decomp_engine web support bundle.\n"
            f"Included: {', '.join(included)}.\n"
            "Excluded by design: uploaded binaries, job directories, reports, source, archives, the launcher's\n"
            "session link, cookies, CSRF tokens, environment values and host paths.\n"
            "Review every file before sharing it.\n")
        scan(bundle, paths + secrets)
    except Exception:
        shutil.rmtree(bundle, ignore_errors=True)
        raise
    return bundle


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--install", type=Path, default=REPOSITORY / "build/install/llm_bin_patch",
                        help="installed distribution root (contains bin/ and lib/)")
    parser.add_argument("--output", type=Path, default=REPOSITORY / "build/support")
    parser.add_argument("--data-dir", type=Path, help="the server's --data-dir; only counts are collected")
    parser.add_argument("--server-log", type=Path, help="captured server stderr; only request-failure lines are kept")
    parser.add_argument("--runtime-json", type=Path, help="a saved /api/v1/session or /api/v1/bootstrap reply")
    parser.add_argument("--no-doctor", action="store_true", help="skip `doctor --tools-only`")
    arguments = parser.parse_args(argv)
    try:
        bundle = collect(arguments.install, arguments.output, arguments.data_dir, arguments.server_log,
                         arguments.runtime_json, dict(os.environ), run_doctor=not arguments.no_doctor)
    except (BundleError, OSError, ValueError) as failure:
        print(f"support bundle not written: {failure}", file=sys.stderr)
        return 1
    print(bundle)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
