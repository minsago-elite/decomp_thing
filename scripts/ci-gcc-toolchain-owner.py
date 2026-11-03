#!/usr/bin/env python3
"""Fail-closed lifecycle owner for the GCC native-builder CI candidate.

The command line exposes only fixed lifecycle verbs. Tests construct an Owner with
an authored adapter; production never accepts an adapter or arbitrary command from
its environment.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
from typing import Protocol

MAX_JOURNAL = 1024 * 1024
MAX_CONTROL = 32 * 1024 * 1024
MAX_FILES = 128
TRANSITIONS = {
    "reserved": {"launch-intent", "sealed", "released"},
    "launch-intent": {"domain-reserved", "sealed"},
    "domain-reserved": {"child-gated", "sealed"},
    "child-gated": {"exec-observed", "sealed"},
    "exec-observed": {"ready", "sealed"},
    "ready": {"sealed"},
    "sealed": {"stopped"},
    "stopped": {"absence-proved"},
    "absence-proved": {"released"},
    "released": set(),
}


class Refusal(RuntimeError):
    pass


class Backend(Protocol):
    def manager_reserve(self, role: str, manifest: dict) -> dict: ...
    def manager_gate(self, role: str, manifest: dict) -> dict: ...
    def manager_stop(self, role: str, receipt: dict, timeout: float) -> dict: ...
    def domain_empty(self, role: str, receipt: dict, timeout: float) -> bool: ...
    def release_volume(self, manifest: dict, timeout: float) -> dict: ...


@dataclasses.dataclass
class ProductionBackend:
    """The manager adapter deliberately fails closed until capabilities are proven."""
    def manager_reserve(self, role: str, manifest: dict) -> dict:
        require_capabilities()
        raise Refusal("transient manager receipt adapter is not available on this host")

    def manager_gate(self, role: str, manifest: dict) -> dict:
        raise Refusal("manager gate has no authenticated reservation receipt")

    def manager_stop(self, role: str, receipt: dict, timeout: float) -> dict:
        raise Refusal("manager stop has no authenticated reservation receipt")

    def domain_empty(self, role: str, receipt: dict, timeout: float) -> bool:
        raise Refusal("domain absence is unknown without privileged manager receipt")

    def release_volume(self, manifest: dict, timeout: float) -> dict:
        raise Refusal("scratch release is unknown without mount and loop receipts")


def require_capabilities() -> None:
    cgroup = Path("/sys/fs/cgroup")
    try:
        if not (cgroup / "cgroup.controllers").is_file():
            raise Refusal("unified cgroup v2 is unavailable")
        controllers = set((cgroup / "cgroup.controllers").read_text().split())
        if not {"memory", "pids"}.issubset(controllers):
            raise Refusal("memory/pids cgroup controllers are unavailable")
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise Refusal("pidfd operations are unavailable")
        if not (cgroup / "cgroup.kill").exists():
            raise Refusal("cgroup.kill is unavailable")
    except OSError as exc:
        raise Refusal(f"cannot inspect cgroup capabilities: {exc}") from exc


def canonical_root(repo: Path, run_id: str, attempt: str, job: str, revision: str) -> Path:
    root = repo.resolve(strict=True)
    name_material = "\0".join((run_id, attempt, job, revision, str(root))).encode()
    short = hashlib.sha256(name_material).hexdigest()[:8]
    return root / "build" / "g" / short


def atomic_json(path: Path, value: dict, *, limit: int = MAX_JOURNAL) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > limit:
        raise Refusal("bounded JSON record exceeds limit")
    tmp = path.with_name(path.name + ".tmp-" + secrets.token_hex(6))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as out:
            out.write(raw)
            out.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class Owner:
    def __init__(self, root: Path, backend: Backend | None = None, *, clock=time.monotonic):
        self.root = root
        self.backend = backend or ProductionBackend()
        self.clock = clock
        self.manifest_path = root / "owner.json"
        self.journal_path = root / "journal.jsonl"

    def _manifest(self) -> dict:
        try:
            st = self.manifest_path.lstat()
            if not self.manifest_path.is_file() or self.manifest_path.is_symlink() or st.st_size > MAX_JOURNAL:
                raise Refusal("missing, linked, or oversized owner manifest")
            data = json.loads(self.manifest_path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise Refusal("owner manifest is missing or corrupt") from exc
        if data.get("schema") != 1 or data.get("root") != str(self.root.resolve()):
            raise Refusal("owner manifest root/schema mismatch")
        return data

    def _event(self, manifest: dict, state: str, **facts) -> None:
        prior_state = manifest["state"]
        if state not in TRANSITIONS.get(prior_state, set()):
            raise Refusal(f"illegal owner transition {prior_state} -> {state}")
        sequence = manifest["sequence"] + 1
        event = {"sequence": sequence, "from": prior_state, "state": state,
                 "ownerToken": manifest["ownerToken"], "monotonic": self.clock(), **facts}
        encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
        existing = self.journal_path.read_bytes() if self.journal_path.exists() else b""
        if len(existing) + len(encoded) > MAX_JOURNAL:
            raise Refusal("owner journal budget exceeded")
        fd = os.open(self.journal_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)
        manifest["sequence"] = sequence
        manifest["state"] = state
        atomic_json(self.manifest_path, manifest)

    def reserve(self, identity: dict, socket_paths: list[str]) -> dict:
        if self.root.exists() or self.root.is_symlink():
            raise Refusal("exclusive owner root already exists")
        for item in socket_paths:
            if len(os.fsencode(item)) > 107:
                raise Refusal("generated Unix socket path exceeds 107 bytes")
        self.root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.mkdir(self.root, 0o700)
        for child in ("control", "evidence"):
            os.mkdir(self.root / child, 0o700)
        owner = {"schema": 1, "ownerToken": secrets.token_hex(16), "root": str(self.root.resolve()),
                 "identity": identity, "state": "reserved", "sequence": 0,
                 "roles": {"buildkit": {"status": "never-launched"}, "rootless": {"status": "never-launched"}},
                 "socketPaths": socket_paths, "createdMonotonic": self.clock()}
        atomic_json(self.manifest_path, owner)
        event = {"sequence": 1, "from": "absent", "state": "reserved",
                 "ownerToken": owner["ownerToken"], "monotonic": self.clock(),
                 "identitySha256": hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()}
        fd = os.open(self.journal_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        owner["sequence"] = 1
        atomic_json(self.manifest_path, owner)
        return owner

    def begin_role(self, role: str, argv: list[str], env: dict[str, str], budgets: dict) -> dict:
        if role not in ("buildkit", "rootless") or not argv or not budgets:
            raise Refusal("invalid fixed role launch request")
        manifest = self._manifest()
        if manifest["state"] not in ("reserved", "ready"):
            raise Refusal("owner is sealed or has unresolved earlier launch")
        identity = {"argv": argv, "env": env, "budgets": budgets, "ownerToken": manifest["ownerToken"]}
        if any("\x00" in x for x in argv) or any("\x00" in k + v for k, v in env.items()):
            raise Refusal("NUL in launch vector")
        manifest["roles"][role] = {"status": "launch-intent", "intent": identity}
        self._event(manifest, "launch-intent", role=role, intentSha256=hashlib.sha256(
            json.dumps(identity, sort_keys=True).encode()).hexdigest())
        receipt = self.backend.manager_reserve(role, manifest)
        if not self._valid_receipt(receipt, manifest, role):
            raise Refusal("manager reservation receipt does not bind owner/role/domain")
        manifest["roles"][role].update({"status": "domain-reserved", "receipt": receipt})
        self._event(manifest, "domain-reserved", role=role, receipt=receipt)
        gate = self.backend.manager_gate(role, manifest)
        if not self._valid_receipt(gate, manifest, role):
            raise Refusal("manager child-gate receipt mismatch")
        manifest["roles"][role]["status"] = "child-gated"
        self._event(manifest, "child-gated", role=role, gate=gate)
        manifest["roles"][role]["status"] = "exec-observed"
        self._event(manifest, "exec-observed", role=role, exec=gate.get("exec"))
        return manifest

    @staticmethod
    def _valid_receipt(receipt: dict, manifest: dict, role: str) -> bool:
        return isinstance(receipt, dict) and receipt.get("ownerToken") == manifest["ownerToken"] \
            and receipt.get("role") == role and receipt.get("unit") and receipt.get("controlGroup") \
            and receipt.get("device") is not None and receipt.get("inode") is not None

    def ready(self, role: str, facts: dict) -> None:
        manifest = self._manifest()
        record = manifest["roles"].get(role, {})
        if record.get("status") != "exec-observed" or not facts.get("pidfd") or not facts.get("identity"):
            raise Refusal("readiness requires pinned pidfd and authenticated executable identity")
        record["status"] = "ready"
        self._event(manifest, "ready", role=role, facts=facts)

    def seal_stop(self, role: str, *, timeout: float = 180.0) -> dict:
        start = self.clock()
        deadline = start + min(max(timeout, 0.001), 180.0)
        manifest = self._manifest()
        role_record = manifest["roles"].get(role)
        if not isinstance(role_record, dict):
            raise Refusal("role is not present in owner manifest")
        if manifest["state"] not in ("sealed", "stopped", "absence-proved"):
            self._event(manifest, "sealed", role=role, reason="finalization")
        role_record["sealed"] = True
        if role_record.get("status") == "never-launched":
            if manifest["state"] == "sealed":
                self._event(manifest, "stopped", role=role, neverLaunched=True)
                self._event(manifest, "absence-proved", role=role, neverLaunched=True)
            return manifest
        receipt = role_record.get("receipt")
        if not receipt:
            role_record["status"] = "quarantined-unknown"
            raise Refusal("launch intent lacks manager receipt; absence is unknown")
        remaining = max(0.001, deadline - self.clock())
        result = self.backend.manager_stop(role, receipt, min(5.0, remaining))
        if result.get("ownerToken") != manifest["ownerToken"] or result.get("role") != role:
            raise Refusal("manager stop receipt does not match pinned owner")
        if self.clock() >= deadline:
            raise Refusal("shared teardown deadline expired during manager stop")
        remaining = max(0.001, deadline - self.clock())
        if not self.backend.domain_empty(role, receipt, min(5.0, remaining)):
            role_record["status"] = "quarantined-unknown"
            raise Refusal("owned cgroup/descendant absence is unknown")
        role_record["status"] = "absence-proved"
        role_record["stopReceipt"] = result
        if manifest["state"] == "sealed":
            self._event(manifest, "stopped", role=role, stopReceipt=result)
            self._event(manifest, "absence-proved", role=role, cgroupEmpty=True)
        return manifest

    def stage_upload(self, *, success: bool) -> Path:
        manifest = self._manifest()
        if manifest["state"] != "absence-proved":
            raise Refusal("upload staging requires complete process absence proof")
        out = self.root / "control" / "upload-manifest.json"
        base = self.root / ("evidence" if success else "control")
        budget = 13 * 1024**3 if success else 32 * 1024**2
        files: list[dict] = []
        total = 0
        for path in sorted(base.iterdir()):
            st = path.lstat()
            if path.is_symlink() or not path.is_file():
                raise Refusal("upload input is not a regular owned file")
            if path == out:
                continue
            total += st.st_size
            if total > budget or len(files) >= MAX_FILES:
                raise Refusal("bounded upload manifest budget exceeded")
            files.append({"path": str(path.relative_to(self.root)), "bytes": st.st_size,
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        atomic_json(out, {"files": files, "bytes": total, "success": success}, limit=4 * 1024 * 1024)
        return out

    def release(self, timeout: float = 60.0) -> None:
        manifest = self._manifest()
        if manifest["state"] != "absence-proved":
            raise Refusal("scratch release requires complete absence receipt")
        result = self.backend.release_volume(manifest, min(timeout, 60.0))
        if result.get("released") is not True or result.get("ownerToken") != manifest["ownerToken"]:
            raise Refusal("scratch release is unknown; retain quarantine")
        self._event(manifest, "released", release=result)


def cli() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("verb", choices=("reserve", "provision", "launch-buildkit", "launch-rootless",
        "status", "seal", "stop", "stage-upload", "release", "supervisor"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--role", choices=("buildkit", "rootless"))
    parser.add_argument("--success", action="store_true")
    args = parser.parse_args()
    owner = Owner(args.root)
    try:
        if args.verb in ("reserve", "provision"):
            paths = [str(args.root / suffix) for suffix in ("d.sock", "b.sock", "r/api.sock",
                "x/containerd/containerd.sock", "x/containerd/containerd.sock.ttrpc", "t/runc-console.sock")]
            owner.reserve({"run": os.environ.get("GITHUB_RUN_ID", "local"),
                "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"), "job": os.environ.get("GITHUB_JOB", "local"),
                "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()}, paths)
        elif args.verb == "status":
            print(json.dumps(owner._manifest(), sort_keys=True))
        elif args.verb == "seal" and args.role:
            manifest = owner._manifest()
            owner._event(manifest, "sealed", role=args.role, reason="explicit seal")
        elif args.verb == "stop" and args.role:
            owner.seal_stop(args.role)
        elif args.verb == "stage-upload":
            print(owner.stage_upload(success=args.success))
        elif args.verb == "release":
            owner.release()
        else:
            raise Refusal("requested fixed manager action lacks a verified production adapter")
    except (Refusal, OSError, subprocess.SubprocessError) as exc:
        print(f"gcc-owner: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
