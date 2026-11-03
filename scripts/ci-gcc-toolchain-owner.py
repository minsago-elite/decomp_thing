#!/usr/bin/env python3
"""Fail-closed lifecycle owner for the GCC native-builder CI candidate.

The command line exposes only fixed lifecycle verbs. Tests construct an Owner with
an authored adapter; production never accepts an adapter or arbitrary command from
its environment.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import math
import os
import re
import select
import selectors
import stat
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
import tomllib
from typing import Any, Protocol

MAX_JOURNAL = 1024 * 1024
MAX_CONTROL = 32 * 1024 * 1024
MAX_FILES = 128
# The authenticated dockerd member is 99,870,816 bytes; identity reads remain finite.
MAX_EXECUTABLE_IDENTITY_BYTES = 128 * 1024 * 1024
PINNED_TOOL_HASHES = {
    "rootlesskit": "98f07e783dd6b3cd236c7865d1dce7937e645ec74a0fe2971725449af074f466",
    "dockerd": "c3ecdc8ac9e56b9a53ffd9fd4aece65432814597046f8d188a538be18c000df8",
}
TRANSITIONS = {
    "reserved": {"launch-intent", "sealed", "released"},
    "launch-intent": {"domain-reserved", "sealed"},
    "domain-reserved": {"child-gated", "sealed"},
    "child-gated": {"exec-observed", "sealed"},
    "exec-observed": {"ready", "sealed"},
    "ready": {"launch-intent", "sealed"},
    "sealed": {"stopped"},
    "stopped": {"absence-proved"},
    "absence-proved": {"launch-intent", "released"},
    "released": set(),
}


class Refusal(RuntimeError):
    pass


class Backend(Protocol):
    def manager_reserve(self, role: str, manifest: dict) -> dict: ...
    def manager_prepare_gate(self, role: str, manifest: dict) -> dict: ...
    def manager_gate(self, role: str, manifest: dict) -> dict: ...
    def manager_stop(self, role: str, receipt: dict, timeout: float) -> dict: ...
    def domain_empty(self, role: str, receipt: dict, timeout: float) -> bool: ...
    def release_domains(self, manifest: dict, timeout: float) -> dict: ...


class CommandRunner:
    """Deadline and output-bounded runner for fixed manager/authority executables."""
    ALLOWED = {"/usr/bin/busctl", "/usr/bin/systemctl", "/usr/bin/sudo", "/usr/bin/python3",
               "/usr/bin/git", "/usr/sbin/apparmor_parser", "/usr/bin/cat"}

    def __init__(self, *, clock=time.monotonic, output_limit: int = 1024 * 1024,
                 tool_root: Path | None = None):
        self.clock = clock
        self.output_limit = output_limit
        self.tool_root = tool_root.resolve(strict=True) if tool_root and tool_root.exists() else None

    def run(self, argv: list[str], timeout: float, *, input_data: bytes | None = None,
            env: dict[str, str] | None = None) -> tuple[int, bytes, bytes]:
        try:
            allowed_tool = bool(self.tool_root and Path(argv[0]).is_absolute() and
                Path(argv[0]).resolve(strict=True).is_relative_to(self.tool_root) and
                Path(argv[0]).is_file() and os.access(argv[0], os.X_OK)) if argv else False
        except OSError:
            allowed_tool = False
        if not argv or (argv[0] not in self.ALLOWED and not allowed_tool) or \
                any(not isinstance(a, str) or "\0" in a for a in argv):
            raise Refusal("external command is outside the fixed argv allowlist")
        if timeout <= 0 or timeout > 30:
            raise Refusal("external command deadline must be in (0, 30] seconds")
        if input_data is not None:
            raise Refusal("fixed manager commands do not accept stdin payloads")
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise Refusal("bounded command runner requires pidfd signal support")
        deadline = self.clock() + timeout
        soft_deadline = deadline - min(2.0, timeout / 2)
        clean = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        if env:
            for key, value in env.items():
                if key not in {"XDG_RUNTIME_DIR", "DOCKER_CONFIG"} or "\0" in value:
                    raise Refusal("manager command environment is not allowlisted")
                clean[key] = value
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean, close_fds=True,
            start_new_session=True)
        try:
            pidfd = os.pidfd_open(process.pid, 0)
        except OSError as exc:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                raise Refusal("fixed command started but pidfd pinning failed; state is unknown") from exc
            raise Refusal("fixed command started but could not be pinned by pidfd") from exc
        selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        outputs = {"stdout": bytearray(), "stderr": bytearray()}
        def terminate_bounded(reason: str) -> None:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as exc:
                raise Refusal(f"cannot terminate pinned fixed-command pidfd: {exc}") from exc
            try:
                process.wait(timeout=min(0.75, max(0.01, deadline - self.clock())))
            except subprocess.TimeoutExpired:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    raise Refusal(f"cannot kill pinned fixed-command pidfd: {exc}") from exc
                try:
                    process.wait(timeout=min(0.75, max(0.01, deadline - self.clock())))
                except subprocess.TimeoutExpired as exc:
                    raise Refusal("fixed command was not reaped within its deadline") from exc
            raise Refusal(reason)
        try:
            while selector.get_map() or process.poll() is None:
                remaining = soft_deadline - self.clock()
                if remaining <= 0:
                    terminate_bounded("fixed manager command deadline expired")
                for key, _ in selector.select(min(0.1, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    target = outputs[key.data]
                    if sum(map(len, outputs.values())) + len(chunk) > self.output_limit:
                        terminate_bounded("fixed manager command output exceeded byte cap")
                    target.extend(chunk)
            status = process.wait(timeout=max(0.01, deadline - self.clock()))
            return status, bytes(outputs["stdout"]), bytes(outputs["stderr"])
        finally:
            selector.close()
            if process.poll() is None:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=1)
            os.close(pidfd)


class LinuxAuthority:
    """Privileged fixed-purpose cgroup inspection and cgroup.kill adapter."""
    def __init__(self, runner: CommandRunner, *, script: Path, python: str = "/usr/bin/python3"):
        self.runner = runner
        self.script = script.resolve(strict=True)
        self.python = "/usr/bin/python3"

    def _call(self, verb: str, root: Path, role: str, timeout: float) -> dict:
        argv = ["/usr/bin/sudo", "-n", self.python, str(self.script), verb,
                "--owner-root", str(root), "--role", role]
        status, out, err = self.runner.run(argv, min(5.0, timeout))
        if status != 0:
            raise Refusal(f"privileged {verb} refused: {err[:2048].decode(errors='replace')}")
        try:
            value = json.loads(out)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Refusal(f"privileged {verb} returned malformed receipt") from exc
        if not isinstance(value, dict):
            raise Refusal(f"privileged {verb} returned non-object receipt")
        return value

    def capabilities(self, root: Path, role: str, timeout: float) -> dict:
        cgroup = Path("/sys/fs/cgroup")
        try:
            controllers_path = cgroup / "cgroup.controllers"
            controllers = controllers_path.read_text().split()
            unified = controllers_path.is_file() and cgroup.is_dir()
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError as exc:
            raise Refusal(f"cannot inspect cgroup-v2 capabilities: {exc}") from exc
        user_manager = False
        if role == "rootless":
            runtime = Path(f"/run/user/{os.getuid()}")
            user_manager = (runtime.is_dir() and not runtime.is_symlink() and
                (runtime / "bus").is_socket())
        # cgroup.events and cgroup.kill are not exposed on the hierarchy root.
        # Their availability is authenticated against the owned slice after
        # systemd creates it, before the gated supervisor can start.
        return {"unified": unified, "controllers": controllers,
                "bootId": boot_id, "userManager": user_manager}

    def inspect(self, root: Path, role: str, timeout: float) -> dict:
        return self._call("_inspect-domain", root, role, timeout)

    def kill(self, root: Path, role: str, timeout: float) -> dict:
        return self._call("_kill-domain", root, role, timeout)


class ProductionBackend:
    def __init__(self, root: Path, *, runner: CommandRunner | None = None,
                 authority: LinuxAuthority | None = None, clock=time.monotonic,
                 fixture_tool_hashes: dict[str, str] | None = None,
                 test_repo_root: Path | None = None):
        self.root = root
        self.clock = clock
        self.test_repo_root = test_repo_root
        if fixture_tool_hashes is not None and set(fixture_tool_hashes) != set(PINNED_TOOL_HASHES):
            raise Refusal("authored fixture tool profile has an unexpected key set")
        self.tool_hashes = fixture_tool_hashes or PINNED_TOOL_HASHES
        self.runner = runner or CommandRunner(clock=clock, tool_root=root / "v" / "tools")
        self.authority = authority or LinuxAuthority(self.runner,
            script=Path(__file__).resolve(), python=sys.executable if sys.executable.startswith("/") else "/usr/bin/python3")

    def _run(self, role: str, args: list[str], timeout: float) -> bytes:
        manager = manager_identity(role)
        argv = ["/usr/bin/busctl", "--json=short", f"--timeout={max(1, int(timeout))}s"]
        if manager == "user":
            argv.append("--user")
        else:
            argv = ["/usr/bin/sudo", "-n", *argv, "--system"]
        if manager == "user":
            runtime = f"/run/user/{os.getuid()}"
            env = {"XDG_RUNTIME_DIR": runtime}
        else:
            env = None
        # ExecStart arguments are D-Bus data, including launcher options such as env -i.
        status, out, err = self.runner.run(argv + ["--"] + args, min(5.0, timeout), env=env)
        if status != 0:
            raise Refusal(f"{manager} systemd manager call failed: {err[:2048].decode(errors='replace')}")
        return out

    def _show(self, role: str, unit: str, timeout: float = 5.0) -> dict[str, str]:
        manager = manager_identity(role)
        argv = ["/usr/bin/systemctl"]
        if manager == "user":
            argv.append("--user")
        else:
            argv += ["--system"]
        argv += ["show", "--no-pager", "--full",
                 "--property=Id,Description,ActiveState,SubState,InvocationID,ControlGroup,Slice", unit]
        env = ({"XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"} if manager == "user" else None)
        status, out, err = self.runner.run(argv, min(5.0, timeout), env=env)
        if status != 0:
            raise Refusal(f"cannot read exact transient unit receipt: {err[:2048].decode(errors='replace')}")
        return parse_systemd_unit_properties(out)

    @staticmethod
    def _busctl_property(name: str, signature: str, *values: str) -> list[str]:
        return [name, signature, *values]

    @staticmethod
    def _busctl_object_path(payload: bytes, prefix: str, operation: str) -> str:
        try:
            result = json.loads(payload)
            data = result["data"]
            if result.get("type") != "o" or not isinstance(data, list) or len(data) != 1 or \
                    not isinstance(data[0], str) or not data[0].startswith(prefix):
                raise ValueError("unexpected object-path reply")
            return data[0]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise Refusal(f"systemd {operation} returned a malformed object path") from exc

    def _start_transient(self, role: str, unit: str, properties: list[list[str]], timeout: float) -> str:
        flattened = [v for prop in properties for v in prop]
        args = ["call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager", "StartTransientUnit", "ssa(sv)a(sa(sv))",
                unit, "fail", str(len(properties)), *flattened, "0"]
        out = self._run(role, args, timeout)
        return self._busctl_object_path(out, "/org/freedesktop/systemd1/job/", "StartTransientUnit")

    def _get_unit_object_path(self, role: str, unit: str) -> str:
        args = ["call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager", "GetUnit", "s", unit]
        return self._busctl_object_path(self._run(role, args, 5),
            "/org/freedesktop/systemd1/unit/", "GetUnit")

    def _systemd_version(self, role: str) -> int:
        manager = manager_identity(role)
        argv = ["/usr/bin/systemctl", "--user" if manager == "user" else "--system", "--version"]
        env = ({"XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"} if manager == "user" else None)
        status, out, err = self.runner.run(argv, 5, env=env)
        if status != 0:
            raise Refusal(f"existing {manager} systemd manager is unavailable: {err[:1024]!r}")
        first = out.decode("ascii", "strict").splitlines()[0].split()
        if len(first) < 2 or first[0] != "systemd" or not first[1].isdigit():
            raise Refusal("systemd version output is malformed")
        version = int(first[1])
        if version < 255:
            raise Refusal("systemd >=255 is required for the admitted transient-unit properties")
        return version

    def _stop_unit(self, role: str, unit: str, timeout: float) -> None:
        args = ["call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager", "StopUnit", "ss", unit, "fail"]
        self._run(role, args, timeout)

    def _facts(self, role: str, unit: str, description: str) -> dict[str, str]:
        facts = self._show(role, unit)
        if facts["id"] != unit or facts["description"] != description or not facts["controlGroup"]:
            raise Refusal("transient unit identity does not bind the reserved owner")
        return facts

    def _await_service_active(self, role: str, unit: str, description: str,
                              slice_name: str, deadline: float) -> dict[str, str]:
        """Observe this start request within its original budget; never re-enqueue it."""
        observed: dict[str, str] = {}
        while True:
            remaining = deadline - self.clock()
            if remaining <= 0:
                break
            facts = self._show(role, unit, min(5.0, remaining))
            if self.clock() >= deadline:
                break
            if facts["id"] != unit or facts["description"] != description or facts["slice"] != slice_name:
                raise Refusal("starting service identity does not bind the reserved owner")
            for field in ("invocation", "controlGroup"):
                if field in observed and observed[field] != facts[field]:
                    raise Refusal("starting service generation or cgroup changed")
                if facts[field]:
                    observed[field] = facts[field]
            if facts["active"] == "active":
                if facts["sub"] not in ("start", "running") or not facts["invocation"] or not facts["controlGroup"]:
                    raise Refusal("active owner supervisor has incomplete execution identity")
                return facts
            if facts["active"] != "activating" or facts["sub"] != "start":
                raise Refusal("gated owner supervisor did not enter its expected start state")
            time.sleep(min(0.025, max(0.0, deadline - self.clock())))
        raise Refusal("gated owner supervisor activation deadline expired")

    def manager_reserve(self, role: str, manifest: dict) -> dict:
        token = manifest.get("ownerToken")
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token):
            raise Refusal("owner token is invalid")
        capabilities = require_capabilities(self.authority, self.root, role)
        version = self._systemd_version(role)
        if role == "rootless":
            self._load_rootless_profile(manifest)
        slice_name, service_name = unit_names(role, token)
        description = f"decomp-gcc-owner:{token}:{role}"
        props_slice = [
            self._busctl_property("Description", "s", description),
            self._busctl_property("MemoryMax", "t", str(4 * 1024**3)),
            self._busctl_property("MemorySwapMax", "t", "0"),
            self._busctl_property("TasksMax", "t", "1024"),
        ]
        # The fail mode prevents adopting a stale transient unit with the same
        # random name; the description and InvocationID are rechecked below.
        slice_job = self._start_transient(role, slice_name, props_slice, 5)
        slice_facts = self._facts(role, slice_name, description)
        if slice_facts["active"] != "active":
            raise Refusal("transient owned slice did not become active")
        script = str(Path(__file__).resolve())
        supervisor_argv = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C",
            "HOME=/root" if role == "buildkit" else f"HOME=/run/user/{os.getuid()}",
            "/usr/bin/python3", script, "supervisor", "--owner-root", str(self.root), "--role", role]
        exec_values = ["1", supervisor_argv[0], str(len(supervisor_argv)), *supervisor_argv, "false"]
        props_service = [
            self._busctl_property("Description", "s", description),
            self._busctl_property("Slice", "s", slice_name),
            self._busctl_property("Type", "s", "exec"),
            self._busctl_property("RemainAfterExit", "b", "true"),
            self._busctl_property("Restart", "s", "no"),
            self._busctl_property("KillMode", "s", "control-group"),
            self._busctl_property("SendSIGKILL", "b", "true"),
            self._busctl_property("TimeoutStartUSec", "t", "60000000"),
            self._busctl_property("TimeoutStopUSec", "t", "25000000"),
            self._busctl_property("RuntimeMaxUSec", "t", str((1800 if role == "buildkit" else 10800) * 1000000)),
            self._busctl_property("Delegate", "b", "true"),
            self._busctl_property("DelegateSubgroup", "s", "control"),
            self._busctl_property("WorkingDirectory", "s", str(repository_root())),
            self._busctl_property("PrivateMounts", "b", "true" if role == "buildkit" else "false"),
            self._busctl_property("ExecStart", "a(sasb)", *exec_values),
        ]
        service_deadline = self.clock() + 5
        service_job = self._start_transient(role, service_name, props_service, 5)
        service_facts = self._await_service_active(role, service_name, description,
                                                  slice_name, service_deadline)
        if service_facts["slice"] != slice_name:
            raise Refusal("service was not placed in the exact owned slice")
        slice_object = self._get_unit_object_path(role, slice_name)
        service_object = self._get_unit_object_path(role, service_name)
        probe = {"ownerToken": token, "role": role, "manager": manager_identity(role),
            "systemdVersion": version, "slice": slice_name, "unit": service_name,
            "description": description, "invocationId": service_facts["invocation"],
            "sliceInvocationId": slice_facts["invocation"],
            "controlGroup": service_facts["controlGroup"],
            "sliceControlGroup": slice_facts["controlGroup"], "sliceJobPath": slice_job,
            "serviceJobPath": service_job, "sliceObjectPath": slice_object,
            "serviceObjectPath": service_object, "capabilities": capabilities}
        atomic_json(self.root / "control" / f"manager-receipt-{role}.json", probe)
        inspected = self.authority.inspect(self.root, role, 5)
        require_domain_receipt(inspected, slice_facts, service_facts, token, role)
        if role == "buildkit":
            bind_buildkit_config(self.root, service_facts["controlGroup"],
                                 manifest["identity"]["ownerUid"], manifest["identity"]["ownerGid"])
        receipt = {"ownerToken": token, "role": role, "manager": manager_identity(role),
            "bootId": inspected["bootId"], "slice": slice_name, "unit": service_name,
            "description": description, "objectPath": service_object,
            "sliceObjectPath": slice_object, "sliceJobPath": slice_job, "serviceJobPath": service_job,
            "invocationId": service_facts["invocation"], "controlGroup": service_facts["controlGroup"],
            "sliceInvocationId": slice_facts["invocation"],
            "sliceControlGroup": slice_facts["controlGroup"], "device": inspected["sliceDevice"],
            "inode": inspected["sliceInode"], "serviceDevice": inspected["serviceDevice"],
            "serviceInode": inspected["serviceInode"], "effectiveLimits": inspected["limits"],
            "toolHashes": ({"rootlesskit": self.tool_hashes["rootlesskit"],
                            "dockerd": self.tool_hashes["dockerd"]} if role == "rootless" else {}),
            "cgroupReceipt": inspected}
        atomic_json(self.root / "control" / f"manager-receipt-{role}.json", receipt)
        return receipt

    def manager_prepare_gate(self, role: str, manifest: dict) -> dict:
        deadline = self.clock() + 5
        path = self.root / "control" / f"child-ready-{role}.json"
        if role == "rootless":
            try:
                loaded = read_json_bounded(self.root / "control" / "apparmor-loaded.json", 4096)
            except Refusal as exc:
                raise Refusal("RootlessKit AppArmor profile is not present at the release gate") from exc
            expected_name = f"decomp-gcc-owner-{manifest['ownerToken']}"
            if loaded.get("ownerToken") != manifest["ownerToken"] or loaded.get("name") != expected_name or \
                    expected_name not in self._profile_list(5):
                raise Refusal("exact RootlessKit AppArmor profile is not present at the release gate")
        while self.clock() < deadline:
            if path.exists():
                value = read_json_bounded(path, 16 * 1024)
                if value.get("ownerToken") != manifest["ownerToken"] or value.get("role") != role:
                    raise Refusal("blocked-child receipt identity mismatch")
                receipt = manifest.get("roles", {}).get(role, {}).get("receipt", {})
                if not value.get("pidfdHeld") or value.get("daemonCgroup") != \
                        str(receipt.get("controlGroup", "")).rstrip("/") + "/daemon":
                    raise Refusal("blocked child lacks pidfd or exact delegated cgroup receipt")
                self._verify_live_domain(role, manifest, populated=True)
                return value
            time.sleep(min(0.05, max(0, deadline - self.clock())))
        raise Refusal("gated supervisor did not publish blocked-child receipt")

    def manager_gate(self, role: str, manifest: dict) -> dict:
        self._verify_live_domain(role, manifest, populated=True)
        gate = self.root / "control" / f"gate-{role}.json"
        atomic_json(gate, {"ownerToken": manifest["ownerToken"], "role": role})
        deadline = self.clock() + 10
        path = self.root / "control" / f"exec-observed-{role}.json"
        while self.clock() < deadline:
            if path.exists():
                value = read_json_bounded(path, 32 * 1024)
                if value.get("ownerToken") != manifest["ownerToken"] or value.get("role") != role:
                    raise Refusal("exec identity receipt mismatch")
                expected = manifest["roles"][role]["receipt"]
                identity = value.get("identity")
                child = read_json_bounded(self.root / "control" / f"child-ready-{role}.json", 16 * 1024)
                expected_exe = (manifest["roles"][role]["intent"]["argv"][0] if role == "buildkit" else
                                str(self.root / "v" / "tools" / "docker-rootless-extras" / "rootlesskit"))
                if not value.get("pidfdHeld") or not isinstance(identity, dict) or \
                        identity.get("exe") != expected_exe or \
                        (role == "rootless" and identity.get("exeSha256") != expected["toolHashes"]["rootlesskit"]) or \
                        value.get("pid") != child.get("pid") or \
                        identity.get("startTicks") != child.get("identity", {}).get("startTicks") or \
                        value.get("daemonCgroup") != str(expected.get("controlGroup", "")).rstrip("/") + "/daemon":
                    raise Refusal("exec receipt does not bind pidfd, executable, and owned cgroup")
                if role == "rootless":
                    descendants = value.get("authenticatedDescendants")
                    if not isinstance(descendants, list) or len(descendants) != 1 or \
                            descendants[0].get("exe") != str(self.root / "v" / "tools" / "docker" / "dockerd") or \
                            descendants[0].get("exeSha256") != PINNED_TOOL_HASHES["dockerd"] or \
                            descendants[0].get("pidfdHeld") is not True or \
                            f"0::{value.get('daemonCgroup')}" not in descendants[0].get("cgroup", "").splitlines():
                        raise Refusal("stable RootlessKit receipt lacks the authenticated dockerd descendant")
                return {**expected, "exec": value}
            time.sleep(min(0.05, max(0, deadline - self.clock())))
        raise Refusal("gated child failed to publish exec identity")

    def _verify_live_domain(self, role: str, manifest: dict, *, populated: bool) -> None:
        receipt = manifest.get("roles", {}).get(role, {}).get("receipt")
        if not isinstance(receipt, dict) or receipt.get("ownerToken") != manifest.get("ownerToken"):
            raise Refusal("live domain check lacks immutable owner receipt")
        facts = self._show(role, receipt["unit"], 5)
        if facts["id"] != receipt["unit"] or facts["description"] != receipt["description"] or \
                facts["invocation"] != receipt["invocationId"] or facts["controlGroup"] != receipt["controlGroup"] or \
                facts["active"] != "active":
            raise Refusal("manager unit identity changed before child gate")
        inspected = self.authority.inspect(self.root, role, 5)
        if inspected.get("ownerToken") != manifest["ownerToken"] or inspected.get("role") != role or \
                inspected.get("bootId") != receipt.get("bootId") or \
                inspected.get("sliceDevice") != receipt.get("device") or \
                inspected.get("sliceInode") != receipt.get("inode") or \
                inspected.get("serviceDevice") != receipt.get("serviceDevice") or \
                inspected.get("serviceInode") != receipt.get("serviceInode") or \
                inspected.get("limits") != receipt.get("effectiveLimits") or \
                inspected.get("sliceControlGroup") != receipt.get("sliceControlGroup") or \
                inspected.get("serviceControlGroup") != receipt.get("controlGroup"):
            raise Refusal("privileged cgroup identity/limits changed before child gate")
        if populated and inspected.get("allDescendantsEmpty") is True:
            raise Refusal("reserved gated child is missing from its cgroup domain")

    def manager_stop(self, role: str, receipt: dict, timeout: float) -> dict:
        start = self.clock()
        deadline = min(start + max(0.001, timeout), start + 180)
        request = self.root / "control" / f"stop-request-{role}.json"
        if not request.exists():
            atomic_json(request, {"ownerToken": receipt["ownerToken"], "role": role,
                                 "deadlineMonotonic": deadline})
        stop_path = self.root / "control" / f"stop-receipt-{role}.json"
        # Preserve time for the privileged emergency cgroup kill even if the
        # supervisor is dead or cannot publish its clean-stop receipt.
        kill_reserve = min(5.0, max(0.001, (deadline - start) * 0.4))
        supervisor_deadline = deadline - kill_reserve
        while self.clock() < supervisor_deadline and not stop_path.exists():
            time.sleep(min(0.05, max(0, supervisor_deadline - self.clock())))
        child_path = self.root / "control" / f"child-ready-{role}.json"
        if not child_path.is_file():
            raise Refusal("missing blocked-child receipt; domain state is unknown")
        child_receipt = read_json_bounded(child_path, 16 * 1024)
        if child_receipt.get("ownerToken") != receipt["ownerToken"] or child_receipt.get("role") != role or \
                child_receipt.get("pidfdHeld") is not True:
            raise Refusal("blocked-child receipt is incomplete or belongs to another owner")
        owner_manifest = Owner(self.root, self, test_repo_root=self.test_repo_root)._manifest()
        role_state = owner_manifest.get("roles", {}).get(role, {}).get("status")
        if role_state in ("exec-observed", "ready", "quarantined-unknown"):
            exec_path = self.root / "control" / f"exec-observed-{role}.json"
            if not exec_path.is_file():
                raise Refusal("missing exec identity receipt after exec-observed state")
            exec_receipt = read_json_bounded(exec_path, 32 * 1024)
            if exec_receipt.get("ownerToken") != receipt["ownerToken"] or \
                    exec_receipt.get("role") != role or exec_receipt.get("pidfdHeld") is not True:
                raise Refusal("exec identity receipt is invalid during stop")
        stop_receipt = read_json_bounded(stop_path, 32 * 1024) if stop_path.is_file() else None
        if stop_receipt and (stop_receipt.get("ownerToken") != receipt["ownerToken"] or
                             stop_receipt.get("role") != role or not stop_receipt.get("pidfdHeld") or
                             not isinstance(stop_receipt.get("daemonEmpty"), bool)):
            raise Refusal("supervisor stop receipt does not bind the pinned child")
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise Refusal("overall teardown deadline expired before cgroup kill")
        killed = self.authority.kill(self.root, role, min(5.0, remaining))
        if killed.get("ownerToken") != receipt["ownerToken"] or killed.get("role") != role or killed.get("empty") is not True:
            raise Refusal("owned slice cgroup.kill receipt did not prove empty subtree")
        if stop_receipt is None:
            atomic_json(self.root / "control" / f"stop-emergency-kill-{role}.json",
                {"ownerToken": receipt["ownerToken"], "role": role,
                 "reason": "supervisor stop receipt missing", "killReceipt": killed}, limit=16 * 1024)
            raise Refusal("missing supervisor stop receipt after emergency cgroup.kill; quarantine required")
        return {"ownerToken": receipt["ownerToken"], "role": role, "manager": receipt["manager"],
                "bootId": receipt["bootId"], "unit": receipt["unit"], "slice": receipt["slice"],
                "invocationId": receipt["invocationId"], "preKillReceipt": stop_receipt,
                "killReceipt": killed, "cgroupEmpty": True}

    def domain_empty(self, role: str, receipt: dict, timeout: float) -> bool:
        if timeout <= 0:
            return False
        current = self.authority.inspect(self.root, role, min(5.0, timeout))
        if current.get("missing") is True:
            facts = self._show(role, receipt["slice"])
            return (facts["active"] == "inactive" and facts["invocation"] in ("", receipt.get("sliceInvocationId", ""))
                    and receipt.get("bootId") == current.get("bootId"))
        return (current.get("ownerToken") == receipt["ownerToken"] and current.get("role") == role and
                current.get("sliceDevice") == receipt["device"] and current.get("sliceInode") == receipt["inode"] and
                current.get("populated") == 0 and current.get("allDescendantsEmpty") is True)

    def release_domains(self, manifest: dict, timeout: float) -> dict:
        deadline = self.clock() + min(timeout, 60)
        released = []
        for role in ("buildkit", "rootless"):
            record = manifest["roles"].get(role, {})
            if record.get("status") == "never-launched" or record.get("neverLaunched") is True:
                released.append({"role": role, "neverLaunched": True})
                continue
            receipt = record.get("receipt")
            if not receipt or record.get("status") != "absence-proved":
                raise Refusal("cannot release manager domain without absence-proved receipt")
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise Refusal("manager-domain release deadline expired")
            empty = self.authority.inspect(self.root, role, min(5.0, remaining))
            if empty.get("ownerToken") != manifest["ownerToken"] or empty.get("allDescendantsEmpty") is not True:
                raise Refusal("owned cgroup ceased to be empty before manager release")
            self._stop_unit(role, receipt["unit"], min(5.0, deadline - self.clock()))
            service = self._show(role, receipt["unit"], min(5.0, deadline - self.clock()))
            if service["active"] not in ("inactive", "failed") or \
                    service["invocation"] not in ("", receipt["invocationId"]):
                raise Refusal("transient service did not stop with its original invocation")
            self._stop_unit(role, receipt["slice"], min(5.0, deadline - self.clock()))
            slice_facts = self._show(role, receipt["slice"], min(5.0, deadline - self.clock()))
            if slice_facts["active"] not in ("inactive", "failed") or \
                    slice_facts["invocation"] not in ("", receipt.get("sliceInvocationId", "")):
                raise Refusal("transient slice did not stop with its original invocation")
            released.append({"role": role, "slice": receipt["slice"], "inactive": True,
                             "serviceInvocationId": receipt["invocationId"],
                             "sliceInvocationId": receipt.get("sliceInvocationId"), "bootId": receipt["bootId"]})
        rootless_record = manifest.get("roles", {}).get("rootless", {})
        if rootless_record.get("status") != "never-launched" and rootless_record.get("neverLaunched") is not True:
            self._remove_rootless_profile(manifest, deadline)
            profile_receipt = read_json_bounded(self.root / "control" / "apparmor-absent.json", 4096)
            if profile_receipt.get("ownerToken") != manifest["ownerToken"] or profile_receipt.get("absent") is not True:
                raise Refusal("AppArmor absence receipt is missing or not bound to owner")
        else:
            profile_receipt = {"neverLoaded": True}
        return {"ownerToken": manifest["ownerToken"], "released": released,
                "apparmorAbsence": profile_receipt}

    def _profile_identity(self, manifest: dict) -> tuple[str, Path]:
        token = manifest.get("ownerToken", "")
        if not re.fullmatch(r"[0-9a-f]{32}", token):
            raise Refusal("invalid owner token for AppArmor profile")
        binary = self.root / "v" / "tools" / "docker-rootless-extras" / "rootlesskit"
        profile_path = self.root / "control" / f"apparmor-{token}.profile"
        if not binary.is_absolute() or not re.fullmatch(r"[A-Za-z0-9_./-]+", str(binary)):
            raise Refusal("RootlessKit path cannot be represented safely in the exact profile")
        if binary.resolve(strict=True) != binary or not binary.is_file() or not os.access(binary, os.X_OK):
            raise Refusal("authenticated RootlessKit executable is missing or linked")
        if _hash_file_bounded(binary, 64 * 1024 * 1024) != self.tool_hashes["rootlesskit"]:
            raise Refusal("RootlessKit executable differs from the sealed tool pin")
        return f"decomp-gcc-owner-{token}", profile_path

    def _profile_list(self, timeout: float) -> set[str]:
        status, out, err = self.runner.run(
            ["/usr/bin/sudo", "-n", "/usr/bin/cat", "/sys/kernel/security/apparmor/profiles"],
            min(5.0, timeout))
        if status != 0:
            raise Refusal(f"AppArmor profile readback failed: {err[:1024]!r}")
        if len(out) > 1024 * 1024:
            raise Refusal("AppArmor profile inventory exceeds read bound")
        try:
            return {line.split(" ", 1)[0] for line in out.decode("utf-8", "strict").splitlines() if line}
        except UnicodeDecodeError as exc:
            raise Refusal("AppArmor profile inventory is not UTF-8") from exc

    def _load_rootless_profile(self, manifest: dict) -> None:
        name, profile_path = self._profile_identity(manifest)
        if name in self._profile_list(5):
            raise Refusal("unique AppArmor profile name already exists; refusing replacement")
        binary = self.root / "v" / "tools" / "docker-rootless-extras" / "rootlesskit"
        content = ("abi <abi/4.0>,\ninclude <tunables/global>\n"
                   f'profile {name} "{binary}" flags=(unconfined) {{\n  userns,\n}}\n').encode()
        if profile_path.exists() or profile_path.is_symlink():
            raise Refusal("AppArmor profile file already exists")
        fd = os.open(profile_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if os.write(fd, content) != len(content):
                raise Refusal("short write creating owned AppArmor profile")
            os.fsync(fd)
        finally:
            os.close(fd)
        dfd = os.open(profile_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        profile_sha = hashlib.sha256(content).hexdigest()
        atomic_json(self.root / "control" / "apparmor-load-intent.json",
                    {"ownerToken": manifest["ownerToken"], "name": name,
                     "profile": str(profile_path), "executable": str(binary),
                     "profileSha256": profile_sha,
                     "executableSha256": self.tool_hashes["rootlesskit"]}, limit=4096)
        status, _, err = self.runner.run(
            ["/usr/bin/sudo", "-n", "/usr/sbin/apparmor_parser", "--add", "--skip-cache", str(profile_path)], 5)
        if status != 0:
            raise Refusal(f"owned AppArmor profile load failed or is ambiguous: {err[:1024]!r}")
        if name not in self._profile_list(5):
            raise Refusal("AppArmor profile load returned without exact kernel readback")
        atomic_json(self.root / "control" / "apparmor-loaded.json",
                    {"ownerToken": manifest["ownerToken"], "name": name,
                     "profile": str(profile_path), "executable": str(binary),
                     "profileSha256": profile_sha,
                     "executableSha256": self.tool_hashes["rootlesskit"]}, limit=4096)

    def _remove_rootless_profile(self, manifest: dict, deadline: float) -> None:
        intent_path = self.root / "control" / "apparmor-load-intent.json"
        if not intent_path.exists():
            raise Refusal("rootless profile load intent is missing; removal state is unknown")
        intent = read_json_bounded(intent_path, 4096)
        name, profile_path = self._profile_identity(manifest)
        expected_binary = self.root / "v" / "tools" / "docker-rootless-extras" / "rootlesskit"
        if intent.get("ownerToken") != manifest["ownerToken"] or intent.get("name") != name or \
                intent.get("profile") != str(profile_path) or intent.get("executable") != str(expected_binary) or \
                intent.get("executableSha256") != self.tool_hashes["rootlesskit"]:
            raise Refusal("AppArmor cleanup intent identity mismatch")
        loaded_path = self.root / "control" / "apparmor-loaded.json"
        if loaded_path.exists():
            loaded = read_json_bounded(loaded_path, 4096)
            if loaded.get("ownerToken") != manifest["ownerToken"] or loaded.get("name") != name or \
                    loaded.get("profileSha256") != intent.get("profileSha256") or \
                    loaded.get("executableSha256") != intent.get("executableSha256"):
                raise Refusal("AppArmor loaded receipt differs from durable load intent")
        try:
            profile_stat = profile_path.lstat()
            profile_bytes = profile_path.read_bytes()
        except OSError as exc:
            raise Refusal("owned AppArmor profile source is missing during cleanup") from exc
        profile_hash = hashlib.sha256(profile_bytes).hexdigest()
        if not stat.S_ISREG(profile_stat.st_mode) or profile_path.is_symlink() or \
                profile_stat.st_size > 4096 or profile_stat.st_uid != manifest["identity"]["ownerUid"] or \
                profile_hash != intent.get("profileSha256"):
            raise Refusal("owned AppArmor profile source changed after durable load intent")
        if name in self._profile_list(max(0.05, deadline - self.clock())):
            if not profile_path.is_file() or profile_path.is_symlink():
                raise Refusal("owned AppArmor profile source is unavailable for removal")
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise Refusal("AppArmor cleanup deadline expired")
            status, _, err = self.runner.run(
                ["/usr/bin/sudo", "-n", "/usr/sbin/apparmor_parser", "--remove", "--skip-cache", str(profile_path)],
                min(5.0, remaining))
            if status != 0:
                raise Refusal(f"owned AppArmor profile removal failed or is ambiguous: {err[:1024]!r}")
        if name in self._profile_list(max(0.05, deadline - self.clock())):
            raise Refusal("owned AppArmor profile remains present after removal")
        atomic_json(self.root / "control" / "apparmor-absent.json",
                    {"ownerToken": manifest["ownerToken"], "name": name, "absent": True,
                     "profileSha256": profile_hash}, limit=4096)


def manager_identity(role: str) -> str:
    if role == "buildkit":
        return "system"
    if role == "rootless":
        return "user"
    raise Refusal("unknown service role")


def unit_names(role: str, token: str) -> tuple[str, str]:
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise Refusal("invalid owner token for unit name")
    prefix = "dgb" if role == "buildkit" else "dgr" if role == "rootless" else None
    if prefix is None:
        raise Refusal("unknown service role")
    return f"{prefix}{token}.slice", f"{prefix}{token}-{role}.service"


SYSTEMD_UNIT_PROPERTIES = {
    "Id": "id", "Description": "description", "ActiveState": "active",
    "SubState": "sub", "InvocationID": "invocation", "ControlGroup": "controlGroup",
    "Slice": "slice",
}


def parse_systemd_unit_properties(payload: bytes) -> dict[str, str]:
    parsed = {}
    try:
        for line in payload.decode("utf-8", "strict").splitlines():
            name, separator, value = line.partition("=")
            if not separator or name not in SYSTEMD_UNIT_PROPERTIES or \
                    SYSTEMD_UNIT_PROPERTIES[name] in parsed:
                raise ValueError("unknown, malformed, or duplicate systemd property")
            parsed[SYSTEMD_UNIT_PROPERTIES[name]] = value
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refusal("systemd show receipt has malformed named properties") from exc
    if set(parsed) != set(SYSTEMD_UNIT_PROPERTIES.values()):
        raise Refusal("systemd show receipt is missing a required named property")
    return parsed


def query_manager_unit(role: str, owner_uid: int, owner_gid: int, unit: str) -> dict[str, str]:
    manager = manager_identity(role)
    argv = ["/usr/bin/systemctl", "--user" if manager == "user" else "--system",
            "show", "--no-pager", "--full",
            "--property=Id,Description,ActiveState,SubState,InvocationID,ControlGroup,Slice", unit]
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    if manager == "user":
        env["XDG_RUNTIME_DIR"] = f"/run/user/{owner_uid}"
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, close_fds=True, timeout=3, check=False,
            user=owner_uid if manager == "user" else 0,
            group=owner_gid if manager == "user" else 0,
            extra_groups=[])
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as exc:
        raise Refusal("cannot query current systemd unit identity in privileged cleanup") from exc
    if result.returncode != 0 or len(result.stdout) > 16 * 1024 or len(result.stderr) > 4096:
        raise Refusal("current systemd unit query failed or exceeded its output bound")
    return parse_systemd_unit_properties(result.stdout)


def require_manager_reservation_binding(receipt: dict, role: str, manifest: dict,
                                       slice_facts: dict[str, str],
                                       service_facts: dict[str, str], *, teardown: bool = False) -> None:
    token = manifest.get("ownerToken")
    expected_slice, expected_service = unit_names(role, token)
    description = f"decomp-gcc-owner:{token}:{role}"
    if receipt.get("ownerToken") != token or receipt.get("role") != role or \
            receipt.get("manager") != manager_identity(role) or receipt.get("slice") != expected_slice or \
            receipt.get("unit") != expected_service or receipt.get("description") != description:
        raise Refusal("manager receipt does not bind the fixed owner reservation")
    if slice_facts.get("id") != expected_slice or slice_facts.get("description") != description or \
            slice_facts.get("active") != "active" or not slice_facts.get("controlGroup") or \
            not slice_facts.get("invocation"):
        raise Refusal("current systemd slice identity does not bind the owner reservation")
    # Teardown can follow supervisor failure; launch/readiness still requires an active service.
    service_states = ("active", "failed") if teardown else ("active",)
    if service_facts.get("id") != expected_service or service_facts.get("description") != description or \
            service_facts.get("slice") != expected_slice or service_facts.get("active") not in service_states or \
            not service_facts.get("controlGroup") or not service_facts.get("invocation"):
        raise Refusal("current systemd service identity does not bind the owner reservation")
    if receipt.get("sliceControlGroup") != slice_facts["controlGroup"] or \
            receipt.get("controlGroup") != service_facts["controlGroup"] or \
            receipt.get("sliceInvocationId") != slice_facts["invocation"] or \
            receipt.get("invocationId") != service_facts["invocation"]:
        raise Refusal("manager receipt target differs from current systemd unit identity")


def require_capabilities(authority: LinuxAuthority, root: Path, role: str) -> dict:
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise Refusal("pidfd open/send-signal operations are unavailable")
    caps = authority.capabilities(root, role, 5)
    if caps.get("unified") is not True:
        raise Refusal("unified cgroup v2 is required")
    if not {"memory", "pids"}.issubset(set(caps.get("controllers", []))):
        raise Refusal("memory and pids controllers are required")
    if role == "rootless" and caps.get("userManager") is not True:
        raise Refusal("an existing authenticated user manager is required")
    return caps


def require_cgroup_kill(directory_fd: int) -> None:
    """Require the writable cgroup.kill control on an authenticated owned cgroup."""
    try:
        fd = os.open("cgroup.kill", os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    except OSError as exc:
        raise Refusal("owned cgroup lacks a writable cgroup.kill control") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refusal("owned cgroup.kill control is not a regular kernel control file")
    finally:
        os.close(fd)


def read_json_bounded(path: Path, limit: int) -> dict:
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or path.is_symlink() or st.st_size > limit:
            raise Refusal("receipt is linked, nonregular, or oversized")
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal("receipt is missing or malformed") from exc
    if not isinstance(value, dict):
        raise Refusal("receipt is not a JSON object")
    return value


def require_domain_receipt(inspected: dict, slice_facts: dict, service_facts: dict,
                           token: str, role: str) -> None:
    if inspected.get("ownerToken") != token or inspected.get("role") != role:
        raise Refusal("privileged cgroup census is not bound to owner and role")
    if inspected.get("bootId") != inspected.get("currentBootId"):
        raise Refusal("manager/cgroup receipt crosses a boot identity")
    if inspected.get("sliceControlGroup") != slice_facts.get("controlGroup") or \
            inspected.get("serviceControlGroup") != service_facts.get("controlGroup"):
        raise Refusal("manager ControlGroup differs from privileged cgroup census")
    if not str(service_facts.get("controlGroup", "")).startswith(
            str(slice_facts.get("controlGroup", "")) + "/"):
        raise Refusal("service ControlGroup is outside its reserved slice")
    if inspected.get("sliceDevice") is None or inspected.get("sliceInode") is None or \
            inspected.get("serviceDevice") is None or inspected.get("serviceInode") is None:
        raise Refusal("cgroup device/inode identity is incomplete")
    limits = inspected.get("limits")
    if limits != {"memory.max": str(4 * 1024**3), "memory.swap.max": "0", "pids.max": "1024"}:
        raise Refusal("effective owned slice limits differ from sealed request")


def _read_proc_identity(pid: int) -> dict:
    """Read process identity from the supervisor's own authority context."""
    try:
        raw_stat = Path(f"/proc/{pid}/stat").read_text()
        close = raw_stat.rfind(")")
        fields = raw_stat[close + 2:].split()
        parent_pid = int(fields[1])
        start_ticks = int(fields[19])
        exe = os.stat(f"/proc/{pid}/exe")
        exe_path = os.readlink(f"/proc/{pid}/exe")
        status = Path(f"/proc/{pid}/status").read_text()
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        uid = int(uid_line.split()[1])
        cgroup = Path(f"/proc/{pid}/cgroup").read_text()
        namespaces = {name: os.stat(f"/proc/{pid}/ns/{name}").st_ino
                      for name in ("mnt", "pid", "user", "net", "ipc", "uts")}
    except (OSError, ValueError, StopIteration, IndexError) as exc:
        raise Refusal(f"process identity for pinned child {pid} is unknown") from exc
    if exe.st_size > MAX_EXECUTABLE_IDENTITY_BYTES:
        raise Refusal("admitted executable exceeds identity hash budget")
    digest = hashlib.sha256()
    observed = 0
    try:
        with open(f"/proc/{pid}/exe", "rb", buffering=0) as executable:
            while True:
                block = executable.read(min(1024 * 1024, MAX_EXECUTABLE_IDENTITY_BYTES - observed + 1))
                if not block:
                    break
                observed += len(block)
                if observed > MAX_EXECUTABLE_IDENTITY_BYTES:
                    raise Refusal("admitted executable exceeds identity hash budget")
                digest.update(block)
            if observed != exe.st_size:
                raise Refusal("admitted executable size changed during identity hashing")
    except OSError as exc:
        raise Refusal("cannot hash the admitted child executable") from exc
    return {"pid": pid, "parentPid": parent_pid, "startTicks": start_ticks, "uid": uid, "exe": exe_path,
            "exeDevice": exe.st_dev, "exeInode": exe.st_ino, "exeSha256": digest.hexdigest(),
            "cgroup": cgroup, "namespaces": namespaces}


def _fixed_child(manifest: dict, role: str) -> tuple[list[str], dict[str, str], str, str]:
    record = manifest.get("roles", {}).get(role, {})
    intent = record.get("intent")
    if not isinstance(intent, dict):
        raise Refusal("supervisor has no durable launch intent")
    argv, env = intent.get("argv"), intent.get("env")
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        raise Refusal("supervisor launch vector is malformed")
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        raise Refusal("supervisor environment is malformed")
    root = Path(manifest["root"])
    executable = Path(argv[0])
    admitted = {root / "v" / "tools" / "buildkit" / "bin" / "buildkitd",
                root / "v" / "tools" / "docker-rootless-extras" / "dockerd-rootless.sh"}
    if not executable.is_absolute() or executable not in admitted or \
            (role == "buildkit" and executable.name != "buildkitd") or \
            (role == "rootless" and executable.name != "dockerd-rootless.sh"):
        raise Refusal("supervisor executable is outside the fixed role allowlist")
    if executable.resolve(strict=True) != executable or executable.is_symlink():
        raise Refusal("supervisor executable is linked or missing")
    launcher_hash = _hash_file_bounded(executable, 64 * 1024 * 1024)
    if launcher_hash != intent.get("launcherSha256"):
        raise Refusal("launch executable differs from durable tool hash")
    if role == "buildkit":
        expected_exe = str(executable)
        expected_sha = launcher_hash
    else:
        expected_exe = str(root / "v" / "tools" / "docker-rootless-extras" / "rootlesskit")
        expected_sha = PINNED_TOOL_HASHES["rootlesskit"]
    rootless_tools = root / "v" / "tools" / "docker-rootless-extras"
    # The pinned rootless launcher invokes sysctl by name through nsenter.
    # Its trusted host location is /usr/sbin; keep this addition role-local.
    safe_env = {"PATH": (f"{rootless_tools}:{root}/v/tools/docker:/usr/bin:/bin:/usr/sbin"
                         if role == "rootless" else "/usr/bin:/bin"),
                "LANG": "C", "LC_ALL": "C"}
    if role == "rootless":
        safe_env["DOCKERD"] = str(root / "v" / "tools" / "docker" / "dockerd")
        safe_env["DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR"] = str(root / "r")
    for key, value in env.items():
        if key not in {"HOME", "XDG_RUNTIME_DIR", "DOCKER_CONFIG", "DOCKERD",
                       "DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR"} or "\0" in value:
            raise Refusal("supervisor environment contains an unapproved variable")
        if key in {"DOCKERD", "DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR"} and \
                value != safe_env.get(key):
            raise Refusal("rootless wrapper path override differs from the authenticated bundle")
        safe_env[key] = value
    if any(key.startswith("DOCKER_") and key not in ("DOCKER_CONFIG", "DOCKERD") for key in env):
        raise Refusal("ambient Docker endpoint override is forbidden")
    return argv, safe_env, expected_exe, expected_sha


def _hash_file_bounded(path: Path, limit: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb", buffering=0) as source:
        while True:
            chunk = source.read(min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise Refusal("tool hash input exceeds fixed byte bound")
            digest.update(chunk)
    return digest.hexdigest()


def stable_exec_identity(role: str, identity: dict, expected_exe: str, expected_sha256: str,
                         original_start_ticks: int) -> bool:
    """Pure admission predicate for the final pidfd-pinned executable identity."""
    if role not in ("buildkit", "rootless") or not isinstance(identity, dict):
        return False
    return (identity.get("startTicks") == original_start_ticks and
            identity.get("exe") == expected_exe and identity.get("exeSha256") == expected_sha256 and
            isinstance(identity.get("uid"), int) and isinstance(identity.get("exeDevice"), int) and
            isinstance(identity.get("exeInode"), int) and isinstance(identity.get("namespaces"), dict) and
            isinstance(identity.get("cgroup"), str))


def await_stable_exec(inspect: Any, alive: Any, role: str, expected_exe: str,
                      expected_sha256: str, start_ticks: int, *, deadline: float,
                      clock=time.monotonic, sleep=time.sleep) -> dict:
    last = None
    while clock() < deadline:
        last = inspect()
        if not alive():
            raise Refusal("pidfd-pinned launch exited before stable executable identity")
        if stable_exec_identity(role, last, expected_exe, expected_sha256, start_ticks):
            return last
        sleep(min(0.025, max(0.0, deadline - clock())))
    raise Refusal("authenticated stable executable was not observed before deadline")


def _read_thread_group_children(parent: int, task_budget: int) -> tuple[list[int], int]:
    """Bounded candidate union, not an atomic process snapshot or absence proof."""
    if task_budget <= 0 or task_budget > 1024:
        raise Refusal("RootlessKit task census exceeds fixed task budget")
    children: set[int] = set()
    tasks_seen = 0
    byte_count = 0
    try:
        with os.scandir(f"/proc/{parent}/task") as tasks:
            for task in tasks:
                if tasks_seen >= task_budget:
                    raise Refusal("RootlessKit task census exceeds fixed task budget")
                if not re.fullmatch(r"[1-9][0-9]{0,19}", task.name) or not task.is_dir(follow_symlinks=False):
                    raise Refusal("RootlessKit task directory is malformed")
                tasks_seen += 1
                raw = bytearray()
                with open(f"/proc/{parent}/task/{task.name}/children", "rb", buffering=0) as source:
                    while True:
                        block = source.read(4096 - byte_count + 1)
                        if not block:
                            break
                        byte_count += len(block)
                        if byte_count > 4096:
                            raise Refusal("RootlessKit child list exceeds bound")
                        raw.extend(block)
                for item in raw.split():
                    if not re.fullmatch(rb"[1-9][0-9]{0,19}", item):
                        raise Refusal("RootlessKit child list is malformed")
                    children.add(int(item))
                    if len(children) > 256:
                        raise Refusal("RootlessKit descendant census exceeds fixed node budget")
    except OSError as exc:
        raise Refusal("RootlessKit child tree is inaccessible") from exc
    if tasks_seen == 0:
        raise Refusal("RootlessKit task census is empty")
    return sorted(children), tasks_seen


def _find_authenticated_dockerd(rootlesskit_pid: int, root: Path, cgroup: str, deadline: float, *,
                                rootlesskit_pidfd: int) -> tuple[int, int, dict]:
    expected = root / "v" / "tools" / "docker" / "dockerd"
    expected_sha = PINNED_TOOL_HASHES["dockerd"]
    root_poller = select.poll()
    root_poller.register(rootlesskit_pidfd, select.POLLIN)
    while time.monotonic() < deadline:
        if root_poller.poll(0):
            raise Refusal("pinned RootlessKit exited during descendant discovery")
        stack = [(rootlesskit_pid, 0)]
        seen: set[int] = set()
        tasks_seen = 0
        observing_descendant = False
        try:
            while stack:
                parent, depth = stack.pop()
                if depth >= 8 or parent in seen:
                    continue
                seen.add(parent)
                # Go launchers can create children from any thread, not just the group leader.
                observing_descendant = parent != rootlesskit_pid
                children, task_count = _read_thread_group_children(parent, 1024 - tasks_seen)
                tasks_seen += task_count
                if len(seen) + len(children) > 256:
                    raise Refusal("RootlessKit descendant census exceeds fixed node budget")
                for pid in children:
                    observing_descendant = True
                    child = _read_proc_identity(pid)
                    if child["parentPid"] != parent or child["uid"] != os.getuid() or \
                            child["cgroup"].splitlines().count(f"0::{cgroup}") != 1:
                        raise Refusal("RootlessKit descendant escaped parent or owned cgroup")
                    if child["exe"] == str(expected) and child["exeSha256"] == expected_sha:
                        first = os.pidfd_open(pid, 0)
                        try:
                            pinned = _read_proc_identity(pid)
                            poller = select.poll()
                            poller.register(first, select.POLLIN)
                            if pinned["startTicks"] != child["startTicks"] or \
                                    pinned["exeDevice"] != child["exeDevice"] or pinned["exeInode"] != child["exeInode"] or \
                                    pinned["parentPid"] != parent or pinned["cgroup"] != child["cgroup"] or \
                                    pinned["uid"] != child["uid"] or pinned["namespaces"] != child["namespaces"] or \
                                    poller.poll(0):
                                raise Refusal("dockerd identity changed during pidfd acquisition")
                            if root_poller.poll(0):
                                raise Refusal("pinned RootlessKit exited during descendant discovery")
                        except BaseException:
                            os.close(first)
                            raise
                        return pid, first, pinned
                    stack.append((pid, depth + 1))
        except (Refusal, ProcessLookupError) as exc:
            # A disappearing setup descendant invalidates this whole candidate pass.
            # Root census, permission, malformed, ancestry and generation failures still refuse.
            cause = exc.__cause__ if isinstance(exc, Refusal) else exc
            if not observing_descendant or not isinstance(cause, OSError) or \
                    cause.errno not in (errno.ENOENT, errno.ESRCH):
                raise
        time.sleep(min(0.025, max(0.0, deadline - time.monotonic())))
    raise Refusal("authenticated dockerd descendant was not observed before the exec deadline")


def supervisor_main(root: Path, role: str) -> None:
    """Fixed transient-unit supervisor; child execution is gated until receipt."""
    owner = Owner(root)
    manifest = owner._manifest()
    token = manifest["ownerToken"]
    receipt_path = root / "control" / f"manager-receipt-{role}.json"
    receipt_deadline = time.monotonic() + 5
    manager_receipt = {}
    while time.monotonic() < receipt_deadline:
        if receipt_path.exists():
            manager_receipt = read_json_bounded(receipt_path, 65536)
            if manager_receipt.get("device") is not None and manager_receipt.get("inode") is not None:
                break
        time.sleep(0.025)
    if manager_receipt.get("ownerToken") != token or manager_receipt.get("role") != role:
        raise Refusal("supervisor manager receipt is missing or belongs to another owner")
    argv, env, expected_exe, expected_sha = _fixed_child(manifest, role)
    service_cgroup = manager_receipt.get("controlGroup")
    slice_cgroup = manager_receipt.get("sliceControlGroup")
    if not isinstance(service_cgroup, str) or not isinstance(slice_cgroup, str) or \
            not service_cgroup.startswith(slice_cgroup.rstrip("/") + "/"):
        raise Refusal("supervisor cgroup receipt is outside its reserved slice")
    if role == "buildkit":
        if os.geteuid() != 0:
            raise Refusal("rootful BuildKit supervisor did not run with privileged identity")
        config = root / "v" / "s" / "buildkitd.toml"
        try:
            st = config.lstat()
            if not stat.S_ISREG(st.st_mode) or config.is_symlink() or st.st_size > 32 * 1024:
                raise Refusal("BuildKit config is linked, nonregular, or oversized")
            with config.open("rb") as source:
                parsed = tomllib.loads(source.read(32 * 1024 + 1).decode("utf-8", "strict"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise Refusal("BuildKit delegated config is missing or malformed") from exc
        worker = parsed.get("worker", {}).get("oci", {})
        if worker.get("defaultCgroupParent") != service_cgroup.rstrip("/") + "/daemon":
            raise Refusal("BuildKit defaultCgroupParent is not the exact owned daemon subtree")
    elif os.geteuid() != manifest["identity"]["ownerUid"]:
        raise Refusal("rootless supervisor identity differs from owned runner user")
    service_fd = _open_cgroup_path(service_cgroup)
    try:
        daemon_name = "daemon"
        try:
            os.mkdir(daemon_name, 0o700, dir_fd=service_fd)
        except FileExistsError as exc:
            raise Refusal("daemon child cgroup already exists") from exc
        daemon_fd = os.open(daemon_name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=service_fd)
    finally:
        os.close(service_fd)
    if role == "buildkit":
        libc = ctypes.CDLL(None, use_errno=True)
        ms_rec = 16384
        ms_private = 1 << 18
        if libc.mount(None, b"/", None, ms_rec | ms_private, None) != 0:
            os.close(daemon_fd)
            raise Refusal("cannot make rootful supervisor mount propagation recursively private")
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    exec_read, exec_write = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(gate_write)
            os.close(exec_read)
            # Parent death must not leave a detached child outside the manager.
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG")
            if os.getppid() == 1:
                raise Refusal("supervisor died before child gate")
            if os.read(gate_read, 1) != b"1":
                raise Refusal("supervisor closed the child gate without release")
            os.close(gate_read)
            os.execve(argv[0], argv, env)
        except BaseException as exc:
            try:
                os.write(exec_write, (type(exc).__name__ + ":" + str(exc)).encode()[:1024])
            except OSError:
                pass
            os._exit(127)
    os.close(gate_read)
    os.close(exec_write)
    pidfd = None
    dockerd_pidfd = None
    try:
        pidfd = os.pidfd_open(pid, 0)
        before = _read_proc_identity(pid)
        if before["uid"] != os.getuid():
            raise Refusal("gated child effective uid differs from supervisor identity")
        procs_fd = os.open("cgroup.procs", os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=daemon_fd)
        try:
            payload = str(pid).encode()
            if os.write(procs_fd, payload) != len(payload):
                raise Refusal("short write moving gated child into daemon cgroup")
        finally:
            os.close(procs_fd)
        before = _read_proc_identity(pid)
        expected_cgroup = service_cgroup.rstrip("/") + "/daemon"
        if f"0::{expected_cgroup}" not in before["cgroup"].splitlines():
            raise Refusal("blocked child did not enter its exact delegated daemon cgroup")
        atomic_json(root / "control" / f"child-ready-{role}.json",
            {"ownerToken": token, "role": role, "pid": pid, "pidfdHeld": True,
             "identity": before, "daemonCgroup": expected_cgroup}, limit=16 * 1024,
            owner=(manifest["identity"]["ownerUid"], manifest["identity"]["ownerGid"]))
        gate_path = root / "control" / f"gate-{role}.json"
        deadline = time.monotonic() + min(float(manifest["roles"][role]["intent"]["budgets"].get("gateSeconds", 10)), 30)
        while time.monotonic() < deadline and not gate_path.exists():
            if select.poll:
                poller = select.poll()
                poller.register(pidfd, select.POLLIN)
                if poller.poll(0):
                    raise Refusal("gated child exited before release")
            time.sleep(0.025)
        gate = read_json_bounded(gate_path, 4096)
        if gate.get("ownerToken") != token or gate.get("role") != role:
            raise Refusal("child release gate token mismatch")
        if os.write(gate_write, b"1") != 1:
            raise Refusal("short supervisor gate release")
        os.close(gate_write)
        gate_write = None
        deadline = time.monotonic() + 10
        selector = selectors.DefaultSelector()
        selector.register(exec_read, selectors.EVENT_READ)
        message = bytearray()
        while time.monotonic() < deadline:
            events = selector.select(min(0.1, deadline - time.monotonic()))
            if not events:
                continue
            chunk = os.read(exec_read, 2048)
            if not chunk:
                break
            message.extend(chunk)
        selector.close()
        if message:
            raise Refusal("gated exec failed: " + message.decode(errors="replace"))
        def child_pidfd_alive() -> bool:
            poller = select.poll()
            poller.register(pidfd, select.POLLIN)
            return not bool(poller.poll(0))
        after = await_stable_exec(lambda: _read_proc_identity(pid), child_pidfd_alive, role,
            expected_exe, expected_sha, before["startTicks"], deadline=deadline)
        if after["uid"] != os.getuid() or f"0::{expected_cgroup}" not in after["cgroup"].splitlines():
            raise Refusal("stable role executable escaped its admitted identity or delegated cgroup")
        exec_receipt = {"ownerToken": token, "role": role, "pid": pid,
            "pidfdHeld": True, "identity": after, "daemonCgroup": service_cgroup.rstrip("/") + "/daemon"}
        if role == "rootless":
            dockerd_pid, dockerd_pidfd, dockerd_identity = _find_authenticated_dockerd(
                pid, root, expected_cgroup, min(deadline, time.monotonic() + 10), rootlesskit_pidfd=pidfd)
            exec_receipt["authenticatedDescendants"] = [{**dockerd_identity,
                "pidfdHeld": True}]
        atomic_json(root / "control" / f"exec-observed-{role}.json", exec_receipt, limit=32 * 1024,
                    owner=(manifest["identity"]["ownerUid"], manifest["identity"]["ownerGid"]))
        stop_path = root / "control" / f"stop-request-{role}.json"
        stop_deadline = time.monotonic() + min(float(manifest["roles"][role]["intent"]["budgets"].get("runtimeSeconds", 1800)), 10800)
        while time.monotonic() < stop_deadline and not stop_path.exists():
            poller = select.poll()
            poller.register(pidfd, select.POLLIN)
            if poller.poll(100):
                # An early clean process exit is recorded; absence still needs
                # the privileged manager's complete descendant census.
                break
        if stop_path.exists():
            request = read_json_bounded(stop_path, 4096)
            if request.get("ownerToken") != token or request.get("role") != role:
                raise Refusal("stop request token mismatch")
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as exc:
                raise Refusal(f"pidfd TERM failed; process state unknown: {exc}") from exc
            if dockerd_pidfd is not None:
                try:
                    signal.pidfd_send_signal(dockerd_pidfd, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    raise Refusal(f"dockerd pidfd TERM failed; process state unknown: {exc}") from exc
            grace_deadline = min(time.monotonic() + 20, float(request.get("deadlineMonotonic", time.monotonic())))
            while time.monotonic() < grace_deadline:
                poller = select.poll()
                poller.register(pidfd, select.POLLIN)
                if poller.poll(100):
                    break
        daemon_empty, nodes = _tree_empty(daemon_fd, deadline=time.monotonic() + 5)
        atomic_json(root / "control" / f"stop-receipt-{role}.json",
            {"ownerToken": token, "role": role, "daemonEmpty": daemon_empty,
             "pidfdHeld": True, "cgroupNodes": nodes}, limit=32 * 1024,
            owner=(manifest["identity"]["ownerUid"], manifest["identity"]["ownerGid"]))
    finally:
        if gate_write is not None:
            os.close(gate_write)
        os.close(exec_read)
        if pidfd is not None:
            os.close(pidfd)
        if dockerd_pidfd is not None:
            os.close(dockerd_pidfd)
        os.close(daemon_fd)


def _read_fd_text(parent_fd: int, name: str, cap: int = 4096) -> str:
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    try:
        chunks = bytearray()
        while len(chunks) <= cap:
            block = os.read(fd, min(1024, cap + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > cap:
            raise Refusal("cgroup control file exceeds read bound")
        return chunks.decode("ascii", "strict")
    finally:
        os.close(fd)


def _open_cgroup_path(control_group: str) -> int:
    if not isinstance(control_group, str) or not control_group.startswith("/") or \
            "\x00" in control_group or ".." in Path(control_group).parts:
        raise Refusal("manager ControlGroup path is malformed")
    root_fd = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    current_fd = root_fd
    try:
        for part in Path(control_group).parts:
            if part in ("/", ""):
                continue
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current_fd)
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
        os.close(root_fd)
        return current_fd
    except BaseException:
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)
        raise


def _populated(fd: int) -> int:
    rows = {}
    for line in _read_fd_text(fd, "cgroup.events").splitlines():
        fields = line.split()
        if len(fields) == 2:
            rows[fields[0]] = fields[1]
    if rows.get("populated") not in ("0", "1"):
        raise Refusal("cgroup.events lacks a valid populated field")
    return int(rows["populated"])


class KernelCgroupIO:
    """Fixed cgroup-v2 operations; tests inject an in-memory implementation."""
    def verify(self, path: str, device: int, inode: int) -> None:
        fd = _open_cgroup_path(path)
        try:
            current = os.fstat(fd)
            if current.st_dev != device or current.st_ino != inode:
                raise Refusal("owned cgroup device/inode changed")
        finally:
            os.close(fd)

    def write_control(self, path: str, name: str, value: bytes, device: int, inode: int) -> None:
        fd = _open_cgroup_path(path)
        try:
            current = os.fstat(fd)
            if current.st_dev != device or current.st_ino != inode:
                raise Refusal("owned cgroup identity changed before control write")
            control_fd = os.open(name, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            try:
                if os.write(control_fd, value) != len(value):
                    raise Refusal(f"short {name} write")
            finally:
                os.close(control_fd)
        finally:
            os.close(fd)

    def frozen(self, path: str, device: int, inode: int) -> bool:
        fd = _open_cgroup_path(path)
        try:
            current = os.fstat(fd)
            if current.st_dev != device or current.st_ino != inode:
                raise Refusal("owned cgroup identity changed during freeze")
            rows = {}
            for line in _read_fd_text(fd, "cgroup.events").splitlines():
                fields = line.split()
                if len(fields) != 2:
                    raise Refusal("malformed cgroup.events during freeze")
                rows[fields[0]] = fields[1]
            if rows.get("frozen") not in ("0", "1"):
                raise Refusal("cgroup.events lacks frozen state")
            return rows["frozen"] == "1"
        finally:
            os.close(fd)

    def empty(self, path: str, device: int, inode: int, deadline: float) -> bool:
        fd = _open_cgroup_path(path)
        try:
            current = os.fstat(fd)
            if current.st_dev != device or current.st_ino != inode:
                raise Refusal("owned cgroup identity changed during absence check")
            empty, _ = _tree_empty(fd, deadline=deadline)
            return empty
        finally:
            os.close(fd)


def freeze_kill_prove(io: Any, path: str, device: int, inode: int, *, timeout: float,
                      clock=time.monotonic, sleep=time.sleep) -> dict:
    deadline = clock() + min(max(timeout, 0.001), 5.0)
    try:
        io.verify(path, device, inode)
        io.write_control(path, "cgroup.freeze", b"1", device, inode)
    except OSError as exc:
        raise Refusal(f"owned cgroup freeze was denied or unknown: {exc}") from exc
    while clock() < deadline:
        try:
            if io.frozen(path, device, inode):
                break
        except OSError as exc:
            raise Refusal(f"owned cgroup frozen state is unknown: {exc}") from exc
        sleep(min(0.05, max(0, deadline - clock())))
    else:
        raise Refusal("owned cgroup subtree did not freeze before deadline")
    try:
        io.verify(path, device, inode)
        io.write_control(path, "cgroup.kill", b"1", device, inode)
    except OSError as exc:
        raise Refusal(f"owned cgroup kill was denied or unknown: {exc}") from exc
    while clock() < deadline:
        try:
            if io.empty(path, device, inode, deadline):
                return {"device": device, "inode": inode, "frozen": True, "empty": True}
        except OSError as exc:
            raise Refusal(f"owned cgroup absence is unknown: {exc}") from exc
        sleep(min(0.05, max(0, deadline - clock())))
    raise Refusal("owned cgroup subtree did not become empty before deadline")


def _tree_empty(fd: int, *, deadline: float, budget: int = 10000) -> tuple[bool, int]:
    stack = [os.dup(fd)]
    visited = 0
    empty = True
    try:
        while stack:
            if time.monotonic() >= deadline:
                raise Refusal("cgroup descendant census deadline expired")
            current = stack.pop()
            visited += 1
            if visited > budget:
                raise Refusal("cgroup descendant census exceeded node budget")
            if _populated(current) != 0:
                empty = False
            for name in os.listdir(current):
                if name in (".", ".."):
                    continue
                try:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
                except NotADirectoryError:
                    continue
                stack.append(child)
            os.close(current)
        return empty, visited
    finally:
        for fd_left in stack:
            os.close(fd_left)


def inspect_domain_local(root: Path, role: str, *, teardown: bool = False) -> dict:
    manifest = Owner(root)._manifest()
    token = manifest.get("ownerToken")
    receipt = read_json_bounded(root / "control" / f"manager-receipt-{role}.json", 65536)
    if receipt.get("ownerToken") != token or receipt.get("role") != role:
        raise Refusal("manager receipt token/role mismatch")
    expected_slice, expected_service = unit_names(role, token)
    if receipt.get("slice") != expected_slice or receipt.get("unit") != expected_service:
        raise Refusal("manager receipt unit names mismatch")
    identity = manifest.get("identity")
    owner_uid = identity.get("ownerUid") if isinstance(identity, dict) else None
    owner_gid = identity.get("ownerGid") if isinstance(identity, dict) else None
    if type(owner_uid) is not int or owner_uid < 0 or type(owner_gid) is not int or owner_gid < 0:
        raise Refusal("owner identity is incomplete for privileged manager revalidation")
    slice_facts = query_manager_unit(role, owner_uid, owner_gid, expected_slice)
    service_facts = query_manager_unit(role, owner_uid, owner_gid, expected_service)
    require_manager_reservation_binding(receipt, role, manifest, slice_facts, service_facts, teardown=teardown)
    slice_cg = receipt.get("sliceControlGroup")
    service_cg = receipt.get("controlGroup")
    if not isinstance(slice_cg, str) or not isinstance(service_cg, str) or not service_cg.startswith(slice_cg.rstrip("/") + "/"):
        raise Refusal("service cgroup is outside the exact owner slice")
    slice_fd = _open_cgroup_path(slice_cg)
    try:
        # These controls exist on normal non-root cgroups, not at the v2
        # hierarchy root. Verify them on the manager-authenticated slice before
        # releasing the gated supervisor.
        require_cgroup_kill(slice_fd)
        service_fd = _open_cgroup_path(service_cg)
        try:
            slice_stat = os.fstat(slice_fd)
            service_stat = os.fstat(service_fd)
            limits = {key: _read_fd_text(slice_fd, key).strip()
                      for key in ("memory.max", "memory.swap.max", "pids.max")}
            empty, nodes = _tree_empty(slice_fd, deadline=time.monotonic() + 5)
            return {"ownerToken": token, "role": role,
                "bootId": receipt.get("bootId", Path("/proc/sys/kernel/random/boot_id").read_text().strip()),
                "currentBootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "sliceControlGroup": slice_cg, "serviceControlGroup": service_cg,
                "sliceDevice": slice_stat.st_dev, "sliceInode": slice_stat.st_ino,
                "serviceDevice": service_stat.st_dev, "serviceInode": service_stat.st_ino,
                "limits": limits, "populated": 0 if empty else 1,
                "allDescendantsEmpty": empty, "cgroupNodes": nodes}
        finally:
            os.close(service_fd)
    finally:
        os.close(slice_fd)


def kill_domain_local(root: Path, role: str) -> dict:
    receipt = read_json_bounded(root / "control" / f"manager-receipt-{role}.json", 65536)
    inspected = inspect_domain_local(root, role, teardown=True)
    for key, receipt_key in (("sliceDevice", "device"), ("sliceInode", "inode"),
                             ("serviceDevice", "serviceDevice"), ("serviceInode", "serviceInode")):
        expected = receipt.get(receipt_key)
        if expected is None:
            # Initial reservation receipts are completed by manager_reserve before
            # domain-reserved is journaled; no kill may precede that completion.
            raise Refusal("cgroup kill lacks a complete pinned identity receipt")
        if inspected.get(key) != expected:
            raise Refusal("owned slice device/inode identity changed before cgroup.kill")
    if not hasattr(signal, "pidfd_send_signal"):
        raise Refusal("pidfd signalling support disappeared")
    killed = freeze_kill_prove(KernelCgroupIO(), receipt["sliceControlGroup"], receipt["device"],
                               receipt["inode"], timeout=5)
    current = inspect_domain_local(root, role, teardown=True)
    if current.get("allDescendantsEmpty") is not True:
        raise Refusal("owned slice remained populated after cgroup.kill")
    return {"ownerToken": receipt["ownerToken"], "role": role,
            "bootId": receipt["bootId"], **killed, "cgroupNodes": current["cgroupNodes"]}


def canonical_root(repo: Path, run_id: str, attempt: str, job: str, revision: str) -> Path:
    root = repo.resolve(strict=True)
    name_material = "\0".join((run_id, attempt, job, revision, str(root))).encode()
    short = hashlib.sha256(name_material).hexdigest()[:8]
    return root / "build" / "g" / short


def fixed_socket_inventory(root: Path) -> list[str]:
    return [str(root / suffix) for suffix in ("d.sock", "b.sock", "r/api.sock",
        "x/containerd/containerd.sock", "x/containerd/containerd.sock.ttrpc", "t/runc-console.sock")]


def bind_buildkit_config(root: Path, service_cgroup: str, uid: int, gid: int) -> None:
    """Bind the fixed worker config to the manager-authenticated service cgroup before child release."""
    if not isinstance(service_cgroup, str) or not re.fullmatch(r"/[A-Za-z0-9_.@/-]+", service_cgroup) or \
            ".." in service_cgroup.split("/"):
        raise Refusal("manager service cgroup cannot be represented in the BuildKit configuration")
    path = root / "v" / "s" / "buildkitd.toml"
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or path.is_symlink() or st.st_size > 32 * 1024 or \
                st.st_uid != uid or st.st_gid != gid or st.st_mode & 0o077:
            raise Refusal("BuildKit config is linked, nonregular, oversized, or not private")
        parsed = tomllib.loads(path.read_bytes().decode("utf-8", "strict"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise Refusal("BuildKit config is missing or malformed before owner binding") from exc
    expected = {"worker": {"oci": {"enabled": True, "snapshotter": "native",
                    "platforms": ["linux/amd64"], "max-parallelism": 1},
                "containerd": {"enabled": False}},
                "grpc": {"address": [f"unix://{root}/b.sock"], "uid": os.getuid(), "gid": os.getgid()}}
    if parsed != expected:
        raise Refusal("BuildKit config differs from the fixed native-worker profile")
    content = ("[worker.oci]\n"
        "  enabled = true\n"
        "  snapshotter = \"native\"\n"
        "  platforms = [\"linux/amd64\"]\n"
        "  max-parallelism = 1\n"
        f"  defaultCgroupParent = \"{service_cgroup.rstrip('/')}/daemon\"\n"
        "[worker.containerd]\n"
        "  enabled = false\n"
        "[grpc]\n"
        f"  address = [\"unix://{root}/b.sock\"]\n"
        f"  uid = {os.getuid()}\n"
        f"  gid = {os.getgid()}\n").encode("utf-8")
    temporary = path.with_name(path.name + ".owner-tmp-" + secrets.token_hex(6))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(content)
        while view:
            amount = os.write(fd, view)
            if amount <= 0:
                raise Refusal("short write binding BuildKit cgroup config")
            view = view[amount:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def fixed_launch_profile(root: Path, role: str, token: str, uid: int) -> tuple[list[str], dict[str, str]]:
    if role == "buildkit":
        binary = root / "v/tools/buildkit/bin/buildkitd"
        argv = [str(binary), "--config", str(root / "v/s/buildkitd.toml"), "--root",
            str(root / "v/s/buildkit-root"), "--addr", f"unix://{root}/b.sock",
            "--oci-worker=true", "--containerd-worker=false", "--oci-worker-snapshotter=native",
            "--oci-worker-platform=linux/amd64", "--oci-worker-binary",
            str(root / "v/tools/buildkit/bin/buildkit-runc"), "--oci-worker-net=host"]
        return argv, {"HOME": str(root / "v/home")}
    if role != "rootless":
        raise Refusal("unknown fixed launch role")
    slice_name, _ = unit_names(role, token)
    binary = root / "v/tools/docker-rootless-extras/dockerd-rootless.sh"
    argv = [str(binary), "--config-file", str(root / "v/s/docker-daemon.json"),
        "--data-root", str(root / "v/s/docker-data"), "--exec-root", str(root / "x"),
        "--pidfile", str(root / "control/dockerd.pid"), "--host", f"unix://{root}/d.sock",
        "--storage-driver=overlay2", "--bridge=none", "--iptables=false", "--ip6tables=false",
        "--ip-forward=false", "--ip-masq=false", "--exec-opt", "native.cgroupdriver=systemd",
        "--cgroup-parent", slice_name]
    return argv, {"HOME": str(root / "v/home"), "XDG_RUNTIME_DIR": f"/run/user/{uid}",
                  "DOCKER_CONFIG": str(root / "v/docker-config"),
                  "DOCKERD": str(root / "v/tools/docker/dockerd"),
                  "DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR": str(root / "r")}


def validate_buildkit_health(workers_raw: bytes, info_raw: bytes) -> dict:
    try:
        workers = json.loads(workers_raw)
        info = json.loads(info_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal("BuildKit health response is malformed") from exc
    rows = workers if isinstance(workers, list) else \
        workers.get("workers", workers.get("Workers", [])) if isinstance(workers, dict) else []
    if not isinstance(rows, list) or len(rows) != 1:
        raise Refusal("BuildKit health response must contain exactly one worker")
    for worker in rows:
        labels = worker.get("labels", worker.get("Labels", {})) if isinstance(worker, dict) else {}
        if not isinstance(labels, dict):
            raise Refusal("BuildKit worker labels are malformed")
        executor = worker.get("executor", labels.get("org.mobyproject.buildkit.worker.executor"))
        snapshotter = worker.get("snapshotter", labels.get("org.mobyproject.buildkit.worker.snapshotter"))
        process_mode = worker.get("process-mode", labels.get("org.mobyproject.buildkit.worker.oci.process-mode"))
        platforms = worker.get("platforms", worker.get("Platforms", worker.get("platform", [])))
        if executor != "oci" or snapshotter != "native" or process_mode != "sandbox" or \
                not isinstance(platforms, list) or not any(p == "linux/amd64" or
                    isinstance(p, dict) and p.get("OS", p.get("os")) == "linux" and
                    p.get("Architecture", p.get("architecture")) == "amd64" for p in platforms):
            raise Refusal("BuildKit worker is not the admitted OCI/native sandbox for linux/amd64")
    info_text = json.dumps(info, sort_keys=True).lower()
    if "v0.20.2" not in info_text or "97437fdd7e32f29bb80288d800cd4ffcb34e1c15" not in info_text:
        raise Refusal("BuildKit daemon health identity differs from the pinned release")
    return {"workerCount": len(rows), "executor": "oci", "snapshotter": "native",
            "processMode": "sandbox", "platform": "linux/amd64", "versionPinned": True}


def validate_docker_health(info_raw: bytes, version_raw: bytes, root: Path, socket_path: Path) -> dict:
    try:
        info = json.loads(info_raw)
        version = version_raw.decode("ascii", "strict").strip().split()
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal("rootless Docker health response is malformed") from exc
    expected_data = root / "v" / "s" / "docker-data"
    if not isinstance(info, dict) or info.get("Driver") != "overlay2" or \
            Path(str(info.get("DockerRootDir", "/"))).resolve() != expected_data.resolve() or \
            info.get("ServerVersion") != "29.7.2" or version != ["29.7.2", "6a43e3d"]:
        raise Refusal("rootless Docker health identity differs from the pinned runtime")
    try:
        endpoint = socket_path.lstat()
    except OSError as exc:
        raise Refusal("rootless Docker health endpoint is unavailable") from exc
    if not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != os.getuid():
        raise Refusal("rootless Docker health endpoint identity is invalid")
    return {"serverVersion": "29.7.2", "serverCommit": "6a43e3d", "driver": "overlay2",
            "dataRoot": str(expected_data), "endpointOwner": endpoint.st_uid}


def repository_root() -> Path:
    root = Path(__file__).resolve(strict=True).parents[1]
    if (root / "build").is_symlink() or (root / "build" / "g").is_symlink():
        raise Refusal("owned build directory may not be a symlink")
    return root


def _upload_inventory(base: Path, *, success: bool, budget: int, output: Path) -> tuple[list[dict], int]:
    """Hash a bounded, fd-rooted inventory of flat controls or parser evidence."""
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    root_fd: int | None = None
    opened_dirs: list[int] = []
    files: list[dict] = []
    total = 0
    dirs_seen = 0
    try:
        root_fd = os.open(base, directory_flags)
        root_st = os.fstat(root_fd)
        if not stat.S_ISDIR(root_st.st_mode):
            raise Refusal("upload base is not a regular owned directory")
        # Keep only the exact parser output directories. Failure/control staging stays flat.
        with os.scandir(root_fd) as entries:
            for entry in entries:
                if len(files) + dirs_seen >= MAX_FILES + 2:
                    raise Refusal("bounded upload manifest entry budget exceeded")
                name = entry.name
                if name in (".", ".."):
                    raise Refusal("invalid upload entry name")
                entry_st = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(entry_st.st_mode):
                    if not success or name not in ("oci-manifests", "provenance-statements"):
                        raise Refusal("upload input contains an unsupported directory")
                    dirs_seen += 1
                    if dirs_seen > 2:
                        raise Refusal("bounded upload directory budget exceeded")
                    child_fd = os.open(name, directory_flags, dir_fd=root_fd)
                    opened_dirs.append(child_fd)
                    child_st = os.fstat(child_fd)
                    if not stat.S_ISDIR(child_st.st_mode) or (child_st.st_dev, child_st.st_ino) != (entry_st.st_dev, entry_st.st_ino):
                        raise Refusal("upload directory changed during inventory")
                    with os.scandir(child_fd) as children:
                        for child in children:
                            if len(files) + dirs_seen >= MAX_FILES + 2:
                                raise Refusal("bounded upload manifest entry budget exceeded")
                            child_entry_st = child.stat(follow_symlinks=False)
                            if not stat.S_ISREG(child_entry_st.st_mode) or child_entry_st.st_nlink != 1:
                                raise Refusal("upload input is not an unlinked regular file")
                            _hash_upload_entry(child_fd, child.name, child_entry_st, base,
                                              f"{name}/{child.name}", files, budget, total)
                            total += child_entry_st.st_size
                elif stat.S_ISREG(entry_st.st_mode):
                    if entry_st.st_nlink != 1:
                        raise Refusal("upload input is not an unlinked regular file")
                    if (base / name) == output:
                        continue
                    _hash_upload_entry(root_fd, name, entry_st, base, name, files, budget, total)
                    total += entry_st.st_size
                else:
                    raise Refusal("upload input is not a regular owned file")
        if dirs_seen > 2 or len(files) > MAX_FILES:
            raise Refusal("bounded upload manifest budget exceeded")
        if success and dirs_seen != 2:
            raise Refusal("upload input is missing a required parser directory")
        files.sort(key=lambda item: item["path"])
        return files, total
    except OSError as exc:
        raise Refusal("upload inventory could not be safely read: " + type(exc).__name__) from exc
    finally:
        close_error = None
        for fd in reversed(opened_dirs):
            try:
                os.close(fd)
            except OSError as exc:
                close_error = close_error or exc
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError as exc:
                close_error = close_error or exc
        if close_error is not None:
            raise Refusal("upload inventory descriptor close failed") from close_error


def _hash_upload_entry(parent_fd: int, name: str, before: os.stat_result, base: Path,
                       relative: str, files: list[dict], budget: int, total: int) -> None:
    if before.st_size < 0 or total + before.st_size > budget or len(files) >= MAX_FILES:
        raise Refusal("bounded upload manifest budget exceeded")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(fd)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_nlink)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or \
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_nlink) != identity:
            raise Refusal("upload file changed during inventory")
        digest = hashlib.sha256()
        observed = 0
        while observed < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - observed + 1))
            if not block:
                raise Refusal("upload file shrank during hashing")
            observed += len(block)
            if observed > before.st_size:
                raise Refusal("upload file grew during hashing")
            digest.update(block)
        if os.read(fd, 1):
            raise Refusal("upload file grew during hashing")
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_nlink) != identity:
            raise Refusal("upload file changed during hashing")
        files.append({"path": str((base / relative).relative_to(base.parent)),
                      "bytes": observed, "sha256": digest.hexdigest()})
    except OSError as exc:
        raise Refusal("upload file could not be safely read: " + type(exc).__name__) from exc
    finally:
        os.close(fd)


def atomic_json(path: Path, value: dict, *, limit: int = MAX_JOURNAL,
                owner: tuple[int, int] | None = None) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > limit:
        raise Refusal("bounded JSON record exceeds limit")
    tmp = path.with_name(path.name + ".tmp-" + secrets.token_hex(6))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as out:
            out.write(raw)
            if owner is not None and os.geteuid() == 0:
                os.fchown(fd, owner[0], owner[1])
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
    def __init__(self, root: Path, backend: Backend | None = None, *, clock=time.monotonic,
                 test_repo_root: Path | None = None):
        self.root = root
        self.clock = clock
        self._test_repo_root = test_repo_root
        self.backend = backend or ProductionBackend(root, clock=clock)
        self.manifest_path = root / "owner.json"
        self.journal_path = root / "journal.jsonl"

    def _manifest(self) -> dict:
        try:
            root_stat = self.root.lstat()
            if not stat.S_ISDIR(root_stat.st_mode) or self.root.is_symlink() or root_stat.st_mode & 0o077:
                raise Refusal("owned root is linked or has unsafe permissions")
            st = self.manifest_path.lstat()
            if not self.manifest_path.is_file() or self.manifest_path.is_symlink() or st.st_size > MAX_JOURNAL or \
                    st.st_mode & 0o077:
                raise Refusal("missing, linked, or oversized owner manifest")
            data = json.loads(self.manifest_path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise Refusal("owner manifest is missing or corrupt") from exc
        if not isinstance(data, dict) or not isinstance(data.get("identity"), dict):
            raise Refusal("owner manifest shape is invalid")
        identity = data["identity"]
        owner_uid = identity.get("ownerUid")
        if data.get("schema") != 1 or data.get("root") != str(self.root.resolve()) or \
                data.get("rootDevice") != root_stat.st_dev or data.get("rootInode") != root_stat.st_ino or \
                not isinstance(owner_uid, int) or isinstance(owner_uid, bool) or \
                root_stat.st_uid != owner_uid or st.st_uid != owner_uid or \
                not re.fullmatch(r"[0-9a-f]{32}", str(data.get("ownerToken", ""))):
            raise Refusal("owner manifest root/schema mismatch")
        try:
            control_stat = (self.root / "control").lstat()
            if not stat.S_ISDIR(control_stat.st_mode) or (self.root / "control").is_symlink() or \
                    control_stat.st_uid != owner_uid or control_stat.st_mode & 0o077:
                raise Refusal("owner control directory identity/permissions changed")
        except OSError as exc:
            raise Refusal("owner control directory is missing") from exc
        if self._test_repo_root is None:
            identity = data.get("identity", {})
            expected_root = canonical_root(repository_root(), str(identity.get("run", "")),
                str(identity.get("attempt", "")), str(identity.get("job", "")),
                str(identity.get("revision", "")))
            if self.root != expected_root:
                raise Refusal("owner root does not match its durable run/source identity")
        self._verify_journal(data)
        return data

    def _verify_journal(self, manifest: dict) -> None:
        marker = self.root / "control" / "journal.incomplete"
        if marker.exists() or marker.is_symlink():
            raise Refusal("owner journal has a partial-write marker; quarantine required")
        try:
            st = self.journal_path.lstat()
            identity = manifest.get("identity")
            if not isinstance(identity, dict) or not stat.S_ISREG(st.st_mode) or \
                    self.journal_path.is_symlink() or st.st_size > MAX_JOURNAL or \
                    st.st_uid != identity.get("ownerUid") or st.st_mode & 0o077:
                raise Refusal("owner journal is linked, nonregular, or oversized")
            raw = self.journal_path.read_bytes()
        except OSError as exc:
            raise Refusal("owner journal is missing") from exc
        if not raw.endswith(b"\n"):
            raise Refusal("owner journal ends in an incomplete record")
        rows = raw.splitlines()
        if not isinstance(manifest.get("sequence"), int) or isinstance(manifest.get("sequence"), bool) or \
                len(rows) != manifest.get("sequence"):
            raise Refusal("owner journal sequence count differs from manifest")
        previous = "absent"
        previous_time = -1.0
        journal_intents: dict[str, str] = {}
        journal_receipts: dict[str, dict] = {}
        journal_gates: dict[str, dict] = {}
        journal_execs: dict[str, dict] = {}
        for index, line in enumerate(rows, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise Refusal("owner journal contains a malformed record") from exc
            if not isinstance(event, dict) or not isinstance(event.get("sequence"), int) or \
                    isinstance(event.get("sequence"), bool) or \
                    event.get("sequence") != index or event.get("ownerToken") != manifest.get("ownerToken") or \
                    not isinstance(event.get("from"), str) or not isinstance(event.get("state"), str):
                raise Refusal("owner journal sequence/token mismatch")
            if index == 1:
                expected_identity = hashlib.sha256(json.dumps(
                    manifest.get("identity", {}), sort_keys=True).encode()).hexdigest()
                if event.get("identitySha256") != expected_identity:
                    raise Refusal("reserved journal record does not bind owner identity")
            if event.get("state") == "launch-intent":
                role = event.get("role")
                if role not in ("buildkit", "rootless") or not re.fullmatch(
                        r"[0-9a-f]{64}", str(event.get("intentSha256", ""))):
                    raise Refusal("launch intent journal record is malformed")
                journal_intents[role] = event["intentSha256"]
            elif event.get("state") == "domain-reserved":
                role = event.get("role")
                if role not in ("buildkit", "rootless"):
                    raise Refusal("domain receipt journal role is invalid")
                journal_receipts[role] = event.get("receipt")
            elif event.get("state") == "child-gated":
                role = event.get("role")
                if role not in ("buildkit", "rootless"):
                    raise Refusal("child-gate journal role is invalid")
                journal_gates[role] = event.get("gate")
            elif event.get("state") == "exec-observed":
                role = event.get("role")
                if role not in ("buildkit", "rootless"):
                    raise Refusal("exec journal role is invalid")
                journal_execs[role] = event.get("exec")
            role_record = event.get("event") == "role-record"
            if role_record:
                if event.get("from") != previous or event.get("state") != previous:
                    raise Refusal("role-level journal record changed global state")
            elif event.get("from") != previous or event.get("state") not in TRANSITIONS.get(previous, set()):
                if not (index == 1 and event.get("from") == "absent" and event.get("state") == "reserved"):
                    raise Refusal("owner journal state chain is invalid")
            if isinstance(event.get("monotonic"), bool) or not isinstance(event.get("monotonic"), (int, float)) or \
                    not math.isfinite(event["monotonic"]) or \
                    event["monotonic"] < previous_time:
                raise Refusal("owner journal monotonic timestamp is invalid")
            previous = event.get("state")
            previous_time = float(event["monotonic"])
        if previous != manifest.get("state"):
            raise Refusal("owner manifest state differs from journal tail")
        roles = manifest.get("roles")
        if not isinstance(roles, dict) or set(roles) != {"buildkit", "rootless"}:
            raise Refusal("owner role inventory is missing or unexpected")
        for role, record in roles.items():
            if not isinstance(record, dict) or not isinstance(record.get("status"), str):
                raise Refusal("owner role record is malformed")
            if record.get("status") == "never-launched" or record.get("neverLaunched") is True:
                if role in journal_intents:
                    raise Refusal("never-launched role has a durable launch-intent record")
                continue
            intent = record.get("intent")
            if not isinstance(intent, dict) or role not in journal_intents or \
                    hashlib.sha256(json.dumps(intent, sort_keys=True).encode()).hexdigest() != journal_intents[role]:
                raise Refusal("manifest launch vector differs from durable prelaunch intent")
            if record.get("receipt") is not None and journal_receipts.get(role) != record["receipt"]:
                raise Refusal("manifest manager receipt differs from durable domain reservation")
            if record.get("gate") is not None and journal_gates.get(role) != record["gate"]:
                raise Refusal("manifest child gate differs from durable gate receipt")
            if record.get("exec") is not None and journal_execs.get(role) != record["exec"]:
                raise Refusal("manifest executable identity differs from durable exec observation")

    def _event(self, manifest: dict, state: str, **facts) -> None:
        prior_state = manifest["state"]
        if state not in TRANSITIONS.get(prior_state, set()):
            raise Refusal(f"illegal owner transition {prior_state} -> {state}")
        sequence = manifest["sequence"] + 1
        event = {"sequence": sequence, "from": prior_state, "state": state,
                 "ownerToken": manifest["ownerToken"], "monotonic": self.clock(), **facts}
        encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
        try:
            existing_bytes = self.journal_path.lstat().st_size
        except FileNotFoundError:
            existing_bytes = 0
        if existing_bytes + len(encoded) > MAX_JOURNAL:
            raise Refusal("owner journal budget exceeded")
        fd = os.open(self.journal_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            written = 0
            while written < len(encoded):
                amount = os.write(fd, encoded[written:])
                if amount <= 0:
                    raise OSError(errno.EIO, "short owner journal append")
                written += amount
            os.fsync(fd)
        except OSError as exc:
            try:
                atomic_json(self.root / "control" / "journal.incomplete",
                    {"sequence": sequence, "ownerToken": manifest["ownerToken"], "error": type(exc).__name__},
                    limit=4096)
            except OSError:
                pass
            raise Refusal("owner journal append/fsync failed; quarantine required") from exc
        finally:
            os.close(fd)
        manifest["sequence"] = sequence
        manifest["state"] = state
        atomic_json(self.manifest_path, manifest)

    def _role_event(self, manifest: dict, role: str, record: dict, reason: str) -> None:
        sequence = manifest["sequence"] + 1
        event = {"sequence": sequence, "from": manifest["state"], "state": manifest["state"],
                 "event": "role-record", "role": role, "record": record,
                 "reason": reason, "ownerToken": manifest["ownerToken"], "monotonic": self.clock()}
        encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
        journal_stat = self.journal_path.lstat()
        if not stat.S_ISREG(journal_stat.st_mode) or journal_stat.st_size + len(encoded) > MAX_JOURNAL:
            raise Refusal("owner journal budget exceeded while recording role receipt")
        fd = os.open(self.journal_path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
        try:
            view = memoryview(encoded)
            while view:
                amount = os.write(fd, view)
                if amount <= 0:
                    raise OSError(errno.EIO, "short role journal append")
                view = view[amount:]
            os.fsync(fd)
        except OSError as exc:
            try:
                atomic_json(self.root / "control" / "journal.incomplete",
                    {"sequence": sequence, "ownerToken": manifest["ownerToken"], "error": type(exc).__name__},
                    limit=4096)
            except OSError:
                pass
            raise Refusal("role journal append failed; quarantine required") from exc
        finally:
            os.close(fd)
        manifest["sequence"] = sequence
        atomic_json(self.manifest_path, manifest)

    def reserve(self, identity: dict, socket_paths: list[str]) -> dict:
        repo = self._test_repo_root.resolve(strict=True) if self._test_repo_root is not None else repository_root()
        expected_parent = repo / "build" / "g"
        if self.root.parent != expected_parent or not self.root.is_absolute():
            raise Refusal("owner root is not the fixed repository build/g location")
        if self.root.exists() or self.root.is_symlink():
            raise Refusal("exclusive owner root already exists")
        for item in socket_paths:
            if len(os.fsencode(item)) > 107:
                raise Refusal("generated Unix socket path exceeds 107 bytes")
        self.root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.mkdir(self.root, 0o700)
        for child in ("control", "evidence", "r"):
            os.mkdir(self.root / child, 0o700)
        root_stat = self.root.stat()
        owner = {"schema": 1, "ownerToken": secrets.token_hex(16), "root": str(self.root.resolve()),
                 "rootDevice": root_stat.st_dev, "rootInode": root_stat.st_ino,
                 "identity": {**identity, "ownerUid": os.getuid(), "ownerGid": os.getgid()},
                 "state": "reserved", "sequence": 0,
                 "roles": {"buildkit": {"status": "never-launched"}, "rootless": {"status": "never-launched"}},
                 "socketPaths": socket_paths, "createdMonotonic": self.clock()}
        atomic_json(self.manifest_path, owner)
        event = {"sequence": 1, "from": "absent", "state": "reserved",
                 "ownerToken": owner["ownerToken"], "monotonic": self.clock(),
                 "identitySha256": hashlib.sha256(json.dumps(owner["identity"], sort_keys=True).encode()).hexdigest()}
        fd = os.open(self.journal_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
        try:
            written = 0
            while written < len(encoded):
                amount = os.write(fd, encoded[written:])
                if amount <= 0:
                    raise OSError(errno.EIO, "short initial journal write")
                written += amount
            os.fsync(fd)
        except OSError as exc:
            try:
                atomic_json(self.root / "control" / "journal.incomplete",
                    {"sequence": 1, "ownerToken": owner["ownerToken"], "error": type(exc).__name__},
                    limit=4096)
            except OSError:
                pass
            raise Refusal("initial owner journal write failed; quarantine required") from exc
        finally:
            os.close(fd)
        parent_fd = os.open(self.journal_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        owner["sequence"] = 1
        atomic_json(self.manifest_path, owner)
        return owner

    def begin_role(self, role: str, argv: list[str], env: dict[str, str], budgets: dict) -> dict:
        if role not in ("buildkit", "rootless") or not argv or not budgets:
            raise Refusal("invalid fixed role launch request")
        manifest = self._manifest()
        if manifest["state"] not in ("reserved", "ready"):
            raise Refusal("owner is sealed or has unresolved earlier launch")
        if manifest["roles"].get(role, {}).get("status") != "never-launched":
            raise Refusal("fixed role may be launched only once per owner token")
        identity = {"argv": argv, "env": env, "budgets": budgets, "ownerToken": manifest["ownerToken"]}
        if any("\x00" in x for x in argv) or any("\x00" in k + v for k, v in env.items()):
            raise Refusal("NUL in launch vector")
        if isinstance(self.backend, ProductionBackend):
            expected = (self.root / "v" / "tools" / "buildkit" / "bin" / "buildkitd" if role == "buildkit"
                        else self.root / "v" / "tools" / "docker-rootless-extras" / "dockerd-rootless.sh")
            if Path(argv[0]) != expected or expected.is_symlink() or not expected.is_file():
                raise Refusal("fixed launch verb executable is missing or differs from production role")
            identity["launcherSha256"] = _hash_file_bounded(expected, 64 * 1024 * 1024)
        manifest["roles"][role] = {"status": "launch-intent", "intent": identity}
        self._event(manifest, "launch-intent", role=role, intentSha256=hashlib.sha256(
            json.dumps(identity, sort_keys=True).encode()).hexdigest())
        receipt = self.backend.manager_reserve(role, manifest)
        if not self._valid_receipt(receipt, manifest, role):
            raise Refusal("manager reservation receipt does not bind owner/role/domain")
        manifest["roles"][role].update({"status": "domain-reserved", "receipt": receipt})
        self._event(manifest, "domain-reserved", role=role, receipt=receipt)
        prepared = self.backend.manager_prepare_gate(role, manifest)
        if not isinstance(prepared, dict) or prepared.get("ownerToken") != manifest["ownerToken"] or \
                prepared.get("role") != role or not prepared.get("pidfdHeld"):
            raise Refusal("manager did not reserve a pidfd-pinned child behind the gate")
        manifest["roles"][role]["gate"] = prepared
        manifest["roles"][role]["status"] = "child-gated"
        self._event(manifest, "child-gated", role=role, gate=prepared)
        gate = self.backend.manager_gate(role, manifest)
        if not self._valid_receipt(gate, manifest, role):
            raise Refusal("manager child-gate receipt mismatch")
        manifest["roles"][role]["status"] = "exec-observed"
        manifest["roles"][role]["exec"] = gate.get("exec")
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
        if isinstance(self.backend, ProductionBackend):
            receipt = read_json_bounded(self.root / "control" / f"exec-observed-{role}.json", 32 * 1024)
            identity = receipt.get("identity")
            expected_exe = (str(self.root / "v" / "tools" / "buildkit" / "bin" / "buildkitd")
                            if role == "buildkit" else
                            str(self.root / "v" / "tools" / "docker-rootless-extras" / "rootlesskit"))
            expected_sha = record.get("intent", {}).get("launcherSha256") if role == "buildkit" else \
                record.get("receipt", {}).get("toolHashes", {}).get("rootlesskit")
            if receipt.get("ownerToken") != manifest["ownerToken"] or receipt.get("role") != role or \
                    receipt.get("pidfdHeld") is not True or not stable_exec_identity(role, identity,
                        expected_exe, expected_sha, record.get("gate", {}).get("identity", {}).get("startTicks")):
                raise Refusal("production readiness does not bind the supervisor's stable pidfd identity")
            if role == "rootless" and (len(receipt.get("authenticatedDescendants", [])) != 1 or
                    receipt["authenticatedDescendants"][0].get("pidfdHeld") is not True):
                raise Refusal("production rootless readiness lacks a pinned dockerd descendant")
        record["status"] = "ready"
        self._event(manifest, "ready", role=role,
                    facts={"health": facts, "execReceiptSha256": hashlib.sha256(
                        json.dumps(record.get("exec", {}), sort_keys=True).encode()).hexdigest()})

    def ready_after_health(self, role: str, *, timeout: float = 60.0) -> dict:
        if role not in ("buildkit", "rootless") or not isinstance(self.backend, ProductionBackend):
            raise Refusal("health-bound readiness requires a production-owned role")
        manifest = self._manifest()
        if manifest["roles"].get(role, {}).get("status") != "exec-observed":
            raise Refusal("health-bound readiness requires an exec-observed role")
        deadline = self.clock() + min(max(timeout, 0.001), 60.0)
        last_error = "service health was not observed"
        while self.clock() < deadline:
            remaining = deadline - self.clock()
            try:
                if role == "buildkit":
                    client = self.root / "v" / "tools" / "buildkit" / "bin" / "buildctl"
                    endpoint = f"unix://{self.root}/b.sock"
                    runner = self.backend.runner
                    status, workers, err = runner.run([str(client), "--addr", endpoint,
                        "debug", "workers", "--format", "{{json .}}"], min(5.0, remaining))
                    if status != 0:
                        raise Refusal(f"BuildKit worker health command failed: {err[:512]!r}")
                    status, info, err = runner.run([str(client), "--addr", endpoint,
                        "debug", "info", "--format", "{{json .}}"], min(5.0, remaining))
                    if status != 0:
                        raise Refusal(f"BuildKit info health command failed: {err[:512]!r}")
                    facts = validate_buildkit_health(workers, info)
                else:
                    client = self.root / "v" / "tools" / "docker" / "docker"
                    endpoint = f"unix://{self.root}/d.sock"
                    env = {"DOCKER_CONFIG": str(self.root / "v" / "docker-config"),
                           "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"}
                    runner = self.backend.runner
                    status, info, err = runner.run([str(client), "--host", endpoint,
                        "info", "--format", "{{json .}}"], min(5.0, remaining), env=env)
                    if status != 0:
                        raise Refusal(f"rootless Docker info health command failed: {err[:512]!r}")
                    status, version, err = runner.run([str(client), "--host", endpoint,
                        "version", "--format", "{{.Server.Version}} {{.Server.GitCommit}}"],
                        min(5.0, remaining), env=env)
                    if status != 0:
                        raise Refusal(f"rootless Docker version health command failed: {err[:512]!r}")
                    facts = validate_docker_health(info, version, self.root, self.root / "d.sock")
            except Refusal as exc:
                last_error = str(exc)
                time.sleep(min(0.2, max(0.0, deadline - self.clock())))
                continue
            self.backend._verify_live_domain(role, manifest, populated=True)
            self.ready(role, {"pidfd": True, "identity": True, **facts})
            return facts
        raise Refusal(f"bounded {role} health readiness deadline expired: {last_error}")

    @staticmethod
    def _all_roles_absence_proved(manifest: dict) -> bool:
        token = manifest.get("ownerToken")
        roles = manifest.get("roles")
        if not isinstance(roles, dict):
            return False
        for role in ("buildkit", "rootless"):
            record = roles.get(role)
            if not isinstance(record, dict) or record.get("status") != "absence-proved":
                return False
            if record.get("neverLaunched") is True:
                continue
            receipt = record.get("receipt")
            stopped = record.get("stopReceipt")
            if not isinstance(receipt, dict) or receipt.get("ownerToken") != token or \
                    receipt.get("role") != role or not isinstance(stopped, dict) or \
                    stopped.get("ownerToken") != token or stopped.get("role") != role or \
                    stopped.get("cgroupEmpty") is not True:
                return False
        return True

    def _mark_absence_if_all_roles_proved(self, manifest: dict) -> None:
        if manifest.get("state") == "stopped" and self._all_roles_absence_proved(manifest):
            self._event(manifest, "absence-proved", roles=("buildkit", "rootless"))

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
            role_record.update({"status": "absence-proved", "neverLaunched": True})
            if manifest["state"] in ("reserved", "launch-intent", "sealed", "stopped"):
                if manifest["state"] not in ("sealed", "stopped"):
                    self._event(manifest, "sealed", role=role, reason="never-launched role finalized")
                if manifest["state"] == "sealed":
                    self._event(manifest, "stopped", role=role, neverLaunched=True)
            else:
                self._role_event(manifest, role, role_record, "never-launched absence")
            self._mark_absence_if_all_roles_proved(manifest)
            return manifest
        receipt = role_record.get("receipt")
        if not receipt:
            role_record["status"] = "quarantined-unknown"
            self._role_event(manifest, role, role_record, "launch intent has no complete manager receipt")
            raise Refusal("launch intent lacks manager receipt; absence is unknown")
        remaining = max(0.001, deadline - self.clock())
        try:
            result = self.backend.manager_stop(role, receipt, remaining)
        except Exception as exc:
            role_record["status"] = "quarantined-unknown"
            self._role_event(manifest, role, role_record, "bounded manager stop failed: " + type(exc).__name__)
            raise
        if result.get("ownerToken") != manifest["ownerToken"] or result.get("role") != role:
            raise Refusal("manager stop receipt does not match pinned owner")
        pre_kill = result.get("preKillReceipt")
        kill_receipt = result.get("killReceipt")
        if result.get("cgroupEmpty") is not True or not isinstance(pre_kill, dict) or \
                pre_kill.get("ownerToken") != manifest["ownerToken"] or pre_kill.get("role") != role or \
                pre_kill.get("pidfdHeld") is not True or not isinstance(kill_receipt, dict) or \
                kill_receipt.get("ownerToken") != manifest["ownerToken"] or \
                kill_receipt.get("role") != role or kill_receipt.get("empty") is not True:
            raise Refusal("manager stop lacks supervisor and complete cgroup-kill receipts")
        if self.clock() >= deadline:
            raise Refusal("shared teardown deadline expired during manager stop")
        remaining = max(0.001, deadline - self.clock())
        if not self.backend.domain_empty(role, receipt, min(5.0, remaining)):
            role_record["status"] = "quarantined-unknown"
            self._role_event(manifest, role, role_record, "owned cgroup descendant absence is unknown")
            raise Refusal("owned cgroup/descendant absence is unknown")
        role_record["status"] = "absence-proved"
        role_record["stopReceipt"] = result
        if manifest["state"] == "sealed":
            self._event(manifest, "stopped", role=role, stopReceipt=result)
        self._mark_absence_if_all_roles_proved(manifest)
        return manifest

    def stage_upload(self, *, success: bool) -> Path:
        manifest = self._manifest()
        if manifest["state"] != "absence-proved" or not self._all_roles_absence_proved(manifest):
            raise Refusal("upload staging requires complete process absence proof")
        for role in ("buildkit", "rootless"):
            record = manifest["roles"][role]
            if record.get("neverLaunched") is not True and not self.backend.domain_empty(
                    role, record["receipt"], 5):
                raise Refusal("upload staging recheck found a populated or unknown owner cgroup")
        out = self.root / "control" / "upload-manifest.json"
        base = self.root / ("evidence" if success else "control")
        budget = 13 * 1024**3 if success else 32 * 1024**2
        files, total = _upload_inventory(base, success=success, budget=budget, output=out)
        atomic_json(out, {"files": files, "bytes": total, "success": success}, limit=4 * 1024 * 1024)
        return out

    def release(self, timeout: float = 60.0) -> None:
        manifest = self._manifest()
        if manifest["state"] != "absence-proved":
            raise Refusal("manager-domain release requires complete absence receipt")
        result = self.backend.release_domains(manifest, min(timeout, 60.0))
        if not isinstance(result, dict) or result.get("ownerToken") != manifest["ownerToken"] or \
                not isinstance(result.get("released"), list) or len(result["released"]) != 2 or \
                not isinstance(result.get("apparmorAbsence"), dict):
            raise Refusal("manager-domain release is unknown; retain quarantine")
        self._event(manifest, "released", release=result)


def cli() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("verb", choices=("reserve", "provision", "launch-buildkit", "launch-rootless",
        "ready", "status", "seal", "stop", "stage-upload", "release", "supervisor",
        "_inspect-domain", "_kill-domain"))
    parser.add_argument("--role", choices=("buildkit", "rootless"))
    parser.add_argument("--owner-root", type=Path)
    parser.add_argument("--success", action="store_true")
    args = parser.parse_args()
    try:
        repo = repository_root()
        if args.verb in ("supervisor", "_inspect-domain", "_kill-domain"):
            if args.owner_root is None or args.role is None:
                raise Refusal("internal owner verb requires fixed owner root and role")
            if args.verb == "supervisor":
                supervisor_main(args.owner_root, args.role)
            elif args.verb == "_inspect-domain":
                print(json.dumps(inspect_domain_local(args.owner_root, args.role), sort_keys=True))
            else:
                print(json.dumps(kill_domain_local(args.owner_root, args.role), sort_keys=True))
            return 0
        run = os.environ.get("GITHUB_RUN_ID", "local")
        attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        job = os.environ.get("GITHUB_JOB", "provenance")
        git_runner = CommandRunner()
        status, out, err = git_runner.run(["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"], 5)
        if status != 0:
            raise Refusal(f"cannot bind owner to checkout revision: {err[:1024]!r}")
        revision = out.decode("ascii", "strict").strip()
        root = args.owner_root if args.owner_root is not None else canonical_root(repo, run, attempt, job, revision)
        if root != canonical_root(repo, run, attempt, job, revision):
            raise Refusal("owner root does not match the fixed run/attempt/job/source identity")
        owner = Owner(root)
        if args.verb in ("reserve", "provision"):
            owner.reserve({"run": run, "attempt": attempt, "job": job, "revision": revision},
                          fixed_socket_inventory(root))
        elif args.verb in ("launch-buildkit", "launch-rootless"):
            role = "buildkit" if args.verb == "launch-buildkit" else "rootless"
            token = owner._manifest()["ownerToken"]
            argv, env = fixed_launch_profile(root, role, token, os.getuid())
            owner.begin_role(role, argv, env, {"gateSeconds": 10, "runtimeSeconds": 1800 if role == "buildkit" else 10800})
        elif args.verb == "status":
            print(json.dumps(owner._manifest(), sort_keys=True))
        elif args.verb == "ready" and args.role:
            print(json.dumps(owner.ready_after_health(args.role), sort_keys=True))
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
