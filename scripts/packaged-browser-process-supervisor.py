#!/usr/bin/env python3
"""Own one packaged-browser driver and reap its Linux descendants.

This helper is deliberately narrow: it starts exactly one driver command, becomes
its child subreaper before the spawn, and signals only pidfd-pinned direct children
that Linux has assigned to this supervisor.  /proc is used to enumerate that
kernel-owned child set, never to discover arbitrary same-UID processes.

The report is a fixed-schema cleanup receipt.  It contains process identities and
termination outcomes, but no command line, environment, URL, or credential data.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import math
import os
import signal
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


PR_SET_CHILD_SUBREAPER = 36
POLL_INTERVAL_SECONDS = 0.05
INITIAL_DRAIN_SECONDS = 2.0
TERM_GRACE_SECONDS = 5.0
KILL_GRACE_SECONDS = 5.0
MAX_CLEANUP_SECONDS = 30.0


class SupervisorError(RuntimeError):
    pass


@dataclass
class Identity:
    pid: int
    start_ticks: int


@dataclass
class SignalRecord:
    pid: int
    start_ticks: int
    signal: str
    sent: bool
    error: str | None = None


def enable_subreaper() -> None:
    if not sys.platform.startswith("linux"):
        raise SupervisorError("Linux child-subreaper support is required")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise SupervisorError(f"cannot become child subreaper (errno {error})")
    if not callable(getattr(os, "pidfd_open", None)):
        raise SupervisorError("pidfd_open is unavailable; refusing unsafe process signaling")
    if not callable(getattr(signal, "pidfd_send_signal", None)):
        raise SupervisorError("pidfd_send_signal is unavailable; refusing unsafe process signaling")
    if not Path("/proc/self/stat").is_file():
        raise SupervisorError("procfs process identity data is unavailable")


def proc_identity(pid: int) -> tuple[int, int] | None:
    """Return (parent PID, start ticks), handling spaces and ')' in comm safely."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ESRCH:
            return None
        raise
    close = raw.rfind(b")")
    if close < 0:
        raise SupervisorError("malformed procfs process identity")
    fields = raw[close + 2 :].split()
    # fields[0] is kernel stat field 3 (state); PPID is field 4 and starttime 22.
    if len(fields) <= 19:
        raise SupervisorError("truncated procfs process identity")
    try:
        return int(fields[1]), int(fields[19])
    except ValueError as error:
        raise SupervisorError("malformed procfs process identity") from error


def waitid_state(pid: int) -> str:
    """Verify wait ownership without reaping; report live, exited, or absent."""
    try:
        result = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return "absent"
    if result is None or result.si_pid == 0:
        return "live"
    return "exited"


def child_pidfds(supervisor_pid: int) -> dict[int, tuple[int, int]]:
    """Enumerate only direct children, then prove wait ownership and pin identity."""
    found: dict[int, tuple[int, int]] = {}
    try:
        entries = os.scandir("/proc")
    except OSError as error:
        raise SupervisorError("cannot enumerate the supervisor's direct child set") from error
    try:
        with entries:
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                pid = int(entry.name)
                if pid == supervisor_pid:
                    continue
                identity = proc_identity(pid)
                if identity is None or identity[0] != supervisor_pid:
                    continue
                start_ticks = identity[1]
                try:
                    pidfd = os.pidfd_open(pid, 0)
                except ProcessLookupError:
                    continue
                except OSError as error:
                    if error.errno == errno.ESRCH:
                        continue
                    raise SupervisorError(f"cannot pin owned child identity (errno {error.errno})") from error
                try:
                    after = proc_identity(pid)
                    if after is None:
                        os.close(pidfd)
                        continue
                    if after != (supervisor_pid, start_ticks):
                        os.close(pidfd)
                        raise SupervisorError("direct-child identity changed while pinning")
                    state = waitid_state(pid)
                    if state == "absent":
                        os.close(pidfd)
                        raise SupervisorError("procfs direct child was not wait-owned")
                    found[pid] = (start_ticks, pidfd)
                except BaseException:
                    try:
                        os.close(pidfd)
                    except OSError:
                        pass
                    raise
    except BaseException:
        for _ticks, fd in found.values():
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    return found


def reap_exited_children() -> list[Identity]:
    reaped: list[Identity] = []
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return reaped
        if pid == 0:
            return reaped
        # A just-reaped process may no longer have a proc entry. PID identity is
        # retained from pidfd discovery whenever it was part of a cleanup round.
        reaped.append(Identity(pid=pid, start_ticks=0))


def send_pinned(pidfd: int, identity: Identity, sig: int, records: list[dict[str, Any]]) -> None:
    try:
        signal.pidfd_send_signal(pidfd, sig, None, 0)
        records.append(asdict(SignalRecord(identity.pid, identity.start_ticks, signal.Signals(sig).name, True)))
    except ProcessLookupError:
        records.append(asdict(SignalRecord(identity.pid, identity.start_ticks, signal.Signals(sig).name, False, "already-exited")))
    except OSError as error:
        records.append(asdict(SignalRecord(identity.pid, identity.start_ticks, signal.Signals(sig).name, False,
                                           f"errno-{error.errno}")))


def terminate_adopted_children(report: dict[str, Any]) -> tuple[bool, bool]:
    """Return (confirmed descendant leak, incomplete ownership scan)."""
    supervisor_pid = os.getpid()
    report["survivors"] = []
    discovered: dict[tuple[int, int], Identity] = {}
    leaked = False
    deadline = time.monotonic() + MAX_CLEANUP_SECONDS
    # Allow ordinary browser helpers and JVM shutdown hooks to exit after the
    # driver has completed its own bounded stop sequence.
    quiet_until = time.monotonic() + INITIAL_DRAIN_SECONDS
    scan_error = False
    while time.monotonic() < quiet_until:
        try:
            children = child_pidfds(supervisor_pid)
        except (OSError, SupervisorError):
            report["cleanupScanIncomplete"] = True
            scan_error = True
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        for pid, (ticks, fd) in children.items():
            discovered[(pid, ticks)] = Identity(pid, ticks)
            os.close(fd)
        reap_exited_children()
        if not children:
            report["observedChildren"] = [asdict(identity) for identity in sorted(discovered.values(), key=lambda item: (item.pid, item.start_ticks))]
            report["cleanupScanIncomplete"] = scan_error
            return leaked, scan_error
        time.sleep(POLL_INTERVAL_SECONDS)

    try:
        children = child_pidfds(supervisor_pid)
    except (OSError, SupervisorError):
        report["cleanupScanIncomplete"] = True
        children = {}
        scan_error = True
    if children:
        leaked = True
    term_started = time.monotonic()
    signalled: set[tuple[int, int]] = set()
    for pid, (ticks, fd) in children.items():
        identity = Identity(pid, ticks)
        discovered[(pid, ticks)] = identity
        send_pinned(fd, identity, signal.SIGTERM, report["signals"])
        signalled.add((pid, ticks))
        os.close(fd)
    while time.monotonic() - term_started < TERM_GRACE_SECONDS and time.monotonic() < deadline:
        reap_exited_children()
        try:
            updated = child_pidfds(supervisor_pid)
        except (OSError, SupervisorError):
            report["cleanupScanIncomplete"] = True
            scan_error = True
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        for pid, (ticks, fd) in updated.items():
            discovered.setdefault((pid, ticks), Identity(pid, ticks))
            leaked = True
            if (pid, ticks) not in signalled:
                send_pinned(fd, Identity(pid, ticks), signal.SIGTERM, report["signals"])
                signalled.add((pid, ticks))
            os.close(fd)
        if not updated:
            break
        time.sleep(POLL_INTERVAL_SECONDS)

    try:
        children = child_pidfds(supervisor_pid)
    except (OSError, SupervisorError):
        report["cleanupScanIncomplete"] = True
        children = {}
        scan_error = True
    if children:
        leaked = True
        killed: set[tuple[int, int]] = set()
        for pid, (ticks, fd) in children.items():
            discovered[(pid, ticks)] = Identity(pid, ticks)
            send_pinned(fd, Identity(pid, ticks), signal.SIGKILL, report["signals"])
            killed.add((pid, ticks))
            os.close(fd)
        kill_deadline = min(deadline, time.monotonic() + KILL_GRACE_SECONDS)
        while time.monotonic() < kill_deadline:
            reap_exited_children()
            try:
                updated = child_pidfds(supervisor_pid)
            except (OSError, SupervisorError):
                report["cleanupScanIncomplete"] = True
                scan_error = True
                time.sleep(POLL_INTERVAL_SECONDS)
                continue
            for pid, (ticks, fd) in updated.items():
                leaked = True
                if (pid, ticks) not in killed:
                    discovered.setdefault((pid, ticks), Identity(pid, ticks))
                    send_pinned(fd, Identity(pid, ticks), signal.SIGKILL, report["signals"])
                    killed.add((pid, ticks))
                os.close(fd)
            if not updated:
                break
            time.sleep(POLL_INTERVAL_SECONDS)

    # Reap all remaining children. A live child after escalation means the trial
    # cannot claim verified teardown; leave its identity in the receipt.
    reap_exited_children()
    try:
        final_children = child_pidfds(supervisor_pid)
    except (OSError, SupervisorError):
        report["cleanupScanIncomplete"] = True
        final_children = {}
        scan_error = True
    for pid, (ticks, fd) in final_children.items():
        leaked = True
        discovered[(pid, ticks)] = Identity(pid, ticks)
        report["survivors"].append(asdict(Identity(pid, ticks)))
        os.close(fd)
    report["observedChildren"] = [asdict(identity) for identity in sorted(discovered.values(), key=lambda item: (item.pid, item.start_ticks))]
    return leaked or bool(final_children), scan_error or bool(final_children)


def write_receipt(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--term-timeout-seconds", type=float, default=TERM_GRACE_SECONDS)
    parser.add_argument("--execution-timeout-seconds", type=float, default=180.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or any(arg in {"-c", "-e"} for arg in command[:1]):
        raise SupervisorError("one explicit driver command is required")
    if not math.isfinite(args.term_timeout_seconds) or args.term_timeout_seconds <= 0 or args.term_timeout_seconds > 30:
        raise SupervisorError("termination timeout must be within 0..30 seconds")
    if not math.isfinite(args.execution_timeout_seconds) or args.execution_timeout_seconds < 1 or args.execution_timeout_seconds > 3600:
        raise SupervisorError("execution timeout must be within 1..3600 seconds")

    # Refuse before spawning unless the required ownership primitives exist.
    enable_subreaper()
    initial_children = child_pidfds(os.getpid())
    preexisting_children = bool(initial_children)
    for _ticks, fd in initial_children.values():
        os.close(fd)
    if preexisting_children:
        raise SupervisorError("supervisor started with pre-existing children")
    try:
        probe_pidfd = os.pidfd_open(os.getpid(), 0)
        signal.pidfd_send_signal(probe_pidfd, 0, None, 0)
    except OSError as error:
        raise SupervisorError(f"pidfd signaling is unavailable (errno {error.errno})") from error
    finally:
        if "probe_pidfd" in locals():
            os.close(probe_pidfd)

    report: dict[str, Any] = {
        "schemaVersion": 1,
        "supervisorPid": os.getpid(),
        "subreaperEnabled": True,
        "signalAuthority": "wait-owned-direct-child-pidfd",
        "processTreeScansUsedForSignals": False,
        "commandExitCode": None,
        "driver": None,
        "signals": [],
        "observedChildren": [],
        "survivors": [],
        "cleanup": "running",
        "leakedDescendants": False,
    }
    cancelled: list[int] = []

    def request_stop(signum: int, _frame: Any) -> None:
        if not cancelled:
            cancelled.append(signum)
            report["cancellationSignal"] = signal.Signals(signum).name

    old_term = signal.signal(signal.SIGTERM, request_stop)
    old_int = signal.signal(signal.SIGINT, request_stop)
    old_chld = signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    process = None
    driver_pidfd = None
    driver_identity: Identity | None = None
    try:
        import subprocess

        process = subprocess.Popen(command, close_fds=True)
        driver_identity = proc_identity(process.pid)
        if driver_identity is None or driver_identity[0] != os.getpid():
            raise SupervisorError("driver did not become a direct supervisor child")
        driver_identity = Identity(process.pid, driver_identity[1])
        report["driver"] = asdict(driver_identity)
        driver_pidfd = os.pidfd_open(process.pid, 0)
        if proc_identity(process.pid) != (os.getpid(), driver_identity.start_ticks) or waitid_state(process.pid) == "absent":
            raise SupervisorError("driver identity changed while pinning")
        execution_deadline = time.monotonic() + args.execution_timeout_seconds
        driver_deadline = None
        driver_kill_deadline = None
        while process.poll() is None:
            if not cancelled and time.monotonic() >= execution_deadline:
                report["executionTimedOut"] = True
                report["terminationReason"] = "execution-timeout"
                cancelled.append(signal.SIGTERM)
            if cancelled and driver_deadline is None:
                signal.pidfd_send_signal(driver_pidfd, signal.SIGTERM, None, 0)
                report["signals"].append(asdict(SignalRecord(process.pid, driver_identity.start_ticks, "SIGTERM", True)))
                driver_deadline = time.monotonic() + args.term_timeout_seconds
            if driver_deadline is not None and driver_kill_deadline is None and time.monotonic() >= driver_deadline and process.poll() is None:
                signal.pidfd_send_signal(driver_pidfd, signal.SIGKILL, None, 0)
                report["signals"].append(asdict(SignalRecord(process.pid, driver_identity.start_ticks, "SIGKILL", True)))
                driver_kill_deadline = time.monotonic() + KILL_GRACE_SECONDS
            if driver_kill_deadline is not None and time.monotonic() >= driver_kill_deadline and process.poll() is None:
                raise SupervisorError("driver termination could not be confirmed")
            time.sleep(POLL_INTERVAL_SECONDS)
        report["commandExitCode"] = process.returncode
    except BaseException as error:
        report["driverError"] = type(error).__name__
        if process is not None and process.poll() is None and driver_pidfd is not None and driver_identity is not None:
            send_pinned(driver_pidfd, driver_identity, signal.SIGTERM, report["signals"])
            try:
                process.wait(timeout=args.term_timeout_seconds)
            except Exception:
                send_pinned(driver_pidfd, driver_identity, signal.SIGKILL, report["signals"])
                try:
                    process.wait(timeout=KILL_GRACE_SECONDS)
                except Exception:
                    pass
        elif process is not None and process.poll() is None:
            # Popen retains unreaped wait ownership of this exact direct child,
            # which keeps its PID from being reused until wait() completes.
            try:
                process.terminate()
                process.wait(timeout=args.term_timeout_seconds)
            except Exception:
                try:
                    process.kill()
                    process.wait(timeout=KILL_GRACE_SECONDS)
                except Exception:
                    pass
    finally:
        if driver_pidfd is not None:
            os.close(driver_pidfd)

    leaked_before_cleanup = False
    while True:
        # Keep this process as the subreaper until a complete scan proves that
        # no adopted descendants remain. The outer driver may time out and
        # detach, but it must never need to kill this final cleanup authority.
        report["cleanupScanIncomplete"] = False
        leaked, cleanup_uncertain = terminate_adopted_children(report)
        leaked_before_cleanup = leaked_before_cleanup or leaked
        report["leakedDescendants"] = leaked_before_cleanup
        report["cleanup"] = "uncertain" if cleanup_uncertain else ("terminated-leaked" if leaked_before_cleanup else "clean")
        report["cleanupOwnerRetained"] = cleanup_uncertain
        report["status"] = "passed" if report["cleanup"] == "clean" and not report.get("cleanupScanIncomplete") and report.get("commandExitCode") == 0 and not cancelled else "failed"
        try:
            write_receipt(args.receipt, report)
        except Exception as error:
            if cleanup_uncertain:
                report["receiptPublicationError"] = type(error).__name__
                time.sleep(POLL_INTERVAL_SECONDS)
                continue
            report["receiptPublicationError"] = type(error).__name__
            report["status"] = "failed"
            break
        if not cleanup_uncertain:
            break
        time.sleep(POLL_INTERVAL_SECONDS)
    # Receipt publication can block on fsync. If termination was requested
    # before that durable write completed, publish a failure receipt afterward.
    if cancelled and report["status"] == "passed":
        report["status"] = "failed"
        report["cancelledDuringReceiptPublication"] = True
        write_receipt(args.receipt, report)
    signal.signal(signal.SIGTERM, old_term)
    signal.signal(signal.SIGINT, old_int)
    signal.signal(signal.SIGCHLD, old_chld)
    if report["status"] != "passed":
        return 70
    return int(report["commandExitCode"] or 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"packaged process supervisor refused: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(78)
