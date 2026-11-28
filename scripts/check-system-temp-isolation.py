#!/usr/bin/env python3
"""Fail when a command's process tree writes to the system temporary directory (#2008).

The command runs in a private mount namespace whose /tmp is an empty observed directory
under build/. An inotify watcher on that directory records every entry the process tree
creates, including entries it deletes again, and the directory is listed after the command.
Any recorded creation or remaining entry fails the check. Because only this process tree can
see the observed directory, concurrent work on the host is not attributed to it.

The host /tmp is also listed recursively before and after, for context only: a change there
comes from a process outside the namespace, such as another build, Docker or a systemd service
the command asked to start, and is reported as unattributed without failing the check.

Isolation: as root, or with passwordless `sudo -n`, the namespace keeps real user and group IDs
(hosted CI). Otherwise an unprivileged user namespace maps only the current user, so files owned
by other users (root included) appear as the overflow user and setuid programs such as sudo do
not work inside; DECOMP_TEMP_CHECK_ISOLATION=sudo|userns|root forces a mode.

Limits: a command that hands work to a process started outside the namespace (an already-running
Gradle or Kotlin daemon, Docker, systemd) is not observed there, so run Gradle with --no-daemon.
The watcher adds watches to new subdirectories as they appear; a short-lived entry inside a new
subdirectory can be missed, but creating the subdirectory is itself recorded and fails the check.

Usage: scripts/check-system-temp-isolation.py [--label NAME] [--] [command [argument...]]
Default command: ./gradlew --no-daemon test -PciTestShard=core
Each invocation writes build/system-temp-isolation/<label>-<time>-<pid>/ with summary.json,
events.txt, remaining.txt, host-before.txt, host-after.txt and host-new.txt.
"""

import argparse
import ctypes
import datetime
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import struct
import subprocess
import sys
import threading
import time

REPOSITORY = Path(__file__).resolve().parent.parent
SYSTEM_TEMP = "/tmp"  # Fixed: HotSpot and most tools hard-code it; there is no override.
DEFAULT_COMMAND = ["./gradlew", "--no-daemon", "test", "-PciTestShard=core"]

IN_MODIFY, IN_ATTRIB, IN_MOVED_TO, IN_CREATE = 0x2, 0x4, 0x80, 0x100
IN_Q_OVERFLOW, IN_IGNORED, IN_ISDIR = 0x4000, 0x8000, 0x40000000
IN_NONBLOCK, IN_CLOEXEC = 0o4000, 0o2000000
WATCH_MASK = IN_CREATE | IN_MOVED_TO | IN_MODIFY | IN_ATTRIB
MS_REC, MS_SLAVE, MS_BIND = 0x4000, 1 << 19, 0x1000


def libc():
    return ctypes.CDLL(None, use_errno=True)


def list_tree(root):
    """Every path under root, relative, without following symbolic links; unreadable parts skipped."""
    entries = []
    for directory, names, files in os.walk(root, onerror=lambda error: None):
        for name in names + files:
            entries.append(os.path.relpath(os.path.join(directory, name), root))
    return sorted(entries)


class Watcher(threading.Thread):
    """Records creations anywhere below root with inotify, watching new subdirectories too."""

    def __init__(self, root):
        super().__init__(daemon=True)
        self.root = root
        self.events = []
        self.seen = set()
        self.overflow = False
        self.stopping = threading.Event()
        self.lib = libc()
        self.fd = self.lib.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.paths = {}
        self.watch(root)

    def record(self, event):
        if event not in self.seen:
            self.seen.add(event)
            self.events.append(event)

    def watch(self, directory):
        wd = self.lib.inotify_add_watch(self.fd, os.fsencode(directory), WATCH_MASK)
        if wd < 0:
            self.record(f"unwatchable {os.path.relpath(directory, self.root)}")
            return
        self.paths[wd] = directory
        # Entries created before the watch existed are recorded from a scan instead.
        if directory != self.root:
            for entry in list_tree(directory):
                self.record(f"present {os.path.relpath(os.path.join(directory, entry), self.root)}")
                if os.path.isdir(os.path.join(directory, entry)) and not os.path.islink(os.path.join(directory, entry)):
                    self.watch(os.path.join(directory, entry))

    def drain(self):
        while True:
            try:
                data = os.read(self.fd, 65536)
            except BlockingIOError:
                return
            offset = 0
            while offset < len(data):
                wd, mask, _cookie, length = struct.unpack_from("iIII", data, offset)
                name = data[offset + 16:offset + 16 + length].rstrip(b"\0").decode(errors="replace")
                offset += 16 + length
                if mask & IN_Q_OVERFLOW:
                    self.overflow = True
                    self.record("overflow (events were lost)")
                    continue
                if mask & IN_IGNORED or wd not in self.paths:
                    continue
                path = os.path.join(self.paths[wd], name) if name else self.paths[wd]
                relative = os.path.relpath(path, self.root)
                kind = "create" if mask & IN_CREATE else "move-in" if mask & IN_MOVED_TO else \
                    "modify" if mask & IN_MODIFY else "attrib"
                if relative == "." and kind == "attrib":
                    continue  # The bind mount itself can touch the root's attributes.
                self.record(f"{kind} {relative}")
                if mask & IN_ISDIR and mask & (IN_CREATE | IN_MOVED_TO):
                    self.watch(path)

    def run(self):
        while not self.stopping.is_set():
            select.select([self.fd], [], [], 0.2)
            self.drain()

    def stop(self):
        time.sleep(0.3)
        self.stopping.set()
        self.join()
        self.drain()
        os.close(self.fd)


def choose_isolation():
    forced = os.environ.get("DECOMP_TEMP_CHECK_ISOLATION")
    if forced:
        if forced not in ("root", "sudo", "userns"):
            sys.exit(f"unsupported DECOMP_TEMP_CHECK_ISOLATION: {forced}")
        return forced
    if os.geteuid() == 0:
        return "root"
    if shutil.which("sudo") and subprocess.run(["sudo", "-n", "true"], stdin=subprocess.DEVNULL,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        return "sudo"
    return "userns"


def enter(arguments):
    """Runs inside the new process: private mount namespace, observed /tmp, then the command."""
    lib = libc()
    if os.geteuid() == 0:
        os.unshare(os.CLONE_NEWNS)
    else:
        uid, gid = os.getuid(), os.getgid()
        os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
        Path("/proc/self/uid_map").write_text(f"{uid} {uid} 1")
        Path("/proc/self/setgroups").write_text("deny")
        Path("/proc/self/gid_map").write_text(f"{gid} {gid} 1")
    for source, target, flags in ((None, "/", MS_REC | MS_SLAVE),
                                  (arguments.observed, SYSTEM_TEMP, MS_BIND | MS_REC)):
        if lib.mount(os.fsencode(source) if source else b"none", os.fsencode(target), None, flags, None) != 0:
            error = ctypes.get_errno()
            sys.exit(f"mount {target} failed: {os.strerror(error)}")
    environment = dict(os.environ)
    if arguments.environment_pid:
        raw = Path(f"/proc/{arguments.environment_pid}/environ").read_bytes()
        environment = dict(entry.split("=", 1) for entry in os.fsdecode(raw).split("\0") if "=" in entry)
    if arguments.user is not None and os.geteuid() == 0 and arguments.uid != 0:
        os.setgroups(os.getgrouplist(arguments.user, arguments.gid))
        os.setresgid(arguments.gid, arguments.gid, arguments.gid)
        os.setresuid(arguments.uid, arguments.uid, arguments.uid)
    os.chdir(arguments.cwd)
    os.execvpe(arguments.command[0], arguments.command, environment)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--enter":
        parser = argparse.ArgumentParser()
        parser.add_argument("--enter", action="store_true")
        parser.add_argument("--observed", required=True)
        parser.add_argument("--cwd", required=True)
        parser.add_argument("--environment-pid", type=int)
        parser.add_argument("--user")
        parser.add_argument("--uid", type=int)
        parser.add_argument("--gid", type=int)
        parser.add_argument("command", nargs=argparse.REMAINDER)
        arguments = parser.parse_args()
        arguments.command = arguments.command[1:] if arguments.command[:1] == ["--"] else arguments.command
        enter(arguments)

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--label", default="check")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command[1:] if arguments.command[:1] == ["--"] else arguments.command
    command = command or DEFAULT_COMMAND
    if not all(character.isalnum() or character in "-_." for character in arguments.label):
        sys.exit("--label may contain only letters, digits, '-', '_' and '.'")

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report = REPOSITORY / "build/system-temp-isolation" / f"{arguments.label}-{stamp}-{os.getpid()}"
    observed = report / "observed-tmp"
    observed.mkdir(parents=True)
    observed.chmod(0o1777)  # Like /tmp, so tools that check its mode behave as they would there.
    isolation = choose_isolation()

    host_before = list_tree(SYSTEM_TEMP)
    (report / "host-before.txt").write_text("".join(f"{entry}\n" for entry in host_before))
    watcher = Watcher(str(observed))
    watcher.start()

    helper = [sys.executable, "-I", str(Path(__file__).resolve()), "--enter", "--observed", str(observed),
              "--cwd", os.getcwd()]
    if isolation == "sudo":
        user = pwd.getpwuid(os.getuid()).pw_name
        helper = ["sudo", "-n", "--"] + helper + ["--environment-pid", str(os.getpid()), "--user", user,
                                                  "--uid", str(os.getuid()), "--gid", str(os.getgid())]
    print(f"==> Observing {SYSTEM_TEMP} for ({isolation} namespace): {' '.join(command)}", flush=True)
    status = subprocess.run(helper + ["--"] + command).returncode

    watcher.stop()
    remaining = list_tree(str(observed))
    host_after = list_tree(SYSTEM_TEMP)
    host_new = sorted(set(host_after) - set(host_before))
    (report / "events.txt").write_text("".join(f"{event}\n" for event in watcher.events))
    (report / "remaining.txt").write_text("".join(f"{entry}\n" for entry in remaining))
    (report / "host-after.txt").write_text("".join(f"{entry}\n" for entry in host_after))
    (report / "host-new.txt").write_text("".join(f"{entry}\n" for entry in host_new))
    leaked = bool(watcher.events or remaining)
    summary = {
        "command": command, "isolation": isolation, "systemTemporaryDirectory": SYSTEM_TEMP,
        "commandExitStatus": status, "observedEvents": len(watcher.events), "eventsLost": watcher.overflow,
        "remainingEntries": len(remaining), "unattributedHostEntries": len(host_new),
        "result": "leak" if leaked else "clean",
    }
    (report / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    if leaked:
        print(f"==> The command wrote to {SYSTEM_TEMP}; see {report.relative_to(REPOSITORY)}", file=sys.stderr)
        for line in (watcher.events + [f"remaining {entry}" for entry in remaining])[:200]:
            print(f"  {line}", file=sys.stderr)
    else:
        print(f"==> No writes to {SYSTEM_TEMP} by the command's process tree")
    if host_new:
        print(f"==> {len(host_new)} unattributed new host {SYSTEM_TEMP} entries (outside the namespace; "
              f"not a failure): {report.relative_to(REPOSITORY)}/host-new.txt")
    if status != 0:
        return status
    return 1 if leaked else 0


if __name__ == "__main__":
    sys.exit(main())
