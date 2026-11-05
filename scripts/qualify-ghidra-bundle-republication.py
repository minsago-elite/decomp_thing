#!/usr/bin/env python3
"""Linux T3/T4 same-bundle qualification (#1903), never a mock qualification.

Requires an already-built installDist and a populated repository-owned Gradle cache.
Runs exactly three authored-input reconstructions and two task-local --rerun installs.
The init script observes the existing final publisher Action; it does not replace the
publisher implementation. Publication is per-file, NOT whole-bundle atomic.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid


WORKER = "decompengine.ghidra.BundledGhidraWorker"
MAX_ENTRIES = 25_000
MAX_FILE = 512 * 1024 * 1024
MAX_TREE = 4 * 1024 * 1024 * 1024
MAX_LOG = 4 * 1024 * 1024
MAX_SAMPLES = 180_000
MAX_TIMELINE_BYTES = 128 * 1024 * 1024
CASE_SECONDS = 600
INSTALL_SECONDS = 900
BARRIER_SECONDS = 120
HARNESS_SECONDS = 3000
POLL_SECONDS = 0.02
PUBLISHER_BLOCK = '''tasks.named<Sync>("installDist") {
    inputs.property("atomicGhidraBundlePublicationVersion", 1)
    preserve { include("libexec/ghidra", "libexec/ghidra/**") }
    eachFile { if (path.startsWith("libexec/ghidra/")) exclude() }
    doLast {
        publishGhidraBundle(project(":ghidra-bridge").layout.buildDirectory.dir("bundle").get().asFile.toPath(),
            destinationDir.resolve("libexec/ghidra").toPath())
    }
}'''


class Refusal(RuntimeError):
    """Static diagnostics only: do not serialize arbitrary process/environment text."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def write_json(path, value):
    data = encode(value) + b"\n"
    require(len(data) <= 32 * 1024 * 1024, "evidence record exceeds bound")
    with path.open("xb") as stream:
        stream.write(data)


def bounded_read(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "input exceeds byte bound")
    return data


def file_identity(value):
    # Reads may update atime; ctime/mtime and the remaining identity must be stable.
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def stable_file(path):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "refuse linked or nonregular file")
    require(before.st_size <= MAX_FILE, "file exceeds byte bound")
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(file_identity(os.fstat(fd)) == file_identity(before), "file changed before read")
        count = 0
        while block := os.read(fd, 1024 * 1024):
            count += len(block)
            require(count <= before.st_size, "file grew while reading")
            h.update(block)
        require(count == before.st_size and file_identity(os.fstat(fd)) == file_identity(before)
                and file_identity(path.lstat()) == file_identity(before),
                "file changed while reading")
    finally:
        os.close(fd)
    return {"type": "F", "sha256": h.hexdigest(), "bytes": count,
            "mode": stat.S_IMODE(before.st_mode), "inode": before.st_ino, "device": before.st_dev}


SOURCE_DRIVERS = ("scripts/qualify-ghidra-bundle-republication.py",
                  "scripts/test-ghidra-bundle-republication.py")


def source_name(raw):
    require(0 < len(raw) <= 4096 and not raw.startswith(b"/") and b"\\" not in raw
            and all(byte >= 32 and byte != 127 for byte in raw), "unsafe source path")
    parts = raw.split(b"/")
    require(len(parts) <= 40 and all(part not in (b"", b".", b"..") and part.lower() != b".git"
                                   for part in parts), "unsafe source path")
    return os.fsdecode(raw)


def source_index(data):
    """Parse the authoritative index, including gitlinks; never flatten conflicts."""
    require(len(data) <= MAX_LOG and (not data or data.endswith(b"\0")), "malformed or oversized source index")
    records = data[:-1].split(b"\0") if data else []
    require(len(records) <= MAX_ENTRIES, "tracked source count exceeds bound")
    entries = {}
    for record in records:
        match = re.fullmatch(rb"(100644|100755|120000|160000) ([0-9a-f]{40}|[0-9a-f]{64}) 0\t(.+)", record)
        require(match is not None, "malformed source index mode/stage/record")
        mode, oid, raw = match.groups()
        require(any(byte != ord("0") for byte in oid), "invalid source index object")
        name = source_name(raw)
        require(name not in entries, "duplicate source index path")
        entries[name] = {"mode": mode.decode(), "object": oid.decode()}
    # A file, symlink or gitlink cannot also be an ancestor of another entry.
    for name in entries:
        require(not any(parent.as_posix() in entries for parent in Path(name).parents if parent != Path(".")),
                "conflicting source index paths")
    return entries


def source_ancestors(root, name, missing=False):
    """Never resolve through symlink ancestors, including for an absent gitlink."""
    require(root.is_absolute() and root.resolve() == root, "source root uses symlink")
    pins = []
    for path in (root, *(root / parent for parent in reversed(Path(name).parents) if parent != Path("."))):
        try:
            value = path.lstat()
        except FileNotFoundError:
            require(missing, "missing source ancestor")
            pins.append(None)
            continue
        require(stat.S_ISDIR(value.st_mode), "linked or non-directory source ancestor")
        # Ancestor timestamps/link counts may change as qualification writes build/.
        pins.append([value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid])
    return pins


class SourcePins:
    """Bounded source snapshots through Harness.command (including its run evidence).

    Initialized gitlinks attest commit + clean Git state, NOT a complete content
    hash. Their index digest and recursive gitlink states make that scope explicit.
    """

    def __init__(self, root, command, phase):
        self.root, self.command, self.phase = root, command, phase
        self.commands = self.gitlinks = self.index_bytes = self.file_bytes = 0

    def git(self, root, *args):
        self.commands += 1
        return self.command(f"source-{self.phase}-{self.commands:04d}",
                            ["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                             "-c", "core.untrackedCache=false", "-C", str(root), *args], 60)

    def index(self, root):
        data = self.git(root, "ls-files", "--stage", "-z")
        self.index_bytes += len(data)
        require(self.index_bytes <= 4 * MAX_LOG, "aggregate source index exceeds bound")
        return source_index(data)

    def pin(self, root, name, entry, depth=0):
        mode = entry["mode"]
        ancestors = source_ancestors(root, name, missing=mode == "160000")
        path = root / name
        try:
            before = path.lstat()
        except FileNotFoundError:
            require(mode == "160000", "tracked source missing")
            before = None
        if mode == "160000":
            observed = self.gitlink(path, before, entry["object"], depth)
        elif mode == "120000":
            require(stat.S_ISLNK(before.st_mode), "tracked symlink changed type")
            target = os.readlink(path)
            require(len(os.fsencode(target)) <= 4096, "source symlink target exceeds bound")
            observed = {"type": "L", "target": target, "mode": stat.S_IMODE(before.st_mode)}
        else:
            require(mode in ("100644", "100755"), "unsupported source mode")
            observed = stable_file(path)
            self.file_bytes += observed["bytes"]
            require(self.file_bytes <= MAX_TREE, "tracked source bytes exceed bound")
        try:
            after = path.lstat()
        except FileNotFoundError:
            after = None
        before_id = list(file_identity(before)) if before is not None else None
        after_id = list(file_identity(after)) if after is not None else None
        require(before_id == after_id, "source changed while pinning")
        require(ancestors == source_ancestors(root, name, missing=mode == "160000"),
                "source ancestors changed while pinning")
        return {"index": entry, "identity": before_id, "ancestors": ancestors, **observed}

    def gitlink(self, path, before, commit, depth):
        self.gitlinks += 1
        require(self.gitlinks <= 128 and depth < 16, "source gitlink count/depth exceeds bound")
        result = {"type": "G", "index_commit": commit, "content_hash_scope": "none"}
        if before is None:
            return {**result, "state": "absent-uninitialized"}
        require(stat.S_ISDIR(before.st_mode), "gitlink is linked or non-directory")
        with os.scandir(path) as children:
            empty = next(children, None) is None
        if empty:
            return {**result, "state": "empty-uninitialized"}
        # An empty/non-repository child must never inherit the parent's Git root.
        require(self.git(path, "rev-parse", "--show-toplevel") == os.fsencode(path) + b"\n",
                "gitlink is not its own repository root")
        marker = path / ".git"
        marker_before = marker.lstat()
        require(stat.S_ISREG(marker_before.st_mode) or stat.S_ISDIR(marker_before.st_mode),
                "gitlink repository marker is linked or nonregular")
        marker_pin = (stable_file(marker) if stat.S_ISREG(marker_before.st_mode)
                      else {"type": "D"})
        head = self.git(path, "rev-parse", "--verify", "HEAD")
        require(head == commit.encode() + b"\n", "gitlink HEAD differs from index commit")
        index = self.index(path)
        status = self.git(path, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none")
        require(status == b"", "gitlink has dirty tracked/untracked/submodule state")
        nested = {name: self.pin(path, name, entry, depth + 1) for name, entry in index.items()
                  if entry["mode"] == "160000"}
        require(self.git(path, "rev-parse", "--verify", "HEAD") == head and self.index(path) == index,
                "gitlink HEAD/index changed while pinning")
        require(self.git(path, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none") == status,
                "gitlink status changed while pinning")
        require(file_identity(marker.lstat()) == file_identity(marker_before), "gitlink repository marker changed")
        return {**result, "state": "initialized", "repository_root": str(path), "head": commit,
                "attestation": "matching HEAD/index commit and clean tracked/untracked/submodule Git status",
                "repository_marker": {**marker_pin, "identity": list(file_identity(marker_before))},
                "status_porcelain_hex": status.hex(), "index_entries": len(index),
                "index_sha256": digest(encode(index)), "gitlinks": nested}

    def snapshot(self):
        index = self.index(self.root)
        pins = {name: self.pin(self.root, name, entry) for name, entry in index.items()}
        # Keep the pre-commit untracked-driver protection without replacing index metadata.
        drivers = {}
        for name in SOURCE_DRIVERS:
            if name in index:
                require(index[name]["mode"] in ("100644", "100755"), "driver must be a regular file")
            else:
                drivers[name] = self.pin(self.root, name, {"mode": "100644", "object": None})
        require(self.index(self.root) == index, "source index changed while pinning")
        return {"schema": "mode-aware-source-pins-v1", "index": index, "tracked": pins,
                "untracked_drivers": drivers}


def verify_source_pins(before, after):
    require(before == after, "source index or pins changed during qualification")


def inventory(root):
    """No symlinks/special files; include root and empty directories, not just files."""
    entries = {}
    total = 0

    def visit(path, depth=0):
        nonlocal total
        require(depth <= 40 and len(entries) < MAX_ENTRIES, "inventory entry/depth bound exceeded")
        attributes = path.lstat()
        key = path.relative_to(root).as_posix()
        if stat.S_ISDIR(attributes.st_mode):
            entries[key] = {"type": "D", "mode": stat.S_IMODE(attributes.st_mode),
                            "inode": attributes.st_ino, "device": attributes.st_dev}
            with os.scandir(path) as iterator:
                names = []
                for entry in iterator:
                    require(len(names) < MAX_ENTRIES, "directory entry bound exceeded")
                    names.append(entry.name)
            for name in sorted(names):
                visit(path / name, depth + 1)
            require(file_identity(path.lstat()) == file_identity(attributes), "directory changed during inventory")
        else:
            entries[key] = stable_file(path)
            total += entries[key]["bytes"]
            require(total <= MAX_TREE, "inventory byte bound exceeded")

    visit(root)
    return {"entries": entries, "sha256": digest(encode(entries)), "total_bytes": total}


def contents(inv):
    return {name: {k: v for k, v in entry.items() if k not in ("inode", "device")}
            for name, entry in inv["entries"].items()}


def subtree(inv, prefix):
    entries = {("." if name == prefix else name[len(prefix) + 1:]): entry
               for name, entry in inv["entries"].items() if name == prefix or name.startswith(prefix + "/")}
    require(entries.get(".", {}).get("type") == "D", "installed bundle directory missing")
    return {"entries": entries, "sha256": digest(encode(entries)),
            "total_bytes": sum(entry.get("bytes", 0) for entry in entries.values())}


def verify_snapshot(baseline, current):
    require(contents(current["staged"]) == contents(current["installed"]),
            "staged/installed full directory-file inventory differs")
    require(contents(baseline["staged"]) == contents(current["staged"]), "staged bundle changed")
    require(contents(baseline["installed"]) == contents(current["installed"]), "installed bundle changed")
    for name, before in baseline["installed"]["entries"].items():
        if before["type"] == "F":
            require(before == current["installed"]["entries"].get(name), "installed regular-file inode/bytes/mode changed")


def parse_stat(data):
    # comm can contain ')' and whitespace. starttime is field 22, ppid field 4.
    end = data.rfind(")")
    fields = data[end + 2:].split()
    require(end > 0 and len(fields) >= 20, "invalid proc identity")
    return {"pid": int(data[:data.index(" ")]), "ppid": int(fields[1]),
            "start_ticks": int(fields[19]), "state": fields[0]}


def proc_stat(pid):
    try:
        return parse_stat(bounded_read(Path(f"/proc/{pid}/stat"), 8192).decode())
    except (FileNotFoundError, ProcessLookupError):
        return None


def identity(value):
    return (value["pid"], value["start_ticks"]) if value else None


def same_live(a, b):
    return bool(a and b and identity(a) == identity(b) and a["ppid"] == b["ppid"]
                and a["state"] not in ("Z", "X") and b["state"] not in ("Z", "X"))


def worker_main(command):
    """Parse only an owned Java command; never emit its arguments to evidence."""
    args = command.rstrip(b"\0").split(b"\0")
    if not args or Path(os.fsdecode(args[0])).name != "java":
        return False
    index = 1
    paired = {b"-cp", b"-classpath", b"--class-path", b"--module-path", b"-p",
              b"--add-opens", b"--add-exports", b"--add-modules", b"--enable-native-access"}
    while index < len(args):
        arg = args[index]
        if arg in paired:
            index += 2
        elif arg.startswith((b"-D", b"-X", b"-ea", b"--add-opens=", b"--add-exports=",
                             b"--enable-native-access=", b"--add-modules=")):
            index += 1
        else:
            return arg == WORKER.encode()
    return False


class OwnedTree:
    """Discover through owned /proc/<pid>/task/*/children, never scan global PIDs.

    Retain pidfds for teardown even when a known descendant becomes orphaned.
    Discovery and worker proof require stable parent/child start identities.
    """

    def __init__(self, root_pid):
        root = proc_stat(root_pid)
        require(root is not None, "owned process exited before authentication")
        self.root = identity(root)
        self.known = {}
        self.add(root)

    def add(self, entry):
        key = identity(entry)
        if key in self.known:
            return
        require(len(self.known) < 512, "owned process count exceeds bound")
        fd = os.pidfd_open(entry["pid"])
        again = proc_stat(entry["pid"])
        if not same_live(entry, again):
            os.close(fd)
            return
        self.known[key] = fd

    def sample(self, workers=False):
        found = []
        visited = set()

        def walk(key, chain, depth, cli_chain):
            if key in visited:
                return
            visited.add(key)
            require(depth < 32, "owned process depth exceeds bound")
            before = proc_stat(key[0])
            if identity(before) != key or before["state"] in ("Z", "X"):
                return
            if chain and before["ppid"] != chain[-1]["pid"]:
                return
            lower = time.monotonic_ns()
            try:
                children = set()
                task_dir = Path(f"/proc/{key[0]}/task")
                with os.scandir(task_dir) as tids:
                    count = 0
                    for tid in tids:
                        count += 1
                        require(count <= 2048, "owned thread count exceeds bound")
                        try:
                            raw = bounded_read(Path(tid.path) / "children", 65536)
                            children.update(int(item) for item in raw.split())
                            require(len(children) <= 512, "owned child count exceeds bound")
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                is_worker = False
                if workers and cli_chain and chain:
                    command = bounded_read(Path(f"/proc/{key[0]}/cmdline"), 256 * 1024)
                    is_worker = worker_main(command) and Path(os.readlink(f"/proc/{key[0]}/exe")).name == "java"
                upper = time.monotonic_ns()
                after = proc_stat(key[0])
                if not same_live(before, after):
                    return
                # Authenticate every ancestor again after inspecting the child.
                if any(not same_live(parent, proc_stat(parent["pid"])) for parent in chain):
                    return
                if is_worker:
                    found.append({"pid": key[0], "start_ticks": key[1], "lo_ns": lower, "hi_ns": upper,
                                  "ancestors": [{k: p[k] for k in ("pid", "ppid", "start_ticks")} for p in chain]})
                for child_pid in sorted(children):
                    child = proc_stat(child_pid)
                    if child and child["ppid"] == key[0] and same_live(before, proc_stat(key[0])):
                        self.add(child)
                        if identity(child) in self.known:
                            walk(identity(child), chain + [before], depth + 1, cli_chain)
            except (FileNotFoundError, ProcessLookupError):
                return

        walk(self.root, [], 0, True)
        # Retained pidfds authenticate already-owned descendants after reparenting.
        # Discover their children for teardown, but never count these detached
        # chains as CLI-worker publication evidence.
        for key in list(self.known):
            walk(key, [], 0, False)
        return found

    def alive(self):
        result = []
        for key in self.known:
            current = proc_stat(key[0])
            if identity(current) == key and current["state"] not in ("Z", "X"):
                result.append(key)
        return result

    def cleanup(self):
        outcomes = []
        discovery_errors = []

        def discover():
            try:
                self.sample(workers=False)
            except Exception as error:
                if type(error).__name__ not in discovery_errors:
                    discovery_errors.append(type(error).__name__)

        # No process group signals: only authenticated pidfds for owned identities.
        for sig, seconds in ((signal.SIGTERM, 3), (signal.SIGKILL, 2)):
            discover()
            for key in self.alive():
                try:
                    signal.pidfd_send_signal(self.known[key], sig)
                    outcomes.append({"pid": key[0], "start_ticks": key[1], "signal": sig.name})
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + seconds
            while self.alive() and time.monotonic() < deadline:
                discover()
                time.sleep(0.02)
        remaining = self.alive()
        for fd in self.known.values():
            os.close(fd)
        self.known.clear()
        return {"signals": outcomes, "survivors": remaining, "discovery_errors": discovery_errors,
                "complete": not remaining and not discovery_errors}


def validate_markers(markers, source_hash):
    require([m.get("event") for m in markers] == ["ready", "begin", "end"],
            "publication markers missing, duplicate or out of order")
    ready, begin, end = markers
    require(0 < ready["ns"] < begin["ns"] <= end["ns"], "publication timestamps out of order")
    require(end.get("success") is True, "original publisher action failed")
    selection = ready["selection"]
    require(selection["build_sha256"] == source_hash and selection["index"] == selection["count"] - 1,
            "publisher selection/source mismatch")
    require(selection["count"] >= 2 and len(selection["actions"]) == selection["count"] and
            selection["publisher_candidates"] == [selection["index"]], "ambiguous publisher action selection")
    require([a["index"] for a in selection["actions"]] == list(range(selection["count"])),
            "captured action order differs")
    selected = selection["actions"][-1]
    require(selected["implementation"].startswith("Build_gradle$") and
            re.fullmatch("[0-9a-f]{64}", selected.get("class_sha256") or ""),
            "selected publisher implementation is not pinned")
    return begin["ns"], end["ns"]


def overlap_proofs(samples, begin, end):
    groups = {}
    for sample in samples:
        groups.setdefault((sample["pid"], sample["start_ticks"]), []).append(sample)
    proofs = []
    for (pid, ticks), observations in groups.items():
        # Conservative guaranteed lifetime: after first read, before last read.
        lo = min(s["hi_ns"] for s in observations)
        hi = max(s["lo_ns"] for s in observations)
        # Markers bracket execute(), including marker I/O and scheduling overhead.
        # Spanning the whole bracket proves the worker was alive during the action;
        # merely intersecting it could count time before execute() actually starts.
        if lo <= begin <= end <= hi:
            proofs.append({"pid": pid, "start_ticks": ticks, "observed_alive_ns": [lo, hi],
                           "publisher_ns": [begin, end], "spans_begin": True, "spans_bracket": True})
    return proofs


def jar_classification(before, after, task):
    if task["did_work"] and not task["skipped"]:
        return "jar-rebuilt"
    if task["skip_message"] == "FROM-CACHE":
        return "jar-restored-from-cache"
    return "unchanged" if before == after else "jar-republished"


# Reflection is restricted to Gradle's TaskActionWrapper.action. The unique final
# action must have a build-script class whose constant pool references the publisher.
# Its entire class bytes and the full build script are pinned. Any unfamiliar wrapper
# or changed source/action arrangement refuses qualification, instead of guessing.
INIT_SCRIPT = r'''
import groovy.json.JsonOutput
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import org.gradle.api.Action

def sha = { byte[] bytes -> MessageDigest.getInstance("SHA-256").digest(bytes).encodeHex().toString() }
def root = new File(@ROOT@)
def out = new File(@OUT@)
def expected = @HASH@
def marker = { Map value ->
    Files.writeString(new File(out, value.event + ".json").toPath(), JsonOutput.toJson(value),
        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
}
gradle.projectsEvaluated {
    if (gradle.rootProject.projectDir.canonicalFile != root.canonicalFile) throw new GradleException("qualification root mismatch")
    if (sha(new File(root, "build.gradle.kts").bytes) != expected) throw new GradleException("qualification source changed")
    def task = gradle.rootProject.tasks.getByName("installDist")
    def original = new ArrayList(task.actions)
    def candidates = []
    def descriptions = []
    original.eachWithIndex { action, index ->
        def impl = action
        def wrapper = impl.class.name
        if (wrapper == 'org.gradle.api.internal.AbstractTask$TaskActionWrapper') {
            def field = impl.class.getDeclaredField("action")
            field.setAccessible(true)
            impl = field.get(impl)
        }
        def name = impl.class.name
        byte[] bytes = null
        def resource = '/' + name.replace('.', '/') + '.class'
        impl.class.getResourceAsStream(resource)?.withCloseable { stream -> bytes = stream.readNBytes(1048577) }
        if (bytes != null && bytes.length > 1048576) throw new GradleException("action class exceeds bound")
        def referencesPublisher = bytes != null && name.startsWith('Build_gradle$') &&
            new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1).contains('publishGhidraBundle')
        if (referencesPublisher) candidates.add(index)
        descriptions.add([index: index, wrapper: wrapper, implementation: name,
                          class_sha256: bytes == null ? null : sha(bytes)])
        if (referencesPublisher) Files.write(new File(out, "publisher-action.class").toPath(), bytes, StandardOpenOption.CREATE_NEW)
    }
    int last = original.size() - 1
    if (original.size() < 2 || candidates != [last]) throw new GradleException("cannot prove unique final publisher action")
    def selected = original[last]
    def selection = [build_sha256: expected, index: last, count: original.size(),
                     publisher_candidates: candidates, actions: descriptions]
    def captured = null
    Action wrapped = { runningTask ->
        if (task.actions.size() != captured.size() ||
            (0..<captured.size()).any { !task.actions[it].is(captured[it]) }) {
            throw new GradleException("installDist actions changed before publication")
        }
        if (sha(new File(root, "build.gradle.kts").bytes) != expected) throw new GradleException("qualification source changed")
        marker([event: "ready", ns: System.nanoTime(), selection: selection])
        long deadline = System.nanoTime() + 120000000000L
        def release = new File(out, "release")
        while (!release.exists()) {
            if (System.nanoTime() > deadline) throw new GradleException("owned-worker publication barrier timed out")
            Thread.sleep(10)
        }
        if (release.text != "owned-worker-observed\n") throw new GradleException("invalid barrier release")
        boolean success = false
        marker([event: "begin", ns: System.nanoTime()])
        try {
            selected.execute(runningTask)
            success = true
        } finally {
            marker([event: "end", ns: System.nanoTime(), success: success])
        }
    } as Action
    def replacement = new ArrayList(original)
    replacement[last] = wrapped
    task.setActions(replacement)
    // Gradle wraps Actions passed to setActions; capture those wrappers for the
    // final graph check, preserving every original action and its order inside.
    captured = new ArrayList(task.actions)
    gradle.taskGraph.whenReady {
        if (task.actions.size() != captured.size() ||
            (0..<captured.size()).any { !task.actions[it].is(captured[it]) }) {
            throw new GradleException("installDist actions changed after capture")
        }
    }
    gradle.taskGraph.afterTask { completed, state ->
        if (completed.path == ':jar') {
            def skip = state.skipMessage
            marker([event: 'jar-task', ns: System.nanoTime(), path: completed.path,
                    did_work: state.didWork, skipped: state.skipped, up_to_date: state.upToDate,
                    skip_message: skip in [null, 'UP-TO-DATE', 'FROM-CACHE', 'NO-SOURCE', 'SKIPPED'] ? skip : 'OTHER',
                    success: state.failure == null])
        }
    }
}
'''


def make_init(root, action_dir, source_hash):
    text = bounded_read(root / "build.gradle.kts", 2 * 1024 * 1024).decode()
    require(text.count(PUBLISHER_BLOCK) == 1 and text.count('tasks.named<Sync>("installDist")') == 1,
            "unsupported installDist publisher source layout")
    return (INIT_SCRIPT.replace("@ROOT@", json.dumps(str(root)))
            .replace("@OUT@", json.dumps(str(action_dir))).replace("@HASH@", json.dumps(source_hash)))


class Run:
    def __init__(self, label, command, root, attempt, env, timeout):
        self.label = label
        self.started = time.monotonic_ns()
        self.deadline = time.monotonic() + timeout
        self.log_path = attempt / (label + ".log")
        self.log = self.log_path.open("xb")
        self.size = 0
        try:
            self.process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        except BaseException:
            self.log.close()
            raise
        try:
            self.tree = OwnedTree(self.process.pid)
        except BaseException:
            # This direct, unreaped child cannot have its PID reused. Authenticate
            # with a pidfd before signaling even on initialization failure.
            fd = os.pidfd_open(self.process.pid)
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
                self.process.wait(timeout=2)
            finally:
                os.close(fd)
                self.process.stdout.close()
                self.log.close()
            raise
        self.selector = selectors.DefaultSelector()
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.record = {"label": label, "command": command, "started_ns": self.started,
                       "root": list(self.tree.root), "log": self.log_path.name, "exit_code": None}

    def pending(self):
        return (self.process.poll() is None or bool(self.selector.get_map())
                or bool(self.tree.alive()))

    def pump(self):
        for key, _ in self.selector.select(0):
            data = os.read(key.fd, 65536)
            if not data:
                self.selector.unregister(key.fileobj)
            else:
                remaining = max(0, MAX_LOG - self.size)
                self.log.write(data[:remaining])
                self.size += len(data)
                require(self.size <= MAX_LOG, "process output exceeded bound")
        self.log.flush()
        status = self.process.poll()
        require(not self.pending() or time.monotonic() <= self.deadline, "owned process exceeded deadline")
        self.record["exit_code"] = status
        if status is not None:
            self.record["finished_ns"] = time.monotonic_ns()
        return status

    def close(self):
        cleanup = self.tree.cleanup()
        try:
            self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            cleanup["complete"] = False
        # Bounded final drain after all owned writers have been torn down.
        for _ in range(MAX_LOG // 65536 + 1):
            if not self.selector.get_map():
                break
            try:
                self.pump()
            except Refusal:
                break
        self.selector.close()
        self.process.stdout.close()
        self.log.close()
        self.record.update(exit_code=self.process.returncode, log_bytes=min(self.size, MAX_LOG),
                           log_sha256=stable_file(self.log_path)["sha256"], cleanup=cleanup)
        return cleanup


def contained(path, root):
    path = Path(path).absolute()
    require(path.is_relative_to(root) and path.resolve() == path, "path escapes repository or uses symlink")
    return path


def environment(root, attempt):
    # No inherited credentials, agent selectors, bundle overrides, or GHIDRA_HOME.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    java_home = Path(os.environ["JAVA_HOME"]).resolve()
    require((java_home / "bin/java").is_file(), "JAVA_HOME lacks Java")
    env["JAVA_HOME"] = str(java_home)
    cache = contained(os.environ.get("GRADLE_USER_HOME", root / "build/gradle-user-home"), root)
    require(cache.is_dir(), "repository Gradle cache must be populated by prior CI build")
    env["GRADLE_USER_HOME"] = str(cache)
    for directory in ("home", "tmp", "cache"):
        (attempt / directory).mkdir()
    # Do not set HOME. Native helpers get explicit repo-owned cache/temp paths;
    # Java parents and children inherit the three approved directory properties.
    env.update(TMPDIR=str(attempt / "tmp"), TMP=str(attempt / "tmp"), TEMP=str(attempt / "tmp"),
               XDG_CACHE_HOME=str(attempt / "cache"), XDG_CONFIG_HOME=str(attempt / "home"),
               XDG_DATA_HOME=str(attempt / "home"), NPM_CONFIG_CACHE=str(root / "build/npm-download-cache"),
               PYTHONPYCACHEPREFIX=str(attempt / "cache/python"))
    options = (f'-Duser.home={attempt / "home"} -Djava.io.tmpdir={attempt / "tmp"} '
               f'-Djna.tmpdir={attempt / "tmp"} -XX:-UsePerfData')
    require(not any(c.isspace() for c in str(attempt)), "JVM property path contains whitespace")
    env["JAVA_TOOL_OPTIONS"] = options
    return env


class Harness:
    def __init__(self, root):
        self.root = root
        parent = contained(root / "build/qualification/ghidra-bundle-republication", root)
        parent.mkdir(parents=True, exist_ok=True)
        self.attempt = parent / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:12])
        self.attempt.mkdir(mode=0o700)
        self.runs = []
        self.samples = []
        self.rounds = 0
        self.timeline_bytes = 0
        self.baseline = None
        self.evidence = {"schema": "ghidra-bundle-republication-v1", "status": "FAIL",
                         "scope": "same-bundle per-file publication; not whole-bundle atomic; not #1789 reproducibility",
                         "fixed_cases": ["baseline", "publication-1", "publication-2"], "cases": [],
                         "publications": [], "snapshots": [], "processes": [], "cleanup": [],
                         "bounds": {"case_seconds": CASE_SECONDS, "install_seconds": INSTALL_SECONDS,
                                    "barrier_seconds": BARRIER_SECONDS, "log_bytes_each": MAX_LOG,
                                    "harness_seconds": HARNESS_SECONDS, "attempt_bytes": MAX_TREE,
                                    "timeline_samples": MAX_SAMPLES, "timeline_bytes": MAX_TIMELINE_BYTES}}
        self.timeline = (self.attempt / "observations.jsonl").open("xb")
        self.next_disk_check = 0

    def start(self, label, command, timeout):
        run = Run(label, command, self.root, self.attempt, self.env, timeout)
        self.runs.append(run)
        self.evidence["processes"].append(run.record)
        return run

    def tick(self, active, cli=None):
        lower = time.monotonic_ns()
        observed = []
        for run in active:
            samples = run.tree.sample(workers=run is cli)
            for sample in samples:
                sample["case"] = run.label
                require(len(self.samples) < MAX_SAMPLES, "observation timeline bound exceeded")
                self.samples.append(sample)
            observed.extend(samples)
            run.pump()
        self.rounds += 1
        row = encode({"lo_ns": lower, "hi_ns": time.monotonic_ns(), "workers": observed,
                      "roots": [{"label": r.label, "identity": list(r.tree.root),
                                 "known": [list(k) for k in r.tree.known]} for r in active]}) + b"\n"
        self.timeline_bytes += len(row)
        require(self.rounds <= MAX_SAMPLES and self.timeline_bytes <= MAX_TIMELINE_BYTES,
                "observation timeline exceeds bound")
        self.timeline.write(row)
        self.timeline.flush()
        if time.monotonic() >= self.next_disk_check:
            self.check_disk()
            self.next_disk_check = time.monotonic() + 2
        time.sleep(POLL_SECONDS)
        return observed

    def check_disk(self):
        total = count = 0
        for directory, dirs, files in os.walk(self.attempt, followlinks=False):
            for name in dirs + files:
                attrs = (Path(directory) / name).lstat()
                require(stat.S_ISDIR(attrs.st_mode) or stat.S_ISREG(attrs.st_mode),
                        "attempt contains linked or special output")
                count += 1
                total += attrs.st_size
                require(count <= 100_000 and total <= MAX_TREE and attrs.st_size <= MAX_FILE,
                        "attempt output exceeds filesystem bound")

    def wait(self, run, timeout_label=None):
        while run.pending():
            self.tick([run])
        require(run.process.returncode == 0, timeout_label or "required command failed")

    def command(self, label, command, timeout=60):
        run = self.start(label, command, timeout)
        self.wait(run)
        return bounded_read(run.log_path, MAX_LOG)

    def snapshot(self, label):
        install = contained(self.root / "build/install/llm_bin_patch", self.root)
        staged = contained(self.root / "ghidra-bridge/build/bundle", self.root)
        jars = sorted((install / "lib").glob("llm-bin-patch-*.jar"))
        require(len(jars) == 1, "cannot select unique application JAR")
        runtime = inventory(install)
        value = {"staged": inventory(staged),
                 "installed": subtree(runtime, "libexec/ghidra"), "installed_runtime": runtime,
                 "application_jar": stable_file(jars[0]),
                 "application_jar_path": str(jars[0].relative_to(self.root)), "time_ns": time.monotonic_ns()}
        entries = value["installed"]["entries"]
        explicit = [n for n in entries if n == "bundle.sha256" or Path(n).name == "mfc140u.exports"]
        require("bundle.sha256" in explicit and len(explicit) >= 2, "manifest or raced exports missing")
        value["explicit_pins"] = {n: entries[n] for n in explicit}
        path = self.attempt / (label + ".snapshot.json")
        write_json(path, value)
        self.evidence["snapshots"].append({"label": label, "path": path.name, "sha256": stable_file(path)["sha256"],
                                           "installed_digest": value["installed"]["sha256"]})
        return value

    def reconstruct(self, label):
        output = self.attempt / (label + "-output")
        require(not output.exists(), "reconstruction output must be fresh")
        cli = contained(self.root / "build/install/llm_bin_patch/bin/llm_bin_patch", self.root)
        run = self.start(label, [str(cli), "reconstruct", str(self.attempt / "hello_world"),
                                 "--output", str(output), "--evidence-only"], CASE_SECONDS)
        self.evidence["cases"].append({"case": label, "status": "RUNNING", "output": output.name})
        return run, output

    def finish_case(self, run, output):
        log = bounded_read(run.log_path, MAX_LOG)
        class_failures = [name for name in (b"ZipException", b"NoClassDefFoundError", b"ClassNotFoundException",
                                           b"ClassFormatError", b"ExceptionInInitializerError", b"VerifyError")
                          if name in log]
        self.evidence["cases"][-1]["classloading_failures"] = [name.decode() for name in class_failures]
        require(not class_failures, "classloading/ZIP failure remains #1834/#1842; no waiver")
        require(run.process.returncode == 0, "reconstruction failed; classloading/ZIP failures remain #1834/#1842")
        workers = [s for s in self.samples if s["case"] == run.label]
        require(workers, "reconstruction has no authenticated bundled-worker observation")
        manifests = list(output.glob("**/source_tree_manifest.json"))
        require(1 <= len(manifests) <= 8, "reconstruction source manifest missing or ambiguous")
        pins = {str(p.relative_to(self.attempt)): stable_file(p) for p in manifests}
        self.evidence["cases"][-1].update(status="PASS", manifest_pins=pins, worker_samples=len(workers))

    def publication(self, number, source_hash):
        action_dir = self.attempt / f"publication-{number}-action"
        action_dir.mkdir()
        init = action_dir / "observe.init.gradle"
        init.write_text(make_init(self.root, action_dir, source_hash))
        record = {"number": number, "directory": action_dir.name, "init_sha256": stable_file(init)["sha256"],
                  "status": "RUNNING", "overlap": []}
        self.evidence["publications"].append(record)
        gradle = self.start(f"install-{number}", [str(self.root / "gradlew"), "--no-daemon", "--offline",
                            "--init-script", str(init), "installDist", "--rerun"], INSTALL_SECONDS)
        while not (action_dir / "ready.json").exists():
            self.tick([gradle])
            require(gradle.process.poll() is None, "install exited before publisher ready")
        ready = self.read_marker(action_dir / "ready.json")
        require(gradle.started <= ready["ns"] <= time.monotonic_ns(), "Java/Python monotonic clocks disagree")
        cli, output = self.reconstruct(f"publication-{number}")
        release_deadline = time.monotonic() + BARRIER_SECONDS - 5
        released = False
        while any(r.pending() for r in (cli, gradle)):
            seen = self.tick([cli, gradle], cli)
            if not released:
                require(time.monotonic() < release_deadline and gradle.process.poll() is None,
                        "owned worker was not observed within publisher barrier")
                if seen:
                    # Atomic rename avoids the publisher seeing a partial token.
                    token = action_dir / "release.tmp"
                    token.write_text("owned-worker-observed\n")
                    record["release_lo_ns"] = time.monotonic_ns()
                    token.rename(action_dir / "release")
                    record["release_hi_ns"] = time.monotonic_ns()
                    released = True
        require(released and gradle.process.returncode == 0, "forced install failed")
        markers = [self.read_marker(action_dir / f"{event}.json") for event in ("ready", "begin", "end")]
        begin, end = validate_markers(markers, source_hash)
        jar_task = self.read_marker(action_dir / "jar-task.json")
        require(jar_task["event"] == "jar-task" and jar_task["path"] == ":jar" and jar_task["success"] is True,
                "application JAR task evidence missing or failed")
        require(ready["ns"] <= record["release_lo_ns"] <= begin <= end <= time.monotonic_ns()
                and record["release_lo_ns"] <= record["release_hi_ns"] <= time.monotonic_ns(),
                "invalid release/action clock ordering")
        samples = [s for s in self.samples if s["case"] == cli.label]
        proofs = overlap_proofs(samples, begin, end)
        record.update(markers=markers, jar_task=jar_task, overlap=proofs, status="PASS" if proofs else "FAIL")
        record["overlap_status"] = "PROVEN" if record["overlap"] else "MISSED"
        self.finish_case(cli, output)

    @staticmethod
    def read_marker(path):
        # A writer may have created the marker but not yet completed its write.
        # Bounded reads only; the action must remain active during this short wait.
        for _ in range(25):
            try:
                return json.loads(bounded_read(path, 128 * 1024))
            except json.JSONDecodeError:
                time.sleep(0.01)
        raise Refusal("publication marker incomplete")

    def execute(self):
        self.env = environment(self.root, self.attempt)
        self.evidence["runtime"] = {"uname": list(os.uname()), "proc_start_ticks_per_second": os.sysconf("SC_CLK_TCK"),
                                    "clock": "Linux CLOCK_MONOTONIC; JVM ready timestamp checked against Python bounds",
                                    "boot_id": bounded_read(Path("/proc/sys/kernel/random/boot_id"), 128).decode().strip()}
        self.evidence["head"] = self.command("source-head", ["git", "rev-parse", "HEAD"]).decode().strip()
        source_pins = SourcePins(self.root, self.command, "before").snapshot()
        write_json(self.attempt / "source-pins.json", source_pins)
        self.evidence["source_pins_sha256"] = digest(encode(source_pins))
        source_hash = stable_file(self.root / "build.gradle.kts")["sha256"]
        self.evidence["build_sha256"] = source_hash
        # Store the exact driver/build sources, not arbitrary environment/diffs.
        for name, destination in (("build.gradle.kts", "build.gradle.kts.source"),
                                  ("scripts/qualify-ghidra-bundle-republication.py", "driver.py.source")):
            (self.attempt / destination).write_bytes(bounded_read(self.root / name, 2 * 1024 * 1024))
        java = Path(self.env["JAVA_HOME"]) / "bin/java"
        compiler = Path(shutil.which("cc", path=self.env["PATH"]) or "/missing-cc").resolve()
        self.evidence["tools"] = {"java": stable_file(java.resolve()), "compiler": stable_file(compiler),
                                  "compiler_path": str(compiler), "java_release": stable_file(java.parent.parent / "release")}
        self.command("java-version", [str(java), "-version"])
        self.command("gradle-version", [str(self.root / "gradlew"), "--no-daemon", "--offline", "--version"], 120)
        self.command("compiler-version", [str(compiler), "--version"])
        fixture = self.root / "src/test/fixtures/c/hello_world.c"
        (self.attempt / "hello_world.c").write_bytes(bounded_read(fixture, 65536))
        self.command("compile-fixture", [str(compiler), "-O0", "-g", "-o", str(self.attempt / "hello_world"), str(fixture)])
        self.evidence["input"] = {"source": stable_file(fixture), "binary": stable_file(self.attempt / "hello_world")}
        before = self.snapshot("before")
        self.baseline = before
        verify_snapshot(before, before)
        cli, output = self.reconstruct("baseline")
        while cli.pending():
            self.tick([cli], cli)
        self.finish_case(cli, output)
        pre = self.snapshot("before-install-1")
        verify_snapshot(before, pre)
        for number in (1, 2):
            self.publication(number, source_hash)
            current = self.snapshot(f"after-install-{number}")
            verify_snapshot(before, current)
            publication = self.evidence["publications"][-1]
            publication["application_jar"] = jar_classification(pre["application_jar"], current["application_jar"],
                                                               publication["jar_task"])
            pre = current
        after = self.snapshot("after")
        verify_snapshot(before, after)
        require(len(self.evidence["publications"]) == 2 and
                all(p["status"] == "PASS" and p["overlap"] for p in self.evidence["publications"]),
                "two publications require proven actual publisher/owned-worker overlap")
        require(len(self.evidence["cases"]) == 3 and all(c["status"] == "PASS" for c in self.evidence["cases"]),
                "fixed reconstruction cases did not all pass")
        final_source_pins = SourcePins(self.root, self.command, "after").snapshot()
        write_json(self.attempt / "source-pins-final.json", final_source_pins)
        self.evidence["final_source_pins_sha256"] = digest(encode(final_source_pins))
        verify_source_pins(source_pins, final_source_pins)
        self.evidence["all_installed_bundle_regular_file_inodes_retained"] = True
        self.evidence["application_jar_classification"] = (
            "unchanged" if before["application_jar"] == after["application_jar"] and
            all(p["application_jar"] == "unchanged" for p in self.evidence["publications"])
            else "changed; see each publication's JAR task and inode/SHA evidence")
        self.evidence["status"] = "PASS"

    def run(self):
        previous = {}

        def cancelled(signum, frame):
            raise Refusal("qualification overall deadline" if signum == signal.SIGALRM else "qualification cancelled by signal")

        try:
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
                previous[sig] = signal.signal(sig, cancelled)
            signal.setitimer(signal.ITIMER_REAL, HARNESS_SECONDS)
            self.execute()
        except BaseException as error:
            self.evidence["status"] = "FAIL"
            self.evidence["failure"] = str(error) if isinstance(error, Refusal) else type(error).__name__
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            # Subsequent cancellation cannot interrupt bounded owned teardown.
            for sig in previous:
                signal.signal(sig, signal.SIG_IGN)
            for run in reversed(self.runs):
                try:
                    result = run.close()
                except Exception as error:
                    result = {"complete": False, "error": type(error).__name__}
                self.evidence["cleanup"].append({"label": run.label, **result})
                if not result["complete"]:
                    self.evidence["status"] = "FAIL"
            if self.evidence["status"] == "FAIL" and self.baseline is not None:
                try:
                    signal.signal(signal.SIGALRM, cancelled)
                    signal.setitimer(signal.ITIMER_REAL, 120)
                    final = self.snapshot("failure-final")
                    self.evidence["application_jar_classification"] = (
                        "unchanged" if self.baseline["application_jar"] == final["application_jar"]
                        else "jar-rebuilt-or-republished")
                    verify_snapshot(self.baseline, final)
                    self.evidence["failure_final_inventory_matches"] = True
                except Exception as error:
                    self.evidence["failure_final_snapshot_error"] = (
                        str(error) if isinstance(error, Refusal) else type(error).__name__)
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
            self.timeline.close()
            for group in ("cases", "publications"):
                for record in self.evidence[group]:
                    if record["status"] == "RUNNING":
                        record["status"] = "FAIL"
            self.evidence["finished_ns"] = time.monotonic_ns()
            write_json(self.attempt / "evidence.json", self.evidence)
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        return 0 if self.evidence["status"] == "PASS" else 1


def main():
    require(len(sys.argv) == 1, "this fixed qualification accepts no overrides")
    root = Path(__file__).resolve().parent.parent
    harness = Harness(root)
    result = harness.run()
    print(f'{harness.evidence["status"]}: {harness.attempt / "evidence.json"}')
    return result


if __name__ == "__main__":
    sys.exit(main())
