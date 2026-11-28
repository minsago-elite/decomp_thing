#!/usr/bin/env python3
"""Closed privileged fixture controller for #930 mounted-state qualification.

This is a disposable hosted-test provisioner, never a production scratch/reset
capability. It deliberately refuses uncertain state instead of removing it.
All backing images and state are repository-owned artifacts; only the fixed
mountpoints use root-owned /var/lib ancestry required by the production adapter.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "build" / "oracle-ext4-admission"
PARENT = Path("/var/lib/decomp-oracle-ext4-admission-ci")
PATHS = {name: PARENT / name for name in ("scratch", "alias", "subtree", "replacement", "retained")}
CANARY_NAME = "replacement-canary.txt"
CANARY_CONTENT = "issue930-owned-replacement-canary-v1\n"
IMAGE_BYTES = 64 * 1024 * 1024
IMAGE_INODES = 4096
STATE_BYTES = 128 * 1024
READY = "ready"
ACTION_SECONDS = 35
_deadline = None
ACTIONS = frozenset({"prepare", "inspect", "restore", "cleanup", "missing-nodev", "missing-nosuid",
                     "missing-noexec", "missing-noatime", "readonly", "wrong-owner", "tmpfs", "nested",
                     "bind-subtree", "bind-alias", "replace-root"})
BASE_OPTIONS = "rw,nodev,nosuid,noexec,noatime"
COMMANDS = {name: next((str(directory / name) for directory in map(Path, ("/usr/sbin", "/usr/bin", "/sbin", "/bin"))
                       if (directory / name).is_file()), "")
            for name in ("mkfs.ext4", "losetup", "mount", "umount")}
LOOP_GET_STATUS64 = 0x4C05
LOOP_PATTERN = re.compile(r"/dev/loop[0-9]{1,6}")


class FixtureError(ValueError):
    pass


def fail(message):
    raise FixtureError(message)


def identity(path: Path, *, directory=False):
    value = path.lstat()
    if value.st_nlink < 1 or stat.S_ISLNK(value.st_mode) or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)):
        fail("fixture object has an unsupported file kind")
    return {"device": value.st_dev, "inode": value.st_ino, "uid": value.st_uid, "gid": value.st_gid,
            "mode": stat.S_IMODE(value.st_mode), **({} if directory else {"bytes": value.st_size, "links": value.st_nlink})}


def mount_table(text=None):
    if text is None:
        with open("/proc/self/mountinfo", "r", encoding="ascii") as source:
            text = source.read(4 * 1024 * 1024 + 1)
    if len(text) > 4 * 1024 * 1024:
        fail("mount inventory exceeds its bound")
    rows = []
    for line in text.splitlines():
        before, separator, after = line.partition(" - ")
        left, right = before.split(), after.split()
        if not separator or len(left) < 6 or len(right) < 3:
            fail("mount inventory is malformed")
        def decode(value):
            return re.sub(r"\\(040|011|012|134)", lambda match: chr(int(match[1], 8)), value)
        rows.append({"id": int(left[0]), "parent": int(left[1]), "device": left[2], "root": decode(left[3]),
                     "path": decode(left[4]), "options": sorted(left[5].split(',')), "type": right[0],
                     "source": decode(right[1]), "superOptions": sorted(right[2].split(',')), "optional": sorted(left[6:])})
    if len({row['id'] for row in rows}) != len(rows):
        fail("mount inventory repeats an identity")
    return rows


def fixture_mounts():
    return sorted((row for row in mount_table() if Path(row["path"]).is_relative_to(PARENT)), key=lambda row: row["id"])


def run(name, arguments, *, pass_fds=()):
    command = COMMANDS.get(name)
    if not command:
        fail("required fixture utility is unavailable")
    deadline = _deadline if _deadline is not None else time.monotonic() + ACTION_SECONDS
    if time.monotonic() >= deadline:
        fail("fixture action exceeded its deadline before a utility launch")
    process = subprocess.Popen([command, *map(str, arguments)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                               pass_fds=pass_fds, start_new_session=True)
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    try:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail("fixture action exceeded its utility deadline")
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                streams[key.fileobj].extend(chunk)
                if len(streams[key.fileobj]) > 4096:
                    fail("fixture utility output exceeds its bound")
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail("fixture action exceeded its utility deadline")
            time.sleep(min(remaining, 0.01))
        # Keep the exited leader unreaped until its entire owned group is killed.
        # Its reserved PID cannot be recycled into an unrelated process group.
        # Even a successful utility may not leave a detached helper behind.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.wait(timeout=5) != 0:
            fail(f"fixture utility {name} refused with exit {process.returncode}")
        return streams[process.stdout].decode("ascii").strip()
    except BaseException:
        # A failed utility remains owned through termination/reaping. Its fresh
        # process group also contains any helper children started by mount.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


def entry_names(path, maximum):
    names = []
    with os.scandir(path) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > maximum:
                fail("fixture directory exceeds its exact population bound")
    return sorted(names)


def loop_identity(path):
    if not LOOP_PATTERN.fullmatch(path):
        fail("loop device name is outside the fixed device family")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISBLK(metadata.st_mode) or os.major(metadata.st_rdev) != 7:
            fail("loop path does not name a loop block device")
        data = fcntl.ioctl(descriptor, LOOP_GET_STATUS64, bytes(232))
        device, inode, _, offset, size_limit = struct.unpack_from("=QQQQQ", data)
        number, encryption, key_size, flags = struct.unpack_from("=IIII", data, 40)
        if offset != 0 or size_limit != 0 or encryption != 0 or key_size != 0 or flags != 0:
            fail("loop device has unsupported offset, sizing or flags")
        if os.minor(metadata.st_rdev) != number:
            fail("loop device number differs from its descriptor")
        return {"path": path, "rdev": metadata.st_rdev, "backingDevice": device, "backingInode": inode}
    finally:
        os.close(descriptor)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def publish(state):
    payload = canonical(state)
    if len(payload) > STATE_BYTES:
        fail("fixture state exceeds its bound")
    stage = STORE / "state.next"
    descriptor = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(stage, STORE / "state.json")
    with_directory_sync(STORE)


def with_directory_sync(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load():
    path = STORE / "state.json"
    facts = identity(path)
    if facts["uid"] != 0 or facts["mode"] != 0o400 or facts["links"] != 1 or facts["bytes"] > STATE_BYTES:
        fail("fixture state identity is invalid")
    payload = path.read_bytes()
    state = json.loads(payload)
    if canonical(state) != payload or set(state) != {"version", "repository", "owner", "mode", "parent", "images", "mounts", "rootMetadata", "canary", "fixtureDirectory", "parentMount", "underlyingParent", "underlyingSlots"}:
        fail("fixture state is not the closed canonical record")
    if state["version"] != 1 or state["repository"] != str(ROOT) or state["mode"] not in ACTIONS | {READY}:
        fail("fixture state has an unsupported identity")
    return state


def image_path(name):
    if name not in ("original", "replacement"):
        fail("fixture image name is invalid")
    return STORE / f"{name}.img"


def verify_image(name, record):
    if identity(image_path(name)) != record["file"]:
        fail("fixture backing image identity changed")
    current = loop_identity(record["loop"]["path"])
    if current != record["loop"] or (current["backingDevice"], current["backingInode"]) != (record["file"]["device"], record["file"]["inode"]):
        fail("fixture loop backing identity changed")


def replacement_root(state):
    return PATHS["scratch"] if state["mode"] == "replace-root" else PATHS["replacement"]


def verify_canary(state):
    path = replacement_root(state) / CANARY_NAME
    if identity(path) != state["canary"] or path.read_bytes() != CANARY_CONTENT.encode("ascii"):
        fail("replacement canary identity or bytes changed; preserving residue")


def verify_mount_shape(state):
    rows = state["mounts"]
    mode = state["mode"]
    parent = state["parentMount"]
    matches = [row for row in rows if row["id"] == parent["id"]]
    if len(matches) != 1 or matches[0] != parent or parent["path"] != str(PARENT) or parent["type"] != "tmpfs" or parent["root"] != "/" or parent["optional"]:
        fail("fixture parent is not the exact private owned tmpfs mount")
    if not set(BASE_OPTIONS.split(',')).issubset(parent["options"]):
        fail("fixture parent mount flags changed")
    known_ids = {parent["id"]}
    for name, image in state["images"].items():
        known_ids.add(image["mountId"])
        matches = [row for row in rows if row["id"] == image["mountId"]]
        if len(matches) != 1:
            fail("owned ext4 mount identity is absent or repeated")
        row = matches[0]
        expected_path = PATHS["retained" if mode == "replace-root" else "scratch"] if name == "original" else replacement_root(state)
        expected_device = f"{os.major(image['loop']['rdev'])}:{os.minor(image['loop']['rdev'])}"
        if row["parent"] != parent["id"] or row["path"] != str(expected_path) or row["device"] != expected_device or row["type"] != "ext4" or row["root"] != "/":
            fail("owned ext4 mount shape changed")
        required = set(BASE_OPTIONS.split(','))
        if name == "original" and mode.startswith("missing-"):
            missing = mode[8:]
            required.remove(missing)
            if missing in row["options"]:
                fail("requested missing-flag state was not established")
        if name == "original" and mode == "readonly":
            required.remove("rw")
            required.add("ro")
        if not required.issubset(row["options"]):
            fail("owned ext4 mount flags differ from the fixture mode")
    extra = [row for row in rows if row["id"] not in known_ids]
    paths = {"tmpfs": PATHS["scratch"], "nested": PATHS["scratch"] / "nested",
             "bind-subtree": PATHS["subtree"], "bind-alias": PATHS["alias"]}
    if mode not in paths:
        if extra:
            fail("fixture contains an unexpected mount")
        return
    if len(extra) != 1 or extra[0]["path"] != str(paths[mode]):
        fail("fixture mutation mount is absent or ambiguous")
    row = extra[0]
    if mode in {"tmpfs", "nested"}:
        if row["type"] != "tmpfs" or row["root"] != "/":
            fail("fixture tmpfs mutation has the wrong type or root")
    else:
        original = next(row for row in rows if row["id"] == state["images"]["original"]["mountId"])
        if row["type"] != "ext4" or row["device"] != original["device"] or row["root"] != ("/subtree" if mode == "bind-subtree" else "/"):
            fail("fixture bind mutation does not retain the owned device and root")


def verify(state):
    if identity(PARENT, directory=True) != state["parent"]:
        fail("fixture mount parent identity changed")
    if entry_names(PARENT, len(PATHS)) != sorted(PATHS):
        fail("fixture mount parent has unknown residue")
    verify_mount_shape(state)
    if fixture_mounts() != state["mounts"]:
        fail("fixture mount inventory changed; refusing unknown mounts")
    for name, record in state["images"].items():
        verify_image(name, record)
    for name, facts in state["rootMetadata"].items():
        if identity(PATHS[name], directory=True) != facts:
            fail("fixture mount-root ownership or identity changed")
    verify_canary(state)
    if entry_names(STORE, 4) != ["lock", "original.img", "replacement.img", "state.json"]:
        fail("fixture storage has unknown residue")
    allowed_devices = {row["device"] for row in state["mounts"]}
    if any(row["device"] in allowed_devices and not Path(row["path"]).is_relative_to(PARENT) for row in mount_table()):
        fail("fixture device has an unowned external mount alias")


def snapshot(state, mode):
    state["mode"] = mode
    state["mounts"] = fixture_mounts()
    state["rootMetadata"] = {name: identity(path, directory=True) for name, path in PATHS.items()}
    publish(state)
    verify(state)


def inspection(state):
    verify(state)
    return {**{name: str(path) for name, path in PATHS.items()},
            "canary": str(replacement_root(state) / CANARY_NAME), "canaryContent": CANARY_CONTENT,
            "mode": state["mode"], "imageBytes": IMAGE_BYTES, "imageInodes": IMAGE_INODES,
            "mounts": state["mounts"]}


def create_image(name, target, owner):
    path = image_path(name)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        os.ftruncate(descriptor, IMAGE_BYTES)
        os.fsync(descriptor)
        run("mkfs.ext4", ["-q", "-F", "-N", str(IMAGE_INODES), "-m", "0", f"/proc/self/fd/{descriptor}"], pass_fds=(descriptor,))
        device = run("losetup", ["--find", "--show", "--nooverlap", f"/proc/self/fd/{descriptor}"], pass_fds=(descriptor,))
        record = {"file": identity(path), "loop": loop_identity(device)}
        verify_image(name, record)
        run("mount", ["-t", "ext4", "-o", BASE_OPTIONS, device, target])
        os.chown(target, owner["uid"], owner["gid"])
        os.chmod(target, 0o700)
        lost = target / "lost+found"
        if lost.exists():
            if not lost.is_dir() or lost.is_symlink() or entry_names(lost, 0):
                fail("new ext4 lost+found has unexpected content")
            lost.rmdir()
        matches = [row for row in fixture_mounts() if row["path"] == str(target)]
        if len(matches) != 1:
            fail("new fixture mount identity is absent or ambiguous")
        record["mountId"] = matches[0]["id"]
        return record
    finally:
        os.close(descriptor)


def prepare():
    if STORE.exists() or STORE.is_symlink() or PARENT.exists() or PARENT.is_symlink() or fixture_mounts():
        fail("fixture preparation requires absent owned targets")
    build = ROOT / "build"
    metadata = identity(build, directory=True)
    owner = {"uid": ROOT.stat().st_uid, "gid": ROOT.stat().st_gid}
    if owner["uid"] == 0 or metadata["uid"] != owner["uid"] or metadata["mode"] & 0o022:
        fail("repository build directory must exist and have a trusted non-root owner")
    for ancestor in (PARENT.parent, *PARENT.parent.parents):
        value = identity(ancestor, directory=True)
        if value["uid"] != 0 or value["mode"] & 0o022 or ancestor.resolve() != ancestor:
            fail("fixture mount ancestry is not trusted")
    STORE.mkdir(mode=0o700)
    PARENT.mkdir(mode=0o755)
    underlying_parent = identity(PARENT, directory=True)
    with locked_store(create=True):
        run("mount", ["-t", "tmpfs", "-o", f"{BASE_OPTIONS},size=1m,nr_inodes=32,mode=0755", "tmpfs", PARENT])
        # MS_MOVE refuses mounts beneath a shared parent. Only this owned finite
        # parent mount changes propagation; the host root remains untouched.
        run("mount", ["--make-private", PARENT])
        parents = fixture_mounts()
        if len(parents) != 1 or parents[0]["path"] != str(PARENT) or parents[0]["optional"]:
            fail("private fixture parent mount was not established")
        for path in PATHS.values():
            path.mkdir(mode=0o755)
        underlying_slots = {name: identity(path, directory=True) for name, path in PATHS.items()}
        images = {name: create_image(name, PATHS[target], owner)
                  for name, target in (("original", "scratch"), ("replacement", "replacement"))}
        canary = PATHS["replacement"] / CANARY_NAME
        descriptor = os.open(canary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            os.write(descriptor, CANARY_CONTENT.encode("ascii"))
            os.fchown(descriptor, owner["uid"], owner["gid"])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        state = {"version": 1, "repository": str(ROOT), "owner": owner, "mode": READY,
                 "parent": identity(PARENT, directory=True), "parentMount": parents[0],
                 "underlyingParent": underlying_parent, "underlyingSlots": underlying_slots, "images": images,
                 "mounts": [], "rootMetadata": {}, "canary": identity(canary), "fixtureDirectory": None}
        snapshot(state, READY)
        return inspection(state)


@contextmanager
def locked_store(create=False):
    metadata = identity(STORE, directory=True)
    if metadata["uid"] != 0 or metadata["mode"] != 0o700:
        fail("fixture state directory is not root-owned and private")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = os.open(STORE / "lock", flags, 0o400)
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != 0 or facts.st_nlink != 1 or stat.S_IMODE(facts.st_mode) != 0o400:
            fail("fixture lock identity is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def mutate(state, action):
    if state["mode"] != READY:
        fail("restore the current fixture mode before another mutation")
    if action.startswith("missing-"):
        replacement = {"nodev": "dev", "nosuid": "suid", "noexec": "exec", "noatime": "atime,relatime"}[action[8:]]
        run("mount", ["-o", "remount," + BASE_OPTIONS.replace(action[8:], replacement), PATHS["scratch"]])
    elif action == "readonly":
        run("mount", ["-o", "remount," + BASE_OPTIONS.replace("rw,", "ro,"), PATHS["scratch"]])
    elif action == "wrong-owner":
        os.chown(PATHS["scratch"], 0, 0)
    elif action == "tmpfs":
        run("mount", ["-t", "tmpfs", "-o", f"{BASE_OPTIONS},size=64m,nr_inodes=4096,mode=0700,uid={state['owner']['uid']},gid={state['owner']['gid']}", "tmpfs", PATHS["scratch"]])
    elif action == "nested":
        nested = PATHS["scratch"] / "nested"
        nested.mkdir(mode=0o700)
        state["fixtureDirectory"] = {"name": "nested", "identity": identity(nested, directory=True)}
        run("mount", ["-t", "tmpfs", "-o", f"{BASE_OPTIONS},size=1m,nr_inodes=16,mode=0700", "tmpfs", nested])
    elif action == "bind-subtree":
        subtree = PATHS["scratch"] / "subtree"
        subtree.mkdir(mode=0o700)
        os.chown(subtree, state["owner"]["uid"], state["owner"]["gid"])
        state["fixtureDirectory"] = {"name": "subtree", "identity": identity(subtree, directory=True)}
        run("mount", ["--bind", subtree, PATHS["subtree"]])
    elif action == "bind-alias":
        run("mount", ["--bind", PATHS["scratch"], PATHS["alias"]])
    elif action == "replace-root":
        run("mount", ["--move", PATHS["scratch"], PATHS["retained"]])
        run("mount", ["--move", PATHS["replacement"], PATHS["scratch"]])
    else:
        fail("unsupported fixture mutation")
    snapshot(state, action)


def restore(state):
    mode = state["mode"]
    if mode == READY:
        return
    if mode.startswith("missing-") or mode == "readonly":
        run("mount", ["-o", "remount," + BASE_OPTIONS, PATHS["scratch"]])
    elif mode == "wrong-owner":
        os.chown(PATHS["scratch"], state["owner"]["uid"], state["owner"]["gid"])
    elif mode == "tmpfs":
        run("umount", ["--", PATHS["scratch"]])
    elif mode == "nested":
        nested = PATHS["scratch"] / "nested"
        run("umount", ["--", nested])
        if identity(nested, directory=True) != state["fixtureDirectory"]["identity"]:
            fail("underlying nested-mount directory changed; preserving residue")
        nested.rmdir()
    elif mode == "bind-subtree":
        run("umount", ["--", PATHS["subtree"]])
        subtree = PATHS["scratch"] / "subtree"
        if identity(subtree, directory=True) != state["fixtureDirectory"]["identity"]:
            fail("underlying bind-subtree directory changed; preserving residue")
        subtree.rmdir()
    elif mode == "bind-alias":
        run("umount", ["--", PATHS["alias"]])
    elif mode == "replace-root":
        run("mount", ["--move", PATHS["scratch"], PATHS["replacement"]])
        run("mount", ["--move", PATHS["retained"], PATHS["scratch"]])
    else:
        fail("fixture mode has no supported restoration")
    state["fixtureDirectory"] = None
    snapshot(state, READY)


def cleanup(state):
    restore(state)
    verify(state)
    if entry_names(PATHS["scratch"], 0) or entry_names(PATHS["replacement"], 1) != [CANARY_NAME]:
        fail("fixture cleanup preserves unowned scratch or replacement residue")
    for name in ("alias", "subtree", "retained"):
        if entry_names(PATHS[name], 0):
            fail("fixture cleanup preserves unknown companion-directory residue")
    verify_canary(state)
    # Keep the canary inside its image through unmount/detach. A failed cleanup
    # must not erase the replacement evidence before ownership is settled.
    for name in ("replacement", "scratch"):
        run("umount", ["--", PATHS[name]])
    if fixture_mounts() != [state["parentMount"]]:
        fail("fixture cleanup found an unexpected remaining mount")
    for name, record in state["images"].items():
        verify_image(name, record)
        run("losetup", ["--detach", record["loop"]["path"]])
        try:
            loop_identity(record["loop"]["path"])
        except OSError as error:
            if error.errno != 6:  # ENXIO: no backing device remains associated.
                raise
        else:
            fail("fixture loop device remained associated")
        if identity(image_path(name)) != record["file"]:
            fail("fixture image changed during detach")
    for name, path in PATHS.items():
        if identity(path, directory=True) != state["underlyingSlots"][name] or entry_names(path, 0):
            fail("fixture cleanup preserves changed underlying slot directories")
    for path in PATHS.values():
        path.rmdir()
    run("umount", ["--", PARENT])
    if fixture_mounts() or identity(PARENT, directory=True) != state["underlyingParent"] or entry_names(PARENT, 0):
        fail("fixture cleanup preserves changed underlying mount parent")
    PARENT.rmdir()
    # Delete backing files only after all exact mounts and loop ownership have
    # terminated, preserving the replacement canary image on earlier failures.
    for name in ("original", "replacement"):
        if identity(image_path(name)) != state["images"][name]["file"]:
            fail("fixture image changed before final removal")
        image_path(name).unlink()
    (STORE / "state.json").unlink()
    # The open lock descriptor remains held until the caller leaves locked_store.
    (STORE / "lock").unlink()
    STORE.rmdir()
    return {"mode": "cleaned", "ownedMountsRemaining": 0}


def main(arguments=None):
    global _deadline
    args = sys.argv[1:] if arguments is None else arguments
    if len(args) != 1 or args[0] not in ACTIONS:
        print("usage: ci-oracle-ext4-admission.py ACTION (closed hosted-fixture action)", file=sys.stderr)
        return 64
    if os.geteuid() != 0:
        print("ext4 admission fixture requires explicit hosted root provisioning", file=sys.stderr)
        return 77
    action = args[0]
    _deadline = time.monotonic() + ACTION_SECONDS
    try:
        if action == "prepare":
            result = prepare()
        else:
            with locked_store():
                state = load()
                verify(state)
                if action == "cleanup":
                    result = cleanup(state)
                else:
                    if action == "restore":
                        restore(state)
                    elif action != "inspect":
                        mutate(state, action)
                    result = inspection(state)
        print(canonical(result).decode("utf-8"), end="")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"ext4 admission fixture refused: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
