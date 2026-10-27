"""Private tmpfs ownership for the generic bubblewrap compatibility runner.

The parent retains the root and both namespaces after a short-lived setup child exits.
Only a sandbox-launch child enters these namespaces; the application never changes its
own namespaces or mounts. One kernel byte/inode quota covers workspace and temporary
files, including unlinked files still held open by a sandbox process.
"""
from __future__ import annotations

import array
import ctypes
import errno
import os
import resource
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class StorageLeaseError(ValueError):
    """The private bounded filesystem could not be established or verified."""


_CLONE_NEWUSER = 0x10000000
_CLONE_NEWNS = 0x00020000
_MS_NOSUID = 2
_MS_NODEV = 4
_MS_NOEXEC = 8
_MS_REC = 16384
_MS_PRIVATE = 1 << 18
_RESERVED_INODES = 3  # filesystem root, work directory, tmp directory
_MAXIMUM_BYTES = 4 * 1024 ** 3
_MAXIMUM_ENTRIES = 4096
_STARTUP_SECONDS = 10.0
_REPLY_BYTES = 512
_FD_COUNT = 3
_TMPFS_MAGIC = 0x01021994


class _StatFs(ctypes.Structure):
    # Linux LP64 statfs, shared by the backend's supported x86-64/AArch64 hosts.
    _fields_ = [("kind", ctypes.c_long), ("block_size", ctypes.c_long),
                ("blocks", ctypes.c_ulong), ("free_blocks", ctypes.c_ulong), ("available_blocks", ctypes.c_ulong),
                ("files", ctypes.c_ulong), ("free_files", ctypes.c_ulong), ("fsid", ctypes.c_int * 2),
                ("name_length", ctypes.c_long), ("fragment_size", ctypes.c_long), ("flags", ctypes.c_long),
                ("spare", ctypes.c_long * 4)]


def _libc():
    native = ctypes.CDLL(None, use_errno=True)
    native.unshare.argtypes = [ctypes.c_int]
    native.unshare.restype = ctypes.c_int
    native.setns.argtypes = [ctypes.c_int, ctypes.c_int]
    native.setns.restype = ctypes.c_int
    native.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    native.mount.restype = ctypes.c_int
    native.fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(_StatFs)]
    native.fstatfs.restype = ctypes.c_int
    return native


def _require_zero(result: int, operation: str) -> None:
    if result != 0:
        raise OSError(ctypes.get_errno(), operation)


def _storage_child(channel_fd: int, mountpoint: Path, byte_limit: int, inode_limit: int, processes: int) -> int:
    """Fixed no-subprocess setup operation, called only by this module's private CLI."""
    channel = socket.socket(fileno=channel_fd)
    descriptors: list[int] = []
    try:
        uid, gid = os.getuid(), os.getgid()
        native = _libc()
        # The namespace retains its creator's RLIMIT_NPROC ceiling. Setting this
        # before unshare prevents an intermediate unlimited namespace from
        # bypassing the later sandbox process limit.
        total = 0
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            try:
                fields = dict(line.split(":", 1) for line in Path(entry.path, "status").read_text().splitlines() if ":" in line)
                if int(fields["Uid"].split()[0]) == uid:
                    total += int(fields["Threads"])
            except (OSError, KeyError, ValueError, IndexError):
                continue
        if total < 1:
            raise StorageLeaseError("private storage could not account for its setup task")
        # The setup child is gone before the sandbox launches; exclude its one
        # task from the frozen baseline rather than granting an extra slot.
        ceiling = total - 1 + processes
        resource.setrlimit(resource.RLIMIT_NPROC, (ceiling, ceiling))
        _require_zero(native.unshare(_CLONE_NEWUSER), "create private storage user namespace")
        Path("/proc/self/setgroups").write_text("deny", encoding="ascii")
        # Keep the real numeric UID/GID nonzero. Mapping the caller to namespace
        # UID 0 would exempt later sandbox processes from RLIMIT_NPROC.
        Path("/proc/self/uid_map").write_text(f"{uid} {uid} 1", encoding="ascii")
        Path("/proc/self/gid_map").write_text(f"{gid} {gid} 1", encoding="ascii")
        _require_zero(native.unshare(_CLONE_NEWNS), "create private storage mount namespace")
        _require_zero(native.mount(None, b"/", None, _MS_REC | _MS_PRIVATE, None), "privatize storage mounts")
        options = f"size={byte_limit},nr_inodes={inode_limit},mode=0700".encode("ascii")
        _require_zero(
            native.mount(b"tmpfs", os.fsencode(mountpoint), b"tmpfs", _MS_NOSUID | _MS_NODEV | _MS_NOEXEC, options),
            "mount bounded private storage",
        )
        (mountpoint / "work").mkdir(mode=0o700)
        (mountpoint / "tmp").mkdir(mode=0o700)
        descriptors = [
            os.open(mountpoint, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW),
            os.open("/proc/self/ns/user", os.O_RDONLY | os.O_CLOEXEC),
            os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC),
        ]
        channel.sendmsg([b"bounded-storage-v1"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors))])
        return 0
    except BaseException as error:
        # No variable host paths, environment or command lines are sent over the control channel.
        error_number = error.errno if isinstance(error, OSError) else errno.EINVAL
        try:
            channel.send(f"storage setup refused: errno={error_number}".encode("ascii"))
        except OSError:
            pass
        return 1
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        channel.close()


class BoundedStorageLease:
    """Own one quota-enforced tmpfs and its retained namespace descriptors.

    ``workspace`` and ``temporary`` are parent-side paths for staging and collecting
    bytes. ``sandbox_workspace`` and ``sandbox_temporary`` are paths visible after
    ``enter_namespace`` runs in a sandbox child. Include ``pass_fds`` in Popen and
    call ``enter_namespace`` before exec. Close the lease only after every sandbox
    child has been reaped. No ordinary-directory fallback exists.
    """

    def __init__(self, scratch: Path, writable_bytes: int, writable_entries: int, *, processes: int):
        if sys.platform != "linux" or ctypes.sizeof(ctypes.c_long) != 8 or os.getuid() == 0 or os.geteuid() == 0:
            raise StorageLeaseError("private storage requires a non-root Linux process")
        if type(writable_bytes) is not int or not 64 * 1024 <= writable_bytes <= _MAXIMUM_BYTES:
            raise StorageLeaseError("private storage byte bound is invalid")
        if type(writable_entries) is not int or not 2 <= writable_entries <= _MAXIMUM_ENTRIES:
            raise StorageLeaseError("private storage entry bound is invalid")
        if type(processes) is not int or not 4 <= processes <= 1024:
            raise StorageLeaseError("private storage process bound is invalid")
        scratch = scratch.absolute()
        repository = Path(__file__).resolve().parents[1]
        if not scratch.resolve(strict=True).is_relative_to(repository):
            raise StorageLeaseError("private storage parent must remain inside the repository")
        metadata = scratch.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise StorageLeaseError("private storage parent must be an owned private non-symlink directory")
        # tmpfs rounds size up to pages. Round down explicitly so its hard ceiling
        # never exceeds a caller's (possibly non-page-aligned) byte budget.
        page = os.sysconf("SC_PAGESIZE")
        self.byte_limit = writable_bytes - writable_bytes % page
        self.inode_limit = writable_entries + _RESERVED_INODES
        self._native = _libc()  # Resolve ctypes/native symbols before any Popen preexec callback.
        self._directory = tempfile.TemporaryDirectory(prefix="bounded-storage-", dir=scratch)
        self.mountpoint = Path(self._directory.name)
        self._fds: list[int] = []
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        process = None
        deadline = time.monotonic() + _STARTUP_SECONDS
        try:
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", "-B", os.fspath(Path(__file__).resolve()), "--storage-child",
                 str(child.fileno()), os.fspath(self.mountpoint), str(self.byte_limit), str(self.inode_limit), str(processes)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={}, close_fds=True, pass_fds=(child.fileno(),),
            )
            child.close()
            parent.settimeout(max(0.001, deadline - time.monotonic()))
            reply, ancillary, flags, _ = parent.recvmsg(
                _REPLY_BYTES, socket.CMSG_SPACE(_FD_COUNT * array.array("i").itemsize), socket.MSG_CMSG_CLOEXEC,
            )
            for level, kind, payload in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors = array.array("i")
                    descriptors.frombytes(payload[:len(payload) - len(payload) % descriptors.itemsize])
                    self._fds.extend(descriptors)
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or reply != b"bounded-storage-v1" or len(self._fds) != _FD_COUNT:
                raise StorageLeaseError("private storage setup refused or returned an invalid descriptor receipt")
            if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                raise StorageLeaseError("private storage setup child failed")
            self._verify()
        except BaseException:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=_STARTUP_SECONDS)
            self.close()
            raise
        finally:
            parent.close()
            child.close()
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=_STARTUP_SECONDS)

    def _verify(self) -> None:
        root, user, mount = self._fds
        metadata = os.fstat(root)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise StorageLeaseError("private storage root identity is invalid")
        filesystem = _StatFs()
        _require_zero(self._native.fstatfs(root, ctypes.byref(filesystem)), "identify private storage filesystem")
        if filesystem.kind != _TMPFS_MAGIC:
            raise StorageLeaseError("private storage is not a kernel tmpfs")
        usage = os.fstatvfs(root)
        required_flags = _MS_NOSUID | _MS_NODEV | _MS_NOEXEC
        if usage.f_flag & required_flags != required_flags:
            raise StorageLeaseError("private storage mount flags are incomplete")
        if usage.f_frsize * usage.f_blocks != self.byte_limit or usage.f_files != self.inode_limit:
            raise StorageLeaseError("kernel private storage bounds differ from the requested limits")
        if usage.f_bfree != usage.f_blocks or usage.f_ffree != self.inode_limit - _RESERVED_INODES:
            raise StorageLeaseError("private storage is not freshly initialized")
        for descriptor, prefix in ((user, "user:["), (mount, "mnt:[")):
            if not os.readlink(f"/proc/self/fd/{descriptor}").startswith(prefix):
                raise StorageLeaseError("private storage namespace descriptor kind differs")
        if sorted(path.name for path in self.root.iterdir()) != ["tmp", "work"]:
            raise StorageLeaseError("private storage initialized an unexpected population")
        if any(self.mountpoint.iterdir()):
            raise StorageLeaseError("private storage changed the host mountpoint")

    @property
    def root(self) -> Path:
        self._require_open()
        return Path(f"/proc/self/fd/{self._fds[0]}")

    @property
    def workspace(self) -> Path:
        return self.root / "work"

    @property
    def temporary(self) -> Path:
        return self.root / "tmp"

    @property
    def sandbox_workspace(self) -> Path:
        self._require_open()
        return self.mountpoint / "work"

    @property
    def sandbox_temporary(self) -> Path:
        self._require_open()
        return self.mountpoint / "tmp"

    @property
    def pass_fds(self) -> tuple[int, int]:
        self._require_open()
        return self._fds[1], self._fds[2]

    def _require_open(self) -> None:
        if len(self._fds) != _FD_COUNT:
            raise StorageLeaseError("private storage lease is closed")

    def enter_namespace(self) -> None:
        """Popen preexec callback: enter user, then mount namespace before exec."""
        self._require_open()
        _require_zero(self._native.setns(self._fds[1], _CLONE_NEWUSER), "enter private storage user namespace")
        _require_zero(self._native.setns(self._fds[2], _CLONE_NEWNS), "enter private storage mount namespace")
        # pass_fds makes these inheritable in the child. Close the child copies
        # before exec so the untrusted subject cannot join an ancestor namespace.
        os.close(self._fds[1])
        os.close(self._fds[2])

    def close(self) -> None:
        descriptors, self._fds = self._fds, []
        for descriptor in descriptors:
            os.close(descriptor)
        self._directory.cleanup()

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(self, *_):
        self.close()


if __name__ == "__main__":
    if len(sys.argv) != 7 or sys.argv[1] != "--storage-child":
        raise SystemExit(2)
    raise SystemExit(_storage_child(int(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])))
