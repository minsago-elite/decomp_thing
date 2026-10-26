"""Kernel quota controls for the generic bubblewrap storage lease."""
from __future__ import annotations

import errno
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from oracle.behavior_storage_lease import BoundedStorageLease, StorageLeaseError

ROOT = Path(__file__).resolve().parents[2]


class StorageLeaseInputTests(unittest.TestCase):
    def test_invalid_bounds_are_refused_before_setup(self):
        for size, entries in ((True, 2), (65535, 2), (4 * 1024 ** 3 + 1, 2), (65536, True),
                              (65536, 1), (65536, 4097)):
            with self.subTest(size=size, entries=entries), self.assertRaises(StorageLeaseError):
                BoundedStorageLease(ROOT / "does-not-exist", size, entries, processes=8)

    def test_invalid_process_bound_is_refused_before_setup(self):
        for processes in (True, 3, 1025):
            with self.subTest(processes=processes), self.assertRaises(StorageLeaseError):
                BoundedStorageLease(ROOT / "does-not-exist", 65536, 4, processes=processes)

    def test_unowned_or_public_parent_is_refused(self):
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build) as directory:
            parent = Path(directory)
            parent.chmod(0o755)
            with self.assertRaisesRegex(StorageLeaseError, "owned private"):
                BoundedStorageLease(parent, 65536, 4, processes=8)
            self.assertEqual(list(parent.iterdir()), [])

    def test_symlink_parent_is_refused(self):
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build) as directory:
            parent = Path(directory)
            real = parent / "real"
            real.mkdir(mode=0o700)
            linked = parent / "link"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(StorageLeaseError, "non-symlink"):
                BoundedStorageLease(linked, 65536, 4, processes=8)
            self.assertEqual(list(real.iterdir()), [])


@unittest.skipUnless(os.environ.get("BEHAVIOR_CORPUS_BWRAP_LIVE") == "1", "set BEHAVIOR_CORPUS_BWRAP_LIVE=1")
class LiveStorageLeaseTests(unittest.TestCase):
    """An explicitly requested native run fails if namespaces or tmpfs are unavailable."""

    def setUp(self):
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=build)
        self.addCleanup(self.directory.cleanup)
        self.parent = Path(self.directory.name)

    def test_kernel_quota_counts_open_unlinked_bytes(self):
        with BoundedStorageLease(self.parent, 65536, 8, processes=8) as lease:
            held = []
            allocated = 0
            try:
                with self.assertRaises(OSError) as caught:
                    for index in range(8):
                        path = lease.workspace / f"unlinked-{index}"
                        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                        held.append(descriptor)
                        path.unlink()
                        for _ in range(4):
                            allocated += os.write(descriptor, b"x" * 4096)
                self.assertEqual(caught.exception.errno, errno.ENOSPC)
                self.assertEqual(allocated, lease.byte_limit)
                self.assertEqual(list(lease.workspace.iterdir()), [])
                self.assertEqual(os.fstatvfs(held[0]).f_bavail, 0)
            finally:
                for descriptor in held:
                    os.close(descriptor)
            usage = os.statvfs(lease.workspace)
            self.assertEqual(usage.f_bavail * usage.f_frsize, lease.byte_limit)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_kernel_inode_quota_counts_open_unlinked_files(self):
        with BoundedStorageLease(self.parent, 65536, 4, processes=8) as lease:
            descriptors = []
            try:
                for index in range(4):
                    path = lease.temporary / str(index)
                    descriptors.append(os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600))
                    path.unlink()
                with self.assertRaises(OSError) as caught:
                    os.open(lease.workspace / "one-too-many", os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                self.assertEqual(caught.exception.errno, errno.ENOSPC)
                self.assertEqual(list(lease.temporary.iterdir()), [])
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_workspace_and_tmp_share_one_byte_ceiling(self):
        with BoundedStorageLease(self.parent, 65537, 8, processes=8) as lease:
            self.assertEqual(lease.byte_limit, 65536)
            (lease.workspace / "first").write_bytes(b"x" * 49152)
            with self.assertRaises(OSError) as caught:
                (lease.temporary / "second").write_bytes(b"y" * 32768)
            self.assertEqual(caught.exception.errno, errno.ENOSPC)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_retained_namespace_mounts_into_bubblewrap_and_leaves_host_empty(self):
        with BoundedStorageLease(self.parent, 65536, 8, processes=8) as lease:
            (lease.workspace / "input").write_text("private", encoding="ascii")
            self.assertEqual(list(lease.mountpoint.iterdir()), [])
            result = subprocess.run(
                ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
                 "--clearenv", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
                 "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/bin", "/bin",
                 "--bind", os.fspath(lease.sandbox_workspace), "/work", "--remount-ro", "/",
                 "/bin/cat", "/work/input"],
                stdin=subprocess.DEVNULL, capture_output=True, env={}, close_fds=True,
                pass_fds=lease.pass_fds, preexec_fn=lease.enter_namespace, timeout=10, check=True,
            )
            self.assertEqual(result.stdout, b"private")
            self.assertEqual(result.stderr, b"")
            self.assertEqual(list(lease.mountpoint.iterdir()), [])
            descriptors = lease.pass_fds
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        self.assertEqual(list(self.parent.iterdir()), [])
        with self.assertRaisesRegex(StorageLeaseError, "closed"):
            lease.enter_namespace()

    def test_namespace_descriptors_do_not_survive_exec(self):
        program = """import os
found = []
for entry in os.scandir('/proc/self/fd'):
    try:
        target = os.readlink(entry.path)
    except OSError:
        continue
    if target.startswith(('user:[', 'mnt:[')):
        found.append(target)
print(found)
"""
        with BoundedStorageLease(self.parent, 65536, 8, processes=8) as lease:
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", program],
                stdin=subprocess.DEVNULL, capture_output=True, env={}, close_fds=True,
                pass_fds=lease.pass_fds, preexec_fn=lease.enter_namespace, timeout=10, check=True,
            )
            self.assertEqual(result.stdout, b"[]\n")
            self.assertEqual(result.stderr, b"")
            for descriptor in lease.pass_fds:
                os.fstat(descriptor)  # Parent ownership is retained after child exec.

    def test_body_failure_releases_all_owned_storage(self):
        with self.assertRaisesRegex(RuntimeError, "expected failure"):
            with BoundedStorageLease(self.parent, 65536, 8, processes=8) as lease:
                (lease.workspace / "retained").write_bytes(b"x" * 65536)
                raise RuntimeError("expected failure")
        self.assertEqual(list(self.parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
