"""Anonymous-storage syscall boundary controls for the bubblewrap backend."""
from __future__ import annotations

import os
import platform
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from oracle.behavior_corpus import BehaviorCorpusError
from oracle.behavior_corpus_bwrap_seccomp import anonymous_storage_filter, storage_filter_bytes

ROOT = Path(__file__).resolve().parents[2]


class StorageFilterTests(unittest.TestCase):
    def test_both_native_abis_have_closed_architecture_and_syscall_boundaries(self):
        for machine, architecture, numbers in (("x86_64", 0xC000003E, (319, 29, 447)),
                                               ("aarch64", 0xC00000B7, (279, 194, 447))):
            with self.subTest(machine=machine):
                payload = storage_filter_bytes(machine)
                self.assertLessEqual(len(payload), 128)
                instructions = list(struct.iter_unpack("<HBBI", payload))
                self.assertEqual(instructions[1], (0x15, 1, 0, architecture))
                self.assertEqual(instructions[2], (0x06, 0, 0, 0x80000000))
                self.assertEqual(instructions[4], (0x35, 0, 1, 0x40000000))
                self.assertEqual([item[3] for item in instructions[6:-1:2]], list(numbers))
                self.assertEqual(instructions[-1], (0x06, 0, 0, 0x7FFF0000))

    def test_unsupported_architecture_and_abi_refuse(self):
        for machine in ("i686", "armv7l", "s390x", "riscv64", "x86_64-x32"):
            with self.subTest(machine=machine), self.assertRaises(BehaviorCorpusError):
                storage_filter_bytes(machine)
        with mock.patch("sys.byteorder", "big"), self.assertRaises(BehaviorCorpusError):
            storage_filter_bytes("x86_64")
        with mock.patch("struct.calcsize", return_value=4), self.assertRaises(BehaviorCorpusError):
            storage_filter_bytes("x86_64")

    def test_filter_descriptor_is_regular_private_owned_and_closed(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as directory:
            scratch = Path(directory)
            with anonymous_storage_filter(scratch) as descriptor:
                self.assertEqual(os.read(descriptor, 128), storage_filter_bytes())
                self.assertEqual(os.fstat(descriptor).st_mode & 0o777, 0o600)
                self.assertFalse(os.get_inheritable(descriptor))
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_public_scratch_refuses_before_filter_publication(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as directory:
            scratch = Path(directory)
            scratch.chmod(0o755)
            with self.assertRaisesRegex(BehaviorCorpusError, "private owned"):
                with anonymous_storage_filter(scratch):
                    self.fail("public scratch was admitted")
            self.assertEqual(list(scratch.iterdir()), [])


_INSTALL_AND_EXEC = r"""
import ctypes, os, resource, sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
class Filter(ctypes.Structure):
    _fields_ = [('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_ = [('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
fd = int(sys.argv[1])
payload = os.read(fd,128)
os.close(fd)
filters = (Filter * (len(payload)//8)).from_buffer_copy(payload)
program = Program(len(filters), filters)
libc = ctypes.CDLL(None,use_errno=True)
if libc.prctl(38,1,0,0,0) or libc.prctl(22,2,ctypes.byref(program),0,0):
    raise OSError(ctypes.get_errno(),'install seccomp')
os.execv(sys.executable,[sys.executable,'-I','-S','-B','-c',sys.argv[2]])
"""


@unittest.skipUnless(os.environ.get("BEHAVIOR_CORPUS_BWRAP_LIVE") == "1", "set BEHAVIOR_CORPUS_BWRAP_LIVE=1")
class LiveStorageFilterTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.addCleanup(self.directory.cleanup)
        self.scratch = Path(self.directory.name)

    def test_filter_survives_exec_and_blocks_all_anonymous_storage_creators(self):
        numbers = {"x86_64": (319,29,447), "aarch64": (279,194,447)}[platform.machine()]
        target = f"""import ctypes,errno,os
libc=ctypes.CDLL(None,use_errno=True)
libc.syscall.restype=ctypes.c_long
for nr,args in (({numbers[0]},(ctypes.c_char_p(b'bounded'),0)),({numbers[1]},(0,4096,0o1600)),({numbers[2]},(0,))):
    ctypes.set_errno(0)
    result=libc.syscall(nr,*args)
    assert result == -1 and ctypes.get_errno() == errno.EPERM,(nr,result,ctypes.get_errno())
os.write(1,b'blocked after exec\\n')
"""
        with anonymous_storage_filter(self.scratch) as descriptor:
            result = subprocess.run([sys.executable,"-I","-S","-B","-c",_INSTALL_AND_EXEC,str(descriptor),target],
                                    pass_fds=(descriptor,),stdin=subprocess.DEVNULL,capture_output=True,env={},timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,b"blocked after exec\n")
        self.assertEqual(result.stderr,b"")

    def test_x32_or_high_syscall_abi_is_killed_instead_of_bypassing_filter(self):
        target = "import ctypes; ctypes.CDLL(None).syscall(0x40000000); raise AssertionError('ABI bypass')"
        with anonymous_storage_filter(self.scratch) as descriptor:
            result = subprocess.run([sys.executable,"-I","-S","-B","-c",_INSTALL_AND_EXEC,str(descriptor),target],
                                    pass_fds=(descriptor,),stdin=subprocess.DEVNULL,capture_output=True,env={},timeout=10)
        self.assertEqual(result.returncode,-signal.SIGSYS,result.stderr)
        self.assertEqual(result.stdout,b"")


if __name__ == "__main__":
    unittest.main()
