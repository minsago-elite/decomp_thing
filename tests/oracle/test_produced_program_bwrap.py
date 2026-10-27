"""Pure controls for the supplemental bubblewrap produced-program observation.

Nothing here launches bubblewrap or Clang. The optional live control runs only when
DECOMP_PRODUCED_PROGRAM_BWRAP_ARTIFACT_ROOT names a directory holding the authenticated locked Clang.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from oracle.behavior_corpus import BehaviorCorpusError
from oracle.llvm import produced_program_bwrap as bw
from oracle.llvm.produced_program import ARGUMENTS, CLANG, MANIFEST_SHA256, MARKER, SOURCE_SHA256


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def blob(payload: bytes) -> dict:
    return {"bytes": len(payload), "sha256": sha(payload), "base64": base64.b64encode(payload).decode("ascii")}


def synthetic_program(name: bytes = b"abcdef", extra: bytes = b"") -> bytes:
    """Static amd64 ET_EXEC with one executable PT_LOAD, one temporary-object name; never executed."""
    code = b"\x90" * 16
    strings = b"\0start-" + name + b".o\0" + extra
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQ", header, 16, 2, 62, 1, 0x401000, 64)
    struct.pack_into("<HHH", header, 52, 64, 56, 1)
    body = 64 + 56
    size = len(code) + len(strings)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, body, 0x401000, 0x401000, size, size, 0x1000)
    return bytes(header) + phdr + code + strings


def result(exit_code=0, stdout=b"", stderr=b"", wall=5) -> dict:
    return {"exitCode": exit_code, "stdout": blob(stdout), "stderr": blob(stderr), "wallMillis": wall}


def run_record(program: bytes, normalized: str | None = None) -> dict:
    if normalized is None:
        normalized = sha(bw.normalize_program(program))
    artifact = {"path": "program", "mode": "0o755", "normalizedSha256": normalized, **blob(program)}
    return {"compile": result(0, b"", bw.COMPILE_STDERR), "artifact": artifact,
            "execution": result(bw.EXPECTED_EXIT, MARKER, b"")}


def valid_document() -> dict:
    libs = [{"path": "/lib64/ld-linux-x86-64.so.2", "bytes": 1, "sha256": "0" * 64},
            {"path": "/usr/lib/x86_64-linux-gnu/libc.so.6", "bytes": 2, "sha256": "1" * 64}]
    return {"schemaVersion": 1, "profile": bw.PROFILE_ID, "authority": dict(bw.AUTHORITY), "limits": dict(bw.LIMITS),
            "manifestSha256": MANIFEST_SHA256, "sourceSha256": SOURCE_SHA256, "clang": dict(CLANG),
            "argv": list(ARGUMENTS),
            "host": {"kernelRelease": "6.8.0", "machine": "x86_64", "osId": "ubuntu", "osVersionId": "24.04",
                     "bubblewrap": "bubblewrap 0.9.0"},
            "linker": {"path": "/usr/bin/ld", "realPath": "/usr/bin/x86_64-linux-gnu-ld.bfd",
                       "versionLine": "GNU ld (GNU Binutils for Ubuntu) 2.42", "bytes": 3, "sha256": "2" * 64},
            "libraries": libs,
            "runs": [run_record(synthetic_program(b"abcdef")), run_record(synthetic_program(b"123abc"))]}


class ParseLdListTest(unittest.TestCase):
    def test_ubuntu_and_gentoo_shapes(self):
        output = ("\tlinux-vdso.so.1 (0x00007ffd0d3f4000)\n"
                  "\tlibm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f3a1c000000)\n"
                  "\tlibstdc++.so.6 => /usr/lib/gcc/x86_64-pc-linux-gnu/16/libstdc++.so.6 (0x00007f3a1b000000)\n"
                  "\t/lib64/ld-linux-x86-64.so.2 (0x00007f3a1c500000)\n")
        self.assertEqual(bw.parse_ld_list(output), ["/lib/x86_64-linux-gnu/libm.so.6",
                         "/usr/lib/gcc/x86_64-pc-linux-gnu/16/libstdc++.so.6", "/lib64/ld-linux-x86-64.so.2"])

    def test_missing_empty_and_oversized_closures_fail(self):
        with self.assertRaises(BehaviorCorpusError):
            bw.parse_ld_list("\tlibfoo.so.1 => not found\n")
        with self.assertRaises(BehaviorCorpusError):
            bw.parse_ld_list("\tlinux-vdso.so.1 (0x00007ffd0d3f4000)\n")
        many = "".join(f"\tlib{i}.so => /lib/lib{i}.so (0x1)\n" for i in range(bw.LIMITS["closureLibraries"] + 1))
        with self.assertRaises(BehaviorCorpusError):
            bw.parse_ld_list(many)


class NormalizationTest(unittest.TestCase):
    def test_only_the_single_temporary_name_is_normalized(self):
        a, b = synthetic_program(b"abcdef"), synthetic_program(b"012345")
        self.assertNotEqual(a, b)
        self.assertEqual(bw.normalize_program(a), bw.normalize_program(b))
        self.assertEqual(len(bw.normalize_program(a)), len(a))

    def test_zero_or_two_names_and_other_differences_refuse(self):
        for payload in (synthetic_program(b"abcdef").replace(b"start-abcdef.o", b"start-abcdefg.o"),
                        synthetic_program(b"abcdef", b"start-123456.o\0")):
            with self.assertRaises(BehaviorCorpusError):
                bw.normalize_program(payload)


class VerifyObservationTest(unittest.TestCase):
    def test_valid_document_verifies(self):
        self.assertEqual(bw.verify_observation(valid_document())["profile"], bw.PROFILE_ID)

    def assert_refused(self, mutate):
        document = valid_document()
        mutate(document)
        with self.assertRaises(BehaviorCorpusError):
            bw.verify_observation(document)

    def test_envelope_authority_and_pins(self):
        self.assert_refused(lambda d: d.update(extra=1))
        self.assert_refused(lambda d: d.update(profile="other"))
        self.assert_refused(lambda d: d["authority"].update(releaseQualified=True))
        self.assert_refused(lambda d: d["authority"].update(historicalOciProfileReused=True))
        self.assert_refused(lambda d: d["limits"].update(wallSeconds=11))
        self.assert_refused(lambda d: d.update(manifestSha256="0" * 64))
        self.assert_refused(lambda d: d.update(sourceSha256="0" * 64))
        self.assert_refused(lambda d: d["clang"].update(bytes=1))
        self.assert_refused(lambda d: d["argv"].append("-O2"))

    def test_host_linker_and_library_shapes(self):
        self.assert_refused(lambda d: d["host"].update(machine="aarch64"))
        self.assert_refused(lambda d: d["linker"].update(versionLine="LLD 22"))
        self.assert_refused(lambda d: d["linker"].update(sha256="zz"))
        self.assert_refused(lambda d: d.update(libraries=[]))
        self.assert_refused(lambda d: d["libraries"][0].update(path="relative/lib.so"))

    def test_run_population(self):
        self.assert_refused(lambda d: d["runs"].pop())
        self.assert_refused(lambda d: d["runs"].append(copy.deepcopy(d["runs"][0])))
        self.assert_refused(lambda d: d["runs"][0].update(extra=1))

    def test_streams_and_exit_statuses(self):
        self.assert_refused(lambda d: d["runs"][0]["compile"].update(exitCode=1))
        self.assert_refused(lambda d: d["runs"][1]["compile"].update(stderr=blob(b"")))
        self.assert_refused(lambda d: d["runs"][0]["compile"].update(stdout=blob(b"x")))
        self.assert_refused(lambda d: d["runs"][0]["execution"].update(exitCode=0))
        self.assert_refused(lambda d: d["runs"][1]["execution"].update(stdout=blob(b"other\n")))
        self.assert_refused(lambda d: d["runs"][1]["execution"].update(stderr=blob(b"boom")))
        self.assert_refused(lambda d: d["runs"][0]["execution"].update(wallMillis=bw.LIMITS["wallSeconds"] * 1000 + 1))

    def test_artifact_identity_and_elf_shape(self):
        self.assert_refused(lambda d: d["runs"][0]["artifact"].update(sha256="0" * 64))
        self.assert_refused(lambda d: d["runs"][0]["artifact"].update(normalizedSha256="0" * 64))
        self.assert_refused(lambda d: d["runs"][0]["artifact"].update(mode="0o777"))
        self.assert_refused(lambda d: d["runs"][0]["artifact"].update(base64=d["runs"][0]["artifact"]["base64"][:-4]))

        def replace_with(d, program):
            d["runs"][1] = run_record(program, normalized="0" * 64)
        dynamic = bytearray(synthetic_program(b"654321"))
        struct.pack_into("<I", dynamic, 64, 3)  # PT_INTERP: dynamic dependencies are refused
        d_ok = bytes(dynamic)
        self.assert_refused(lambda d: d["runs"].__setitem__(1, run_record(d_ok)))
        self.assert_refused(lambda d: replace_with(d, b"not an elf at all"))

    def test_programs_must_match_after_the_one_normalization(self):
        def differ(d):
            other = bytearray(synthetic_program(b"fedcba"))
            other[130] ^= 0xFF  # inside the code, not the temporary name
            d["runs"][1] = run_record(bytes(other))
        self.assert_refused(differ)


class LoadObservationTest(unittest.TestCase):
    def test_canonical_json_roundtrip_and_noncanonical_refusal(self):
        document = valid_document()
        canonical = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observation.json"
            path.write_bytes(canonical)
            os.chmod(path, 0o600)
            self.assertEqual(bw.load_observation(path)["profile"], bw.PROFILE_ID)
            path.write_bytes(json.dumps(document).encode())
            with self.assertRaises(BehaviorCorpusError):
                bw.load_observation(path)


class LiveObservationTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("DECOMP_PRODUCED_PROGRAM_BWRAP_ARTIFACT_ROOT"),
                         "live control needs the authenticated locked Clang artifact root")
    def test_live_pair(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(dir=root / "build") as directory:
            document = bw.observe(bw.PROFILE / "oracle-manifest.json",
                                  Path(os.environ["DECOMP_PRODUCED_PROGRAM_BWRAP_ARTIFACT_ROOT"]),
                                  Path(directory), Path("/usr/bin/bwrap"))
        self.assertEqual(bw.verify_observation(document)["runs"][0]["execution"]["exitCode"], bw.EXPECTED_EXIT)


if __name__ == "__main__":
    unittest.main()
