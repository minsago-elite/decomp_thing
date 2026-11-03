from __future__ import annotations

import gzip
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PARSER_PATH = ROOT / "scripts/ci-gcc-toolchain-archive.py"
spec = importlib.util.spec_from_file_location("gcc_archive", PARSER_PATH)
archive_module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(archive_module)


class ArchiveLimitsTest(unittest.TestCase):
    def test_small_expansion_budget_refuses_compressed_overflow(self):
        stream = io.BytesIO(gzip.compress(b"A" * 4096, mtime=0))
        with self.assertRaisesRegex(SystemExit, "expanded layer exceeds"):
            list(archive_module.decoded_chunks(stream, "gzip", 1024))

    def test_truncated_and_trailing_gzip_members_refuse(self):
        valid = gzip.compress(b"payload", mtime=0)
        with self.assertRaisesRegex(SystemExit, "truncated gzip"):
            list(archive_module.decoded_chunks(io.BytesIO(valid[:-3]), "gzip", 1024))
        with self.assertRaisesRegex(SystemExit, "trailing bytes"):
            list(archive_module.decoded_chunks(io.BytesIO(valid + b"garbage"), "gzip", 1024))

    def test_outer_tar_scanner_rejects_bad_checksum_and_oversized_file_before_open(self):
        base = ROOT / "build/pr-merge-audit/gcc-native-builder-repair-implementation/tests"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base, prefix="archive-limit-") as tmp:
            path = Path(tmp) / "header.tar"
            header = bytearray(512)
            header[:4] = b"test"
            header[124:136] = b"00000000000\0"
            header[148:156] = b"0000000\0"
            path.write_bytes(header + b"\0" * 1024)
            with self.assertRaisesRegex(SystemExit, "checksum"):
                archive_module.scan_tar(path)
            with self.assertRaisesRegex(SystemExit, "stored-byte budget"):
                archive_module.scan_tar(path, file_limit=1)

    def test_malformed_pax_length_refuses_within_small_record(self):
        base = ROOT / "build/pr-merge-audit/gcc-native-builder-repair-implementation/tests"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base, prefix="pax-limit-") as tmp:
            path = Path(tmp) / "pax.tar"
            info = bytearray(512)
            info[:8] = b"PaxHeader"
            info[100:108] = b"0000644\0"
            info[108:116] = b"0000000\0"
            info[116:124] = b"0000000\0"
            info[124:136] = b"00000000012\0"
            info[136:148] = b"00000000000\0"
            info[148:156] = b"        "
            info[156:157] = b"x"
            checksum = sum(info)
            info[148:156] = f"{checksum:06o}\0 ".encode()
            path.write_bytes(info + b"not-a-pax\0\0" + b"\0" * 1024)
            with self.assertRaisesRegex(SystemExit, "PAX record length"):
                archive_module.scan_tar(path)


if __name__ == "__main__":
    unittest.main()
