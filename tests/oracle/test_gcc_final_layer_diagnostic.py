import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("gcc_layer", ROOT / "scripts/diagnose-gcc-final-layer.py")
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def tar(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        for name, data in entries:
            entry = tarfile.TarInfo(name)
            if isinstance(data, str):
                entry.type = tarfile.SYMTYPE
                entry.linkname = data
                archive.addfile(entry)
            else:
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
    return buf.getvalue()


def export(layer, compressed=False, claimed=None, extra=()):
    blob = gzip.compress(layer) if compressed else layer
    layer_name = "blobs/sha256/" + hashlib.sha256(blob).hexdigest()
    ids = ["sha256:" + "a" * 64] * 8 + [claimed or "sha256:" + hashlib.sha256(layer).hexdigest()]
    config = json.dumps({"rootfs": {"diff_ids": ids}, "history": [{"created_by": "PRIVATE"}]}).encode()
    config_name = "blobs/sha256/" + hashlib.sha256(config).hexdigest()
    manifest = [{"Layers": ["blobs/sha256/" + "a" * 64] * 8 + [layer_name], "Config": config_name}]
    return tar([(layer_name, blob), (config_name, config),
                ("manifest.json", json.dumps(manifest).encode()), *extra])


class FinalLayerTest(unittest.TestCase):
    def test_plain_and_gzip_produce_same_sanitized_comparable_report(self):
        layer = tar([("./usr/include/mpc.h", b"PRIVATE"),
                     ("usr/lib/x86_64-linux-gnu/libmpc.so", "/PRIVATE"),
                     ("usr/share/doc/libmpc-dev/PRIVATE", b"PRIVATE"),
                     ("../../PRIVATE", b"PRIVATE")])
        report = capture.diagnose(io.BytesIO(export(layer)))
        self.assertEqual(report, capture.diagnose(io.BytesIO(export(layer, compressed=True))))
        self.assertEqual("sha256:" + hashlib.sha256(layer).hexdigest(), report["uncompressedDiffId"])
        self.assertEqual(2, report["unlistedEntries"])
        file, link = report["entries"]
        self.assertEqual(hashlib.sha256(b"PRIVATE").hexdigest(), file["sha256"])
        self.assertEqual(hashlib.sha256(b"/PRIVATE").hexdigest(), link["targetSha256"])
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_config_disagreement_and_duplicate_member_rejected(self):
        layer = tar([])
        for data in (export(layer, claimed="sha256:" + "0" * 64),
                     export(layer, extra=[("manifest.json", b"[]")])):
            with self.assertRaises(ValueError):
                capture.diagnose(io.BytesIO(data))

    def test_initial_etc_raw_suffix_measurement(self):
        rest = tar([("usr/include/mpc.h", b"PRIVATE")])
        entry = tarfile.TarInfo("etc")
        entry.type = tarfile.DIRTYPE
        layer = entry.tobuf(format=tarfile.USTAR_FORMAT) + rest
        report = capture.diagnose(io.BytesIO(export(layer)))
        field = "suffixAfterInitialEtcHeaderSha256"
        self.assertEqual(hashlib.sha256(rest).hexdigest(), report[field])
        self.assertEqual("sha256:" + hashlib.sha256(layer).hexdigest(),
                         report["uncompressedDiffId"])
        self.assertIsNone(capture.diagnose(io.BytesIO(export(rest)))[field])
        changed_payload = layer.replace(b"PRIVATE", b"CHANGED")
        changed_trailer = layer + b"TRAILER" + bytes(505)
        for changed in (changed_payload, changed_trailer):
            measured = capture.diagnose(io.BytesIO(export(changed)))[field]
            self.assertEqual(hashlib.sha256(memoryview(changed)[512:]).hexdigest(), measured)
            self.assertNotEqual(report[field], measured)

    def test_initial_extension_withholds_suffix_measurement(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as archive:
            entry = tarfile.TarInfo("etc")
            entry.type = tarfile.DIRTYPE
            entry.pax_headers = {"mtime": "1.5"}
            archive.addfile(entry)
        self.assertIsNone(capture.diagnose(io.BytesIO(export(buf.getvalue())))[
            "suffixAfterInitialEtcHeaderSha256"])

    def test_bad_initial_header_withholds_suffix_measurement(self):
        entry = tarfile.TarInfo("etc")
        entry.type = tarfile.DIRTYPE
        header = bytearray(entry.tobuf(format=tarfile.USTAR_FORMAT))
        header[0] ^= 1
        self.assertIsNone(capture.suffix_after_initial_etc_header_sha256(bytes(header)))
        self.assertIsNone(capture.suffix_after_initial_etc_header_sha256(b"short"))
        entry.size = 512
        self.assertIsNone(capture.suffix_after_initial_etc_header_sha256(entry.tobuf()))

    def test_later_pax_keeps_exact_suffix_measurement(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as archive:
            entry = tarfile.TarInfo("etc")
            entry.type = tarfile.DIRTYPE
            archive.addfile(entry)
            file = tarfile.TarInfo("usr/include/mpc.h")
            file.pax_headers = {"mtime": "1.5"}
            archive.addfile(file)
        layer = buf.getvalue()
        self.assertEqual(hashlib.sha256(memoryview(layer)[512:]).hexdigest(),
                         capture.diagnose(io.BytesIO(export(layer)))[
                             "suffixAfterInitialEtcHeaderSha256"])

    def test_stream_cache_expansion_and_member_bounds(self):
        layer = tar([("usr/include/mpc.h", bytes(20480))])
        data = export(layer, compressed=True)
        for limit in ("EXPORT_LIMIT", "CACHE_LIMIT", "BLOB_LIMIT", "JSON_LIMIT"):
            with self.subTest(limit=limit), patch.object(capture, limit, 2048 if limit == "BLOB_LIMIT" else 32):
                with self.assertRaises(ValueError):
                    capture.diagnose(io.BytesIO(data))
        with self.assertRaises(ValueError):
            capture.inventory(tar([("unlisted", b"")] * 513))


if __name__ == "__main__":
    unittest.main()
