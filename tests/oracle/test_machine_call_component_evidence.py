"""Authored offline provenance fixtures; no builds, network, or original-host input reads."""

from __future__ import annotations

import gzip
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from hashlib import sha256
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("machine_call_evidence", ROOT / "scripts/verify-machine-call-component-evidence.py")
if spec is None:
    raise ImportError("cannot load offline machine-call evidence verifier")
loader = spec.loader
if loader is None:
    raise ImportError("offline machine-call evidence verifier has no loader")
VERIFY = importlib.util.module_from_spec(spec)
loader.exec_module(VERIFY)


def reference(path: str, data: bytes) -> dict:
    return {"path": path, "bytes": len(data), "sha256": sha256(data).hexdigest()}


class MachineCallComponentEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary_root = ROOT / "build/machine-call-evidence-controls"
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="authored-", dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(VERIFY, "REPOSITORY_ROOT", self.root).start()
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})

        def git(*arguments: str) -> str:
            return subprocess.run(["git", "-C", str(self.root), *arguments], env=environment,
                                  capture_output=True, check=True, timeout=10).stdout.decode().strip()

        git("init", "--quiet")
        sources = []
        for index, path in enumerate(sorted(VERIFY.SOURCE_PATHS)):
            data = f"authored source {index}\n".encode()
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            sources.append(reference(path, data))
        inputs = {}
        for name in ("rich", "canonicalOracle", "artifactManifest"):
            path = f"fixtures/{name}.bin"
            data = f"authored committed {name} input\n".encode()
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            inputs[name] = reference(path, data)
        git("add", ".")
        git("-c", "user.name=Authored Evidence Test", "-c", "user.email=evidence-test@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "authored provenance fixture")
        commit, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
        runtime = {"archiveBytes": 569445154, "archiveSha256": "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54",
                   "bridgeSha256": "a" * 64, "bundleManifestSha256": "b" * 64, "languageId": "x86:LE:64:default", "languageVersion": "4.8"}
        request_runtime = runtime | {"bundleRoot": "/unavailable/original/bundle", "ghidraArchivePath": "/unavailable/original/archive.zip"}
        self.request = {"schemaVersion": 1, "kind": "independent-machine-call-request-v1",
                        "canonicalOracle": inputs["canonicalOracle"] | {"path": "/unavailable/original/canonical.json"},
                        "richFile": inputs["rich"] | {"path": "/unavailable/original/rich.elf"},
                        "manifestSha256": inputs["artifactManifest"]["sha256"], "runtime": request_runtime,
                        "limits": dict(VERIFY.LIMIT_CEILINGS), "outputPath": "/unavailable/original/output.json"}
        root = {"id": "symbol-root:authored:1", "rva": "0x10", "endExclusiveRva": "0x16", "fileOffset": 0,
                "ownershipProblems": [], "traversalStops": [], "traversalStopEvents": [], "instructionAttempts": 2,
                "negativeCompleteness": False, "origins": [{"name": "function", "locator": "authored:1", "type": 2,
                    "binding": 1, "visibility": 0, "other": 0, "sectionKind": "defined", "sectionIndex": 1,
                    "sectionName": ".text", "value": "0x1010", "size": "0x6"}]}
        call = {"callerRoot": root["id"], "callerRva": "0x10", "callerCanonicalId": "function", "instructionRva": "0x10",
                "instructionBytes": "e8fbffffff", "instructionLength": 5, "classification": "direct-call", "directTargetRva": "0x10",
                "directTargetAddress": "0x1010", "rawPcodeCallTargetAddress": "0x1010", "targetAgreement": "typed-flow-and-raw-call",
                "targetCanonicalId": "function", "directTargetAddresses": ["0x1010"], "fallthroughAddress": "0x1015",
                "contextStatus": "language-default-no-commits-v1", "disposition": "positive-internal-exact-start", "negativeCompleteness": False}
        counts = {"rawFunctionSymbols": 1, "roots": 1, "canonicalFunctions": 1, "instructionAttempts": 2, "physicalCallSites": 1,
                  "positiveInternalCallSites": 1, "unresolvedCallSites": 0, "rootsWithUnresolvedOwnership": 0, "rootsWithTraversalStops": 0}
        self.report = {"schemaVersion": 1, "kind": "independent-machine-call-positive-observations", "scope": "component",
            "complete": False, "releaseEligible": False, "negativeCompleteness": False, "canonicalPopulationComplete": True,
            "rawSymbolPopulationComplete": True, "inputSha256": inputs["rich"]["sha256"], "inputBytes": inputs["rich"]["bytes"],
            "canonicalOracleSha256": inputs["canonicalOracle"]["sha256"], "artifactManifestSha256": inputs["artifactManifest"]["sha256"],
            "imageBase": "0x1000", "languageId": "x86:LE:64:default", "languageVersion": "4.8",
            "decoderAuthentication": "authenticated-bundled-worker-v1", "limits": dict(VERIFY.LIMIT_CEILINGS),
            "canonicalOracleRecordLimit": 20000, "canonicalPopulation": [{"id": "function", "rva": "0x10", "exclusion": None,
                "rootIds": [root["id"]], "disposition": "owned-symbol-extent"}], "roots": [root], "calls": [call],
            "counts": dict(counts), "runtime": request_runtime, "requestSha256": "", "containmentStatus": "external-owner-required"}
        self.evidence = {"schemaVersion": 1, "kind": "retained-machine-call-component-evidence", "authority": "component-only",
            "complete": False, "releaseEligible": False, "negativeCompleteness": False, "containmentStatus": "external-owner-required",
            "counts": dict(counts), "inputs": inputs, "payloads": {}, "producerJar": {"path": "unretained-producer.jar", "bytes": 999, "sha256": "e" * 64},
            "runtime": runtime, "source": {"commit": commit, "tree": tree, "files": sources}}
        self.directory = self.root / "evidence"
        self.directory.mkdir()
        self.manifest = self.directory / "evidence.json"
        self.write_payloads()

    def write_manifest(self) -> None:
        self.manifest.write_bytes(VERIFY.canonical_bytes(self.evidence))

    def write_payloads(self) -> None:
        request_bytes = VERIFY.canonical_bytes(self.request)
        self.report["requestSha256"] = sha256(request_bytes).hexdigest()
        report_bytes = VERIFY.canonical_bytes(self.report)
        stored = gzip.compress(report_bytes, mtime=0)
        (self.directory / "request.json").write_bytes(request_bytes)
        (self.directory / "report.json.gz").write_bytes(stored)
        self.evidence["payloads"] = {"request": reference("request.json", request_bytes), "report": reference("report.json.gz", report_bytes) |
            {"compression": "gzip", "storedBytes": len(stored), "storedSha256": sha256(stored).hexdigest()}}
        self.write_manifest()

    def verify(self) -> tuple[bytes, dict]:
        return VERIFY.verify_evidence(self.manifest)

    def test_recoverable_bytes_verify_committed_blobs_without_current_checkout_or_original_paths(self) -> None:
        # Current checkout modifications are deliberately ignored; the committed Git blobs are read.
        for reference_ in self.evidence["source"]["files"] + list(self.evidence["inputs"].values()):
            (self.root / reference_["path"]).write_bytes(b"modified working tree")
        recovered, counts = self.verify()
        self.assertEqual(VERIFY.canonical_bytes(self.report), recovered)
        self.assertEqual(self.evidence["counts"], counts)
        self.assertFalse((self.root / "unretained-producer.jar").exists())
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, VERIFY.main([str(self.manifest), "--extract-report", str(self.root / "recovered.json")]))
        self.assertEqual(recovered, (self.root / "recovered.json").read_bytes())
        self.assertIn("source-to-binary attestation are not verified", output.getvalue())

    def test_hash_and_raw_byte_commitments_are_required(self) -> None:
        for target, field in (("request", "sha256"), ("report", "sha256"), ("report", "storedSha256")):
            with self.subTest(target=target, field=field):
                original = self.evidence["payloads"][target][field]
                self.evidence["payloads"][target][field] = "0" * 64
                self.write_manifest()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
                self.evidence["payloads"][target][field] = original
        self.evidence["payloads"]["report"]["bytes"] += 1
        self.write_manifest()
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_gzip_rejects_corruption_truncation_concatenation_trailing_and_overflow(self) -> None:
        original = (self.directory / "report.json.gz").read_bytes()
        for changed in (original[:-1], original + b"trailing", original + gzip.compress(b"", mtime=0), b"corrupt" + original[7:]):
            with self.subTest(length=len(changed)):
                (self.directory / "report.json.gz").write_bytes(changed)
                # Deliberately update the outer stored digest to test the gzip boundary itself.
                self.evidence["payloads"]["report"]["storedBytes"] = len(changed)
                self.evidence["payloads"]["report"]["storedSha256"] = sha256(changed).hexdigest()
                self.write_manifest()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.inflate_report(gzip.compress(b"x" * 1025, mtime=0), maximum=1024)

    def test_source_commit_tree_and_every_source_and_input_blob_are_bound(self) -> None:
        for field in ("commit", "tree"):
            original = self.evidence["source"][field]
            self.evidence["source"][field] = "0" * 40
            self.write_manifest()
            with self.assertRaises(VERIFY.VerificationError):
                self.verify()
            self.evidence["source"][field] = original
        for reference_ in self.evidence["source"]["files"] + list(self.evidence["inputs"].values()):
            original = reference_["sha256"]
            reference_["sha256"] = "0" * 64
            self.write_manifest()
            with self.assertRaises(VERIFY.VerificationError):
                self.verify()
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.verify_git_blob(self.evidence["source"]["commit"], reference_)
            reference_["sha256"] = original

    def test_authority_flags_counts_runtime_and_input_relations_cannot_be_rehashed_away(self) -> None:
        mutations = [
            (self.report, "complete", True), (self.report, "releaseEligible", True), (self.report, "negativeCompleteness", True),
            (self.report["roots"][0], "negativeCompleteness", True), (self.report["calls"][0], "negativeCompleteness", True),
            (self.report["counts"], "physicalCallSites", 2), (self.report, "inputSha256", "0" * 64),
            (self.report, "runtime", self.request["runtime"] | {"bridgeSha256": "0" * 64}),
            (self.report, "containmentStatus", "contained"), (self.evidence, "authority", "production"),
            (self.evidence, "releaseEligible", True), (self.request, "manifestSha256", "0" * 64),
        ]
        for container, key, changed in mutations:
            with self.subTest(field=key, changed=changed):
                original = container[key]
                container[key] = changed
                self.write_payloads()  # Deliberately refresh payload digests, leaving cross-links to reject the claim.
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
                container[key] = original

    def test_json_is_bounded_duplicate_free_closed_and_canonical(self) -> None:
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1.0}', b'{"a":"\\ud800"}',
                     b'{"a":' + b'[' * 65 + b'0' + b']' * 65 + b'}', b'{}', b'{}\n\n'):
            with self.subTest(data=data[:40]), self.assertRaises(VERIFY.VerificationError):
                VERIFY.parse_canonical(data)
        self.evidence["unexpected"] = False
        self.write_manifest()
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_fifo_substitution_after_path_validation_refuses_without_blocking(self) -> None:
        victim = self.root / "fifo-substitution.bin"
        victim.write_bytes(b"authored regular file")
        child = r"""
import importlib.util
import os
from pathlib import Path
import stat
import sys
spec = importlib.util.spec_from_file_location("evidence_fifo_control", sys.argv[1])
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)
verify.REPOSITORY_ROOT = Path(sys.argv[2])
victim = verify.REPOSITORY_ROOT / "fifo-substitution.bin"
original = os.open
def substitute(path, flags, *args, **kwargs):
    if path == victim.name:
        assert kwargs.get("dir_fd") is not None
        victim.unlink()
        os.mkfifo(victim, 0o600)
    return original(path, flags, *args, **kwargs)
os.open = substitute
try:
    verify.read_file(victim, 64)
except verify.VerificationError:
    assert stat.S_ISFIFO(victim.lstat().st_mode)
    print("real FIFO substitution refused")
else:
    raise AssertionError("substituted FIFO was accepted")
"""
        result = subprocess.run([sys.executable, "-c", child,
            str(ROOT / "scripts/verify-machine-call-component-evidence.py"), str(self.root)],
            env=os.environ | {"PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, timeout=5, check=True)
        self.assertIn(b"real FIFO substitution refused", result.stdout)

    def parent_substitution_control(self, operation: str, stage: str) -> None:
        fixture = self.root / f"{operation}-{stage}"
        repository = fixture / "repository"
        parent = repository / "selected"
        moved = repository / "original"
        outside = fixture / "outside-repository"
        for directory in (parent / "nested", outside / "nested"):
            directory.mkdir(parents=True)
        victim = parent / "nested/report.json"
        outside_victim = outside / "nested/report.json"
        if operation == "read":
            victim.write_bytes(b"original repository bytes")
            outside_victim.write_bytes(b"outside repository bytes")
        original_path = VERIFY.repository_path
        original_open = os.open
        replaced = False

        def substitute() -> None:
            nonlocal replaced
            self.assertFalse(replaced)
            parent.rename(moved)
            parent.symlink_to(outside, target_is_directory=True)
            replaced = True

        def after_validation(path, *, existing):
            selected = original_path(path, existing=existing)
            if stage == "after-validation":
                substitute()
            return selected

        def before_leaf(path, flags, *args, **kwargs):
            if stage == "before-leaf" and path == "report.json":
                self.assertIn("dir_fd", kwargs)
                substitute()
            return original_open(path, flags, *args, **kwargs)

        with mock.patch.object(VERIFY, "REPOSITORY_ROOT", repository), \
                mock.patch.object(VERIFY, "repository_path", side_effect=after_validation), \
                mock.patch.object(VERIFY.os, "open", side_effect=before_leaf):
            def perform():
                if operation == "read":
                    return VERIFY.read_file(victim, 1024)
                VERIFY.extract_report(victim, b"verified report")

            if stage == "after-validation":
                # A substituted parent cannot be opened as a nonsymlink directory.
                with self.assertRaises((VERIFY.VerificationError, OSError)):
                    perform()
            elif operation == "read":
                self.assertEqual(b"original repository bytes", perform())
            else:
                perform()
                self.assertEqual(b"verified report", (moved / "nested/report.json").read_bytes())
        self.assertTrue(replaced)
        if operation == "read":
            self.assertEqual(b"outside repository bytes", outside_victim.read_bytes())
        else:
            self.assertFalse(outside_victim.exists())

    def test_parent_substitution_cannot_redirect_reads(self) -> None:
        for stage in ("after-validation", "before-leaf"):
            with self.subTest(stage=stage):
                self.parent_substitution_control("read", stage)

    def test_parent_substitution_cannot_redirect_extraction(self) -> None:
        for stage in ("after-validation", "before-leaf"):
            with self.subTest(stage=stage):
                self.parent_substitution_control("extract", stage)

    def test_failed_extraction_cleans_up_using_retained_parent_not_substituted_path(self) -> None:
        repository = self.root / "cleanup-repository"
        parent = repository / "selected"
        moved = repository / "original"
        outside = self.root / "cleanup-outside"
        parent.mkdir(parents=True)
        outside.mkdir()
        outside_victim = outside / "report.json"
        outside_victim.write_bytes(b"outside file must survive")

        def fail_sync(descriptor):
            parent.rename(moved)
            parent.symlink_to(outside, target_is_directory=True)
            raise OSError("authored sync failure after parent substitution")

        with (mock.patch.object(VERIFY, "REPOSITORY_ROOT", repository),
              mock.patch.object(VERIFY.os, "fsync", side_effect=fail_sync),
              self.assertRaisesRegex(OSError, "authored sync failure")):
            VERIFY.extract_report(parent / "report.json", b"verified report")
        self.assertFalse((moved / "report.json").exists())
        self.assertEqual(b"outside file must survive", outside_victim.read_bytes())
    def test_parent_substitution_cannot_redirect_read_create_or_failure_cleanup(self) -> None:
        # Deterministic syscall-boundary substitutions, not timing-dependent race loops.
        for operation in ("read", "create", "cleanup"):
            with self.subTest(operation=operation):
                base = self.root / operation
                repository = base / "repository"
                parent = repository / "parent"
                outside = base / "outside"
                parent.mkdir(parents=True)
                outside.mkdir()
                held = repository / "held-parent"
                destination = parent / "report.json"
                sentinel = outside / destination.name
                sentinel.write_bytes(b"outside sentinel")
                if operation == "read":
                    destination.write_bytes(b"inside input")
                original_open = os.open
                substituted = False

                def substitute(path, flags, *args, destination=destination, parent=parent, held=held,
                               outside=outside, original_open=original_open, **kwargs):
                    nonlocal substituted
                    if path == destination.name:
                        self.assertIsNotNone(kwargs.get("dir_fd"))
                        self.assertFalse(substituted)
                        parent.rename(held)
                        parent.symlink_to(outside, target_is_directory=True)
                        substituted = True
                    return original_open(path, flags, *args, **kwargs)

                with mock.patch.object(VERIFY, "REPOSITORY_ROOT", repository), mock.patch.object(VERIFY.os, "open", substitute):
                    if operation == "read":
                        self.assertEqual(b"inside input", VERIFY.read_file(destination, 64))
                    elif operation == "create":
                        VERIFY.extract_report(destination, b"inside output")
                        self.assertEqual(b"inside output", (held / destination.name).read_bytes())
                    else:
                        with (mock.patch.object(VERIFY.os, "fsync", side_effect=OSError("authored write failure")),
                              self.assertRaisesRegex(OSError, "authored write failure")):
                            VERIFY.extract_report(destination, b"partial output")
                        self.assertFalse((held / destination.name).exists())
                self.assertTrue(substituted)
                self.assertEqual(b"outside sentinel", sentinel.read_bytes())

    def test_parent_substitution_before_directory_open_is_rejected(self) -> None:
        parent = self.root / "race-parent"
        parent.mkdir()
        outside = self.root / "race-outside"
        outside.mkdir()
        original_open = os.open

        def substitute(path, flags, *args, **kwargs):
            if path == parent.name:
                parent.rename(self.root / "race-held")
                parent.symlink_to(outside, target_is_directory=True)
            return original_open(path, flags, *args, **kwargs)

        with (mock.patch.object(VERIFY.os, "open", substitute), self.assertRaises(OSError)):
            VERIFY.extract_report(parent / "report.json", b"must not escape")
        self.assertEqual([], list(outside.iterdir()))

    def test_read_refuses_symlink_parent_final_symlink_and_oversized_input(self) -> None:
        victim = self.root / "input.bin"
        victim.write_bytes(b"bounded input")
        link = self.root / "input-link"
        link.symlink_to(victim)
        parent_link = self.root / "input-parent-link"
        parent_link.symlink_to(self.directory, target_is_directory=True)
        for candidate in (link, parent_link / "request.json", self.directory):
            with self.subTest(path=candidate), self.assertRaises((VERIFY.VerificationError, OSError)):
                VERIFY.read_file(candidate, 64)
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.read_file(victim, 1)
    def test_extraction_refuses_overwrite_symlinks_missing_parent_and_repository_escape(self) -> None:
        recovered, _ = self.verify()
        output = self.root / "output.json"
        VERIFY.extract_report(output, recovered)
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.extract_report(output, recovered)
        link = self.root / "link.json"
        link.symlink_to(output)
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(self.directory, target_is_directory=True)
        for destination in (link, parent_link / "output.json", self.root / "absent/output.json", self.root.parent / "escape.json"):
            with self.subTest(path=destination), self.assertRaises((VERIFY.VerificationError, OSError)):
                VERIFY.extract_report(destination, recovered)
        self.assertEqual(recovered, output.read_bytes())
        self.assertFalse((self.directory / "output.json").exists())


if __name__ == "__main__":
    unittest.main()
