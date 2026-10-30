"""Offline provenance controls; no builds, network, or original-host input reads.

The retained-driver regression requires the two recorded source commits locally;
CI fetches those objects before these tests, never from inside the verifier.
"""

from __future__ import annotations

import copy
import gzip
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from contextlib import redirect_stdout
from hashlib import sha256
from importlib.machinery import ModuleSpec
from pathlib import Path
from typing import cast
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("machine_call_evidence", ROOT / "scripts/verify-machine-call-component-evidence.py")
if spec is None:
    raise ImportError("cannot load offline machine-call evidence verifier")
spec = cast(ModuleSpec, spec)
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

        self.git = git
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
            if name == "rich":
                data = data.ljust(4096, b"\0")  # Space for authored file-backed code/version witnesses.
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

        with (
            mock.patch.object(VERIFY, "REPOSITORY_ROOT", repository),
            mock.patch.object(VERIFY.os, "fsync", side_effect=fail_sync),
            self.assertRaisesRegex(OSError, "authored sync failure"),
        ):
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


class ExternalCallComponentEvidenceTest(unittest.TestCase):
    root: Path
    git: Callable[..., str]

    # Reuse the tiny authored Git fixture without inheriting/re-running the eight machine controls.
    write_manifest = MachineCallComponentEvidenceTest.write_manifest
    write_payloads = MachineCallComponentEvidenceTest.write_payloads
    verify = MachineCallComponentEvidenceTest.verify

    def setUp(self) -> None:
        MachineCallComponentEvidenceTest.setUp(cast(MachineCallComponentEvidenceTest, self))
        call = self.report["calls"][0]
        call.update(instructionBytes="e8eb0f0000", directTargetRva="0x1000", directTargetAddress="0x2000",
            rawPcodeCallTargetAddress="0x2000", directTargetAddresses=["0x2000"], targetCanonicalId=None,
            disposition="unresolved-target-outside-canonical-population")
        for counts in (self.report["counts"], self.evidence["counts"]):
            counts.update(positiveInternalCallSites=0, unresolvedCallSites=1)
        self.write_payloads()
        self.source_evidence = copy.deepcopy(self.evidence)
        self.source_report = copy.deepcopy(self.report)
        self.source_request = copy.deepcopy(self.request)
        self.source_manifest = self.manifest
        self.source_directory = self.directory
        for index, path in enumerate(sorted(VERIFY.EXTERNAL_SOURCE_PATHS - VERIFY.SOURCE_PATHS)):
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(f"authored external source {index}\n".encode())
        self.git("add", ".")
        self.commit("authored external source and retained machine payloads")
        source = self.source_provenance()
        runtime = copy.deepcopy(self.source_request["runtime"])
        runtime["bridgeSha256"] = "c" * 64  # The new bridge legitimately differs from the source run's bridge.
        runtime["bridgeSnapshot"] = {"path": "/unavailable/original/bridge.runtime", "bytes": 3,
            "sha256": runtime["bridgeSha256"]}
        runtime["bundleManifestSnapshot"] = {"path": "/unavailable/original/manifest.runtime", "bytes": 3,
            "sha256": runtime["bundleManifestSha256"]}
        report_runtime = {key: runtime[key] for key in VERIFY.RUNTIME | VERIFY.RUNTIME_PATHS}
        self.request = {"schemaVersion": 1, "kind": "independent-external-call-request-v1",
            "richFile": copy.deepcopy(self.source_request["richFile"]),
            "sourceReport": self.source_evidence["payloads"]["report"] | {"path": "/unavailable/source-report.json"},
            "sourceRequest": self.source_evidence["payloads"]["request"] | {"path": "/unavailable/source-request.json"},
            "runtime": runtime, "outputPath": "/unavailable/external-report.json", "limits": dict(VERIFY.EXTERNAL_LIMITS),
            "metadataPolicy": "elf-dynamic-binding-default-limits-v1"}
        self.request["sourceReport"] = {key: self.request["sourceReport"][key] for key in ("path", "bytes", "sha256")}
        input_sha = self.source_report["inputSha256"]
        symbol = {"tableSectionIndex": 1, "symbolIndex": 1, "locator": "dynsym:1:1", "nameOffset": 1, "name": "imported_function",
            "info": 18, "other": 0, "type": 2, "binding": 1, "visibility": 0, "rawSectionIndex": 0, "resolvedSectionIndex": 0,
            "sectionKind": "undefined", "value": "0x0", "size": "0x0", "version": None}
        relocation = {"sectionIndex": 2, "relocationIndex": 0, "fileOffset": 0, "locator": "rela:2:0", "symbolTableSectionIndex": 1,
            "symbolIndex": 1, "offset": "0x3000", "type": 7, "addend": 0, "dynamicTables": ["jmprel"],
            "slotFileOffset": 0, "slotLoadIndices": [0], "dispositions": []}
        inventory = {"schemaVersion": 1, "kind": "independent-elf-dynamic-bindings-v1", "authority": "diagnostic-authenticated-elf-metadata",
            "inputSha256": input_sha, "elfClass": 2, "byteOrder": 1, "elfType": "ET_DYN", "machine": 62, "imageBase": "0x1000",
            "activeSymbolTableSectionIndex": 1, "symbolPopulationBasis": "section-declared-dynsym", "complete": False,
            "releaseEligible": False, "negativeCompleteness": False, "sections": [
                {"index": index, "name": name, "type": kind, "flags": "0x2", "address": start, "offset": offset,
                 "size": size, "link": link, "info": 0, "alignment": "0x8", "entrySize": width}
                for index, name, kind, start, offset, size, link, width in (
                    (1, ".dynsym", 11, "0x7000", 256, "0x30", 3, "0x18"),
                    (2, ".rela.plt", 4, "0x4000", 0, "0x18", 1, "0x18"),
                    (3, ".dynstr", 3, "0x7100", 512, "0x40", 0, "0x0"),
                    (5, ".rela.dyn", 4, "0x5000", 24, "0x0", 1, "0x18"))], "programHeaders": [{"index": 0, "type": 1,
                "flags": 6, "offset": "0x0", "virtualAddress": "0x3000", "physicalAddress": "0x3000", "fileSize": "0x8",
                "memorySize": "0x8", "alignment": "0x1"}], "dynamicEntries": [
                    {"index": index, "fileOffset": index * 16, "tag": hex(tag), "value": hex(value)}
                    for index, (tag, value) in enumerate(((23, 0x4000), (2, 24), (20, 7), (7, 0x5000), (8, 0), (9, 24),
                                                         (6, 0x7000), (11, 24), (5, 0x7100), (10, 64), (1, 20), (0, 0)))],
            "dynamicSymbols": [symbol | {"symbolIndex": 0, "locator": "dynsym:1:0", "nameOffset": 0,
                "name": "", "info": 0, "type": 0, "binding": 0}, symbol], "relocations": [relocation], "versionRequirements": [], "versionDefinitions": [],
            "neededLibraries": ["libexample.so"], "unsupportedReasons": ["dynamic-hash-population-not-reconciled",
                "runtime-provider-and-interposition-unresolved"]}
        # Dynamic relocation sections need their own file-backed LOAD witnesses;
        # leave room for tests that extend the separate relative-relocation table.
        for index, start, offset, size in ((20, 0x4000, 0, 24), (21, 0x5000, 24, 128)):
            inventory["programHeaders"].append({"index": index, "type": 1, "flags": 4, "offset": hex(offset),
                "virtualAddress": hex(start), "physicalAddress": hex(start), "fileSize": hex(size),
                "memorySize": hex(size), "alignment": "0x1"})
        for index, name, start, offset in ((9, ".text", 0x1010, 160), (10, ".plt", 0x2000, 200)):
            inventory["sections"].append({"index": index, "name": name, "type": 1, "flags": "0x6", "address": hex(start),
                "offset": offset, "size": "0xf", "link": 0, "info": 0, "alignment": "0x1", "entrySize": "0x0"})
            inventory["programHeaders"].append({"index": index, "type": 1, "flags": 5, "offset": hex(offset),
                "virtualAddress": hex(start), "physicalAddress": hex(start), "fileSize": "0xf", "memorySize": "0xf", "alignment": "0x1"})
        inventory["sections"][0]["info"] = 1
        inventory["sections"].append({"index": 23, "name": ".dynamic", "type": 6, "flags": "0x2", "address": "0x7200",
            "offset": 768, "size": "0xb0", "link": 3, "info": 0, "alignment": "0x8", "entrySize": "0x10"})
        for index, start, offset, size in ((24, 0x7000, 256, 48), (25, 0x7100, 512, 64), (26, 0x7200, 768, 176)):
            inventory["programHeaders"].append({"index": index, "type": 1, "flags": 4, "offset": hex(offset),
                "virtualAddress": hex(start), "physicalAddress": hex(start), "fileSize": hex(size),
                "memorySize": hex(size), "alignment": "0x1"})
        inventory["programHeaders"].append(inventory["programHeaders"][-1] | {"index": 23, "type": 2})
        self.sync_dynamic_storage(inventory)
        identity = {"schemaVersion": 1, "namespace": "elf-static-import-request-v1", "inputSha256": input_sha,
            "symbolTableSectionIndex": 1, "symbolIndex": 1, "name": "imported_function", "type": 2, "binding": 1, "visibility": 0,
            "version": None, "weakMayRemainNull": False, "ifuncImplementationUnresolved": False, "runtimeProviderAvailable": False,
            "runtimeImplementationAvailable": False, "interpositionUnresolved": True}
        identifier = "ext-" + sha256(VERIFY.canonical_bytes(identity)).hexdigest()
        namespace = {"schemaVersion": 1, "kind": "elf-static-import-request-namespace-v1", "inputSha256": input_sha,
            "populationBasis": "eligible-section-declared-undefined-dynamic-symbols", "runtimeImplementationAvailable": False,
            "negativeCompleteness": False, "entries": [{"id": identifier, "identity": identity}]}
        coverage = {"kind": "elf-relocation-slot-write-coverage-v1", "slotAddress": "0x3000", "candidateLocator": "rela:2:0",
            "candidateActive": True, "candidateCoversSlot": True, "slotAddressOverflow": False, "unknownWriteWidth": False,
            "writeAddressOverflow": False, "overlappingWrite": False, "overlapLocator": None, "unknownWidthLocator": None,
            "overflowLocator": None, "safeForStaticSlotAssociation": True, "negativeCompleteness": False}
        binding = {"slotAddress": "0x3000", "relocationLocator": "rela:2:0", "relocationType": 7, "relocationAddend": 0,
            "dynamicTables": ["jmprel"], "slotLoadIndices": [0], "slotFileOffset": 0, "relocationDispositions": [],
            "writeCoverage": coverage, "symbolTableSectionIndex": 1, "symbolIndex": 1, "symbolLocator": "dynsym:1:1",
            "runtimeImplementationAvailable": False, "runtimeProviderAvailable": False}
        transfer = {"address": "0x2000", "length": 6, "bytes": "ff25fa0f0000", "classification": "indirect-jump",
            "pointerSlotAddress": "0x3000", "pointerWidthBytes": 8, "relationship": "static-ram-varnode-exact-transfer-v1",
            "rawReadOpcode": "BRANCHIND", "rawReadOpIndex": 0, "rawTransferOpcode": "BRANCHIND", "rawTransferOpIndex": 0,
            "rawCopyOpIndices": [], "contextStatus": "language-default-no-commits-v1", "unresolvedReason": None}
        site = {key: call[key] for key in ("callerRoot", "callerCanonicalId", "callerRva", "instructionRva", "instructionBytes", "instructionLength")}
        site.update(sourceOrdinal=0, returnAddress=call["fallthroughAddress"], physicalClassification=call["classification"],
            physicalTargetAddress=call["directTargetAddress"], sourceDisposition=call["disposition"], compositionDisposition="static-import-request-reference",
            targetBindingDisposition="static-import-request-reference", externalTargetId=identifier, viaForwarder=True,
            memoryProbe={"address": "0x2000", "availableBytes": "ff25fa0f0000" + "00" * 9, "refusal": None}, memoryTransfer=transfer,
            relocationBinding=binding, negativeCompleteness=False)
        counts = {"sourcePhysicalSites": 1, "composedSiteRecords": 1, "namespaceEntries": 1, "dispositions": {"static-import-request-reference": 1}}
        self.report = {"schemaVersion": 1, "kind": "independent-external-call-component-v1", "scope": "component",
            "decoderAuthentication": "authenticated-bundled-worker-v1", "complete": False, "releaseEligible": False,
            "negativeCompleteness": False, "sourceCallRecordsEnumerated": True, "sourceCallPopulationComplete": False,
            "limits": dict(VERIFY.EXTERNAL_LIMITS), "metadataPolicy": "elf-dynamic-binding-default-limits-v1", "inputSha256": input_sha,
            "inputBytes": self.source_report["inputBytes"], "imageBase": "0x1000", "sourceReportSha256": self.request["sourceReport"]["sha256"],
            "sourceRequestSha256": self.request["sourceRequest"]["sha256"], "externalNamespaceSha256": sha256(VERIFY.canonical_bytes(namespace)).hexdigest(),
            "externalNamespace": namespace, "sourceCanonicalPopulation": [{key: row[key] for key in ("id", "rva", "exclusion")}
                for row in self.source_report["canonicalPopulation"]], "dynamicInventory": inventory, "sites": [site], "counts": copy.deepcopy(counts),
            "requestSha256": "", "runtime": report_runtime, "containmentStatus": "external-owner-required"}
        self.evidence = {"schemaVersion": 1, "kind": VERIFY.EXTERNAL_KIND, "authority": "component-only", "complete": False,
            "releaseEligible": False, "negativeCompleteness": False, "containmentStatus": "external-owner-required", "counts": counts,
            "inputs": {"rich": copy.deepcopy(self.source_evidence["inputs"]["rich"])}, "payloads": {},
            "producerJar": copy.deepcopy(self.source_evidence["producerJar"]), "runtime": {key: runtime[key] for key in VERIFY.RUNTIME},
            "source": source, "sourceEvidence": reference("evidence/evidence.json", self.source_manifest.read_bytes())}
        self.directory = self.root / "external-evidence"
        self.directory.mkdir()
        self.manifest = self.directory / "evidence.json"
        self.write_payloads()
        self.assertEqual(VERIFY.canonical_bytes(self.report), self.verify()[0])

    @staticmethod
    def sync_dynamic_storage(inventory: dict) -> None:
        """Build valid authored tag storage before mutations (never during payload rehash)."""
        section = next(row for row in inventory["sections"] if row["type"] == 6)
        size = len(inventory["dynamicEntries"]) * 16
        section["size"] = hex(size)
        for index, entry in enumerate(inventory["dynamicEntries"]):
            entry.update(index=index, fileOffset=section["offset"] + index * 16)
        for program in inventory["programHeaders"]:
            if program["index"] in {23, 26}:
                program.update(fileSize=hex(size), memorySize=hex(size))

    def commit(self, message: str) -> None:
        self.git("-c", "user.name=Authored Evidence Test", "-c", "user.email=evidence-test@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message)

    def source_provenance(self) -> dict:
        return {"commit": self.git("rev-parse", "HEAD"), "tree": self.git("rev-parse", "HEAD^{tree}"),
            "files": [reference(path, (self.root / path).read_bytes()) for path in sorted(VERIFY.EXTERNAL_SOURCE_PATHS)]}

    def commit_changed_source_manifest(self, value: dict) -> None:
        data = VERIFY.canonical_bytes(value)
        self.source_manifest.write_bytes(data)
        self.git("add", "evidence/evidence.json")
        self.commit("authored changed source evidence boundary")
        self.evidence["source"] = self.source_provenance()
        self.evidence["sourceEvidence"] = reference("evidence/evidence.json", data)
        self.write_manifest()

    def test_external_recovery_uses_committed_source_payloads_and_two_distinct_source_commits(self) -> None:
        self.assertNotEqual(self.source_evidence["source"]["commit"], self.evidence["source"]["commit"])
        self.assertEqual(11, len(self.evidence["source"]["files"]))
        for path in self.source_directory.iterdir():
            path.unlink()
        for item in self.evidence["source"]["files"] + list(self.evidence["inputs"].values()):
            (self.root / item["path"]).write_bytes(b"uncommitted replacement")
        raw, counts = self.verify()
        self.assertEqual(VERIFY.canonical_bytes(self.report), raw)
        self.assertEqual(self.evidence["counts"], counts)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, VERIFY.main([str(self.manifest), "--extract-report", str(self.root / "recovered-external.json")]))
        self.assertEqual(raw, (self.root / "recovered-external.json").read_bytes())
        self.assertIn("1 static import requests", output.getvalue())
        self.assertIn("no production qualification", output.getvalue())

    def test_external_source_reference_hash_commit_exact_inventory_and_recursion_are_required(self) -> None:
        original = copy.deepcopy(self.evidence)
        mutations = [lambda: self.evidence["sourceEvidence"].update(sha256="0" * 64),
            lambda: self.evidence["sourceEvidence"].update(path="../escape.json"),
            lambda: self.evidence["source"].update(commit="0" * 40),
            lambda: self.evidence["source"].update(tree="0" * 40),
            lambda: self.evidence["source"]["files"].pop(),
            lambda: self.evidence["source"]["files"][0].update(sha256="0" * 64)]
        for change in mutations:
            self.evidence = copy.deepcopy(original)
            change()
            self.write_manifest()
            with self.assertRaises(VERIFY.VerificationError):
                self.verify()
        self.evidence = original
        self.commit_changed_source_manifest(self.source_evidence | {"kind": VERIFY.EXTERNAL_KIND})
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_source_manifest_machine_semantics_are_verified_after_git_recovery(self) -> None:
        changed = copy.deepcopy(self.source_evidence)
        changed["releaseEligible"] = True
        self.commit_changed_source_manifest(changed)
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()
        changed = copy.deepcopy(self.source_evidence)
        changed["source"]["commit"] = "0" * 40
        self.commit_changed_source_manifest(changed)
        with self.assertRaisesRegex(VERIFY.VerificationError, "fetch that commit's history"):
            self.verify()

    def test_external_request_runtime_inputs_and_authority_cannot_be_rehashed_away(self) -> None:
        original_request, original_report = copy.deepcopy(self.request), copy.deepcopy(self.report)
        changes = [lambda: self.request["sourceReport"].update(sha256="0" * 64),
            lambda: self.request["sourceRequest"].update(bytes=self.request["sourceRequest"]["bytes"] + 1),
            lambda: self.request["richFile"].update(sha256="0" * 64), lambda: self.request["runtime"].update(bridgeSha256="0" * 64),
            lambda: self.request["runtime"]["bridgeSnapshot"].update(sha256="0" * 64),
            lambda: self.request["runtime"]["bundleManifestSnapshot"].update(bytes=0),
            lambda: self.report.update(complete=True), lambda: self.report.update(sourceCallPopulationComplete=True),
            lambda: self.report.update(sourceCallRecordsEnumerated=False), lambda: self.report.update(sourceReportSha256="0" * 64),
            lambda: self.report.update(runtime=original_report["runtime"] | {"bridgeSha256": "0" * 64}),
            lambda: self.request.update(metadataPolicy="unbounded"), lambda: self.request.update(recoveredFunctions=[])]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.request, self.report = copy.deepcopy(original_request), copy.deepcopy(original_report)
                change()
                self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()

    def test_source_call_instruction_requires_executable_owned_file_bytes(self) -> None:
        original = copy.deepcopy(self.report)
        section = next(row for row in self.report["dynamicInventory"]["sections"] if row["name"] == ".text")
        section["flags"] = "0x2"  # Keep source hashes/metadata internally consistent but drop execute ownership.
        self.write_payloads()
        with self.assertRaisesRegex(VERIFY.VerificationError, "source call instruction lacks uniquely owned executable"):
            self.verify()
        self.report = original

    def test_external_sites_namespace_nested_authority_and_population_are_bound(self) -> None:
        original = copy.deepcopy(self.report)
        changes = [lambda: self.report["sites"].clear(), lambda: self.report["sites"].append(copy.deepcopy(self.report["sites"][0])),
            lambda: self.report["sites"][0].update(instructionBytes="e800000000"), lambda: self.report["sites"][0].update(returnAddress="0x1016"),
            lambda: self.report["sites"][0].update(externalTargetId="ext-" + "0" * 64), lambda: self.report["sites"][0].update(negativeCompleteness=True),
            lambda: self.report["sites"][0]["relocationBinding"].update(runtimeImplementationAvailable=True),
            lambda: self.report["sites"][0]["relocationBinding"]["writeCoverage"].update(negativeCompleteness=True),
            lambda: self.report["sites"][0]["memoryTransfer"].update(rawReadOpcode="CALLIND"),
            lambda: self.report["sites"][0]["memoryTransfer"].update(runtimeImplementation="invented"),
            lambda: self.report["dynamicInventory"].update(releaseEligible=True),
            lambda: self.report["externalNamespace"]["entries"][0]["identity"].update(runtimeProviderAvailable=True),
            lambda: self.report["sourceCanonicalPopulation"].clear(), lambda: self.report["counts"].update(sourcePhysicalSites=2)]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.report = copy.deepcopy(original)
                change()
                self.report["externalNamespaceSha256"] = sha256(VERIFY.canonical_bytes(self.report["externalNamespace"])).hexdigest()
                self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()

    def test_external_gzip_and_git_recovered_source_gzip_both_refuse_trailing_members(self) -> None:
        data = (self.directory / "report.json.gz").read_bytes() + gzip.compress(b"", mtime=0)
        (self.directory / "report.json.gz").write_bytes(data)
        self.evidence["payloads"]["report"].update(storedBytes=len(data), storedSha256=sha256(data).hexdigest())
        self.write_manifest()
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()
        self.write_payloads()
        data = (self.source_directory / "report.json.gz").read_bytes() + b"trailing"
        (self.source_directory / "report.json.gz").write_bytes(data)
        changed = copy.deepcopy(self.source_evidence)
        changed["payloads"]["report"].update(storedBytes=len(data), storedSha256=sha256(data).hexdigest())
        self.git("add", "evidence/report.json.gz")
        self.commit_changed_source_manifest(changed)
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_unresolved_transfer_opcode_and_index_remain_closed_typed_and_paired(self) -> None:
        site = self.report["sites"][0]
        site.update(relocationBinding=None, externalTargetId=None, compositionDisposition="unresolved-memory-transfer",
                    targetBindingDisposition="unresolved-memory-transfer")
        site["memoryTransfer"].update(pointerSlotAddress=None, pointerWidthBytes=None, relationship="unresolved",
            rawReadOpcode=None, rawReadOpIndex=None, unresolvedReason="register-transfer")
        for counts in (self.report["counts"], self.evidence["counts"]):
            counts["dispositions"] = {"unresolved-memory-transfer": 1}
        self.write_payloads()
        self.verify()
        original = copy.deepcopy(site["memoryTransfer"])
        for change in ({"rawTransferOpcode": value} for value in (None, {}, [], 0, True, "CALLIND", "UNKNOWN")):
            with self.subTest(change=change):
                site["memoryTransfer"] = original | change
                self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
        for value in (None, {}, [], True, "0", -1, 4096):
            with self.subTest(index=value):
                site["memoryTransfer"] = original | {"rawTransferOpIndex": value}
                self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
        site["memoryTransfer"] = original | {"rawTransferOpcode": None, "rawTransferOpIndex": None}
        self.write_payloads()
        self.verify()

    def test_write_coverage_optional_witnesses_are_typed_and_match_flags(self) -> None:
        original = copy.deepcopy(self.report)
        for flag, locator in (("overlappingWrite", "overlapLocator"), ("unknownWriteWidth", "unknownWidthLocator"),
                              ("writeAddressOverflow", "overflowLocator")):
            for value in ({}, [], True, 7, "", "rela:2:0"):
                with self.subTest(flag=flag, witness=value):
                    self.report = copy.deepcopy(original)
                    self.report["sites"][0]["relocationBinding"]["writeCoverage"][locator] = value
                    self.write_payloads()
                    with self.assertRaises(VERIFY.VerificationError):
                        self.verify()
            # Rehash a negative assessment with a true uncertainty flag but no locator witness.
            self.report = copy.deepcopy(original)
            site = self.report["sites"][0]
            site.update(compositionDisposition="unresolved-relocation-write-coverage", targetBindingDisposition="unresolved-relocation-write-coverage")
            site["relocationBinding"]["writeCoverage"].update({flag: True, "safeForStaticSlotAssociation": False})
            for counts in (self.report["counts"], self.evidence["counts"]):
                counts["dispositions"] = {"unresolved-relocation-write-coverage": 1}
            self.write_payloads()
            with self.assertRaises(VERIFY.VerificationError):
                self.verify()
            # The scalar envelope accepts a bounded named witness with its matching flag.
            site["relocationBinding"]["writeCoverage"][locator] = "rela:2:0"
            self.write_payloads()
            self.verify()
            self.evidence["counts"]["dispositions"] = {"static-import-request-reference": 1}

    def test_binding_numeric_commitments_reject_python_boolean_integer_equivalence(self) -> None:
        original = copy.deepcopy(self.report["sites"][0]["relocationBinding"])
        for key, value in (("symbolTableSectionIndex", True), ("symbolIndex", True), ("relocationAddend", False),
                           ("slotFileOffset", False), ("slotLoadIndices", [False])):
            with self.subTest(field=key):
                self.report["sites"][0]["relocationBinding"] = original | {key: value}
                self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()

    def test_external_direct_call_cannot_be_rehashed_as_same_site_indirect_transfer(self) -> None:
        site = self.report["sites"][0]
        site["viaForwarder"] = False
        site["memoryProbe"].update(address="0x1010", availableBytes="ff15ea1f0000")
        site["memoryTransfer"].update(address="0x1010", bytes="ff15ea1f0000", classification="indirect-call",
            rawReadOpcode="CALLIND", rawTransferOpcode="CALLIND")
        self.write_payloads()
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_external_forwarding_mode_is_bound_even_without_a_probe(self) -> None:
        site = self.report["sites"][0]
        disposition = "unresolved-forwarder-byte-ownership"
        next(row for row in self.report["dynamicInventory"]["sections"] if row["name"] == ".plt")["flags"] = "0x2"
        site.update(memoryProbe=None, memoryTransfer=None, relocationBinding=None, externalTargetId=None,
            targetBindingDisposition=disposition, compositionDisposition=disposition)
        self.report["counts"]["dispositions"] = {disposition: 1}
        self.evidence["counts"] = copy.deepcopy(self.report["counts"])
        self.write_payloads()
        self.verify()  # The original noncanonical direct destination still requires forwarding mode.
        site["viaForwarder"] = False
        self.write_payloads()
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_source_instruction_bytes_conflict_with_overlapping_probe_windows(self) -> None:
        # Ordinal 1184's source call starts eight bytes inside ordinal 1183's probe window.
        source_instruction = bytes.fromhex("e867c80f00")
        probe_window = b"\x00" * 8 + b"\x90" + b"\x00" * 6
        ranges = [(0, 0x412244, source_instruction), (0, 0x41223C, probe_window)]
        with self.assertRaisesRegex(VERIFY.VerificationError, "source/probe byte windows conflict"):
            VERIFY.require_consistent_byte_ranges(ranges,
                "retained source/probe byte windows conflict at overlapping executable addresses")

    def test_source_and_probe_bytes_reconcile_aliased_executable_file_ranges(self) -> None:
        site = self.report["sites"][0]
        self.assertEqual("static-import-request-reference", site["compositionDisposition"])
        inventory = self.report["dynamicInventory"]
        text = next(row for row in inventory["sections"] if row["name"] == ".text")
        plt = next(row for row in inventory["sections"] if row["name"] == ".plt")
        load = next(row for row in inventory["programHeaders"] if row["type"] == 1 and row["virtualAddress"] == plt["address"])
        self.assertEqual(160, text["offset"])
        self.assertNotEqual(text["offset"], plt["offset"])
        # Distinct virtual addresses now claim the same retained file bytes.
        plt["offset"] = text["offset"]
        load["offset"] = hex(text["offset"])
        self.write_payloads()
        with self.assertRaisesRegex(VERIFY.VerificationError, "file ranges"):
            self.verify()

    def test_executable_source_bytes_cannot_alias_retained_dynamic_metadata(self) -> None:
        inventory = self.report["dynamicInventory"]
        text = next(row for row in inventory["sections"] if row["name"] == ".text")
        dynsym = next(row for row in inventory["sections"] if row["type"] == 11)
        load = next(row for row in inventory["programHeaders"] if row["type"] == 1 and row["virtualAddress"] == text["address"])
        text["offset"] = dynsym["offset"]
        load["offset"] = hex(dynsym["offset"])
        self.write_payloads()
        with self.assertRaisesRegex(VERIFY.VerificationError, "alias dynamic metadata"):
            self.verify()

    def test_executable_probe_bytes_cannot_alias_retained_dynamic_metadata(self) -> None:
        inventory = self.report["dynamicInventory"]
        plt = next(row for row in inventory["sections"] if row["name"] == ".plt")
        dynsym = next(row for row in inventory["sections"] if row["type"] == 11)
        load = next(row for row in inventory["programHeaders"] if row["type"] == 1 and row["virtualAddress"] == plt["address"])
        plt["offset"] = dynsym["offset"]
        load["offset"] = hex(dynsym["offset"])
        self.write_payloads()
        with self.assertRaisesRegex(VERIFY.VerificationError, "alias dynamic metadata"):
            self.verify()

    def test_nonforwarded_receipt_requires_the_exact_physical_instruction(self) -> None:
        symbols, relocations, imports = VERIFY.verify_external_inventory(self.report["dynamicInventory"],
            self.report["externalNamespace"], self.report["externalNamespaceSha256"], self.report["inputSha256"], self.report["imageBase"])
        index = VERIFY.RetainedRelocationIndex(self.report["dynamicInventory"], symbols, self.report["inputBytes"])
        site = copy.deepcopy(self.report["sites"][0])
        site.update(physicalClassification="indirect-call", physicalTargetAddress=None, viaForwarder=False,
            instructionBytes="ff15ea1f0000", instructionLength=6, returnAddress="0x1016")
        site["memoryProbe"].update(address="0x1010", availableBytes=site["instructionBytes"] + "00" * 9)
        site["memoryTransfer"].update(address="0x1010", bytes=site["instructionBytes"], classification="indirect-call",
            rawReadOpcode="CALLIND", rawTransferOpcode="CALLIND")
        VERIFY.verify_external_site(site, 0x1010, symbols, relocations, imports, index)
        mutations = [lambda row: row["memoryTransfer"].update(length=5, bytes="ff15ea1f00"),
            lambda row: (row["memoryTransfer"].update(bytes="ff15eb1f0000"), row["memoryProbe"].update(availableBytes="ff15eb1f0000")),
            lambda row: row["memoryTransfer"].update(classification="indirect-jump", rawReadOpcode="BRANCHIND", rawTransferOpcode="BRANCHIND"),
            lambda row: row.update(viaForwarder=True)]
        for ordinal, change in enumerate(mutations):
            with self.subTest(mutation=ordinal):
                changed = copy.deepcopy(site)
                change(changed)
                with self.assertRaises(VERIFY.VerificationError):
                    VERIFY.verify_external_site(changed, 0x1010, symbols, relocations, imports, index)

    def test_direct_self_target_preserves_same_instruction_unresolved_receipt(self) -> None:
        symbols, relocations, imports = VERIFY.verify_external_inventory(self.report["dynamicInventory"],
            self.report["externalNamespace"], self.report["externalNamespaceSha256"], self.report["inputSha256"], self.report["imageBase"])
        index = VERIFY.RetainedRelocationIndex(self.report["dynamicInventory"], symbols, self.report["inputBytes"])
        site = copy.deepcopy(self.report["sites"][0])
        site.update(physicalTargetAddress="0x1010", viaForwarder=False, instructionBytes="e8fbffffff", instructionLength=5,
            relocationBinding=None, externalTargetId=None, targetBindingDisposition="unresolved-forwarder-sequence",
            compositionDisposition="unresolved-forwarder-sequence")
        site["memoryProbe"].update(address="0x1010", availableBytes=site["instructionBytes"] + "00" * 10)
        site["memoryTransfer"].update(address="0x1010", bytes=site["instructionBytes"], length=5, classification="direct-call",
            pointerSlotAddress=None, pointerWidthBytes=None, relationship="unresolved", rawReadOpcode=None, rawReadOpIndex=None,
            rawTransferOpcode=None, rawTransferOpIndex=None, rawCopyOpIndices=[], unresolvedReason="unsupported-transfer-profile")
        VERIFY.verify_external_site(site, 0x1010, symbols, relocations, imports, index)

    def test_raw_dynamic_mechanisms_cannot_omit_uncertainty_after_rehash(self) -> None:
        original = copy.deepcopy(self.report)
        for tags, reason in (((35, 36, 37), "packed-relr-relocations-not-expanded"),
                ((0x6000000f, 0x60000010, 0x60000011, 0x60000012, 0x6fffe000, 0x6fffe001, 0x6fffe003),
                 "android-packed-relocations-not-expanded"), ((0x12345678,), "unclassified-dynamic-tag")):
            for tag in tags:
                with self.subTest(tag=hex(tag)):
                    self.report = copy.deepcopy(original)
                    inventory = self.report["dynamicInventory"]
                    inventory["dynamicEntries"].insert(-1, {"index": 7, "fileOffset": 112, "tag": hex(tag), "value": "0x1000"})
                    self.sync_dynamic_storage(inventory)
                    self.write_payloads()
                    with self.assertRaisesRegex(VERIFY.VerificationError, "unsupported reasons differ"):
                        self.verify()
                    inventory["unsupportedReasons"] = sorted(inventory["unsupportedReasons"] + [reason])
                    self.write_payloads()
                    with self.assertRaisesRegex(VERIFY.VerificationError, "static import disposition contradicts"):
                        self.verify()

    def test_raw_dynamic_ranges_and_section_membership_cannot_be_rehashed_away(self) -> None:
        original = copy.deepcopy(self.report)
        changes = [lambda inv: inv["dynamicEntries"][1].update(value="0x0"),
            lambda inv: inv["dynamicEntries"][0].update(value="0x5000"),
            lambda inv: inv["dynamicEntries"][1].update(value="0x17"),
            lambda inv: inv["dynamicEntries"][2].update(value="0x11"),
            lambda inv: inv["dynamicEntries"].pop(2),
            lambda inv: inv["dynamicEntries"].insert(0, copy.deepcopy(inv["dynamicEntries"][0])),
            lambda inv: inv["dynamicEntries"][4].update(value="0x18"),
            lambda inv: inv["dynamicEntries"][6].update(value="0x1234"),
            lambda inv: inv["dynamicEntries"][7].update(value="0x10"),
            lambda inv: inv["sections"][1].update(link=3),
            lambda inv: inv["sections"][1].update(address="0x4001"),
            lambda inv: inv["sections"][1].update(entrySize="0x10"),
            lambda inv: inv["relocations"][0].update(fileOffset=1),
            lambda inv: inv["relocations"][0].update(relocationIndex=1),
            lambda inv: inv["sections"][1].update(size="0x30")]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.report = copy.deepcopy(original)
                change(self.report["dynamicInventory"])
                self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
        # REL and RELA use the same reconstruction; both remain valid positive profiles.
        for kind, width, pointer, size, entry_size in ((4, 24, 7, 8, 9), (9, 16, 17, 18, 19)):
            with self.subTest(positive_kind=kind):
                self.report = copy.deepcopy(original)
                inventory = self.report["dynamicInventory"]
                inventory["sections"][1].update(type=kind, entrySize=hex(width), size=hex(width))
                inventory["relocations"][0]["dynamicTables"] = ["rela" if kind == 4 else "rel"]
                self.report["sites"][0]["relocationBinding"]["dynamicTables"] = inventory["relocations"][0]["dynamicTables"]
                inventory["dynamicEntries"] = [{"index": index, "fileOffset": index * 16, "tag": hex(tag), "value": hex(value)}
                    for index, (tag, value) in enumerate(((pointer, 0x4000), (size, width), (entry_size, width),
                                                       (6, 0x7000), (11, 24), (5, 0x7100), (10, 64), (1, 20), (0, 0)))]
                self.sync_dynamic_storage(inventory)
                self.write_payloads()
                self.verify()
                inventory["dynamicEntries"][1]["value"] = "0x0"
                self.write_payloads()
                with self.assertRaisesRegex(VERIFY.VerificationError, "membership differs"):
                    self.verify()

    def test_absent_and_refused_probes_require_matching_unresolved_dispositions(self) -> None:
        original = copy.deepcopy(self.report)
        for refusal in (None, "decoder-refused"):
            for disposition in ("retained-canonical-target", "unresolved-source-instruction-boundary", "unresolved-memory-transfer",
                                "unresolved-null-physical-target", "unresolved-forwarder-byte-ownership", "unresolved-memory-decoder-refusal"):
                with self.subTest(refusal=refusal, disposition=disposition):
                    self.report = copy.deepcopy(original)
                    site = self.report["sites"][0]
                    site.update(memoryTransfer=None, relocationBinding=None, externalTargetId=None,
                        targetBindingDisposition=disposition, compositionDisposition=disposition)
                    if refusal is None:
                        site["memoryProbe"] = None
                        next(row for row in self.report["dynamicInventory"]["sections"] if row["name"] == ".plt")["flags"] = "0x2"
                    else:
                        site["memoryProbe"]["refusal"] = refusal
                    self.report["counts"]["dispositions"] = {disposition: 1}
                    self.evidence["counts"] = copy.deepcopy(self.report["counts"])
                    self.write_payloads()
                    expected = "unresolved-forwarder-byte-ownership" if refusal is None else "unresolved-memory-decoder-refusal"
                    if disposition == expected:
                        self.verify()
                    else:
                        with self.assertRaises(VERIFY.VerificationError):
                            self.verify()

    def test_static_import_rejects_irelative_after_rehash(self) -> None:
        for kind in (6, 7):
            self.report["dynamicInventory"]["relocations"][0]["type"] = kind
            self.report["sites"][0]["relocationBinding"]["relocationType"] = kind
            self.write_payloads()
            self.verify()
        self.report["dynamicInventory"]["relocations"][0]["type"] = 37
        self.report["sites"][0]["relocationBinding"]["relocationType"] = 37
        self.write_payloads()
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_static_import_checks_active_binding_and_slot_metadata_after_rehash(self) -> None:
        original = copy.deepcopy(self.report)
        for field, binding_field, value in (("type", "relocationType", 8), ("type", "relocationType", 36),
                ("dynamicTables", "dynamicTables", []), ("dynamicTables", "dynamicTables", ["rela", "jmprel"]),
                ("dynamicTables", "dynamicTables", ["invented"]), ("slotLoadIndices", "slotLoadIndices", []),
                ("slotLoadIndices", "slotLoadIndices", [0, 1]), ("slotLoadIndices", "slotLoadIndices", [1]),
                ("slotFileOffset", "slotFileOffset", None), ("slotFileOffset", "slotFileOffset", 1)):
            with self.subTest(field=field, value=value):
                self.report = copy.deepcopy(original)
                self.report["dynamicInventory"]["relocations"][0][field] = value
                self.report["sites"][0]["relocationBinding"][binding_field] = value
                self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
        changes = [lambda inv: inv.update(activeSymbolTableSectionIndex=2),
            lambda inv: inv["unsupportedReasons"].append("packed-relr-relocations-not-expanded"),
            lambda inv: inv["unsupportedReasons"].append("android-packed-relocations-not-expanded"),
            lambda inv: inv["unsupportedReasons"].append("unclassified-dynamic-tag"),
            lambda inv: inv["dynamicSymbols"][1].update(info=17),
            lambda inv: inv["dynamicSymbols"][1].update(other=1),
            lambda inv: inv["dynamicSymbols"][1].update(rawSectionIndex=4),
            lambda inv: inv["dynamicSymbols"][1].update(resolvedSectionIndex=4),
            lambda inv: inv["programHeaders"][0].update(fileSize="0x7"),
            lambda inv: inv["programHeaders"].append(inv["programHeaders"][0] | {"index": 1})]
        for index, change in enumerate(changes):
            with self.subTest(metadata=index):
                self.report = copy.deepcopy(original)
                change(self.report["dynamicInventory"])
                self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()

    def test_static_import_recomputes_competing_writes_instead_of_trusting_safe_flags(self) -> None:
        original = copy.deepcopy(self.report)
        # The original candidate always falsely retains safe=true in the rejecting cases.
        cases = [(2, 0x2ffc, ["rela"], True), (2, 0x2ffd, ["rela"], False),
                 (8, 0x3008, ["rela"], True), (8, 0x3007, ["rela"], False),
                 (36, 0x2ff8, ["rela"], False), (7, 0x3000, ["rela"], False),
                 (1, (1 << 64) - 1, ["rela"], False), (777, 0x9000, ["rela"], False),
                 (5, 0x9000, ["rela"], False), (0, 0x9000, ["rela"], True), (777, 0x9000, [], True)]
        for kind, slot, tables, accepted in cases:
            with self.subTest(kind=kind, slot=hex(slot), tables=tables):
                self.report = copy.deepcopy(original)
                inventory = self.report["dynamicInventory"]
                inventory["sections"][3]["size"] = "0x18"
                inventory["dynamicEntries"][4]["value"] = "0x18" if tables else "0x0"
                inventory["relocations"].append(inventory["relocations"][0] | {"sectionIndex": 5, "relocationIndex": 0, "locator": "rela:5:0",
                    "fileOffset": 24, "offset": hex(slot), "type": kind, "dynamicTables": tables,
                    "slotFileOffset": None, "slotLoadIndices": []})
                self.write_payloads()
                if accepted:
                    self.verify()
                else:
                    with self.assertRaises(VERIFY.VerificationError):
                        self.verify()
        self.report = copy.deepcopy(original)
        inventory = self.report["dynamicInventory"]
        inventory["sections"][3]["size"] = "0x30"
        inventory["dynamicEntries"][4]["value"] = "0x30"
        inventory["sections"].append({"index": 4, "name": ".bss", "type": 8, "flags": "0x2", "address": "0x2fe0", "offset": 0,
            "size": "0x40", "link": 0, "info": 0, "alignment": "0x8", "entrySize": "0x0"})
        inventory["sections"][0]["size"] = "0x48"
        next(row for row in inventory["programHeaders"] if row["index"] == 24).update(fileSize="0x48", memorySize="0x48")
        inventory["dynamicSymbols"].append(inventory["dynamicSymbols"][1] | {"symbolIndex": 2, "locator": "dynsym:1:2",
            "name": "copy_storage", "info": 17, "type": 1, "rawSectionIndex": 4, "resolvedSectionIndex": 4,
            "sectionKind": "defined", "value": "0x2fe0", "size": "0x40"})
        for index, kind, slot, symbol in ((1, 5, 0x2fe0, 2), (2, 2, 0x2ff0, 1)):
            inventory["relocations"].append(inventory["relocations"][0] | {"sectionIndex": 5, "relocationIndex": index - 1, "locator": f"rela:5:{index - 1}",
                "fileOffset": index * 24, "offset": hex(slot), "type": kind, "symbolIndex": symbol, "dynamicTables": ["rela"],
                "slotFileOffset": None, "slotLoadIndices": []})
        self.write_payloads()
        # Earlier COPY encloses the slot although the immediately preceding short write does not.
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_relative_count_tags_require_bounded_relative_symbol_zero_prefixes(self) -> None:
        original = copy.deepcopy(self.report)
        # Keep the JMPREL import positive while adding a separate REL/RELA prefix.
        for kind, width, pointer, size, entry_size, count_tag, name in (
                (4, 24, 7, 8, 9, 0x6ffffff9, "rela"), (9, 16, 17, 18, 19, 0x6ffffffa, "rel")):
            for count, relocation_type, symbol_index, accepted in (
                    (0, 6, 1, True), (1, 8, 0, True), (2, 8, 0, True),
                    (3, 8, 0, False), (1, 6, 0, False), (1, 8, 1, False), (1, 6, 1, False)):
                with self.subTest(table=name, count=count, kind=relocation_type, symbol=symbol_index):
                    self.report = copy.deepcopy(original)
                    inventory = self.report["dynamicInventory"]
                    inventory["sections"][3].update(type=kind, entrySize=hex(width), size=hex(width * 2))
                    inventory["dynamicEntries"][3:6] = [
                        {"index": index + 3, "fileOffset": (index + 3) * 16, "tag": hex(tag), "value": hex(value)}
                        for index, (tag, value) in enumerate(((pointer, 0x5000), (size, width * 2),
                                                            (entry_size, width), (count_tag, count)))]
                    self.sync_dynamic_storage(inventory)
                    # Reverse input order: prefix ordering must derive from section address/index.
                    for index in (1, 0):
                        # A count-one valid prefix may be followed by a non-relative row.
                        nonrelative_suffix = accepted and count == 1 and index == 1
                        inventory["relocations"].append(inventory["relocations"][0] | {
                            "sectionIndex": 5, "relocationIndex": index, "locator": f"{name}:5:{index}",
                            "fileOffset": 24 + index * width, "offset": hex(0x9000 + index * 8),
                            "type": 6 if nonrelative_suffix else relocation_type,
                            "symbolIndex": 1 if nonrelative_suffix else symbol_index, "dynamicTables": [name],
                            "slotFileOffset": None, "slotLoadIndices": []})
                    self.write_payloads()
                    if accepted:
                        self.verify()
                    else:
                        with self.assertRaisesRegex(VERIFY.VerificationError, "relative relocation prefix"):
                            self.verify()
        for tag in (0x6ffffff9, 0x6ffffffa):
            for count in (0, 1):
                with self.subTest(empty_or_absent_table=hex(tag), count=count):
                    self.report = copy.deepcopy(original)
                    self.report["dynamicInventory"]["dynamicEntries"].insert(-1,
                        {"index": 8, "fileOffset": 128, "tag": hex(tag), "value": hex(count)})
                    self.sync_dynamic_storage(self.report["dynamicInventory"])
                    self.write_payloads()
                    if count == 0:
                        self.verify()
                    else:
                        with self.assertRaisesRegex(VERIFY.VerificationError, "relative relocation prefix"):
                            self.verify()

    def test_dynamic_metadata_rejects_overlapping_symbol_and_string_ranges_after_rehash(self) -> None:
        inventory = self.report["dynamicInventory"]
        symbols = next(row for row in inventory["sections"] if row["name"] == ".dynsym")
        strings = next(row for row in inventory["sections"] if row["name"] == ".dynstr")
        old_string_address = int(strings["address"], 16)
        strings.update(address=symbols["address"], offset=symbols["offset"])
        next(row for row in inventory["dynamicEntries"] if row["tag"] == "0x5")["value"] = symbols["address"]
        inventory["programHeaders"] = [row for row in inventory["programHeaders"]
            if not (row["type"] == 1 and int(row["virtualAddress"], 16) == old_string_address)]
        symbol_load = next(row for row in inventory["programHeaders"]
            if row["type"] == 1 and row["virtualAddress"] == symbols["address"])
        symbol_load.update(fileSize=strings["size"], memorySize=strings["size"])
        self.write_payloads()  # Rehash every payload while keeping the contradictory positive import claim.
        with self.assertRaisesRegex(VERIFY.VerificationError, "dynamic metadata sections overlap"):
            self.verify()

    def test_dynamic_metadata_requires_allocated_uncompressed_uniquely_mapped_storage(self) -> None:
        inventory = self.report["dynamicInventory"]
        # The baseline includes complete nonempty symbol/string/dynamic storage.
        self.write_payloads()
        self.verify()
        original = copy.deepcopy(self.report)
        for name in (".dynsym", ".dynstr", ".dynamic", ".rela.plt"):
            for mutation in ("unallocated", "compressed", "file-bounds", "address-overflow", "offset", "absent-load",
                             "partial-load", "zero-fill", "duplicate-load", "nested-load"):
                with self.subTest(section=name, mutation=mutation):
                    self.report = copy.deepcopy(original)
                    inventory = self.report["dynamicInventory"]
                    section = next(row for row in inventory["sections"] if row["name"] == name)
                    start = int(section["address"], 16)
                    load = next(row for row in inventory["programHeaders"] if int(row["virtualAddress"], 16) == start)
                    if mutation == "unallocated":
                        section["flags"] = "0x0"
                    elif mutation == "compressed":
                        section["flags"] = "0x802"
                    elif mutation == "file-bounds":
                        section["offset"] = self.report["inputBytes"]
                    elif mutation == "address-overflow":
                        section["address"] = "0xfffffffffffffff0"
                        if name == ".dynsym":
                            next(row for row in inventory["dynamicEntries"] if row["tag"] == "0x6")["value"] = section["address"]
                    elif mutation == "offset":
                        section["offset"] += 1
                        # Preserve the derived relocation file offsets: reject mapping, not row mismatch.
                        for row in inventory["relocations"]:
                            if row["sectionIndex"] == section["index"]:
                                row["fileOffset"] += 1
                    elif mutation == "absent-load":
                        inventory["programHeaders"].remove(load)
                    elif mutation == "partial-load":
                        load["virtualAddress"] = hex(start + 1)
                    elif mutation == "zero-fill":
                        load["fileSize"] = hex(int(section["size"], 16) - 1)
                    else:
                        other = load | {"index": 27}
                        if mutation == "nested-load":
                            other.update(virtualAddress=hex(start + 1), fileSize="0x1", memorySize="0x1")
                        inventory["programHeaders"].append(other)
                    self.write_payloads()
                    with self.assertRaises(VERIFY.VerificationError):
                        self.verify()
        # An empty DYNSYM is invalid as a population, regardless of storage flags.
        for flags in ("0x0", "0x802"):
            self.report = copy.deepcopy(original)
            section = next(row for row in self.report["dynamicInventory"]["sections"] if row["name"] == ".dynsym")
            section.update(size="0x0", flags=flags)
            self.write_payloads()
            with self.assertRaises(VERIFY.VerificationError):
                self.verify()

    def test_symbol_and_dynamic_populations_require_section_backed_provenance(self) -> None:
        original = copy.deepcopy(self.report)
        changes = {
            "strtab-pointer": lambda inv: next(row for row in inv["dynamicEntries"] if row["tag"] == "0x5").update(value="0x1"),
            "strtab-size": lambda inv: next(row for row in inv["dynamicEntries"] if row["tag"] == "0xa").update(value="0x0"),
            "strtab-absent": lambda inv: next(row for row in inv["dynamicEntries"] if row["tag"] == "0x5").update(tag="0x15"),
            "dynamic-link": lambda inv: next(row for row in inv["sections"] if row["type"] == 6).update(link=1),
            "dynsym-size": lambda inv: inv["sections"][0].update(size="0x18"),
            "dynsym-width": lambda inv: inv["sections"][0].update(entrySize="0x10"),
            "dynsym-no-null": lambda inv: inv["dynamicSymbols"].pop(0),
            "dynsym-null-value": lambda inv: inv["dynamicSymbols"][0].update(value="0x1"),
            "dynsym-gap": lambda inv: inv["dynamicSymbols"][1].update(symbolIndex=2),
            "dynsym-local-boundary": lambda inv: inv["sections"][0].update(info=2),
            "dynsym-owner": lambda inv: inv["dynamicSymbols"][1].update(tableSectionIndex=3),
            "name-outside": lambda inv: inv["dynamicSymbols"][1].update(nameOffset=0xffffffff),
            "name-at-end": lambda inv: inv["dynamicSymbols"][1].update(nameOffset=64),
            "name-truncated": lambda inv: inv["dynamicSymbols"][1].update(nameOffset=63),
            "name-zero": lambda inv: inv["dynamicSymbols"][1].update(nameOffset=0),
            "pt-empty": lambda inv: next(row for row in inv["programHeaders"] if row["type"] == 2).update(fileSize="0x0"),
            "pt-duplicate": lambda inv: inv["programHeaders"].append(next(row for row in inv["programHeaders"] if row["type"] == 2) | {"index": 30}),
            "pt-absent": lambda inv: inv["programHeaders"].remove(next(row for row in inv["programHeaders"] if row["type"] == 2)),
            "pt-offset": lambda inv: next(row for row in inv["programHeaders"] if row["type"] == 2).update(offset="0x0"),
            "pt-address": lambda inv: next(row for row in inv["programHeaders"] if row["type"] == 2).update(virtualAddress="0x1"),
            "pt-memory": lambda inv: next(row for row in inv["programHeaders"] if row["type"] == 2).update(memorySize="0x1"),
            "sht-empty": lambda inv: next(row for row in inv["sections"] if row["type"] == 6).update(size="0x0"),
            "sht-width": lambda inv: next(row for row in inv["sections"] if row["type"] == 6).update(entrySize="0x8"),
            "sht-duplicate": lambda inv: inv["sections"].append(next(row for row in inv["sections"] if row["type"] == 6) | {"index": 30}),
            "entry-outside": lambda inv: inv["dynamicEntries"][0].update(fileOffset=self.report["inputBytes"] + 100),
            "entry-gap": lambda inv: inv["dynamicEntries"][0].update(index=1),
            "entry-missing": lambda inv: inv["dynamicEntries"].pop(0),
        }
        for name, change in changes.items():
            with self.subTest(mutation=name):
                self.report = copy.deepcopy(original)
                change(self.report["dynamicInventory"])
                self.write_payloads()  # Deliberately retain malformed storage while refreshing all payload hashes.
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()

    def test_inactive_dynsym_also_requires_complete_section_population(self) -> None:
        inventory = self.report["dynamicInventory"]
        inventory["sections"].append(inventory["sections"][0] | {"index": 4, "name": ".dynsym.inactive",
            "address": "0x7300", "offset": 1024, "size": "0x18"})
        inventory["programHeaders"].append({"index": 30, "type": 1, "flags": 4, "offset": "0x400",
            "virtualAddress": "0x7300", "physicalAddress": "0x7300", "fileSize": "0x18", "memorySize": "0x18", "alignment": "0x1"})
        inventory["dynamicSymbols"].append(inventory["dynamicSymbols"][0] | {"tableSectionIndex": 4, "locator": "dynsym:4:0"})
        inventory["unsupportedReasons"] = sorted(inventory["unsupportedReasons"] + ["inactive-dynsym-table-retained"])
        self.write_payloads()
        self.verify()  # An independently complete inactive null-only table is valid diagnostic evidence.
        original = copy.deepcopy(self.report)
        for change in (lambda inv: inv["sections"][-1].update(size="0x30"),
                       lambda inv: inv["dynamicSymbols"].pop(),
                       lambda inv: inv["sections"][-1].update(link=2),
                       lambda inv: inv["dynamicSymbols"][-1].update(nameOffset=64)):
            self.report = copy.deepcopy(original)
            change(self.report["dynamicInventory"])
            self.write_payloads()
            with self.assertRaises(VERIFY.VerificationError):
                self.verify()

    def test_static_import_requires_consistent_retained_version_identity(self) -> None:
        inventory = self.report["dynamicInventory"]
        inventory["sections"].extend({"index": index, "name": name, "type": kind, "flags": "0x2", "address": "0x0", "offset": 0,
            "size": "0x0", "link": link, "info": 0, "alignment": "0x1", "entrySize": "0x0"}
            for index, name, kind, link in ((6, ".gnu.version", 0x6fffffff, 1), (7, ".gnu.version_r", 0x6ffffffe, 3)))
        inventory["sections"][7].update(address="0x6300", offset=128, entrySize="0x2", size="0x4")
        inventory["programHeaders"].append({"index": 22, "type": 1, "flags": 4, "offset": "0x80",
            "virtualAddress": "0x6300", "physicalAddress": "0x6300", "fileSize": "0x4", "memorySize": "0x4", "alignment": "0x1"})
        inventory["sections"][8].update(address="0x6000", offset=64, size="0x20", info=1)
        inventory["programHeaders"].append({"index": 1, "type": 1, "flags": 4, "offset": "0x40",
            "virtualAddress": "0x6000", "physicalAddress": "0x6000", "fileSize": "0x20", "memorySize": "0x20", "alignment": "0x1"})
        inventory["dynamicEntries"][-1:-1] = [{"index": index + 8, "fileOffset": (index + 8) * 16, "tag": hex(tag), "value": hex(value)}
            for index, (tag, value) in enumerate(((0x6ffffffe, 0x6000), (0x6fffffff, 1), (0x6ffffff0, 0x6300)))]
        self.sync_dynamic_storage(inventory)
        inventory["dynamicSymbols"][0]["version"] = {"sectionIndex": 6, "fileOffset": 128, "raw": 0, "index": 0, "hidden": False,
            "kind": "local", "name": None, "providerRequest": None}
        inventory["dynamicSymbols"][1]["version"] = {"sectionIndex": 6, "fileOffset": 130, "raw": 2, "index": 2, "hidden": False,
            "kind": "required-version", "name": "VER_1", "providerRequest": "libexample.so"}
        inventory["versionRequirements"] = [{"sectionIndex": 7, "stringSectionIndex": 3, "recordOffset": 64, "auxiliaryOffset": 80,
            "providerRequest": "libexample.so", "providerRequestOffset": 20, "name": "VER_1", "nameOffset": 35,
            "rawIndex": 2, "index": 2, "flags": 0, "hash": 0x5aa821}]

        def rehash_identity() -> None:
            version = self.report["dynamicInventory"]["dynamicSymbols"][1]["version"]
            entry = self.report["externalNamespace"]["entries"][0]
            entry["identity"]["version"] = None if version is None else {
                key: value for key, value in version.items() if key not in {"sectionIndex", "fileOffset"}}
            entry["id"] = "ext-" + sha256(VERIFY.canonical_bytes(entry["identity"])).hexdigest()
            self.report["sites"][0]["externalTargetId"] = entry["id"]
            self.report["externalNamespaceSha256"] = sha256(VERIFY.canonical_bytes(self.report["externalNamespace"])).hexdigest()
            self.write_payloads()

        rehash_identity()
        self.verify()
        original = copy.deepcopy(self.report)

        self.report = copy.deepcopy(original)
        inventory = self.report["dynamicInventory"]
        requirement = inventory["versionRequirements"][0]
        owner = next(row for row in inventory["sections"] if row["index"] == requirement["sectionIndex"])
        owner.update(size="0x30")
        load = next(row for row in inventory["programHeaders"]
                    if row["type"] == 1 and row["virtualAddress"] == owner["address"])
        load.update(fileSize="0x30", memorySize="0x30")
        second = requirement | {"auxiliaryOffset": 96, "rawIndex": 3, "index": 3}
        inventory["versionRequirements"].append(second)
        self.write_payloads()
        self.verify()
        # A Verneed header has one vn_file offset shared by all its Vernaux entries.
        second["providerRequestOffset"] = 49
        self.write_payloads()
        with self.assertRaisesRegex(VERIFY.VerificationError, "provider request differs within header"):
            self.verify()

        # A Vernaux record cannot cross the next distinct Verneed header.
        self.report = copy.deepcopy(original)
        inventory = self.report["dynamicInventory"]
        requirement = inventory["versionRequirements"][0]
        owner = next(row for row in inventory["sections"] if row["index"] == requirement["sectionIndex"])
        owner.update(size="0x40", info=2)
        load = next(row for row in inventory["programHeaders"]
                    if row["type"] == 1 and row["virtualAddress"] == owner["address"])
        load.update(fileSize="0x40", memorySize="0x40")
        second = requirement | {"recordOffset": 96, "auxiliaryOffset": 112, "rawIndex": 3, "index": 3}
        inventory["versionRequirements"].append(second)
        next(row for row in inventory["dynamicEntries"] if row["tag"] == "0x6fffffff").update(value="0x2")
        self.sync_dynamic_storage(inventory)
        self.write_payloads()
        self.verify()
        requirement["auxiliaryOffset"] = 112
        self.write_payloads()
        with self.assertRaisesRegex(VERIFY.VerificationError, "auxiliary bounds/order"):
            self.verify()

        self.report = copy.deepcopy(original)
        inventory = self.report["dynamicInventory"]
        version_name, provider = "N" * 1846, "P" * 1846
        version = inventory["versionRequirements"][0]
        version.update(name=version_name, nameOffset=1, providerRequest=provider, providerRequestOffset=2)
        value = 0
        for byte in version_name.encode("utf-8"):
            value = ((value << 4) + byte) & 0xffffffff
            high = value & 0xf0000000
            if high:
                value ^= high >> 24
            value &= ~high
        version["hash"] = value
        inventory["dynamicSymbols"][1]["nameOffset"] = 1863
        inventory["dynamicSymbols"][1]["version"].update(name=version_name, providerRequest=provider)
        string_table = next(row for row in inventory["sections"] if row["index"] == 3)
        string_table.update(address="0x9000", offset=1024, size=hex(1881))
        string_load = next(row for row in inventory["programHeaders"] if row["index"] == 25)
        string_load.update(offset="0x400", virtualAddress="0x9000", physicalAddress="0x9000",
            fileSize=hex(1881), memorySize=hex(1881))
        next(row for row in inventory["dynamicEntries"] if int(row["tag"], 16) == 5).update(value="0x9000")
        next(row for row in inventory["dynamicEntries"] if int(row["tag"], 16) == 10).update(value=hex(1881))
        next(row for row in inventory["dynamicEntries"] if int(row["tag"], 16) == 1).update(value=hex(1849))
        rehash_identity()
        with self.assertRaisesRegex(VERIFY.VerificationError, "retained GNU version strings conflict in linked table"):
            self.verify()

        changes = [lambda inv: inv["sections"][7].update(size="0x2"),
            lambda inv: inv["sections"][7].update(size="0x6"),
            lambda inv: inv["sections"][7].update(entrySize="0x4"),
            lambda inv: inv["dynamicSymbols"][0]["version"].update(raw=1, index=1, kind="global-unversioned"),
            lambda inv: inv["dynamicSymbols"][1].update(version=None),
            lambda inv: inv["sections"].append(copy.deepcopy(inv["sections"][7]) | {"index": 8}),
            lambda inv: inv["dynamicEntries"][-2].update(value="0x1234"),
            lambda inv: inv["dynamicEntries"].pop(-2),
            lambda inv: inv["dynamicSymbols"][1]["version"].update(fileOffset=0),
            lambda inv: inv["dynamicSymbols"][1]["version"].update(name=None),
            lambda inv: inv["dynamicSymbols"][1]["version"].update(providerRequest=None),
            lambda inv: inv["dynamicSymbols"][1]["version"].update(kind="defined-version"),
            lambda inv: inv["dynamicSymbols"][1]["version"].update(raw=3),
            lambda inv: inv["dynamicSymbols"][1]["version"].update(hidden=True),
            lambda inv: inv["versionRequirements"].clear(),
            lambda inv: inv["versionRequirements"].append(copy.deepcopy(inv["versionRequirements"][0])),
            lambda inv: inv["versionRequirements"][0].update(providerRequest="other.so"),
            lambda inv: inv["versionRequirements"][0].update(rawIndex=3),
            lambda inv: inv["sections"][0].update(link=9), lambda inv: inv["sections"][7].update(link=9),
            lambda inv: inv["sections"][7].update(flags="0x0"), lambda inv: inv["sections"][7].update(flags="0x802"),
            lambda inv: (inv["sections"][7].update(offset=1), inv["dynamicSymbols"][1]["version"].update(fileOffset=3)),
            lambda inv: inv["programHeaders"].remove(next(row for row in inv["programHeaders"] if row["index"] == 22)),
            lambda inv: next(row for row in inv["programHeaders"] if row["index"] == 22).update(fileSize="0x3"),
            lambda inv: inv["programHeaders"].append(next(row for row in inv["programHeaders"] if row["index"] == 22) | {"index": 23}),
            lambda inv: inv["sections"][8].update(type=1), lambda inv: inv["sections"][8].update(link=1),
            lambda inv: inv["sections"][8].update(info=2), lambda inv: inv["sections"][8].update(flags="0x802"),
            lambda inv: inv["sections"][8].update(offset=4090), lambda inv: inv["sections"][8].update(address="0x6001"),
            lambda inv: inv["versionRequirements"][0].update(recordOffset=4096),
            lambda inv: inv["versionRequirements"][0].update(auxiliaryOffset=79),
            lambda inv: inv["versionRequirements"][0].update(auxiliaryOffset=81),
            lambda inv: inv["versionRequirements"][0].update(hash=0),
            lambda inv: inv["versionRequirements"][0].update(index=1, rawIndex=1),
            lambda inv: inv["dynamicEntries"][-3].update(value="0x0"),
            lambda inv: inv["dynamicEntries"].pop(-4)]
        for index, change in enumerate(changes):
            with self.subTest(version=index):
                self.report = copy.deepcopy(original)
                change(self.report["dynamicInventory"])
                rehash_identity()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
        # Local/global version indices still require the correct VERSYM owner/offset.
        for index, kind in ((0, "local"), (1, "global-unversioned")):
            self.report = copy.deepcopy(original)
            version = self.report["dynamicInventory"]["dynamicSymbols"][1]["version"]
            version.update(raw=index, index=index, kind=kind, name=None, providerRequest=None)
            rehash_identity()
            self.verify()
            for field, value in (("sectionIndex", 7), ("fileOffset", 0)):
                previous = version[field]
                version[field] = value
                rehash_identity()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
                version[field] = previous

    def test_probe_requires_unique_executable_file_backed_window_and_exact_length(self) -> None:
        original = copy.deepcopy(self.report)
        for length in (6, 7, 14, 15):
            with self.subTest(valid_window=length):
                self.report = copy.deepcopy(original)
                inventory = self.report["dynamicInventory"]
                next(row for row in inventory["sections"] if row["name"] == ".plt")["size"] = hex(length)
                self.report["sites"][0]["memoryProbe"]["availableBytes"] = original["sites"][0]["memoryProbe"]["availableBytes"][:length * 2]
                self.write_payloads()
                self.verify()  # Section end may legitimately shorten the 15-byte window.
                self.report = copy.deepcopy(original)
                next(row for row in self.report["dynamicInventory"]["programHeaders"] if row["index"] == 10)["fileSize"] = hex(length)
                self.report["sites"][0]["memoryProbe"]["availableBytes"] = original["sites"][0]["memoryProbe"]["availableBytes"][:length * 2]
                self.write_payloads()
                self.verify()  # A file-backed LOAD end independently bounds the window.
        mutations = [("section", {"flags": "0x2"}), ("section", {"flags": "0x4"}), ("section", {"type": 8}),
            ("section", {"offset": 33}), ("section", {"offset": 4090}), ("section", {"size": "0x8"}),
            ("section", {"address": "0xfffffffffffffff8", "size": "0xf"}),
            ("load", {"flags": 4}), ("load", {"fileSize": "0x0"}), ("load", {"fileSize": "0x8"}),
            ("load", {"offset": "0x21"}), ("load", {"memorySize": "0xffffffffffffffff"}),
            ("probe", {"availableBytes": "ff25fa0f0000"}),
            ("probe", {"refusal": "decoder-refused", "availableBytes": "ff25fa0f0000"})]
        for group, change in mutations:
            with self.subTest(group=group, change=change):
                self.report = copy.deepcopy(original)
                inventory = self.report["dynamicInventory"]
                target = (next(row for row in inventory["sections"] if row["name"] == ".plt") if group == "section" else
                    next(row for row in inventory["programHeaders"] if row["index"] == 10) if group == "load" else
                    self.report["sites"][0]["memoryProbe"])
                target.update(change)
                self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()
        # Other allocated sections and LOADs can overlap at the first byte or later in the window,
        # even if the other owner is nonexecutable or not file-backed.
        for group in ("sections", "programHeaders"):
            for delta in (0, 1, 14):
                with self.subTest(overlap=group, delta=delta):
                    self.report = copy.deepcopy(original)
                    inventory = self.report["dynamicInventory"]
                    if group == "sections":
                        other = next(row for row in inventory[group] if row["name"] == ".plt") | {
                            "index": 11, "type": 8, "flags": "0x2", "address": hex(0x2000 + delta), "size": "0x1"}
                    else:
                        other = next(row for row in inventory[group] if row["index"] == 10) | {
                            "index": 11, "flags": 4, "virtualAddress": hex(0x2000 + delta), "fileSize": "0x0", "memorySize": "0x1"}
                    inventory[group].append(other)
                    self.write_payloads()
                    with self.assertRaisesRegex(VERIFY.VerificationError, "byte-window ownership"):
                        self.verify()
        self.report = copy.deepcopy(original)
        symbols, _, _ = VERIFY.verify_external_inventory(self.report["dynamicInventory"], self.report["externalNamespace"],
            self.report["externalNamespaceSha256"], self.report["inputSha256"], self.report["imageBase"])
        index = VERIFY.RetainedRelocationIndex(self.report["dynamicInventory"], symbols, self.report["inputBytes"])
        for location, expected in ((0x1fff, None), (0x2000, 15), (0x200e, 1), (0x200f, None)):
            self.assertEqual(expected, index.code_window_length(location))
            self.assertEqual(expected, index.code_window_length(location))  # Cached positive and negative answers.

    def test_indexed_code_windows_match_independent_linear_ownership_checks(self) -> None:
        def linear_window(inventory: dict, location: int):
            sections = [row for row in inventory["sections"] if int(row["flags"], 16) & 2 and
                int(row["address"], 16) <= location < int(row["address"], 16) + int(row["size"], 16)]
            loads = [row for row in inventory["programHeaders"] if row["type"] == 1 and
                int(row["virtualAddress"], 16) <= location < int(row["virtualAddress"], 16) + int(row["memorySize"], 16)]
            if len(sections) != 1 or len(loads) != 1:
                return None
            section, load = sections[0], loads[0]
            if section["type"] != 1 or int(section["flags"], 16) & 6 != 6 or not load["flags"] & 1:
                return None
            file_end = int(load["virtualAddress"], 16) + int(load["fileSize"], 16)
            if location >= file_end:
                return None
            length = min(15, int(section["address"], 16) + int(section["size"], 16) - location, file_end - location)
            end = location + length
            if any(row["index"] != section["index"] and int(row["flags"], 16) & 2 and
                int(row["address"], 16) < end and location < int(row["address"], 16) + int(row["size"], 16)
                for row in inventory["sections"]):
                return None
            if any(row["index"] != load["index"] and row["type"] == 1 and int(row["virtualAddress"], 16) < end and
                location < int(row["virtualAddress"], 16) + int(row["memorySize"], 16) for row in inventory["programHeaders"]):
                return None
            return length if section["offset"] + location - int(section["address"], 16) == int(load["offset"], 16) + location - int(load["virtualAddress"], 16) else None

        original = self.report["dynamicInventory"]
        for group in ("sections", "programHeaders"):
            for delta in (-4, -1, 0, 1, 8, 14, 15, 16):
                for width in (1, 4, 20):
                    inventory = copy.deepcopy(original)
                    if group == "sections":
                        other = next(row for row in inventory[group] if row["name"] == ".plt") | {
                            "index": 11, "type": 8, "flags": "0x2", "address": hex(0x2000 + delta), "size": hex(width)}
                    else:
                        other = next(row for row in inventory[group] if row["index"] == 10) | {
                            "index": 11, "flags": 4, "virtualAddress": hex(0x2000 + delta), "fileSize": "0x0", "memorySize": hex(width)}
                    inventory[group].append(other)
                    symbols = {(row["tableSectionIndex"], row["symbolIndex"]): row for row in inventory["dynamicSymbols"]}
                    index = VERIFY.RetainedRelocationIndex(inventory, symbols, self.report["inputBytes"])
                    for location in range(0x1fff, 0x2011):
                        with self.subTest(group=group, delta=delta, width=width, location=hex(location)):
                            self.assertEqual(linear_window(inventory, location), index.code_window_length(location))

    def test_owned_window_cannot_be_hidden_by_an_absent_probe(self) -> None:
        site = self.report["sites"][0]
        disposition = "unresolved-forwarder-byte-ownership"
        site.update(memoryProbe=None, memoryTransfer=None, relocationBinding=None, externalTargetId=None,
            targetBindingDisposition=disposition, compositionDisposition=disposition)
        self.report["counts"]["dispositions"] = {disposition: 1}
        self.evidence["counts"] = copy.deepcopy(self.report["counts"])
        self.write_payloads()
        with self.assertRaisesRegex(VERIFY.VerificationError, "absent byte probe disposition/ownership"):
            self.verify()

    def test_version_definition_provenance_tags_population_and_verdaux_are_checked(self) -> None:
        inventory = self.report["dynamicInventory"]
        inventory["sections"].append({"index": 8, "name": ".gnu.version_d", "type": 0x6ffffffd, "flags": "0x2",
            "address": "0x6080", "offset": 1024, "size": "0x24", "link": 3, "info": 1, "alignment": "0x4", "entrySize": "0x0"})
        inventory["programHeaders"].append({"index": 1, "type": 1, "flags": 4, "offset": "0x400",
            "virtualAddress": "0x6080", "physicalAddress": "0x6080", "fileSize": "0x24", "memorySize": "0x24", "alignment": "0x1"})
        inventory["versionDefinitions"] = [{"sectionIndex": 8, "stringSectionIndex": 3, "recordOffset": 1024,
            "rawIndex": 1, "index": 1, "flags": 1, "hash": 0x5aa821, "name": "VER_1",
            "parentNames": ["PARENT"], "auxiliaryOffsets": [1044, 1052], "auxiliaryNameOffsets": [35, 42]}]
        inventory["dynamicEntries"][-1:-1] = [{"index": index + 8, "fileOffset": (index + 8) * 16, "tag": hex(tag), "value": hex(value)}
            for index, (tag, value) in enumerate(((0x6ffffffc, 0x6080), (0x6ffffffd, 1)))]
        self.sync_dynamic_storage(inventory)
        self.write_payloads()
        self.verify()  # A retained base definition does not turn an unversioned import into a runtime provider.
        original = copy.deepcopy(self.report)
        changes = [lambda inv: inv["sections"][-1].update(type=1), lambda inv: inv["sections"][-1].update(link=1),
            lambda inv: inv["sections"][-1].update(info=2), lambda inv: inv["sections"][-1].update(entrySize="0x14"),
            lambda inv: inv["sections"][-1].update(flags="0x0"), lambda inv: inv["sections"][-1].update(offset=4090),
            lambda inv: inv["sections"][-1].update(address="0xfffffffffffffff0"),
            lambda inv: inv["dynamicEntries"][-3].update(value="0x1"),
            lambda inv: inv["dynamicEntries"][-2].update(value="0x0"),
            lambda inv: inv["dynamicEntries"].pop(-2), lambda inv: inv["dynamicEntries"].__delitem__(slice(-3, -1)),
            lambda inv: inv["versionDefinitions"].clear(),
            lambda inv: inv["versionDefinitions"].append(copy.deepcopy(inv["versionDefinitions"][0])),
            lambda inv: inv["versionDefinitions"][0].update(recordOffset=4096),
            lambda inv: inv["versionDefinitions"][0].update(rawIndex=2),
            lambda inv: inv["versionDefinitions"][0].update(hash=0),
            lambda inv: inv["versionDefinitions"][0].update(parentNames=[""]),
            lambda inv: inv["versionDefinitions"][0].update(auxiliaryOffsets=[]),
            lambda inv: inv["versionDefinitions"][0].update(auxiliaryOffsets=[1044, 1044]),
            lambda inv: inv["versionDefinitions"][0].update(auxiliaryOffsets=[1044, 1051]),
            lambda inv: inv["versionDefinitions"][0].update(auxiliaryOffsets=[1052, 1044]),
            lambda inv: inv["versionDefinitions"][0].update(auxiliaryOffsets=[1043, 1052]),
            lambda inv: inv["versionDefinitions"][0].update(auxiliaryOffsets=[1044, 1053])]
        for ordinal, change in enumerate(changes):
            with self.subTest(mutation=ordinal):
                self.report = copy.deepcopy(original)
                change(self.report["dynamicInventory"])
                self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()

    def test_version_auxiliary_must_end_before_next_record_header(self) -> None:
        inventory = self.report["dynamicInventory"]
        inventory["sections"].append({"index": 8, "name": ".gnu.version_d", "type": 0x6ffffffd, "flags": "0x2",
            "address": "0x6080", "offset": 1024, "size": "0x50", "link": 3, "info": 2, "alignment": "0x4", "entrySize": "0x0"})
        inventory["programHeaders"].append({"index": 1, "type": 1, "flags": 4, "offset": "0x400",
            "virtualAddress": "0x6080", "physicalAddress": "0x6080", "fileSize": "0x50", "memorySize": "0x50", "alignment": "0x1"})
        first = {"sectionIndex": 8, "stringSectionIndex": 3, "recordOffset": 1024, "rawIndex": 1, "index": 1,
            "flags": 1, "hash": 0x5aa821, "name": "VER_1", "parentNames": ["PARENT"],
            "auxiliaryOffsets": [1044, 1052], "auxiliaryNameOffsets": [35, 42]}
        second = {"sectionIndex": 8, "stringSectionIndex": 3, "recordOffset": 1060, "rawIndex": 2, "index": 2,
            "flags": 1, "hash": 0x5aa821, "name": "VER_1", "parentNames": [],
            "auxiliaryOffsets": [1096], "auxiliaryNameOffsets": [35]}
        inventory["versionDefinitions"] = [first, second]
        inventory["dynamicEntries"][-1:-1] = [{"index": index + 8, "fileOffset": (index + 8) * 16, "tag": hex(tag), "value": hex(value)}
            for index, (tag, value) in enumerate(((0x6ffffffc, 0x6080), (0x6ffffffd, 2)))]
        self.sync_dynamic_storage(inventory)
        self.write_payloads()
        self.verify()
        # This disjoint range does not overlap any other retained record or auxiliary,
        # but it belongs after the next Verdef header and cannot be this record's child.
        first["auxiliaryOffsets"][1] = 1080
        self.write_payloads()
        with self.assertRaisesRegex(VERIFY.VerificationError, "auxiliary bounds/order"):
            self.verify()

    def test_version_section_ownership_reuses_one_load_interval_index(self) -> None:
        inventory = copy.deepcopy(self.report["dynamicInventory"])
        rows = []
        definitions = 24
        for ordinal in range(definitions):
            section_index = 8 + ordinal
            load_index = 30 + ordinal
            offset = 128 + ordinal * 36
            start = 0x6080 + ordinal * 36
            inventory["sections"].append({"index": section_index, "name": f".gnu.version_d.{ordinal}",
                "type": 0x6ffffffd, "flags": "0x2", "address": hex(start), "offset": offset, "size": "0x24",
                "link": 3, "info": 1, "alignment": "0x4", "entrySize": "0x0"})
            inventory["programHeaders"].append({"index": load_index, "type": 1, "flags": 4, "offset": hex(offset),
                "virtualAddress": hex(start), "physicalAddress": hex(start), "fileSize": "0x24", "memorySize": "0x24",
                "alignment": "0x1"})
            rows.append({"sectionIndex": section_index, "stringSectionIndex": 3, "recordOffset": offset,
                "rawIndex": ordinal + 1, "index": ordinal + 1, "flags": 1, "hash": 0x5aa821, "name": "VER_1",
                "parentNames": ["PARENT"], "auxiliaryOffsets": [offset + 20, offset + 28],
                "auxiliaryNameOffsets": [35, 42]})
        inventory["versionDefinitions"] = rows
        inventory["dynamicEntries"][-1:-1] = [{"index": index + 8, "fileOffset": (index + 8) * 16,
            "tag": hex(tag), "value": hex(value)} for index, (tag, value) in enumerate(
                ((0x6ffffffc, 0x6080), (0x6ffffffd, definitions)))]
        self.sync_dynamic_storage(inventory)
        interval_index = VERIFY.RetainedLoadIndex(inventory, self.report["inputBytes"])

        class NoRescanList(list):
            def __iter__(self):
                raise AssertionError("version-record ownership rescanned LOAD headers")

        inventory["programHeaders"] = NoRescanList(inventory["programHeaders"])
        sections = {row["index"]: row for row in inventory["sections"]}
        requirements = VERIFY.retained_version_records(inventory, sections, self.report["inputBytes"], interval_index)
        self.assertEqual({}, requirements)


class RetainedExternalEvidenceRegressionTest(unittest.TestCase):
    def test_real_driver_rehashed_metadata_and_canonical_bypasses_are_rejected(self) -> None:
        directory = ROOT / "oracle/gcc/16.2.0/external-call-component-v1"
        original_evidence = json.loads((directory / "evidence.json").read_bytes())
        original_report = json.loads(gzip.decompress((directory / "driver-report.json.gz").read_bytes()))
        self.assertEqual(15376, VERIFY.verify_evidence(directory / "evidence.json")[1]["sourcePhysicalSites"])
        temporary_root = ROOT / "build/machine-call-evidence-controls"
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="real-driver-", dir=temporary_root) as temporary:
            output = Path(temporary)
            (output / "driver-request.json").write_bytes((directory / "driver-request.json").read_bytes())
            for mutation, error in (("strtab-pointer", "dynamic string tags"), ("strtab-size", "dynamic string tags"),
                                    ("dynsym-storage", "DYNSYM section population"), ("dynsym-name-offset", "symbol name exceeds linked string table"),
                                    ("dynsym-name-truncated", "symbol name exceeds linked string table"),
                                    ("pt-dynamic-empty", "dynamic section/program population"),
                                    ("sht-dynamic-empty", "dynamic section/program population"),
                                    ("dynamic-entry-outside", "dynamic entry index/file offset"),
                                    ("versym-storage", "VERSYM section population"),
                                    ("dynsym-unallocated", "dynamic metadata"), ("jmprel-mapping-disagrees", "dynamic metadata"),
                                    ("packed-relr", "unsupported reasons differ"), ("empty-jmprel", "membership differs"),
                                    ("false-canonical", "noncanonical physical destination"),
                                    ("indirect-canonical", "noncanonical physical destination"),
                                    ("stripped-strlen-version", "version presence differs"),
                                    ("relacount-nonrelative-prefix", "relative relocation prefix"),
                                    ("relacount-exceeds-population", "relative relocation prefix"),
                                    ("relcount-without-table", "relative relocation prefix"),
                                    ("verneed-zero-count", "GNU version tag"), ("verneed-invalid-pointer", "GNU version tag"),
                                    ("verneed-tags-absent", "GNU version tag"), ("verneed-wrong-section-type", "GNU version"),
                                    ("verneed-out-of-file-records", "GNU version record"),
                                    ("plt-nonexecutable-section", "byte-window ownership"),
                                    ("plt-file-mapping-disagrees", "byte-window ownership"),
                                    ("plt-nonexecutable-load", "source call instruction lacks uniquely owned executable file-backed bytes"),
                                    ("overlapping-forwarder-probe", "retained source/probe byte windows conflict"),
                                    ("overlapping-string-name", "retained symbol names conflict in linked string table"),
                                    ("verneed-provider-conflict", "retained Verneed provider request differs within header"),
                                    ("verneed-oversized-provider", "retained GNU version string exceeds linked string table"),
                                    ("verneed-oversized-name", "retained GNU version string exceeds linked string table"),
                                    ("verneed-overlapping-auxiliary", "retained GNU version record storage overlaps"),
                                    ("copy-raw-section-index", "active COPY relocation symbol raw/resolved section index differs")):
                with self.subTest(mutation=mutation):
                    report, evidence = copy.deepcopy(original_report), copy.deepcopy(original_evidence)
                    if mutation in {"strtab-pointer", "strtab-size"}:
                        tag, value = (5, "0x1") if mutation == "strtab-pointer" else (10, "0x0")
                        next(row for row in report["dynamicInventory"]["dynamicEntries"] if int(row["tag"], 16) == tag)["value"] = value
                    elif mutation == "dynsym-storage":
                        next(row for row in report["dynamicInventory"]["sections"] if row["type"] == 11)["size"] = "0x18"
                    elif mutation == "dynsym-name-offset":
                        next(row for row in report["dynamicInventory"]["dynamicSymbols"] if row["name"] == "strlen")["nameOffset"] = 0xffffffff
                    elif mutation == "dynsym-name-truncated":
                        inventory = report["dynamicInventory"]
                        symbol = next(row for row in inventory["dynamicSymbols"] if row["name"] == "strlen")
                        strings = next(row for row in inventory["sections"] if row["index"] == next(
                            section["link"] for section in inventory["sections"] if section["type"] == 11))
                        symbol["nameOffset"] = int(strings["size"], 16) - 1
                    elif mutation == "pt-dynamic-empty":
                        next(row for row in report["dynamicInventory"]["programHeaders"] if row["type"] == 2)["fileSize"] = "0x0"
                    elif mutation == "sht-dynamic-empty":
                        next(row for row in report["dynamicInventory"]["sections"] if row["type"] == 6)["size"] = "0x0"
                    elif mutation == "dynamic-entry-outside":
                        report["dynamicInventory"]["dynamicEntries"][0]["fileOffset"] = report["inputBytes"] + 100
                    elif mutation == "versym-storage":
                        next(row for row in report["dynamicInventory"]["sections"] if row["type"] == 0x6fffffff)["size"] = "0x2"
                    elif mutation == "dynsym-unallocated":
                        next(row for row in report["dynamicInventory"]["sections"] if row["name"] == ".dynsym")["flags"] = "0x0"
                    elif mutation == "jmprel-mapping-disagrees":
                        inventory = report["dynamicInventory"]
                        section = next(row for row in inventory["sections"] if row["name"] == ".rela.plt")
                        section["offset"] += 1
                        for row in inventory["relocations"]:
                            if row["sectionIndex"] == section["index"]:
                                row["fileOffset"] += 1
                    elif mutation == "packed-relr":
                        entry = next(row for row in report["dynamicInventory"]["dynamicEntries"] if row["tag"] == "0x15")
                        entry.update(tag="0x24", value="0x401da0")
                    elif mutation == "stripped-strlen-version":
                        symbol = next(row for row in report["dynamicInventory"]["dynamicSymbols"] if row["name"] == "strlen")
                        self.assertEqual(("GLIBC_2.2.5", "libc.so.6"),
                            (symbol["version"]["name"], symbol["version"]["providerRequest"]))
                        symbol["version"] = None
                        entry = next(row for row in report["externalNamespace"]["entries"] if row["identity"]["name"] == "strlen")
                        old_id = entry["id"]
                        entry["identity"]["version"] = None
                        entry["id"] = "ext-" + sha256(VERIFY.canonical_bytes(entry["identity"])).hexdigest()
                        report["externalNamespaceSha256"] = sha256(VERIFY.canonical_bytes(report["externalNamespace"])).hexdigest()
                        affected = 0
                        for site in report["sites"]:
                            if site["externalTargetId"] == old_id:
                                site["externalTargetId"] = entry["id"]
                                affected += site["compositionDisposition"] == "static-import-request-reference"
                        self.assertEqual(376, affected)
                    elif mutation.startswith("relacount-") or mutation == "relcount-without-table":
                        tag, value = {"relacount-nonrelative-prefix": (0x6ffffff9, 4),
                            "relacount-exceeds-population": (0x6ffffff9, 9), "relcount-without-table": (0x6ffffffa, 1)}[mutation]
                        entry = next(row for row in report["dynamicInventory"]["dynamicEntries"] if row["tag"] == "0x15")
                        entry.update(tag=hex(tag), value=hex(value))
                    elif mutation.startswith("plt-"):
                        inventory = report["dynamicInventory"]
                        section = next(row for row in inventory["sections"] if row["name"] == ".plt")
                        if mutation == "plt-nonexecutable-section":
                            section["flags"] = "0x2"
                        elif mutation == "plt-file-mapping-disagrees":
                            section["offset"] += 1
                        else:
                            location = int(section["address"], 16)
                            load = next(row for row in inventory["programHeaders"] if row["type"] == 1 and
                                int(row["virtualAddress"], 16) <= location < int(row["virtualAddress"], 16) + int(row["fileSize"], 16))
                            load["flags"] &= ~1
                    elif mutation == "overlapping-forwarder-probe":
                        site = report["sites"][40]
                        memmove = next(row for row in report["sites"] if row["relocationBinding"] is not None and
                            row["relocationBinding"]["slotAddress"] == "0x63c2c0")
                        site["memoryProbe"] = copy.deepcopy(memmove["memoryProbe"])
                        site["memoryProbe"]["address"] = site["physicalTargetAddress"]
                        for key in ("memoryTransfer", "relocationBinding", "externalTargetId"):
                            site[key] = copy.deepcopy(memmove[key])
                        site["memoryTransfer"]["address"] = site["physicalTargetAddress"]
                    elif mutation == "overlapping-string-name":
                        symbols = report["dynamicInventory"]["dynamicSymbols"]
                        strlen = next(row for row in symbols if row["name"] == "strlen")
                        memmove = next(row for row in symbols if row["name"] == "memmove")
                        strlen["nameOffset"] = memmove["nameOffset"]
                    elif mutation == "verneed-provider-conflict":
                        inventory = report["dynamicInventory"]
                        requirement = next(row for row in inventory["versionRequirements"]
                            if row["sectionIndex"] == 8 and row["recordOffset"] == 7344 and row["name"] == "GLIBC_2.2.5")
                        requirement["providerRequest"] = "other.so"
                        symbol_strings = {row["index"]: row["link"] for row in inventory["sections"] if row["type"] == 11}
                        affected_symbols = {(symbol["tableSectionIndex"], symbol["symbolIndex"]): symbol
                            for symbol in inventory["dynamicSymbols"]
                            if symbol_strings[symbol["tableSectionIndex"]] == requirement["stringSectionIndex"] and
                                symbol["version"] is not None and symbol["version"]["index"] == requirement["index"]}
                        self.assertTrue(affected_symbols)
                        for symbol in affected_symbols.values():
                            symbol["version"]["providerRequest"] = "other.so"
                        for entry in report["externalNamespace"]["entries"]:
                            identity = entry["identity"]
                            key = (identity["symbolTableSectionIndex"], identity["symbolIndex"])
                            if key in affected_symbols:
                                old_id = entry["id"]
                                identity["version"]["providerRequest"] = "other.so"
                                entry["id"] = "ext-" + sha256(VERIFY.canonical_bytes(identity)).hexdigest()
                                for site in report["sites"]:
                                    if site["externalTargetId"] == old_id:
                                        site["externalTargetId"] = entry["id"]
                        report["externalNamespaceSha256"] = sha256(VERIFY.canonical_bytes(report["externalNamespace"])).hexdigest()
                    elif mutation in {"verneed-oversized-provider", "verneed-oversized-name"}:
                        inventory = report["dynamicInventory"]
                        requirement = next(row for row in inventory["versionRequirements"]
                            if row["sectionIndex"] == 8 and row["recordOffset"] == 7344 and row["name"] == "GLIBC_2.2.5")
                        field = "providerRequest" if mutation == "verneed-oversized-provider" else "name"
                        oversized = "x" * 2000
                        affected_requirements = [row for row in inventory["versionRequirements"]
                            if row["sectionIndex"] == requirement["sectionIndex"] and row["recordOffset"] == requirement["recordOffset"]]
                        if field == "name":
                            affected_requirements = [requirement]
                        for row in affected_requirements:
                            row[field] = oversized
                            if field == "name":
                                elf_hash = 0
                                for byte in oversized.encode("utf-8"):
                                    elf_hash = (elf_hash << 4) + byte
                                    high = elf_hash & 0xf0000000
                                    elf_hash = (elf_hash ^ (high >> 24)) & ~high
                                row["hash"] = elf_hash
                        symbol_strings = {row["index"]: row["link"] for row in inventory["sections"] if row["type"] == 11}
                        affected_versions = {(row["stringSectionIndex"], row["index"]) for row in affected_requirements}
                        affected_symbols = {(symbol["tableSectionIndex"], symbol["symbolIndex"]): symbol
                            for symbol in inventory["dynamicSymbols"] if symbol["version"] is not None and
                            (symbol_strings[symbol["tableSectionIndex"]], symbol["version"]["index"]) in affected_versions}
                        self.assertTrue(affected_symbols)
                        for symbol in affected_symbols.values():
                            symbol["version"][field] = oversized
                        for entry in report["externalNamespace"]["entries"]:
                            identity = entry["identity"]
                            key = (identity["symbolTableSectionIndex"], identity["symbolIndex"])
                            if key in affected_symbols:
                                old_id = entry["id"]
                                identity["version"][field] = oversized
                                entry["id"] = "ext-" + sha256(VERIFY.canonical_bytes(identity)).hexdigest()
                                for site in report["sites"]:
                                    if site["externalTargetId"] == old_id:
                                        site["externalTargetId"] = entry["id"]
                        report["externalNamespaceSha256"] = sha256(VERIFY.canonical_bytes(report["externalNamespace"])).hexdigest()
                    elif mutation == "verneed-overlapping-auxiliary":
                        requirement = next(row for row in report["dynamicInventory"]["versionRequirements"]
                            if row["sectionIndex"] == 8 and row["name"] == "GLIBC_2.14")
                        self.assertEqual(7360, requirement["auxiliaryOffset"])
                        requirement["auxiliaryOffset"] = 7372
                    elif mutation == "copy-raw-section-index":
                        inventory = report["dynamicInventory"]
                        relocation = next(row for row in inventory["relocations"] if row["type"] == 5)
                        symbol = next(row for row in inventory["dynamicSymbols"]
                            if row["tableSectionIndex"] == relocation["symbolTableSectionIndex"] and
                                row["symbolIndex"] == relocation["symbolIndex"])
                        self.assertEqual(("stderr", 28, 28, "defined"),
                            (symbol["name"], symbol["rawSectionIndex"], symbol["resolvedSectionIndex"], symbol["sectionKind"]))
                        symbol["rawSectionIndex"] = 0
                    elif mutation.startswith("verneed-"):
                        inventory = report["dynamicInventory"]
                        if mutation in {"verneed-zero-count", "verneed-invalid-pointer"}:
                            tag, value = (0x6fffffff, "0x0") if mutation == "verneed-zero-count" else (0x6ffffffe, "0x1")
                            next(row for row in inventory["dynamicEntries"] if int(row["tag"], 16) == tag)["value"] = value
                        elif mutation == "verneed-tags-absent":
                            for row in inventory["dynamicEntries"]:
                                if int(row["tag"], 16) in {0x6ffffffe, 0x6fffffff}:
                                    row.update(tag="0x15", value="0x0")
                        elif mutation == "verneed-wrong-section-type":
                            next(row for row in inventory["sections"] if row["type"] == 0x6ffffffe)["type"] = 1
                        else:
                            for row in inventory["versionRequirements"]:
                                row.update(recordOffset=report["inputBytes"] + 100, auxiliaryOffset=report["inputBytes"] + 116)
                    elif mutation == "empty-jmprel":
                        entry = next(row for row in report["dynamicInventory"]["dynamicEntries"] if row["tag"] == "0x2")
                        entry["value"] = "0x0"
                    else:
                        if mutation == "false-canonical":
                            site = report["sites"][40]
                            self.assertEqual(("0x3cc9", "0x403360", "unresolved-target-outside-canonical-population"),
                                (site["instructionRva"], site["physicalTargetAddress"], site["sourceDisposition"]))
                        else:
                            site = next(row for row in report["sites"] if row["physicalClassification"] == "indirect-call" and
                                        row["compositionDisposition"] == "unresolved-memory-transfer")
                        previous = site["compositionDisposition"]
                        site.update(compositionDisposition="retained-canonical-target", targetBindingDisposition="retained-canonical-target",
                            memoryProbe=None, memoryTransfer=None, relocationBinding=None, externalTargetId=None)
                        report["counts"]["dispositions"][previous] -= 1
                        report["counts"]["dispositions"]["retained-canonical-target"] += 1
                    raw = VERIFY.canonical_bytes(report)
                    stored = gzip.compress(raw, mtime=0)
                    evidence["payloads"]["report"].update(bytes=len(raw), sha256=sha256(raw).hexdigest(),
                        storedBytes=len(stored), storedSha256=sha256(stored).hexdigest())
                    evidence["counts"] = copy.deepcopy(report["counts"])
                    (output / "driver-report.json.gz").write_bytes(stored)
                    manifest = output / "evidence.json"
                    manifest.write_bytes(VERIFY.canonical_bytes(evidence))
                    with self.assertRaisesRegex(VERIFY.VerificationError, error):
                        VERIFY.verify_evidence(manifest)


if __name__ == "__main__":
    unittest.main()
