"""Authored offline provenance fixtures; no builds, network, or original-host input reads."""

from __future__ import annotations

from contextlib import redirect_stdout
import copy
from hashlib import sha256
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("machine_call_evidence", ROOT / "scripts/verify-machine-call-component-evidence.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


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
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=10).stdout.decode().strip()

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
            with self.subTest(data=data[:40]):
                with self.assertRaises(VERIFY.VerificationError):
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
original = verify.repository_path
def substitute(path, *, existing):
    selected = original(path, existing=existing)
    assert selected == victim and existing
    selected.unlink()
    os.mkfifo(selected, 0o600)
    return selected
verify.repository_path = substitute
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
            env=os.environ | {"PYTHONDONTWRITEBYTECODE": "1"}, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=5, check=True)
        self.assertIn(b"real FIFO substitution refused", result.stdout)

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
            with self.subTest(path=destination):
                with self.assertRaises((VERIFY.VerificationError, OSError)):
                    VERIFY.extract_report(destination, recovered)
        self.assertEqual(recovered, output.read_bytes())
        self.assertFalse((self.directory / "output.json").exists())


class ExternalCallComponentEvidenceTest(unittest.TestCase):
    # Reuse the tiny authored Git fixture without inheriting/re-running the eight machine controls.
    write_manifest = MachineCallComponentEvidenceTest.write_manifest
    write_payloads = MachineCallComponentEvidenceTest.write_payloads
    verify = MachineCallComponentEvidenceTest.verify

    def setUp(self) -> None:
        MachineCallComponentEvidenceTest.setUp(self)
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
            "symbolIndex": 1, "offset": "0x3000", "type": 7, "addend": 0, "dynamicTables": ["DT_JMPREL"],
            "slotFileOffset": 0, "slotLoadIndices": [0], "dispositions": []}
        inventory = {"schemaVersion": 1, "kind": "independent-elf-dynamic-bindings-v1", "authority": "diagnostic-authenticated-elf-metadata",
            "inputSha256": input_sha, "elfClass": 2, "byteOrder": 1, "elfType": "ET_DYN", "machine": 62, "imageBase": "0x1000",
            "activeSymbolTableSectionIndex": 1, "symbolPopulationBasis": "section-declared-dynsym", "complete": False,
            "releaseEligible": False, "negativeCompleteness": False, "sections": [], "programHeaders": [], "dynamicEntries": [],
            "dynamicSymbols": [symbol], "relocations": [relocation], "versionRequirements": [], "versionDefinitions": [],
            "neededLibraries": ["libexample.so"], "unsupportedReasons": ["runtime-provider-and-interposition-unresolved"]}
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
            "dynamicTables": ["DT_JMPREL"], "slotLoadIndices": [0], "slotFileOffset": 0, "relocationDispositions": [],
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
            memoryProbe={"address": "0x2000", "availableBytes": "ff25fa0f0000", "refusal": None}, memoryTransfer=transfer,
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
            "requestSha256": "", "runtime": runtime, "containmentStatus": "external-owner-required"}
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
            change(); self.write_manifest()
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
            lambda: self.report.update(complete=True), lambda: self.report.update(sourceCallPopulationComplete=True),
            lambda: self.report.update(sourceCallRecordsEnumerated=False), lambda: self.report.update(sourceReportSha256="0" * 64),
            lambda: self.report.update(runtime=original_report["runtime"] | {"bridgeSha256": "0" * 64}),
            lambda: self.request.update(metadataPolicy="unbounded"), lambda: self.request.update(recoveredFunctions=[])]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.request, self.report = copy.deepcopy(original_request), copy.deepcopy(original_report)
                change(); self.write_payloads()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()

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


if __name__ == "__main__":
    unittest.main()
