"""Offline provenance controls; no builds, network, or original-host input reads.

The retained-driver regression requires the two recorded source commits locally;
CI fetches those objects before these tests, never from inside the verifier.
"""

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
            "symbolIndex": 1, "offset": "0x3000", "type": 7, "addend": 0, "dynamicTables": ["jmprel"],
            "slotFileOffset": 0, "slotLoadIndices": [0], "dispositions": []}
        inventory = {"schemaVersion": 1, "kind": "independent-elf-dynamic-bindings-v1", "authority": "diagnostic-authenticated-elf-metadata",
            "inputSha256": input_sha, "elfClass": 2, "byteOrder": 1, "elfType": "ET_DYN", "machine": 62, "imageBase": "0x1000",
            "activeSymbolTableSectionIndex": 1, "symbolPopulationBasis": "section-declared-dynsym", "complete": False,
            "releaseEligible": False, "negativeCompleteness": False, "sections": [
                {"index": index, "name": name, "type": kind, "flags": "0x2", "address": start, "offset": offset,
                 "size": size, "link": link, "info": 0, "alignment": "0x8", "entrySize": width}
                for index, name, kind, start, offset, size, link, width in (
                    (1, ".dynsym", 11, "0x0", 0, "0x0", 3, "0x18"),
                    (2, ".rela.plt", 4, "0x4000", 0, "0x18", 1, "0x18"),
                    (3, ".dynstr", 3, "0x0", 0, "0x0", 0, "0x0"),
                    (5, ".rela.dyn", 4, "0x5000", 24, "0x0", 1, "0x18"))], "programHeaders": [{"index": 0, "type": 1,
                "flags": 6, "offset": "0x0", "virtualAddress": "0x3000", "physicalAddress": "0x3000", "fileSize": "0x8",
                "memorySize": "0x8", "alignment": "0x1"}], "dynamicEntries": [
                    {"index": index, "fileOffset": index * 16, "tag": hex(tag), "value": hex(value)}
                    for index, (tag, value) in enumerate(((23, 0x4000), (2, 24), (20, 7), (7, 0x5000), (8, 0), (9, 24),
                                                         (6, 0), (11, 24), (0, 0)))],
            "dynamicSymbols": [symbol], "relocations": [relocation], "versionRequirements": [], "versionDefinitions": [],
            "neededLibraries": ["libexample.so"], "unsupportedReasons": ["dynamic-hash-population-not-reconciled",
                "runtime-provider-and-interposition-unresolved"]}
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

    def test_nonforwarded_receipt_requires_the_exact_physical_instruction(self) -> None:
        symbols, relocations, imports = VERIFY.verify_external_inventory(self.report["dynamicInventory"],
            self.report["externalNamespace"], self.report["externalNamespaceSha256"], self.report["inputSha256"], self.report["imageBase"])
        index = VERIFY.RetainedRelocationIndex(self.report["dynamicInventory"], symbols, self.report["inputBytes"])
        site = copy.deepcopy(self.report["sites"][0])
        site.update(physicalClassification="indirect-call", physicalTargetAddress=None, viaForwarder=False,
            instructionBytes="ff15ea1f0000", instructionLength=6, returnAddress="0x1016")
        site["memoryProbe"].update(address="0x1010", availableBytes=site["instructionBytes"])
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
        site["memoryProbe"].update(address="0x1010", availableBytes=site["instructionBytes"])
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
                    for index, (tag, value) in enumerate(((pointer, 0x4000), (size, width), (entry_size, width), (6, 0), (11, 24), (0, 0)))]
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
            lambda inv: inv["dynamicSymbols"][0].update(info=17),
            lambda inv: inv["dynamicSymbols"][0].update(other=1),
            lambda inv: inv["dynamicSymbols"][0].update(rawSectionIndex=4),
            lambda inv: inv["dynamicSymbols"][0].update(resolvedSectionIndex=4),
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
        inventory["dynamicSymbols"].append(inventory["dynamicSymbols"][0] | {"symbolIndex": 2, "locator": "dynsym:1:2",
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

    def test_static_import_requires_consistent_retained_version_identity(self) -> None:
        inventory = self.report["dynamicInventory"]
        inventory["sections"].extend({"index": index, "name": name, "type": kind, "flags": "0x2", "address": "0x0", "offset": 0,
            "size": "0x0", "link": link, "info": 0, "alignment": "0x1", "entrySize": "0x0"}
            for index, name, kind, link in ((6, ".gnu.version", 0x6fffffff, 1), (7, ".gnu.version_r", 0x6ffffffe, 3)))
        inventory["dynamicSymbols"][0]["version"] = {"sectionIndex": 6, "fileOffset": 0, "raw": 2, "index": 2, "hidden": False,
            "kind": "required-version", "name": "VER_1", "providerRequest": "libexample.so"}
        inventory["versionRequirements"] = [{"sectionIndex": 7, "stringSectionIndex": 3, "recordOffset": 0, "auxiliaryOffset": 16,
            "providerRequest": "libexample.so", "name": "VER_1", "rawIndex": 2, "index": 2, "flags": 0, "hash": 0x5aa821}]

        def rehash_identity() -> None:
            version = self.report["dynamicInventory"]["dynamicSymbols"][0]["version"]
            entry = self.report["externalNamespace"]["entries"][0]
            entry["identity"]["version"] = {key: value for key, value in version.items() if key not in {"sectionIndex", "fileOffset"}}
            entry["id"] = "ext-" + sha256(VERIFY.canonical_bytes(entry["identity"])).hexdigest()
            self.report["sites"][0]["externalTargetId"] = entry["id"]
            self.report["externalNamespaceSha256"] = sha256(VERIFY.canonical_bytes(self.report["externalNamespace"])).hexdigest()
            self.write_payloads()

        rehash_identity()
        self.verify()
        original = copy.deepcopy(self.report)
        changes = [lambda inv: inv["dynamicSymbols"][0]["version"].update(name=None),
            lambda inv: inv["dynamicSymbols"][0]["version"].update(providerRequest=None),
            lambda inv: inv["dynamicSymbols"][0]["version"].update(kind="defined-version"),
            lambda inv: inv["dynamicSymbols"][0]["version"].update(raw=3),
            lambda inv: inv["dynamicSymbols"][0]["version"].update(hidden=True),
            lambda inv: inv["versionRequirements"].clear(),
            lambda inv: inv["versionRequirements"].append(copy.deepcopy(inv["versionRequirements"][0])),
            lambda inv: inv["versionRequirements"][0].update(providerRequest="other.so"),
            lambda inv: inv["versionRequirements"][0].update(rawIndex=3),
            lambda inv: inv["sections"][0].update(link=9), lambda inv: inv["sections"][4].update(link=9)]
        for index, change in enumerate(changes):
            with self.subTest(version=index):
                self.report = copy.deepcopy(original)
                change(self.report["dynamicInventory"])
                rehash_identity()
                with self.assertRaises(VERIFY.VerificationError):
                    self.verify()


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
            for mutation, error in (("packed-relr", "unsupported reasons differ"), ("empty-jmprel", "membership differs"),
                                    ("false-canonical", "noncanonical physical destination"),
                                    ("indirect-canonical", "noncanonical physical destination")):
                with self.subTest(mutation=mutation):
                    report, evidence = copy.deepcopy(original_report), copy.deepcopy(original_evidence)
                    if mutation == "packed-relr":
                        entry = next(row for row in report["dynamicInventory"]["dynamicEntries"] if row["tag"] == "0x15")
                        entry.update(tag="0x24", value="0x401da0")
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
