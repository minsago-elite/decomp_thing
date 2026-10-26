from __future__ import annotations

import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from oracle.gcc import verify_production_function_replay_evidence as verifier


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RETAINED = REPOSITORY_ROOT / "oracle/gcc/16.2.0/production-function-replay"


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class ProductionFunctionReplayEvidenceTest(unittest.TestCase):
    """Retained-byte controls establish offline consistency, never live admission."""

    @classmethod
    def setUpClass(cls) -> None:
        parent = REPOSITORY_ROOT / "build/python-test-tmp"
        parent.mkdir(parents=True, exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix="function-replay-evidence-", dir=parent)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.repository = Path(cls.temporary.name) / "repository"
        cls.repository.mkdir()
        cls.original_manifest = json.loads((RETAINED / "evidence.json").read_bytes())
        oracle_path = cls.repository / cls.original_manifest["oracle"]["path"]
        oracle_path.parent.mkdir(parents=True)
        shutil.copyfile(REPOSITORY_ROOT / cls.original_manifest["oracle"]["path"], oracle_path)
        (cls.repository / "authored-source.txt").write_text("original fixture source\n")
        cls._git("init", "-q")
        cls._git("add", ".")
        cls._git("-c", "user.name=Evidence control", "-c", "user.email=fixture@example.invalid",
                 "commit", "-q", "-m", "Authored offline source fixture")
        cls.source_commit = cls._git("rev-parse", "HEAD").decode().strip()
        cls.source_tree = cls._git("rev-parse", "HEAD^{tree}").decode().strip()
        cls.source_body = cls._git("cat-file", "commit", cls.source_commit)
        cls.source_inventory = cls._git("ls-tree", "-r", "-z", "--full-tree", cls.source_commit)
        # The checkout object is verified from its exact body. Its parent is the retained source;
        # the verifier must not silently replace either identity with the current checkout HEAD.
        cls._git("-c", "user.name=Evidence control", "-c", "user.email=fixture@example.invalid",
                 "commit", "--allow-empty", "-q", "-m", "Authored checkout fixture")
        cls.checkout_commit = cls._git("rev-parse", "HEAD").decode().strip()
        cls.checkout_body = cls._git("cat-file", "commit", cls.checkout_commit)
        (cls.repository / "authored-source.txt").write_text("different current fixture HEAD\n")
        cls._git("add", "authored-source.txt")
        cls._git("-c", "user.name=Evidence control", "-c", "user.email=fixture@example.invalid",
                 "commit", "-q", "-m", "Current HEAD is not the retained source")
        cls.current_tree = cls._git("rev-parse", "HEAD^{tree}").decode().strip()
        cls.oracle = json.loads(oracle_path.read_bytes())
        cls.model = cls._retained_json("model")
        cls.observation = cls._retained_json("boundary-observation")
        cls.accuracy = cls._retained_json("accuracy")

    @classmethod
    def _git(cls, *arguments: str) -> bytes:
        result = subprocess.run(["git", "-C", str(cls.repository), *arguments], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout

    @classmethod
    def _retained_json(cls, role: str) -> dict:
        row = next(row for row in cls.original_manifest["payloads"] if row["role"] == role)
        return json.loads(gzip.decompress((RETAINED / row["path"]).read_bytes()))

    def setUp(self) -> None:
        self.case = Path(tempfile.mkdtemp(prefix="case-", dir=self.repository))
        self.addCleanup(shutil.rmtree, self.case)
        self.evidence = self.case / "evidence"
        shutil.copytree(RETAINED, self.evidence)
        self.manifest_path = self.evidence / "evidence.json"
        self.manifest = copy.deepcopy(self.original_manifest)
        source = self.manifest["source"]
        source["commit"] = self.source_commit
        source["treeSha1"] = self.source_tree
        source["inventory"]["bytes"] = len(self.source_inventory)
        source["inventory"]["sha256"] = _sha(self.source_inventory)
        (self.evidence / source["inventory"]["path"]).write_bytes(self.source_inventory)
        source["commitObject"] = {
            "path": "authored-source-commit.raw", "bytes": len(self.source_body),
            "sha256": _sha(self.source_body),
        }
        (self.evidence / "authored-source-commit.raw").write_bytes(self.source_body)
        source["checkoutCommit"] = self.checkout_commit
        source["checkoutCommitObject"] = {
            "path": "authored-checkout-commit.raw", "bytes": len(self.checkout_body),
            "sha256": _sha(self.checkout_body),
        }
        (self.evidence / "authored-checkout-commit.raw").write_bytes(self.checkout_body)
        self.manifest["actions"]["headSha"] = self.source_commit
        self._write_manifest()

    def _write_manifest(self) -> None:
        self.manifest_path.write_bytes(_json_bytes(self.manifest))

    def _row(self, role: str) -> dict:
        return next(row for row in self.manifest["payloads"] if row["role"] == role)

    def _replace_encoded(self, role: str, encoded: bytes, decoded: bytes | None = None) -> None:
        row = self._row(role)
        (self.evidence / row["path"]).write_bytes(encoded)
        row["gzipBytes"] = len(encoded)
        row["gzipSha256"] = _sha(encoded)
        if decoded is not None:
            row["bytes"] = len(decoded)
            row["sha256"] = _sha(decoded)
        self._write_manifest()

    def _replace_decoded(self, role: str, decoded: bytes) -> None:
        self._replace_encoded(role, gzip.compress(decoded, mtime=0), decoded)

    def _verify(self) -> dict:
        return verifier.verify(self.manifest_path, repository_root=self.repository)

    def test_verified_retained_bytes_rederive_thresholds_without_granting_live_authority(self) -> None:
        report = self._verify()
        self.assertTrue(report["offlineIntegrityVerified"])
        self.assertIn("rederivedThresholds", report)
        self.assertNotIn("productionVerified", report)
        self.assertNotEqual(self.source_tree, self.current_tree)
        measurements = verifier.rederive_measurements(self.model, self.oracle, self.observation)
        self.assertEqual(self.accuracy["score"]["measurements"], measurements)
        self.assertEqual({"numerator": 3269, "denominator": 3273}, measurements["functionStarts"]["precision"])
        self.assertEqual({"numerator": 3269, "denominator": 3284}, measurements["functionStarts"]["recall"])
        self.assertEqual(6, measurements["survivingSymbolIdentity"]["population"])

    def test_changed_compressed_bytes_are_not_accepted_under_old_commitments(self) -> None:
        path = self.evidence / self._row("qualification")["path"]
        value = bytearray(path.read_bytes())
        value[len(value) // 2] ^= 1
        path.write_bytes(value)
        with self.assertRaises(verifier.EvidenceError):
            self._verify()

    def test_rebound_compressed_bytes_do_not_bypass_decompressed_commitment(self) -> None:
        value = _json_bytes({"provider": "substituted receipt"})
        self._replace_encoded("qualification", gzip.compress(value, mtime=0))
        with self.assertRaises(verifier.EvidenceError):
            self._verify()

    def test_duplicate_payload_json_key_is_rejected_after_matching_byte_hashes(self) -> None:
        self._replace_decoded("qualification", b'{"provider":"first","provider":"second"}\n')
        with self.assertRaisesRegex(verifier.EvidenceError, "[Dd]uplicate"):
            self._verify()

    def test_trailing_payload_json_document_is_rejected_after_matching_byte_hashes(self) -> None:
        self._replace_decoded("qualification", b'{"provider":"first"}\n{}\n')
        with self.assertRaisesRegex(verifier.EvidenceError, "JSON|[Tt]railing|[Ee]xtra"):
            self._verify()

    def test_gzip_member_boundary_and_checksum_are_enforced(self) -> None:
        original = (self.evidence / self._row("qualification")["path"]).read_bytes()
        for name, encoded in (
            ("multiple-members", original + gzip.compress(b"{}", mtime=0)),
            ("trailing-bytes", original + b"unbound-trailing-bytes"),
            ("truncated-member", original[:-1]),
            ("malformed-header", b"not a gzip stream"),
            ("invalid-checksum", original[:-8] + bytes([original[-8] ^ 1]) + original[-7:]),
        ):
            with self.subTest(name=name):
                self._replace_encoded("qualification", encoded)
                with self.assertRaisesRegex(verifier.EvidenceError, "gzip|[Cc]ompress|[Tt]railing|[Mm]ember|[Tt]runcat"):
                    self._verify()

    def test_manifest_rejects_duplicate_keys_and_nonclosed_fields(self) -> None:
        original = self.manifest_path.read_bytes()
        self.manifest_path.write_bytes(original.replace(b'"schemaVersion": 1', b'"schemaVersion": 1, "schemaVersion": 1', 1))
        with self.assertRaisesRegex(verifier.EvidenceError, "[Dd]uplicate"):
            self._verify()
        self.manifest["productionVerified"] = True
        self._write_manifest()
        with self.assertRaises(verifier.EvidenceError):
            self._verify()

    def test_missing_extra_and_duplicate_payload_roles_are_rejected(self) -> None:
        original = copy.deepcopy(self.manifest["payloads"])
        for payloads in (original[:-1], original + [copy.deepcopy(original[0])],
                         original + [{**original[0], "role": "unrecognized", "path": "unexpected.gz"}]):
            with self.subTest(roles=[row["role"] for row in payloads]):
                self.manifest["payloads"] = payloads
                self._write_manifest()
                with self.assertRaises(verifier.EvidenceError):
                    self._verify()

    def test_payload_paths_reject_traversal_absolute_alias_and_repeated_names(self) -> None:
        row = self._row("model")
        original = row["path"]
        for candidate in ("../model.json.gz", "./" + original, str(self.evidence / original),
                          self._row("qualification")["path"]):
            with self.subTest(path=candidate):
                row["path"] = candidate
                self._write_manifest()
                with self.assertRaises(verifier.EvidenceError):
                    self._verify()

    def test_symlink_payload_is_not_followed(self) -> None:
        path = self.evidence / self._row("model")["path"]
        path.unlink()
        path.symlink_to(RETAINED / self._row("model")["path"])
        with self.assertRaises(verifier.EvidenceError):
            self._verify()

    def test_hardlink_alias_is_rejected_even_with_matching_file_commitments(self) -> None:
        path = self.evidence / self._row("model")["path"]
        os.link(path, self.evidence / "authored-hardlink")
        with self.assertRaisesRegex(verifier.EvidenceError, "link|alias"):
            self._verify()

    def test_identical_byte_replacement_during_descriptor_read_is_rejected(self) -> None:
        path = self.evidence / self._row("qualification")["path"]
        identity = path.stat()
        target = identity.st_dev, identity.st_ino
        read = os.read
        replaced = False

        def replace_after_read(descriptor: int, maximum: int) -> bytes:
            nonlocal replaced
            value = read(descriptor, maximum)
            current = os.fstat(descriptor)
            if value and not replaced and (current.st_dev, current.st_ino) == target:
                replacement = path.with_suffix(".replacement")
                replacement.write_bytes(path.read_bytes())
                replacement.replace(path)
                replaced = True
            return value

        with patch.object(verifier.os, "read", side_effect=replace_after_read):
            with self.assertRaisesRegex(verifier.EvidenceError, "identity|metadata|changed"):
                self._verify()
        self.assertTrue(replaced, "control must mutate the file during its actual descriptor read")

    def test_fifo_payload_is_rejected_without_waiting_for_a_writer(self) -> None:
        path = self.evidence / self._row("model")["path"]
        path.unlink()
        os.mkfifo(path)
        script = (
            "from pathlib import Path\n"
            "from oracle.gcc.verify_production_function_replay_evidence import verify, EvidenceError\n"
            "import sys\n"
            "try:\n"
            "    verify(Path(sys.argv[1]), repository_root=Path(sys.argv[2]))\n"
            "except EvidenceError:\n"
            "    sys.exit(0)\n"
            "raise SystemExit('FIFO was accepted')\n"
        )
        result = subprocess.run([sys.executable, "-c", script, str(self.manifest_path), str(self.repository)],
                                cwd=REPOSITORY_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))

    def test_retained_scope_cannot_claim_full_structural_or_release_authority(self) -> None:
        for field in ("fullStructuralScored", "complete", "releaseEligible"):
            with self.subTest(field=field):
                self.manifest["scope"][field] = True
                self._write_manifest()
                with self.assertRaises(verifier.EvidenceError):
                    self._verify()
                self.manifest["scope"][field] = False

    def test_manifest_declared_and_actual_byte_bounds_are_enforced(self) -> None:
        for field in ("bytes", "gzipBytes"):
            with self.subTest(field=field):
                row = self._row("model")
                original = row[field]
                row[field] = original + 1
                self._write_manifest()
                with self.assertRaises(verifier.EvidenceError):
                    self._verify()
                row[field] = original
        self._write_manifest()
        for name, bound in (
            ("MAX_MANIFEST_BYTES", self.manifest_path.stat().st_size - 1),
            ("MAX_INVENTORY_BYTES", len(self.source_inventory) - 1),
            ("MAX_COMPRESSED_BYTES", sum(row["gzipBytes"] for row in self.manifest["payloads"]) - 1),
            ("MAX_DECODED_BYTES", max(row["bytes"] for row in self.manifest["payloads"]) - 1),
            ("MAX_TOTAL_DECODED_BYTES", sum(row["bytes"] for row in self.manifest["payloads"]) - 1),
        ):
            with self.subTest(limit=name), patch.object(verifier, name, bound):
                with self.assertRaises(verifier.EvidenceError):
                    self._verify()

    def test_rebound_inventory_cannot_substitute_for_the_original_git_tree(self) -> None:
        replacement = self._git("ls-tree", "-r", "-z", "--full-tree", "HEAD")
        inventory = self.manifest["source"]["inventory"]
        (self.evidence / inventory["path"]).write_bytes(replacement)
        inventory["bytes"] = len(replacement)
        inventory["sha256"] = _sha(replacement)
        self._write_manifest()
        with self.assertRaises(verifier.EvidenceError):
            self._verify()

    def test_duplicate_inventory_entry_is_rejected_after_rebinding_its_file_hash(self) -> None:
        replacement = self.source_inventory + self.source_inventory.split(b"\0", 1)[0] + b"\0"
        inventory = self.manifest["source"]["inventory"]
        (self.evidence / inventory["path"]).write_bytes(replacement)
        inventory["bytes"] = len(replacement)
        inventory["sha256"] = _sha(replacement)
        self._write_manifest()
        with self.assertRaises(verifier.EvidenceError):
            self._verify()

    def test_retained_git_objects_work_without_local_historical_git_objects(self) -> None:
        git = self.repository / ".git"
        hidden = self.repository / ".git-authored-test-storage"
        git.rename(hidden)
        try:
            self.assertTrue(self._verify()["offlineIntegrityVerified"])
        finally:
            hidden.rename(git)

    def test_source_commit_object_cannot_be_replaced_under_the_original_commit_id(self) -> None:
        entry = self.manifest["source"]["commitObject"]
        changed = self.source_body + b"changed source commit message\n"
        (self.evidence / entry["path"]).write_bytes(changed)
        entry["bytes"] = len(changed)
        entry["sha256"] = _sha(changed)
        self._write_manifest()
        with self.assertRaises(verifier.EvidenceError):
            self._verify()

    def test_tree_hash_and_checkout_object_are_verified_independently(self) -> None:
        self.manifest["source"]["treeSha1"] = self.current_tree
        self._write_manifest()
        with self.assertRaises(verifier.EvidenceError):
            self._verify()
        self.manifest["source"]["treeSha1"] = self.source_tree
        entry = self.manifest["source"]["checkoutCommitObject"]
        changed = self.checkout_body + b"changed commit message\n"
        (self.evidence / entry["path"]).write_bytes(changed)
        entry["bytes"] = len(changed)
        entry["sha256"] = _sha(changed)
        self._write_manifest()
        with self.assertRaises(verifier.EvidenceError):
            self._verify()

    def test_missing_or_extra_survivors_cannot_match_the_complete_raw_oracle_census(self) -> None:
        measurements = verifier.rederive_measurements(self.model, self.oracle, self.observation)
        for extra in (False, True):
            with self.subTest(extra=extra):
                claimed = copy.deepcopy(self.accuracy)
                survivors = claimed["score"]["measurements"]["survivingSymbolIdentity"]
                if extra:
                    row = copy.deepcopy(survivors["symbols"][0])
                    row["name"] = "invented-surviving-symbol"
                    survivors["symbols"].append(row)
                    delta = 1
                else:
                    survivors["symbols"].pop()
                    delta = -1
                for field in ("population", "exact"):
                    survivors[field] += delta
                for field in ("numerator", "denominator"):
                    survivors["identityRecovery"][field] += delta
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_accuracy(claimed, measurements)

    def test_boundary_excluded_surviving_alias_still_enters_symbol_denominator(self) -> None:
        oracle = copy.deepcopy(self.oracle)
        observation = copy.deepcopy(self.observation)
        ignored = observation["result"]["ignoredExcludedRecoveries"][0]
        function = next(row for row in oracle["functions"] if row["id"] == ignored["oracleId"])
        alias = next(row for row in function["aliases"] if row["availability"]["stripped"] == "removed")
        alias["availability"]["stripped"] = "surviving"
        exclusion = next(row for row in observation["excludedFunctions"] if row["oracleId"] == function["id"])
        exclusion["aliases"] = copy.deepcopy(function["aliases"])
        measurements = verifier.rederive_measurements(self.model, oracle, observation)
        symbols = measurements["survivingSymbolIdentity"]
        self.assertEqual(7, symbols["population"])
        self.assertEqual(6, symbols["exact"])
        self.assertEqual(1, symbols["nameMismatch"])
        included = next(row for row in symbols["symbols"] if row["oracleId"] == function["id"])
        self.assertTrue(included["oracleExcluded"])
        self.assertEqual(alias["name"], included["name"])
        self.assertEqual("name-mismatch", included["outcome"])

    def test_omitted_false_negative_cannot_shrink_the_reference_population(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["result"]["falseNegatives"].pop()
        boundaries = observation["result"]["boundaries"]
        boundaries["referenceCount"] -= 1
        boundaries["falseNegatives"] -= 1
        boundaries["recall"]["denominator"] -= 1
        with self.assertRaises(verifier.EvidenceError):
            verifier.rederive_measurements(self.model, self.oracle, observation)

    def test_near_matches_cannot_be_credited_to_the_exact_start_threshold(self) -> None:
        measurements = copy.deepcopy(self.accuracy["score"]["measurements"])
        starts = measurements["functionStarts"]
        starts["nearMisses"] = starts["exactMatches"]
        starts["exactMatches"] = 0
        starts["falsePositives"] = starts["scoredRecoveredCount"]
        starts["falseNegatives"] = starts["referenceCount"]
        starts["precision"]["numerator"] = 0
        starts["recall"]["numerator"] = 0
        claimed = copy.deepcopy(self.accuracy)
        claimed["score"]["measurements"] = measurements
        # Crediting near matches would retain the original above-95% acceptance booleans.
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_accuracy(claimed, measurements)
        claimed["acceptance"]["functionStarts"].update(
            accepted=False, precisionAccepted=False, recallAccepted=False,
        )
        claimed["benchmarkAccepted"] = False
        thresholds = verifier.verify_accuracy(claimed, measurements)
        self.assertFalse(thresholds["functionStarts"]["accepted"])

    def test_explicit_manifest_is_required_by_cli(self) -> None:
        result = subprocess.run([sys.executable, str(REPOSITORY_ROOT / "scripts/verify-gcc-production-function-replay-evidence.py")],
                                cwd=REPOSITORY_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn(b"manifest", result.stderr.lower())

    def test_boolean_and_integer_json_types_cannot_alias_reported_metrics(self) -> None:
        measurements = verifier.rederive_measurements(self.model, self.oracle, self.observation)
        for target in ("count", "acceptance"):
            with self.subTest(target=target):
                claimed = copy.deepcopy(self.accuracy)
                if target == "count":
                    claimed["score"]["measurements"]["functionStarts"]["nearMisses"] = False
                else:
                    claimed["acceptance"]["functionStarts"]["accepted"] = 1
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_accuracy(claimed, measurements)

    def test_strict_json_rejects_unbounded_numbers_and_unpaired_unicode_scalars(self) -> None:
        for payload in (b'{"extra":1e999}', b'{"extra":-1e999}',
                        b'{"extra":' + b'9' * 1024 + b'}',
                        b'{"extra":"\\ud800"}', b'{"\\udfff":0}'):
            with self.subTest(payload=payload[:40]):
                with self.assertRaises(verifier.EvidenceError):
                    verifier._json(payload)
        self.assertEqual({"ratio": 0.995432, "symbol": "\U0001f600"},
                         verifier._json(b'{"ratio":0.995432,"symbol":"\\ud83d\\ude00"}'))

    def test_rebound_unused_malformed_json_scalars_still_reject_the_package(self) -> None:
        qualification = self._retained_json("qualification")
        qualification["extra"] = "MALFORMED_SCALAR"
        for token in (b'1e999', b'"\\ud800"', b'9' * 1024):
            with self.subTest(token=token[:20]):
                payload = _json_bytes(qualification).replace(b'"MALFORMED_SCALAR"', token)
                self._replace_decoded("qualification", payload)
                with self.assertRaises(verifier.EvidenceError):
                    self._verify()

    def test_rehashed_target_substitutions_cannot_detach_from_the_observation_and_oracle(self) -> None:
        assessment = self._retained_json("export-assessment")["assessment"]
        for field, replacement in (("imageBase", "0x400001"), ("ghidraLanguage", "AARCH64:LE:64:v8A"),
                                   ("executableRangesSha256", "f" * 64)):
            with self.subTest(field=field):
                binding = self._retained_json("full-export-binding")
                binding["targetDescriptor"][field] = replacement
                binding["targetDescriptorSha256"] = _sha(_json_bytes(binding["targetDescriptor"]))
                self.assertEqual(binding["targetDescriptorSha256"], _sha(_json_bytes(binding["targetDescriptor"])))
                with self.assertRaises(verifier.EvidenceError):
                    verifier._verify_target(binding, self.observation, self.oracle, assessment)

    def test_rehashed_assessment_inputs_and_loader_must_match_unique_intent_artifacts(self) -> None:
        binding = self._retained_json("full-export-binding")
        intent = self._retained_json("intent")
        for field, replacement in (("inputBytes", 1), ("exporterSha256", "f" * 64),
                                   ("analysisToolBytes", 1), ("complete", True), ("releaseEligible", True)):
            with self.subTest(field=field):
                assessment = self._retained_json("export-assessment")["assessment"]
                assessment[field] = replacement
                assessment["assessmentSha256"] = _sha(_json_bytes({k: v for k, v in assessment.items() if k != "assessmentSha256"}))
                with self.assertRaises(verifier.EvidenceError):
                    verifier._verify_export_inputs(binding, assessment, intent)
        duplicated = copy.deepcopy(intent)
        duplicated["artifacts"].append(copy.deepcopy(duplicated["artifacts"][0]))
        with self.assertRaises(verifier.EvidenceError):
            verifier._verify_export_inputs(binding, self._retained_json("export-assessment")["assessment"], duplicated)
        changed_loader = self._retained_json("export-assessment")["assessment"]
        changed_loader["compilerSpec"] = "windows"
        changed_loader["assessmentSha256"] = _sha(_json_bytes({k: v for k, v in changed_loader.items() if k != "assessmentSha256"}))
        with self.assertRaises(verifier.EvidenceError):
            verifier._verify_target(binding, self.observation, self.oracle, changed_loader)

    def test_rebound_replay_scope_overclaims_are_rejected(self) -> None:
        for role, field, replacement in (("replay-capture", "complete", True),
                                          ("replay-capture", "releaseEligible", True),
                                          ("replay-output", "authority", "production-verified")):
            with self.subTest(role=role, field=field):
                output = self._retained_json("replay-output")
                capture = self._retained_json("replay-capture")
                (output if role == "replay-output" else capture)[field] = replacement
                output_bytes = _json_bytes(output)
                capture["metadataSha256"] = _sha(output_bytes)
                capture_bytes = _json_bytes(capture)
                score = self._retained_json("boundary-score")
                score["replayMetadataSha256"] = _sha(output_bytes)
                score["replayCaptureSha256"] = _sha(capture_bytes)
                score_bytes = _json_bytes(score)
                accuracy = self._retained_json("accuracy")
                accuracy["score"]["boundaryScoreSha256"] = _sha(score_bytes)
                accuracy_bytes = _json_bytes(accuracy)
                result = self._retained_json("result")
                for name, payload in (("boundaryScore", score_bytes), ("functionAccuracy", accuracy_bytes)):
                    result[name]["bytes"] = len(payload)
                    result[name]["sha256"] = _sha(payload)
                qualification = self._retained_json("qualification")
                qualification["productionBoundaryScoreSha256"] = _sha(score_bytes)
                qualification["productionFunctionAccuracySha256"] = _sha(accuracy_bytes)
                for name, payload in (("replay-output", output_bytes), ("replay-capture", capture_bytes),
                                      ("boundary-score", score_bytes), ("accuracy", accuracy_bytes),
                                      ("result", _json_bytes(result)), ("qualification", _json_bytes(qualification))):
                    self._replace_decoded(name, payload)
                with self.assertRaises(verifier.EvidenceError):
                    self._verify()


if __name__ == "__main__":
    unittest.main()
