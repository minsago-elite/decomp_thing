from __future__ import annotations

import copy
import base64
import json
import shlex
from pathlib import Path
import tempfile
import unittest

from oracle.gcc import orchestration_contract as contract


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "oracle/gcc/16.2.0"


class ArgumentEquivalenceTest(unittest.TestCase):
    def setUp(self):
        self.reference = json.loads((PROFILE / contract.REFERENCE_NAME).read_text())
        self.tools = self.reference["toolchain"]["phaseTools"]
        self.case = next(case for case in self.reference["cases"] if case["id"] == "compile-to-object")
        self.plan = copy.deepcopy(self.case["observed"]["plan"]["phases"])
        self.trace = copy.deepcopy(self.case["observed"]["executedPhases"]["phases"])

    def check(self, planned=None, traced=None, failed=False):
        contract.validate_phase_arguments(self.plan if planned is None else planned,
                                          self.trace if traced is None else traced, self.tools, failed=failed)

    def test_all_real_reference_vectors_obey_the_declared_equivalence(self):
        for case in self.reference["cases"]:
            with self.subTest(case=case["id"]):
                observed = case["observed"]
                contract.validate_phase_arguments(observed["plan"]["phases"], observed["executedPhases"]["phases"],
                                                  self.tools, failed=observed["execution"]["exitCode"] != 0)

    def test_extra_argument_is_not_hidden_by_verbosity_normalization(self):
        for value in ("-I/w/injected", "-v", "-version"):
            changed = copy.deepcopy(self.trace)
            changed[0]["argv"].append(value)
            with self.subTest(value=value), self.assertRaises(contract.ContractError):
                self.check(traced=changed)

    def test_verbosity_at_a_different_position_is_rejected(self):
        changed = copy.deepcopy(self.trace)
        changed[0]["argv"].remove("-v")
        changed[0]["argv"].append("-v")
        with self.assertRaisesRegex(contract.ContractError, "positional verbosity"):
            self.check(traced=changed)

    def test_same_basename_at_unbound_path_is_rejected(self):
        for source in ("plan", "trace"):
            changed = copy.deepcopy(self.plan if source == "plan" else self.trace)
            changed[0]["tool"] = "/w/cc1"
            changed[0]["argv"][0] = "/w/cc1"
            with self.subTest(source=source), self.assertRaisesRegex(contract.ContractError, "phase path"):
                self.check(planned=changed) if source == "plan" else self.check(traced=changed)

    def test_success_requires_every_phase_and_failure_allows_only_prefix(self):
        self.check(traced=self.trace[:1], failed=True)
        for traced, failed in ((self.trace[:1], False), ([], True), (self.trace[1:], True)):
            with self.subTest(traced=traced, failed=failed), self.assertRaises(contract.ContractError):
                self.check(traced=traced, failed=failed)

    def test_pipeline_edges_cannot_be_changed(self):
        changed = copy.deepcopy(self.trace)
        changed[0]["stdoutPipedToNextPhase"] = not changed[0]["stdoutPipedToNextPhase"]
        with self.assertRaisesRegex(contract.ContractError, "pipe edge"):
            self.check(traced=changed)

    def test_link_arguments_are_exact(self):
        case = next(case for case in self.reference["cases"] if case["id"] == "link-single")
        plan = case["observed"]["plan"]["phases"]
        trace = copy.deepcopy(case["observed"]["executedPhases"]["phases"])
        trace[-1]["argv"].append("-lundeclared")
        with self.assertRaisesRegex(contract.ContractError, "positional verbosity"):
            self.check(planned=plan, traced=trace)


class ContractVerificationTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / "build/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_checked_contract_is_canonical_and_rebuilds_from_reviewed_inputs(self):
        verified = contract.verify_contract()
        self.assertEqual(verified["schemaVersion"], 2)
        self.assertEqual(len(verified["cases"]), 14)
        self.assertEqual(verified["provenance"]["reference"]["sha256"], contract.REVIEWED_REFERENCE_SHA256)

    def test_contract_mutations_are_rejected_against_the_independent_reference(self):
        original = contract.generate_contract()
        mutations = {
            "case-membership": lambda changed: changed["cases"].pop(),
            "driver-argument": lambda changed: changed["cases"][0]["driverInvocation"]["argv"].append("-malicious"),
            "phase-argument": lambda changed: changed["cases"][0]["phaseInvocations"]["planned"][0]["argv"].append("-malicious"),
            "phase-path": lambda changed: changed["phaseTools"]["compile"].update(path="/w/cc1"),
            "runtime-library": lambda changed: changed["phaseStartupDependencies"][changed["driver"]["path"]]["libraries"][0].update(sha256="0" * 64),
            "source-binding": lambda changed: changed["provenance"]["driverManifest"].update(sha256="0" * 64),
        }
        for name, mutate in mutations.items():
            changed = copy.deepcopy(original)
            mutate(changed)
            proposed = self.directory / f"{name}.json"
            proposed.write_bytes(contract.canonical(changed))
            with self.subTest(name=name), self.assertRaises(contract.ContractError):
                contract.verify_contract(proposed)

    def test_modified_reference_cannot_be_admitted_by_its_own_hash(self):
        reference = json.loads((PROFILE / contract.REFERENCE_NAME).read_text())
        observed = reference["cases"][0]["observed"]
        for mode in ("plan", "executedPhases"):
            entry = observed[mode]
            entry["phases"][0]["argv"].append("-self-consistent-forgery")
            lines = entry["stderr"]["text"].splitlines(keepends=True)
            index = next(i for i, line in enumerate(lines) if line.startswith(" "))
            lines[index] = " " + shlex.join(entry["phases"][0]["argv"]) + "\n"
            payload = "".join(lines).encode()
            entry["stderr"] = {"bytes": len(payload), "sha256": contract.sha256(payload),
                               "base64": base64.b64encode(payload).decode(), "text": payload.decode()}
            if mode == "executedPhases":
                entry["stderrSha256"] = contract.sha256(payload)
        # The changed document has coherent phase vectors, transcripts and stream hashes.
        contract.validate_phase_arguments(observed["plan"]["phases"], observed["executedPhases"]["phases"],
                                          reference["toolchain"]["phaseTools"], failed=False)
        with self.assertRaisesRegex(contract.ContractError, "independently reviewed capture digest"):
            contract._generate(PROFILE, contract.canonical(reference))

    def test_duplicate_keys_and_excessive_depth_are_rejected(self):
        for payload in (b'{"schemaVersion":2,"schemaVersion":2}', b'{"x":' * 60 + b'0' + b'}' * 60):
            proposed = self.directory / "invalid.json"
            proposed.write_bytes(payload)
            with self.subTest(payload=payload[:80]), self.assertRaises(contract.ContractError):
                contract.verify_contract(proposed)

    def test_proposed_document_byte_bound_is_checked_before_parsing(self):
        proposed = self.directory / "oversized.json"
        with proposed.open("wb") as stream:
            stream.truncate(contract.MAX_DOCUMENT_BYTES + 1)
        with self.assertRaisesRegex(contract.ContractError, "document exceeds byte bound"):
            contract.verify_contract(proposed)

    def test_manifest_input_is_checked_against_its_reviewed_manifest(self):
        manifest_name = "oracle-manifest.json"
        manifest_payload = (PROFILE / manifest_name).read_bytes()
        manifest = json.loads(manifest_payload)
        (self.directory / manifest_name).write_bytes(manifest_payload)
        for role in ("sourceLock", "buildRecord"):
            relative = manifest["inputs"][role]["path"]
            (self.directory / relative).write_bytes((PROFILE / relative).read_bytes())
        changed = self.directory / manifest["inputs"]["buildRecord"]["path"]
        changed.write_bytes(changed.read_bytes() + b"\n")
        with self.assertRaisesRegex(contract.ContractError, "manifest input changed"):
            contract._authority(self.directory, manifest_name)

    def test_unreviewed_manifest_cannot_choose_a_new_source_lock(self):
        manifest = json.loads((PROFILE / "oracle-manifest.json").read_text())
        manifest["inputs"]["sourceLock"]["sha256"] = "0" * 64
        (self.directory / "oracle-manifest.json").write_bytes(contract.canonical(manifest))
        with self.assertRaisesRegex(contract.ContractError, "manifest differs from reviewed"):
            contract._authority(self.directory, "oracle-manifest.json")

    def test_noncanonical_serialization_is_rejected(self):
        original = contract.generate_contract()
        proposed = self.directory / "compact.json"
        proposed.write_text(json.dumps(original))
        with self.assertRaises(contract.ContractError):
            contract.verify_contract(proposed)


if __name__ == "__main__":
    unittest.main()
