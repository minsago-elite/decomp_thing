#!/usr/bin/env python3
"""Authored, in-memory metadata controls. No agent, provider or subject runs."""

import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "acp_release_manifest", Path(__file__).resolve().parents[1] / "contracts/acp/v1/verify.py")
MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST)
DEFINITION, DEFINITION_SHA = MANIFEST.read_json(MANIFEST.DEFINITION)
COMMIT = "a" * 40


def authored_bindings():
    """Synthetic declarations exercise the format; they are never real evidence."""
    value = MANIFEST.empty_bindings(DEFINITION, DEFINITION_SHA, COMMIT)
    for ordinal, agent in enumerate(value["agents"], 1):
        name = agent["pin"]["id"]
        agent["runtime"] = {
            "implementation": "AUTHORED Java VM", "version": "AUTHORED-1", "os": "AUTHORED OS",
            "architecture": "AUTHORED-arch",
            "containmentPolicy": {"id": "AUTHORED-containment", "version": "AUTHORED-1", "sha256": "1" * 64},
        }
        agent["providerPolicy"] = {
            "id": "AUTHORED-provider", "version": "AUTHORED-1", "sha256": "2" * 64, "mode": "brokered",
        }
        artifact_id = name + "-authored"
        for result in agent["results"]:
            result.update(outcome="PASS", artifact=artifact_id)
        payload = b"AUTHORED metadata only; no execution evidence"
        value["artifacts"].append({
            "id": artifact_id, "agentId": name, "cases": list(MANIFEST.CASE_IDS),
            "scope": "positive-required-case", "sourceCommit": COMMIT,
            "contextSha256": MANIFEST.context_digest(value, agent), "repository": "authored/fixtures",
            "runId": ordinal, "runAttempt": 1, "artifactId": ordinal + 100,
            "bytes": len(payload), "sha256": MANIFEST.sha256(payload),
        })
    return value


class RequiredCaseManifestControls(unittest.TestCase):
    def inspect(self, value, commit=COMMIT):
        return MANIFEST.inspect_bindings(DEFINITION, DEFINITION_SHA, value, commit)

    def refuse(self, value):
        with self.assertRaises(ValueError):
            self.inspect(value)

    def test_authored_complete_bindings_never_grant_payload_or_release_qualification(self):
        result = self.inspect(authored_bindings())
        self.assertTrue(result["bindingsComplete"])
        self.assertEqual(20, result["positiveCaseBindings"])
        self.assertEqual([], result["blockingCases"])
        self.assertFalse(result["artifactPayloadsIndependentlyVerified"])
        self.assertFalse(result["releaseQualified"])

    def test_template_explicitly_retains_every_missing_case_and_unknown_context(self):
        value = MANIFEST.empty_bindings(DEFINITION, DEFINITION_SHA, COMMIT)
        result = self.inspect(value)
        self.assertFalse(result["bindingsComplete"])
        self.assertEqual(20, len(result["blockingCases"]))
        self.assertEqual(0, result["positiveCaseBindings"])
        self.assertTrue(all(row["outcome"] == "UNQUALIFIED" for row in result["blockingCases"]))
        self.assertTrue(all(agent["runtime"] is None and agent["providerPolicy"] is None
                            for agent in value["agents"]))

    def test_missing_duplicate_or_foreign_required_case_cannot_shrink_the_matrix(self):
        for change in ("missing", "duplicate", "foreign"):
            value = authored_bindings()
            if change == "missing":
                value["agents"][0]["results"].pop()
            else:
                value["agents"][0]["results"][-1]["caseId"] = "initialize" if change == "duplicate" else "optional"
            with self.subTest(change=change):
                self.refuse(value)

    def test_missing_duplicate_or_changed_agent_is_refused(self):
        for change in ("missing", "duplicate", "version", "archive"):
            value = authored_bindings()
            if change == "missing":
                value["agents"].pop()
            elif change == "duplicate":
                value["agents"][1] = copy.deepcopy(value["agents"][0])
            elif change == "version":
                value["agents"][0]["pin"]["version"] = "changed"
            else:
                value["agents"][0]["pin"]["archiveSha256"] = "b" * 64
            with self.subTest(change=change):
                self.refuse(value)

    def test_source_definition_and_client_sdk_protocol_drift_are_refused(self):
        for change in ("releaseCommit", "definitionSha256", "client", "sdk", "protocolVersion"):
            value = authored_bindings()
            value[change] = {"client": {"implementation": "decomp_engine", "version": "changed"},
                             "sdk": {"artifact": "changed", "reportedVersion": "changed"},
                             "protocolVersion": 2}.get(change, "b" * (40 if change == "releaseCommit" else 64))
            with self.subTest(change=change):
                self.refuse(value)

    def test_artifacts_from_another_source_or_version_context_are_refused(self):
        for change in ("sourceCommit", "contextSha256", "runtime", "providerPolicy"):
            value = authored_bindings()
            if change in ("sourceCommit", "contextSha256"):
                value["artifacts"][0][change] = "b" * (40 if change == "sourceCommit" else 64)
            else:
                value["agents"][0][change]["version"] = "changed-after-artifact"
            with self.subTest(change=change):
                self.refuse(value)

    def test_cross_agent_and_cross_case_artifact_substitution_are_refused(self):
        value = authored_bindings()
        value["agents"][0]["results"][0]["artifact"] = value["artifacts"][1]["id"]
        self.refuse(value)
        value = authored_bindings()
        value["artifacts"][0]["cases"].remove("repair")
        self.refuse(value)

    def test_missing_artifact_and_unreferenced_or_conflicting_artifact_are_refused(self):
        value = authored_bindings()
        value["artifacts"].pop()
        self.refuse(value)
        value = authored_bindings()
        artifact = copy.deepcopy(value["artifacts"][0])
        artifact["id"] = "extra"
        value["artifacts"].append(artifact)
        self.refuse(value)
        artifact["sha256"] = "b" * 64
        self.refuse(value)

    def test_immutable_artifact_location_digest_size_and_types_are_required(self):
        for field, invalid in (("artifactId", True), ("runId", 0), ("runAttempt", -1),
                               ("bytes", 0), ("bytes", 1024 ** 4 + 1), ("sha256", "short"),
                               ("sha256", "0" * 64), ("repository", "owner/repo/mutable/path")):
            value = authored_bindings()
            value["artifacts"][0][field] = invalid
            with self.subTest(field=field, invalid=invalid):
                self.refuse(value)

    def test_credential_free_observation_or_auth_required_cannot_be_a_positive_pass(self):
        for scope in ("credential-free-initialize", "credential-free-authentication-boundary"):
            value = authored_bindings()
            value["artifacts"][0]["scope"] = scope
            with self.subTest(scope=scope):
                self.refuse(value)

    def test_negative_and_unsupported_outcomes_are_retained_and_block_completeness(self):
        for outcome in ("FAIL", "SKIP", "UNSUPPORTED", "AUTH_REQUIRED"):
            value = authored_bindings()
            value["artifacts"][0]["scope"] = "negative-required-case"
            for result in value["agents"][0]["results"]:
                result["outcome"] = outcome
            report = self.inspect(value)
            with self.subTest(outcome=outcome):
                self.assertFalse(report["bindingsComplete"])
                self.assertEqual(10, report["positiveCaseBindings"])
                self.assertEqual({outcome}, {row["outcome"] for row in report["blockingCases"]})

    def test_credential_free_observations_retain_only_their_actual_boundary_scope(self):
        value = authored_bindings()
        covered = {"initialize", "advertised-capabilities", "clean-shutdown"}
        artifact = value["artifacts"][0]
        artifact.update(scope="credential-free-initialize", cases=sorted(covered))
        for result in value["agents"][0]["results"]:
            result["outcome"] = "OBSERVED" if result["caseId"] in covered else "UNQUALIFIED"
            if result["caseId"] not in covered:
                result["artifact"] = None
        report = self.inspect(value)
        self.assertFalse(report["bindingsComplete"])
        self.assertEqual(10, report["positiveCaseBindings"])
        self.assertEqual(3, sum(row["outcome"] == "OBSERVED" for row in report["blockingCases"]))
        artifact["cases"].append("repair")
        self.refuse(value)

    def test_expected_source_and_definition_trust_anchors_cannot_be_branch_names_or_placeholders(self):
        for commit in ("master", "HEAD", "a" * 39, "0" * 40):
            with self.subTest(commit=commit):
                with self.assertRaises(ValueError):
                    self.inspect(authored_bindings(), commit=commit)
        with self.assertRaises(ValueError):
            MANIFEST.inspect_bindings(DEFINITION, "b" * 64, authored_bindings(), COMMIT)

    def test_typed_authentication_boundary_is_retained_without_a_successful_session_binding(self):
        value = authored_bindings()
        covered = {"initialize", "advertised-capabilities", "clean-shutdown", "session-creation"}
        agent = value["agents"][0]
        agent["providerPolicy"]["mode"] = "credential-free"
        artifact = value["artifacts"][0]
        artifact.update(scope="credential-free-authentication-boundary", cases=sorted(covered),
                        contextSha256=MANIFEST.context_digest(value, agent))
        for result in agent["results"]:
            result["outcome"] = ("AUTH_REQUIRED" if result["caseId"] == "session-creation" else
                                 "OBSERVED" if result["caseId"] in covered else "UNQUALIFIED")
            if result["caseId"] not in covered:
                result["artifact"] = None
        report = self.inspect(value)
        self.assertEqual(10, report["positiveCaseBindings"])
        self.assertEqual([{"agentId": "goose", "caseId": "session-creation", "outcome": "AUTH_REQUIRED"}],
                         [row for row in report["blockingCases"] if row["outcome"] == "AUTH_REQUIRED"])
        next(row for row in agent["results"] if row["caseId"] == "session-creation")["outcome"] = "PASS"
        self.refuse(value)

    def test_missing_context_and_unavailable_or_credential_free_provider_cannot_pass(self):
        for field in ("runtime", "providerPolicy"):
            value = authored_bindings()
            value["agents"][0][field] = None
            value["artifacts"][0]["contextSha256"] = MANIFEST.context_digest(value, value["agents"][0])
            self.refuse(value)
        for mode in ("unavailable", "credential-free"):
            value = authored_bindings()
            value["agents"][0]["providerPolicy"]["mode"] = mode
            value["artifacts"][0]["contextSha256"] = MANIFEST.context_digest(value, value["agents"][0])
            self.refuse(value)

    def test_failed_boundary_with_unknown_runtime_and_policy_is_retained_as_incomplete(self):
        value = authored_bindings()
        agent = value["agents"][0]
        agent.update(runtime=None, providerPolicy=None)
        for result in agent["results"]:
            result["outcome"] = "FAIL"
        value["artifacts"][0].update(scope="negative-required-case",
                                    contextSha256=MANIFEST.context_digest(value, agent))
        report = self.inspect(value)
        self.assertFalse(report["bindingsComplete"])
        self.assertEqual(["goose"], report["agentsWithIncompleteVersionContext"])
        self.assertEqual(10, sum(row["outcome"] == "FAIL" for row in report["blockingCases"]))
        self.assertFalse(report["releaseQualified"])

    def test_reordering_does_not_change_binding_identity(self):
        value = authored_bindings()
        value["agents"].reverse()
        value["artifacts"].reverse()
        for agent in value["agents"]:
            agent["results"].reverse()
        self.assertTrue(self.inspect(value)["bindingsComplete"])

    def test_unknown_fields_schema_and_boolean_integer_versions_are_refused(self):
        for field, invalid in (("schemaVersion", 2), ("schemaVersion", True), ("protocolVersion", True),
                               ("releaseQualified", True)):
            value = authored_bindings()
            value[field] = invalid
            with self.subTest(field=field, invalid=invalid):
                self.refuse(value)

    def test_definition_cannot_drop_a_required_case_agent_or_stable_protocol(self):
        for field in ("requiredCases", "agents", "protocolVersion"):
            value = copy.deepcopy(DEFINITION)
            if field == "protocolVersion":
                value[field] = 2
            else:
                value[field].pop()
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    MANIFEST.validate_definition(value)

    def test_duplicate_json_nonfinite_invalid_and_oversized_inputs_are_refused(self):
        for payload in (b'{"same":1,"same":2}', b'{"value":NaN}', b'{"value":Infinity}', b'{',
                        b'\xff', b' ' * (MANIFEST.MAX_JSON_BYTES + 1)):
            with self.subTest(payloadBytes=len(payload)):
                with self.assertRaises(ValueError):
                    MANIFEST.parse_json(payload)


if __name__ == "__main__":
    unittest.main()
