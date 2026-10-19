#!/usr/bin/env python3
"""Validate ACP case/version/artifact declarations; never execute or qualify agents.

The inspect and verify modes consume public metadata only. Matching declarations
do not independently establish artifact provenance, payload semantics or release
acceptance. Those remain prerequisites of the release consumer.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[3]
DEFINITION = Path(__file__).with_name("required-cases.json")
MAX_JSON_BYTES = 1024 * 1024
CASE_IDS = (
    "initialize", "advertised-capabilities", "session-creation", "prompt-streaming",
    "authorized-file-edits", "permission-handling", "cancellation", "clean-shutdown",
    "reconstruction", "repair",
)
OUTCOMES = {"PASS", "FAIL", "SKIP", "UNSUPPORTED", "AUTH_REQUIRED", "OBSERVED", "UNQUALIFIED"}
SCOPES = {"positive-required-case", "negative-required-case", "credential-free-initialize",
          "credential-free-authentication-boundary"}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def obj(value, keys, code):
    require(type(value) is dict and set(value) == set(keys.split()), code)


def token(value, code):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,159}", value), code)


def label(value, code):
    require(type(value) is str and re.fullmatch(r"[ -~]{1,160}", value) and value.strip(), code)


def integer(value, maximum, code):
    require(type(value) is int and 0 < value <= maximum, code)


def hex_value(value, length, code):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value)
            and value != "0" * length, code)


def unique_list(value, maximum, code):
    require(type(value) is list and 0 < len(value) <= maximum, code)
    require(all(type(item) is str for item in value) and len(value) == len(set(value)), code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii"))


def parse_json(data):
    require(type(data) is bytes and len(data) <= MAX_JSON_BYTES, "json-size")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "json-duplicate-key")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("json-nonfinite")

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("json-format") from error


def read_json(path):
    with path.open("rb") as source:
        raw = source.read(MAX_JSON_BYTES + 1)
    return parse_json(raw), sha256(raw)


def validate_definition(value):
    obj(value, "schemaVersion scope client sdk protocolVersion agents requiredCases", "definition-fields")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1, "definition-schema")
    require(value["scope"] == "acp-required-case-definition", "definition-scope")
    obj(value["client"], "implementation version", "client-fields")
    require(value["client"]["implementation"] == "decomp_engine", "client-implementation")
    token(value["client"]["version"], "client-version")
    obj(value["sdk"], "artifact reportedVersion", "sdk-fields")
    token(value["sdk"]["artifact"], "sdk-artifact")
    token(value["sdk"]["reportedVersion"], "sdk-reported-version")
    require(type(value["protocolVersion"]) is int and value["protocolVersion"] == 1, "stable-protocol")
    require(type(value["requiredCases"]) is list and tuple(value["requiredCases"]) == CASE_IDS,
            "required-case-inventory")
    require(type(value["agents"]) is list and len(value["agents"]) == 2, "agent-inventory")
    agents = {}
    for agent in value["agents"]:
        obj(agent, "id version archiveBytes archiveSha256", "agent-fields")
        token(agent["id"], "agent-id")
        require(agent["id"] not in agents, "duplicate-agent")
        token(agent["version"], "agent-version")
        integer(agent["archiveBytes"], 1024 ** 3, "agent-archive-bytes")
        hex_value(agent["archiveSha256"], 64, "agent-archive-sha256")
        agents[agent["id"]] = agent
    require(set(agents) == {"goose", "codex-acp"}, "required-agent-inventory")
    return agents


def check_source_pins(definition, root):
    """Read existing tracked definitions only; no harness, imports or subprocesses."""
    agents = validate_definition(definition)
    build = (root / "build.gradle.kts").read_text()
    require(re.findall(r'^version = "([^"\n]+)"$', build, re.M) == [definition["client"]["version"]],
            "client-source-drift")
    require(re.findall(r'^\s*implementation\("(com\.agentclientprotocol:acp:[^"\n]+)"\)', build, re.M)
            == [definition["sdk"]["artifact"]], "sdk-source-drift")
    golden, _ = read_json(root / "src/test/resources/acp/v1/wire-contract.json")
    require(type(golden["protocolVersion"]) is int and golden["protocolVersion"] == definition["protocolVersion"]
            and definition["sdk"]["artifact"] == "com.agentclientprotocol:acp:" + golden["sdkArtifactVersion"]
            and golden["sdkReportedVersion"] == definition["sdk"]["reportedVersion"]
            and golden["messages"]["initialize.request"]["params"]["clientInfo"] == {
                "name": definition["client"]["implementation"], "version": definition["client"]["version"]},
            "wire-source-drift")
    for name, prefix in (("goose", "GOOSE"), ("codex-acp", "CODEX_ACP")):
        source = (root / ("scripts/ci-qualify-" + name + "-acp.sh" if name == "goose"
                          else "scripts/ci-qualify-codex-acp.sh")).read_text()
        for field, suffix in (("version", "VERSION"), ("archiveBytes", "ARCHIVE_BYTES"),
                              ("archiveSha256", "ARCHIVE_SHA256")):
            matches = re.findall(r'^readonly ' + prefix + "_" + suffix + r'="([^"\n]+)"$', source, re.M)
            require(matches == [str(agents[name][field])], "agent-source-drift")


def policy(value, provider=False):
    obj(value, "id version sha256 mode" if provider else "id version sha256", "policy-fields")
    token(value["id"], "policy-id")
    token(value["version"], "policy-version")
    hex_value(value["sha256"], 64, "policy-sha256")
    if provider:
        require(value["mode"] in ("credential-free", "brokered", "unavailable"), "provider-mode")


def context_digest(manifest, agent):
    """The exact version context each retained artifact declaration must bind."""
    return canonical_digest({
        "releaseCommit": manifest["releaseCommit"], "definitionSha256": manifest["definitionSha256"],
        "client": manifest["client"], "sdk": manifest["sdk"], "protocolVersion": manifest["protocolVersion"],
        "agent": agent["pin"], "runtime": agent["runtime"], "providerPolicy": agent["providerPolicy"],
    })


def empty_bindings(definition, definition_sha256, release_commit):
    validate_definition(definition)
    hex_value(definition_sha256, 64, "expected-definition-sha256")
    hex_value(release_commit, 40, "expected-release-commit")
    return {"schemaVersion": 1, "scope": "acp-required-case-result-bindings",
            "releaseCommit": release_commit, "definitionSha256": definition_sha256,
            "client": dict(definition["client"]), "sdk": dict(definition["sdk"]),
            "protocolVersion": definition["protocolVersion"], "artifacts": [],
            "agents": [{"pin": dict(pin), "runtime": None, "providerPolicy": None,
                        "results": [{"caseId": case, "outcome": "UNQUALIFIED", "artifact": None}
                                    for case in CASE_IDS]} for pin in definition["agents"]]}


def inspect_bindings(definition, definition_sha256, manifest, release_commit):
    pins = validate_definition(definition)
    hex_value(definition_sha256, 64, "expected-definition-sha256")
    hex_value(release_commit, 40, "expected-release-commit")
    obj(manifest, "schemaVersion scope releaseCommit definitionSha256 client sdk protocolVersion agents artifacts",
        "result-fields")
    require(type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 1, "result-schema")
    require(manifest["scope"] == "acp-required-case-result-bindings", "result-scope")
    require(manifest["releaseCommit"] == release_commit, "release-commit-mismatch")
    require(manifest["definitionSha256"] == definition_sha256, "definition-digest-mismatch")
    for field in ("client", "sdk", "protocolVersion"):
        require(type(manifest[field]) is type(definition[field]) and manifest[field] == definition[field],
                "result-version-mismatch")
    require(type(manifest["agents"]) is list and len(manifest["agents"]) == len(pins), "result-agent-inventory")
    agents = {}
    for agent in manifest["agents"]:
        obj(agent, "pin runtime providerPolicy results", "result-agent-fields")
        pin = agent["pin"]
        require(type(pin) is dict and type(pin.get("id")) is str and pin["id"] in pins,
                "result-agent-pin")
        require(pin == pins[pin["id"]] and type(pin.get("archiveBytes")) is int, "result-agent-pin")
        require(pin["id"] not in agents, "result-duplicate-agent")
        if agent["runtime"] is not None:
            runtime = agent["runtime"]
            obj(runtime, "implementation version os architecture containmentPolicy", "runtime-fields")
            for field in ("implementation", "os"):
                label(runtime[field], "runtime-identity")
            for field in ("version", "architecture"):
                token(runtime[field], "runtime-identity")
            policy(runtime["containmentPolicy"])
        if agent["providerPolicy"] is not None:
            policy(agent["providerPolicy"], provider=True)
        require(type(agent["results"]) is list and len(agent["results"]) == len(CASE_IDS),
                "result-case-inventory")
        agents[pin["id"]] = agent
    require(set(agents) == set(pins), "result-agent-inventory")
    require(type(manifest["artifacts"]) is list and len(manifest["artifacts"]) <= 200, "artifact-inventory")
    artifacts = {}
    physical = {}
    for artifact in manifest["artifacts"]:
        obj(artifact, "id agentId cases scope sourceCommit contextSha256 repository runId runAttempt artifactId bytes sha256",
            "artifact-fields")
        token(artifact["id"], "artifact-id")
        require(artifact["id"] not in artifacts, "duplicate-artifact")
        require(type(artifact["agentId"]) is str and artifact["agentId"] in agents, "artifact-agent")
        unique_list(artifact["cases"], len(CASE_IDS), "artifact-cases")
        require(set(artifact["cases"]) <= set(CASE_IDS), "artifact-cases")
        require(type(artifact["scope"]) is str and artifact["scope"] in SCOPES, "artifact-scope")
        if artifact["scope"].startswith("credential-free-"):
            provider = agents[artifact["agentId"]]["providerPolicy"]
            require(provider is None or provider["mode"] == "credential-free", "credential-free-provider-policy")
            covered = {"initialize", "advertised-capabilities", "clean-shutdown"}
            if artifact["scope"] == "credential-free-authentication-boundary":
                covered.add("session-creation")
            require(set(artifact["cases"]) <= covered, "credential-free-case-scope")
        require(artifact["sourceCommit"] == release_commit, "artifact-source-mismatch")
        require(artifact["contextSha256"] == context_digest(manifest, agents[artifact["agentId"]]),
                "artifact-context-mismatch")
        require(type(artifact["repository"]) is str and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", artifact["repository"]),
            "artifact-repository")
        for field in ("runId", "artifactId"):
            integer(artifact[field], 2 ** 63 - 1, "artifact-location")
        integer(artifact["runAttempt"], 2 ** 31 - 1, "artifact-attempt")
        integer(artifact["bytes"], 1024 ** 4, "artifact-bytes")
        hex_value(artifact["sha256"], 64, "artifact-sha256")
        location = (artifact["repository"].lower(), artifact["artifactId"])
        binding = {k: v for k, v in artifact.items() if k != "id"}
        require(location not in physical or physical[location] == binding, "conflicting-physical-artifact")
        physical[location] = binding
        artifacts[artifact["id"]] = artifact
    blocking = []
    referenced = set()
    coverage = {}
    for name, agent in agents.items():
        cases = set()
        for result in agent["results"]:
            obj(result, "caseId outcome artifact", "case-result-fields")
            case_id = result["caseId"]
            require(type(case_id) is str and case_id in CASE_IDS and case_id not in cases,
                    "duplicate-or-unknown-case")
            cases.add(case_id)
            outcome = result["outcome"]
            require(type(outcome) is str and outcome in OUTCOMES, "case-outcome")
            if outcome == "UNQUALIFIED":
                require(result["artifact"] is None, "unqualified-artifact")
            else:
                ref = result["artifact"]
                require(type(ref) is str and ref in artifacts, "missing-artifact-binding")
                artifact = artifacts[ref]
                require(artifact["agentId"] == name and case_id in artifact["cases"], "cross-case-artifact")
                referenced.add(ref)
                coverage.setdefault(ref, set()).add(case_id)
                if outcome == "PASS":
                    require(agent["runtime"] is not None and agent["providerPolicy"] is not None,
                            "missing-version-context")
                    require(artifact["scope"] == "positive-required-case"
                            and agent["providerPolicy"]["mode"] == "brokered", "nonpositive-required-pass")
                elif outcome == "OBSERVED":
                    require(artifact["scope"] in ("credential-free-initialize", "credential-free-authentication-boundary"),
                            "observation-scope")
                elif outcome == "AUTH_REQUIRED":
                    require(artifact["scope"] in ("credential-free-authentication-boundary", "negative-required-case"),
                            "authentication-required-scope")
                else:
                    require(artifact["scope"] != "positive-required-case", "negative-result-scope")
            if outcome != "PASS":
                blocking.append({"agentId": name, "caseId": case_id, "outcome": outcome})
        require(cases == set(CASE_IDS), "result-case-inventory")
    require(referenced == set(artifacts), "unreferenced-artifact")
    require(all(coverage[ref] == set(artifact["cases"]) for ref, artifact in artifacts.items()),
            "artifact-case-coverage-mismatch")
    return {"schemaVersion": 1, "scope": "acp-required-case-binding-inspection", "releaseCommit": release_commit,
            "definitionSha256": definition_sha256, "requiredCases": len(pins) * len(CASE_IDS),
            "positiveCaseBindings": len(pins) * len(CASE_IDS) - len(blocking), "blockingCases": blocking,
            "bindingsComplete": not blocking, "artifactDeclarations": len(artifacts),
            "agentsWithIncompleteVersionContext": [name for name, agent in agents.items()
                if agent["runtime"] is None or agent["providerPolicy"] is None],
            "artifactPayloadsIndependentlyVerified": False, "releaseQualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("definition", "template", "inspect", "verify"))
    parser.add_argument("--definition", type=Path, default=DEFINITION)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--release-commit")
    parser.add_argument("--definition-sha256", help="Expected definition digest from the release consumer")
    args = parser.parse_args()
    try:
        definition, digest = read_json(args.definition)
        if args.mode == "definition":
            require(args.manifest is None and args.release_commit is None and args.definition_sha256 is None,
                    "definition-arguments")
            check_source_pins(definition, ROOT)
            print(json.dumps({"definitionValid": True, "definitionSha256": digest,
                              "requiredCases": 20, "releaseQualified": False}))
            return 0
        if args.mode == "template":
            require(args.manifest is None and args.release_commit is not None and args.definition_sha256 is None,
                    "template-arguments")
            print(json.dumps(empty_bindings(definition, digest, args.release_commit), indent=2))
            return 0
        require(args.manifest is not None and args.release_commit is not None
                and args.definition_sha256 is not None, "result-arguments")
        require(args.definition_sha256 == digest, "expected-definition-digest-mismatch")
        manifest, _ = read_json(args.manifest)
        result = inspect_bindings(definition, args.definition_sha256, manifest, args.release_commit)
        print(json.dumps(result, sort_keys=True))
        return 0 if args.mode == "inspect" or result["bindingsComplete"] else 1
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        # Do not print metadata values, paths, exception chains or credential-shaped input.
        print("ACP manifest invalid; no qualification granted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
