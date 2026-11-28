"""Closed GCC reference invocation declarations, separate from candidate qualification.

The reviewed reference digest is an independent profile input. A proposed
contract cannot choose its reference or repair a modified reference by rehashing
it. Updating that digest requires a new reviewed real reference capture.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "oracle/gcc/16.2.0"
REFERENCE_NAME = "orchestration-phase-reference.json"
CONTRACT_NAME = "orchestration-identity-contract.json"
# Original-driver capture and independent live replay qualified these exact bytes.
REVIEWED_REFERENCE_SHA256 = "41768c5ff120e4f749d02859437b122c223e2cfaea44151c044aeaf5c3bf24d1"
MANIFEST_PINS = {
    "oracle-manifest.json": "c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9",
    "cc1-oracle-manifest.json": "dbef520c025d268f5126229ace8ad5b08a15722573d45b5e1ab934611905abb4",
}
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_NODES = 200_000
MAX_DEPTH = 48
PHASE_ROLES = {"preprocess": "compile", "compile": "compile", "assemble": "assemble", "link": "link"}


class ContractError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()


def _read(path: Path) -> bytes:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ContractError(f"expected a regular unlinked document: {path}")
    with path.open("rb") as source:
        payload = source.read(MAX_DOCUMENT_BYTES + 1)
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise ContractError(f"document exceeds byte bound: {path}")
    return payload


def _json(payload: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ContractError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid(value):
        raise ContractError(f"non-finite JSON value: {value}")

    try:
        result = json.loads(payload, object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ContractError(f"invalid JSON document: {error}") from error
    if not isinstance(result, dict):
        raise ContractError("document root must be an object")
    stack = [(result, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise ContractError("JSON structure exceeds bounds")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
    return result


def _profile_member(profile: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if relative.is_absolute() or relative.as_posix() != name or ".." in relative.parts:
        raise ContractError(f"noncanonical profile path: {name}")
    path = profile / name
    if path.resolve().parent != profile.resolve():
        raise ContractError(f"profile document escapes its directory: {name}")
    return path


def _authority(profile: Path, name: str) -> tuple[dict, dict]:
    payload = _read(_profile_member(profile, name))
    if sha256(payload) != MANIFEST_PINS[name]:
        raise ContractError(f"manifest differs from reviewed identity: {name}")
    manifest = _json(payload)
    inputs = {}
    for role in ("sourceLock", "buildRecord"):
        expected = manifest["inputs"][role]
        data = _read(_profile_member(profile, expected["path"]))
        if (len(data), sha256(data)) != (expected["bytes"], expected["sha256"]):
            raise ContractError(f"manifest input changed: {expected['path']}")
        inputs[role] = dict(expected)
    return manifest, {"path": name, "bytes": len(payload), "sha256": sha256(payload), "inputs": inputs}


def _source_policy() -> tuple[dict, dict]:
    # Execute one immutable snapshot of repository-owned definitions, never caller code.
    path = ROOT / "scripts/capture-gcc-preprocessing-reference.py"
    payload = _read(path)
    namespace = {"__file__": str(path), "__name__": "gcc_reference_policy_definitions"}
    exec(compile(payload, str(path), "exec"), namespace)
    return namespace, {"path": path.relative_to(ROOT).as_posix(), "bytes": len(payload), "sha256": sha256(payload)}


def _stream(value: dict) -> bytes:
    try:
        payload = base64.b64decode(value["base64"], validate=True)
    except (KeyError, ValueError) as error:
        raise ContractError("invalid retained stream") from error
    if (len(payload), sha256(payload)) != (value.get("bytes"), value.get("sha256")):
        raise ContractError("retained stream identity does not match its bytes")
    if value.get("text") != payload.decode("utf-8", "backslashreplace"):
        raise ContractError("retained stream display does not match its bytes")
    return payload


def _phase_identity(phase: dict, tools: dict) -> tuple[str, dict]:
    if set(phase) != {"phase", "tool", "argv", "stdoutPipedToNextPhase"}:
        raise ContractError("phase entry does not have the closed declaration fields")
    role = PHASE_ROLES.get(phase["phase"])
    if role is None or role not in tools:
        raise ContractError("undeclared phase role")
    identity = tools[role]
    allowed = {identity["path"]}
    if "invokedAs" in identity:
        allowed.add(identity["invokedAs"])
    argv = phase["argv"]
    if (not isinstance(argv, list) or not argv or not all(isinstance(item, str) and "\x00" not in item for item in argv)
            or phase["tool"] != argv[0] or argv[0] not in allowed
            or type(phase["stdoutPipedToNextPhase"]) is not bool):
        raise ContractError("undeclared phase path or invalid argument vector")
    return role, identity


def verbose_arguments(planned: dict) -> list[str]:
    """Admit only GCC's positional verbosity additions, not arbitrary flag removal."""
    argv = list(planned["argv"])
    phase = planned["phase"]
    if phase == "assemble":
        argv.insert(1, "-v")
    elif phase in {"compile", "preprocess"}:
        if "-fpreprocessed" not in argv:
            if "-quiet" not in argv:
                raise ContractError("compiler plan lacks its required quiet marker")
            argv.insert(argv.index("-quiet") + 1, "-v")
        if phase == "compile":
            if "-o" not in argv:
                raise ContractError("compiler plan lacks its required output argument")
            argv.insert(argv.index("-o"), "-version")
    elif phase != "link":
        raise ContractError("undeclared verbosity equivalence role")
    return argv


def validate_phase_arguments(planned: list[dict], traced: list[dict], phase_tools: dict, *, failed: bool) -> None:
    """Check transcript coherence; only verify_contract admits a closed reviewed case."""
    if not planned or not traced or len(traced) > len(planned):
        raise ContractError("phase trace must be a nonempty planned prefix")
    if not failed and len(traced) != len(planned):
        raise ContractError("successful reference omitted a planned phase")
    for phase in [*planned, *traced]:
        _phase_identity(phase, phase_tools)
    for expected, observed in zip(planned, traced):
        if (observed["phase"], observed["tool"], observed["stdoutPipedToNextPhase"]) != (
                expected["phase"], expected["tool"], expected["stdoutPipedToNextPhase"]):
            raise ContractError("phase trace changed the planned role, tool or pipe edge")
        if observed["argv"] != verbose_arguments(expected):
            raise ContractError("phase trace arguments differ outside positional verbosity additions")


def _parse_phases(payload: bytes, tools: dict, *, strict: bool) -> list[dict]:
    known = {}
    for role in ("compile", "assemble", "link"):
        entry = tools[role]
        known[entry["path"]] = role
        if "invokedAs" in entry:
            known[entry["invokedAs"]] = role
    result = []
    for line in payload.decode("utf-8", "backslashreplace").splitlines():
        if not line.startswith(" ") or not line.strip():
            continue
        piped = line.endswith(" |")
        try:
            argv = shlex.split(line[:-2] if piped else line)
        except ValueError as error:
            if strict:
                raise ContractError("unparseable reference plan") from error
            continue
        if not argv or argv[0] not in known:
            if strict:
                raise ContractError("undeclared command in reference plan")
            continue
        role = known[argv[0]]
        phase = "preprocess" if role == "compile" and "-E" in argv else role
        result.append({"phase": phase, "tool": argv[0], "argv": argv, "stdoutPipedToNextPhase": piped})
    return result


def _runtime(closure: dict, identity: dict) -> None:
    elf = closure["elf"]
    for key in ("path", "sha256"):
        if elf[key] != identity[key]:
            raise ContractError("startup closure does not bind its declared executable")
    if "bytes" in identity and elf["bytes"] != identity["bytes"]:
        raise ContractError("startup closure executable size differs")
    libraries = closure["libraries"]
    names = [entry["name"] for entry in libraries]
    if len(names) != len(set(names)) or not set(closure["needed"]).issubset(names):
        raise ContractError("startup closure is missing or duplicates a needed library")
    for entry in [elf, *libraries, *([closure["interpreter"]] if closure["interpreter"] else [])]:
        if (type(entry["bytes"]) is not int or entry["bytes"] <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
            raise ContractError("invalid startup dependency identity")


def _generate(profile: Path, reference_payload: bytes) -> dict:
    if sha256(reference_payload) != REVIEWED_REFERENCE_SHA256:
        raise ContractError("reference differs from the independently reviewed capture digest")
    reference = _json(reference_payload)
    source, source_identity = _source_policy()
    probe_path = ROOT / "oracle/gcc/reference_runtime_probe.py"
    probe_payload = _read(probe_path)
    probe_identity = {"path": probe_path.relative_to(ROOT).as_posix(), "sha256": sha256(probe_payload)}
    if reference["referenceInvocationPolicy"]["runtimeProbe"] != probe_identity:
        raise ContractError("runtime probe source differs from the captured probe")
    driver, driver_authority = _authority(profile, "oracle-manifest.json")
    frontend, frontend_authority = _authority(profile, "cc1-oracle-manifest.json")
    if driver["oracle"] != frontend["oracle"] or driver["inputs"]["sourceLock"] != frontend["inputs"]["sourceLock"]:
        raise ContractError("driver and frontend source identities differ")
    toolchain = reference["toolchain"]
    for name, expected in (("image", source["IMAGE"]), ("imageConfig", source["IMAGE_CONFIG"]), ("platform", "linux/amd64")):
        if toolchain[name] != expected:
            raise ContractError(f"reference runtime changed: {name}")
    identities = toolchain["phaseTools"]
    if set(identities) != {"compile", "assemble", "link", "linkEditor", "ltoWrapper", "ltoPlugin"}:
        raise ContractError("phase tool membership differs from the closed profile")
    if toolchain["target"] != "x86_64-pc-linux-gnu" or toolchain["version"] != driver["oracle"]["version"]:
        raise ContractError("reference compiler configuration differs from the original oracle")
    driver_identity = toolchain["driver"]
    for identity, manifest, path in ((driver_identity, driver, source["ORACLE_DRIVER_PATH"]),
                                    (identities["compile"], frontend, source["ORACLE_FRONTEND_PATH"])):
        expected = manifest["artifacts"]["stripped"]
        if identity["path"] != path or identity["sha256"] != expected["sha256"]:
            raise ContractError("reference does not use the original manifest-pinned driver/frontend")
        if identity.get("bytes", expected["bytes"]) != expected["bytes"]:
            raise ContractError("reference tool size differs from its manifest")
    for role, manifest, name in (("oracleDriver", driver, "oracle-manifest.json"),
                                 ("oracleFrontend", frontend, "cc1-oracle-manifest.json")):
        identity = reference[role]
        expected = manifest["artifacts"]["stripped"]
        if (identity["bytes"], identity["sha256"], identity["artifact"]) != (
                expected["bytes"], expected["sha256"], f"oracle/gcc/16.2.0/{expected['path']}"):
            raise ContractError("original tool provenance differs from its manifest")
        if identity["manifest"] != {"path": f"oracle/gcc/16.2.0/{name}", "sha256": MANIFEST_PINS[name]}:
            raise ContractError("original tool provenance names an unbound manifest")
    frontend_provenance = reference["oracleFrontend"]
    if frontend_provenance["source"] != driver["oracle"] or frontend_provenance["sourceLock"] != driver["inputs"]["sourceLock"]:
        raise ContractError("original frontend provenance changes its source identity")
    archive_payload = _read(profile / "artifacts/gcc-cc1.stripped.xz")
    if frontend_provenance["archive"] != {
            "path": "oracle/gcc/16.2.0/artifacts/gcc-cc1.stripped.xz",
            "bytes": len(archive_payload), "sha256": sha256(archive_payload)}:
        raise ContractError("original frontend archive differs from the captured input")
    declared = [driver_identity, *identities.values()]
    runtime = toolchain["runtimeClosure"]
    if set(runtime) != {entry["path"] for entry in declared}:
        raise ContractError("phase startup closure membership differs from tool declarations")
    for identity in declared:
        _runtime(runtime[identity["path"]], identity)
    specs = source["ORCHESTRATION_CASES"]
    cases = reference["cases"]
    if [case["id"] for case in cases] != [spec["id"] for spec in specs]:
        raise ContractError("case membership or order differs from the closed source policy")
    environment = {**source["ENVIRONMENT"], **source["ORCHESTRATION_ENVIRONMENT"]}
    results = []
    for spec, case in zip(specs, cases):
        inputs = [{"path": path, "bytes": len(data), "sha256": sha256(data)}
                  for path, data in sorted(spec["inputs"].items())]
        if case["arguments"] != spec["arguments"] or case["environment"] != environment or case["inputs"] != inputs:
            raise ContractError(f"case input, environment or arguments changed: {case['id']}")
        if case["repetitions"] != 2 or case["normalizations"] != ["temporary-file-names"]:
            raise ContractError("reference repetition or normalization policy changed")
        observed = case["observed"]
        plan, trace, execution = (observed[name] for name in ("plan", "executedPhases", "execution"))
        failed = "failure-propagation" in spec["categories"]
        if plan["exitCode"] != 0 or trace["exitCode"] != execution["exitCode"] or (execution["exitCode"] != 0) != failed:
            raise ContractError("reference phase results do not match the fixed success/failure case")
        planned = _parse_phases(_stream(plan["stderr"]), identities, strict=True)
        traced = _parse_phases(_stream(trace["stderr"]), identities, strict=False)
        if planned != plan["phases"] or traced != trace["phases"] or trace["stderrSha256"] != trace["stderr"]["sha256"]:
            raise ContractError("structured phases differ from retained command transcripts")
        validate_phase_arguments(planned, traced, identities, failed=failed)
        for stream in (execution["stdout"], execution["stderr"], *execution["artifacts"]):
            _stream(stream)
        modes = {}
        for name, phases in (("planned", planned), ("verbose", traced)):
            modes[name] = [{**phase, "index": index, "toolSha256": _phase_identity(phase, identities)[1]["sha256"]}
                           for index, phase in enumerate(phases)]
        item = {"id": case["id"], "driverInvocation": {
            "argv": [source["ORACLE_DRIVER_PATH"], *spec["arguments"]], "cwd": source["WORKDIR"],
            "environment": environment, "inputs": inputs,
        }, "phaseInvocations": modes,
            "referenceObservationSha256": sha256(canonical(observed))}
        if spec["program"]:
            program = observed["programBehavior"]
            path = f"{source['WORKDIR']}/{spec['program']}"
            if program["program"] != spec["program"] or program["invocation"] != {
                "argv": [path], "cwd": source["WORKDIR"], "environment": source["PROGRAM_ENVIRONMENT"]}:
                raise ContractError("produced-program invocation differs from the closed policy")
            artifacts = [artifact for artifact in execution["artifacts"] if artifact["path"] == spec["program"]]
            if len(artifacts) != 1:
                raise ContractError("produced executable is not uniquely bound to an output artifact")
            _runtime(program["runtime"], {"path": path, "bytes": artifacts[0]["bytes"], "sha256": artifacts[0]["sha256"]})
            _stream(program["stdout"])
            _stream(program["stderr"])
            item["producedProgram"] = {"invocation": program["invocation"], "startupDependencies": program["runtime"],
                                       "exitCode": program["exitCode"], "stdoutSha256": program["stdout"]["sha256"],
                                       "stderrSha256": program["stderr"]["sha256"]}
        elif "programBehavior" in observed:
            raise ContractError("undeclared produced-program execution")
        results.append(item)
    return {
        "schemaVersion": 2, "kind": "gcc-orchestration-identity-contract-v2", "issue": 712,
        "scope": "closed-original-driver-reference-invocations",
        "provenance": {"reference": {"path": REFERENCE_NAME, "bytes": len(reference_payload), "sha256": sha256(reference_payload)},
                       "policySource": source_identity, "runtimeProbe": probe_identity, "driverManifest": driver_authority,
                       "frontendManifest": frontend_authority, "source": driver["oracle"]},
        "runtime": {key: toolchain[key] for key in ("image", "imageConfig", "platform", "sandbox")},
        "driver": driver_identity, "phaseTools": identities, "phaseStartupDependencies": runtime,
        "invocationPolicy": {"mode": "closed", "caseOrder": [spec["id"] for spec in specs],
                             "argumentEquivalence": {
                                 "compile": "insert -v after the first -quiet unless -fpreprocessed; insert -version immediately before -o",
                                 "preprocess": "insert -v after the first -quiet",
                                 "assemble": "insert -v immediately after argv[0]",
                                 "link": "byte-identical argv", "failure": "observed phases form a nonempty prefix; successful cases include all planned phases",
                             }, "temporaryNames": reference["normalizations"]["temporary-file-names"],
                             "undeclaredCaseOrArgument": "reject"},
        "cases": results,
        "acceptanceBoundary": "This declares independently captured reference identities and equivalent required invocations. Candidate compile/assemble, linking/artifact and produced-program qualification belong to issues 713, 714 and 715; GCC verbose observations are not independent candidate execution receipts.",
    }


def generate_contract(profile: Path = PROFILE) -> dict:
    return _generate(profile, _read(_profile_member(profile, REFERENCE_NAME)))


def verify_contract(contract_path: Path | None = None, *, profile: Path = PROFILE) -> dict:
    payload = _read(contract_path or _profile_member(profile, CONTRACT_NAME))
    contract = _json(payload)
    expected = generate_contract(profile)
    if contract != expected or payload != canonical(expected):
        raise ContractError("contract differs from independently bound reference invocations")
    return contract


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the contract from the reviewed reference")
    args = parser.parse_args()
    if args.write:
        (PROFILE / CONTRACT_NAME).write_bytes(canonical(generate_contract()))
    else:
        verify_contract()
    print("GCC orchestration identity contract v2 verified")


if __name__ == "__main__":
    main()
