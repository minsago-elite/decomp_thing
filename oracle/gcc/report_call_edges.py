#!/usr/bin/env python3
"""Score GCC stripped-twin call edges against a bound recovered model.

The oracle edges are unique (caller, callee) function-start pairs derived from
the DWARF call-site entries of the authenticated full twin.  A direct call site
names its callee definition; a cross-unit call site names a declaration, which
is resolved through the oracle alias table only when exactly one oracle
function carries that name.  Indirect, virtual, ambiguous and unresolved sites
contribute no edge and are counted.  Both endpoints of an oracle edge must be
scoreable oracle functions; tail calls are retained and marked.

Recovered edges come from the ``calls`` lists of the bound stripped program
model. Every edge with scoreable endpoints stays in the precision denominator.
A matching positive is observable even for a partial caller. An unmatched edge
is proven fabricated only when DWARF declares complete emitted-call coverage
and every possibly relevant target was resolved; otherwise it remains unknown.
Precision is an interval when unknowns remain, never an exact passing score.
All excluded edges and per-caller negative-authority limitations are retained.
Nothing here admits the model for release scoring.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import gc
import hashlib
import io
import json
from pathlib import Path
import sys
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

import elftools  # noqa: E402
from elftools.dwarf.descriptions import describe_form_class  # noqa: E402
from elftools.dwarf.ranges import BaseAddressEntry, RangeEntry  # noqa: E402
from elftools.elf.elffile import ELFFile  # noqa: E402

from oracle.full_tree_call_observations import (  # noqa: E402
    _address,
    _parent_subprogram,
    _target,
)
from oracle.function_recovery import MAX_MANIFEST_BYTES, MAX_REPORT_BYTES  # noqa: E402
from oracle.function_recovery_oracle import (  # noqa: E402
    _attribute_chain,
    _dwarf_starts,
    _in_executable_range,
)
from oracle.gcc.bound_recovered_model import (  # noqa: E402
    TWIN,
    BoundStrippedModel,
    load_bound_stripped_model,
)
from oracle.gcc.report_accuracy_coverage import (  # noqa: E402
    CoverageError,
    _json_snapshot,
    _ratio,
    _read_regular,
    _required_mapping,
    _write_json,
)


REPORT_ID = "gcc-driver-call-edge-score-v2"
PYELFTOOLS_VERSION = "0.33"
CALL_SITE_TAGS = ("DW_TAG_call_site", "DW_TAG_GNU_call_site")
FUNCTION_ID_PREFIX = "function-rva-"
MODEL_ID_PREFIX = "fn_"


def _full_artifact(
    profile_directory: Path, expected_manifest_sha256: str
) -> tuple[bytes, str]:
    manifest, manifest_record = _json_snapshot(
        profile_directory / "oracle-manifest.json", "oracle artifact manifest", MAX_MANIFEST_BYTES
    )
    if manifest_record["sha256"] != expected_manifest_sha256:
        raise CoverageError("oracle artifact manifest changed after model binding")
    record = _required_mapping(
        _required_mapping(manifest.get("artifacts"), "manifest.artifacts").get("full"),
        "manifest.artifacts.full",
    )
    relative = record.get("path")
    if not isinstance(relative, str):
        raise CoverageError("manifest.artifacts.full.path must be a string")
    payload = _read_regular(profile_directory / relative, "full artifact", record["bytes"])
    digest = hashlib.sha256(payload).hexdigest()
    if digest != record.get("sha256"):
        raise CoverageError("full artifact disagrees with the manifest")
    # Callers parse these verified bytes; the path is never reopened.
    return payload, digest


@dataclass(frozen=True)
class OracleCallPopulation:
    edges: dict[tuple[int, int], set[bool]]
    callers_with_sites: set[int]
    kinds: Counter[str]
    caller_coverage: dict[int, dict[str, Any]]


def _complete_call_coverage(die: Any) -> tuple[str, ...]:
    # DWARF 5 section 3.3.1.3 certifies calls in the emitted subprogram. Do not
    # promote flags on abstract origins/specifications into evidence about this
    # concrete DIE's call-site children. Tail-only coverage is insufficient.
    return tuple(name for name in (
        "DW_AT_call_all_calls", "DW_AT_call_all_source_calls",
        "DW_AT_GNU_all_call_sites", "DW_AT_GNU_all_source_call_sites",
    ) if name in die.attributes and bool(die.attributes[name].value))


def _oracle_edges(
    full_payload: bytes, oracle: Any, scoreable: set[int], excluded: set[int]
) -> OracleCallPopulation:
    candidates: dict[str, set[int]] = {}
    for function in oracle.functions:
        if function.rva is None:
            continue
        for alias in function.aliases:
            candidates.setdefault(alias.name, set()).add(function.rva)
    unique_alias = {
        name: next(iter(rvas)) for name, rvas in candidates.items() if len(rvas) == 1
    }
    # The oracle population depends on the DWARF decoder, so it is pinned to the
    # version the retained report was produced with.
    if getattr(elftools, "__version__", None) != PYELFTOOLS_VERSION:
        raise CoverageError(f"call edge oracle requires pyelftools {PYELFTOOLS_VERSION}")
    edges: dict[tuple[int, int], set[bool]] = {}
    callers_with_sites: set[int] = set()
    kinds: Counter[str] = Counter()
    coverage_flags: dict[int, set[str]] = {}
    inherited_flags: dict[int, set[str]] = {}
    incomplete_callers: set[int] = set()
    unresolved_sites: dict[int, Counter[str]] = {}
    helpers = (BaseAddressEntry, RangeEntry, describe_form_class)
    with io.BytesIO(full_payload) as stream:
        elf = ELFFile(stream)
        dwarf = elf.get_dwarf_info(follow_links=False)
        loads = [
            segment
            for segment in elf.iter_segments()
            if segment["p_type"] == "PT_LOAD" and int(segment["p_memsz"]) > 0
        ]
        image_base = min(int(segment["p_vaddr"]) for segment in loads)
        executable = tuple(
            sorted(
                (
                    int(segment["p_vaddr"]) - image_base,
                    int(segment["p_vaddr"]) + int(segment["p_memsz"]) - image_base,
                )
                for segment in loads
                if int(segment["p_flags"]) & 1
            )
        )
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    starts = [start - image_base for start in _dwarf_starts(die, dwarf, *helpers)
                              if _in_executable_range(start, image_base, executable)]
                    flags = _complete_call_coverage(die) if starts else ()
                    inherited = {flag for source in _attribute_chain(die)[1:]
                                 for flag in _complete_call_coverage(source)} if starts else set()
                    for start in starts:
                        if start not in scoreable:
                            continue
                        coverage_flags.setdefault(start, set()).update(flags)
                        inherited_flags.setdefault(start, set()).update(inherited)
                        if not flags:
                            incomplete_callers.add(start)
                    continue
                if die.tag not in CALL_SITE_TAGS:
                    continue
                attributes = die.attributes
                caller_die = _parent_subprogram(die)
                starts = (
                    [] if caller_die is None else [
                        start - image_base for start in _dwarf_starts(caller_die, dwarf, *helpers)
                        if _in_executable_range(start, image_base, executable)
                    ]
                )
                pc = (attributes.get("DW_AT_call_return_pc")
                      or attributes.get("DW_AT_call_pc") or attributes.get("DW_AT_low_pc"))
                address = None if pc is None else _address(pc, dwarf, unit)
                if address is None or not _in_executable_range(address, image_base, executable):
                    kinds["call-site-no-address"] += 1
                    for start in starts:
                        if start in scoreable:
                            unresolved_sites.setdefault(start, Counter())["unlocated-call-site"] += 1
                    continue
                rva = address - image_base
                caller = max((start for start in starts if start <= rva), default=None)
                if caller is None:
                    kinds["caller-no-emitted-range"] += 1
                    continue
                if caller in scoreable:
                    callers_with_sites.add(caller)
                target = _target(die, dwarf, image_base, executable, helpers)
                kind = target["kind"]
                if kind == "external-unresolved":
                    hits = {
                        unique_alias[name]
                        for name in target["aliases"]
                        if name in unique_alias
                    }
                    if len(hits) == 1:
                        kind = "external-resolved-by-name"
                        target = {
                            "kind": "direct-internal",
                            "functionId": f"{FUNCTION_ID_PREFIX}{hits.pop():#x}",
                        }
                    elif hits:
                        kind = "external-ambiguous-name"
                kinds[kind] += 1
                if target["kind"] != "direct-internal":
                    if caller in scoreable:
                        unresolved_sites.setdefault(caller, Counter())[kind] += 1
                    continue
                callee = int(target["functionId"][len(FUNCTION_ID_PREFIX) :], 16)
                if caller not in scoreable:
                    kinds["caller-excluded" if caller in excluded else "caller-not-oracle"] += 1
                    continue
                if callee not in scoreable:
                    kinds["callee-excluded" if callee in excluded else "callee-not-oracle"] += 1
                    continue
                tail = attributes.get("DW_AT_call_tail_call")
                edges.setdefault((caller, callee), set()).add(
                    bool(tail is not None and tail.value)
                )
            # Each unit's DIE trees are dropped before the next is parsed.
            dwarf._cu_cache.clear()
            dwarf._cu_offsets_map.clear()
            dwarf._linetable_cache.clear()
            gc.collect()
    coverage: dict[int, dict[str, Any]] = {}
    for caller in sorted(scoreable):
        flags = sorted(coverage_flags.get(caller, set()))
        complete = bool(flags) and caller not in incomplete_callers
        unresolved = dict(sorted(unresolved_sites.get(caller, {}).items()))
        reasons = []
        if not complete:
            reasons.append("complete-emitted-call-coverage-unproven")
        if unresolved:
            reasons.append("unresolved-or-unlocated-call-targets")
        coverage[caller] = {
            "callerRva": hex(caller),
            "completenessAttributes": flags,
            "inheritedCompletenessAttributes": sorted(inherited_flags.get(caller, set())),
            "completeEmittedCallCoverage": complete,
            "hasLocatedCallSites": caller in callers_with_sites,
            "unresolvedSiteKinds": unresolved,
            "negativeEvidenceComplete": complete and not unresolved,
            "limitationReasons": reasons,
        }
    return OracleCallPopulation(edges, callers_with_sites, kinds, coverage)


@dataclass(frozen=True)
class ScoredReport:
    report: dict[str, Any]
    evidence: dict[str, Any]


def _recovered_edges(
    program_model_path: Path, bound: BoundStrippedModel
) -> set[tuple[int, int]]:
    # The boundary projection does not retain calls. Reopen only within the
    # verified byte budget, and require this snapshot to match that projection.
    model, record = _json_snapshot(
        program_model_path, "program model", bound.model_record["bytes"]
    )
    if record != bound.model_record:
        raise CoverageError("program model changed after it was bound")
    functions = model.get("functions")
    if not isinstance(functions, list) or len(functions) != len(bound.model.functions):
        raise CoverageError("program model function list disagrees with the bound model")
    rvas = {function.identifier: function.rva for function in bound.model.functions}
    edges: set[tuple[int, int]] = set()
    try:
        for function in functions:
            caller = rvas[function["id"]]
            for callee in function.get("calls", []):
                # Known identifiers resolve through validated addresses, not
                # through an assumed address embedded in the identifier.
                target = rvas.get(callee)
                if target is None:
                    if not callee.startswith(MODEL_ID_PREFIX):
                        raise ValueError("unresolved callee has no address identifier")
                    target = int(callee[len(MODEL_ID_PREFIX):], 16) - bound.model.image_base
                edges.add((caller, target))
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise CoverageError("program model call list is malformed") from error
    return edges


def build_report(
    profile_directory: Path,
    program_model_path: Path,
    binding_path: Path,
    qualification_path: Path,
) -> dict[str, Any]:
    return score_report(
        profile_directory, program_model_path, binding_path, qualification_path
    ).report


def score_report(
    profile_directory: Path,
    program_model_path: Path,
    binding_path: Path,
    qualification_path: Path,
) -> ScoredReport:
    bound = load_bound_stripped_model(
        profile_directory,
        program_model_path,
        binding_path,
        qualification_path,
    )
    full_payload, full_sha256 = _full_artifact(
        profile_directory, bound.provenance["artifactManifestSha256"]
    )
    oracle = bound.oracle
    scoreable = {
        function.rva
        for function in oracle.functions
        if function.rva is not None and function.exclusion is None
    }
    excluded = {
        function.rva
        for function in oracle.functions
        if function.rva is not None and function.exclusion is not None
    }
    names = {
        function.rva: function.aliases[0].name if function.aliases else function.identifier
        for function in oracle.functions
        if function.rva is not None
    }
    population = _oracle_edges(full_payload, oracle, scoreable, excluded)
    oracle_edges = population.edges
    callers_with_sites = population.callers_with_sites
    kinds = population.kinds
    recovered = _recovered_edges(program_model_path, bound)
    scored = {edge for edge in recovered if edge[0] in scoreable and edge[1] in scoreable}
    reference = set(oracle_edges)
    matched = scored & reference
    unmatched = scored - reference
    fabricated = {edge for edge in unmatched
                  if population.caller_coverage[edge[0]]["negativeEvidenceComplete"]}
    unknown = unmatched - fabricated
    excluded_recovered = recovered - scored
    true_positives = len(matched)
    precision_lower = _ratio(true_positives, len(scored))
    precision_upper = _ratio(true_positives + len(unknown), len(scored))

    # Reserve fixed metadata and conservative per-record JSON overhead, then
    # charge escaped names once per emitted outcome before allocating them.
    projected = (
        16 * 1024
        + len(json.dumps(bound.provenance, ensure_ascii=True, indent=2).encode("ascii"))
        + 160 * len(reference)
        + 32 * len(callers_with_sites)
        + sum(len(json.dumps(value, ensure_ascii=True, indent=2).encode("ascii")) + 256
              for value in population.caller_coverage.values())
        + 256 * len(excluded_recovered)
        + 256 * len(unknown)
    )
    name_bytes = {
        rva: len(json.dumps(name, ensure_ascii=True).encode("ascii"))
        for rva, name in names.items()
    }
    for outcome in (reference - scored, matched, fabricated, unknown):
        for caller, callee in outcome:
            projected += 256 + name_bytes[caller] + name_bytes[callee]
            if projected > MAX_REPORT_BYTES:
                raise CoverageError("call edge report exceeds its projected output byte limit")
    if projected > MAX_REPORT_BYTES:
        raise CoverageError("call edge report exceeds its projected output byte limit")

    def edge(pair: tuple[int, int]) -> dict[str, Any]:
        return {
            "callerRva": hex(pair[0]),
            "calleeRva": hex(pair[1]),
            "callerName": names[pair[0]],
            "calleeName": names[pair[1]],
        }

    report = {
        "schemaVersion": 2,
        "reportId": REPORT_ID,
        "twin": TWIN,
        "populationDefinition": (
            "unique caller/callee function-start pairs from full-twin DWARF call "
            "sites whose callee is a definition or a uniquely named oracle alias, "
            "with both endpoints scoreable; every recovered edge with scoreable "
            "endpoints remains in the precision denominator; unmatched edges are "
            "fabricated only with complete emitted-call and target coverage, otherwise unknown"
        ),
        "provenance": {**bound.provenance, "fullArtifactSha256": full_sha256},
        "oracle": {
            "edgeCount": len(reference),
            "tailCallEdgeCount": sum(True in tails for tails in oracle_edges.values()),
            "callersWithCallSites": len(callers_with_sites),
            "callSiteKinds": dict(sorted(kinds.items())),
            "callersWithCompleteNegativeEvidence": sum(
                value["negativeEvidenceComplete"] for value in population.caller_coverage.values()
            ),
            "negativeEvidencePolicy": "dwarf5-all-emitted-calls-and-resolved-targets-v1",
        },
        "summary": {
            "referenceCount": len(reference),
            "rawRecoveredCount": len(recovered),
            "scoredRecoveredCount": len(scored),
            "excludedRecoveredCount": len(excluded_recovered),
            "truePositives": true_positives,
            "falsePositives": len(fabricated),
            "unknownRecoveredCount": len(unknown),
            "falseNegatives": len(reference - scored),
            "precision": precision_lower if scored and not unknown else None,
            "precisionStatus": ("unavailable" if not scored else
                                "exact" if not unknown else "bounded-with-unknowns"),
            "precisionBounds": {"lower": precision_lower, "upper": precision_upper},
            "recall": _ratio(true_positives, len(reference)),
            "thresholdAssessment": {
                "precisionAtLeast": 0.9,
                "recallAtLeast": 0.9,
                "precision": ("unproven" if unknown or not scored else
                              "pass" if 10 * true_positives >= 9 * len(scored) else "fail"),
                "recall": ("unproven" if not reference else
                           "pass" if 10 * true_positives >= 9 * len(reference) else "fail"),
                "releaseEligible": False,
            },
        },
        "productionVerified": False,
        "callersWithCallSites": [hex(rva) for rva in sorted(callers_with_sites)],
        "oracleEdges": [
            {
                "callerRva": hex(pair[0]),
                "calleeRva": hex(pair[1]),
                "tailCall": sorted(oracle_edges[pair]) != [False],
            }
            for pair in sorted(reference)
        ],
        "missingEdges": [edge(pair) for pair in sorted(reference - scored)],
        "fabricatedEdges": [edge(pair) for pair in sorted(fabricated)],
        "matchedEdges": [edge(pair) for pair in sorted(matched)],
        "unknownRecoveredEdges": [
            {**edge(pair), "reasonCodes": population.caller_coverage[pair[0]]["limitationReasons"]}
            for pair in sorted(unknown)
        ],
        "excludedRecoveredEdges": [
            {"callerRva": hex(pair[0]), "calleeRva": hex(pair[1]),
             "reasonCodes": [f"{role}-" + ("oracle-excluded" if rva in excluded else "outside-oracle")
                             for role, rva in zip(("caller", "callee"), pair) if rva not in scoreable]}
            for pair in sorted(excluded_recovered)
        ],
        "callerCoverage": list(population.caller_coverage.values()),
    }

    return ScoredReport(
        report=report,
        evidence={
            "programModel": bound.model_record,
            "binding": bound.binding_record,
            "qualification": bound.qualification_record,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score GCC stripped call edges in a bound recovered model."
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=REPOSITORY_ROOT / "oracle/gcc/16.2.0",
    )
    parser.add_argument("--program-model", type=Path, required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = build_report(
            arguments.profile,
            arguments.program_model,
            arguments.binding,
            arguments.qualification,
        )
        _write_json(arguments.output, report)
    except CoverageError as error:
        print(f"call edge report failed: {error}", file=sys.stderr)
        return 1
    summary = report["summary"]
    lower, upper = (summary["precisionBounds"][key] for key in ("lower", "upper"))
    recall = summary["recall"]
    print(
        f"call edges: precision bounds {lower['numerator']}..{upper['numerator']}/{lower['denominator']}, "
        f"recall {recall['numerator']}/{recall['denominator']} "
        f"({summary['falsePositives']} fabricated, {summary['unknownRecoveredCount']} unknown, "
        f"{summary['falseNegatives']} missing)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
