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
model.  An edge is scored when both endpoints are scoreable oracle functions
and the caller has at least one DWARF call site, because a function compiled
without call-site information cannot witness a missing or fabricated edge.
The unrestricted figures are reported alongside.  The report retains every
oracle, missing and fabricated edge, and every recovered edge excluded only
because its caller has no call site, so each figure can be recomputed; it does
not admit the model for release scoring.
"""

from __future__ import annotations

import argparse
from collections import Counter
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
from oracle.function_recovery_oracle import (  # noqa: E402
    _dwarf_starts,
    _in_executable_range,
)
from oracle.gcc.bound_recovered_model import (  # noqa: E402
    TWIN,
    load_bound_stripped_model,
)
from oracle.gcc.report_accuracy_coverage import (  # noqa: E402
    CoverageError,
    _json,
    _ratio,
    _read_regular,
    _required_mapping,
    _write_json,
)


REPORT_ID = "gcc-driver-call-edge-score-v1"
PYELFTOOLS_VERSION = "0.33"
CALL_SITE_TAGS = ("DW_TAG_call_site", "DW_TAG_GNU_call_site")
FUNCTION_ID_PREFIX = "function-rva-"
MODEL_ID_PREFIX = "fn_"


def _full_artifact(profile_directory: Path) -> tuple[bytes, str]:
    manifest = _json(profile_directory / "oracle-manifest.json", "oracle artifact manifest")
    record = _required_mapping(
        _required_mapping(manifest.get("artifacts"), "manifest.artifacts").get("full"),
        "manifest.artifacts.full",
    )
    relative = record.get("path")
    if not isinstance(relative, str):
        raise CoverageError("manifest.artifacts.full.path must be a string")
    payload = _read_regular(profile_directory / relative, "full artifact")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != record.get("sha256"):
        raise CoverageError("full artifact disagrees with the manifest")
    # Callers parse these verified bytes; the path is never reopened.
    return payload, digest


def _oracle_edges(
    full_payload: bytes, oracle: Any, scoreable: set[int], excluded: set[int]
) -> tuple[dict[tuple[int, int], set[bool]], set[int], Counter[str]]:
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
                if die.tag not in CALL_SITE_TAGS:
                    continue
                attributes = die.attributes
                pc = (
                    attributes.get("DW_AT_call_return_pc")
                    or attributes.get("DW_AT_call_pc")
                    or attributes.get("DW_AT_low_pc")
                )
                address = None if pc is None else _address(pc, dwarf, unit)
                if address is None or not _in_executable_range(
                    address, image_base, executable
                ):
                    kinds["call-site-no-address"] += 1
                    continue
                rva = address - image_base
                caller_die = _parent_subprogram(die)
                starts = (
                    []
                    if caller_die is None
                    else [
                        start - image_base
                        for start in _dwarf_starts(caller_die, dwarf, *helpers)
                        if _in_executable_range(start, image_base, executable)
                    ]
                )
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
    return edges, callers_with_sites, kinds


def _recovered_edges(
    program_model_path: Path, model_sha256: str, image_base: int, function_count: int
) -> set[tuple[int, int]]:
    payload = _read_regular(program_model_path, "program model")
    if hashlib.sha256(payload).hexdigest() != model_sha256:
        raise CoverageError("program model changed after it was bound")
    functions = json.loads(payload).get("functions")
    if not isinstance(functions, list) or len(functions) != function_count:
        raise CoverageError("program model function list disagrees with the bound model")
    edges: set[tuple[int, int]] = set()
    try:
        for function in functions:
            caller = int(function["id"].removeprefix(MODEL_ID_PREFIX), 16) - image_base
            for callee in function.get("calls", []):
                edges.add(
                    (caller, int(callee.removeprefix(MODEL_ID_PREFIX), 16) - image_base)
                )
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise CoverageError("program model call list is malformed") from error
    return edges


def build_report(
    profile_directory: Path,
    program_model_path: Path,
    binding_path: Path,
    qualification_path: Path,
) -> dict[str, Any]:
    bound = load_bound_stripped_model(
        profile_directory,
        program_model_path,
        binding_path,
        qualification_path,
    )
    full_payload, full_sha256 = _full_artifact(profile_directory)
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
    oracle_edges, callers_with_sites, kinds = _oracle_edges(
        full_payload, oracle, scoreable, excluded
    )
    recovered = _recovered_edges(
        program_model_path,
        bound.provenance["programModel"]["sha256"],
        bound.model.image_base,
        len(bound.model.functions),
    )
    unrestricted = {
        edge for edge in recovered if edge[0] in scoreable and edge[1] in scoreable
    }
    scored = {edge for edge in unrestricted if edge[0] in callers_with_sites}
    reference = set(oracle_edges)
    true_positives = len(scored & reference)
    unrestricted_true_positives = len(unrestricted & reference)

    def edge(pair: tuple[int, int]) -> dict[str, Any]:
        return {
            "callerRva": hex(pair[0]),
            "calleeRva": hex(pair[1]),
            "callerName": names[pair[0]],
            "calleeName": names[pair[1]],
        }

    return {
        "schemaVersion": 1,
        "reportId": REPORT_ID,
        "twin": TWIN,
        "populationDefinition": (
            "unique caller/callee function-start pairs from full-twin DWARF call "
            "sites whose callee is a definition or a uniquely named oracle alias, "
            "with both endpoints scoreable; recovered edges are scored when both "
            "endpoints are scoreable and the caller has a DWARF call site"
        ),
        "provenance": {**bound.provenance, "fullArtifactSha256": full_sha256},
        "oracle": {
            "edgeCount": len(reference),
            "tailCallEdgeCount": sum(True in tails for tails in oracle_edges.values()),
            "callersWithCallSites": len(callers_with_sites),
            "callSiteKinds": dict(sorted(kinds.items())),
        },
        "summary": {
            "referenceCount": len(reference),
            "rawRecoveredCount": len(recovered),
            "scoredRecoveredCount": len(scored),
            "truePositives": true_positives,
            "falsePositives": len(scored - reference),
            "falseNegatives": len(reference - scored),
            "precision": _ratio(true_positives, len(scored)),
            "recall": _ratio(true_positives, len(reference)),
            "unrestricted": {
                "scoredRecoveredCount": len(unrestricted),
                "precision": _ratio(unrestricted_true_positives, len(unrestricted)),
                "recall": _ratio(unrestricted_true_positives, len(reference)),
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
        "fabricatedEdges": [edge(pair) for pair in sorted(scored - reference)],
        "callerWithoutCallSiteEdges": [
            edge(pair) for pair in sorted(unrestricted - scored)
        ],
    }


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
    precision = summary["precision"]
    recall = summary["recall"]
    print(
        f"call edges: precision {precision['numerator']}/{precision['denominator']}, "
        f"recall {recall['numerator']}/{recall['denominator']} "
        f"({summary['falsePositives']} fabricated, {summary['falseNegatives']} missing)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
