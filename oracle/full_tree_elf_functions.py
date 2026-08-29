"""Bounded ELF-only function/alias index for full-tree truth reconciliation."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from oracle.full_tree_scope import canonical_json_bytes


class FullTreeElfFunctionError(ValueError):
    """Raised when authenticated ELF twins do not yield a closed function index."""


MAX_SYMBOLS = 2_000_000
MAX_ALIASES_PER_RVA = 512
PRODUCER_POLICY = {
    "id": "full-tree-elf-functions",
    "version": 1,
    "identity": "one-record-per-image-relative-function-symbol-rva",
    "aliasPolicy": "all-defined-stt-func-names-with-rich-stripped-availability",
}


def _configuration_sha256() -> str:
    schema = Path(__file__).with_name("full-tree-elf-functions.schema.json").read_bytes()
    return hashlib.sha256(canonical_json_bytes(PRODUCER_POLICY) + schema).hexdigest()


def validate_full_tree_elf_function_index(
    document: dict[str, Any],
    *,
    scope: dict[str, Any],
    scope_sha256: str,
    inventory: dict[str, Any],
) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise FullTreeElfFunctionError("ELF function validation requires pinned dependencies") from error
    schema_path = Path(__file__).with_name("full-tree-elf-functions.schema.json")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(document)
    except (OSError, json.JSONDecodeError, fastjsonschema.JsonSchemaException) as error:
        raise FullTreeElfFunctionError(f"ELF function index fails JSON Schema: {error}") from error
    if document["oracle"] != {
        "configurationSha256": _configuration_sha256(),
        "inventoryIndexSha256": inventory["indexSha256"],
        "scopeSha256": scope_sha256,
    }:
        raise FullTreeElfFunctionError("ELF function index bindings do not match")
    if document["artifacts"]["rich"]["inputSha256"] != scope["oracle"]["richArtifactSha256"]:
        raise FullTreeElfFunctionError("ELF function rich binding does not match scope")
    if document["artifacts"]["stripped"]["inputSha256"] != scope["oracle"]["strippedArtifactSha256"]:
        raise FullTreeElfFunctionError("ELF function stripped binding does not match scope")
    functions = document["functions"]
    if functions != sorted(functions, key=lambda item: int(item["rva"], 16)):
        raise FullTreeElfFunctionError("ELF functions are not canonically ordered")
    if len({item["rva"] for item in functions}) != len(functions):
        raise FullTreeElfFunctionError("ELF functions contain duplicate RVAs")
    for function in functions:
        if function["id"] != f"function-rva-{function['rva']}":
            raise FullTreeElfFunctionError("ELF function identity does not match RVA")
        if function["aliases"] != sorted(function["aliases"], key=lambda item: item["name"]):
            raise FullTreeElfFunctionError("ELF function aliases are not ordered")
        if len({item["name"] for item in function["aliases"]}) != len(function["aliases"]):
            raise FullTreeElfFunctionError("ELF function aliases contain duplicate names")
        for alias in function["aliases"]:
            if alias["evidence"] != sorted(alias["evidence"], key=lambda item: item["locator"]):
                raise FullTreeElfFunctionError("ELF alias evidence is not ordered")
    expected_counts = {
        "aliases": sum(len(item["aliases"]) for item in functions),
        "functionRvas": len(functions),
        "strippedFunctionRvas": sum(
            any(alias["availability"]["stripped"] == "surviving" for alias in item["aliases"])
            for item in functions
        ),
    }
    if document["counts"] != expected_counts:
        raise FullTreeElfFunctionError("ELF function counts do not reconcile")


def _open(path: Path, label: str) -> tuple[Any, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FullTreeElfFunctionError(f"cannot open {label}: {error}") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 1024 * 1024 * 1024:
        os.close(descriptor)
        raise FullTreeElfFunctionError(f"{label} must be a regular file of 1 byte..1 GiB")
    return os.fdopen(descriptor, "rb", closefd=True), metadata


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _sha256(stream: Any) -> str:
    stream.seek(0)
    digest = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        digest.update(block)
    stream.seek(0)
    return digest.hexdigest()


def _scan(path: Path, label: str, expected_sha256: str) -> dict[str, Any]:
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
        from elftools.elf.sections import SymbolTableSection  # type: ignore[import-untyped]
        import elftools  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise FullTreeElfFunctionError("ELF function indexing requires pinned pyelftools") from error
    if getattr(elftools, "__version__", None) != "0.33":
        raise FullTreeElfFunctionError("ELF function indexing requires exactly pyelftools 0.33")
    stream, before = _open(path, label)
    try:
        observed_sha256 = _sha256(stream)
        if observed_sha256 != expected_sha256:
            raise FullTreeElfFunctionError(f"{label} SHA-256 does not match the full-tree scope")
        elf = ELFFile(stream)
        loads = [
            segment
            for segment in elf.iter_segments()
            if segment["p_type"] == "PT_LOAD" and int(segment["p_memsz"]) > 0
        ]
        if not loads:
            raise FullTreeElfFunctionError(f"{label} has no nonempty PT_LOAD segment")
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
        aliases: dict[int, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        scanned = 0
        for section_index, section in enumerate(elf.iter_sections()):
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol_index, symbol in enumerate(section.iter_symbols()):
                scanned += 1
                if scanned > MAX_SYMBOLS:
                    raise FullTreeElfFunctionError(f"{label} exceeds the {MAX_SYMBOLS}-symbol bound")
                if symbol["st_info"]["type"] != "STT_FUNC" or symbol["st_shndx"] == "SHN_UNDEF" or not symbol.name:
                    continue
                try:
                    symbol.name.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise FullTreeElfFunctionError(f"{label} contains a non-UTF-8 function alias") from error
                if len(symbol.name) > 4096:
                    raise FullTreeElfFunctionError(f"{label} contains an overlong function alias")
                address = int(symbol["st_value"])
                if address < image_base:
                    continue
                rva = address - image_base
                if not any(start <= rva < end for start, end in executable):
                    continue
                if symbol.name not in aliases[rva] and len(aliases[rva]) >= MAX_ALIASES_PER_RVA:
                    raise FullTreeElfFunctionError(f"{label} RVA {hex(rva)} exceeds its alias bound")
                aliases[rva][symbol.name].add(
                    f"{label}:section[{section_index}]={section.name}:symbol[{symbol_index}]"
                )
        after = os.fstat(stream.fileno())
        if _identity(before) != _identity(after):
            raise FullTreeElfFunctionError(f"{label} changed while it was indexed")
        return {
            "aliases": aliases,
            "elfType": str(elf.header["e_type"]),
            "executableRanges": executable,
            "imageBase": image_base,
            "inputSha256": observed_sha256,
            "scannedSymbols": scanned,
            "sizeBytes": before.st_size,
        }
    except FullTreeElfFunctionError:
        raise
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise FullTreeElfFunctionError(f"cannot index {label}: {error}") from error
    finally:
        stream.close()


def generate_full_tree_elf_function_index(
    rich_path: Path,
    stripped_path: Path,
    *,
    scope: dict[str, Any],
    scope_sha256: str,
    inventory: dict[str, Any],
) -> dict[str, Any]:
    rich = _scan(rich_path, "rich", scope["oracle"]["richArtifactSha256"])
    stripped = _scan(stripped_path, "stripped", scope["oracle"]["strippedArtifactSha256"])
    for field in ("elfType", "executableRanges", "imageBase"):
        if rich[field] != stripped[field]:
            raise FullTreeElfFunctionError(f"ELF twins disagree on {field}")
    rich_rvas = set(rich["aliases"])
    stripped_rvas = set(stripped["aliases"])
    if extra := stripped_rvas - rich_rvas:
        raise FullTreeElfFunctionError(f"stripped ELF introduces function RVA {hex(min(extra))}")
    functions = []
    for rva in sorted(rich_rvas):
        rich_aliases = rich["aliases"][rva]
        stripped_aliases = stripped["aliases"].get(rva, {})
        if extra_names := set(stripped_aliases) - set(rich_aliases):
            raise FullTreeElfFunctionError(
                f"stripped ELF introduces alias {min(extra_names)!r} at {hex(rva)}"
            )
        functions.append(
            {
                "aliases": [
                    {
                        "availability": {
                            "rich": "surviving",
                            "stripped": "surviving" if name in stripped_aliases else "removed",
                        },
                        "evidence": [
                            {"kind": "elf-symbol", "locator": locator}
                            for locator in sorted(rich_aliases[name] | stripped_aliases.get(name, set()))
                        ],
                        "name": name,
                    }
                    for name in sorted(rich_aliases)
                ],
                "id": f"function-rva-{hex(rva)}",
                "rva": hex(rva),
            }
        )
    if not functions or len(functions) > scope["bounds"]["wholeRun"]["entities"]:
        raise FullTreeElfFunctionError("ELF function count is outside the full-tree entity bound")
    document = {
        "artifacts": {
            twin: {
                "inputSha256": record["inputSha256"],
                "scannedSymbols": record["scannedSymbols"],
                "sizeBytes": record["sizeBytes"],
            }
            for twin, record in (("rich", rich), ("stripped", stripped))
        },
        "counts": {
            "aliases": sum(len(item["aliases"]) for item in functions),
            "functionRvas": len(functions),
            "strippedFunctionRvas": len(stripped_rvas),
        },
        "functions": functions,
        "image": {
            "elfType": rich["elfType"],
            "executableRanges": [
                {"endExclusive": hex(end), "start": hex(start)}
                for start, end in rich["executableRanges"]
            ],
            "imageBase": hex(rich["imageBase"]),
        },
        "oracle": {
            "configurationSha256": _configuration_sha256(),
            "inventoryIndexSha256": inventory["indexSha256"],
            "scopeSha256": scope_sha256,
        },
        "schemaVersion": 1,
    }
    payload = canonical_json_bytes(document)
    if len(payload) > scope["bounds"]["wholeRun"]["serializedBytes"]:
        raise FullTreeElfFunctionError("ELF function index exceeds the full-tree byte bound")
    validate_full_tree_elf_function_index(
        document,
        scope=scope,
        scope_sha256=scope_sha256,
        inventory=inventory,
    )
    return document
