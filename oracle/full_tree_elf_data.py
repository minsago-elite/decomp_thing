"""Authenticate ELF global/TLS objects and Itanium ABI object bytes."""
from __future__ import annotations
from collections import defaultdict
import hashlib, json, os, stat
from pathlib import Path
from typing import Any
from oracle.full_tree_scope import canonical_json_bytes

class FullTreeElfDataError(ValueError):
    """Raised when ELF data twins cannot produce a closed index."""

POLICY = {"id": "full-tree-elf-data", "version": 2, "identity": "one-record-per-defined-object-rva", "abiSlots": "authenticated-eight-byte-little-endian-object-words-with-loaded-image-pointer-resolution"}
ABI_PREFIXES = {"_ZTV": "vtable", "_ZTT": "vtt", "_ZTI": "typeinfo", "_ZTS": "typeinfo-name"}
MAX_SYMBOLS = 2_000_000; MAX_ABI_OBJECT_BYTES = 1024 * 1024; MAX_ABI_SLOTS = 2_000_000

def _sha(payload: bytes) -> str: return hashlib.sha256(payload).hexdigest()
def _configuration_sha256() -> str: return _sha(canonical_json_bytes(POLICY) + Path(__file__).with_name("full-tree-elf-data.schema.json").read_bytes())

def _scan(path: Path, label: str, expected_sha256: str) -> dict[str, Any]:
    from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
    from elftools.elf.sections import SymbolTableSection  # type: ignore[import-untyped]
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0); descriptor = os.open(path, flags)
    stream = os.fdopen(descriptor, "rb", closefd=True)
    try:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode): raise FullTreeElfDataError(f"{label} is not a regular file")
        digest = hashlib.sha256()
        while block := stream.read(1024 * 1024): digest.update(block)
        if digest.hexdigest() != expected_sha256: raise FullTreeElfDataError(f"{label} SHA-256 differs from scope")
        stream.seek(0); elf = ELFFile(stream); loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD" and int(segment["p_memsz"]) > 0]; image_base = min(int(segment["p_vaddr"]) for segment in loads)
        loaded_ranges = tuple((int(segment["p_vaddr"]), int(segment["p_vaddr"]) + int(segment["p_memsz"]), bool(int(segment["p_flags"]) & 1)) for segment in loads)
        aliases: dict[tuple[str, int], dict[str, dict[str, Any]]] = defaultdict(dict); externals: dict[str, set[str]] = defaultdict(set); scanned = 0; abi_slots = 0
        for section_index, section in enumerate(elf.iter_sections()):
            if not isinstance(section, SymbolTableSection): continue
            for symbol_index, symbol in enumerate(section.iter_symbols()):
                scanned += 1
                if scanned > MAX_SYMBOLS: raise FullTreeElfDataError(f"{label} exceeds symbol bound")
                symbol_type = symbol["st_info"]["type"]
                if symbol_type not in {"STT_OBJECT", "STT_TLS"} or not symbol.name: continue
                locator = f"{label}:section[{section_index}]={section.name}:symbol[{symbol_index}]"
                if symbol["st_shndx"] == "SHN_UNDEF": externals[symbol.name].add(locator); continue
                if not isinstance(symbol["st_shndx"], int): continue
                target_section = elf.get_section(symbol["st_shndx"]); address = int(symbol["st_value"]); size = int(symbol["st_size"])
                if symbol_type != "STT_TLS" and address < image_base: continue
                abi = None
                for prefix, kind in ABI_PREFIXES.items():
                    if symbol.name.startswith(prefix):
                        if size > MAX_ABI_OBJECT_BYTES: raise FullTreeElfDataError(f"ABI object {symbol.name!r} exceeds byte bound")
                        section_offset = address - int(target_section["sh_addr"]); data = target_section.data()[section_offset:section_offset + size]; slots = []
                        for index in range(0, len(data) - (len(data) % 8), 8):
                            abi_slots += 1
                            if abi_slots > MAX_ABI_SLOTS: raise FullTreeElfDataError(f"{label} exceeds ABI slot bound")
                            word = data[index:index + 8]
                            value = int.from_bytes(word, byteorder="little", signed=False)
                            target = next(((start, executable) for start, end, executable in loaded_ranges if start <= value < end), None)
                            slots.append({"index": index // 8, "rawLittleEndian": word.hex(), "rva": hex(address + index - image_base), "targetKind": None if target is None else "code" if target[1] else "data", "targetRva": None if target is None else hex(value - image_base)})
                        abi = {"kind": kind, "ownerMangledName": symbol.name[len(prefix):], "slots": slots}; break
                address_kind = "tls-offset" if symbol_type == "STT_TLS" else "image-rva"
                normalized_address = address if symbol_type == "STT_TLS" else address - image_base
                aliases[(address_kind, normalized_address)][symbol.name] = {"abi": abi, "alignment": int(target_section["sh_addralign"]), "binding": str(symbol["st_info"]["bind"]), "evidence": [locator], "kind": "tls" if symbol_type == "STT_TLS" else "object", "mutability": "mutable" if int(target_section["sh_flags"]) & 1 else "constant", "name": symbol.name, "size": size, "visibility": str(symbol["st_other"]["visibility"])}
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise FullTreeElfDataError(f"{label} changed during scan")
        return {"aliases": aliases, "externals": externals, "inputSha256": expected_sha256, "scannedSymbols": scanned, "sizeBytes": before.st_size}
    finally: stream.close()

def generate_full_tree_elf_data_index(rich_path: Path, stripped_path: Path, *, scope: dict[str, Any], scope_sha256: str, inventory: dict[str, Any]) -> dict[str, Any]:
    rich = _scan(rich_path, "rich", scope["oracle"]["richArtifactSha256"]); stripped = _scan(stripped_path, "stripped", scope["oracle"]["strippedArtifactSha256"])
    if set(stripped["aliases"]) - set(rich["aliases"]): raise FullTreeElfDataError("stripped ELF introduces a global RVA")
    globals_ = []
    for address_key in sorted(rich["aliases"]):
        address_kind, address = address_key
        aliases = []
        for name, record in sorted(rich["aliases"][address_key].items()):
            stripped_record = stripped["aliases"].get(address_key, {}).get(name)
            if stripped_record and any(record[field] != stripped_record[field] for field in ("kind", "size", "alignment", "mutability", "abi")): raise FullTreeElfDataError(f"ELF twins disagree on data alias {name!r}")
            aliases.append({**record, "availability": {"rich": "surviving", "stripped": "surviving" if stripped_record else "removed"}, "evidence": sorted(record["evidence"] + (stripped_record["evidence"] if stripped_record else []))})
        globals_.append({"address": hex(address), "addressKind": address_kind, "aliases": aliases, "id": f"global-{'rva' if address_kind == 'image-rva' else 'tls'}-{hex(address)}"})
    external = [{"evidence": sorted(evidence), "name": name} for name, evidence in sorted(rich["externals"].items())]
    without_hash = {"artifacts": {label: {"inputSha256": item["inputSha256"], "scannedSymbols": item["scannedSymbols"], "sizeBytes": item["sizeBytes"]} for label, item in (("rich", rich), ("stripped", stripped))}, "counts": {"abiObjects": sum(alias["abi"] is not None for item in globals_ for alias in item["aliases"]), "abiSlots": sum(len(alias["abi"]["slots"]) for item in globals_ for alias in item["aliases"] if alias["abi"]), "abiResolvedSlots": sum(slot["targetRva"] is not None for item in globals_ for alias in item["aliases"] if alias["abi"] for slot in alias["abi"]["slots"]), "aliases": sum(len(item["aliases"]) for item in globals_), "externalGlobals": len(external), "globalRvas": len(globals_)}, "externalGlobals": external, "globals": globals_, "oracle": {"configurationSha256": _configuration_sha256(), "inventoryIndexSha256": inventory["indexSha256"], "scopeSha256": scope_sha256}, "schemaVersion": 1}
    document = {**without_hash, "indexSha256": _sha(canonical_json_bytes(without_hash))}
    validate_full_tree_elf_data_index(document, scope=scope, scope_sha256=scope_sha256, inventory=inventory); return document

def validate_full_tree_elf_data_index(document: dict[str, Any], *, scope: dict[str, Any], scope_sha256: str, inventory: dict[str, Any]) -> None:
    try:
        import fastjsonschema  # type: ignore[import-untyped]
        schema = json.loads(Path(__file__).with_name("full-tree-elf-data.schema.json").read_text(encoding="utf-8")); fastjsonschema.compile(schema)(document)
    except Exception as error: raise FullTreeElfDataError(f"ELF data index fails validation: {error}") from error
    if document["oracle"] != {"configurationSha256": _configuration_sha256(), "inventoryIndexSha256": inventory["indexSha256"], "scopeSha256": scope_sha256}: raise FullTreeElfDataError("ELF data index bindings differ")
    without_hash = {key: value for key, value in document.items() if key != "indexSha256"}
    if document["indexSha256"] != _sha(canonical_json_bytes(without_hash)): raise FullTreeElfDataError("ELF data index hash does not reconcile")
    ordering = lambda item: (item["addressKind"], int(item["address"], 16))
    if document["globals"] != sorted(document["globals"], key=ordering) or len({(item["addressKind"], item["address"]) for item in document["globals"]}) != len(document["globals"]): raise FullTreeElfDataError("ELF global address ordering or uniqueness differs")
    counts = {"abiObjects": sum(alias["abi"] is not None for item in document["globals"] for alias in item["aliases"]), "abiSlots": sum(len(alias["abi"]["slots"]) for item in document["globals"] for alias in item["aliases"] if alias["abi"]), "abiResolvedSlots": sum(slot["targetRva"] is not None for item in document["globals"] for alias in item["aliases"] if alias["abi"] for slot in alias["abi"]["slots"]), "aliases": sum(len(item["aliases"]) for item in document["globals"]), "externalGlobals": len(document["externalGlobals"]), "globalRvas": len(document["globals"])}
    if document["counts"] != counts: raise FullTreeElfDataError("ELF data counts do not reconcile")
