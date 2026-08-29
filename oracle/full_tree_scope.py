"""Closed, artifact-bound scope and shard policy for full-tree ELF truth."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


MAX_SCOPE_BYTES = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SHARD_COMPONENT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


class FullTreeScopeError(ValueError):
    """Raised when scope identity, policy, or a source path fails closed."""


def _read_regular(path: Path, label: str, maximum: int = MAX_SCOPE_BYTES) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FullTreeScopeError(f"cannot open {label} {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise FullTreeScopeError(f"{label} must be a regular file of 1..{maximum} bytes")
        payload = b""
        while len(payload) <= maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(payload)))
            if not block:
                break
            payload += block
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if len(payload) != before.st_size or identity(before) != identity(after):
            raise FullTreeScopeError(f"{label} changed while it was read")
        return payload
    finally:
        os.close(descriptor)


def _json(payload: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise FullTreeScopeError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FullTreeScopeError(f"{label} is invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise FullTreeScopeError(f"{label} root must be an object")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def load_full_tree_scope(
    scope_path: Path,
    *,
    source_lock_path: Path,
    artifact_manifest_path: Path,
) -> dict[str, Any]:
    scope_payload = _read_regular(scope_path, "full-tree scope")
    scope = _json(scope_payload, "full-tree scope")
    if scope_payload != canonical_json_bytes(scope):
        raise FullTreeScopeError("full-tree scope is not canonical JSON")
    try:
        import fastjsonschema  # type: ignore[import-untyped]
    except ModuleNotFoundError as error:
        raise FullTreeScopeError("scope validation requires pinned oracle dependencies") from error
    schema_path = Path(__file__).with_name("full-tree-scope.schema.json")
    schema = _json(_read_regular(schema_path, "full-tree scope schema"), "full-tree scope schema")
    try:
        fastjsonschema.compile(schema)(scope)
    except fastjsonschema.JsonSchemaException as error:
        raise FullTreeScopeError(f"full-tree scope fails JSON Schema: {error}") from error

    source_payload = _read_regular(source_lock_path, "source lock", 4 * 1024 * 1024)
    manifest_payload = _read_regular(artifact_manifest_path, "artifact manifest", 32 * 1024 * 1024)
    oracle = scope["oracle"]
    if hashlib.sha256(source_payload).hexdigest() != oracle["sourceLockSha256"]:
        raise FullTreeScopeError("full-tree scope source-lock binding does not match")
    if hashlib.sha256(manifest_payload).hexdigest() != oracle["artifactManifestSha256"]:
        raise FullTreeScopeError("full-tree scope artifact-manifest binding does not match")
    manifest = _json(manifest_payload, "artifact manifest")
    try:
        if manifest["artifacts"]["full"]["sha256"] != oracle["richArtifactSha256"]:
            raise FullTreeScopeError("full-tree scope rich artifact binding does not match manifest")
        if manifest["artifacts"]["stripped"]["sha256"] != oracle["strippedArtifactSha256"]:
            raise FullTreeScopeError("full-tree scope stripped artifact binding does not match manifest")
    except (KeyError, TypeError) as error:
        raise FullTreeScopeError("artifact manifest lacks full-tree artifact bindings") from error

    prefix_maps = scope["pathPolicy"]["prefixMaps"]
    sources = [item["from"] for item in prefix_maps]
    targets = [item["to"] for item in prefix_maps]
    if len(set(sources)) != len(sources):
        raise FullTreeScopeError("full-tree prefix maps must have unique sources")
    for left in sources:
        for right in sources:
            if left != right and right.startswith(left):
                raise FullTreeScopeError("full-tree prefix-map sources may not overlap")

    rules = scope["sharding"]["rules"]
    rule_prefixes = [item["pathPrefix"] for item in rules]
    if len(set(rule_prefixes)) != len(rule_prefixes):
        raise FullTreeScopeError("full-tree shard-rule prefixes must be unique")
    for rule in rules:
        if not any(rule["pathPrefix"].startswith(target) for target in targets):
            raise FullTreeScopeError("full-tree shard rule is outside normalized prefix-map targets")
    for category in ("compilationUnits", "cpuSeconds", "entities", "serializedBytes", "wallClockSeconds", "maximumResidentBytes"):
        if scope["bounds"]["perShard"][category] > scope["bounds"]["wholeRun"][category]:
            raise FullTreeScopeError(f"per-shard {category} bound exceeds the whole-run bound")
    return scope


def normalize_source_path(scope: dict[str, Any], raw_path: str) -> str:
    if not raw_path or "\x00" in raw_path or "\\" in raw_path:
        raise FullTreeScopeError("DWARF compilation-unit path is invalid")
    matches = [item for item in scope["pathPolicy"]["prefixMaps"] if raw_path.startswith(item["from"])]
    if len(matches) != 1:
        raise FullTreeScopeError(f"DWARF path matches {len(matches)} explicit prefix maps: {raw_path}")
    mapping = matches[0]
    normalized = mapping["to"] + raw_path[len(mapping["from"]):]
    parts = normalized.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise FullTreeScopeError(f"normalized DWARF path is not canonical: {normalized}")
    return normalized


def shard_for_source_path(scope: dict[str, Any], normalized_path: str) -> str:
    matches = [rule for rule in scope["sharding"]["rules"] if normalized_path.startswith(rule["pathPrefix"])]
    if len(matches) != 1:
        raise FullTreeScopeError(f"source path matches {len(matches)} shard rules: {normalized_path}")
    rule = matches[0]
    remainder = normalized_path[len(rule["pathPrefix"]):].split("/")
    depth = rule["componentDepth"]
    if len(remainder) <= depth:
        raise FullTreeScopeError(f"source path lacks {depth} shard components: {normalized_path}")
    components = []
    for raw in remainder[:depth]:
        component = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
        if not component or _SHARD_COMPONENT.fullmatch(component) is None:
            raise FullTreeScopeError(f"source path has an invalid shard component: {normalized_path}")
        components.append(component)
    return "-".join([rule["shardPrefix"], *components])
