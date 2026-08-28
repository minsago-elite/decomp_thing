"""Dispatch closed source-lock validation to a benchmark-specific profile."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oracle.gcc.verify_source_lock import VerificationError


def _project(path: Path) -> str:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise VerificationError(f"duplicate JSON object key: {key}")
            value[key] = item
        return value

    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
        project = payload["oracle"]["project"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise VerificationError(f"cannot identify source-lock profile {path}: {error}") from error
    if not isinstance(project, str):
        raise VerificationError("oracle.project must be a string")
    return project


def load_and_validate_lock(path: Path) -> dict[str, Any]:
    """Validate *path* with the source project's closed profile."""

    project = _project(path)
    if project == "GNU Compiler Collection":
        from oracle.gcc.verify_source_lock import load_and_validate_lock as validate
    elif project == "LLVM Project":
        try:
            from oracle.llvm.verify_source_lock import load_and_validate_lock as validate
        except ModuleNotFoundError as error:
            raise VerificationError("LLVM source-lock support is not installed") from error
    else:
        raise VerificationError(f"unsupported source-lock project: {project!r}")
    return validate(path)
