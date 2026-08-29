#!/usr/bin/env python3
"""Clean-build and authenticate the pinned GCC cc1 and lto1 ELF twins."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.elf_oracle import create_oracle_manifest  # noqa: E402
from oracle.full_tree_scope import canonical_json_bytes  # noqa: E402
from oracle.gcc.compiler_engines import load_compiler_engine_profile  # noqa: E402
from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402
# The historical runner has a hyphenated script filename, so import its stable
# implementation by path rather than duplicating its security-sensitive build.
import importlib.util  # noqa: E402


_RUNNER_PATH = REPOSITORY_ROOT / "scripts/rebuild-gcc-oracle.py"
_SPEC = importlib.util.spec_from_file_location("rebuild_gcc_oracle_runner", _RUNNER_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot load GCC oracle rebuild runner")
_RUNNER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_RUNNER)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def promote_candidate_manifests(
    *,
    workspace: Path,
    profile_path: Path,
    candidate_manifest_root: Path,
) -> list[Path]:
    """Accept only manifests reproduced in the retained clean-build workspace."""

    profile, _ = load_compiler_engine_profile(profile_path)
    promoted: list[Path] = []
    for engine in profile["engines"]:
        relative = engine["oracleManifest"]
        candidate = candidate_manifest_root / relative
        reproduced = workspace / relative
        for path, label in ((candidate, "candidate"), (reproduced, "reproduced")):
            if path.is_symlink() or not path.is_file():
                raise VerificationError(
                    f"{label} {engine['id']} manifest must be a non-symlink regular file",
                )
            if not 0 < path.stat().st_size <= 32 * 1024 * 1024:
                raise VerificationError(f"{label} {engine['id']} manifest has invalid size")
        payload = candidate.read_bytes()
        if payload != reproduced.read_bytes():
            raise VerificationError(
                f"candidate {engine['id']} manifest differs from retained clean-build evidence",
            )
        destination = profile_path.parent / relative
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file() or destination.read_bytes() != payload:
                raise VerificationError(
                    f"checked {engine['id']} manifest already exists with different bytes",
                )
        else:
            shutil.copy2(candidate, destination, follow_symlinks=False)
        promoted.append(destination)
        print(f"promoted byte-identical {engine['id']} manifest: {destination}")
    return promoted


def rebuild_engines(
    *,
    docker: str,
    workspace: Path,
    source_cache: Path,
    profile_path: Path,
    candidate_manifest_root: Path | None,
) -> dict[str, Path]:
    profile, records = load_compiler_engine_profile(profile_path)
    version_root = profile_path.parent
    _RUNNER.rebuild(
        docker=docker,
        workspace=workspace,
        archive=source_cache / "gcc-16.2.0.tar.xz",
        signature=source_cache / "gcc-16.2.0.tar.xz.sig",
        version_root=version_root,
    )
    base_record = _RUNNER._load_json(version_root / "build-record.json", "base build record")
    container = base_record["environment"]["container"]
    digest = container["digest"]
    outputs: dict[str, Path] = {}
    for engine in profile["engines"]:
        identifier = engine["id"]
        record = records[identifier]
        for phase in ("stageFull", "strip"):
            command = _RUNNER._replace_outputs(
                record["commands"][phase],
                f"/oracle/{record['outputs']['full']}",
                f"/oracle/{record['outputs']['stripped']}",
            )
            print(f"==> {identifier}:{phase}", flush=True)
            _RUNNER._run(
                _RUNNER._container_arguments(
                    docker,
                    digest,
                    container["platform"],
                    record["environment"]["variables"],
                    workspace,
                    "/oracle/build",
                    command,
                ),
            )
        build_record_path = workspace / engine["buildRecord"]
        build_record_path.write_bytes(canonical_json_bytes(record))
        manifest_path = workspace / engine["oracleManifest"]
        create_oracle_manifest(
            manifest_path,
            workspace / "source-lock.json",
            build_record_path,
        )
        checked = version_root / engine["oracleManifest"]
        if checked.is_file():
            if manifest_path.read_bytes() != checked.read_bytes():
                raise VerificationError(f"clean {identifier} manifest differs from checked evidence")
            print(f"reproduced checked {identifier} manifest")
        elif candidate_manifest_root is not None:
            candidate_manifest_root.mkdir(parents=True, exist_ok=True)
            candidate = candidate_manifest_root / engine["oracleManifest"]
            shutil.copy2(manifest_path, candidate)
            print(f"wrote candidate {identifier} manifest: {candidate}")
        else:
            raise VerificationError(
                f"checked {identifier} manifest is absent; pass --candidate-manifest-root for initial evidence",
            )
        for role in ("full", "stripped"):
            artifact = workspace / record["outputs"][role]
            print(f"  {role}: {_sha256(artifact)} ({artifact.stat().st_size} bytes)")
        outputs[identifier] = manifest_path
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--source-cache", type=Path)
    parser.add_argument("--profile", type=Path, default=REPOSITORY_ROOT / "oracle/gcc/16.2.0/compiler-engines.json")
    parser.add_argument("--candidate-manifest-root", type=Path)
    parser.add_argument(
        "--promote-existing",
        action="store_true",
        help="promote candidates only after matching retained clean-build manifests",
    )
    parser.add_argument("--docker", default="docker")
    arguments = parser.parse_args()
    try:
        workspace = arguments.workspace.absolute()
        profile = arguments.profile.absolute()
        candidate_root = (
            None
            if arguments.candidate_manifest_root is None
            else arguments.candidate_manifest_root.absolute()
        )
        if arguments.promote_existing:
            if candidate_root is None:
                parser.error("--promote-existing requires --candidate-manifest-root")
            promote_candidate_manifests(
                workspace=workspace,
                profile_path=profile,
                candidate_manifest_root=candidate_root,
            )
        else:
            if arguments.source_cache is None:
                parser.error("a clean rebuild requires --source-cache")
            rebuild_engines(
                docker=arguments.docker,
                workspace=workspace,
                source_cache=arguments.source_cache.absolute(),
                profile_path=profile,
                candidate_manifest_root=candidate_root,
            )
    except (OSError, VerificationError) as error:
        print(f"compiler-engine rebuild failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
