from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oracle.gcc import rebuild_compiler_engines as rebuild
from oracle.gcc.verify_source_lock import VerificationError


class RebuildCompilerEngineArtifactTests(unittest.TestCase):
    def test_initial_candidate_rebuild_verifies_workspace_manifest_without_checked_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gcc-engine-candidate-test-") as temporary:
            root = Path(temporary)
            version_root = root / "profile"
            workspace = root / "workspace"
            candidate_root = root / "candidates"
            version_root.mkdir()
            (workspace / "artifacts").mkdir(parents=True)
            (workspace / "artifacts/gcc-cc1.full").write_bytes(b"full")
            (workspace / "artifacts/gcc-cc1.stripped").write_bytes(b"stripped")
            engine = {"id": "cc1", "buildRecord": "cc1-build-record.json", "oracleManifest": "cc1-oracle-manifest.json"}
            record = {
                "commands": {"stageFull": ["stage"], "strip": ["strip"]},
                "environment": {"variables": {}},
                "outputs": {"full": "artifacts/gcc-cc1.full", "stripped": "artifacts/gcc-cc1.stripped"},
            }
            runner = SimpleNamespace(
                rebuild=Mock(),
                _load_json=Mock(return_value={"environment": {"container": {"platform": "linux/amd64"}}}),
                verified_container_image=Mock(return_value=("digest", {})),
                _replace_outputs=Mock(return_value=["true"]),
                _container_arguments=Mock(return_value=["true"]),
                _run=Mock(),
            )

            def write_manifest(path: Path, *_args: object) -> None:
                path.write_bytes(b"candidate manifest")

            with patch.object(rebuild, "load_compiler_engine_profile", return_value=({"engines": [engine]}, {"cc1": record})), \
                    patch.object(rebuild, "_RUNNER", runner), \
                    patch.object(rebuild, "create_oracle_manifest", side_effect=write_manifest), \
                    patch.object(rebuild, "verify_oracle_manifest") as verify_manifest, \
                    patch.object(rebuild, "verify_engine_artifacts") as verify_checked:
                result = rebuild.rebuild_engines(
                    docker="docker", workspace=workspace, source_cache=root / "source",
                    profile_path=version_root / "compiler-engines.json",
                    candidate_manifest_root=candidate_root, engine_ids=["cc1"],
                )
                self.assertEqual(workspace / "cc1-oracle-manifest.json", result["cc1"])
                self.assertEqual(b"candidate manifest", (candidate_root / "cc1-oracle-manifest.json").read_bytes())
                verify_manifest.assert_called_once_with(workspace / "cc1-oracle-manifest.json", artifact_root=workspace)
                verify_checked.assert_not_called()

    def test_engine_selection_defaults_to_profile_order_and_can_select_cc1_only(self) -> None:
        profile = {"engines": [{"id": "cc1"}, {"id": "lto1"}]}

        self.assertEqual(["cc1", "lto1"], rebuild._selected_engine_ids(profile, None))
        self.assertEqual(["cc1"], rebuild._selected_engine_ids(profile, ["cc1"]))
        with self.assertRaises(VerificationError):
            rebuild._selected_engine_ids(profile, ["cc1", "cc1"])
        with self.assertRaises(VerificationError):
            rebuild._selected_engine_ids(profile, ["gcc-driver"])

    def test_cached_engine_pair_is_checked_against_the_profile_bound_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gcc-engine-cache-test-") as temporary:
            root = Path(temporary)
            version_root = root / "profile"
            artifacts_root = root / "workspace" / "artifacts"
            version_root.mkdir()
            artifacts_root.mkdir(parents=True)
            full = b"authenticated full cc1 fixture"
            stripped = b"authenticated stripped cc1 fixture"
            full_path = artifacts_root / "gcc-cc1.full"
            stripped_path = artifacts_root / "gcc-cc1.stripped"
            full_path.write_bytes(full)
            stripped_path.write_bytes(stripped)
            facts = {
                "full": {"bytes": len(full), "sha256": hashlib.sha256(full).hexdigest()},
                "stripped": {"bytes": len(stripped), "sha256": hashlib.sha256(stripped).hexdigest()},
            }
            manifest_bytes = json.dumps({"fixture": True}, sort_keys=True, separators=(",", ":")).encode()
            manifest_path = version_root / "cc1-oracle-manifest.json"
            manifest_path.write_bytes(manifest_bytes)
            engine = {
                "id": "cc1",
                "oracleManifest": manifest_path.name,
                "oracleManifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            }
            profile = {"engines": [engine]}
            records = {"cc1": {"outputs": {"full": "artifacts/gcc-cc1.full", "stripped": "artifacts/gcc-cc1.stripped"}}}

            with patch.object(rebuild, "load_compiler_engine_profile", return_value=(profile, records)), \
                    patch.object(rebuild, "verify_oracle_manifest", return_value={"artifacts": facts}) as verify_manifest:
                selected = rebuild.verify_engine_artifacts(
                    workspace=root / "workspace", profile_path=version_root / "compiler-engines.json",
                    engine_ids=["cc1"],
                )
                self.assertEqual((full_path, stripped_path), selected["cc1"])
                verify_manifest.assert_called_once_with(manifest_path, artifact_root=root / "workspace")

                stripped_path.write_bytes(b"substituted cached binary")
                with self.assertRaisesRegex(VerificationError, "differs from its checked oracle manifest"):
                    rebuild.verify_engine_artifacts(
                        workspace=root / "workspace", profile_path=version_root / "compiler-engines.json",
                        engine_ids=["cc1"],
                    )


if __name__ == "__main__":
    unittest.main()
