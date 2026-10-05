import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/oracle"))
import provision_clang_18_1_3 as provision


class ProvisioningNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = provision.read_contract()
        cls.temp_root = ROOT / "build/clang1813-offline-tests"
        cls.temp_root.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_root, ignore_errors=True)

    def temporary_directory(self):
        return tempfile.TemporaryDirectory(dir=self.temp_root)

    def valid_build_record(self):
        digest = "a" * 64
        profile = self.contract["profile"]
        packages = []
        for pin in profile["binaryRoots"]:
            packages.append({
                "name": pin["name"], "version": pin["version"], "architecture": "amd64",
                "suite": "noble", "component": "universe",
                "file": f"pool/universe/l/llvm-toolchain-18/{pin['name']}.deb",
                "bytes": 1, "sha256": digest,
            })
        tool = lambda role: {
            "role": role, "path": "/usr/bin/clang-18" if role == "c-driver" else "/usr/bin/clang++-18",
            "symlinkChain": [], "resolvedPath": "/usr/lib/llvm-18/bin/clang",
            "bytes": 1, "sha256": digest,
            "mode": "0555",
            "versionOutput": "clang version 18.1.3\n",
        }
        file_manifest = provision.manifest([{"path": "/usr/lib/llvm-18/lib/libclang-cpp.so",
                                             "bytes": 1, "sha256": digest}])
        resources = provision.manifest([{"path": "/usr/lib/llvm-18/lib/clang/18.1.3/include/stddef.h",
                                         "bytes": 1, "sha256": digest}])
        repositories = [{
            "suite": suite,
            "inRelease": f"{profile['snapshotBase']}dists/{suite}/InRelease",
            "sha256": digest, "bytes": 1,
            "signerPrimaryFingerprint": profile["ubuntuArchivePrimaryFingerprints"][0],
        } for suite in profile["suites"]]
        probe = {
            "compilerVersion": "18.1.3", "target": "x86_64-pc-linux-gnu",
            "inventoryEvidence": self.contract["langOptions"]["inventoryEvidence"],
            "generatedFields": self.contract["langOptions"]["generatedFieldCount"],
            "familyCounts": self.contract["langOptions"]["familyCounts"],
            "generatedFieldNames": [f"Field{i}" for i in range(298)],
            "manualFields": self.contract["langOptions"]["manualFields"],
            "callingConventions": self.contract["langOptions"]["callingConventions"],
            "apiChecks": self.contract["langOptions"]["apiChecks"],
            "runtimeLangOptionsChecks": self.contract["langOptions"]["runtimeChecks"],
            "macroObservations": {"expansionCount": 1, "macroInfoChecks": 1,
                                   "nonBuiltinClassifications": 1},
            "definitionSha256": digest, "headerSha256": digest,
            "sourceSha256": digest, "binarySha256": digest, "fixtureSha256": digest,
        }
        return {
            "schemaVersion": 1,
            "buildSystem": "ubuntu-snapshot-debootstrap-apt",
            "profile": {"id": profile["id"], "architecture": "amd64", "target": profile["target"],
                        "snapshot": profile["snapshot"], "codename": profile["codename"]},
            "acquisition": {
                "repositories": repositories, "ubuntuKeyring": {"bytes": 1, "sha256": digest},
                "candidateSha256": digest,
                "sourceIndexesSha256": digest, "binaryIndexesSha256": digest,
                "signatureFingerprints": [row["signerPrimaryFingerprint"] for row in repositories],
            },
            "source": {
                "package": "llvm-toolchain-18", "version": "1:18.1.3-1ubuntu1",
                "upstreamTag": "llvmorg-18.1.3",
                "dsc": {"bytes": 1, "sha256": digest},
                "files": [{"name": "source.dsc", "bytes": 1, "sha256": digest, "role": "dsc"}],
                "upstreamArchive": {"bytes": 1, "sha256": digest},
                "upstreamSignature": {"bytes": 1, "sha256": digest},
                "upstreamKeyring": {"bytes": 1, "sha256": digest},
            },
            "patchAudit": {"status": "compatible", "patchCount": 0,
                            "patchInventorySha256": digest, "relevantFileCount": 34,
                            "relevantFileManifestSha256": digest},
            "packages": packages, "downloadedPackages": [dict(row) for row in packages],
            "tools": [tool("c-driver"), tool("cxx-driver")],
            "runtime": file_manifest, "resources": resources,
            "resourceDirectory": "/usr/lib/llvm-18/lib/clang/18.1.3",
            "probe": probe, "environment": self.contract["environment"],
            "recipe": provision.recipe_identity(),
            "commands": {name: ["command", name] for name in {
                "debootstrap", "writeAptSources", "aptUpdate", "aptDownloadOnly", "aptInstall",
                "clangCVersion", "clangCxxVersion", "clangResourceDirectory", "llvmConfigLibdir",
                "llvmConfigCxxflags", "probeCompile", "probeRun", "rootfsTar", "ociArchive",
            }},
            "rootfs": {"bytes": 1, "sha256": digest},
            "image": {"format": "oci-image-layout-v1", "manifestSha256": digest,
                      "imageDigest": "sha256:" + digest},
            "imageArtifact": {"bytes": 1, "sha256": digest},
            "reproducibility": {"cleanBuilds": 2, "matchingRootfsSha256": True,
                                 "matchingImageDigest": True},
        }

    def test_contract_pins_all_development_and_runtime_roots(self):
        roots = {row["name"] for row in self.contract["profile"]["binaryRoots"]}
        self.assertEqual(roots, {
            "clang-18", "llvm-18-dev", "libclang-18-dev",
            "libclang-cpp18-dev", "libclang-cpp18",
        })

    def test_workflow_actions_are_pinned_to_immutable_commit_shas(self):
        workflow = (ROOT / ".github/workflows/generic-template-toolchain.yml").read_text(encoding="utf-8")
        actions = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, flags=re.MULTILINE)
        self.assertTrue(actions)
        self.assertTrue(all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action) for action in actions), actions)
        self.assertIn("Production snapshot metadata diagnostic", workflow)
        self.assertIn("--snapshot 20240702T000000Z", workflow)
        self.assertIn("if: ${{ github.event_name == 'pull_request' || (github.event_name == 'workflow_dispatch' && inputs.mode == 'snapshot-metadata-diagnostic') }}", workflow)
        qualify_job = re.search(r"(?ms)^  qualify:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", workflow)
        self.assertIsNotNone(qualify_job)
        self.assertIn("if: ${{ github.event_name != 'workflow_dispatch' || inputs.mode == 'full-qualification' }}",
                      qualify_job.group(1))

    def test_rootfs_command_uses_the_selected_contract_environment(self):
        contract = {"environment": {"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "7",
                                     "PATH": "/custom/bin"}}
        completed = type("Result", (), {"stdout": "ok"})()
        with mock.patch.object(provision, "run_checked", return_value=completed) as run:
            self.assertEqual(provision.rootfs_run(Path("/rootfs"), ["/usr/bin/env"], contract), "ok")
        command = run.call_args.args[0]
        self.assertIn("PATH=/custom/bin", command)
        self.assertIn("SOURCE_DATE_EPOCH=7", command)

    def test_driver_symlink_resolved_path_is_canonical_but_chain_is_preserved(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            target = rootfs / "usr/lib/llvm-18/bin/clang++"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"clang++ bytes")
            logical = rootfs / "usr/bin/clang++-18"
            logical.parent.mkdir(parents=True)
            logical.symlink_to("../lib/llvm-18/bin/clang++")
            row = provision.driver_record(rootfs, "/usr/bin/clang++-18", "cxx-driver", "clang version 18.1.3\n")
            self.assertEqual(row["resolvedPath"], "/usr/lib/llvm-18/bin/clang++")
            self.assertEqual(row["symlinkChain"], ["/usr/bin/clang++-18 -> ../lib/llvm-18/bin/clang++"])

    def test_runtime_manifest_binds_resolved_library_bytes_and_symlink_rows(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            library_dir = rootfs / "usr/lib/llvm-18/lib"
            library_dir.mkdir(parents=True)
            for name, content in (("libclang-cpp.so.18.1", b"clang library"), ("libLLVM-18.so.1", b"llvm library")):
                (library_dir / name).write_bytes(content)
            (library_dir / "libclang-cpp.so").symlink_to("libclang-cpp.so.18.1")
            (library_dir / "libLLVM-18.so").symlink_to("libLLVM-18.so.1")
            rows = provision.runtime_dependencies(rootfs, [], self.contract)
            by_path = {row["path"]: row for row in rows}
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so.18.1"]["sha256"],
                             provision.sha256(b"clang library"))
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so"]["sha256"],
                             provision.sha256(b"symlink\0libclang-cpp.so.18.1"))

    def test_loader_resource_manifest_is_rechecked_before_emitting_input(self):
        record = self.valid_build_record()
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            resource_file = rootfs / "usr/lib/llvm-18/lib/clang/18.1.3/include/stddef.h"
            resource_file.parent.mkdir(parents=True)
            resource_file.write_bytes(b"resource header")
            record["resources"] = provision.resource_manifest(rootfs, record["resourceDirectory"])
            self.assertEqual(provision.verify_recorded_resource_manifest(rootfs, record), record["resources"])
            resource_file.write_bytes(b"changed resource header")
            with self.assertRaisesRegex(provision.ProvisionError, "resource-directory bytes differ"):
                provision.verify_recorded_resource_manifest(rootfs, record)

    def test_normalization_removes_inode_bearing_ldconfig_aux_cache(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            rootfs.mkdir()
            with mock.patch.object(provision, "run_checked") as run:
                provision.normalize_rootfs(rootfs, 1714003200)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertTrue(any(str(rootfs / "var/cache/ldconfig/aux-cache") in command for command in commands))

    def test_provenance_reports_must_bind_to_build_record_and_locked_comparator(self):
        record = self.valid_build_record()
        record["probe"]["fixtureSha256"] = provision.sha256_file(
            ROOT / self.contract["negativeControl"]["fixture"])
        provision.validate_provenance_probe_report(dict(record["probe"]), record)

        record_sha = "b" * 64
        resource_digest = provision.frontend_resource_manifest_sha256(
            record["resourceDirectory"], record["resources"])
        loader_report = {
            "scope": "infrastructure-loader-smoke-only",
            "buildRecordSha256": record_sha,
            "imageDigest": record["image"]["imageDigest"],
            "resourceDirectory": "toolchain" + record["resourceDirectory"],
            "resourceFileCount": record["resources"]["entryCount"],
            "resourceTreeBytes": sum(row["bytes"] for row in record["resources"]["entries"]),
            "resourceManifestSha256": resource_digest,
            "infrastructureProfileProjectionSha256": "c" * 64,
            "pathTransformSha256": "d" * 64,
            "cxxDriverIdentitySha256": "e" * 64,
            "rejectedWrongImage": True,
            "rejectedWrongCxxDriverBytes": True,
            "rejectedChangedResourceIdentity": True,
            "rejectedChangedRuntimeLibraryIdentity": True,
            "rejectedMissingResourceDirectory": True,
        }
        provision.validate_provenance_loader_report(loader_report, record, record_sha)
        loader_report["buildRecordSha256"] = "f" * 64
        with self.assertRaisesRegex(provision.ProvisionError, "does not bind the build record"):
            provision.validate_provenance_loader_report(loader_report, record, record_sha)

        lock_path = ROOT / self.contract["negativeControl"]["artifactLock"]
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        artifact = lock["artifacts"][self.contract["negativeControl"]["artifactRole"]]
        fixture = ROOT / self.contract["negativeControl"]["fixture"]
        negative = {
            "scope": "negative-version-gate-only; not a Clang 18.1.3 identity",
            "artifactOracleId": self.contract["negativeControl"]["oracleId"],
            "artifactLockSha256": provision.sha256_file(lock_path),
            "compilerBytes": artifact["bytes"],
            "compilerSha256": artifact["sha256"],
            "compilerVersionOutput": "Ubuntu clang version 22.1.6",
            "fixtureBytes": fixture.stat().st_size,
            "fixtureSha256": record["probe"]["fixtureSha256"],
            "fixtureAcceptedByClang22": True,
            "compiler18GateRejected": "probe compiler version or target mismatch",
        }
        provision.validate_provenance_negative_report(negative, record, self.contract)
        negative["compilerSha256"] = "0" * 64
        with self.assertRaisesRegex(provision.ProvisionError, "does not match the locked comparator"):
            provision.validate_provenance_negative_report(negative, record, self.contract)

    def test_deb822_rejects_duplicate_fields(self):
        with self.assertRaises(provision.ProvisionError):
            provision.parse_deb822("Package: llvm\nPackage: forged\n")

    def test_deb822_rejects_orphan_continuation(self):
        with self.assertRaises(provision.ProvisionError):
            provision.parse_deb822(" continuation\n")

    def test_streamed_index_rejects_an_oversized_line_before_unbounded_read(self):
        with self.temporary_directory() as temp:
            path = Path(temp) / "Packages.gz"
            path.write_bytes(gzip.compress(b"12345\n"))
            with mock.patch.object(provision, "MAX_INDEX_LINE_BYTES", 4):
                with self.assertRaisesRegex(provision.ProvisionError, "oversized control line"):
                    list(provision.iter_compressed_index(path))

    def test_signed_empty_package_index_is_allowed_but_empty_control_document_is_not(self):
        with self.temporary_directory() as temp:
            path = Path(temp) / "Packages.gz"
            path.write_bytes(gzip.compress(b""))
            self.assertEqual(list(provision.iter_compressed_index(path)), [])
        with self.assertRaisesRegex(provision.ProvisionError, "empty Debian control/index document"):
            provision.parse_deb822("")

    def test_inrelease_cleartext_unescapes_dash_prefixed_lines(self):
        data = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
                "Suite: noble\n- -leading dash\n-----BEGIN PGP SIGNATURE-----\n"
                "signature\n-----END PGP SIGNATURE-----\n").encode()
        self.assertEqual(provision.cleartext_body(data), b"Suite: noble\n-leading dash\n")

    def test_release_identity_mismatch_fails_closed(self):
        with self.assertRaises(provision.ProvisionError):
            provision.verify_release_identity({"Suite": "noble", "Codename": "jammy"}, "noble", "noble")

    def test_official_release_component_superset_is_valid_for_selected_components(self):
        release = {"Origin": "Ubuntu", "Label": "Ubuntu", "Suite": "noble", "Codename": "noble",
                   "Architectures": "amd64 arm64", "Components": "main restricted universe multiverse"}
        provision.verify_release_profile(release, "noble", self.contract["profile"])
        release["Origin"] = "Ubuntu mirror"
        with self.assertRaises(provision.ProvisionError):
            provision.verify_release_profile(release, "noble", self.contract["profile"])

    def test_signed_index_selection_uses_architecture_packages_and_sources(self):
        table = {
            "main/binary-amd64/Packages.gz": (1, "0" * 64),
            "main/source/Sources.xz": (1, "1" * 64),
        }
        self.assertEqual(provision.index_path(table, "main", "binary-amd64", "amd64"),
                         "main/binary-amd64/Packages.gz")
        self.assertEqual(provision.index_path(table, "main", "source"), "main/source/Sources.xz")

    def test_release_sha256_table_accepts_standard_empty_field_value_line(self):
        digest = "a" * 64
        release = provision.parse_deb822(
            "Suite: noble\nSHA256:\n  " + digest + " 123 main/binary-amd64/Packages.gz\n"
        )[0]
        self.assertEqual(
            provision.release_sha256_table(release),
            {"main/binary-amd64/Packages.gz": (123, digest)},
        )

    def test_release_sha256_table_rejects_an_internal_blank_row(self):
        digest = "a" * 64
        release = provision.parse_deb822(
            "SHA256:\n  " + digest + " 123 Packages.gz\n \n  " + "b" * 64 + " 456 Sources.gz\n"
        )[0]
        with self.assertRaisesRegex(provision.ProvisionError, "malformed SHA256 row"):
            provision.release_sha256_table(release)

    def test_source_checksums_accept_standard_empty_field_value_line(self):
        digest = "c" * 64
        source = provision.parse_deb822(
            "Package: llvm-toolchain-18\nChecksums-Sha256:\n  " + digest + " 456 llvm-toolchain-18.tar.xz\n"
        )[0]
        self.assertEqual(
            provision.source_file_rows(source),
            [{"name": "llvm-toolchain-18.tar.xz", "bytes": 456, "sha256": digest}],
        )

    def test_source_checksums_reject_an_internal_blank_row(self):
        digest = "c" * 64
        source = provision.parse_deb822(
            "Package: llvm-toolchain-18\nChecksums-Sha256:\n  " + digest +
            " 456 first.tar.xz\n \n  " + "d" * 64 + " 789 second.tar.xz\n"
        )[0]
        with self.assertRaisesRegex(provision.ProvisionError, "malformed source Checksums-Sha256 row"):
            provision.source_file_rows(source)

    def test_source_selection_error_reports_versions_from_signed_package_records(self):
        rows = [{
            "Package": "llvm-toolchain-18", "Version": "1:18.1.3-1ubuntu0",
            "_suite": "noble", "_component": "universe",
        }]
        with self.assertRaisesRegex(
            provision.ProvisionError,
            r"expected a unique signed source record.*observed signed versions: 1:18.1.3-1ubuntu0@noble/universe",
        ):
            provision.select_source_record(rows, "llvm-toolchain-18", "1:18.1.3-1ubuntu1")

    def test_source_index_diagnostic_binds_snapshot_hashes_versions_and_binary_sources(self):
        profile = self.contract["profile"]
        digest = "e" * 64
        repositories = [{
            "suite": "noble",
            "signerPrimaryFingerprint": profile["ubuntuArchivePrimaryFingerprints"][0],
            "inRelease": {"bytes": 123, "sha256": digest},
            "releaseIdentity": {"Date": "Thu, 25 Apr 2024 00:00:00 UTC", "Suite": "noble"},
        }]
        indexes = [{
            "suite": "noble", "component": "universe", "kind": "source",
            "path": "downloads/noble/universe/source/Sources.xz", "bytes": 456, "sha256": digest,
        }, {
            "suite": "noble", "component": "universe", "kind": "binary-amd64",
            "path": "downloads/noble/universe/binary-amd64/Packages.xz", "bytes": 654, "sha256": digest,
        }]
        sources = [{
            "_suite": "noble", "_component": "universe", "Package": "llvm-toolchain-18",
            "Version": "1:18.1.3-1ubuntu0", "Directory": "pool/universe/l/llvm-toolchain-18",
            "Checksums-Sha256": "f" * 64 + " 789 llvm-toolchain-18_18.1.3.orig.tar.xz",
        }]
        binaries = [{
            "_suite": "noble", "_component": "universe", "Package": "clang-18",
            "Version": "1:18.1.3-1ubuntu1", "Architecture": "amd64",
            "Source": "llvm-toolchain-18 (1:18.1.3-1ubuntu0)",
            "Filename": "pool/universe/l/llvm-toolchain-18/clang-18.deb",
            "Size": "987", "SHA256": digest,
        }]

        related_sources = [{
            "_suite": "noble", "_component": "universe", "Package": "llvm-toolchain-17",
            "Version": "1:17.0.6-9ubuntu1", "Directory": "pool/universe/l/llvm-toolchain-17",
        }]
        report = provision.source_index_diagnostic(
            profile, repositories, indexes, sources, related_sources, len(related_sources), binaries
        )
        self.assertEqual(report["snapshot"], profile["snapshot"])
        self.assertEqual(report["expectedSource"], profile["sourcePackage"])
        self.assertEqual(report["sourceIndexes"][0]["sha256"], digest)
        self.assertEqual(report["binaryIndexes"][0]["sha256"], digest)
        self.assertEqual(report["sourcePackageVersionsObserved"], ["1:18.1.3-1ubuntu0"])
        self.assertEqual(report["exactSourceVersionRecordCount"], 0)
        self.assertEqual(report["selectionAssessment"], "package-found-but-exact-version-not-found")
        self.assertEqual(report["selectionSemantics"], "exact Package and Version strings; no epoch or version normalization")
        self.assertEqual(report["matchingSourcePackageRecords"][0]["package"], "llvm-toolchain-17")
        self.assertEqual(report["binaryRootRecords"][0]["source"], binaries[0]["Source"])

    def test_source_index_diagnostic_caps_related_rows_and_marks_truncation(self):
        profile = self.contract["profile"]
        related_sources = [{
            "_suite": "noble", "_component": "universe", "Package": f"llvm-toolchain-{index}",
            "Version": f"1:{index}.0.0-1", "Directory": f"pool/universe/l/llvm-toolchain-{index}",
        } for index in range(provision.MAX_SOURCE_DIAGNOSTIC_ROWS + 1)]
        report = provision.source_index_diagnostic(profile, [], [], [], related_sources,
                                                   len(related_sources), [])
        self.assertEqual(len(report["matchingSourcePackageRecords"]), provision.MAX_SOURCE_DIAGNOSTIC_ROWS)
        self.assertEqual(report["matchingPackageRecordCount"], provision.MAX_SOURCE_DIAGNOSTIC_ROWS + 1)
        self.assertTrue(report["matchingPackageRecordsTruncated"])

    def test_snapshot_metadata_probe_reports_exact_source_and_binary_roots_without_payload_claims(self):
        profile = {**self.contract["profile"], "snapshot": provision.SNAPSHOT_METADATA_PROBE,
                   "snapshotBase": f"https://snapshot.ubuntu.com/ubuntu/{provision.SNAPSHOT_METADATA_PROBE}/"}
        source_pin = profile["sourcePackage"]
        source = {
            "Package": source_pin["name"], "Version": source_pin["version"],
            "Directory": "pool/main/l/llvm-toolchain-18",
            "Checksums-Sha256": "\n  ".join([
                "e" * 64 + " 8313 llvm-toolchain-18_18.1.3-1ubuntu1.dsc",
                "d" * 64 + " 155361864 llvm-toolchain-18_18.1.3.orig.tar.xz",
                "a" * 64 + " 162568 llvm-toolchain-18_18.1.3-1ubuntu1.debian.tar.xz",
            ]),
            "_suite": "noble-updates", "_component": "main",
        }
        binaries = []
        for index, pin in enumerate(profile["binaryRoots"]):
            binaries.append({
                "Package": pin["name"], "Version": pin["version"], "Architecture": "amd64",
                "Source": "llvm-toolchain-18 (18.1.3-1ubuntu1)",
                "Filename": f"pool/universe/l/llvm-toolchain-18/{pin['name']}_18.1.3-1ubuntu1_amd64.deb",
                "Size": 100 + index, "SHA256": f"{index + 1:x}" * 64,
                "_suite": "noble-updates", "_component": "universe",
            })
        with self.temporary_directory() as temp:
            keyring = Path(temp) / "ubuntu-archive-keyring.gpg"
            keyring.write_bytes(b"fixture keyring bytes")
            report = provision.snapshot_metadata_selection(
                self.contract, profile, [], [], [source], binaries, 1234, keyring,
            )
        self.assertEqual(report["status"], "exact-contract-records-present")
        self.assertEqual(report["candidateSnapshot"], provision.SNAPSHOT_METADATA_PROBE)
        self.assertEqual(report["configuredSnapshot"], self.contract["profile"]["snapshot"])
        self.assertEqual(report["payloadBytesDownloaded"], 0)
        self.assertEqual(report["sourcePackage"]["exactRecords"][0]["sourceFiles"][0]["name"],
                         "llvm-toolchain-18_18.1.3-1ubuntu1.dsc")
        self.assertEqual({row["package"] for row in report["binaryRoots"]},
                         {row["name"] for row in profile["binaryRoots"]})
        self.assertTrue(all(row["status"] == "exact-version-unique" for row in report["binaryRoots"]))

    def test_snapshot_metadata_probe_does_not_normalize_source_or_binary_versions(self):
        profile = {**self.contract["profile"], "snapshot": provision.SNAPSHOT_METADATA_PROBE,
                   "snapshotBase": f"https://snapshot.ubuntu.com/ubuntu/{provision.SNAPSHOT_METADATA_PROBE}/"}
        source = {"Package": "llvm-toolchain-18", "Version": "1:18.1.3-1",
                  "Directory": "pool/main/l/llvm-toolchain-18",
                  "Checksums-Sha256": "f" * 64 + " 1 x.dsc",
                  "_suite": "noble-updates", "_component": "main"}
        binaries = [{
            "Package": pin["name"],
            "Version": "1:18.1.3-1" if pin["name"] == "clang-18" else pin["version"],
            "Architecture": "amd64", "Source": "llvm-toolchain-18 (18.1.3-1)",
            "Filename": f"pool/universe/llvm/{pin['name']}.deb", "Size": 2,
            "SHA256": "b" * 64, "_suite": "noble-updates", "_component": "universe",
        } for pin in profile["binaryRoots"]]
        with self.temporary_directory() as temp:
            keyring = Path(temp) / "ubuntu-archive-keyring.gpg"
            keyring.write_bytes(b"fixture keyring bytes")
            report = provision.snapshot_metadata_selection(
                self.contract, profile, [], [], [source], binaries, 1234, keyring,
            )
        self.assertEqual(report["status"], "source-exact-version-not-found")
        self.assertEqual(report["sourcePackage"]["observedVersions"], ["1:18.1.3-1"])
        clang = next(row for row in report["binaryRoots"] if row["package"] == "clang-18")
        self.assertEqual(clang["status"], "exact-version-not-found")
        self.assertEqual(clang["observedVersions"], ["1:18.1.3-1"])

    def test_snapshot_metadata_probe_is_locked_to_the_reviewed_timestamp(self):
        with self.temporary_directory() as temp:
            output = Path(temp) / "metadata"
            with self.assertRaisesRegex(provision.ProvisionError, "metadata-only probe is pinned"):
                provision.probe_snapshot_metadata(
                    self.contract, "20240425T000000Z", output, Path(temp) / "keyring"
                )
            self.assertFalse(output.exists())

    def test_snapshot_metadata_probe_authenticates_only_inrelease_and_index_urls(self):
        profile = self.contract["profile"]
        snapshot = provision.SNAPSHOT_METADATA_PROBE
        base = f"https://snapshot.ubuntu.com/ubuntu/{snapshot}/"
        objects = {}

        def packed_text(value):
            return gzip.compress(value.encode("utf-8"), mtime=0)

        source = (
            "Package: llvm-toolchain-18\n"
            "Version: 1:18.1.3-1ubuntu1\n"
            "Directory: pool/main/l/llvm-toolchain-18\n"
            "Checksums-Sha256:\n"
            " " + "e" * 64 + " 8313 llvm-toolchain-18_18.1.3-1ubuntu1.dsc\n"
            " " + "d" * 64 + " 155361864 llvm-toolchain-18_18.1.3.orig.tar.xz\n"
            " " + "a" * 64 + " 162568 llvm-toolchain-18_18.1.3-1ubuntu1.debian.tar.xz\n"
        )
        packages = []
        for index, pin in enumerate(profile["binaryRoots"]):
            package_digest = f"{index + 1:x}" * 64
            packages.append(
                f"Package: {pin['name']}\n"
                f"Version: {pin['version']}\n"
                "Architecture: amd64\n"
                "Source: llvm-toolchain-18 (18.1.3-1ubuntu1)\n"
                f"Filename: pool/universe/l/llvm-toolchain-18/{pin['name']}.deb\n"
                f"Size: {100 + index}\n"
                f"SHA256: {package_digest}\n"
            )
        release_docs = []
        for suite in profile["suites"]:
            entries = []
            for component in profile["components"]:
                for kind in ("source", "binary-amd64"):
                    relative_index = (f"{component}/source/Sources.gz" if kind == "source" else
                                      f"{component}/binary-amd64/Packages.gz")
                    if suite == "noble-updates" and component == "main" and kind == "source":
                        index_bytes = packed_text(source)
                    elif suite == "noble-updates" and component == "universe" and kind == "binary-amd64":
                        index_bytes = packed_text("\n".join(packages))
                    else:
                        index_bytes = packed_text("")
                    index_url = base + f"dists/{suite}/{relative_index}"
                    objects[index_url] = index_bytes
                    entries.append(f"  {provision.sha256(index_bytes)} {len(index_bytes)} {relative_index}")
            body = (
                f"Origin: Ubuntu\nLabel: Ubuntu\nSuite: {suite}\nCodename: noble\n"
                "Date: Fri, 14 Jun 2024 23:00:00 UTC\n"
                "Architectures: amd64 arm64\nComponents: main universe\n"
                "SHA256:\n" + "\n".join(entries) + "\n"
            )
            inrelease = (
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + body +
                "-----BEGIN PGP SIGNATURE-----\n\nfixture-signature\n-----END PGP SIGNATURE-----\n"
            ).encode("utf-8")
            objects[base + f"dists/{suite}/InRelease"] = inrelease
            release_docs.append(suite)

        class FakeDownloader:
            all_calls = []

            def __init__(self, root, total_limit):
                self.total = 0
                self.calls = []

            def get(self, url, expected_size=None, expected_sha256=None, max_bytes=0, allow_github_redirect=False):
                self.calls.append(url)
                self.all_calls.append(url)
                data = objects[url]
                if len(data) > max_bytes:
                    raise AssertionError("probe exceeded its test byte bound")
                if expected_size is not None:
                    self_test.assertEqual(len(data), expected_size)
                digest = provision.sha256(data)
                if expected_sha256 is not None:
                    self_test.assertEqual(digest, expected_sha256)
                self.total += len(data)
                return data, {"url": url, "finalUrl": url, "bytes": len(data), "sha256": digest}

        self_test = self
        with self.temporary_directory() as temp:
            keyring = Path(temp) / "ubuntu-archive-keyring.gpg"
            keyring.write_bytes(b"test keyring")
            output = Path(temp) / "metadata"
            with mock.patch.object(provision, "BoundedDownloader", FakeDownloader), \
                 mock.patch.object(provision, "check_runner_bounds"), \
                 mock.patch.object(provision, "verify_gpgv",
                                   return_value=profile["ubuntuArchivePrimaryFingerprints"][0]):
                report = provision.probe_snapshot_metadata(self.contract, snapshot, output, keyring)
            report_exists = (output / "snapshot-metadata-report.json").is_file()
            payload_files_exist = any(path.suffix in (".deb", ".dsc") for path in output.rglob("*"))

        self.assertEqual(report["status"], "exact-contract-records-present")
        self.assertEqual(len(report["repositories"]), 3)
        self.assertEqual(len(report["indexes"]), 12)
        self.assertEqual(report["payloadBytesDownloaded"], 0)
        self.assertEqual(len(release_docs), 3)
        self.assertEqual(len(FakeDownloader.all_calls), 15)
        self.assertTrue(all(url.startswith(base + "dists/") for url in FakeDownloader.all_calls))
        self.assertTrue(report_exists)
        self.assertFalse(payload_files_exist)

    def test_gpgv_primary_fingerprint_is_not_signature_class(self):
        signing = "A" * 40
        primary = "B" * 40
        fields = ["[GNUPG:]", "VALIDSIG", signing, "20261005", "1", "0", "4", "0", "1", "8", "00", primary]
        self.assertEqual(provision.valid_sig_primary_fingerprint(fields), primary)

    def test_gpgv_malformed_validsig_fails_closed(self):
        with self.assertRaises(provision.ProvisionError):
            provision.valid_sig_primary_fingerprint(["[GNUPG:]", "VALIDSIG", "A" * 40, "00"])

    def test_gpgv_requires_an_allowlisted_primary_fingerprint(self):
        with self.temporary_directory() as temp:
            keyring = Path(temp) / "keyring.gpg"
            keyring.write_bytes(b"fixture")
            signing, primary = "A" * 40, "B" * 40
            status = ("[GNUPG:] VALIDSIG " + signing +
                      " 20261005 1 0 4 0 1 8 00 " + primary + "\n")
            proc = mock.Mock(returncode=0, stdout=status, stderr="")
            with mock.patch.object(provision.subprocess, "run", return_value=proc):
                self.assertEqual(provision.verify_gpgv(Path("unused"), keyring, {primary}), primary)
                with self.assertRaises(provision.ProvisionError):
                    provision.verify_gpgv(Path("unused"), keyring, {signing})

    def test_armored_upstream_key_is_dearmored_with_a_workspace_local_gnupg_home(self):
        with self.temporary_directory() as temp:
            proc = mock.Mock(returncode=0, stdout=b"\x99binary-keyring", stderr=b"")
            with mock.patch.object(provision.subprocess, "run", return_value=proc) as run:
                result = provision.dearmor_release_key(
                    provision.ROOT / self.contract["profile"]["upstream"]["keyFile"], Path(temp),
                )
            self.assertEqual(result, b"\x99binary-keyring")
            command = run.call_args.args[0]
            self.assertIn("--homedir", command)
            self.assertTrue(Path(command[command.index("--homedir") + 1]).parent == Path(temp))

    def test_armored_upstream_key_dearmor_failure_rejects(self):
        with self.temporary_directory() as temp:
            proc = mock.Mock(returncode=1, stdout=b"", stderr=b"bad key")
            with mock.patch.object(provision.subprocess, "run", return_value=proc):
                with self.assertRaises(provision.ProvisionError):
                    provision.dearmor_release_key(
                        provision.ROOT / self.contract["profile"]["upstream"]["keyFile"], Path(temp),
                    )

    def test_redirect_handler_rejects_unapproved_destination_before_following(self):
        handler = provision.LockedRedirectHandler("snapshot.ubuntu.com", False)
        request = provision.urllib.request.Request("https://snapshot.ubuntu.com/object")
        with self.assertRaises(provision.urllib.error.URLError):
            handler.redirect_request(request, None, 302, "Found", {}, "https://attacker.invalid/object")

    def test_redirect_handler_allows_only_locked_github_release_cdns(self):
        handler = provision.LockedRedirectHandler("github.com", True)
        request = provision.urllib.request.Request("https://github.com/llvm/asset")
        redirected = handler.redirect_request(request, None, 302, "Found", {},
                                               "https://release-assets.githubusercontent.com/asset")
        self.assertEqual(redirected.full_url, "https://release-assets.githubusercontent.com/asset")

    def test_public_downloader_rejects_untrusted_redirect_host(self):
        class Response(io.BytesIO):
            headers = {"Content-Encoding": "identity", "Content-Length": "4"}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.close()

            def geturl(self):
                return "https://attacker.invalid/payload"

        with self.temporary_directory() as temp:
            downloader = provision.BoundedDownloader(Path(temp))
            with mock.patch.object(downloader, "_open_request", return_value=Response(b"data")):
                with self.assertRaises(provision.ProvisionError):
                    downloader.get("https://snapshot.ubuntu.com/object")

    def test_public_downloader_rejects_size_and_digest_mismatch(self):
        class Response(io.BytesIO):
            headers = {"Content-Encoding": "identity", "Content-Length": "4"}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.close()

            def geturl(self):
                return "https://snapshot.ubuntu.com/object"

        with self.temporary_directory() as temp:
            downloader = provision.BoundedDownloader(Path(temp))
            with mock.patch.object(downloader, "_open_request", return_value=Response(b"data")):
                with self.assertRaises(provision.ProvisionError):
                    downloader.get("https://snapshot.ubuntu.com/object", expected_size=5)
            downloader = provision.BoundedDownloader(Path(temp) / "second")
            with mock.patch.object(downloader, "_open_request", return_value=Response(b"data")):
                with self.assertRaises(provision.ProvisionError):
                    downloader.get("https://snapshot.ubuntu.com/object", expected_sha256="0" * 64)

    def test_source_package_identity_requires_unambiguous_syntax(self):
        self.assertEqual(provision.package_source_identity({"Source": "llvm-toolchain-18 (18.1.3-1ubuntu1)"}),
                         ("llvm-toolchain-18", "18.1.3-1ubuntu1"))
        with self.assertRaises(provision.ProvisionError):
            provision.package_source_identity({"Source": "llvm toolchain"})

    def test_safe_upstream_extractor_rejects_parent_path(self):
        with self.temporary_directory() as temp:
            archive = Path(temp) / "malicious.tar.xz"
            with tarfile.open(archive, mode="w:xz") as output:
                member = tarfile.TarInfo("llvm-project/../../escape")
                member.size = 1
                output.addfile(member, io.BytesIO(b"x"))
            with self.assertRaises(provision.ProvisionError):
                provision.safe_extract_xz_tar(archive, Path(temp) / "out")

    def test_langoptions_inventory_rejects_family_count_drift(self):
        report = {"compilerVersion": "18.1.3", "target": "x86_64-pc-linux-gnu",
                  "callingConventions": self.contract["langOptions"]["callingConventions"],
                  "apiChecks": self.contract["langOptions"]["apiChecks"]}
        inventory = {"generatedFields": 297, "familyCounts": self.contract["langOptions"]["familyCounts"],
                     "manualFields": self.contract["langOptions"]["manualFields"],
                     "manualFieldsCount": 28}
        with self.assertRaises(provision.ProvisionError):
            provision.validate_probe_report(report, inventory, self.contract)

    def test_probe_report_rejects_real_22_1_6_identity(self):
        report = {"compilerVersion": "22.1.6", "target": "x86_64-pc-linux-gnu",
                  "callingConventions": self.contract["langOptions"]["callingConventions"],
                  "apiChecks": self.contract["langOptions"]["apiChecks"],
                  "runtimeLangOptionsChecks": self.contract["langOptions"]["runtimeChecks"],
                  "macroObservations": {"expansionCount": 1, "macroInfoChecks": 1,
                                         "nonBuiltinClassifications": 1}}
        inventory = {"generatedFields": 298, "familyCounts": self.contract["langOptions"]["familyCounts"],
                     "manualFields": self.contract["langOptions"]["manualFields"],
                     "manualFieldsCount": 28,
                     "inventoryEvidence": self.contract["langOptions"]["inventoryEvidence"]}
        with self.assertRaisesRegex(provision.ProvisionError, "compiler version or target mismatch"):
            provision.validate_probe_report(report, inventory, self.contract)

    def test_probe_report_rejects_missing_runtime_macro_observations(self):
        report = {"compilerVersion": "18.1.3", "target": "x86_64-pc-linux-gnu",
                  "callingConventions": self.contract["langOptions"]["callingConventions"],
                  "apiChecks": self.contract["langOptions"]["apiChecks"],
                  "runtimeLangOptionsChecks": self.contract["langOptions"]["runtimeChecks"],
                  "macroObservations": {"expansionCount": 1, "macroInfoChecks": 1,
                                         "nonBuiltinClassifications": 0}}
        inventory = {"generatedFields": 298, "familyCounts": self.contract["langOptions"]["familyCounts"],
                     "manualFields": self.contract["langOptions"]["manualFields"],
                     "manualFieldsCount": 28,
                     "inventoryEvidence": self.contract["langOptions"]["inventoryEvidence"]}
        with self.assertRaisesRegex(provision.ProvisionError, "macro expansion and MacroInfo classification"):
            provision.validate_probe_report(report, inventory, self.contract)

    def test_build_record_rejects_missing_root_package(self):
        record = self.valid_build_record()
        record["packages"] = [row for row in record["packages"] if row["name"] != "libclang-18-dev"]
        record["downloadedPackages"] = [row for row in record["downloadedPackages"] if row["name"] != "libclang-18-dev"]
        with self.assertRaisesRegex(provision.ProvisionError, "missing the pinned package"):
            provision.validate_build_record(record, self.contract)

    def test_build_record_rejects_wrong_root_package_version(self):
        record = self.valid_build_record()
        for rows in (record["packages"], record["downloadedPackages"]):
            next(row for row in rows if row["name"] == "clang-18")["version"] = "1:18.1.8-1ubuntu1"
        with self.assertRaisesRegex(provision.ProvisionError, "missing the pinned package"):
            provision.validate_build_record(record, self.contract)

    def test_build_record_rejects_non_executable_driver_mode(self):
        record = self.valid_build_record()
        record["tools"][0]["mode"] = "0444"
        with self.assertRaisesRegex(provision.ProvisionError, "tool executable byte identity"):
            provision.validate_build_record(record, self.contract)

    def test_build_record_rejects_downloaded_package_digest_drift(self):
        record = self.valid_build_record()
        record["downloadedPackages"][0]["sha256"] = "b" * 64
        with self.assertRaisesRegex(provision.ProvisionError, "differs from the installed signed package"):
            provision.validate_build_record(record, self.contract)

    def test_build_record_rejects_missing_or_malformed_source_inventory_digests(self):
        for field in ("definitionSha256", "headerSha256"):
            for omit in (True, False):
                with self.subTest(field=field, omit=omit):
                    record = self.valid_build_record()
                    if omit:
                        record["probe"].pop(field)
                    else:
                        record["probe"][field] = "not-a-sha256"
                    with self.assertRaisesRegex(provision.ProvisionError, "probe bytes are not authenticated"):
                        provision.validate_build_record(record, self.contract)

    def test_langoptions_source_audit_accepts_exact_pinned_inventory(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definitions = []
            serial = 0
            for family, count in self.contract["langOptions"]["familyCounts"].items():
                for _ in range(count):
                    name = "C99" if serial == 0 else f"Field{serial}"
                    definitions.append(f"{family}({name}, x)\n")
                    serial += 1
            definition = base / "LangOptions.def"
            definition.write_text("".join(definitions), encoding="utf-8")
            header = base / "LangOptions.h"
            members = "\n".join(f"  int {name};" for name in self.contract["langOptions"]["manualFields"])
            header.write_text("class LangOptions : public LangOptionsBase {\n" + members + "\n};\n", encoding="utf-8")
            inventory = provision.audit_langoptions(definition, header, self.contract)
            self.assertEqual(inventory["generatedFields"], 298)
            self.assertEqual(inventory["inventoryEvidence"], self.contract["langOptions"]["inventoryEvidence"])
            self.assertEqual(inventory["manualFieldsCount"], 28)
            report = {
                "compilerVersion": "18.1.3",
                "target": "x86_64-pc-linux-gnu",
                "callingConventions": self.contract["langOptions"]["callingConventions"],
                "apiChecks": self.contract["langOptions"]["apiChecks"],
                "runtimeLangOptionsChecks": self.contract["langOptions"]["runtimeChecks"],
                "macroObservations": {"expansionCount": 1, "macroInfoChecks": 1,
                                       "nonBuiltinClassifications": 1},
            }
            checked = provision.validate_probe_report(report, inventory, self.contract)
            self.assertEqual(checked["inventoryEvidence"], self.contract["langOptions"]["inventoryEvidence"])
            self.assertEqual(checked["runtimeLangOptionsChecks"], self.contract["langOptions"]["runtimeChecks"])

    def test_source_patch_audit_emits_rejection_for_contract_file_difference(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            package = base / "package"
            upstream = base / "upstream"
            (package / "debian/patches").mkdir(parents=True)
            (package / "debian/patches/series").write_text("", encoding="utf-8")
            rel = self.contract["relevantFiles"][0]
            (package / rel).parent.mkdir(parents=True)
            (upstream / rel).parent.mkdir(parents=True)
            (package / rel).write_bytes(b"patched package bytes")
            (upstream / rel).write_bytes(b"upstream bytes")
            with self.assertRaises(provision.ProvisionError):
                provision.audit_patches(package, upstream, base / "patch-audit.json", self.contract)
            result = json.loads((base / "patch-audit.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "incompatible")
            self.assertEqual(result["decision"], "reject-distro-profile")
            self.assertTrue((base / "patch-audit.json").is_file())

    def test_source_patch_audit_covers_tooling_and_recursive_visitor_headers(self):
        tooling_header = "clang/include/clang/Tooling/Tooling.h"
        visitor_header = "clang/include/clang/AST/RecursiveASTVisitor.h"
        self.assertIn(tooling_header, self.contract["relevantFiles"])
        self.assertIn(visitor_header, self.contract["relevantFiles"])
        self.assertEqual(len(self.contract["relevantFiles"]), 34)
        with self.temporary_directory() as temp:
            base = Path(temp)
            package = base / "package"
            upstream = base / "upstream"
            (package / "debian/patches").mkdir(parents=True)
            (package / "debian/patches/series").write_text("", encoding="utf-8")
            for rel in self.contract["relevantFiles"]:
                package_path, upstream_path = package / rel, upstream / rel
                package_path.parent.mkdir(parents=True, exist_ok=True)
                upstream_path.parent.mkdir(parents=True, exist_ok=True)
                package_path.write_bytes(b"identical source bytes")
                upstream_path.write_bytes(b"identical source bytes")
            (package / visitor_header).write_bytes(b"changed visitor semantics")
            with self.assertRaises(provision.ProvisionError):
                provision.audit_patches(package, upstream, base / "patch-audit.json", self.contract)
            result = json.loads((base / "patch-audit.json").read_text(encoding="utf-8"))
            self.assertEqual(result["relevantFileCount"], 34)
            self.assertEqual([row["path"] for row in result["unresolvedContractRelevantDifferences"]],
                             [visitor_header])

    def test_oci_image_verifier_rejects_unrecorded_blob(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs_tar = base / "rootfs.tar"
            payload = b"bounded synthetic rootfs tar payload"
            rootfs_tar.write_bytes(payload)
            layout = base / "layout"
            image = provision.create_oci_layout(rootfs_tar, layout, "fixture", 1714003200)
            archive_path = base / "image.tar"
            names = sorted(path.relative_to(layout).as_posix() for path in layout.rglob("*") if path.is_file())
            provision.run_checked([
                "tar", "--sort=name", "--format=posix", "--numeric-owner", "--owner=0", "--group=0",
                "--mtime=@1714003200", "--pax-option=delete=atime,delete=ctime", "-cf", str(archive_path),
                "-C", str(layout), *names,
            ])
            record = {"rootfs": {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
                      "image": image,
                      "imageArtifact": {"bytes": archive_path.stat().st_size,
                                        "sha256": provision.sha256_file(archive_path)}}
            provision.verify_oci_archive(archive_path, record, 1024 * 1024)
            record["imageArtifact"]["sha256"] = "f" * 64
            with self.assertRaisesRegex(provision.ProvisionError, "checksummed build-record artifact identity"):
                provision.verify_oci_archive(archive_path, record, 1024 * 1024)
            with tarfile.open(archive_path, "a") as archive:
                info = tarfile.TarInfo("blobs/sha256/" + "f" * 64)
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            record["imageArtifact"] = {"bytes": archive_path.stat().st_size,
                                       "sha256": provision.sha256_file(archive_path)}
            with self.assertRaisesRegex(provision.ProvisionError, "unrecorded files or blobs"):
                provision.verify_oci_archive(archive_path, record, 1024 * 1024)

    def test_oci_image_verifier_rejects_config_descriptor_size_mismatch(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs_tar = base / "rootfs.tar"
            payload = b"bounded synthetic rootfs tar payload"
            rootfs_tar.write_bytes(payload)
            layout = base / "layout"
            image = provision.create_oci_layout(rootfs_tar, layout, "fixture", 1714003200)

            manifest_path = layout / "blobs/sha256" / image["manifestSha256"]
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            config_path = layout / "blobs/sha256" / manifest["config"]["digest"].removeprefix("sha256:")
            config_bytes = config_path.read_bytes()
            manifest["config"]["size"] = len(config_bytes) + 1
            manifest_bytes = provision.canonical_json(manifest)
            manifest_sha256 = provision.sha256(manifest_bytes)
            (manifest_path.parent / manifest_sha256).write_bytes(manifest_bytes)
            manifest_path.unlink()

            index_path = layout / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["manifests"][0]["digest"] = "sha256:" + manifest_sha256
            index["manifests"][0]["size"] = len(manifest_bytes)
            index_path.write_bytes(provision.canonical_json(index))

            archive_path = base / "image.tar"
            names = sorted(path.relative_to(layout).as_posix() for path in layout.rglob("*") if path.is_file())
            provision.run_checked([
                "tar", "--sort=name", "--format=posix", "--numeric-owner", "--owner=0", "--group=0",
                "--mtime=@1714003200", "--pax-option=delete=atime,delete=ctime", "-cf", str(archive_path),
                "-C", str(layout), *names,
            ])
            record = {
                "rootfs": {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
                "image": {**image, "manifestSha256": manifest_sha256,
                          "imageDigest": "sha256:" + manifest_sha256},
                "imageArtifact": {"bytes": archive_path.stat().st_size,
                                  "sha256": provision.sha256_file(archive_path)},
            }
            with self.assertRaisesRegex(provision.ProvisionError, "config descriptor size differs"):
                provision.verify_oci_archive(archive_path, record, 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
