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
        packages.append({
            "name": "ca-certificates", "version": "synthetic-test-only", "architecture": "all",
            "suite": "noble", "component": "main", "file": "pool/main/c/ca-certificates/fixture.deb",
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
            "commands": provision.canonical_commands(self.contract, digest),
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
        qualify_text = qualify_job.group(1)
        self.assertIn("if: ${{ github.event_name != 'workflow_dispatch' || inputs.mode == 'full-qualification' }}",
                      qualify_text)
        self.assertLess(qualify_text.index("Run offline fail-closed provisioning tests"),
                        qualify_text.index("Authenticate Ubuntu Snapshot source and patch compatibility first"))
        trigger_text = workflow[:workflow.index("permissions:")]
        self.assertEqual(trigger_text.count("'oracle/llvm/22.1.6/release-artifacts.json'"), 2)
        self.assertLess(qualify_text.index("Authenticate Ubuntu Snapshot source and patch compatibility first"),
                        qualify_text.index('bash scripts/install-frontend-node.sh'))
        self.assertEqual(qualify_text.count('-PfrontendNodeHome="$CLANG_WORK/frontend-node"'),
                         qualify_text.count('./gradlew'))
        self.assertLess(qualify_text.index('bash scripts/install-frontend-node.sh'), qualify_text.index('./gradlew'))

    def test_rootfs_command_uses_the_selected_contract_environment(self):
        contract = {"environment": {"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "7",
                                     "PATH": "/custom/bin"}}
        completed = type("Result", (), {"stdout": "ok"})()
        with mock.patch.object(provision, "run_checked", return_value=completed) as run:
            self.assertEqual(provision.rootfs_run(Path("/rootfs"), ["/usr/bin/env"], contract), "ok")
        command = run.call_args.args[0]
        self.assertIn("PATH=/custom/bin", command)
        self.assertIn("SOURCE_DATE_EPOCH=7", command)

    def test_debootstrap_command_records_the_selected_keyring(self):
        keyring = Path("workspace-keys/selected archive-keyring.gpg")
        executed = provision.debootstrap_command(self.contract, "/workspace/profile-root", keyring)
        recorded = provision.debootstrap_command(self.contract, "<PROFILE_ROOT>", keyring)
        self.assertIn("--keyring=workspace-keys/selected archive-keyring.gpg", executed)
        self.assertEqual(recorded, ["<PROFILE_ROOT>" if value == "/workspace/profile-root" else value
                                    for value in executed])
        self.assertIn("--include=ca-certificates", executed)

    def test_build_record_commands_reject_changed_omitted_inserted_and_reordered_arguments(self):
        baseline = self.valid_build_record()
        provision.validate_build_record(baseline, self.contract)
        for name, argv in baseline["commands"].items():
            mutations = {
                "changed": ["unreviewed-command", *argv[1:]],
                "omitted": argv[:-1],
                "inserted": [*argv, "--unreviewed-argument"],
                "reordered": [argv[1], argv[0], *argv[2:]],
            }
            for mutation, replacement in mutations.items():
                record = self.valid_build_record()
                record["commands"][name] = replacement
                with self.subTest(command=name, mutation=mutation), self.assertRaisesRegex(
                    provision.ProvisionError, "canonical recipe"
                ):
                    provision.validate_build_record(record, self.contract)
        for mutation in ("missing", "extra"):
            record = self.valid_build_record()
            if mutation == "missing":
                record["commands"].pop("aptCheck")
            else:
                record["commands"]["extra"] = ["unreviewed"]
            with self.subTest(mutation=mutation), self.assertRaisesRegex(provision.ProvisionError, "canonical recipe"):
                provision.validate_build_record(record, self.contract)

    def test_build_record_commands_bind_keyring_environment_and_package_pins(self):
        record = self.valid_build_record()
        commands = record["commands"]
        digest = record["acquisition"]["ubuntuKeyring"]["sha256"]
        self.assertIn(f"--keyring=<UBUNTU_ARCHIVE_KEYRING_SHA256:{digest}>", commands["debootstrap"])
        self.assertIn("-fno-exceptions", commands["probeCompile"])
        self.assertIn("-fno-rtti", commands["probeCompile"])
        mutations = {
            "debootstrap": (f"--keyring=<UBUNTU_ARCHIVE_KEYRING_SHA256:{digest}>", "--keyring=/unbound/keyring"),
            "aptInstall": ("clang-18=1:18.1.3-1ubuntu1", "clang-18=1:22.1.6-unreviewed"),
            "aptUpdate": (f"PATH={self.contract['environment']['PATH']}", "PATH=/unreviewed/bin"),
            "rootfsTar": (f"--mtime=@{self.contract['environment']['SOURCE_DATE_EPOCH']}", "--mtime=@0"),
            "probeCompile": ("-fno-rtti", "-fplugin=/unreviewed/plugin.so"),
        }
        for name, (old, new) in mutations.items():
            record = self.valid_build_record()
            self.assertIn(old, record["commands"][name])
            record["commands"][name] = [new if arg == old else arg for arg in record["commands"][name]]
            with self.subTest(command=name), self.assertRaisesRegex(provision.ProvisionError, "canonical recipe"):
                provision.validate_build_record(record, self.contract)
        for digest in (None, 123, int("1" * 64)):
            record = self.valid_build_record()
            record["acquisition"]["ubuntuKeyring"]["sha256"] = digest
            with self.subTest(digest=digest), self.assertRaisesRegex(provision.ProvisionError, "keyring"):
                provision.validate_build_record(record, self.contract)

    def test_selected_environment_changes_canonical_chroot_and_archive_commands(self):
        contract = json.loads(json.dumps(self.contract))
        contract["environment"]["PATH"] = "/custom/bin"
        contract["environment"]["SOURCE_DATE_EPOCH"] = "7"
        commands = provision.canonical_commands(contract, "b" * 64)
        for name in ("aptUpdate", "aptDownloadOnly", "aptInstall", "aptCheck", "clangCVersion",
                     "clangCxxVersion", "clangResourceDirectory", "llvmConfigLibdir", "llvmConfigCxxflags",
                     "probeCompile", "probeRun"):
            self.assertIn("PATH=/custom/bin", commands[name], name)
            self.assertIn("SOURCE_DATE_EPOCH=7", commands[name], name)
        self.assertIn("SOURCE_DATE_EPOCH=7", commands["debootstrap"])
        for name in ("rootfsTar", "ociArchive"):
            self.assertIn("--mtime=@7", commands[name])

    def test_bootstrap_ca_check_requires_package_and_nonempty_contained_bundle(self):
        packages = {("ca-certificates", "synthetic-test-only", "all")}
        with self.temporary_directory() as temp:
            rootfs = Path(temp)
            bundle = rootfs / "etc/ssl/certs/ca-certificates.crt"
            bundle.parent.mkdir(parents=True)
            for payload in (None, b""):
                if payload is not None:
                    bundle.write_bytes(payload)
                with self.subTest(payload=payload), self.assertRaisesRegex(provision.ProvisionError, "CA bundle"):
                    provision.require_bootstrap_ca_certificates(rootfs, packages)
            bundle.write_bytes(b"synthetic nonempty bundle; no TLS performed\n")
            with self.assertRaisesRegex(provision.ProvisionError, "package closure"):
                provision.require_bootstrap_ca_certificates(rootfs, set())
            provision.require_bootstrap_ca_certificates(rootfs, packages)
            bundle.unlink()
            bundle.symlink_to(Path(temp).parent)
            with self.assertRaisesRegex(provision.ProvisionError, "escapes"):
                provision.require_bootstrap_ca_certificates(rootfs, packages)

    def test_provisioning_checks_bootstrap_ca_before_any_apt_command(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            args = provision.argparse.Namespace(
                contract=provision.CONTRACT_PATH, workdir=base, rootfs=base / "rootfs",
                output=base / "output", acquisition=base / "acquisition", keyring=base / "keyring")
            with mock.patch.object(provision, "load_candidate", return_value=({}, [])), \
                    mock.patch.object(provision.shutil, "rmtree"), \
                    mock.patch.object(provision, "check_runner_bounds"), \
                    mock.patch.object(provision, "run_checked") as bootstrap, \
                    mock.patch.object(provision, "installed_package_keys", return_value=set()), \
                    mock.patch.object(provision, "rootfs_run") as apt, \
                    mock.patch.object(provision.BoundedDownloader, "get") as network:
                with self.assertRaisesRegex(provision.ProvisionError, "package closure"):
                    provision.provision_rootfs(args)
                self.assertIn("--include=ca-certificates", bootstrap.call_args.args[0])
                bootstrap.assert_called_once()
                apt.assert_not_called()
                network.assert_not_called()
            self.assertFalse(args.output.exists())

    def test_build_record_requires_bootstrap_ca_package_in_authenticated_closure(self):
        record = self.valid_build_record()
        record["packages"] = [row for row in record["packages"] if row["name"] != "ca-certificates"]
        with self.assertRaisesRegex(provision.ProvisionError, "bootstrap ca-certificates"):
            provision.validate_build_record(record, self.contract)

    def test_downloaded_package_key_parses_labeled_dpkg_deb_fields(self):
        result = mock.Mock(stdout="Package: clang-18\nVersion: 1:18.1.3-1ubuntu1\nArchitecture: amd64\n")
        with mock.patch.object(provision, "run_checked", return_value=result):
            self.assertEqual(provision.downloaded_package_key(Path("fixture.deb")),
                             ("clang-18", "1:18.1.3-1ubuntu1", "amd64"))
        for output in ("clang-18\n1:18.1.3-1ubuntu1\namd64\n",
                       "Package: clang-18\nVersion: 1:18.1.3-1ubuntu1\n",
                       "Package: clang-18\nPackage: substituted\nVersion: 1:18.1.3-1ubuntu1\nArchitecture: amd64\n"):
            with self.subTest(output=output), mock.patch.object(provision, "run_checked", return_value=mock.Mock(stdout=output)):
                with self.assertRaises(provision.ProvisionError):
                    provision.downloaded_package_key(Path("fixture.deb"))

    def test_build_record_rejects_missing_or_malformed_acquisition_digests(self):
        for field in ("candidateSha256", "sourceIndexesSha256", "binaryIndexesSha256"):
            for value in (None, "", "wrong", "F" * 64, int("1" * 64)):
                record = self.valid_build_record()
                if value is None:
                    record["acquisition"].pop(field)
                else:
                    record["acquisition"][field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    provision.ProvisionError, "acquisition candidate|signed index digest",
                ):
                    provision.validate_build_record(record, self.contract)

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

    def test_driver_and_runtime_symlinks_retain_every_hop_and_enforce_limit(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            library_dir = rootfs / "usr/lib/llvm-18/lib"
            library_dir.mkdir(parents=True)
            target = library_dir / "library-bytes"
            target.write_bytes(b"library")
            for name in ("libclang-cpp.so", "libLLVM-18.so"):
                (library_dir / name).symlink_to("intermediate")
            (library_dir / "intermediate").symlink_to("library-bytes")
            chain, resolved = provision.symlink_chain(rootfs, "/usr/lib/llvm-18/lib/libclang-cpp.so")
            self.assertEqual(resolved, target)
            self.assertEqual(chain, [
                "/usr/lib/llvm-18/lib/libclang-cpp.so -> intermediate",
                "/usr/lib/llvm-18/lib/intermediate -> library-bytes",
            ])
            rows = provision.runtime_dependencies(rootfs, [], self.contract)
            self.assertEqual({row["path"] for row in rows}, {
                "/usr/lib/llvm-18/lib/libclang-cpp.so", "/usr/lib/llvm-18/lib/libLLVM-18.so",
                "/usr/lib/llvm-18/lib/intermediate", "/usr/lib/llvm-18/lib/library-bytes",
            })
            for index in reversed(range(17)):
                (library_dir / f"hop{index}").symlink_to("library-bytes" if index == 16 else f"hop{index + 1}")
            self.assertEqual(len(provision.symlink_chain(rootfs, "/usr/lib/llvm-18/lib/hop1")[0]), 16)
            with self.assertRaisesRegex(provision.ProvisionError, "cycle/depth overflow"):
                provision.symlink_chain(rootfs, "/usr/lib/llvm-18/lib/hop0")

    def test_driver_symlinks_resolve_parent_segments_after_directory_links(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            directory = rootfs / "usr/lib/llvm-18/bin"
            (directory / "other/subdir").mkdir(parents=True)
            (directory / "target").write_bytes(b"wrong lexical target")
            target = directory / "other/target"
            target.write_bytes(b"actual compiler")
            (directory / "alias").symlink_to("other/subdir")
            (directory / "clang").symlink_to("alias/../target")
            chain, resolved = provision.symlink_chain(rootfs, "/usr/lib/llvm-18/bin/clang")
            self.assertEqual(resolved, target)
            self.assertEqual(chain, [
                "/usr/lib/llvm-18/bin/clang -> alias/../target",
                "/usr/lib/llvm-18/bin/alias -> other/subdir",
            ])
            (directory / "escape").symlink_to("../../../../../../outside")
            with self.assertRaisesRegex(provision.ProvisionError, "escapes rootfs"):
                provision.symlink_chain(rootfs, "/usr/lib/llvm-18/bin/escape")

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

    def test_frontend_hashes_match_real_a_loader_vectors(self):
        # Independently emitted by the real Java A loader using synthetic bytes;
        # these pin its canonical encoding without asserting a qualified compiler.
        record = self.valid_build_record()
        self.assertEqual(provision.frontend_cxx_driver_identity_sha256(record, "b" * 64),
                         "7142e7789d3b8c9714f3468a4f571b40ff9db017ca271fcba3b4a394095af455")
        header = b"synthetic header\n"
        resources = provision.manifest([{
            "path": record["resourceDirectory"] + "/include/stddef.h",
            "bytes": len(header), "sha256": provision.sha256(header),
        }])
        self.assertEqual(provision.frontend_resource_manifest_sha256(record["resourceDirectory"], resources),
                         "26b8373fc116f0dd9ad8c09f98391092f66e87f254e6cff13d37cb2601208faf")

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
            "cxxDriverIdentitySha256": provision.frontend_cxx_driver_identity_sha256(record, record_sha),
            "rejectedWrongImage": True,
            "rejectedWrongCxxDriverBytes": True,
            "rejectedChangedResourceIdentity": True,
            "rejectedChangedRuntimeLibraryIdentity": True,
            "rejectedMissingResourceDirectory": True,
        }
        provision.validate_provenance_loader_report(loader_report, record, record_sha)
        for field in ("cxxDriverIdentitySha256", "imageDigest", "resourceManifestSha256"):
            changed = dict(loader_report, **{field: "0" * 64})
            with self.subTest(field=field), self.assertRaises(provision.ProvisionError):
                provision.validate_provenance_loader_report(changed, record, record_sha)
        for field, changed_value in (("sha256", "0" * 64), ("bytes", 2), ("mode", "0755"),
                                     ("symlinkChain", ["/usr/bin/clang++-18 -> changed-target"])):
            changed_record = json.loads(json.dumps(record))
            next(row for row in changed_record["tools"] if row["role"] == "cxx-driver")[field] = changed_value
            with self.subTest(driver_field=field), self.assertRaisesRegex(provision.ProvisionError, "C\\+\\+ driver identity"):
                provision.validate_provenance_loader_report(loader_report, changed_record, record_sha)
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

    def test_upstream_signature_pause_rejects_exact_and_changed_urls_before_download(self):
        with self.temporary_directory() as temp:
            upstream = self.contract["profile"]["upstream"]
            signature_urls = (
                upstream["signatureUrl"],
                provision.PAUSED_UPSTREAM_SIGNATURE_URL + "?download=1",
                "https://mirror.example.invalid/llvm-project-18.1.3.src.tar.xz.sig",
            )
            for index, signature_url in enumerate(signature_urls):
                with self.subTest(signature_url=signature_url):
                    contract = {
                        **self.contract,
                        "profile": {
                            **self.contract["profile"],
                            "upstream": {**upstream, "signatureUrl": signature_url},
                        },
                    }
                    output = Path(temp) / f"acquisition-{index}"
                    with mock.patch.object(provision.BoundedDownloader, "__init__") as init, \
                            mock.patch.object(provision.BoundedDownloader, "get") as get:
                        with self.assertRaisesRegex(provision.ProvisionError, "no acquisition requests were made"):
                            provision.acquire_candidate(contract, output, Path(temp) / "missing-keyring.gpg")
                    init.assert_not_called()
                    get.assert_not_called()
                    self.assertFalse(output.exists())

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

    def test_oci_selected_environment_and_config_semantics_are_bound(self):
        environment = {**self.contract["environment"], "PATH": "/selected/bin", "SOURCE_DATE_EPOCH": "7"}
        changes = [
            ("architecture", lambda c: c.update(architecture="arm64")),
            ("os", lambda c: c.update(os="windows")),
            ("created", lambda c: c.update(created="2024-04-25T00:00:00Z")),
            ("history", lambda c: c.update(history=[])),
            ("environment", lambda c: c["config"].update(Env=["PATH=/different/bin"])),
            ("labels", lambda c: c["config"].update(Labels={})),
            ("working directory", lambda c: c["config"].update(WorkingDir="/tmp")),
            ("entrypoint", lambda c: c["config"].update(Entrypoint=["/bin/sh"])),
            ("command", lambda c: c["config"].update(Cmd=["unrecorded"])),
            ("user", lambda c: c["config"].update(User="1000")),
            ("rootfs type", lambda c: c["rootfs"].update(type="unrecorded")),
            ("extra field", lambda c: c.update(unrecorded=True)),
        ]
        with self.temporary_directory() as temp:
            base = Path(temp)
            payload = b"synthetic rootfs bytes; not a qualified image"
            rootfs_tar = base / "rootfs.tar"
            rootfs_tar.write_bytes(payload)
            for label, mutate in [("valid", None), *changes]:
                with self.subTest(label=label):
                    layout = base / label
                    image = provision.create_oci_layout(rootfs_tar, layout, "fixture", environment)
                    manifest_path = layout / "blobs/sha256" / image["manifestSha256"]
                    manifest = json.loads(manifest_path.read_text())
                    config_path = layout / "blobs/sha256" / manifest["config"]["digest"].removeprefix("sha256:")
                    config = json.loads(config_path.read_text())
                    self.assertEqual(config["created"], "1970-01-01T00:00:07Z")
                    self.assertEqual(config["config"]["Env"], [f"{key}={value}" for key, value in sorted(environment.items())])
                    if mutate:
                        mutate(config)
                        config_bytes = provision.canonical_json(config)
                        config_digest = provision.sha256(config_bytes)
                        config_path.unlink()
                        (config_path.parent / config_digest).write_bytes(config_bytes)
                        manifest["config"].update(digest="sha256:" + config_digest, size=len(config_bytes))
                        manifest_bytes = provision.canonical_json(manifest)
                        manifest_digest = provision.sha256(manifest_bytes)
                        manifest_path.unlink()
                        (manifest_path.parent / manifest_digest).write_bytes(manifest_bytes)
                        index_path = layout / "index.json"
                        index = json.loads(index_path.read_text())
                        index["manifests"][0].update(digest="sha256:" + manifest_digest, size=len(manifest_bytes))
                        index_path.write_bytes(provision.canonical_json(index))
                        image.update(manifestSha256=manifest_digest, imageDigest="sha256:" + manifest_digest)
                    archive_path = base / (label + ".tar")
                    with tarfile.open(archive_path, "w") as archive:
                        for path in sorted(layout.rglob("*")):
                            if path.is_file():
                                archive.add(path, arcname=path.relative_to(layout).as_posix())
                    record = {
                        "profile": {"id": "fixture"}, "environment": environment,
                        "rootfs": {"bytes": len(payload), "sha256": provision.sha256(payload)},
                        "image": image,
                        "imageArtifact": {"bytes": archive_path.stat().st_size, "sha256": provision.sha256_file(archive_path)},
                    }
                    if mutate:
                        with self.assertRaisesRegex(provision.ProvisionError, "config semantics"):
                            provision.verify_oci_archive(archive_path, record, 1024 * 1024)
                    else:
                        provision.verify_oci_archive(archive_path, record, 1024 * 1024)

    def test_oci_image_verifier_rejects_unrecorded_blob(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs_tar = base / "rootfs.tar"
            payload = b"bounded synthetic rootfs tar payload"
            rootfs_tar.write_bytes(payload)
            layout = base / "layout"
            image = provision.create_oci_layout(rootfs_tar, layout, "fixture", self.contract["environment"])
            archive_path = base / "image.tar"
            names = sorted(path.relative_to(layout).as_posix() for path in layout.rglob("*") if path.is_file())
            provision.run_checked([
                "tar", "--sort=name", "--format=posix", "--numeric-owner", "--owner=0", "--group=0",
                "--mtime=@1714003200", "--pax-option=delete=atime,delete=ctime", "-cf", str(archive_path),
                "-C", str(layout), *names,
            ])
            record = {"profile": {"id": "fixture"}, "environment": self.contract["environment"],
                      "rootfs": {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
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
            image = provision.create_oci_layout(rootfs_tar, layout, "fixture", self.contract["environment"])

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
                "profile": {"id": "fixture"}, "environment": self.contract["environment"],
                "rootfs": {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
                "image": {**image, "manifestSha256": manifest_sha256,
                          "imageDigest": "sha256:" + manifest_sha256},
                "imageArtifact": {"bytes": archive_path.stat().st_size,
                                  "sha256": provision.sha256_file(archive_path)},
            }
            with self.assertRaisesRegex(provision.ProvisionError, "config descriptor size differs"):
                provision.verify_oci_archive(archive_path, record, 1024 * 1024)


class RecipeAndCandidateBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = provision.read_contract()
        cls.temp_root = ROOT / "build/clang1813-binding-tests"
        cls.temp_root.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_root, ignore_errors=True)

    def temporary_directory(self):
        return tempfile.TemporaryDirectory(dir=self.temp_root)

    def valid_build_record(self):
        return ProvisioningNegativeTests.valid_build_record(self)

    def candidate_fixture(self, base):
        root = base / "acquisition"
        root.mkdir()
        keyring = base / "ubuntu-keyring.gpg"
        keyring.write_bytes(b"synthetic keyring; signatures are mocked")

        def artifact(relative):
            payload = ("synthetic bytes for " + relative).encode()
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            return {"path": relative, "bytes": len(payload), "sha256": provision.sha256(payload)}

        profile = self.contract["profile"]
        repositories, indexes = [], []
        for suite in profile["suites"]:
            repositories.append({
                "suite": suite,
                "inRelease": {**artifact(f"downloads/{suite}/InRelease"),
                              "finalUrl": f"{profile['snapshotBase']}dists/{suite}/InRelease"},
                "signerPrimaryFingerprint": profile["ubuntuArchivePrimaryFingerprints"][0],
            })
            for component in profile["components"]:
                for kind in ("source", "binary-amd64"):
                    indexes.append({**artifact(f"downloads/{suite}/{component}/{kind}/index.gz"),
                                    "suite": suite, "component": component, "kind": kind})
        package_source = root / "source/package-source"
        upstream_source = root / "source/upstream/llvm-project-18.1.3.src"
        (package_source / "debian/patches").mkdir(parents=True)
        (package_source / "debian/patches/series").write_bytes(b"")
        for relative in self.contract["relevantFiles"]:
            for source_root in (package_source, upstream_source):
                path = source_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"matching synthetic source\n")
        audit = provision.audit_patches(package_source, upstream_source, root / "patch-audit.json", self.contract)
        candidate = {
            "schemaVersion": 1, "status": "authenticated-candidate-awaiting-repository-lock-review",
            "profileId": profile["id"], "snapshot": profile["snapshot"],
            "trustedKeyring": {"bytes": keyring.stat().st_size, "sha256": provision.sha256_file(keyring)},
            "repositories": repositories, "indexes": indexes,
            "source": {
                **profile["sourcePackage"],
                "files": [{**artifact("downloads/source/source.dsc"), "name": "source.dsc"}],
                "upstreamArchive": artifact("downloads/upstream/source.tar.xz"),
                "upstreamArchivePath": "downloads/upstream/source.tar.xz",
                "upstreamSignature": artifact("downloads/upstream/source.tar.xz.sig"),
                "upstreamSignaturePath": "downloads/upstream/source.tar.xz.sig",
                "upstreamKeyring": artifact("downloads/upstream/llvm-release-keyring.gpg"),
            },
            "patchAudit": {key: audit[key] for key in (
                "status", "patchCount", "patchInventorySha256", "relevantFileCount", "relevantFileManifestSha256")},
            "binaryRoots": sorted(profile["binaryRoots"], key=lambda row: row["name"]),
            "downloadedBytes": 1,
        }
        self.write_candidate(root, candidate)
        record = self.valid_build_record()
        record.update(provision.candidate_build_evidence(candidate, self.contract))
        record["commands"] = provision.canonical_commands(self.contract, candidate["trustedKeyring"]["sha256"])
        return root, candidate, record, keyring

    def write_candidate(self, root, candidate):
        candidate.pop("candidateSha256", None)
        candidate["candidateSha256"] = provision.sha256(provision.canonical_json(candidate))
        (root / "acquisition-candidate.json").write_bytes(provision.canonical_json(candidate))

    def test_recipe_hashes_selected_contract_bytes_and_preserves_other_recipe_files(self):
        with self.temporary_directory() as temp:
            selected = Path(temp) / "custom-contract.json"
            contract = json.loads(json.dumps(self.contract))
            contract["environment"]["PATH"] = "/custom/bin"
            selected.write_bytes(provision.canonical_json(contract))
            actual = provision.recipe_identity(selected)
            default = provision.recipe_identity()
            self.assertNotEqual(actual["contractSha256"], default["contractSha256"])
            self.assertEqual(actual, {**default, "contractSha256": provision.sha256_file(selected)})
            record = self.valid_build_record()
            record["environment"] = contract["environment"]
            record["commands"] = provision.canonical_commands(contract, record["acquisition"]["ubuntuKeyring"]["sha256"])
            with self.assertRaisesRegex(provision.ProvisionError, "recipe hashes"):
                provision.validate_build_record(record, contract, selected)
            record["recipe"] = actual
            provision.validate_build_record(record, contract, selected)
            selected.write_bytes(selected.read_bytes() + b" ")
            with self.assertRaisesRegex(provision.ProvisionError, "recipe hashes"):
                provision.validate_build_record(record, contract, selected)

    def test_recipe_binds_production_a_loader_bytes_and_rejects_stale_records(self):
        loader = ROOT / "src/main/kotlin/decompengine/oracle/fulltree/FullTreeGenericTemplateFrontendProfileV1.kt"
        self.assertEqual(provision.RECIPE_FILES["aLoaderSha256"], loader)
        record = self.valid_build_record()
        self.assertEqual(record["recipe"]["aLoaderSha256"], provision.sha256_file(loader))
        provision.validate_build_record(record, self.contract)
        with self.temporary_directory() as temp:
            changed_loader = Path(temp) / loader.name
            changed_loader.write_bytes(loader.read_bytes() + b"\n// changed loader semantics\n")
            with mock.patch.dict(provision.RECIPE_FILES, {"aLoaderSha256": changed_loader}):
                with self.assertRaisesRegex(provision.ProvisionError, "recipe hashes"):
                    provision.validate_build_record(record, self.contract)
        del record["recipe"]["aLoaderSha256"]
        with self.assertRaisesRegex(provision.ProvisionError, "recipe hashes"):
            provision.validate_build_record(record, self.contract)

    def test_record_commands_propagate_selected_contract_to_verification(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            selected, record_path = base / "contract.json", base / "record.json"
            selected.write_bytes(provision.canonical_json(self.contract))
            record_path.write_bytes(provision.canonical_json(self.valid_build_record()))
            commands = (provision.command_verify_record, provision.command_write_loader_input,
                        provision.command_verify_image, provision.command_package_provenance)
            for command in commands:
                args = provision.argparse.Namespace(contract=selected, record=record_path)
                with self.subTest(command=command.__name__), mock.patch.object(
                    provision, "validate_build_record", side_effect=provision.ProvisionError("stop before work")
                ) as validate:
                    with self.assertRaisesRegex(provision.ProvisionError, "stop before work"):
                        command(args)
                    self.assertEqual(validate.call_args.args[2], selected)

    def test_compare_runs_and_metadata_report_bind_selected_contract(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            selected = base / "contract.json"
            selected.write_bytes(provision.canonical_json(self.contract))
            record = self.valid_build_record()
            record["recipe"] = provision.recipe_identity(selected)
            first, second = base / "first.json", base / "second.json"
            first.write_bytes(provision.canonical_json(record))
            second.write_bytes(provision.canonical_json(record))
            args = provision.argparse.Namespace(contract=selected, first=first, second=second,
                                               output=base / "final.json")
            self.assertEqual(provision.command_compare_runs(args), 0)
            self.assertEqual(json.loads(args.output.read_bytes())["recipe"], record["recipe"])
            keyring = base / "keyring"
            keyring.write_bytes(b"fixture")
            report = provision.snapshot_metadata_selection(
                self.contract, self.contract["profile"], [], [], [], [], 0, keyring, selected)
            self.assertEqual(report["contractSha256"], provision.sha256_file(selected))
            self.assertEqual(report["recipe"], record["recipe"])

    def test_candidate_replay_accepts_bound_evidence_and_cleans_temporary_audit(self):
        with self.temporary_directory() as temp:
            root, candidate, record, keyring = self.candidate_fixture(Path(temp))
            with mock.patch.object(provision, "verify_candidate_data", return_value=[]) as signed:
                actual, parsed = provision.load_candidate(root, self.contract, keyring, record)
            self.assertEqual(actual, candidate)
            self.assertEqual(parsed, [])
            signed.assert_called_once_with(root, candidate, self.contract, keyring)
            self.assertEqual(list(root.glob("patch-audit-replay-*")), [])

    def test_candidate_replay_rejects_stale_self_digest_and_different_candidate(self):
        with self.temporary_directory() as temp:
            root, candidate, record, keyring = self.candidate_fixture(Path(temp))
            candidate["downloadedBytes"] += 1
            (root / "acquisition-candidate.json").write_bytes(provision.canonical_json(candidate))
            with self.assertRaisesRegex(provision.ProvisionError, "self-digest mismatch"):
                provision.load_candidate(root, self.contract, keyring, record)
            self.write_candidate(root, candidate)
            with self.assertRaisesRegex(provision.ProvisionError, "acquisition differs from the build record"):
                provision.load_candidate(root, self.contract, keyring, record)

    def test_candidate_replay_rejects_unrelated_record_sections(self):
        with self.temporary_directory() as temp:
            root, candidate, record, keyring = self.candidate_fixture(Path(temp))
            for section, field in (("acquisition", "sourceIndexesSha256"),
                                   ("acquisition", "binaryIndexesSha256"),
                                   ("source", "dsc"), ("patchAudit", "patchInventorySha256")):
                changed = json.loads(json.dumps(record))
                changed[section][field] = "f" * 64
                with self.subTest(section=section, field=field), self.assertRaisesRegex(
                    provision.ProvisionError, f"{section} differs from the build record"
                ):
                    provision.load_candidate(root, self.contract, keyring, changed)

    def test_candidate_download_inventory_rejects_changed_missing_extra_and_symlink_files(self):
        for mutation in ("same-size", "length", "missing", "extra", "symlink"):
            with self.subTest(mutation=mutation), self.temporary_directory() as temp:
                root, candidate, record, keyring = self.candidate_fixture(Path(temp))
                path = root / candidate["source"]["upstreamArchivePath"]
                if mutation == "same-size":
                    path.write_bytes(b"x" * path.stat().st_size)
                elif mutation == "length":
                    path.write_bytes(path.read_bytes() + b"x")
                elif mutation == "missing":
                    path.unlink()
                elif mutation == "extra":
                    (root / "downloads/unrecorded.txt").write_bytes(b"unrelated evidence")
                else:
                    path.unlink()
                    path.symlink_to(keyring)
                with mock.patch.object(provision, "verify_candidate_data") as signed:
                    with self.assertRaises(provision.ProvisionError):
                        provision.load_candidate(root, self.contract, keyring, record)
                    signed.assert_not_called()

    def test_candidate_replay_rejects_changed_patch_audit_and_source_tree(self):
        for mutation in ("audit", "audit-details", "source"):
            with self.subTest(mutation=mutation), self.temporary_directory() as temp:
                root, candidate, record, keyring = self.candidate_fixture(Path(temp))
                if mutation in ("audit", "audit-details"):
                    path = root / "patch-audit.json"
                    audit = json.loads(path.read_bytes())
                    if mutation == "audit":
                        audit["patchInventorySha256"] = "f" * 64
                    else:
                        audit["patchInventory"] = []
                    path.write_bytes(provision.canonical_json(audit))
                else:
                    relative = self.contract["relevantFiles"][0]
                    (root / "source/package-source" / relative).write_bytes(b"changed source")
                with mock.patch.object(provision, "verify_candidate_data", return_value=[]):
                    with self.assertRaises(provision.ProvisionError):
                        provision.load_candidate(root, self.contract, keyring, record)
                self.assertEqual(list(root.glob("patch-audit-replay-*")), [])

    def test_packaging_authenticates_candidate_before_creating_archive(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            root, candidate, record, keyring = self.candidate_fixture(base)
            record_path = base / "record.json"
            record_path.write_bytes(provision.canonical_json(record))
            args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH, record=record_path,
                                               acquisition=root, keyring=keyring, output=base / "provenance.tar")
            with mock.patch.object(provision, "verify_candidate_data",
                                   side_effect=provision.ProvisionError("signature rejected")) as signed:
                with self.assertRaisesRegex(provision.ProvisionError, "signature rejected"):
                    provision.command_package_provenance(args)
                signed.assert_called_once_with(root, candidate, self.contract, keyring)
            self.assertFalse(args.output.exists())

    def test_packaging_accepts_bound_local_evidence_and_selected_contract(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            root, candidate, record, keyring = self.candidate_fixture(base)
            selected = base / "selected-contract.json"
            selected.write_bytes(provision.canonical_json(self.contract))
            record["recipe"] = provision.recipe_identity(selected)
            record["probe"]["fixtureSha256"] = provision.sha256_file(
                ROOT / self.contract["negativeControl"]["fixture"])
            record_path = base / "record.json"
            record_path.write_bytes(provision.canonical_json(record))
            record_sha = provision.sha256_file(record_path)
            resources = record["resources"]
            loader = {
                "scope": "infrastructure-loader-smoke-only", "buildRecordSha256": record_sha,
                "imageDigest": record["image"]["imageDigest"],
                "resourceDirectory": "toolchain" + record["resourceDirectory"],
                "resourceFileCount": resources["entryCount"],
                "resourceTreeBytes": sum(row["bytes"] for row in resources["entries"]),
                "resourceManifestSha256": provision.frontend_resource_manifest_sha256(
                    record["resourceDirectory"], resources),
                "cxxDriverIdentitySha256": provision.frontend_cxx_driver_identity_sha256(record, record_sha),
                "infrastructureProfileProjectionSha256": "c" * 64, "pathTransformSha256": "d" * 64,
                **{field: True for field in (
                    "rejectedWrongImage", "rejectedWrongCxxDriverBytes", "rejectedChangedResourceIdentity",
                    "rejectedChangedRuntimeLibraryIdentity", "rejectedMissingResourceDirectory")},
            }
            negative_contract = self.contract["negativeControl"]
            lock_path = ROOT / negative_contract["artifactLock"]
            artifact = json.loads(lock_path.read_bytes())["artifacts"][negative_contract["artifactRole"]]
            fixture = ROOT / negative_contract["fixture"]
            negative = {
                "scope": "negative-version-gate-only; not a Clang 18.1.3 identity",
                "artifactOracleId": negative_contract["oracleId"],
                "artifactLockSha256": provision.sha256_file(lock_path),
                "compilerBytes": artifact["bytes"], "compilerSha256": artifact["sha256"],
                "compilerVersionOutput": "clang version 22.1.6",
                "fixtureBytes": fixture.stat().st_size, "fixtureSha256": provision.sha256_file(fixture),
                "fixtureAcceptedByClang22": True,
                "compiler18GateRejected": "probe compiler version or target mismatch",
            }
            report_paths = {}
            for name, report in (("probe_report", record["probe"]), ("loader_report", loader),
                                 ("negative_report", negative)):
                report_paths[name] = base / f"{name}.json"
                report_paths[name].write_bytes(provision.canonical_json(report))
            args = provision.argparse.Namespace(contract=selected, record=record_path, acquisition=root,
                                               keyring=keyring, output=base / "provenance.tar", **report_paths)
            with mock.patch.object(provision, "verify_candidate_data", return_value=[]) as signed, \
                    mock.patch.object(provision.BoundedDownloader, "get") as network:
                self.assertEqual(provision.command_package_provenance(args), 0)
                signed.assert_called_once_with(root, candidate, self.contract, keyring)
                network.assert_not_called()
            with tarfile.open(args.output) as archive:
                self.assertEqual(archive.extractfile("provisioning-contract.json").read(), selected.read_bytes())
                self.assertEqual(archive.extractfile("build-record.schema.json").read(),
                                 provision.RECIPE_FILES["schemaSha256"].read_bytes())
                loader_path = "src/main/kotlin/decompengine/oracle/fulltree/FullTreeGenericTemplateFrontendProfileV1.kt"
                loader_bytes = archive.extractfile(loader_path).read()
                self.assertEqual(loader_bytes, (ROOT / loader_path).read_bytes())
                self.assertEqual(provision.sha256(loader_bytes), record["recipe"]["aLoaderSha256"])
                self.assertEqual(archive.extractfile("acquisition/acquisition-candidate.json").read(),
                                 (root / "acquisition-candidate.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
