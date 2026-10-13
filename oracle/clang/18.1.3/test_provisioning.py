import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/oracle"))
import provision_clang_18_1_3 as provision


def signed_package_rows_for_fixture(record):
    rows = {}
    for section in ("packages", "downloadedPackages"):
        for package in record[section]:
            key = (package["name"], package["version"], package["architecture"])
            rows[key] = {
                "Package": package["name"], "Version": package["version"],
                "Architecture": package["architecture"], "Filename": package["file"],
                "Size": str(package["bytes"]), "SHA256": package["sha256"],
                "_suite": package["suite"], "_component": package["component"],
            }
    return list(rows.values())


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
        file_manifest = provision.manifest([
            {"path": "/usr/lib/llvm-18/lib/libclang-cpp.so", "bytes": 1, "sha256": digest,
             "kind": "regular-file", "target": None},
            {"path": "/usr/lib/llvm-18/lib/libLLVM-18.so", "bytes": 2, "sha256": "b" * 64,
             "kind": "regular-file", "target": None},
            {"path": "/usr/lib/llvm-18/lib/libclang.so", "bytes": 3, "sha256": "c" * 64,
             "kind": "regular-file", "target": None},
        ])
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

    def prepare_runtime_rootfs(self, record, rootfs):
        rootfs.mkdir(parents=True, exist_ok=True)
        compiler = next(tool for tool in record["tools"] if tool["role"] == "cxx-driver")
        original_compiler_sha = compiler["sha256"]
        for row in record["runtime"]["entries"]:
            if row["kind"] != "regular-file":
                continue
            payload = (b"synthetic compiler/runtime bytes" if row["sha256"] == original_compiler_sha
                       else ("synthetic runtime bytes: " + row["path"]).encode())
            path = rootfs / row["path"].lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            if row["sha256"] == original_compiler_sha:
                compiler["bytes"] = len(payload)
                compiler["sha256"] = provision.sha256(payload)
        for row in record["runtime"]["entries"]:
            if row["kind"] != "symlink":
                continue
            path = rootfs / row["path"].lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(row["target"])
        record["runtime"] = provision.manifest([
            provision.runtime_file_entry(rootfs, row["path"]) for row in record["runtime"]["entries"]
        ])

    def valid_loader_report(self, record, record_sha, rootfs):
        provision.verified_frontend_runtime_library_digests(rootfs, record)
        projection = provision.frontend_profile_projection_preimage(record, record_sha)
        return {
            "scope": "infrastructure-loader-smoke-only",
            "buildRecordSha256": record_sha,
            "imageDigest": record["image"]["imageDigest"],
            "resourceDirectory": "toolchain" + record["resourceDirectory"],
            "resourceFileCount": record["resources"]["entryCount"],
            "resourceTreeBytes": sum(row["bytes"] for row in record["resources"]["entries"]),
            "resourceManifestSha256": provision.frontend_resource_manifest_sha256(
                record["resourceDirectory"], record["resources"]),
            "infrastructureProfileProjectionSha256": provision.frontend_profile_projection_sha256(projection),
            "infrastructureProfileProjection": projection,
            "pathTransformSha256": provision.frontend_path_transform_sha256(record),
            "cxxDriverIdentitySha256": provision.frontend_cxx_driver_identity_sha256(record, record_sha),
            **{field: True for field in (
                "rejectedWrongImage", "rejectedWrongCxxDriverBytes", "rejectedChangedResourceIdentity",
                "rejectedChangedRuntimeLibraryIdentity", "rejectedMissingResourceDirectory")},
        }

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
        self.assertIn("needs: offline-validation", qualify_text)
        self.assertIn("if: ${{ needs.offline-validation.result == 'success' && "
                      "needs.offline-validation.outputs.acquisition_enabled == 'true' && "
                      "(github.event_name != 'workflow_dispatch' || inputs.mode == 'full-qualification') }}",
                      qualify_text)
        trigger_text = workflow[:workflow.index("permissions:")]
        for dependency in (
                "oracle/llvm/22.1.6/release-artifacts.json",
                "oracle/llvm/22.1.6/oracle-manifest.json",
                "oracle/llvm/22.1.6/keys/douglas-yung-llvm-release.asc"):
            self.assertEqual(trigger_text.count(f"'{dependency}'"), 2)
        self.assertLess(qualify_text.index("Authenticate Ubuntu Snapshot source and patch compatibility first"),
                        qualify_text.index('bash scripts/install-frontend-node.sh'))
        self.assertEqual(qualify_text.count('-PfrontendNodeHome="$CLANG_WORK/frontend-node"'),
                         qualify_text.count('./gradlew'))
        self.assertLess(qualify_text.index('bash scripts/install-frontend-node.sh'), qualify_text.index('./gradlew'))
        self.assertIn('--rootfs "$CLANG_WORK/rootfs-run2"', qualify_text)
        self.assertLess(qualify_text.index("package-provenance"),
                        qualify_text.index('sudo rm -rf "$CLANG_WORK/rootfs-run2"'))
        self.assertIn('--oci-archive "$CLANG_WORK/run2/clang-18.1.3-noble-amd64.oci.tar"',
                      qualify_text)
        self.assertLess(qualify_text.index("package-provenance"),
                        qualify_text.index('rm "$CLANG_WORK/run2/clang-18.1.3-noble-amd64.oci.tar"'))

    def test_workflow_offline_job_gates_native_setup_without_suppressing_failures(self):
        workflow = (ROOT / ".github/workflows/generic-template-toolchain.yml").read_text(encoding="utf-8")
        offline = re.search(r"(?ms)^  offline-validation:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", workflow).group(1)
        self.assertIn("acquisition_enabled: ${{ steps.acquisition_status.outputs.acquisition_enabled }}", offline)
        self.assertIn('"acquisition-status"', offline)
        self.assertIn("run: python3 -m unittest discover -s oracle/clang/18.1.3 -p 'test_*.py' -v", offline)
        self.assertNotIn("continue-on-error", workflow)
        self.assertNotIn("if:", offline)
        for costly_setup in ("setup-java", "setup-gradle", "apt-get", "./gradlew", "install-frontend-node"):
            self.assertNotIn(costly_setup, offline)
        self.assertNotIn(" || ", offline)
        self.assertNotIn("always()", offline)

    def test_workflow_status_report_accepts_prerequisite_fixtures_without_claiming_qualification(self):
        workflow = (ROOT / ".github/workflows/generic-template-toolchain.yml").read_text(encoding="utf-8")
        offline = re.search(r"(?ms)^  offline-validation:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", workflow).group(1)
        source = textwrap.dedent(re.search(r"python3 - <<'PY'\n(.*?)          PY\n", offline, re.DOTALL).group(1))
        for enabled in (False, True):
            # The enabled branch is only a mocked status fixture, never acquisition permission.
            with mock.patch.object(provision, "UPSTREAM_SIGNATURE_ACCESS_ENABLED", enabled):
                status = provision.acquisition_status()
            with self.subTest(enabled=enabled), self.temporary_directory() as temp:
                output, summary = Path(temp) / "outputs", Path(temp) / "summary"
                with mock.patch.dict(provision.os.environ, {"GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary)}), \
                        mock.patch.object(provision.subprocess, "run", return_value=mock.Mock(stdout=json.dumps(status))) as run, \
                        mock.patch.object(provision.sys, "stdout", io.StringIO()):
                    exec(compile(source, "<workflow-acquisition-status>", "exec"), {})
                self.assertEqual(output.read_text(), f"acquisition_enabled={str(enabled).lower()}\n")
                self.assertIn("**INCOMPLETE**", summary.read_text())
                self.assertIn("**NOT-RUN**" if enabled else "**SKIPPED**", summary.read_text())
                self.assertIn(status["reason"], summary.read_text())
                self.assertEqual(run.call_args.args[0][-1], "acquisition-status")
                self.assertTrue(run.call_args.kwargs["check"])
        for changes in ({"acquisitionEnabled": "true"}, {"qualified": True},
                        {"acceptanceStatus": "accepted"}, {"nativeQualification": "passed"}):
            status = {**provision.acquisition_status(), **changes}
            with self.subTest(changes=changes), mock.patch.object(
                provision.subprocess, "run", return_value=mock.Mock(stdout=json.dumps(status))
            ), self.assertRaises(SystemExit):
                exec(compile(source, "<workflow-acquisition-status>", "exec"), {})

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

    def test_selected_archive_keyring_is_installed_and_bound_to_https_sources(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = base / "rootfs"
            keyring = base / "selected archive-keyring.gpg"
            payload = b"synthetic selected Ubuntu archive keyring bytes"
            keyring.write_bytes(payload)
            (rootfs / "usr/share/keyrings").mkdir(parents=True)

            def install(command, timeout=None):
                shutil.copyfile(command[-2], command[-1])
                Path(command[-1]).chmod(0o644)
                return mock.Mock(stdout="")

            with mock.patch.object(provision, "run_checked", side_effect=install) as run:
                installed = provision.install_selected_archive_keyring(rootfs, keyring, provision.sha256(payload))
            self.assertEqual(installed.read_bytes(), payload)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o644)
            self.assertEqual(run.call_args.args[0], [
                "sudo", "install", "-m", "0644", str(keyring), str(installed),
            ])
            with mock.patch.object(provision, "run_checked") as run:
                with self.assertRaisesRegex(provision.ProvisionError, "selected Ubuntu archive keyring bytes"):
                    provision.install_selected_archive_keyring(rootfs, keyring, "f" * 64)
                run.assert_not_called()

        sources = provision.apt_source_list(self.contract).decode("utf-8")
        self.assertIn(f"signed-by={provision.APT_KEYRING_IN_ROOT}", sources)
        self.assertNotIn("signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg", sources)
        digest = "a" * 64
        commands = provision.canonical_commands(self.contract, digest)
        self.assertEqual(commands["installAptKeyring"], [
            "sudo", "install", "-m", "0644", f"<UBUNTU_ARCHIVE_KEYRING_SHA256:{digest}>",
            f"<PROFILE_ROOT>{provision.APT_KEYRING_IN_ROOT}",
        ])
        self.assertEqual(commands["writeAptSources"][4],
                         f"<SOURCE_LIST_SHA256:{provision.sha256(provision.apt_source_list(self.contract))}>")

    def test_selected_archive_keyring_install_precedes_first_apt_command(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            keyring = base / "selected.gpg"
            keyring.write_bytes(b"selected bytes")
            rootfs = base / "rootfs"
            events = []

            def bootstrap(command, timeout=None):
                rootfs.mkdir(parents=True)
                (rootfs / "usr/share/keyrings").mkdir(parents=True)
                (rootfs / "etc/apt").mkdir(parents=True)
                (rootfs / "etc/ssl/certs").mkdir(parents=True)
                (rootfs / "etc/ssl/certs/ca-certificates.crt").write_bytes(b"synthetic CA bundle")
                return mock.Mock(stdout="")

            def run_checked(command, timeout=None):
                if "debootstrap" in command:
                    return bootstrap(command, timeout)
                if command[1:4] == ["install", "-m", "0644"]:
                    source, destination = Path(command[-2]), Path(command[-1])
                    shutil.copyfile(source, destination)
                    destination.chmod(0o644)
                    events.append("selected-keyring" if destination.name == Path(provision.APT_KEYRING_IN_ROOT).name
                                  else "source-list")
                    return mock.Mock(stdout="")
                raise AssertionError(command)

            def rootfs_run(root, command, contract, **kwargs):
                events.append("apt-update")
                raise provision.ProvisionError("stop before package fetch")

            args = provision.argparse.Namespace(
                contract=provision.CONTRACT_PATH, workdir=base, rootfs=rootfs,
                output=base / "output", acquisition=base / "acquisition", keyring=keyring, label="fixture",
            )
            candidate = {"trustedKeyring": {"sha256": provision.sha256_file(keyring)}}
            packages = {("ca-certificates", "synthetic", "all")}
            with mock.patch.object(provision, "load_candidate", return_value=(candidate, [])), \
                    mock.patch.object(provision.shutil, "rmtree"), \
                    mock.patch.object(provision, "check_runner_bounds"), \
                    mock.patch.object(provision, "run_checked", side_effect=run_checked), \
                    mock.patch.object(provision, "installed_package_keys", return_value=packages), \
                    mock.patch.object(provision, "rootfs_run", side_effect=rootfs_run), \
                    mock.patch.object(provision.BoundedDownloader, "get") as network:
                with self.assertRaisesRegex(provision.ProvisionError, "stop before package fetch"):
                    provision.provision_rootfs(args)
            self.assertEqual(events, ["selected-keyring", "source-list", "apt-update"])
            self.assertEqual((rootfs / Path(provision.APT_KEYRING_IN_ROOT).relative_to("/")).read_bytes(),
                             keyring.read_bytes())
            self.assertIn(f"signed-by={provision.APT_KEYRING_IN_ROOT}",
                          (rootfs / "etc/apt/sources.list").read_text(encoding="utf-8"))
            network.assert_not_called()

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

    def test_build_record_rejects_schema_disallowed_top_level_and_nested_fields(self):
        mutations = (
            ("top-level", lambda record: record.update(acceptanceStatus="accepted"), False),
            ("profile", lambda record: record["profile"].update(unreviewed=True), True),
            ("package", lambda record: (record["packages"][0].update(unreviewed=True),
                                         record["downloadedPackages"][0].update(unreviewed=True)), False),
            ("runtime entry", lambda record: record["runtime"]["entries"][0].update(unreviewed=True), False),
            ("image", lambda record: record["image"].update(acceptanceStatus="accepted"), False),
            ("probe", lambda record: record["probe"]["macroObservations"].update(accepted=True), False),
        )
        for label, mutate, schema_only in mutations:
            record = self.valid_build_record()
            mutate(record)
            if label == "runtime entry" and not schema_only:
                record["runtime"].update(provision.manifest(record["runtime"]["entries"]))
            with self.subTest(location=label), self.assertRaisesRegex(
                provision.ProvisionError, r"checked-in schema.*unknown field",
            ):
                if schema_only:
                    provision.reject_build_record_schema_unknown_fields(record)
                else:
                    provision.validate_build_record(record, self.contract)

    def test_rootfs_archive_budget_fails_before_writing_when_walk_cannot_read_a_subtree(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = base / "rootfs"
            rootfs.mkdir()
            archive = base / "rootfs.tar"

            def denied_walk(root, followlinks=False, onerror=None):
                error = PermissionError("unreadable retained rootfs subtree")
                if onerror is not None:
                    onerror(error)
                return iter(())

            with mock.patch.object(provision.os, "walk", side_effect=denied_walk), \
                    mock.patch.object(provision, "run_checked") as tar:
                with self.assertRaisesRegex(provision.ProvisionError, "could not inspect retained rootfs"):
                    provision.deterministic_rootfs_tar(rootfs, archive, 0, normalize=False, max_bytes=1024 * 1024)
                tar.assert_not_called()
            self.assertFalse(archive.exists())

    def test_rootfs_archive_preserves_numeric_package_ownership(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = base / "rootfs"
            rootfs.mkdir()
            package_file = rootfs / "usr/bin/package-owned"
            package_file.parent.mkdir(parents=True)
            package_file.write_bytes(b"synthetic package file")
            expected_owner = package_file.stat()
            destination = base / "rootfs.tar"

            def local_tar(command, timeout=None):
                self.assertNotIn("--owner=0", command)
                self.assertNotIn("--group=0", command)
                subprocess.run(command[1:], check=True)
                return mock.Mock(stdout="")

            with mock.patch.object(provision, "normalize_rootfs"), \
                    mock.patch.object(provision, "run_checked", side_effect=local_tar) as run:
                provision.deterministic_rootfs_tar(rootfs, destination, 1714003200)
            command = run.call_args.args[0]
            self.assertIn("--numeric-owner", command)
            self.assertFalse(any(arg.startswith("--owner=") or arg.startswith("--group=") for arg in command))
            with tarfile.open(destination, "r:") as archive:
                member = archive.getmember("./usr/bin/package-owned")
                self.assertEqual((member.uid, member.gid), (expected_owner.st_uid, expected_owner.st_gid))

    def test_build_record_commands_bind_keyring_environment_and_package_pins(self):
        record = self.valid_build_record()
        commands = record["commands"]
        digest = record["acquisition"]["ubuntuKeyring"]["sha256"]
        self.assertIn(f"--keyring=<UBUNTU_ARCHIVE_KEYRING_SHA256:{digest}>", commands["debootstrap"])
        self.assertIn(f"<UBUNTU_ARCHIVE_KEYRING_SHA256:{digest}>", commands["installAptKeyring"])
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
            with mock.patch.object(provision, "rootfs_run", return_value="") as ldd:
                rows = provision.runtime_dependencies(rootfs, [], self.contract)
            self.assertEqual([call.args[1] for call in ldd.call_args_list], [
                ["/usr/bin/ldd", "/usr/lib/llvm-18/lib/libclang-cpp.so"],
                ["/usr/bin/ldd", "/usr/lib/llvm-18/lib/libLLVM-18.so"],
            ])
            by_path = {row["path"]: row for row in rows}
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so.18.1"]["sha256"],
                             provision.sha256(b"clang library"))
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so"]["sha256"],
                             provision.sha256(b"symlink\0libclang-cpp.so.18.1"))
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so"]["kind"], "symlink")
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so"]["target"], "libclang-cpp.so.18.1")
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so.18.1"]["kind"], "regular-file")
            self.assertIsNone(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so.18.1"]["target"])
            record = {
                "tools": [{"role": "cxx-driver", "sha256": provision.sha256(b"clang library")}],
                "runtime": provision.manifest(rows),
            }
            self.assertEqual(provision.verified_frontend_runtime_library_digests(rootfs, record), [{
                "path": "toolchain/usr/lib/llvm-18/lib/libLLVM-18.so.1",
                "sha256": provision.sha256(b"llvm library"),
            }])

    def test_loader_projection_rejects_rehashed_runtime_omissions_extra_duplicate_and_order_changes(self):
        record = self.valid_build_record()
        target = "libclang-cpp.so.18.1"
        record["runtime"] = provision.manifest([
            {"path": "/usr/lib/llvm-18/lib/libLLVM-18.so.1", "bytes": 2, "sha256": "b" * 64,
             "kind": "regular-file", "target": None},
            {"path": "/usr/lib/llvm-18/lib/libclang-cpp.so.18.1", "bytes": 3, "sha256": "c" * 64,
             "kind": "regular-file", "target": None},
            {"path": "/usr/lib/llvm-18/lib/libclang-cpp.so", "bytes": len(target),
             "sha256": provision.sha256(b"symlink\0" + target.encode()), "kind": "symlink", "target": target},
        ])
        rootfs = Path(self.temp_root) / "rehashed-runtime-rootfs"
        shutil.rmtree(rootfs, ignore_errors=True)
        self.prepare_runtime_rootfs(record, rootfs)
        record_sha = provision.sha256(provision.canonical_json(record))
        report = self.valid_loader_report(record, record_sha, rootfs)
        expected_rows = [
            {"path": "toolchain/usr/lib/llvm-18/lib/libLLVM-18.so.1",
             "sha256": provision.sha256(b"synthetic runtime bytes: /usr/lib/llvm-18/lib/libLLVM-18.so.1")},
            {"path": "toolchain/usr/lib/llvm-18/lib/libclang-cpp.so.18.1",
             "sha256": provision.sha256(b"synthetic runtime bytes: /usr/lib/llvm-18/lib/libclang-cpp.so.18.1")},
        ]
        self.assertEqual(report["infrastructureProfileProjection"]["runtimeLibraryDigests"], expected_rows)
        provision.validate_provenance_loader_report(report, record, record_sha, rootfs)
        symlink = next(row for row in record["runtime"]["entries"] if row["kind"] == "symlink")
        mutations = {
            "omitted": expected_rows[:1],
            "extra": [*expected_rows, {"path": "toolchain/usr/lib/llvm-18/lib/unrecorded.so", "sha256": "d" * 64}],
            "duplicate": [*expected_rows, expected_rows[-1]],
            "reordered": list(reversed(expected_rows)),
            "symlink-added": [*expected_rows, {"path": "toolchain" + symlink["path"], "sha256": symlink["sha256"]}],
            "wrong-bytes": [expected_rows[0], {**expected_rows[1], "sha256": "d" * 64}],
        }
        for label, rows in mutations.items():
            changed = json.loads(json.dumps(report))
            projection = changed["infrastructureProfileProjection"]
            projection["runtimeLibraryDigests"] = rows
            changed["infrastructureProfileProjectionSha256"] = provision.frontend_profile_projection_sha256(projection)
            with self.subTest(label=label), self.assertRaisesRegex(provision.ProvisionError, "projection differs"):
                provision.validate_provenance_loader_report(changed, record, record_sha, rootfs)

    def test_runtime_manifest_rejects_missing_classification_and_inconsistent_symlink_bytes(self):
        target = "library.so.1"
        baseline = provision.manifest([
            {"path": "/usr/lib/library.so.1", "bytes": 2, "sha256": "b" * 64,
             "kind": "regular-file", "target": None},
            {"path": "/usr/lib/library.so", "bytes": len(target),
             "sha256": provision.sha256(b"symlink\0" + target.encode()), "kind": "symlink", "target": target},
        ])
        provision.validated_runtime_entries(baseline)
        mutations = {
            "missing-kind": lambda rows: rows[0].pop("kind"),
            "missing-target": lambda rows: rows[0].pop("target"),
            "unknown-kind": lambda rows: rows[0].update(kind="unknown"),
            "regular-target": lambda rows: rows[1].update(target=target),
            "symlink-null-target": lambda rows: rows[0].update(target=None),
            "changed-target": lambda rows: rows[0].update(target="different.so"),
            "changed-size": lambda rows: rows[0].update(bytes=1),
            "changed-sha": lambda rows: rows[0].update(sha256="d" * 64),
            "nul-target": lambda rows: rows[0].update(target="bad\0target"),
            "surrogate-target": lambda rows: rows[0].update(target="\ud800"),
            "oversize-target": lambda rows: rows[0].update(target="x" * 4097),
            "duplicate": lambda rows: rows.append(dict(rows[-1])),
            "reordered": lambda rows: rows.reverse(),
            "unknown-field": lambda rows: rows[0].update(accepted=True),
        }
        for label, mutate in mutations.items():
            changed = json.loads(json.dumps(baseline))
            mutate(changed["entries"])
            with self.subTest(label=label), self.assertRaises(provision.ProvisionError):
                provision.validated_runtime_entries(changed)

    def test_recorded_runtime_rechecks_kind_targets_and_bytes_in_rootfs(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            directory = rootfs / "usr/lib"
            directory.mkdir(parents=True)
            library = directory / "library.so.1"
            library.write_bytes(b"library bytes")
            link = directory / "library.so"
            link.symlink_to("/usr/lib/library.so.1")
            rows = [provision.runtime_file_entry(rootfs, "/usr/lib/library.so.1"),
                    provision.runtime_file_entry(rootfs, "/usr/lib/library.so")]
            record = {"runtime": provision.manifest(rows)}
            provision.verify_recorded_runtime_manifest(rootfs, record)

            link.unlink()
            link.write_bytes(b"library bytes")
            with self.assertRaisesRegex(provision.ProvisionError, "classification or bytes changed"):
                provision.verify_recorded_runtime_manifest(rootfs, record)
            link.unlink()
            link.symlink_to("library.so.1")
            with self.assertRaisesRegex(provision.ProvisionError, "classification or bytes changed"):
                provision.verify_recorded_runtime_manifest(rootfs, record)
            link.unlink()
            link.symlink_to("/usr/lib/library.so.1")
            library.write_bytes(b"changed library bytes")
            with self.assertRaisesRegex(provision.ProvisionError, "classification or bytes changed"):
                provision.verify_recorded_runtime_manifest(rootfs, record)
            library.write_bytes(b"library bytes")
            duplicate = directory / "identical.so.1"
            duplicate.write_bytes(b"library bytes")
            library.unlink()
            library.symlink_to("identical.so.1")
            with self.assertRaisesRegex(provision.ProvisionError, "classification or bytes changed"):
                provision.verify_recorded_runtime_manifest(rootfs, record)

    def test_runtime_classification_preserves_resources_manifest_wire(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            file = rootfs / "usr/lib/library.so.1"
            file.parent.mkdir(parents=True)
            file.write_bytes(b"library bytes")
            self.assertEqual(set(provision.file_entry(rootfs, "/usr/lib/library.so.1")), {"path", "bytes", "sha256"})
            self.assertEqual(set(provision.runtime_file_entry(rootfs, "/usr/lib/library.so.1")),
                             {"path", "bytes", "sha256", "kind", "target"})

    def test_runtime_dependencies_retain_directory_aliases_without_projecting_them_as_libraries(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            llvm_lib = rootfs / "usr/lib/llvm-18/lib"
            llvm_lib.mkdir(parents=True)
            (llvm_lib / "libclang-cpp.so").write_bytes(b"clang library")
            (llvm_lib / "libLLVM-18.so").write_bytes(b"llvm library")
            libc = rootfs / "usr/lib/x86_64-linux-gnu/libc.so.6"
            libc.parent.mkdir(parents=True)
            libc.write_bytes(b"libc library")
            (rootfs / "lib").symlink_to("usr/lib")
            with mock.patch.object(provision, "rootfs_run", return_value="libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1234)"):
                rows = provision.runtime_dependencies(rootfs, ["/usr/bin/clang-18"], self.contract)
            by_path = {row["path"]: row for row in rows}
            self.assertEqual(by_path["/lib"], {
                "path": "/lib", "bytes": len("usr/lib"), "sha256": provision.sha256(b"symlink\0usr/lib"),
                "kind": "symlink", "target": "usr/lib",
            })
            self.assertEqual(by_path["/usr/lib/x86_64-linux-gnu/libc.so.6"]["kind"], "regular-file")
            record = self.valid_build_record()
            record["runtime"] = provision.manifest(rows)
            provision.verify_recorded_runtime_manifest(rootfs, record)
            self.assertEqual(len(provision.frontend_runtime_library_digests(record)), 3)
            self.assertNotIn("toolchain/lib", [row["path"] for row in provision.frontend_runtime_library_digests(record)])
            # Driver resolution still requires a regular file, even though runtime alias metadata permits directories.
            with self.assertRaisesRegex(provision.ProvisionError, "non-regular file"):
                provision.symlink_chain(rootfs, "/lib")

    def test_runtime_manifest_headers_and_projection_paths_match_schema_and_a_loader_bounds(self):
        entry = {"path": "/usr/lib/library.so.1", "bytes": 2, "sha256": "b" * 64,
                 "kind": "regular-file", "target": None}
        baseline = provision.manifest([entry])
        for field, value in (("entryCount", True), ("entryCount", 1.0), ("entryCount", 0),
                             ("bytes", float(baseline["bytes"])), ("bytes", False), ("bytes", 0)):
            changed = dict(baseline, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(provision.ProvisionError):
                provision.validated_runtime_entries(changed)
        exact_path = "/" + ("a" * 255 + "/") * 15 + "b" * 246
        self.assertEqual(len(("toolchain" + exact_path).encode()), 4096)
        provision.validated_runtime_entries(provision.manifest([{**entry, "path": exact_path}]))
        for path in (exact_path + "b", "/usr/lib/back\\slash.so", "/usr/lib/../library.so", "/usr//lib/library.so"):
            changed = provision.manifest([{**entry, "path": path}])
            with self.subTest(path=path), self.assertRaises(provision.ProvisionError):
                provision.validated_runtime_entries(changed)

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
            with mock.patch.object(provision, "rootfs_run", return_value=""):
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

        rootfs = Path(self.temp_root) / "loader-report-rootfs"
        shutil.rmtree(rootfs, ignore_errors=True)
        self.prepare_runtime_rootfs(record, rootfs)
        record_sha = "b" * 64
        loader_report = self.valid_loader_report(record, record_sha, rootfs)
        provision.validate_provenance_loader_report(loader_report, record, record_sha, rootfs)
        for field in ("cxxDriverIdentitySha256", "imageDigest", "resourceManifestSha256"):
            changed = dict(loader_report, **{field: "0" * 64})
            with self.subTest(field=field), self.assertRaises(provision.ProvisionError):
                provision.validate_provenance_loader_report(changed, record, record_sha, rootfs)
        for field in ("infrastructureProfileProjectionSha256", "pathTransformSha256"):
            digest = loader_report[field]
            wrong_digest = ("1" if digest[0] == "0" else "0") + digest[1:]
            changed = dict(loader_report, **{field: wrong_digest})
            with self.subTest(field=field), self.assertRaises(provision.ProvisionError):
                provision.validate_provenance_loader_report(changed, record, record_sha, rootfs)
        omitted = json.loads(json.dumps(loader_report))
        omitted_projection = omitted["infrastructureProfileProjection"]
        omitted_projection["runtimeLibraryDigests"].pop()
        omitted["infrastructureProfileProjectionSha256"] = provision.frontend_profile_projection_sha256(
            omitted_projection)
        with self.assertRaisesRegex(provision.ProvisionError, "frontend profile projection differs"):
            provision.validate_provenance_loader_report(omitted, record, record_sha, rootfs)
        added = json.loads(json.dumps(loader_report))
        added_projection = added["infrastructureProfileProjection"]
        added_projection["runtimeLibraryDigests"].append({
            "path": "toolchain/usr/lib/llvm-18/lib/unrecorded.so", "sha256": "d" * 64,
        })
        added["infrastructureProfileProjectionSha256"] = provision.frontend_profile_projection_sha256(
            added_projection)
        with self.assertRaisesRegex(provision.ProvisionError, "frontend profile projection differs"):
            provision.validate_provenance_loader_report(added, record, record_sha, rootfs)
        duplicated = json.loads(json.dumps(loader_report))
        duplicate_projection = duplicated["infrastructureProfileProjection"]
        duplicate_projection["runtimeLibraryDigests"].append(
            dict(duplicate_projection["runtimeLibraryDigests"][0]))
        duplicate_projection["runtimeLibraryDigests"].sort(key=lambda row: row["path"])
        duplicated["infrastructureProfileProjectionSha256"] = provision.frontend_profile_projection_sha256(
            duplicate_projection)
        with self.assertRaisesRegex(provision.ProvisionError, "frontend profile projection differs"):
            provision.validate_provenance_loader_report(duplicated, record, record_sha, rootfs)
        for field, changed_value in (("sha256", "0" * 64), ("bytes", 2), ("mode", "0755"),
                                     ("symlinkChain", ["/usr/bin/clang++-18 -> changed-target"])):
            changed_record = json.loads(json.dumps(record))
            next(row for row in changed_record["tools"] if row["role"] == "cxx-driver")[field] = changed_value
            with self.subTest(driver_field=field), self.assertRaisesRegex(provision.ProvisionError, "C\\+\\+ driver identity"):
                provision.validate_provenance_loader_report(loader_report, changed_record, record_sha, rootfs)
        loader_report["buildRecordSha256"] = "f" * 64
        with self.assertRaisesRegex(provision.ProvisionError, "does not bind the build record"):
            provision.validate_provenance_loader_report(loader_report, record, record_sha, rootfs)

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

        with self.temporary_directory() as temp:
            base = Path(temp)
            copied_lock = base / "release-artifacts.json"
            copied_manifest = base / "oracle-manifest.json"
            shutil.copyfile(lock_path, copied_lock)
            shutil.copyfile(lock_path.parent / "oracle-manifest.json", copied_manifest)
            negative_contract = self.contract["negativeControl"]
            lock_copy = json.loads(copied_lock.read_bytes())
            self.assertEqual(provision.validate_locked_comparator_manifest(copied_lock, negative_contract)[1],
                             copied_manifest)

            copied_manifest.write_bytes(copied_manifest.read_bytes() + b"\n")
            with self.assertRaisesRegex(provision.ProvisionError, "manifest digest differs from the release-artifacts lock"):
                provision.validate_locked_comparator_manifest(copied_lock, negative_contract)

            manifest_copy = json.loads((lock_path.parent / "oracle-manifest.json").read_bytes())
            manifest_copy["oracle"]["id"] = "unlocked-comparator"
            modified_manifest = provision.canonical_json(manifest_copy)
            copied_manifest.write_bytes(modified_manifest)
            lock_copy["oracle"]["artifactManifestSha256"] = provision.sha256(modified_manifest)
            copied_lock.write_bytes(provision.canonical_json(lock_copy))
            with self.assertRaisesRegex(provision.ProvisionError, "manifest oracle identity differs"):
                provision.validate_locked_comparator_manifest(copied_lock, negative_contract)

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

    def test_acquisition_status_is_read_only_and_cannot_be_enabled_by_environment(self):
        stdout = io.StringIO()
        with mock.patch.dict(provision.os.environ, {"UPSTREAM_SIGNATURE_ACCESS_ENABLED": "true",
                                                   "INPUT_ACQUISITION_ENABLED": "true",
                                                   "INPUT_MODE": "full-qualification"}), \
                mock.patch.object(provision.sys, "stdout", stdout), \
                mock.patch.object(provision, "read_contract") as contract, \
                mock.patch.object(provision.BoundedDownloader, "__init__") as downloader, \
                mock.patch.object(provision, "atomic_write") as write, \
                mock.patch.object(Path, "mkdir") as mkdir:
            self.assertEqual(provision.main(["acquisition-status"]), 0)
        status = json.loads(stdout.getvalue())
        self.assertEqual(status, {
            "schemaVersion": 1, "scope": "acquisition-prerequisite-status-only",
            "acquisitionEnabled": False, "acquisitionStatus": "paused",
            "nativeQualification": "skipped", "acceptanceStatus": "incomplete", "qualified": False,
            "reason": provision.ACQUISITION_PAUSE_REASON,
        })
        contract.assert_not_called()
        downloader.assert_not_called()
        write.assert_not_called()
        mkdir.assert_not_called()
        self.assertEqual(stdout.getvalue().encode(), provision.canonical_json(status))

    def test_acquisition_status_has_no_contract_output_or_enable_override(self):
        for extra in (["--contract", "unreviewed.json"], ["--output", "unrequested-output"], ["--enable"]):
            with self.subTest(extra=extra), mock.patch.object(provision.sys, "stderr", io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    provision.main(["acquisition-status", *extra])
                self.assertEqual(error.exception.code, 2)

    def test_direct_acquire_cli_fails_with_status_reason_before_reading_contract_or_creating_output(self):
        with self.temporary_directory() as temp:
            output = Path(temp) / "acquisition"
            stderr = io.StringIO()
            with mock.patch.dict(provision.os.environ, {"UPSTREAM_SIGNATURE_ACCESS_ENABLED": "true"}), \
                    mock.patch.object(provision.sys, "stderr", stderr), \
                    mock.patch.object(provision, "read_contract") as contract, \
                    mock.patch.object(provision.BoundedDownloader, "__init__") as downloader:
                self.assertEqual(provision.main([
                    "acquire", "--output", str(output), "--contract", str(Path(temp) / "missing-contract.json"),
                ]), 1)
            self.assertEqual(stderr.getvalue(), "provisioning failed: " + provision.acquisition_status()["reason"] + "\n")
            contract.assert_not_called()
            downloader.assert_not_called()
            self.assertFalse(output.exists())

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
                        with self.assertRaisesRegex(provision.ProvisionError, "no acquisition requests were made") as error:
                            provision.acquire_candidate(contract, output, Path(temp) / "missing-keyring.gpg")
                    self.assertEqual(str(error.exception), provision.acquisition_status()["reason"])
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

    def test_build_record_package_closure_binds_every_tuple_to_signed_metadata(self):
        record = self.valid_build_record()
        signed = provision.package_metadata_map(signed_package_rows_for_fixture(record))
        installed_keys = {
            (row["name"], row["version"], row["architecture"]) for row in record["packages"]
        }
        provision.validate_record_package_metadata(record, signed, installed_keys)

        bootstrap = next(row for row in record["packages"] if row["name"] == "ca-certificates")
        for field, value in (
                ("name", "ca-certificates-forged"), ("version", "0:0"), ("architecture", "amd64"),
                ("suite", "noble-security"), ("component", "universe"),
                ("file", "pool/main/c/ca-certificates/forged.deb"), ("bytes", 2), ("sha256", "f" * 64)):
            changed = json.loads(json.dumps(record))
            row = next(item for item in changed["packages"] if item["name"] == "ca-certificates")
            row[field] = value
            changed_keys = {
                (item["name"], item["version"], item["architecture"]) for item in changed["packages"]
            }
            with self.subTest(field=field), self.assertRaises(provision.ProvisionError):
                provision.validate_record_package_metadata(changed, signed, changed_keys)

        omitted = json.loads(json.dumps(record))
        omitted["packages"] = [row for row in omitted["packages"] if row["name"] != "ca-certificates"]
        with self.assertRaisesRegex(provision.ProvisionError, "differs from the installed rootfs"):
            provision.validate_record_package_metadata(omitted, signed, installed_keys)
        added = json.loads(json.dumps(record))
        extra = dict(bootstrap, name="unindexed-bootstrap-package")
        added["packages"].append(extra)
        added_keys = installed_keys | {(extra["name"], extra["version"], extra["architecture"])}
        with self.assertRaisesRegex(provision.ProvisionError, "differs from signed Packages metadata"):
            provision.validate_record_package_metadata(added, signed, added_keys)

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

    def langoptions_definition_fixture(self, base):
        definitions = []
        serial = 0
        for family, count in self.contract["langOptions"]["familyCounts"].items():
            for _ in range(count):
                name = "C99" if serial == 0 else f"Field{serial}"
                definitions.append(f"{family}({name}, x)\n")
                serial += 1
        definition = base / "LangOptions.def"
        definition.write_text("".join(definitions), encoding="utf-8")
        return definition

    def test_langoptions_source_audit_accepts_exact_pinned_inventory(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            header = base / "LangOptions.h"
            members = "\n".join(f"  int {name};" for name in self.contract["langOptions"]["manualFields"])
            header.write_text(
                "class LangOptions : public LangOptionsBase {\npublic:\n" + members +
                "\n  void localMethod() { int localOnly; }\n  struct Nested { int nestedOnly; };\n};\n"
                "class Unrelated { int unrelatedOnly; };\n", encoding="utf-8")
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

    def test_langoptions_full_audit_accepts_public_llvmorg_18_1_3_fixtures(self):
        fixtures = ROOT / "oracle/clang/18.1.3/fixtures"
        definition = fixtures / "llvmorg-18.1.3-LangOptions.def"
        header = fixtures / "llvmorg-18.1.3-LangOptions.h"
        inventory = provision.audit_langoptions(definition, header, self.contract)
        self.assertEqual(inventory["generatedFields"], self.contract["langOptions"]["generatedFieldCount"])
        self.assertEqual(inventory["familyCounts"], self.contract["langOptions"]["familyCounts"])
        self.assertEqual(inventory["manualFields"], self.contract["langOptions"]["manualFields"])
        self.assertEqual(inventory["manualFieldsCount"], 28)

    def test_langoptions_source_audit_rejects_added_or_removed_manual_members(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            fields = list(self.contract["langOptions"]["manualFields"])
            mutations = (
                ("added", "\n".join(f"int {name};" for name in fields) + "\nint UnexpectedManualField;"),
                ("added-nested-member", "\n".join(f"int {name};" for name in fields) +
                 "\nstruct Additional { int nestedOnly; } nestedField;"),
                ("removed", "\n".join(f"int {name};" for name in fields[:-1])),
            )
            for label, members in mutations:
                header = base / f"LangOptions-{label}.h"
                declarations = "\n".join("  " + line for line in members.splitlines())
                header.write_text(
                    "class LangOptions : public LangOptionsBase {\npublic:\n" + declarations + "\n};\n",
                    encoding="utf-8")
                with self.subTest(change=label), self.assertRaisesRegex(
                        provision.ProvisionError, "direct manual member inventory mismatch"):
                    provision.audit_langoptions(definition, header, self.contract)

    def test_langoptions_source_audit_rejects_added_state_hidden_in_declarator_shapes(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            fields = self.contract["langOptions"]["manualFields"]
            members = "\n".join(f"int {name};" for name in fields)
            mutations = {
                "function-pointer": members + "\nint (*AddedCallback)(int);",
                "comma-declarator": members.replace(f"int {fields[0]};", f"int {fields[0]}, AddedMember;"),
                "comma-initializers": members.replace(f"int {fields[0]};", f"int {fields[0]}=0, AddedMember=1;"),
                "array-size-expression": members + "\nint Added[sizeof(int)];",
                "template-size-expression": members + "\nstd::array<int, sizeof(int)> Added;",
                "braced-array-size-expression": members + "\nint Added[sizeof(int)]{};",
                "braced-template-size-expression": members + "\nstd::array<int, sizeof(int)> Added{};",
                "gnu-attribute": members + "\nint Added __attribute__((aligned(16)));",
                "annotation-macro": members + "\nint Added MEMBER_ATTRIBUTE(16);",
                "mixed-method-and-field": members + "\nint method(), Added;",
                "anonymous-union-state": members + "\nunion { int Added; };",
            }
            for label, changed in mutations.items():
                header = base / f"LangOptions-{label}.h"
                header.write_text("class LangOptions {\n" + changed + "\n};\n")
                with self.subTest(label=label), self.assertRaisesRegex(
                        provision.ProvisionError, "direct manual member inventory mismatch|unsupported direct"):
                    provision.audit_langoptions(definition, header, self.contract)

    def test_langoptions_member_scanner_preserves_supported_initializers_and_method_boundaries(self):
        header = """class LangOptions {
          int First = 0, Second = makeValue(1, 2);
          std::vector<int> Third{1, 2}, Fourth = {3, 4};
          unsigned Bits : 1, OtherBits : 2;
          int Array[sizeof(int)]{};
          std::array<int, sizeof(int)> Sized{};
          const char *Text = "braces { commas , and fake int Added; }";
          LangOptions() { int localOnly; }
          ~LangOptions() {}
          void method(int *parameter) const { int localOnly; }
          void declaredMethod(int *parameter) const;
          const std::vector<int> &items() const;
          unsigned long long flags() const;
          struct Nested { int nestedOnly; };
        };"""
        self.assertEqual(provision.extract_cxx_class_data_members(header, "LangOptions"),
                         ["First", "Second", "Third", "Fourth", "Bits", "OtherBits", "Array", "Sized", "Text"])

    def test_langoptions_member_scanner_rejects_unrecognized_direct_state_declarations(self):
        for declaration in ("DECLARE_STATE(Added);", "MYSTERY_STATE;", "int (*Added)(int);",
                            "int (LangOptions::*Added)(int);", "int [[gnu::aligned(16)]] Added;",
                            "int Added __attribute__((aligned(16)));", "int Added __declspec(align(16));",
                            "int Added MEMBER_ATTRIBUTE(16);",
                            "int method(), Added;",
                            "union { int Added; };",
                            "template <typename T> static T Added;", "int MissingSemicolon"):
            with self.subTest(declaration=declaration), self.assertRaisesRegex(
                    provision.ProvisionError, "unsupported direct|unterminated direct"):
                provision.extract_cxx_class_data_members("class LangOptions {" + declaration + "};", "LangOptions")

    def test_langoptions_source_audit_rejects_comma_declarator_injection(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            members = list(self.contract["langOptions"]["manualFields"])
            declarations = [
                f"bool {name} = false, Injected = false;" if name == "SanitizeCoverage"
                else f"bool {name};"
                for name in members
            ]
            header = base / "LangOptions-comma-injection.h"
            header.write_text(
                "class LangOptions : public LangOptionsBase {\npublic:\n  " +
                "\n  ".join(declarations) + "\n};\n", encoding="utf-8")
            with self.assertRaisesRegex(provision.ProvisionError, "direct manual member inventory mismatch"):
                provision.audit_langoptions(definition, header, self.contract)

    def test_langoptions_member_parser_preserves_nested_initializer_commas(self):
        header = """class LangOptions {
public:
  std::pair<int, int> templateField = std::pair<int, int>{1, 2};
  bool functionField = consume(1, 2);
  int unqualifiedTemplateField = consume<int, long>(1, 2);
  std::function<void(int, int)> callbackField;
  int bracedField{1, 2};
  int commaExpressionField = (1, 2);
  void methodWithPointerParameter(void (*callback)(int, int)) const;
  decltype(auto) inferredMethod();
};
"""
        self.assertEqual(
            provision.extract_cxx_class_data_members(header, "LangOptions"),
            ["templateField", "functionField", "unqualifiedTemplateField", "callbackField",
             "bracedField", "commaExpressionField"],
        )

    def test_langoptions_member_parser_handles_default_argument_methods_and_templated_function_braces(self):
        header = """class LangOptions {
public:
  std::function<void()> AddedCallback{};
  void setLangDefaults(int value = defaultValue()) { int methodLocal; }
  template <typename T> void setTemplatedDefaults(T value = T{}) { int templateLocal; }
  decltype(auto) inferredBody() { int inferredLocal; }
  auto trailingReturnBody() -> decltype(0 + 1) { int trailingLocal; }
  bool operator<(int other) { int operatorLocal; return false; }
  int FollowingField;
};
"""
        self.assertEqual(
            provision.extract_cxx_class_data_members(header, "LangOptions"),
            ["AddedCallback", "FollowingField"],
        )

    def test_langoptions_source_audit_rejects_parenthesized_type_and_member_declarators(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            fields = list(self.contract["langOptions"]["manualFields"])
            injections = (
                "decltype(0 + 1) stealth{};",
                "static decltype(0 + 1) staticStealth{};",
                "int (stealth){};",
                "alignas(8) int (alignedStealth){};",
                "typeof(0 + 1) typeofStealth{};",
                "__typeof__(0 + 1) gnuTypeofStealth{};",
            )
            for index, declaration in enumerate(injections):
                header = base / f"LangOptions-parenthesized-{index}.h"
                header.write_text(
                    "class LangOptions : public LangOptionsBase {\npublic:\n  " +
                    "\n  ".join(f"int {name};" for name in fields) +
                    "\n  " + declaration + "\n};\n",
                    encoding="utf-8")
                with self.subTest(declaration=declaration), self.assertRaisesRegex(
                        provision.ProvisionError, "unsupported direct|unsupported or ambiguous parenthesized"):
                    provision.audit_langoptions(definition, header, self.contract)

    def test_langoptions_source_audit_fails_closed_on_function_pointer_member(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            fields = self.contract["langOptions"]["manualFields"]
            header = base / "LangOptions-function-pointer.h"
            header.write_text(
                "class LangOptions : public LangOptionsBase {\npublic:\n  " +
                "\n  ".join(f"int {name};" for name in fields) +
                "\n  void (*AddedCallback)(int);\n};\n", encoding="utf-8")
            with self.assertRaisesRegex(provision.ProvisionError, "unsupported direct parenthesized"):
                provision.audit_langoptions(definition, header, self.contract)

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

    def test_oci_image_verifier_rejects_missing_or_untrusted_media_types(self):
        descriptor_fields = ("index", "index-manifest", "manifest", "config", "layer")
        for field in descriptor_fields:
            for mutation in ("missing", "untrusted"):
                with self.subTest(field=field, mutation=mutation), self.temporary_directory() as temp:
                    base = Path(temp)
                    rootfs_tar = base / "rootfs.tar"
                    payload = b"synthetic rootfs bytes for media-type validation"
                    rootfs_tar.write_bytes(payload)
                    layout = base / "layout"
                    image = provision.create_oci_layout(rootfs_tar, layout, "fixture", self.contract["environment"])
                    index_path = layout / "index.json"
                    index = json.loads(index_path.read_text(encoding="utf-8"))
                    descriptor = index["manifests"][0]
                    manifest_path = layout / "blobs/sha256" / image["manifestSha256"]
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    target = {
                        "index": (index, "mediaType"),
                        "index-manifest": (descriptor, "mediaType"),
                        "manifest": (manifest, "mediaType"),
                        "config": (manifest["config"], "mediaType"),
                        "layer": (manifest["layers"][0], "mediaType"),
                    }[field]
                    if mutation == "missing":
                        target[0].pop(target[1])
                    else:
                        target[0][target[1]] = "application/x-untrusted"
                    if field in ("manifest", "config", "layer"):
                        manifest_bytes = provision.canonical_json(manifest)
                        manifest_sha256 = provision.sha256(manifest_bytes)
                        (manifest_path.parent / manifest_sha256).write_bytes(manifest_bytes)
                        manifest_path.unlink()
                        descriptor.update(digest="sha256:" + manifest_sha256, size=len(manifest_bytes))
                        image.update(manifestSha256=manifest_sha256, imageDigest="sha256:" + manifest_sha256)
                    index_path.write_bytes(provision.canonical_json(index))

                    archive_path = base / "image.tar"
                    with tarfile.open(archive_path, "w") as archive:
                        for path in sorted(layout.rglob("*")):
                            if path.is_file():
                                archive.add(path, arcname=path.relative_to(layout).as_posix())
                    record = {
                        "profile": {"id": "fixture"}, "environment": self.contract["environment"],
                        "rootfs": {"bytes": len(payload), "sha256": provision.sha256(payload)},
                        "image": image,
                        "imageArtifact": {"bytes": archive_path.stat().st_size,
                                          "sha256": provision.sha256_file(archive_path)},
                    }
                    with self.assertRaisesRegex(provision.ProvisionError, "media type"):
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

    def retained_rootfs_image_fixture(self, base, record):
        rootfs = base / "rootfs"
        ProvisioningNegativeTests.prepare_runtime_rootfs(self, record, rootfs)
        rootfs_tar = base / "rootfs.tar"

        def local_tar(command, timeout=None):
            return subprocess.run(command[1:], check=False, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, timeout=timeout)

        with mock.patch.object(provision, "run_checked", side_effect=local_tar):
            rootfs_identity = provision.deterministic_rootfs_tar(
                rootfs, rootfs_tar, int(self.contract["environment"]["SOURCE_DATE_EPOCH"]),
                normalize=False, max_bytes=self.contract["profile"]["bounds"]["maxArtifactBytes"],
            )
        record["rootfs"] = rootfs_identity
        layout = base / "image-layout"
        image = provision.create_oci_layout(
            rootfs_tar, layout, record["profile"]["id"], self.contract["environment"],
        )
        record["image"] = {
            "format": image["format"], "manifestSha256": image["manifestSha256"],
            "imageDigest": image["imageDigest"],
        }
        oci_archive = base / "run2.oci.tar"
        with tarfile.open(oci_archive, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(item for item in layout.rglob("*") if item.is_file()):
                data = path.read_bytes()
                member = tarfile.TarInfo(path.relative_to(layout).as_posix())
                member.size = len(data)
                member.mode = 0o644
                member.uid = member.gid = 0
                member.mtime = int(self.contract["environment"]["SOURCE_DATE_EPOCH"])
                archive.addfile(member, io.BytesIO(data))
        record["imageArtifact"] = {
            "bytes": oci_archive.stat().st_size, "sha256": provision.sha256_file(oci_archive),
        }
        return rootfs, oci_archive

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
            expected_names = {row["name"] for section in ("packages", "downloadedPackages")
                              for row in record[section]}
            signed.assert_called_once_with(root, candidate, self.contract, keyring,
                                           extra_binary_package_names=expected_names)
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
            rootfs = base / "rootfs"
            rootfs.mkdir()
            record_path = base / "record.json"
            record_path.write_bytes(provision.canonical_json(record))
            args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH, record=record_path,
                                               acquisition=root, rootfs=rootfs, keyring=keyring,
                                               output=base / "provenance.tar")
            with mock.patch.object(provision, "verify_candidate_data",
                                   side_effect=provision.ProvisionError("signature rejected")) as signed:
                with self.assertRaisesRegex(provision.ProvisionError, "signature rejected"):
                    provision.command_package_provenance(args)
                expected_names = {row["name"] for section in ("packages", "downloadedPackages")
                                  for row in record[section]}
                signed.assert_called_once_with(root, candidate, self.contract, keyring,
                                               extra_binary_package_names=expected_names)
            self.assertFalse(args.output.exists())

    def test_package_provenance_rechecks_retained_rootfs_identity(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            _, _, record, _ = self.candidate_fixture(base)
            rootfs, oci_archive = self.retained_rootfs_image_fixture(base, record)
            changed = rootfs / record["runtime"]["entries"][0]["path"].lstrip("/")
            original_bytes = changed.read_bytes()
            changed.write_bytes(original_bytes + b"tamper")

            def local_tar(command, timeout=None):
                return subprocess.run(command[1:], check=False, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True, timeout=timeout)

            with mock.patch.object(provision, "run_checked", side_effect=local_tar):
                with self.assertRaisesRegex(provision.ProvisionError, "retained rootfs differs"):
                    provision.verify_retained_rootfs_and_image(rootfs, oci_archive, record, self.contract)

            changed.write_bytes(original_bytes)
            with tarfile.open(oci_archive, mode="a") as archive:
                extra = tarfile.TarInfo("unrecorded-evidence")
                extra.size = 1
                archive.addfile(extra, io.BytesIO(b"x"))
            record["imageArtifact"] = {
                "bytes": oci_archive.stat().st_size, "sha256": provision.sha256_file(oci_archive),
            }
            with mock.patch.object(provision, "run_checked", side_effect=local_tar):
                with self.assertRaisesRegex(provision.ProvisionError, "unrecorded files or blobs"):
                    provision.verify_retained_rootfs_and_image(rootfs, oci_archive, record, self.contract)

    def test_packaging_accepts_bound_local_evidence_and_selected_contract(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            root, candidate, record, keyring = self.candidate_fixture(base)
            selected = base / "selected-contract.json"
            selected.write_bytes(provision.canonical_json(self.contract))
            record["recipe"] = provision.recipe_identity(selected)
            record["probe"]["fixtureSha256"] = provision.sha256_file(
                ROOT / self.contract["negativeControl"]["fixture"])
            rootfs, oci_archive = self.retained_rootfs_image_fixture(base, record)
            record_path = base / "record.json"
            record_path.write_bytes(provision.canonical_json(record))
            record_sha = provision.sha256_file(record_path)
            loader = ProvisioningNegativeTests.valid_loader_report(self, record, record_sha, rootfs)
            signed_rows = signed_package_rows_for_fixture(record)
            installed_keys = {
                (row["name"], row["version"], row["architecture"]) for row in record["packages"]
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
                                               rootfs=rootfs, oci_archive=oci_archive, keyring=keyring,
                                               output=base / "provenance.tar", **report_paths)

            def local_tar(command, timeout=None):
                return subprocess.run(command[1:], check=False, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True, timeout=timeout)

            with mock.patch.object(provision, "verify_candidate_data", return_value=signed_rows) as signed, \
                    mock.patch.object(provision, "installed_package_keys", return_value=installed_keys), \
                    mock.patch.object(provision, "runtime_dependencies",
                                      return_value=record["runtime"]["entries"]) as runtime, \
                    mock.patch.object(provision, "run_checked", side_effect=local_tar), \
                    mock.patch.object(provision.BoundedDownloader, "get") as network:
                self.assertEqual(provision.command_package_provenance(args), 0)
                expected_names = {row["name"] for section in ("packages", "downloadedPackages")
                                  for row in record[section]}
                signed.assert_called_once_with(root, candidate, self.contract, keyring,
                                               extra_binary_package_names=expected_names)
                runtime.assert_called_once_with(rootfs, list(provision.FRONTEND_RUNTIME_ROOTS), self.contract)
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
                comparator_manifest = archive.extractfile(
                    "trusted_keys/clang-22.1.6-oracle-manifest.json").read()
                comparator_lock = json.loads(lock_path.read_bytes())
                self.assertEqual(provision.sha256(comparator_manifest),
                                 comparator_lock["oracle"]["artifactManifestSha256"])
                self.assertEqual(comparator_manifest,
                                 (lock_path.parent / comparator_lock["oracle"]["artifactManifestPath"]).read_bytes())

            # A self-consistent record and report cannot define a smaller runtime
            # closure than the one re-derived from the retained rootfs.
            original_runtime = record["runtime"]
            remove_path = next(
                row["path"] for row in original_runtime["entries"]
                if row["sha256"] != next(tool["sha256"] for tool in record["tools"]
                                         if tool["role"] == "cxx-driver")
            )
            record["runtime"] = provision.manifest([
                row for row in original_runtime["entries"] if row["path"] != remove_path
            ])
            record_path.write_bytes(provision.canonical_json(record))
            omitted_record_sha = provision.sha256_file(record_path)
            omitted_loader = ProvisioningNegativeTests.valid_loader_report(
                self, record, omitted_record_sha, rootfs,
            )
            provision.validate_provenance_loader_report(
                omitted_loader, record, omitted_record_sha, rootfs,
            )
            omitted_loader_path = base / "loader-report-omitted-runtime.json"
            omitted_loader_path.write_bytes(provision.canonical_json(omitted_loader))
            args.loader_report = omitted_loader_path
            args.output = base / "provenance-omitted-runtime.tar"
            with mock.patch.object(provision, "verify_candidate_data", return_value=signed_rows), \
                    mock.patch.object(provision, "installed_package_keys", return_value=installed_keys), \
                    mock.patch.object(provision, "runtime_dependencies",
                                      return_value=original_runtime["entries"]), \
                    mock.patch.object(provision, "run_checked", side_effect=local_tar):
                with self.assertRaisesRegex(provision.ProvisionError, "runtime closure differs"):
                    provision.command_package_provenance(args)
            self.assertFalse(args.output.exists())


if __name__ == "__main__":
    unittest.main()
