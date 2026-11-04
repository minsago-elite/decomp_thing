#!/usr/bin/env python3
"""Pure-Python controls for the installed qualification record selector."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTROL_TMP = ROOT / "build/orchestration/atomic-install-ci-remediation/tmp"
CONTROL_TMP.mkdir(parents=True, exist_ok=True)
SPEC = importlib.util.spec_from_file_location("atomic_install_verifier", ROOT / "scripts/verify-atomic-install-qualification.py")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)
DRIVER_SPEC = importlib.util.spec_from_file_location("inert_atomic_producer", ROOT / "scripts/test-atomic-install.py")
driver = importlib.util.module_from_spec(DRIVER_SPEC)
DRIVER_SPEC.loader.exec_module(driver)  # Definitions only; never call main/Gradle/Child.

PHASES = ["agent build", "initial A and no-update", "initial A and no-update", "failed-before-rename live A",
          "live transition A->B", "live transition A->B", "live transition B->A", "live transition B->A",
          "retained gcc authority", "retained gcc authority", "retained llvm authority", "retained llvm authority",
          "archive/classpath/helper contracts"]
REFERENCE_NAMES = ["kotlin-boot-classpath-reference-v1.json", "gcc-bundled-ghidra-reference-v1.json",
                   "llvm-behavior-hosted-worker-classpath-reference-v1.json"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def fixture(base):
    repo = base / "repo"
    evidence = repo / "build/orchestration/atomic-install-remediation"
    marker_path = repo / "build/orchestration/atomic-install-ci/driver-started.json"
    write_json(marker_path, {"sourceHead": "0123456789abcdef", "runId": "fixture", "runAttempt": "1",
                             "startedAtUnixNs": 1})
    run_dir = evidence / "installed-current"
    run_dir.mkdir(parents=True)
    install_lib = run_dir / "root-build/install/llm_bin_patch/lib"
    install_lib.mkdir(parents=True)
    installed_app = install_lib / "llm_bin_patch.jar"
    installed_app.write_bytes(b"fixture installed app jar")
    sources = {}
    for name in (*verifier.OWNED, "src/main/c/fixture.c", "frontend/fixture.ts", "settings.gradle.kts"):
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture source " + name + "\n", encoding="utf-8")
        sources[name] = sha(path)
    owned = {name: sources[name] for name in verifier.OWNED}
    agent = repo / "build/atomic-install/atomic-install-probe-agent.jar"
    agent.parent.mkdir(parents=True)
    agent.write_bytes(b"synthetic inert agent receipt; never executed")
    # Fake only git's listing and HEAD, never validation, file receipts, or filters.
    # Include deleted tracked names and newly created untracked fixture sources.
    verifier.git_source_names = lambda current: set(sources) | {
        str(p.relative_to(current)) for top in ("src", "scripts", "frontend", "ghidra-bridge")
        for p in (current / top).rglob("*")}
    with mock.patch.object(driver, "WORK", run_dir), mock.patch.object(driver, "INIT", run_dir / "atomic-install.init.gradle"):
        driver.write_init("B")  # Pure text generator; the producer overwrites this per install.

    def probe(index, generation, authority="none"):
        root = run_dir / "barriers" / f"barrier-{index}"
        root.mkdir(parents=True)
        old_digest = hashlib.sha256(f"app-{generation}-{index}".encode()).hexdigest()
        ready = {"descriptorDigest": old_digest, "mainOrigin": str(installed_app),
                 "mainLoader": "jdk.internal.loader.ClassLoaders$AppClassLoader@1", "classpath": str(installed_app),
                 "archiveMarker": generation, "modelAbsentBeforeReady": "true", "resourceOpenedBeforeReady": "true",
                 "authority": authority, "releaseTimeoutSeconds": "1500"}
        loaded = {**ready, "lateResourceMarker": generation, "schemaVersion": "4", "inputSha256": "a" * 64,
                  "modelLoader": "jdk.internal.loader.ClassLoaders$AppClassLoader@1",
                  "transformLoader": "jdk.internal.loader.ClassLoaders$AppClassLoader@1",
                  "modelOrigin": ready["mainOrigin"], "transformOrigin": ready["mainOrigin"],
                  "installedPathDigestAfterRelease": old_digest}
        if authority != "none":
            loaded["authorityOutcome"] = "rejected-before-authorization"
        write_json(root / "READY", ready)
        write_json(root / "READY.loaded", loaded)
        log = root / "launcher.log"
        log.write_text("synthetic completed probe\n")
        (root / "RELEASE").write_text("unchanged\n" if index < 2 else "changed\n")
        return {"generation": generation, "authority": authority, "root": str(root), "status": "passed",
                "ready": ready, "loaded": loaded, "pid": 1000 + index, "exitCode": 0,
                "log": str(log), "logSha256": sha(log)}

    probe_rows = [probe(0, "A"), probe(1, "A"), probe(2, "A"), probe(3, "B"),
                  probe(4, "B"), probe(5, "A"), probe(6, "A", "gcc"), probe(7, "A", "llvm")]
    probe_rows[2]["loaded"]["installedPathDigestAfterRelease"] = "b" * 64
    probe_rows[3]["ready"]["descriptorDigest"] = "b" * 64
    probe_rows[3]["loaded"]["descriptorDigest"] = "b" * 64
    probe_rows[3]["loaded"]["installedPathDigestAfterRelease"] = "b" * 64
    probe_rows[4]["loaded"]["installedPathDigestAfterRelease"] = "c" * 64
    probe_rows[5]["ready"]["descriptorDigest"] = "c" * 64
    probe_rows[5]["loaded"]["descriptorDigest"] = "c" * 64
    probe_rows[5]["loaded"]["installedPathDigestAfterRelease"] = "c" * 64
    for row in (probe_rows[2], probe_rows[3], probe_rows[4], probe_rows[5]):
        write_json(pathlib.Path(row["root"]) / "READY", row["ready"])
        write_json(pathlib.Path(row["root"]) / "READY.loaded", row["loaded"])
    transition_ab = {"from": "A", "to": "B", "beforeFileKey": [1, 10], "afterFileKey": [1, 11],
                     "oldParent": probe_rows[2]["loaded"],
                     "newProcessByInstalledPath": probe_rows[3]["loaded"]}
    transition_ba = {"from": "B", "to": "A", "beforeFileKey": [1, 11], "afterFileKey": [1, 12],
                     "oldParent": probe_rows[4]["loaded"],
                     "newProcessByInstalledPath": probe_rows[5]["loaded"]}

    args = [
        ["./gradlew", "--no-daemon", "atomicInstallProbeAgentJar"],
        ["./gradlew", "--no-daemon", "installDist"], ["./gradlew", "--no-daemon", "installDist"],
        ["./gradlew", "--no-daemon", "installDist"],
        ["./gradlew", "--no-daemon", "installDist"], ["./gradlew", "--no-daemon", "installDist"],
        ["./gradlew", "--no-daemon", "installDist"], ["./gradlew", "--no-daemon", "installDist"],
        ["./gradlew", "--no-daemon", "installDist"], ["./gradlew", "--no-daemon", "installDist"],
        ["./gradlew", "--no-daemon", "installDist"], ["./gradlew", "--no-daemon", "installDist"],
        ["./gradlew", "--no-daemon", "installDist", "distZip", "distTar", "verifyGhidraDistributionArchives",
         "verifyAnalysisIoHelperInstalled", "verifyAcpGateHelperDistribution", "verifyLlvmBehaviorHelperDistribution",
         "verifyKotlinBootClasspathDistribution"],
    ]
    commands = []
    for index, command_args in enumerate(args):
        command_args[:2] = [str(repo / "gradlew"), "--no-daemon", "-g", str(repo / "build/.gradle-user-home"),
                           "-Dorg.gradle.jvmargs=-XX:-UsePerfData",
                           "-Dorg.gradle.java.installations.auto-download=false",
                           "-Dorg.gradle.java.installations.paths=/synthetic/jdk21"]
        if index:
            command_args[7:7] = ["-I", str(run_dir / "atomic-install.init.gradle")]
        log = run_dir / ["agent-build.log", "install-A-1.log", "install-A-2.log", "install-B-3.log",
                         "install-A-4.log", "install-B-5.log", "install-B-6.log", "install-A-7.log",
                         "install-A-8.log", "gcc-held-install.log", "install-A-10.log", "llvm-held-install.log",
                         "distribution-contracts.log"][index]
        log.write_text("atomic-probe injected before first rename\ncompleted renames=0\n" if index == 3 else "BUILD SUCCESSFUL\n")
        status = "failed" if index == 3 else "passed"
        commands.append({"args": command_args, "phase": PHASES[index], "status": status,
                         "exitCode": 17 if index == 3 else 0, "log": str(log), "logSha256": sha(log)})

    record = {"status": "passed", "phase": "complete", "runRoot": str(run_dir), "sourceHead": "0123456789abcdef",
              "agentSha256": sha(agent),
              "sourceHashes": sources, "finalSourceHashes": dict(sources), "finalOwnedSourceHashes": owned,
              "commands": commands, "probes": probe_rows,
              "noUpdate": {"status": "passed", "protectedUnchanged": True, "probe": probe_rows[0]["loaded"]},
              "failedBeforeRename": probe_rows[1]["loaded"], "transitions": [transition_ab, transition_ba],
              "authorities": [{"authority": "gcc", "installExit": 0, "protectedUnchanged": False,
                               "probe": probe_rows[6]["loaded"]},
                              {"authority": "llvm", "installExit": 0, "protectedUnchanged": False,
                               "probe": probe_rows[7]["loaded"]}],
              "archiveHashes": {}, "finalProtectedFiles": {}}
    archives = run_dir / "root-build/distributions"
    archives.mkdir()
    for name in ("llm_bin_patch-0.1.0.zip", "llm_bin_patch-0.1.0.tar"):
        path = archives / name
        path.write_bytes(b"synthetic archive bytes " + name.encode())
        record["archiveHashes"][str(path)] = sha(path)
    for name in REFERENCE_NAMES:
        (install_lib / name).write_text('{"scope":"synthetic consistency fixture"}\n')
    install_bin = install_lib.parent / "bin"
    install_bin.mkdir()
    for name in ("llm_bin_patch", "llm_bin_patch.bat"):
        path = install_bin / name
        path.write_text("synthetic launcher, never executed\n")
        path.chmod(0o755 if name == "llm_bin_patch" else 0o644)
    for path in [installed_app, *(install_lib / n for n in REFERENCE_NAMES)]:
        path.chmod(0o644)
    with mock.patch.object(driver, "WORK", run_dir):
        record["finalProtectedFiles"] = driver.protected_snapshot()  # Actual producer path/key policy.
    write_json(run_dir / "qualification.json", record)
    write_json(evidence / "latest-installed-run.json", {"record": str(run_dir / "qualification.json")})

    controls_dir = evidence / "driver-controls-current"
    controls_dir.mkdir()
    expected_controls = ["distinct-buildDir-production-service-contention/release/task-failure/process-cancel/reacquire",
                         "agent-clock-121-second-update/full-expiry/signed-wrap/backward-rejection",
                         "synthetic-agent-A-B-A-late-loader-origin-resource-descriptor-JSON/no-product-main"]
    write_json(controls_dir / "controls.json", {"status": "passed", "passed": expected_controls,
                                               "sourceHashes": owned})
    write_json(controls_dir / "java-fixture/synthetic-agent-results.json", [{"from": "A", "to": "B"}, {"from": "B", "to": "A"}])
    publisher = repo / "build/atomic-install/publisher-controls/run-fixture"
    publisher.mkdir(parents=True)
    required_publisher = ["source-before-copy", "source-after-copy", "copy-failure", "file-force-failure",
                          "last-stage-file-force", "corrupt-copy", "unsupported-atomic-move",
                          "post-rename-directory-force", "stale-prune-failure", "stale-closure-mismatch",
                          "prune-directory-force", "first-install/replacement/no-update/order/closure/modes",
                          "writer-contention/release/cooperative-cancellation", "symlink-lock-rejection",
                          "pre-Sync-symlink/foreign-write/target-rejection"]
    (publisher / "passed.txt").write_text("\n".join(required_publisher) + "\n")
    verifier.current_checkout_head = lambda _repo: "0123456789abcdef"
    return repo, run_dir


class QualificationVerifierControls(unittest.TestCase):
    def setUp(self):
        original_head = verifier.current_checkout_head
        original_names = getattr(verifier, "git_source_names", None)
        self.addCleanup(setattr, verifier, "current_checkout_head", original_head)
        if original_names is not None:
            self.addCleanup(setattr, verifier, "git_source_names", original_names)

    def test_actual_producer_shape_positive(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, _ = fixture(pathlib.Path(temp))
            result = verifier.select_and_verify(repo, "0123456789abcdef")
            self.assertEqual("passed", result["status"])

    def test_required_build_exit_and_status_consistency(self):
        for index in (0, 1, 2, 4, 5, 6, 7, 8, 10, 12):
            with self.subTest(index=index), tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
                repo, run_dir = fixture(pathlib.Path(temp))
                record = json.loads((run_dir / "qualification.json").read_text())
                record["commands"][index].update(status="failed", exitCode=1)
                write_json(run_dir / "qualification.json", record)
                with self.assertRaises(verifier.QualificationError):
                    verifier.select_and_verify(repo, "0123456789abcdef")
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run_dir = fixture(pathlib.Path(temp))
            record = json.loads((run_dir / "qualification.json").read_text())
            record["commands"][0]["exitCode"] = 1
            write_json(run_dir / "qualification.json", record)
            with self.assertRaises(verifier.QualificationError):
                verifier.select_and_verify(repo, "0123456789abcdef")

    def test_changed_log_cannot_keep_previous_digest(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run_dir = fixture(pathlib.Path(temp))
            (run_dir / "agent-build.log").write_text("changed retained log\n")
            with self.assertRaisesRegex(verifier.QualificationError, "log digest"):
                verifier.select_and_verify(repo, "0123456789abcdef")

    def test_required_field_omission_fails(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run_dir = fixture(pathlib.Path(temp))
            record = json.loads((run_dir / "qualification.json").read_text())
            record["transitions"].pop()
            write_json(run_dir / "qualification.json", record)
            with self.assertRaisesRegex(verifier.QualificationError, "A→B and B→A"):
                verifier.select_and_verify(repo, "0123456789abcdef")

    def test_duplicate_and_truncated_json_fail(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, _ = fixture(pathlib.Path(temp))
            pointer = repo / "build/orchestration/atomic-install-remediation/latest-installed-run.json"
            pointer.write_text('{"record":"x","record":"y"}')
            with self.assertRaisesRegex(verifier.QualificationError, "duplicate JSON key"):
                verifier.select_and_verify(repo, "0123456789abcdef")
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run_dir = fixture(pathlib.Path(temp))
            (run_dir / "qualification.json").write_text('{"status":"passed"')
            with self.assertRaisesRegex(verifier.QualificationError, "malformed/truncated"):
                verifier.select_and_verify(repo, "0123456789abcdef")

    def test_current_source_corruption_and_wrong_head_fail(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run_dir = fixture(pathlib.Path(temp))
            (repo / verifier.OWNED[0]).write_text("mutated\n")
            with self.assertRaisesRegex(verifier.QualificationError, "current source differs"):
                verifier.select_and_verify(repo, "0123456789abcdef")
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, _ = fixture(pathlib.Path(temp))
            verifier.current_checkout_head = lambda _repo: "fedcba9876543210"
            marker = repo / "build/orchestration/atomic-install-ci/driver-started.json"
            marker_data = json.loads(marker.read_text())
            marker_data["sourceHead"] = "fedcba9876543210"
            write_json(marker, marker_data)
            with self.assertRaisesRegex(verifier.QualificationError, "sourceHead"):
                verifier.select_and_verify(repo, "fedcba9876543210")

    def test_failed_latest_run_cannot_be_masked_by_prior_pass(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run_dir = fixture(pathlib.Path(temp))
            stale = run_dir.parent / "installed-prior"
            stale.mkdir()
            with self.assertRaisesRegex(verifier.QualificationError, "stale, ambiguous"):
                verifier.select_and_verify(repo, "0123456789abcdef")
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run_dir = fixture(pathlib.Path(temp))
            record = json.loads((run_dir / "qualification.json").read_text())
            record["status"] = "failed"
            record["phase"] = "initial A and no-update"
            write_json(run_dir / "qualification.json", record)
            with self.assertRaisesRegex(verifier.QualificationError, "did not finish passed/complete"):
                verifier.select_and_verify(repo, "0123456789abcdef")

    def test_nonzero_unqualified_authority_failure_fails(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run_dir = fixture(pathlib.Path(temp))
            record = json.loads((run_dir / "qualification.json").read_text())
            command = record["commands"][9]
            command.update(status="failed", exitCode=124)
            pathlib.Path(command["log"]).write_text("timed out\n")
            command["logSha256"] = sha(pathlib.Path(command["log"]))
            record["authorities"][0].update(installExit=124, protectedUnchanged=True)
            write_json(run_dir / "qualification.json", record)
            with self.assertRaisesRegex(verifier.QualificationError, "explicit unchanged lease refusal"):
                verifier.select_and_verify(repo, "0123456789abcdef")

    def test_real_checkout_only_four_owned_sources(self):
        owned = {name: sha(ROOT / name) for name in verifier.OWNED}
        record = {"sourceHead": "fixture-head", "sourceHashes": owned, "finalSourceHashes": owned,
                  "finalOwnedSourceHashes": owned}
        with self.assertRaisesRegex(verifier.QualificationError, "source path sets differ"):
            verifier.validate_sources(record, ROOT, "fixture-head")

    def test_real_producer_source_policy(self):
        # Other source owners may add files during this pure test. Use one real
        # Git listing for both policies, rather than asserting a frozen checkout.
        names = verifier.git_source_names(ROOT)
        with mock.patch.object(verifier, "git_source_names", return_value=names), \
                mock.patch.object(driver.subprocess, "check_output", return_value="\0".join(names).encode()):
            self.assertEqual(set(driver.source_hashes()), verifier.current_source_paths(ROOT))

    def test_source_filters_match_producer(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, _ = fixture(pathlib.Path(temp))
            paths = ["src/yes.c", "scripts/yes", "frontend/yes.ts", "ghidra-bridge/yes",
                     "config/yes.properties", "included.gradle.kts", "notes/no.md", "build/no.jar"]
            for name in paths:
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
            (repo / "src/symlink.c").symlink_to(repo / "src/yes.c")
            os.mkfifo(repo / "src/pipe.c")
            names = [*paths, "src/symlink.c", "src/pipe.c", "src/deleted.c", "src"]
            with mock.patch.object(verifier, "git_source_names", return_value=names), \
                    mock.patch.object(driver, "ROOT", repo), \
                    mock.patch.object(driver.subprocess, "check_output", return_value="\0".join(names).encode()):
                self.assertEqual(set(driver.source_hashes()), verifier.current_source_paths(repo))

    def test_qualified_authority_lease_refusal_positive(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run = fixture(pathlib.Path(temp))
            record = json.loads((run / "qualification.json").read_text())
            for command_index, probe_index, authority_index in ((9, 6, 0), (11, 7, 1)):
                command = record["commands"][command_index]
                command.update(status="failed", exitCode=1)
                log = pathlib.Path(command["log"])
                log.write_text("resource temporarily unavailable: lease refused\n")
                command["logSha256"] = sha(log)
                loaded = record["probes"][probe_index]["loaded"]
                loaded["authorityOutcome"] = "unchanged-valid"
                record["authorities"][authority_index].update(installExit=1, protectedUnchanged=True, probe=loaded)
                barrier = pathlib.Path(record["probes"][probe_index]["root"])
                write_json(barrier / "READY.loaded", loaded)
                (barrier / "RELEASE").write_text("lease-refused\n")
            write_json(run / "qualification.json", record)
            self.assertEqual("passed", verifier.select_and_verify(repo, "0123456789abcdef")["status"])

    def test_product_streaming_limits_and_aggregate(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run = fixture(pathlib.Path(temp))
            record = json.loads((run / "qualification.json").read_text())
            path = pathlib.Path(next(iter(record["archiveHashes"])))
            # A real sparse 129 MiB file catches accidental reuse of the old
            # 128 MiB digest cap. No large buffer and no executable archive.
            with path.open("wb") as stream:
                stream.truncate(129 * 1024 * 1024)
            record["archiveHashes"][str(path)] = driver.digest(path)
            write_json(run / "qualification.json", record)
            result = verifier.select_and_verify(repo, "0123456789abcdef")
            self.assertGreater(result["verifiedProducts"]["bytesVerified"], 128 * 1024 * 1024)
            self.assertGreaterEqual(verifier.MAX_PROTECTED, 512 * 1024 * 1024)
            self.assertGreaterEqual(verifier.MAX_ARCHIVE, 8 * 1024**3)
            for constant in ("MAX_ARCHIVE", "MAX_PROTECTED", "MAX_PROTECTED_RUNTIME", "MAX_PRODUCTS"):
                with self.subTest(limit=constant), mock.patch.object(verifier, constant, 1):
                    with self.assertRaisesRegex(verifier.QualificationError, "bound|exceeds"):
                        verifier.select_and_verify(repo, "0123456789abcdef")

    def test_bounded_reads_reject_growth_and_special_files(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            path = pathlib.Path(temp) / "input"
            os.mkfifo(path)
            with self.assertRaisesRegex(verifier.QualificationError, "nonregular"):
                verifier.read_bytes(path, 128)
            path.unlink()
            path.write_bytes(b"small")
            with self.assertRaisesRegex(verifier.QualificationError, "changed during read"):
                with verifier.regular_stream(path, 128) as (stream, _):
                    path.write_bytes(b"growth")
                    stream.read(128)
            path.write_bytes(b"large")
            with self.assertRaisesRegex(verifier.QualificationError, "exceeds"):
                verifier.read_bytes(path, 1)

    def test_final_init_receipt_explicitly_limits_historical_claim(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run = fixture(pathlib.Path(temp))
            # There is no producer per-command init digest to compare with.
            # Capture final bytes honestly instead of pretending to reconstruct A/B.
            path = run / "atomic-install.init.gradle"
            path.write_text("// final init alone cannot prove previous generations\n")
            result = verifier.select_and_verify(repo, "0123456789abcdef")
            self.assertEqual(sha(path), result["commands"]["finalInitSha256"])
            self.assertIn("no historical", result["commands"]["limitation"])

    def test_streaming_checks_growth_without_unbounded_read(self):
        import io
        from contextlib import contextmanager
        requests = []
        class Growing(io.BytesIO):
            def read(self, size=-1):
                self_test.assertGreater(size, 0)
                self_test.assertLessEqual(size, 1024 * 1024)
                requests.append(size)
                return super().read(size)
        self_test = self
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            path = pathlib.Path(temp) / "input"
            path.write_bytes(b"12345678")
            @contextmanager
            def growing_stream(_path, _limit):
                yield Growing(b"123456789"), path.stat()
            with mock.patch.object(verifier, "regular_stream", growing_stream):
                with self.assertRaisesRegex(verifier.QualificationError, "grew beyond"):
                    verifier.file_receipt(path, 8)
            self.assertEqual([9], requests)


def first_archive(run, record):
    return pathlib.Path(next(iter(record["archiveHashes"])))


def protected_jar(run):
    return run / "root-build/install/llm_bin_patch/lib/llm_bin_patch.jar"


def probe_log(record):
    return pathlib.Path(record["probes"][0]["log"])


def mutate_commands(record, indices, kind):
    for index in indices:
        command = record["commands"][index]
        if kind == "task":
            command["args"] = ["./gradlew", "--no-daemon", "atomicInstallProbeAgentJar"]
        elif kind == "log":
            command.update(log=record["commands"][0]["log"], logSha256=record["commands"][0]["logSha256"])
        elif kind == "init":
            pos = command["args"].index("-I")
            del command["args"][pos:pos + 2]
        elif kind == "phase":
            command["phase"] = "wrong phase"


def omit_source(record, name):
    del record["sourceHashes"][name]
    del record["finalSourceHashes"][name]


def replace_with_symlink_or_fifo(path, kind):
    path.unlink()
    if kind == "fifo":
        os.mkfifo(path)
    else:
        path.symlink_to(path.parent / "missing-target")


def changed_protected(run, record):
    path = protected_jar(run)
    path.write_bytes(b"CHANGED INSTALLED JAR\n")
    path.chmod(0o600)


def replace_inode(run, record):
    path = protected_jar(run)
    replacement = path.with_suffix(".replacement")
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o644)
    replacement.replace(path)


def reuse_log_inode(record):
    target = pathlib.Path(record["commands"][1]["log"])
    target.unlink()
    target.hardlink_to(pathlib.Path(record["commands"][0]["log"]))
    record["commands"][1]["logSha256"] = record["commands"][0]["logSha256"]


def symlink_parent(repo, run, record):
    path = protected_jar(run).parent
    moved = path.with_name("moved-lib")
    path.rename(moved)
    path.symlink_to(moved, target_is_directory=True)


# Each mutation runs against a separately verified green, producer-shaped fixture.
# The first thirteen entries plus test_real_checkout_only_four_owned_sources are
# the review's fourteen counterexamples, reproduced without its omitted receipts.
NEGATIVE_CASES = {
    "retained_agent_changed": lambda repo, run, r: (repo / "build/atomic-install/atomic-install-probe-agent.jar").write_bytes(b"changed"),
    "retained_agent_missing": lambda repo, run, r: (repo / "build/atomic-install/atomic-install-probe-agent.jar").unlink(),
    "retained_agent_digest_missing": lambda repo, run, r: r.pop("agentSha256"),
    "no_update_wrong_probe_role": lambda repo, run, r: r["noUpdate"].update(probe=r["probes"][2]["loaded"]),
    "failed_update_wrong_probe_role": lambda repo, run, r: r.update(failedBeforeRename=r["probes"][0]["loaded"]),
    "archive_bytes_changed": lambda repo, run, r: first_archive(run, r).write_bytes(b"changed"),
    "archive_missing": lambda repo, run, r: first_archive(run, r).unlink(),
    "wrong_archive_set": lambda repo, run, r: r.update(archiveHashes={"does-not-exist": "0" * 64}),
    "installed_jar_digest_mode_changed": lambda repo, run, r: changed_protected(run, r),
    "installed_launcher_missing": lambda repo, run, r: (run / "root-build/install/llm_bin_patch/bin/llm_bin_patch").unlink(),
    "wrong_protected_set": lambda repo, run, r: r.update(finalProtectedFiles={"not-installed": {"sha256": "0" * 64, "mode": -1}}),
    "installer_temp_leftover": lambda repo, run, r: (protected_jar(run).parent / ".install-leftover.tmp").write_bytes(b"leftover"),
    "probe_nonzero_exit_passed_status": lambda repo, run, r: r["probes"][0].update(exitCode=1),
    "probe_log_changed_digest_unchanged": lambda repo, run, r: probe_log(r).write_text("failed after READY.loaded\n"),
    "probe_log_missing": lambda repo, run, r: probe_log(r).unlink(),
    "release_files_missing": lambda repo, run, r: [(pathlib.Path(p["root"]) / "RELEASE").unlink() for p in r["probes"]],
    "setup_transition_commands_not_installs": lambda repo, run, r: mutate_commands(r, (1, 2, 4, 5, 6, 7, 8, 10), "task"),
    "duplicate_command_log": lambda repo, run, r: mutate_commands(r, (1, 2, 4, 5, 6, 7, 8, 10), "log"),
    "source_missing_nonowned": lambda repo, run, r: omit_source(r, "src/main/c/fixture.c"),
    "source_added_current": lambda repo, run, r: (repo / "src/main/c/added.c").write_text("new source\n"),
    "source_removed_current": lambda repo, run, r: (repo / "src/main/c/fixture.c").unlink(),
    "archive_added_current": lambda repo, run, r: (first_archive(run, r).parent / "extra.zip").write_bytes(b"extra"),
    "archive_missing_receipt": lambda repo, run, r: r["archiveHashes"].pop(str(first_archive(run, r))),
    "archive_invalid_digest": lambda repo, run, r: r["archiveHashes"].update({str(first_archive(run, r)): "bad"}),
    "protected_bytes_only": lambda repo, run, r: protected_jar(run).write_bytes(b"changed bytes"),
    "protected_mode_only": lambda repo, run, r: protected_jar(run).chmod(0o600),
    "protected_replaced_inode": lambda repo, run, r: replace_inode(run, r),
    "protected_wrong_key": lambda repo, run, r: r["finalProtectedFiles"][str(protected_jar(run).relative_to(run))].update(key=[0, 0]),
    "protected_missing_key": lambda repo, run, r: r["finalProtectedFiles"][str(protected_jar(run).relative_to(run))].pop("key"),
    "protected_missing_receipt": lambda repo, run, r: r["finalProtectedFiles"].pop(str(protected_jar(run).relative_to(run))),
    "protected_added_jar": lambda repo, run, r: (protected_jar(run).parent / "extra.jar").write_bytes(b"extra"),
    "protected_missing_reference": lambda repo, run, r: (protected_jar(run).parent / REFERENCE_NAMES[0]).unlink(),
    "protected_unexpected_reference": lambda repo, run, r: (protected_jar(run).parent / "fake-reference-v1.json").write_text("{}"),
    "installer_bin_temp": lambda repo, run, r: (protected_jar(run).parent.parent / "bin/.install-leftover.tmp").write_bytes(b"leftover"),
    "probe_exit_missing": lambda repo, run, r: r["probes"][0].pop("exitCode"),
    "probe_exit_boolean": lambda repo, run, r: r["probes"][0].update(exitCode=False),
    "probe_log_digest_missing": lambda repo, run, r: r["probes"][0].pop("logSha256"),
    "probe_log_reused": lambda repo, run, r: r["probes"][1].update(log=r["probes"][0]["log"], logSha256=r["probes"][0]["logSha256"]),
    "probe_wrong_release": lambda repo, run, r: (pathlib.Path(r["probes"][0]["root"]) / "RELEASE").write_text("changed\n"),
    "probe_ready_failure": lambda repo, run, r: (pathlib.Path(r["probes"][0]["root"]) / "READY.failure").write_text("failure"),
    "probe_cleanup_failure": lambda repo, run, r: r.update(cleanupFailures=["not reaped"]),
    "command_missing": lambda repo, run, r: r["commands"].pop(1),
    "command_hardlinked_log": lambda repo, run, r: reuse_log_inode(r),
    "command_missing_log": lambda repo, run, r: pathlib.Path(r["commands"][1]["log"]).unlink(),
    "command_missing_digest": lambda repo, run, r: r["commands"][1].pop("logSha256"),
    "command_wrong_digest": lambda repo, run, r: r["commands"][1].update(logSha256="0" * 64),
    "command_init_missing_file": lambda repo, run, r: (run / "atomic-install.init.gradle").unlink(),
    "command_init_wrong_path": lambda repo, run, r: r["commands"][1]["args"].__setitem__(8, str(run / "different.init.gradle")),
    "command_extra_task": lambda repo, run, r: r["commands"][1]["args"].insert(7, "clean"),
    "command_final_missing_helper": lambda repo, run, r: r["commands"][12]["args"].pop(),
    "command_final_extra_task": lambda repo, run, r: r["commands"][12]["args"].append("clean"),
    "product_symlink_parent": lambda repo, run, r: symlink_parent(repo, run, r),
    "command_log_escape": lambda repo, run, r: r["commands"][1].update(log=str(run / "../outside.log")),
    "probe_log_escape": lambda repo, run, r: r["probes"][0].update(log=str(run / "../outside.log")),
    "archive_receipt_escape": lambda repo, run, r: r.update(archiveHashes={str(run / "../outside.zip"): "0" * 64}),
    "protected_receipt_escape": lambda repo, run, r: r["finalProtectedFiles"].update({"../outside.jar": {"sha256": "0" * 64, "mode": 420, "key": [1, 1]}}),
    "probe_authority_wrong_release": lambda repo, run, r: (pathlib.Path(r["probes"][6]["root"]) / "RELEASE").write_text("lease-refused\n"),
}
# Separate test identities for every required install, phase and init position.
for _index in range(13):
    NEGATIVE_CASES[f"command_phase_{_index}"] = lambda repo, run, r, i=_index: mutate_commands(r, (i,), "phase")
    if _index:
        NEGATIVE_CASES[f"command_init_{_index}"] = lambda repo, run, r, i=_index: mutate_commands(r, (i,), "init")
        NEGATIVE_CASES[f"command_task_{_index}"] = lambda repo, run, r, i=_index: mutate_commands(r, (i,), "task")
for _kind in ("symlink", "fifo"):
    for _target in ("archive", "protected", "probe_log", "release", "command_log", "publisher_receipt"):
        def special_file(repo, run, r, kind=_kind, target=_target):
            paths = {"archive": first_archive(run, r), "protected": protected_jar(run), "probe_log": probe_log(r),
                     "release": pathlib.Path(r["probes"][0]["root"]) / "RELEASE",
                     "command_log": pathlib.Path(r["commands"][0]["log"]),
                     "publisher_receipt": repo / "build/atomic-install/publisher-controls/run-fixture/passed.txt"}
            replace_with_symlink_or_fifo(paths[target], kind)
        NEGATIVE_CASES[f"{_target}_{_kind}"] = special_file


def negative_control(mutation):
    def control(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo, run = fixture(pathlib.Path(temp))
            self.assertEqual("passed", verifier.select_and_verify(repo, "0123456789abcdef")["status"])
            record = json.loads((run / "qualification.json").read_text())
            mutation(repo, run, record)
            write_json(run / "qualification.json", record)
            with self.assertRaises((verifier.QualificationError, OSError)):
                verifier.select_and_verify(repo, "0123456789abcdef")
    return control


for _name, _mutation in NEGATIVE_CASES.items():
    setattr(QualificationVerifierControls, "test_reject_" + _name, negative_control(_mutation))


if __name__ == "__main__":
    unittest.main(verbosity=2)
