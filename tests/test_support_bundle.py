"""Synthetic checks that scripts/collect-support-bundle.py keeps secrets, paths and job content out."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("support_bundle", REPOSITORY_ROOT / "scripts/collect-support-bundle.py")
bundle_module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(bundle_module)

SECRET = "sk-fixture-provider-secret-value"
JOB = "0123456789abcdef0123456789abcdef"
PASSPHRASE = "private-keystore-passphrase"
REQUEST = "web-http-failure request_id=6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f status=503 code=JOB_STORAGE_UNAVAILABLE"


class SupportBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        (REPOSITORY_ROOT / "build").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="support-bundle-", dir=REPOSITORY_ROOT / "build")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.install = self.root / "install"
        (self.install / "bin").mkdir(parents=True)
        (self.install / "lib").mkdir()
        jar = io.BytesIO()
        with zipfile.ZipFile(jar, "w") as archive:
            archive.writestr("decompengine/web/ui/asset-manifest.json", json.dumps({"buildId": "b" * 64}))
        self.jar = jar.getvalue()
        (self.install / "lib/llm-bin-patch-0.1.0.jar").write_bytes(self.jar)
        launcher = self.install / "bin/llm_bin_patch"
        launcher.write_text(
            "#!/bin/sh\n"
            f"echo '[ok] Java: Check passed.'\n"
            f"echo '[failed] angr: interpreter {self.install}/python token {SECRET} missing.'\n"
            "echo 'debug: unlisted diagnostic line'\n"
            "echo 'Environment check failed (1 check(s)); resolve each [failed] item above.'\n"
            "exit 1\n")
        launcher.chmod(0o755)
        self.data = self.root / "data/jobs"
        job = self.data / JOB
        (job / "reports").mkdir(parents=True)
        (job / "input.elf").write_bytes(b"\x7fELF private binary")
        (job / "job.json").write_text(json.dumps({"filename": "customer-secret.elf", "binary_path": str(job / "input.elf")}))
        (job / "workflow-state.json").write_text(json.dumps({"schemaVersion": 1}))
        damaged = self.data / ("f" * 32)
        damaged.mkdir()
        (damaged / "workflow-state.json").write_text(json.dumps({"schemaVersion": "customer-confidential-schema"}))
        (job / "reports/exploration.json").write_text("{\"stdout\": \"private output\"}")
        (self.data / ".web-owner.lock").write_bytes(b"")
        (self.data / "customer-confidential-project.lock").write_bytes(b"")
        self.log = self.root / "server.err"
        self.log.write_text(
            "Serving decomp_engine spa UI on http://127.0.0.1:8000/\n"
            "Open local browser session (expires 2026-10-22T01:01:19Z): http://127.0.0.1:8000/#bootstrap=abcdefghijklmnopqrstuvwxyz012345\n"
            f"{REQUEST}\n"
            f"Exception in thread main: failed at {job}/job.json\n")
        self.reply = self.root / "bootstrap.json"
        self.reply.write_text(json.dumps({"requestId": "r", "data": {
            "applicationBuildId": "a" * 64, "uiBuildId": "b" * 64, "readiness": "degraded", "basePath": "/",
            "csrfToken": "csrf-secret-value-0123456789", "serverInstanceId": "instance", "sessionExpiresAt": "2026",
            "capabilities": [{"id": "workflows", "state": "unavailable", "reasonCode": "PREVIEW_UNAVAILABLE", "message": "m"}],
            "limits": {"maxUploadBytes": "33554432"},
            "runtime": {"javaVersion": "21", "osName": "linux", "architecture": "x86_64", "gitVersion": None}}}))
        java_home = self.root / "jdk"
        (java_home / "bin").mkdir(parents=True)
        java = java_home / "bin/java"
        # Mirrors the JVM: option variables are echoed to stderr before the version lines.
        java.write_text(
            "#!/bin/sh\n"
            "[ -n \"$JAVA_TOOL_OPTIONS\" ] && echo \"Picked up JAVA_TOOL_OPTIONS: $JAVA_TOOL_OPTIONS\" >&2\n"
            "[ -n \"$JDK_JAVA_OPTIONS\" ] && echo \"NOTE: Picked up JDK_JAVA_OPTIONS: $JDK_JAVA_OPTIONS\" >&2\n"
            "echo 'openjdk version \"21.0.12.1\" 2026-08-18 LTS' >&2\n"
            "echo 'OpenJDK Runtime Environment Temurin-21.0.12.1+1 (build 21.0.12.1+1-LTS)' >&2\n"
            "echo 'OpenJDK 64-Bit Server VM Temurin-21.0.12.1+1 (build 21.0.12.1+1-LTS, mixed mode, sharing)' >&2\n")
        java.chmod(0o755)
        self.environment = {"PATH": "/usr/bin:/bin", "OPENAI_API_KEY": SECRET, "HOME": str(self.root),
                            "JAVA_HOME": str(java_home),
                            "JAVA_TOOL_OPTIONS": f"-Djavax.net.ssl.keyStorePassword={PASSPHRASE}",
                            "JDK_JAVA_OPTIONS": f"-Dprovider.password={PASSPHRASE}"}

    def collect(self) -> Path:
        return bundle_module.collect(self.install, self.root / "out", self.data, self.log, self.reply, self.environment)

    def test_bundle_contains_only_allowlisted_redacted_facts(self) -> None:
        bundle = self.collect()
        names = sorted(path.name for path in bundle.iterdir())
        self.assertEqual(["README.txt", "distribution.json", "doctor.txt", "java.txt", "requests.txt", "runtime.json", "storage.json"], names)
        text = "\n".join(path.read_text() for path in bundle.iterdir())
        for forbidden in (SECRET, PASSPHRASE, "Picked up", "customer-confidential", str(self.root), str(self.data), JOB, "customer-secret", "private", "bootstrap=",
                          "csrf-secret", "instance", "unlisted diagnostic"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(REQUEST + "\n", (bundle / "requests.txt").read_text())
        distribution = json.loads((bundle / "distribution.json").read_text())
        self.assertEqual(hashlib.sha256(self.jar).hexdigest(), distribution["applicationBuildId"])
        self.assertEqual("b" * 64, distribution["uiBuildId"])
        storage = json.loads((bundle / "storage.json").read_text())
        self.assertEqual(2, storage["jobDirectories"])
        self.assertEqual({"1": 1, "invalid": 1}, storage["workflowStateSchemaVersions"])
        self.assertEqual([".web-owner.lock"], storage["ownerLocks"])
        self.assertEqual(3, len((bundle / "java.txt").read_text().splitlines()))
        self.assertIn('openjdk version "21.0.12.1"', (bundle / "java.txt").read_text())
        doctor = (bundle / "doctor.txt").read_text()
        self.assertIn("[ok] Java: Check passed.", doctor)
        self.assertIn("<redacted>", doctor)
        self.assertIn("exit status: 1", doctor)
        runtime = json.loads((bundle / "runtime.json").read_text())
        self.assertEqual("/", runtime["basePath"])
        self.assertEqual([{"id": "workflows", "state": "unavailable", "reasonCode": "PREVIEW_UNAVAILABLE"}], runtime["capabilities"])

    def test_nested_runtime_objects_keep_only_known_scalar_facts(self) -> None:
        document = json.loads(self.reply.read_text())
        data = document["data"]
        data["uiBuildId"] = {"customer-confidential-build": "private-project"}
        data["apiVersions"] = [1, {"customer-confidential-version": "private-project"}, True]
        data["capabilities"][0]["state"] = {"customer-confidential-state": "private-project"}
        data["limits"]["customer-confidential-limit"] = "private-project"
        data["limits"]["maxJsonBytes"] = {"customer-confidential-object": "private-project"}
        data["runtime"]["scheduler"] = {
            "state": "available", "activeWorkers": "1", "workerLimit": "2",
            "customer-confidential-worker": "private-project"}
        data["runtime"]["progressRetention"] = {
            "enabled": True, "examined": "3", "lastFailureCode": None,
            "customer-confidential-retention": "private-project"}
        self.reply.write_text(json.dumps(document))
        output = self.collect()
        text = (output / "runtime.json").read_text()
        self.assertNotIn("customer-confidential", text)
        self.assertNotIn("private-project", text)
        facts = json.loads(text)
        self.assertNotIn("uiBuildId", facts)
        self.assertEqual([1], facts["apiVersions"])
        self.assertNotIn("state", facts["capabilities"][0])
        self.assertEqual({"maxUploadBytes": "33554432"}, facts["limits"])
        self.assertEqual({"state": "available", "activeWorkers": "1", "workerLimit": "2"},
                         facts["runtime"]["scheduler"])
        self.assertEqual({"enabled": True, "examined": "3", "lastFailureCode": None},
                         facts["runtime"]["progressRetention"])

    def test_numeric_runtime_facts_drop_confidential_or_malformed_scalars(self) -> None:
        document = json.loads(self.reply.read_text())
        data = document["data"]
        for index, malformed in enumerate(("customer-confidential-counter", "-1", "01", "1.5", "1e2", " 1", "١", "9" * 500,
                                           str(1 << 64), -1, 1.5, True, None, [], {})):
            with self.subTest(value=malformed):
                data["limits"] = {"maxUploadBytes": malformed, "maxJsonBytes": malformed,
                                  "defaultPageLimit": malformed, "maxPageLimit": malformed}
                data["runtime"]["scheduler"] = {field: malformed for field in (
                    "activeWorkers", "workerLimit", "queuedTasks", "queueCapacity")}
                data["runtime"]["progressRetention"] = {field: malformed for field in (
                    "examined", "expired", "failures", "enabled", "sampledAt")}
                # True is valid only for the boolean field, never for numeric counters.
                self.reply.write_text(json.dumps(document))
                output = bundle_module.collect(self.install, self.root / f"out-{index}", self.data, self.log,
                                               self.reply, self.environment)
                facts = json.loads((output / "runtime.json").read_text())
                self.assertEqual({}, facts["limits"])
                self.assertEqual({}, facts["runtime"]["scheduler"])
                self.assertEqual({"enabled": True} if malformed is True else {}, facts["runtime"]["progressRetention"])
                self.assertNotIn("customer-confidential", "".join(path.read_text() for path in output.iterdir()))

    def test_runtime_wire_bounds_and_formats_are_preserved(self) -> None:
        document = json.loads(self.reply.read_text())
        data = document["data"]
        data["limits"] = {"maxUploadBytes": str((1 << 64) - 1), "maxJsonBytes": "0",
                          "defaultPageLimit": 1, "maxPageLimit": 200}
        data["runtime"]["scheduler"] = {
            "activeWorkers": "2", "workerLimit": "2", "queuedTasks": "32", "queueCapacity": "32",
            "sampledAt": "2026-10-27T01:02:03.123456789Z", "approximate": True,
            "state": "available", "source": "web-workflow-executor", "lifecycle": "running"}
        data["runtime"]["progressRetention"] = {"enabled": False, "examined": "0", "expired": "1", "failures": "2",
                                                 "sampledAt": "2026-10-27T01:02:03Z", "lastFailureCode": "RETENTION_UNAVAILABLE"}
        self.reply.write_text(json.dumps(document))
        facts = bundle_module.runtime(self.reply)
        self.assertEqual(data["limits"], facts["limits"])
        self.assertEqual(data["runtime"], facts["runtime"])
        data["runtime"]["scheduler"].update(activeWorkers="3", workerLimit="0", queuedTasks="33", queueCapacity="0")
        data["runtime"]["progressRetention"].update(sampledAt="2026-02-30T00:00:00Z", lastFailureCode="private-project")
        self.reply.write_text(json.dumps(document))
        facts = bundle_module.runtime(self.reply)
        for field in ("activeWorkers", "workerLimit", "queuedTasks", "queueCapacity"):
            self.assertNotIn(field, facts["runtime"]["scheduler"])
        for field in ("sampledAt", "lastFailureCode"):
            self.assertNotIn(field, facts["runtime"]["progressRetention"])

    def test_non_object_runtime_is_refused_without_retaining_a_bundle(self) -> None:
        for malformed in (None, "customer-confidential-runtime", []):
            with self.subTest(runtime=malformed):
                self.reply.write_text(json.dumps({"applicationBuildId": "a" * 64, "runtime": malformed}))
                with self.assertRaisesRegex(bundle_module.BundleError, "runtime must be an object"):
                    self.collect()
                self.assertEqual([], list((self.root / "out").iterdir()))

    def test_a_session_reply_is_refused_because_it_lacks_runtime_facts(self) -> None:
        self.reply.write_text(json.dumps({"requestId": "r", "data": {"csrfToken": "csrf-secret-value-0123456789", "expiresAt": "2026"}}))
        with self.assertRaisesRegex(bundle_module.BundleError, "bootstrap"):
            self.collect()
        self.assertEqual([], list((self.root / "out").iterdir()))

    def test_a_leak_that_survives_redaction_deletes_the_bundle(self) -> None:
        original = bundle_module.runtime
        self.addCleanup(setattr, bundle_module, "runtime", original)
        bundle_module.runtime = lambda reply: {"leak": "decomp_session_0123456789abcdef=value"}
        with self.assertRaises(bundle_module.BundleError):
            self.collect()
        self.assertEqual([], list((self.root / "out").iterdir()))


if __name__ == "__main__":
    unittest.main()
