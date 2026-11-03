from __future__ import annotations

import ast
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PARSER = ROOT / "scripts/ci-gcc-toolchain-archive.py"
HELPER = ROOT / "scripts/ci-gcc-toolchain-builder.sh"
WORKFLOW = ROOT / ".github/workflows/gcc-oracle-model.yml"
ARTIFACTS = ROOT / "build/pr-merge-audit/gcc-native-builder-repair-implementation/tests"


def tar_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as tf:
        for name, payload in entries:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def write_tar(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w:") as tf:
        for name, payload in entries:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))


class GccToolchainBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ARTIFACTS, prefix="builder-")
        self.root = Path(self.temp.name)
        self.out = self.root / "evidence"
        self.out.mkdir(mode=0o700)
        self.docker = self.root / "docker.tar"
        self.oci = self.root / "oci.tar"
        self.layers = [tar_bytes([(f"usr/file-{i}", f"payload-{i}".encode())]) for i in range(9)]
        self.config = {"created": "2026-08-07T00:00:00Z", "architecture": "amd64", "os": "linux",
            "config": {"Cmd": ["bash"]}, "rootfs": {"type": "layers", "diff_ids": [
                "sha256:" + hashlib.sha256(item).hexdigest() for item in self.layers]}}
        self.config_raw = json.dumps(self.config, sort_keys=True, separators=(",", ":")).encode()
        self.write_pair()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_pair(self, *, nested=True, subject=False, join=True) -> None:
        stored = [gzip.compress(item, mtime=0) for item in self.layers]
        names = [f"blobs/sha256/{hashlib.sha256(item).hexdigest()}" for item in stored]
        manifest = [{"Config": "config.json", "RepoTags": ["fixture:1"],
                     "Layers": [f"layer-{i}.tar.gz" for i in range(9)]}]
        write_tar(self.docker, [("manifest.json", json.dumps(manifest).encode()),
            ("config.json", self.config_raw), *[(f"layer-{i}.tar.gz", value) for i, value in enumerate(stored)]])
        c_digest = "sha256:" + hashlib.sha256(self.config_raw).hexdigest()
        blobs = [("blobs/sha256/" + c_digest[7:], self.config_raw)]
        layers = []
        for original, compressed in zip(self.layers, stored):
            digest = "sha256:" + hashlib.sha256(compressed).hexdigest()
            blobs.append(("blobs/sha256/" + digest[7:], compressed))
            layers.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest,
                           "size": len(compressed)})
        runtime = {"schemaVersion": 2, "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": c_digest, "size": len(self.config_raw)}, "layers": layers}
        runtime_raw = json.dumps(runtime, sort_keys=True).encode()
        runtime_digest = "sha256:" + hashlib.sha256(runtime_raw).hexdigest()
        statement = {"_type": "https://in-toto.io/Statement/v0.1", "subject": [{"name": "fixture:1",
            "digest": {"sha256": runtime_digest[7:]}}], "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {}}
        statement_raw = json.dumps(statement, sort_keys=True).encode()
        statement_digest = "sha256:" + hashlib.sha256(statement_raw).hexdigest()
        blobs.append(("blobs/sha256/" + statement_digest[7:], statement_raw))
        att_config = b'{"mediaType":"application/vnd.oci.image.config.v1+json"}'
        ac_digest = "sha256:" + hashlib.sha256(att_config).hexdigest()
        blobs.append(("blobs/sha256/" + ac_digest[7:], att_config))
        att = {"schemaVersion": 2, "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": ac_digest, "size": len(att_config)}, "layers": [{"mediaType": "application/vnd.in-toto+json",
            "digest": statement_digest, "size": len(statement_raw)}]}
        if subject:
            att["subject"] = {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": runtime_digest, "size": len(runtime_raw)}
        att_raw = json.dumps(att, sort_keys=True).encode()
        att_digest = "sha256:" + hashlib.sha256(att_raw).hexdigest()
        descriptors = [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": runtime_digest,
            "size": len(runtime_raw)}, {"mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": att_digest, "size": len(att_raw), "annotations": {
                "vnd.docker.reference.type": "attestation-manifest",
                "vnd.docker.reference.digest": runtime_digest if join else "sha256:" + "f" * 64}}]
        outer_entries = [("blobs/sha256/" + runtime_digest[7:], runtime_raw),
                         ("blobs/sha256/" + att_digest[7:], att_raw), *blobs]
        if nested:
            nested_raw = json.dumps({"schemaVersion": 2, "manifests": descriptors}, sort_keys=True).encode()
            nested_digest = "sha256:" + hashlib.sha256(nested_raw).hexdigest()
            index = {"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": nested_digest, "size": len(nested_raw)}]}
            outer_entries += [("blobs/sha256/" + nested_digest[7:], nested_raw)]
        else:
            index = {"schemaVersion": 2, "manifests": descriptors}
        write_tar(self.oci, [("index.json", json.dumps(index).encode()), *outer_entries])

    def run_parser(self, cap=4 * 1024 * 1024):
        env = {**os.environ, "TMPDIR": str(self.root)}
        return subprocess.run([sys.executable, str(PARSER), "inspect", str(self.docker), str(self.oci),
            str(self.out), str(cap)], cwd=ROOT, env=env, text=True, capture_output=True, timeout=10)

    def test_source_shaped_compressed_nested_default_attestation_succeeds(self):
        result = self.run_parser()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads((self.out / "ordered-layers.json").read_text())
        self.assertEqual(len(rows), 9)
        self.assertTrue(all(row["codec"] == "gzip" for row in rows))
        self.assertGreater(rows[0]["storedBytes"], 0)
        self.assertNotEqual(rows[0]["storedBytes"], rows[0]["decodedBytes"])
        self.assertTrue(json.loads((self.out / "provenance-joins.json").read_text())[0]["statementSubjectsJoined"])
        self.assertTrue((self.out / "final-layer.tar").is_file())

    def test_optional_matching_attestation_subject_is_accepted_but_bad_join_refuses(self):
        self.write_pair(subject=True)
        self.assertEqual(self.run_parser().returncode, 0)
        self.write_pair(subject=True, join=False)
        result = self.run_parser()
        self.assertNotEqual(result.returncode, 0)

    def test_actual_worker_mode_requires_explicit_oci_native_sandbox(self):
        fixture = self.root / "workers.json"
        worker = {"executor": "oci", "snapshotter": "native", "process-mode": "sandbox",
            "platforms": ["linux/amd64"], "labels": {}}
        fixture.write_text(json.dumps([worker]))
        run = subprocess.run([sys.executable, str(PARSER), "workers", str(fixture)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        worker["process-mode"] = "no-sandbox"
        fixture.write_text(json.dumps([worker]))
        self.assertNotEqual(subprocess.run([sys.executable, str(PARSER), "workers", str(fixture)],
            capture_output=True).returncode, 0)
        worker.pop("process-mode")
        fixture.write_text(json.dumps([worker]))
        self.assertNotEqual(subprocess.run([sys.executable, str(PARSER), "workers", str(fixture)],
            capture_output=True).returncode, 0)

    def test_live_verification_precedes_image_publication(self):
        helper = HELPER.read_text()
        strict = helper.index("scripts/verify-gcc-toolchain-reproduction.py")
        invocation = helper.index('"$docker_bin" --host "unix://$socket" run --rm')
        live = helper.index("scripts/verify-gcc-oracle-build-record.py")
        publication = helper.index("GCC_TOOLCHAIN_IMAGE_ID=%s")
        self.assertLess(strict, invocation)
        self.assertLess(live, publication)
        for required in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                         "--source-lock", "--build-record", "--container-digest", "--reproduction-lock"):
            self.assertIn(required, helper[invocation:publication])

    def test_authentication_applies_the_locked_client_fingerprint_to_the_client(self):
        # Execute the actual authentication prefix with every external effect stubbed. Stop at
        # the daemon member fingerprint before any extracted executable can run.
        helper = HELPER.read_text()
        body = "authenticate() {\n" + helper.split("\nauthenticate() {\n", 1)[1].split("\nstart_rootless() {", 1)[0]
        script = "set -euo pipefail\n" + body + """
clean_environment() { :; }
bounded_curl() { :; }
safe_extract() { :; }
check_archive() { :; }
install() { :; }
mv() { :; }
sha256sum() { :; }
check_executable() { printf '%s\n' "$1" "$2" "$3"; if [[ "$1" == "$daemon_bin" ]]; then exit 0; fi; }
authenticate
"""
        client = self.root / "tools/docker/docker"
        env = {"PATH": "/usr/bin:/bin", "tools": str(self.root / "tools"),
               "docker_bin": str(client), "daemon_bin": str(self.root / "tools/docker/dockerd"),
               "docker_hash": "authored-archive-stub", "rootless_hash": "authored-archive-stub",
               "buildkit_hash": "authored-archive-stub"}
        result = subprocess.run(["/usr/bin/bash", "--noprofile", "--norc", "-c", script],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        # Independently recorded Docker client member fingerprint, not the daemon's.
        daemon_sha = "c3ecdc8ac9e56b9a53ffd9fd4aece65432814597046f8d188a538be18c000df8"
        self.assertEqual(result.stdout.splitlines(), [str(client), "42677472",
                         "e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13",
                         str(self.root / "tools/docker/dockerd"), "99870816", daemon_sha])
        owner = ast.parse((ROOT / "scripts/ci-gcc-toolchain-owner.py").read_text())
        pins = next(ast.literal_eval(node.value) for node in owner.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "PINNED_TOOL_HASHES" for target in node.targets))
        self.assertEqual(pins["dockerd"], daemon_sha)

    def test_actual_workflow_invokes_authenticate_and_reproduction_stages(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("bash scripts/ci-gcc-toolchain-builder.sh authenticate", workflow)
        self.assertIn("bash scripts/ci-gcc-toolchain-builder.sh reproduce", workflow)
        self.assertIn("test_gcc_toolchain_builder", workflow)
        self.assertIn("GCC_TOOLCHAIN_IMAGE_ID", HELPER.read_text())

    def test_workflow_uses_and_retains_the_owned_builder_layout(self):
        workflow = WORKFLOW.read_text()
        helper = HELPER.read_text()
        self.assertIn("id: gcc-builder-init", workflow)
        self.assertIn("steps.gcc-builder-init.outputs.job-root", workflow)
        self.assertIn("build/g/*/v/e", workflow)
        self.assertNotIn("build/gcc-toolchain-reproduction/", workflow)
        self.assertIn("GCC_BUILDER_ROOT=%s", helper)
        self.assertIn('"$socket" "$job_root"', helper)

    def test_generated_socket_inventory_accepts_107_and_rejects_108_bytes(self):
        suffixes = ("/d.sock", "/b.sock", "/r/api.sock", "/x/containerd/containerd.sock",
                    "/x/containerd/containerd.sock.ttrpc", "/t/runc-console.sock")
        longest = max(suffixes, key=len)
        for budget, expected in ((107, 0), (108, 1)):
            root = "/" + "r" * (budget - len(longest) - 1)
            script = "source \"$1\"; job_root=\"$2\"; socket=\"$job_root/d.sock\"; " \
                "bk_socket=\"$job_root/b.sock\"; validate_socket_inventory"
            result = subprocess.run(["/usr/bin/bash", "-c", script, "socket-control", str(HELPER), root],
                cwd=ROOT, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, expected, result.stderr)

if __name__ == "__main__":
    unittest.main()
