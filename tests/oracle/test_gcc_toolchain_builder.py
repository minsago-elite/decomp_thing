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

    def write_pair(self, *, nested=True, subject=False, join=True, statement_subject="matching") -> None:
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
        subject_digest = runtime_digest[7:] if statement_subject == "matching" else "f" * 64
        statement_subjects = [] if statement_subject == "empty" else [{"name": "fixture:1",
            "digest": {"sha256": subject_digest}}]
        statement = {"_type": "https://in-toto.io/Statement/v0.1", "subject": statement_subjects,
            "predicateType": "https://slsa.dev/provenance/v0.2",
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

    def test_empty_provenance_subject_refuses(self):
        self.write_pair(statement_subject="empty")
        result = self.run_parser()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("statement subject", result.stderr)

    def test_wrong_provenance_subject_refuses(self):
        self.write_pair(statement_subject="wrong")
        result = self.run_parser()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("statement subject", result.stderr)

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
        self.assertIn("build/g/*/evidence", workflow)
        self.assertIn("python3 scripts/ci-gcc-toolchain-owner.py", helper)
        self.assertIn("owner_call reserve", helper)
        self.assertIn("owner_call launch-rootless", helper)
        self.assertIn("owner_call launch-buildkit", helper)
        self.assertIn("owner_call ready --role rootless", helper)
        self.assertIn("owner_call ready --role buildkit", helper)
        self.assertIn("owner_call stop --role buildkit", helper)
        self.assertIn("owner_call stop --role rootless", helper)
        self.assertIn("owner_call stage-upload", helper)
        self.assertIn("owner_call release", helper)
        self.assertNotIn('setsid "$rootless/dockerd-rootless.sh"', helper)
        self.assertNotIn('sudo -n bash -c', helper)
        self.assertNotIn("record_process()", helper)
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

class GccNamedOciSolveAdmissionTest(unittest.TestCase):
    """Exercise only extracted production solve functions with inert boundaries."""

    def _function(self, source: str, name: str, next_name: str) -> str:
        start = source.index(f"{name}() {{")
        end = source.index(f"\n{next_name}() {{", start)
        return source[start:end]

    def _invoke(self, source: str, *, argv_edit: str = "") -> subprocess.CompletedProcess:
        solve = self._function(source, "build_solve_argv", "run_solve")
        run = self._function(source, "run_solve", "admit_solve_argv")
        admit = self._function(source, "admit_solve_argv", "verify_archive")
        script = ("set -euo pipefail\nbuildctl=/fake/buildctl\nbk_socket=/fake/buildkit.sock\nrepo=/repo\n"
                  "evidence=/evidence\ntag=ghcr.io/example/gcc:locked\n"
                  "die() { printf 'REFUSED'; exit 1; }\n"
                  "timeout() { printf 'FAKE_LAUNCH'; printf ' <%s>' \"$@\"; printf '\\n'; return 0; }\n"
                  "bounded_stream() { while IFS= read -r line; do printf '%s\\n' \"$line\"; done; }\n")
        if argv_edit:
            # Interpose only the argv producer; still exercise the real run_solve admission call.
            solve = solve.replace("build_solve_argv() {", "original_build_solve_argv() {", 1)
        script += solve + "\n" + run + "\n" + admit + "\n"
        if argv_edit:
            script += 'build_solve_argv() { original_build_solve_argv "$@";\n' + argv_edit + "\n}\n"
        script += "run_solve /tmp/docker.tar /tmp/oci.tar\n"
        return subprocess.run(["/usr/bin/bash", "-c", script], cwd=ROOT, text=True,
                              env={"PATH": "/nonexistent", "LANG": "C.UTF-8", "TMPDIR": str(ARTIFACTS)},
                              capture_output=True, timeout=5)

    def test_normal_argv_keeps_one_solve_and_same_tag_for_both_exports(self):
        source = HELPER.read_text()
        result = self._invoke(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("FAKE_LAUNCH"), 1)
        actual = [item[1:-1] for item in result.stdout.split()[1:]]
        previous = ["--signal=TERM", "--kill-after=30s", "20m", "/fake/buildctl", "--addr",
                    "unix:///fake/buildkit.sock", "build", "--frontend", "dockerfile.v0", "--local",
                    "context=/repo/oracle/gcc/16.2.0", "--local", "dockerfile=/repo/oracle/gcc/16.2.0",
                    "--opt", "filename=build-toolchain.Dockerfile", "--opt", "platform=linux/amd64",
                    "--opt", "build-arg:SOURCE_DATE_EPOCH=1786060800", "--no-cache", "--opt",
                    "attest:provenance=mode=min,inline-only=true", "--output",
                    "type=docker,name=ghcr.io/example/gcc:locked,dest=/tmp/docker.tar", "--output",
                    "type=oci,dest=/tmp/oci.tar,attestation-inline=true", "--metadata-file",
                    "/evidence/solve-metadata.json", "--progress=plain"]
        current = list(actual)
        named_oci = "type=oci,name=ghcr.io/example/gcc:locked,dest=/tmp/oci.tar,attestation-inline=true"
        self.assertIn(named_oci, current)
        oci = current.index(named_oci)
        current[oci] = current[oci].replace("name=ghcr.io/example/gcc:locked,", "")
        self.assertEqual(current, previous)
        expected = ('--output "type=docker,name=$tag,dest=$1"\n'
                    '    --output "type=oci,name=$tag,dest=$2,attestation-inline=true"')
        self.assertIn(expected, source)
        self.assertEqual(source.count("run_solve() {"), 1)
        self.assertEqual(source.count('build_solve_argv "$1" "$2"'), 1)

    def test_missing_or_wrong_oci_name_refuses_before_solve_launch(self):
        source = HELPER.read_text()
        for mutate in (
            'for i in "${!SOLVE_ARGV[@]}"; do [[ ${SOLVE_ARGV[$i]} != type=oci,* ]] || SOLVE_ARGV[$i]=type=oci,dest=/tmp/oci.tar,attestation-inline=true; done',
            'for i in "${!SOLVE_ARGV[@]}"; do [[ ${SOLVE_ARGV[$i]} != type=oci,* ]] || SOLVE_ARGV[$i]=type=oci,name=wrong,dest=/tmp/oci.tar,attestation-inline=true; done',
        ):
            result = self._invoke(source, argv_edit=mutate)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("FAKE_LAUNCH", result.stdout)

    def test_mutant_deleting_production_oci_name_is_detected(self):
        source = HELPER.read_text()
        mutant = source.replace('type=oci,name=$tag,dest=$2,attestation-inline=true',
                                'type=oci,dest=$2,attestation-inline=true', 1)
        result = self._invoke(mutant)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("FAKE_LAUNCH", result.stdout)


class GccInspectApiContractTest(unittest.TestCase):
    """Fixed-lock consumer checks with actual producer bodies and inert effect boundaries."""

    def setUp(self):
        from tests.oracle.gcc_inspect_controls import run_control
        self.run_control = run_control
        root = Path(os.environ.get("GCC_INSPECT_TMP", ROOT / "build/test-tmp/gcc-inspect-api"))
        root.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="inspect-", dir=root)).resolve()
        self.fixtures = ROOT / "tests/oracle/fixtures/gcc-inspect-api"
        self.helper = Path(os.environ.get("GCC_INSPECT_BUILDER", HELPER))
        self.index = 0

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def _case(self, options=None, *, reproduce=False, source=None):
        self.index += 1
        return self.run_control(self.tmp / str(self.index), ROOT, self.helper, self.fixtures,
                                options=options, reproduce=reproduce, source=source)

    def _consumer(self, raw, *, file=False):
        # The same guarded Python entrypoint executes the unchanged strict CLI in a child.
        import base64
        from tests.oracle import gcc_inspect_controls as control
        case = self.tmp / ("consumer-" + str(self.index)); self.index += 1; case.mkdir()
        candidate = case / "inspect.json"; candidate.write_bytes(raw)
        context = case / "context.json"
        context.write_text(json.dumps({"root": str(case), "repo": str(ROOT), "log": str(case / "calls.jsonl")}))
        argv = ["/usr/bin/python3", "-I", "-B", str(Path(control.__file__).resolve()), "python", str(context),
                "scripts/verify-gcc-toolchain-reproduction.py", "--lock", "oracle/gcc/16.2.0/toolchain-reproduction.json",
                "--build-record", "oracle/gcc/16.2.0/build-record.json"]
        if file: argv += ["--inspect-json", str(candidate)]
        return subprocess.run(argv, cwd=ROOT, input=None if file else raw, capture_output=True, timeout=10)

    @staticmethod
    def _encoded(raw):
        import base64
        return base64.b64encode(raw).decode()

    def _version(self, update):
        value = json.loads((self.fixtures / "current-docker-version.json").read_bytes())
        value["Client"]["ApiVersion"] = "1.49"
        update(value)
        return {"version_bytes": self._encoded(json.dumps(value).encode()), "derive_api": False}

    @staticmethod
    def _clients(records):
        return [row for row in records if row["kind"] == "client"]

    def _assert_capture_calls(self, records, evidence):
        client = str(evidence.parent / "tools/docker/docker")
        calls = self._clients(records)
        relevant = [row for row in calls if "version" in row["argv"] or "inspect" in row["argv"]]
        self.assertEqual([row["argv"] for row in relevant], [
            ["--host", "unix:///owned/service.sock", "version", "--format", "{{json .}}"],
            ["--host", "unix:///owned/service.sock", "image", "inspect", "decomp-gcc-oracle-toolchain:16.2.0"],
        ])
        for row in relevant:
            self.assertEqual(row["executable"], client)
            self.assertEqual(row["environment"], {"DOCKER_CONFIG": "/private/docker-config", "DOCKER_API_VERSION": "1.49"})
        timeouts = [row["argv"] for row in records if row["kind"] == "timeout" and "env" in row["argv"] and ("version" in row["argv"] or "inspect" in row["argv"])]
        self.assertEqual(timeouts, [["--signal=TERM", "--kill-after=5s", "30s", "env", "-u", "DOCKER_HOST", "-u", "DOCKER_CONTEXT",
                                    "DOCKER_CONFIG=/private/docker-config", "DOCKER_API_VERSION=1.49", client, *row["argv"]] for row in relevant])
        self.assertFalse(any(row["kind"] == "unwrapped-env" for row in records))

    def test_fixed_lock_current_is_red_and_historical_stdin_and_file_are_green(self):
        current = (self.fixtures / "current-image-inspect.json").read_bytes()
        red = self._consumer(current)
        self.assertNotEqual(red.returncode, 0)
        self.assertIn(b"configSha256 mismatch", red.stderr)
        self.assertIn(b"ee682c2852cca4a6d7d5ff9642ddb1a48aa1bb654d1271a762a85e437016cc5c", red.stderr)
        for file in [False, True]:
            result = self._consumer((self.fixtures / "historical-image-inspect.json").read_bytes(), file=file)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"sha256:807f16e03368e1e0ff3c904f21f1a13c260d78a8b7226a52284a2ee68a4d1511", result.stdout)
            self.assertIn(b"sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248", result.stdout)

    def test_actual_capture_preserves_raw_bytes_and_records_exact_invocations(self):
        result, evidence, records = self._case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self._assert_capture_calls(records, evidence)
        self.assertEqual(len(self._clients(records)), 2)
        raw = (evidence / "image-inspect.json").read_bytes()
        self.assertEqual(raw, (self.fixtures / "historical-image-inspect.json").read_bytes())
        self.assertEqual(self._consumer(raw).returncode, 0)
        sidecar = json.loads((evidence / "image-inspect-api-provenance.json").read_bytes())
        self.assertEqual(sidecar["selectedApi"], "1.49")
        self.assertEqual(sidecar["effectiveApiObservedByVersionCall"], "1.49")
        self.assertIn("not wire-observed", sidecar["classification"])
        self.assertIn("inherited mutable metadata", sidecar["inputAuthority"])
        self.assertIn("no fresh executable authentication", sidecar["inputAuthority"])
        self.assertNotIn("authenticatedFingerprintSha256", sidecar["client"])
        for name, record in [("image-inspect.json", sidecar["inspectFile"]), ("image-inspect-api-version.json", sidecar["versionFile"]),
                             ("executable-sha256.txt", sidecar["client"]["fingerprintRecord"]), ("source-hashes.txt", sidecar["sourceHashRecord"])]:
            data = (evidence / name).read_bytes()
            self.assertEqual(record, {"path": str(evidence / name), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})

    def test_missing_malformed_unsupported_and_failed_capture_refuse_without_stale_success(self):
        updates = [lambda d: d.pop("Client"), lambda d: d.pop("Server"), lambda d: d.__setitem__("Server", None),
                   lambda d: d["Client"].pop("ApiVersion"), lambda d: d["Client"].__setitem__("ApiVersion", "1.55"),
                   lambda d: d["Server"].pop("MinAPIVersion"), lambda d: d["Server"].__setitem__("MinAPIVersion", "1.50"),
                   lambda d: d["Server"].__setitem__("ApiVersion", "1.48"), lambda d: d["Client"].__setitem__("GitCommit", "wrong"),
                   lambda d: d["Server"].__setitem__("GitCommit", "wrong"), lambda d: d["Client"].__setitem__("Version", 29)]
        cases = [self._version(update) for update in updates]
        for bad in [None, 1.49, "1.x", "01.49", "1.049", "1.49.0", "1.99999", "-1.49", "1.49 "]:
            cases.append(self._version(lambda d, bad=bad: d["Client"].__setitem__("ApiVersion", bad)))
        for raw in [b"", b"{", b'{"Client":{},"Client":{}}', b'{"Client":NaN}', b" " * 65537]:
            cases.append({"version_bytes": self._encoded(raw), "derive_api": False})
        cases.append({"version_exit": True})
        for options in cases:
            with self.subTest(options=options.keys()):
                result, evidence, records = self._case(options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(self._clients(records)), 1)
                self.assertFalse((evidence / "image-inspect.json").exists())
                self.assertFalse((evidence / "image-inspect-api-provenance.json").exists())
        for options in [{"inspect_exit": True}, {"inspect_bytes": self._encoded(b'[{"Id":1,"Id":2}]')},
                        {"inspect_bytes": self._encoded(b"[NaN]")}, {"inspect_bytes": self._encoded(b"[]")},
                        {"inspect_bytes": self._encoded(b"")}, {"inspect_bytes": self._encoded(b" " * (16 * 1024 * 1024 + 1))}]:
            result, evidence, records = self._case(options)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(self._clients(records)), 2)
            self.assertFalse((evidence / "image-inspect-api-provenance.json").exists())

    def test_preflight_record_replacements_including_valid_same_length_bytes_refuse(self):
        doc = json.loads((self.fixtures / "current-docker-version.json").read_bytes())
        doc["Client"]["ApiVersion"] = "1.49"
        before = json.dumps(doc).encode(); doc["Client"]["ApiVersion"] = "1.55"
        after = json.dumps(doc).encode(); self.assertEqual(len(before), len(after))
        valid_different = before + b" "
        replacements = [("image-inspect-api-version.json", after), ("image-inspect-api-version.json", valid_different),
                        ("executable-sha256.txt", b"changed retained record\n"), ("source-hashes.txt", b"changed source record\n")]
        for name, raw in replacements:
            with self.subTest(name=name):
                result, evidence, records = self._case({"replace_during_inspect": {name: self._encoded(raw)}}, reproduce=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"preflight bytes changed", result.stderr)
                self.assertFalse((evidence / "image-inspect-api-provenance.json").exists())
                self.assertFalse(any(row["kind"] in {"strict", "live-sentinel"} for row in records))

    def test_fingerprint_schema_exact_pin_and_source_raw_byte_binding(self):
        from tests.oracle.gcc_inspect_controls import CLIENT_PIN
        for kind in ["missing", "duplicate", "malformed", "wrong-pin", "oversized"]:
            next_client = self.tmp / str(self.index + 1) / "tools/docker/docker"
            line = f"{CLIENT_PIN}  {next_client}\n".encode()
            raw = {"missing": b"", "duplicate": line * 2, "malformed": b"not a fingerprint\n",
                   "wrong-pin": line.replace(CLIENT_PIN.encode(), b"0" * 64), "oversized": b" " * 65537}[kind]
            result, evidence, records = self._case({"fingerprint_bytes": self._encoded(raw)})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(self._clients(records)), 1)
            self.assertFalse((evidence / "image-inspect-api-provenance.json").exists())
        digests = []
        for raw in [b"source\n", b"source\r\n"]:
            result, evidence, _ = self._case({"source_bytes": self._encoded(raw)})
            self.assertEqual(result.returncode, 0, result.stderr)
            digest = json.loads((evidence / "image-inspect-api-provenance.json").read_bytes())["sourceHashRecord"]["sha256"]
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest()); digests.append(digest)
        self.assertNotEqual(*digests)

    def test_actual_bounded_reader_requests_limit_plus_one_before_parsing(self):
        import ast
        from io import BytesIO
        from types import SimpleNamespace
        source = self.helper.read_text()
        for label in ["PYVERSION", "PYPROVENANCE"]:
            body = source.split("<<'" + label + "'\n", 1)[1].split("\n" + label, 1)[0]
            declaration = next(node for node in ast.parse(body).body if isinstance(node, ast.FunctionDef) and node.name == "bounded")
            for size, succeeds in [(0, False), (8, True), (9, False)]:
                reads = []
                class Reader(BytesIO):
                    def read(self, count=-1): reads.append(count); return super().read(count)
                fake_path = SimpleNamespace(open=lambda mode: Reader(b"x" * size))
                namespace = {"pathlib": SimpleNamespace(Path=lambda path: fake_path)}
                exec(compile(ast.Module(body=[declaration], type_ignores=[]), "<actual-bounded-reader>", "exec"), namespace)
                if succeeds: self.assertEqual(namespace["bounded"]("fixture", 8), b"x" * 8)
                else:
                    with self.assertRaises(SystemExit): namespace["bounded"]("fixture", 8)
                self.assertEqual(reads, [9])

    def test_sidecar_failures_and_existing_temporary_file_never_publish_success(self):
        for failure in ["open", "write", "flush", "replace"]:
            result, evidence, records = self._case({"sidecar_failure": failure}, reproduce=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((evidence / "image-inspect-api-provenance.json").exists())
            self.assertFalse(any(row["kind"] in {"strict", "live-sentinel"} for row in records))
        result, evidence, _ = self._case({"leftover_tmp": True})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((evidence / "image-inspect-api-provenance.json").exists())
        self.assertEqual((evidence / "image-inspect-api-provenance.json.tmp").read_bytes(), b"earlier-unknown-control")

    def test_actual_reproduce_capture_count_strict_order_and_no_publication(self):
        for kind in ["current", "historical"]:
            result, evidence, records = self._case({"inspect_kind": kind}, reproduce=True)
            self.assertNotEqual(result.returncode, 0)
            self._assert_capture_calls(records, evidence)
            events = [row["kind"] for row in records if row["kind"] in {"strict", "live-sentinel"}]
            self.assertEqual(events, ["strict"] if kind == "current" else ["strict", "live-sentinel"])
            if kind == "current": self.assertIn(b"configSha256 mismatch", result.stderr)
            self.assertFalse((evidence.parent / "GITHUB_ENV").exists())

    def test_nested_shell_and_python_guards_refuse_before_external_dispatch(self):
        source = self.helper.read_text()
        prefix = "  local inspect_api=1.49"
        probes = ["/usr/bin/docker version", 'x=$(/usr/bin/docker version)', 'admission=$(/usr/bin/docker version)', 'X=1 /usr/bin/docker version',
                  'timeout --signal=TERM --kill-after=5s 30s env /usr/bin/docker version',
                  'python3 -c \'import subprocess; subprocess.run(["/usr/bin/docker", "version"])\'']
        for probe in probes:
            mutated = source.replace(prefix, prefix + "\n  " + probe, 1)
            result, _, records = self._case(source=mutated)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self._clients(records))
            self.assertTrue(b"refused" in result.stderr or b"unexpected" in result.stderr)
        nested = source.replace('import hashlib, json, pathlib, re, sys',
                                'import hashlib, json, pathlib, re, sys\nimport subprocess\nsubprocess.run(["/usr/bin/docker", "version"])', 1)
        result, _, records = self._case(source=nested)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'network/process/native boundary refused', result.stderr)
        self.assertEqual(len(self._clients(records)), 1)

    def test_real_consumer_preserves_all_config_identity_and_serialization_negatives(self):
        historical = json.loads((self.fixtures / "historical-image-inspect.json").read_bytes())
        changes = {"Env": ["DIFFERENT=1"], "Cmd": ["different"], "Domainname": "changed", "Hostname": "changed",
                   "Image": "changed", "User": "changed", "WorkingDir": "/changed", "AttachStderr": True,
                   "AttachStdin": True, "AttachStdout": True, "OpenStdin": True, "StdinOnce": True, "Tty": True,
                   "Entrypoint": ["changed"], "Labels": {"changed": "1"}, "OnBuild": ["changed"], "Volumes": {"/changed": {}},
                   "StopSignal": "SIGTERM", "ExposedPorts": {"80/tcp": {}}, "ArgsEscaped": True,
                   "Healthcheck": {"Test": ["CMD", "x"]}, "Shell": ["/bin/sh"], "UnknownNonempty": "changed"}
        for key, value in changes.items():
            candidate = json.loads(json.dumps(historical)); candidate[0]["Config"][key] = value
            result = self._consumer(json.dumps(candidate).encode())
            self.assertNotEqual(result.returncode, 0, key); self.assertIn(b"configSha256 mismatch", result.stderr)
        candidate = json.loads(json.dumps(historical)); candidate[0]["Config"]["Env"].reverse()
        self.assertNotEqual(self._consumer(json.dumps(candidate).encode()).returncode, 0)
        mutations = [lambda d: d[0].pop("Config"), lambda d: d[0].__setitem__("Config", {}), lambda d: d[0]["Config"].pop("User"),
                     lambda d: d[0].__setitem__("Id", "sha256:" + "0" * 64), lambda d: d[0].__setitem__("Created", "2026-01-01T00:00:00Z"),
                     lambda d: d[0].__setitem__("Architecture", "arm64"), lambda d: d[0].__setitem__("Os", "windows"),
                     lambda d: d[0]["RootFS"]["Layers"].pop(), lambda d: d[0]["RootFS"]["Layers"].reverse()]
        mutations += [lambda d, i=i: d[0]["RootFS"]["Layers"].__setitem__(i, "sha256:" + "0" * 64) for i in range(9)]
        for mutate in mutations:
            candidate = json.loads(json.dumps(historical)); mutate(candidate)
            self.assertNotEqual(self._consumer(json.dumps(candidate).encode()).returncode, 0)
        current = json.loads((self.fixtures / "current-image-inspect.json").read_bytes())
        for api in ["1.50", "1.51", "1.55"]:
            candidate = json.loads(json.dumps(current))
            if api != "1.55":
                for key, value in {"Cmd": None, "Entrypoint": None, "Env": None, "Labels": None, "OnBuild": None, "User": "", "Volumes": None, "WorkingDir": ""}.items():
                    if candidate[0]["Config"].get(key) is None: candidate[0]["Config"][key] = value
            result = self._consumer(json.dumps(candidate).encode())
            self.assertNotEqual(result.returncode, 0); self.assertIn(b"configSha256 mismatch", result.stderr)

    def test_omitted_nested_config_fields_change_the_consequent_image_digest(self):
        raw = (self.fixtures / "current-image-config.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "807f16e03368e1e0ff3c904f21f1a13c260d78a8b7226a52284a2ee68a4d1511")
        config = json.loads(raw)
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        baseline = hashlib.sha256(canonical(config)).hexdigest()
        historical = json.loads((self.fixtures / "historical-image-inspect.json").read_bytes())
        for key, value in [("Hostname", "changed"), ("Tty", True), ("AttachStdin", True), ("AttachStdout", True), ("AttachStderr", True), ("NewRawField", "changed")]:
            changed = json.loads(json.dumps(config)); changed["config"][key] = value
            self.assertEqual(changed["config"][key], value)
            self.assertEqual({k: v for k, v in changed.items() if k != "config"}, {k: v for k, v in config.items() if k != "config"})
            digest = hashlib.sha256(canonical(changed)).hexdigest(); self.assertNotEqual(digest, baseline)
            candidate = json.loads(json.dumps(historical)); candidate[0]["Id"] = "sha256:" + digest
            result = self._consumer(json.dumps(candidate).encode())
            self.assertNotEqual(result.returncode, 0); self.assertIn(b"imageDigest", result.stderr)


if __name__ == "__main__":
    unittest.main()

