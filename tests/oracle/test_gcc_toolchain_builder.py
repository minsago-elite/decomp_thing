from __future__ import annotations

import hashlib
import ctypes
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
PARSER = ROOT / "scripts/ci-gcc-toolchain-archive.py"
HELPER = ROOT / "scripts/ci-gcc-toolchain-builder.sh"
WORKFLOW = ROOT / ".github/workflows/gcc-oracle-model.yml"


def tar_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as tf:
        for name, payload in entries:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            tf.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def archive(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w:") as tf:
        for name, payload in entries:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))


class GccToolchainBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "build", prefix="gcc-builder-test-")
        self.root = Path(self.temp.name)
        self.out = self.root / "evidence"
        self.out.mkdir(mode=0o700)
        self.docker = self.root / "image.docker.tar"
        self.oci = self.root / "image.oci.tar"
        self.layers = [tar_bytes([(f"usr/file-{i}", f"payload-{i}".encode())]) for i in range(9)]
        self.config = {
            "created": "2026-08-07T00:00:00Z", "architecture": "amd64", "os": "linux",
            "config": {"Cmd": ["bash"]}, "rootfs": {"type": "layers", "diff_ids": [
                "sha256:" + hashlib.sha256(layer).hexdigest() for layer in self.layers]},
        }
        self.config_raw = json.dumps(self.config, sort_keys=True, separators=(",", ":")).encode()
        self.make_pair()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_pair(self, *, unsafe: bool = False, join: bool = True, truncated_layer: bool = False) -> None:
        config_path = "config.json"
        layer_names = [f"{i}/layer.tar" for i in range(9)]
        manifest = [{"Config": config_path, "RepoTags": ["fixture:1"], "Layers": layer_names}]
        docker_entries = [("manifest.json", json.dumps(manifest).encode()), (config_path, self.config_raw)]
        docker_entries += list(zip(layer_names, self.layers))
        if truncated_layer:
            docker_entries[-1] = (layer_names[-1], self.layers[-1][:-20])
        if unsafe:
            docker_entries.append(("../../outside", b"must-not-extract"))
        archive(self.docker, docker_entries)

        config_digest = "sha256:" + hashlib.sha256(self.config_raw).hexdigest()
        blobs: list[tuple[str, bytes]] = []
        config_blob = self.config_raw
        blobs.append(("blobs/sha256/" + config_digest[7:], config_blob))
        runtime_layers = []
        for layer in self.layers:
            digest = "sha256:" + hashlib.sha256(layer).hexdigest()
            runtime_layers.append({"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest,
                "size": len(layer)})
            blobs.append(("blobs/sha256/" + digest[7:], layer))
        runtime = {"schemaVersion": 2, "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest, "size": len(config_blob)}, "layers": runtime_layers}
        runtime_raw = json.dumps(runtime, sort_keys=True).encode()
        runtime_digest = "sha256:" + hashlib.sha256(runtime_raw).hexdigest()
        statement = {"_type": "https://in-toto.io/Statement/v0.1", "subject": [{"name": "fixture:1",
            "digest": {"sha256": runtime_digest[7:]}}], "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {}}
        statement_raw = json.dumps(statement, sort_keys=True).encode()
        statement_digest = "sha256:" + hashlib.sha256(statement_raw).hexdigest()
        blobs.append(("blobs/sha256/" + statement_digest[7:], statement_raw))
        attestation = {"schemaVersion": 2, "subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": runtime_digest, "size": len(runtime_raw)}, "config": {"digest": "sha256:" + "0" * 64},
            "layers": [{"mediaType": "application/vnd.in-toto+json", "digest": statement_digest,
                "size": len(statement_raw)}]}
        att_raw = json.dumps(attestation, sort_keys=True).encode()
        att_digest = "sha256:" + hashlib.sha256(att_raw).hexdigest()
        index = {"schemaVersion": 2, "manifests": [
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": runtime_digest,
             "size": len(runtime_raw)},
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": att_digest,
             "size": len(att_raw), "annotations": {"vnd.docker.reference.type": "attestation-manifest",
             "vnd.docker.reference.digest": runtime_digest if join else "sha256:" + "f" * 64}},
        ]}
        archive(self.oci, [("index.json", json.dumps(index).encode()),
            ("blobs/sha256/" + runtime_digest[7:], runtime_raw),
            ("blobs/sha256/" + att_digest[7:], att_raw), *blobs])

    def run_parser(self, cap: int = 4 * 1024 * 1024) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "TMPDIR": str(self.root)}
        return subprocess.run([sys.executable, str(PARSER), "inspect", str(self.docker), str(self.oci),
            str(self.out), str(cap)], cwd=ROOT, env=env, text=True, capture_output=True, timeout=5)

    def test_actual_workflow_calls_owned_helper_in_required_order(self) -> None:
        workflow = WORKFLOW.read_text()
        sequence = ["Run GCC builder command and archive controls", "Authenticate the pinned Docker executor and BuildKit bundle",
                    "Start the owned rootless behavior executor", "Reproduce and verify the recorded toolchain image"]
        positions = [workflow.index(name) for name in sequence]
        self.assertEqual(positions, sorted(positions))
        self.assert_wired(workflow)
        # This mutation is the integration negative: changing/removing the real call breaks the contract.
        with self.assertRaises(AssertionError):
            self.assert_wired(workflow.replace("bash scripts/ci-gcc-toolchain-builder.sh reproduce", "echo bypass"))
        helper = HELPER.read_text()
        for literal in ("--oci-worker-snapshotter=native", "--oci-worker=true", "--containerd-worker=false",
                        "--oci-worker-platform=linux/amd64", "--oci-worker-net=host", "--no-cache",
                        "SOURCE_DATE_EPOCH=1786060800", "type=docker", "type=oci", "unix://$bk_socket"):
            self.assertIn(literal, helper)
        self.assertIn("unset DOCKER_HOST DOCKER_CONTEXT BUILDKIT_HOST BUILDKIT_DEBUG_FORCE_OVERLAY_DIFF", helper)
        self.assertIn('"features":{"containerd-snapshotter":false}', helper)
        self.assertLess(helper.index("scripts/verify-gcc-toolchain-reproduction.py"), helper.index('GCC_TOOLCHAIN_IMAGE_ID=%s'))

    def assert_wired(self, workflow: str) -> None:
        section = workflow[workflow.index("- name: Reproduce and verify the recorded toolchain image"):]
        self.assertIn("run: bash scripts/ci-gcc-toolchain-builder.sh reproduce", section)
        self.assertNotIn("docker buildx build", section[:section.index("- name: Test oracle schemas")])

    def test_pinned_tool_and_archive_authentication_precedes_launch(self) -> None:
        helper = HELPER.read_text()
        self.assertLess(helper.index("check_archive \"$b\" 82062349"), helper.index("start_buildkit()"))
        self.assertIn("f64589601e0f06164041dc6be45ed259cffb67539130e434d236551d63ab6030", helper)
        self.assertIn("if [[ -e \"$job_root\" ]]; then die \"refusing reused/nonempty job root", helper)
        staged = self.root / "staged-executable"
        staged.write_bytes(b"authentic first\n")
        staged.chmod(0o755)
        digest = hashlib.sha256(staged.read_bytes()).hexdigest()
        script = [str(HELPER), "verify-executable", str(staged), str(staged.stat().st_size), digest]
        verified = subprocess.run(["/usr/bin/bash", *script], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        for changed in (b"changed executable", b"authentic first\nextra"):
            staged.write_bytes(changed)
            refusal = subprocess.run(["/usr/bin/bash", *script], cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(refusal.returncode, 0)
        archive_path = self.root / "authenticated-archive"
        archive_path.write_bytes(b"authentic archive bytes\n")
        archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        archive_args = ["/usr/bin/bash", str(HELPER), "verify-archive", str(archive_path),
            str(archive_path.stat().st_size), archive_hash]
        self.assertEqual(subprocess.run(archive_args, cwd=ROOT, capture_output=True).returncode, 0)
        archive_path.write_bytes(b"mutated archive bytes\n")
        self.assertNotEqual(subprocess.run(archive_args, cwd=ROOT, capture_output=True).returncode, 0)

    def test_production_solve_argv_reaches_absolute_stub_under_hostile_ambient_state(self) -> None:
        sentinel_dir = self.root / "hostile-bin"
        sentinel_dir.mkdir()
        sentinel_hit = self.root / "sentinel-hit"
        for name in ("docker", "buildx", "buildkitd", "buildctl"):
            sentinel = sentinel_dir / name
            sentinel.write_text(f"#!/bin/sh\nprintf '%s\\n' {name} >> {shlex.quote(str(sentinel_hit))}\nexit 99\n")
            sentinel.chmod(0o755)
        stub = self.root / "buildctl-stub"
        stub.write_text("#!/usr/bin/python3\nimport json,os,sys\njson.dump({'argv':sys.argv[1:],'ambient':{k:os.environ.get(k) for k in ('DOCKER_HOST','DOCKER_CONTEXT','BUILDKIT_HOST','BUILDKIT_DEBUG_FORCE_OVERLAY_DIFF')},'path':os.environ['PATH']},open(os.environ['STUB_CAPTURE'],'w'))\nwith open(os.environ['STUB_COUNT'],'a') as f: f.write('solve\\n')\nprint('stub solve')\nraise SystemExit(42 if os.environ.get('STUB_FAIL') else 0)\n")
        stub.chmod(0o755)
        capture = self.root / "solve-capture.json"
        (self.root / "evidence").mkdir(exist_ok=True)
        source = f'''source {shlex.quote(str(HELPER))}
buildctl={shlex.quote(str(stub))}
bk_socket={shlex.quote(str(self.root / 'owned.sock'))}
job_root={shlex.quote(str(self.root / 'owned-root'))}
evidence={shlex.quote(str(self.out))}
repo={shlex.quote(str(ROOT))}
clean_environment
run_solve {shlex.quote(str(self.root / 'image.docker.tar'))} {shlex.quote(str(self.root / 'image.oci.tar'))}'''
        count = self.root / "solve-count.txt"
        env = {**os.environ, "PATH": str(sentinel_dir) + ":/usr/bin:/bin", "STUB_CAPTURE": str(capture),
            "STUB_COUNT": str(count),
            "DOCKER_HOST": "tcp://host.invalid:2375", "DOCKER_CONTEXT": "hostile-context",
            "BUILDKIT_HOST": "tcp://host.invalid:1234", "BUILDKIT_DEBUG_FORCE_OVERLAY_DIFF": "1"}
        result = subprocess.run(["/usr/bin/bash", "-c", source], cwd=ROOT, env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(capture.read_text())
        argv = observed["argv"]
        self.assertEqual(argv[0:5], ["--addr", "unix://" + str(self.root / "owned.sock"), "build", "--frontend", "dockerfile.v0"])
        self.assertIn("--no-cache", argv)
        self.assertIn("--opt", argv)
        self.assertIn("build-arg:SOURCE_DATE_EPOCH=1786060800", argv)
        self.assertEqual(sum(arg.startswith("--output") for arg in argv), 2)
        self.assertIn("type=docker,name=decomp-gcc-oracle-toolchain:16.2.0,dest=" + str(self.root / "image.docker.tar"), argv)
        self.assertIn("type=oci,dest=" + str(self.root / "image.oci.tar") + ",attestation-inline=true", argv)
        self.assertEqual(observed["ambient"], {"DOCKER_HOST": None, "DOCKER_CONTEXT": None,
            "BUILDKIT_HOST": None, "BUILDKIT_DEBUG_FORCE_OVERLAY_DIFF": None})
        self.assertNotIn(str(sentinel_dir), observed["path"])
        self.assertFalse(sentinel_hit.exists())
        self.assertEqual(count.read_text().splitlines(), ["solve"])

        failed_env = self.root / "github-env.txt"
        failed_env.write_text("")
        env.update({"STUB_FAIL": "1", "GITHUB_ENV": str(failed_env)})
        failed = subprocess.run(["/usr/bin/bash", "-c", source], cwd=ROOT, env=env,
            text=True, capture_output=True, timeout=10)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(count.read_text().splitlines(), ["solve", "solve"])
        self.assertEqual(failed_env.read_text(), "")

    def test_buildkit_native_endpoint_mutations_refuse_at_production_admission(self) -> None:
        source = f'''source {shlex.quote(str(HELPER))}
buildkitd={shlex.quote(str(self.root / 'tools' / 'buildkitd'))}
state={shlex.quote(str(self.root / 'state'))}
bk_socket={shlex.quote(str(self.root / 'owned.sock'))}
tools={shlex.quote(str(self.root / 'tools'))}
buildkitd_argv
admit_buildkitd_argv'''
        positive = subprocess.run(["/usr/bin/bash", "-c", source], cwd=ROOT, capture_output=True)
        self.assertEqual(positive.returncode, 0, positive.stderr)
        for mutation in ("unset 'BUILDKITD_ARGV[8]'", "BUILDKITD_ARGV[9]=--oci-worker-snapshotter=auto",
                         "BUILDKITD_ARGV[9]=--oci-worker-snapshotter=overlayfs",
                         "BUILDKITD_ARGV[6]=unix:///host.sock"):
            negative = subprocess.run(["/usr/bin/bash", "-c", source + "\n" + mutation + "\nadmit_buildkitd_argv"], cwd=ROOT, capture_output=True)
            self.assertNotEqual(negative.returncode, 0, mutation)

    def test_solve_recipe_epoch_output_and_endpoint_mutations_refuse(self) -> None:
        docker_output = str(self.root / "image.docker.tar")
        oci_output = str(self.root / "image.oci.tar")
        source = "\n".join((
            "source " + shlex.quote(str(HELPER)),
            "buildctl=" + shlex.quote(str(self.root / "buildctl")),
            "repo=" + shlex.quote(str(ROOT)),
            "evidence=" + shlex.quote(str(self.out)),
            "bk_socket=" + shlex.quote(str(self.root / "owned.sock")),
            "build_solve_argv " + shlex.quote(docker_output) + " " + shlex.quote(oci_output),
            "admit_solve_argv " + shlex.quote(docker_output) + " " + shlex.quote(oci_output),
        ))
        self.assertEqual(subprocess.run(["/usr/bin/bash", "-c", source], cwd=ROOT, capture_output=True).returncode, 0)
        for mutation in ("SOLVE_ARGV[15]=build-arg:SOURCE_DATE_EPOCH=1786060801", "SOLVE_ARGV[2]=unix:///host.sock",
                         "unset 'SOLVE_ARGV[16]'", "SOLVE_ARGV[20]='type=docker,name=other,dest=bad'",
                         "SOLVE_ARGV[22]='type=oci,dest=other,attestation-inline=false'"):
            negative = subprocess.run(["/usr/bin/bash", "-c", source + "\n" + mutation + "\nadmit_solve_argv " +
                shlex.quote(docker_output) + " " + shlex.quote(oci_output)], cwd=ROOT, capture_output=True)
            self.assertNotEqual(negative.returncode, 0, mutation)

    def test_worker_count_snapshotter_platform_version_and_sandbox_refusals(self) -> None:
        worker = {"ID": "worker0", "Labels": {"org.mobyproject.buildkit.worker.snapshotter": "native"},
            "Platforms": [{"OS": "linux", "Architecture": "amd64"}]}
        info = {"buildkitVersion": {"version": "v0.20.2", "revision": "97437fdd7e32f29bb80288d800cd4ffcb34e1c15"}}
        worker_path = self.root / "workers.json"
        info_path = self.root / "info.json"
        def validate(data: object) -> int:
            worker_path.write_text(json.dumps(data))
            return subprocess.run([sys.executable, str(PARSER), "workers", str(worker_path)], cwd=ROOT,
                capture_output=True).returncode
        self.assertEqual(validate([worker]), 0)
        for data in ([], [worker, worker], [{**worker, "Labels": {"org.mobyproject.buildkit.worker.snapshotter": "overlayfs"}}],
                     [{**worker, "Labels": {"org.mobyproject.buildkit.worker.snapshotter": "auto"}}],
                     [{**worker, "Platforms": [{"OS": "linux", "Architecture": "arm64"}]}],
                     [{**worker, "Labels": {"org.mobyproject.buildkit.worker.snapshotter": "native",
                         "org.mobyproject.buildkit.worker.no-process-sandbox": "true"}}]):
            self.assertNotEqual(validate(data), 0)
        info_path.write_text(json.dumps(info))
        self.assertEqual(subprocess.run([sys.executable, str(PARSER), "info", str(info_path)], cwd=ROOT).returncode, 0)
        info["buildkitVersion"]["revision"] = "untrusted"
        info_path.write_text(json.dumps(info))
        self.assertNotEqual(subprocess.run([sys.executable, str(PARSER), "info", str(info_path)], cwd=ROOT).returncode, 0)

    def test_worker_readiness_call_hang_is_bounded_by_production_timeout_path(self) -> None:
        stub = self.root / "hung-buildctl"
        stub.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(30)\n")
        stub.chmod(0o755)
        source = f'''source {shlex.quote(str(HELPER))}
buildctl={shlex.quote(str(stub))}
bk_socket={shlex.quote(str(self.root / 'owned.sock'))}
run_worker_call 0.2 debug workers'''
        start = time.monotonic()
        result = subprocess.run(["/usr/bin/bash", "-c", source], cwd=ROOT, capture_output=True, timeout=4)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - start, 3)

    def test_successful_cleanup_reaps_only_owned_authored_stub_and_preserves_evidence(self) -> None:
        base = ROOT / "build/gcc-toolchain-reproduction"
        base.mkdir(parents=True, exist_ok=True)
        run_id = str(9_100_000_000 + os.getpid() * 10)
        runroot = base / f"{run_id}-1"
        for item in ("tools", "state", "evidence"):
            (runroot / item).mkdir(parents=True, exist_ok=True, mode=0o700)
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        (runroot / "owner.txt").write_text(f"run={run_id}\nattempt=1\nrevision={revision}\n")
        evidence = runroot / "evidence" / "keep.txt"
        evidence.write_text("diagnostic survives successful cleanup\n")
        stub = self.root / "owned-process-stub.py"
        stub.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(30)\n")
        proc = subprocess.Popen([sys.executable, str(stub)], start_new_session=True)
        try:
            stat_fields = Path(f"/proc/{proc.pid}/stat").read_text().split()
            process = {"pid": proc.pid, "startTicks": stat_fields[21], "pgid": os.getpgid(proc.pid), "sid": os.getsid(proc.pid),
                "exe": str(Path(f"/proc/{proc.pid}/exe").resolve()), "root": str(runroot.resolve())}
            self.assertEqual(process["pid"], process["pgid"])
            (runroot / "rootless.process.json").write_text(json.dumps(process))
            env = {**os.environ, "GITHUB_RUN_ID": run_id, "GITHUB_RUN_ATTEMPT": "1", "PRIMARY_STATUS": "success"}
            cleanup = subprocess.Popen(["/usr/bin/bash", str(HELPER), "cleanup"], cwd=ROOT, env=env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while cleanup.poll() is None:
                proc.poll()  # Reap the authored stub promptly so zombie state cannot mask process absence.
                time.sleep(0.05)
            stdout, stderr = cleanup.communicate(timeout=2)
            self.assertEqual(cleanup.returncode, 0, stdout + stderr)
            self.assertIsNotNone(proc.poll())
            self.assertTrue(evidence.is_file())
            self.assertTrue((runroot / "evidence/cleanup.json").is_file())
            self.assertFalse((runroot / "state").exists())
            self.assertFalse((runroot / "tools").exists())
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            if runroot.exists():
                shutil.rmtree(runroot)

    def test_partial_start_with_child_surviving_leader_refuses_cleanup(self) -> None:
        base = ROOT / "build/gcc-toolchain-reproduction"
        base.mkdir(parents=True, exist_ok=True)
        run_id = str(9_200_000_000 + os.getpid() * 10)
        runroot = base / f"{run_id}-1"
        for item in ("tools", "state", "evidence"):
            (runroot / item).mkdir(parents=True, exist_ok=True, mode=0o700)
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        (runroot / "owner.txt").write_text(f"run={run_id}\nattempt=1\nrevision={revision}\n")
        child = self.root / "partial-child.py"
        child.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(30)\n")
        ready = self.root / "partial-child.pid"
        parent = self.root / "partial-parent.py"
        parent.write_text("#!/usr/bin/python3\nimport pathlib,subprocess,sys,time\np=subprocess.Popen([sys.executable,sys.argv[1]])\npathlib.Path(sys.argv[2]).write_text(str(p.pid))\ntime.sleep(.5)\nraise SystemExit(17)\n")
        self.assertEqual(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0), 0)  # Adopt the intentionally orphaned stub for bounded teardown.
        starter = subprocess.Popen([sys.executable, str(parent), str(child), str(ready)], start_new_session=True)
        child_pid = None
        try:
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(ready.is_file())
            parent_fields = Path(f"/proc/{starter.pid}/stat").read_text().split()
            child_pid = int(ready.read_text())
            record = {"pid": starter.pid, "startTicks": parent_fields[21], "pgid": os.getpgid(starter.pid), "sid": os.getsid(starter.pid),
                "exe": str(Path(f"/proc/{starter.pid}/exe").resolve()), "root": str(runroot.resolve())}
            self.assertEqual(record["pgid"], record["pid"])
            (runroot / "rootless.process.json").write_text(json.dumps(record))
            self.assertEqual(starter.wait(timeout=3), 17)
            env = {**os.environ, "GITHUB_RUN_ID": run_id, "GITHUB_RUN_ATTEMPT": "1"}
            cleanup = subprocess.run(["/usr/bin/bash", str(HELPER), "cleanup"], cwd=ROOT, env=env,
                text=True, capture_output=True, timeout=5)
            self.assertNotEqual(cleanup.returncode, 0)
            self.assertTrue((runroot / "rootless.process.json").is_file())
            os.kill(child_pid, 0)
        finally:
            if child_pid is not None:
                try:
                    os.kill(child_pid, 15)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        os.kill(child_pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(.02)
                try:
                    os.waitpid(child_pid, os.WNOHANG)
                except ChildProcessError:
                    pass
                try:
                    os.kill(child_pid, 0)
                    os.kill(child_pid, 9)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child_pid, 0)
                except ChildProcessError:
                    pass
            ctypes.CDLL(None).prctl(36, 0, 0, 0, 0)
            if starter.poll() is None:
                starter.kill()
                starter.wait(timeout=2)
            if runroot.exists():
                shutil.rmtree(runroot)

    def test_rootless_executor_info_requires_owned_socket_overlay_and_classic_store_config(self) -> None:
        job = self.root / "private-run"
        data_root = job / "state/docker-data"
        data_root.mkdir(parents=True)
        endpoint = job / "docker.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(endpoint))
        info_path = self.root / "docker-info.json"
        info = {"Driver": "overlay2", "DockerRootDir": str(data_root), "DriverStatus": [["Backing Filesystem", "extfs"]]}
        info_path.write_text(json.dumps(info))
        command = [sys.executable, str(PARSER), "docker-info", str(info_path), str(data_root), str(endpoint)]
        self.assertEqual(subprocess.run(command, cwd=ROOT, capture_output=True).returncode, 0)
        info["Driver"] = "vfs"
        info_path.write_text(json.dumps(info))
        self.assertNotEqual(subprocess.run(command, cwd=ROOT, capture_output=True).returncode, 0)
        info["Driver"] = "overlay2"
        info["DockerRootDir"] = str(self.root / "wrong-root")
        info_path.write_text(json.dumps(info))
        self.assertNotEqual(subprocess.run(command, cwd=ROOT, capture_output=True).returncode, 0)
        info["DockerRootDir"] = str(data_root)
        info_path.write_text(json.dumps(info))
        listener.close()
        endpoint.unlink()
        endpoint.write_text("not a socket")
        self.assertNotEqual(subprocess.run(command, cwd=ROOT, capture_output=True).returncode, 0)
        self.assertIn('"features":{"containerd-snapshotter":false}', HELPER.read_text())

    def test_cleanup_refuses_stale_pid_and_escaped_owner_without_touching_sentinels(self) -> None:
        base = ROOT / "build/gcc-toolchain-reproduction"
        base.mkdir(parents=True, exist_ok=True)
        run_id = str(9_000_000_000 + os.getpid() * 10 + 1)
        runroot = base / f"{run_id}-1"
        for item in ("tools", "state", "evidence"):
            (runroot / item).mkdir(parents=True, exist_ok=True, mode=0o700)
        (runroot / "owner.txt").write_text(f"run={run_id}\nattempt=1\nrevision={subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()}\n")
        sentinel = runroot / "evidence" / "primary-failure.txt"
        sentinel.write_text("original verifier refusal\n")
        record = {"pid": os.getpid(), "startTicks": "0", "pgid": os.getpgid(os.getpid()), "sid": os.getsid(os.getpid()),
            "exe": str(Path(sys.executable).resolve()), "root": str(runroot.resolve())}
        (runroot / "rootless.process.json").write_text(json.dumps(record))
        env = {**os.environ, "GITHUB_RUN_ID": run_id, "GITHUB_RUN_ATTEMPT": "1", "PRIMARY_STATUS": "failure"}
        result = subprocess.run(["/usr/bin/bash", str(HELPER), "diagnostics"], cwd=ROOT, env=env,
            text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(["/usr/bin/bash", str(HELPER), "cleanup"], cwd=ROOT, env=env,
            text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(sentinel.is_file())
        self.assertEqual(sentinel.read_text(), "original verifier refusal\n")
        self.assertIn("failure", (runroot / "evidence/primary-status.txt").read_text())
        self.assertTrue(Path(f"/proc/{os.getpid()}").exists())
        shutil.rmtree(runroot)

        run_id = str(9_000_000_000 + os.getpid() * 10 + 2)
        runroot = base / f"{run_id}-1"
        for item in ("tools", "state", "evidence"):
            (runroot / item).mkdir(parents=True, exist_ok=True, mode=0o700)
        (runroot / "owner.txt").write_text(f"run={run_id}\nattempt=1\nrevision={subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()}\n")
        sentinel = runroot / "evidence" / "unowned-sentinel.txt"
        sentinel.write_text("leave in place\n")
        record["root"] = str((self.root / "escaped").resolve())
        (runroot / "rootless.process.json").write_text(json.dumps(record))
        env["GITHUB_RUN_ID"] = run_id
        result = subprocess.run(["/usr/bin/bash", str(HELPER), "cleanup"], cwd=ROOT, env=env,
            text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(sentinel.is_file())
        self.assertTrue(Path(f"/proc/{os.getpid()}").exists())
        shutil.rmtree(runroot)

    def test_bounded_diagnostic_overflow_is_labelled_and_fails(self) -> None:
        log = self.root / "bounded.log"
        source = f'''source {shlex.quote(str(HELPER))}
printf '123456789' | bounded_stream {shlex.quote(str(log))} 4'''
        result = subprocess.run(["/usr/bin/bash", "-c", source], cwd=ROOT, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(log.read_bytes(), b"1234")
        self.assertIn("byte budget", log.with_suffix(".log.truncated").read_text())

    def test_archive_layer_digests_provenance_join_and_census_are_retained(self) -> None:
        result = self.run_parser()
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads((self.out / "ordered-layers.json").read_text())
        self.assertEqual(len(inventory), 9)
        self.assertEqual(inventory[-1]["ordinal"], 8)
        self.assertEqual(len(json.loads((self.out / "provenance-joins.json").read_text())), 1)
        census = json.loads((self.out / "final-layer-census.json").read_text())
        self.assertEqual(census[0]["payloadSha256"], hashlib.sha256(b"payload-8").hexdigest())
        self.assertTrue((self.out / "final-layer.tar").is_file())

    def test_duplicate_final_tar_entries_are_preserved_and_header_or_payload_drift_refuses(self) -> None:
        duplicate = tar_bytes([("usr/duplicate", b"first"), ("usr/duplicate", b"second")])
        self.layers[8] = duplicate
        self.config["rootfs"]["diff_ids"][8] = "sha256:" + hashlib.sha256(duplicate).hexdigest()
        self.config_raw = json.dumps(self.config, sort_keys=True, separators=(",", ":")).encode()
        self.make_pair()
        accepted = self.run_parser()
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        census = json.loads((self.out / "final-layer-census.json").read_text())
        duplicate_rows = [row for row in census if row["name"] == "usr/duplicate"]
        self.assertEqual([row["ordinal"] for row in duplicate_rows], [0, 1])
        original = duplicate
        changed = tar_bytes([("usr/duplicate", b"first"), ("usr/duplicate", b"changed")])
        self.layers[8] = changed
        self.make_pair()
        self.assertNotEqual(self.run_parser().returncode, 0)
        self.layers[8] = original
        changed_header = bytearray(original)
        changed_header[100] ^= 1
        self.layers[8] = bytes(changed_header)
        self.make_pair()
        self.assertNotEqual(self.run_parser().returncode, 0)

    def test_unsafe_oversized_truncated_and_unjoined_archives_refuse_without_extraction(self) -> None:
        self.make_pair(unsafe=True)
        result = self.run_parser()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root.parent / "outside").exists())
        self.make_pair()
        self.assertNotEqual(self.run_parser(cap=64).returncode, 0)
        self.make_pair(truncated_layer=True)
        self.assertNotEqual(self.run_parser().returncode, 0)
        self.make_pair(join=False)
        result = self.run_parser()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not join", result.stderr)

    def test_same_config_and_created_with_ninth_diff_id_change_is_still_refused(self) -> None:
        sys.path.insert(0, str(ROOT))
        from oracle.gcc.toolchain_reproduction import verify_toolchain_reproduction
        from oracle.gcc.verify_source_lock import VerificationError
        import copy
        source = ROOT / "oracle/gcc/16.2.0"
        lock = json.loads((source / "toolchain-reproduction.json").read_text())
        work = self.root / "strict"
        work.mkdir()
        for name in ("toolchain-reproduction.json", "build-record.json", "build-toolchain.Dockerfile"):
            (work / name).write_bytes((source / name).read_bytes())
        inspected = {"Id": "sha256:" + "8" * 64, "Created": "2026-08-07T00:00:00Z",
            "Architecture": "amd64", "Os": "linux", "Config": {"Cmd": ["bash"], "Env": ["FIXTURE=1"]},
            "RootFS": {"Layers": ["sha256:" + f"{i + 1:064x}" for i in range(9)]}}
        lock["reproducedImage"] = {"imageDigest": inspected["Id"], "created": inspected["Created"],
            "configSha256": hashlib.sha256(json.dumps(inspected["Config"], ensure_ascii=True,
                separators=(",", ":"), sort_keys=True).encode()).hexdigest(),
            "rootfsDiffIds": list(inspected["RootFS"]["Layers"])}
        (work / "toolchain-reproduction.json").write_text(json.dumps(lock))
        inspected["RootFS"]["Layers"][8] = "sha256:" + "0" * 64
        inspected["RootFS"]["Layers"][8] = "sha256:" + "0" * 64
        # The unchanged verifier rejects the final diff ID even when Config and Created remain locked.
        self.assertEqual(inspected["Created"], lock["reproducedImage"]["created"])
        with self.assertRaises(VerificationError):
            verify_toolchain_reproduction(work / "toolchain-reproduction.json", work / "build-record.json", inspected)


if __name__ == "__main__":
    unittest.main()
