#!/usr/bin/env python3
"""Rebuild and byte-compare the pinned historical repair graph fixtures."""

from __future__ import annotations

import hashlib
import io
import json
import os
import argparse
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "src/test/resources/repair"
PRODUCERS = {
    1: "d58e62203c2e992183a730875c4bca9eb90b5130",
    2: "5a608003f176b6ff59769d6d1e413164230467f0",
    3: "c19636157b1cc3081b6df3dd8417a4e53fc729aa",
    4: "2b1121999c806d5b3f89d3723fca8a39879c49b1",
}


def capture_method(schema: int) -> str:
    setup = []
    if schema == 3:
        setup = [
            "            graph.enableRunContract()",
            "            graph.beginRun(2, 60_000)",
            "            val corpus = graph.retainedRegressionCorpus()",
            '            val metadata = RevisionRepairMetadata(1, "compile", "historical pending", null,',
            "                corpus.inputs.map { it.id }, null, corpus.sha256,",
            "                publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)",
            "            val attempt = graph.beginAttempt(listOf(relative), metadata)",
        ]
    elif schema == 4:
        setup = [
            "            graph.enableRunContract()",
            "            check(graph.snapshot.schemaVersion == 4)",
            "            val attempt = graph.beginAttempt(listOf(relative))",
        ]
    else:
        setup = ["            val attempt = graph.beginAttempt(listOf(relative))"]
    lines = [
        "",
        "    @Test",
        f"    fun `capture historical schema {schema} pending writer fixture`() {{",
        "        val project = generatedProject()",
        '        val relative = "src/modules/alpha.c"',
        "        val source = project.resolve(relative)",
        "        val before = source.readBytes()",
        "        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->",
        *setup,
        f'            graph.installCandidate(attempt, mapOf(relative to before + "\\n/* historical schema {schema} writer */\\n".toByteArray()))',
        "        }",
        '        val destination = Path.of(requireNotNull(System.getenv("LEGACY_CAPTURE_OUTPUT")))',
        "        destination.toFile().deleteRecursively()",
        "        project.toFile().copyRecursively(destination.toFile(), overwrite = true)",
        "    }",
    ]
    return "\n".join(lines) + "\n"


def extract_revision(revision: str, destination: Path) -> None:
    resolved = subprocess.run(
        ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    if resolved != revision:
        raise RuntimeError(f"producer SHA resolved unexpectedly: {revision} -> {resolved}")
    archive = subprocess.run(["git", "archive", revision], cwd=ROOT, check=True, stdout=subprocess.PIPE).stdout
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        members = bundle.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError(f"unsafe producer archive entry: {member.name}")
        bundle.extractall(destination, members=members)


def install_capture_method(producer: Path, schema: int) -> str:
    test_file = producer / "src/test/kotlin/decompengine/repair/ModuleRevisionGraphTest.kt"
    source = test_file.read_text(encoding="utf-8")
    marker = f"capture historical schema {schema} pending writer fixture"
    if marker in source or not source.endswith("}\n"):
        raise RuntimeError(f"unexpected historical graph test source: {test_file}")
    test_file.write_text(source[:-2] + capture_method(schema) + "}\n", encoding="utf-8")
    return marker


def hashes(root: Path, *, fixture: bool = False) -> dict[str, str]:
    result = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if fixture and relative in {"PROVENANCE.md", "SHA256SUMS"}:
            continue
        result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def verify_fixture_manifest(fixture: Path, expected: dict[str, str]) -> None:
    manifest = fixture / "SHA256SUMS"
    recorded = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        path = PurePosixPath(relative)
        if len(digest) != 64 or path.is_absolute() or ".." in path.parts:
            raise RuntimeError(f"invalid fixture checksum entry: {line}")
        recorded[relative] = digest
    if recorded != expected:
        raise RuntimeError(f"schema fixture checksum manifest does not match checked-in files: {manifest}")


def compare(schema: int, capture: Path) -> None:
    fixture = FIXTURES / f"legacy-schema{schema}-writer-pending"
    graph_path = capture / "reports/repair-revisions/graph.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    if graph.get("schemaVersion") != schema or not isinstance(graph.get("pending"), dict):
        raise RuntimeError(f"schema {schema} writer did not emit the expected pending graph")
    expected = hashes(fixture, fixture=True)
    verify_fixture_manifest(fixture, expected)
    actual = hashes(capture)
    if schema == 3 and expected.get("reports/repair-revisions/graph.json") != actual.get("reports/repair-revisions/graph.json"):
        fixture_graph = json.loads((fixture / "reports/repair-revisions/graph.json").read_text(encoding="utf-8"))
        captured_graph = json.loads(graph_path.read_text(encoding="utf-8"))
        for run in fixture_graph.get("runs", []) + captured_graph.get("runs", []):
            run.pop("startedEpochMillis", None)
            run.pop("deadlineEpochMillis", None)
        if fixture_graph == captured_graph:
            expected["reports/repair-revisions/graph.json"] = actual["reports/repair-revisions/graph.json"]
    if expected != actual:
        missing = sorted(expected.keys() - actual.keys())
        extra = sorted(actual.keys() - expected.keys())
        changed = sorted(key for key in expected.keys() & actual.keys() if expected[key] != actual[key])
        raise RuntimeError(f"schema {schema} bytes differ: missing={missing[:8]} extra={extra[:8]} changed={changed[:8]}")
    clock_note = " (run start/deadline values normalized)" if schema == 3 else ""
    print(f"schema {schema}: {len(actual)} fixture files match writer {PRODUCERS[schema]}{clock_note}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=int, choices=PRODUCERS, action="append",
                        help="verify only this schema; repeat to select multiple")
    args = parser.parse_args()
    selected = args.schema or list(PRODUCERS)
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    frontend_exclusions = [
        "-x", "verifyFrontendToolchain", "-x", "frontendInstall", "-x", "frontendBuild",
        "-x", "generateFrontendAssetManifest", "-x", "verifyFrontendAssets", "-x", "stageFrontend",
    ]
    with tempfile.TemporaryDirectory(prefix="legacy-repair-fixtures-", dir=build) as temporary:
        temp_root = Path(temporary)
        for schema in selected:
            revision = PRODUCERS[schema]
            producer = temp_root / f"schema{schema}-producer"
            capture = temp_root / f"schema{schema}-capture"
            extract_revision(revision, producer)
            marker = install_capture_method(producer, schema)
            environment = os.environ.copy()
            environment["LEGACY_CAPTURE_OUTPUT"] = str(capture)
            exclusions = frontend_exclusions if schema >= 3 else []
            command = [
                str(producer / "gradlew"), "-p", str(producer), "test",
                "--tests", f"decompengine.repair.ModuleRevisionGraphTest.{marker}",
                "--no-daemon", "--max-workers=1", *exclusions,
                "-Pkotlin.daemon.jvmargs=-Xmx4g", "-Dorg.gradle.jvmargs=-Xmx4g",
            ]
            subprocess.run(command, cwd=ROOT, env=environment, check=True)
            compare(schema, capture)


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        print(f"historical repair fixture verification failed: {failure}", file=sys.stderr)
        raise
