#!/usr/bin/env python3
"""Rebuild the application JAR from an unchanged tree and require byte-identical output.

The web server's applicationBuildId is the SHA-256 of this JAR, so a release checksum is only
reproducible from source when two Gradle invocations produce the same bytes (#1789). The second
invocation reruns the generated-resource producers (the native helpers are never up to date),
resource processing and the JAR task itself. Every entry is also scanned for the repository's
absolute path and for the producers' private build-directory names.
"""

import argparse
import hashlib
import pathlib
import shutil
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOST_MARKERS = (".analysis-io-build-", ".native-helper-build-")


def application_jar() -> pathlib.Path:
    jars = sorted((ROOT / "build/libs").glob("llm-bin-patch-*.jar"))
    if len(jars) != 1:
        sys.exit(f"expected exactly one application JAR in build/libs, found {[jar.name for jar in jars]}")
    return jars[0]


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def gradle(arguments: list[str], tasks: list[str]) -> None:
    subprocess.run([str(ROOT / "gradlew"), "--no-daemon", *arguments, *tasks], cwd=ROOT, check=True)


def entries(path: pathlib.Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {info.filename: archive.read(info) for info in archive.infolist()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gradle-arg", action="append", default=[], help="extra Gradle argument, e.g. --offline")
    options = parser.parse_args()

    gradle(options.gradle_arg, ["jar"])
    jar = application_jar()
    evidence = ROOT / "build/reproducible-jar"
    shutil.rmtree(evidence, ignore_errors=True)
    evidence.mkdir(parents=True)
    first = evidence / "first.jar"
    shutil.copyfile(jar, first)

    gradle(options.gradle_arg, ["processResources", "--rerun", "jar", "--rerun"])
    second = application_jar()
    first_sha, second_sha = sha256(first), sha256(second)
    print(f"first  {first_sha}  {jar.name}")
    print(f"second {second_sha}  {second.name}")

    failures = []
    if first_sha != second_sha:
        before, after = entries(first), entries(second)
        changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
        failures.append("application JAR differs between invocations; changed entries: " +
                        (", ".join(changed) if changed else "(metadata only: timestamps or order)"))
    root = str(ROOT).encode()
    # Producer classes legitimately hold the temporary-directory prefixes as string constants.
    leaking = sorted(name for name, data in entries(second).items() if root in data or (
        not name.endswith(".class") and any(marker.encode() in data for marker in HOST_MARKERS)))
    if leaking:
        failures.append("application JAR embeds build-host paths in: " + ", ".join(leaking))
    for failure in failures:
        print(failure, file=sys.stderr)
    if not failures:
        print("application JAR is byte-identical across Gradle invocations and carries no build-tree paths")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
