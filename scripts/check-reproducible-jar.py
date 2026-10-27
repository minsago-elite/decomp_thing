#!/usr/bin/env python3
"""Rebuild the application JAR from an unchanged tree and require byte-identical output.

The web server's applicationBuildId is the SHA-256 of this JAR, so a release checksum is only
reproducible from source when two Gradle invocations produce the same bytes (#1789). The second
invocation reruns the generated-resource producers (the native helpers are never up to date),
resource processing and the JAR task itself. Every entry is also scanned for the repository's
absolute path and for the producers' private build-directory names. Shipped helper JSON records
are additionally checked for absolute paths outside the fixed platform recipe constants, including
compiler locations outside the checkout (for example a user-local toolchain).
"""

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOST_MARKERS = (".analysis-io-build-", ".native-helper-build-")
BUILD_RECORDS = (
    "analysis-native-io/build-v1.json",
    "oracle/native-helper/decomp-llvm-behavior-helper-build-v2.json",
    "oracle/native-helper/llvm-behavior-native-helper-deployment-reference-v1.json",
)
PLATFORM_PATHS = {
    ("compilation", "workingDirectory"): "/",
    ("compilation", "environment", "PATH"): "/usr/bin:/bin",
}
ABSOLUTE_PATH = re.compile(r"(?:^|[\s=(])/(?!/)\S*")


def build_record_path_failures(archive: dict[str, bytes]) -> list[str]:
    failures = []

    def visit(value, path: tuple[str, ...]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, (*path, key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, (*path, str(index)))
        elif isinstance(value, str) and ABSOLUTE_PATH.search(value):
            if PLATFORM_PATHS.get(path) != value:
                failures.append("absolute build-host path in " + name + ": " + ".".join(path))

    for name in BUILD_RECORDS:
        if name not in archive:
            failures.append("missing shipped build record: " + name)
            continue
        try:
            visit(json.loads(archive[name]), ())
        except (ValueError, UnicodeError) as error:
            failures.append(f"invalid shipped build record {name}: {type(error).__name__}")
    return failures


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
    shipped = entries(second)
    failures.extend(build_record_path_failures(shipped))
    leaking = sorted(name for name, data in shipped.items() if root in data or (
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
