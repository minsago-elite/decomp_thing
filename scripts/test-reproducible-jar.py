#!/usr/bin/env python3
"""Fast controls for the shipped-record path gate; no Gradle or browser substitution."""
import importlib.util
import json
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("reproducible_jar", pathlib.Path(__file__).with_name("check-reproducible-jar.py"))
reproducible_jar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reproducible_jar)


def records(compiler="${BUILD_ROOT}/compiler"):
    document = {
        "compiler": {"path": compiler, "versionCommand": [compiler, "--version"], "version": "cc fixture 1.0"},
        "compilation": {
            "arguments": [compiler, "${BUILD_ROOT}/source.c", "-o", "${BUILD_ROOT}/helper"],
            "workingDirectory": "/",
            "environment": {"HOME": "${BUILD_ROOT}/home", "TMPDIR": "${BUILD_ROOT}/tmp", "PATH": "/usr/bin:/bin"},
        },
    }
    return {name: json.dumps(document).encode() for name in reproducible_jar.BUILD_RECORDS}


class BuildRecordPathsTest(unittest.TestCase):
    def test_logical_locations_and_exact_platform_constants_pass(self):
        self.assertEqual([], reproducible_jar.build_record_path_failures(records()))

    def test_user_local_and_system_compiler_locations_fail_outside_checkout(self):
        for compiler in ("/home/developer/.local/toolchain/cc", "/opt/private/toolchain/cc", "/usr/bin/cc"):
            with self.subTest(compiler=compiler):
                failures = reproducible_jar.build_record_path_failures(records(compiler))
                self.assertEqual(9, len(failures))  # path, versionCommand[0], compile argv[0] in each record

    def test_build_record_executable_alias_is_checked_too(self):
        archive = records()
        name = reproducible_jar.BUILD_RECORDS[1]
        archive[name] = json.dumps({"compiler": {"executable": "/home/developer/toolchain/cc"}}).encode()
        self.assertEqual([f"absolute build-host path in {name}: compiler.executable"],
                         reproducible_jar.build_record_path_failures(archive))

    def test_version_text_and_rewritten_platform_paths_cannot_hide_host_paths(self):
        for path, value in (("version", "cc fixture (/home/developer/private/toolchain)"),
                            ("workingDirectory", "/home/developer"),
                            ("PATH", "/home/developer/bin:/usr/bin:/bin")):
            with self.subTest(path=path):
                archive = records()
                name = reproducible_jar.BUILD_RECORDS[0]
                document = json.loads(archive[name])
                if path == "version":
                    document["compiler"][path] = value
                elif path == "PATH":
                    document["compilation"]["environment"][path] = value
                else:
                    document["compilation"][path] = value
                archive[name] = json.dumps(document).encode()
                self.assertEqual(1, len(reproducible_jar.build_record_path_failures(archive)))

    def test_missing_or_invalid_records_fail_closed(self):
        self.assertEqual(3, len(reproducible_jar.build_record_path_failures({})))
        archive = records()
        archive[reproducible_jar.BUILD_RECORDS[0]] = b"not JSON"
        self.assertEqual(1, len(reproducible_jar.build_record_path_failures(archive)))


if __name__ == "__main__":
    unittest.main()
