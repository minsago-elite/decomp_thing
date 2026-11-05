"""Bounded prepared-input receipts for the test-only installed replay.

No build or native execution. The CLI is called by the immutable Gradle test init
before Sync. Receipts establish consistency, not compiler/toolchain authenticity.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import time
import zipfile
from contextlib import contextmanager

BUILD_CONTROLS = (".github/workflows/ci.yml", "gradlew", "gradlew.bat",
                  "gradle/wrapper/gradle-wrapper.jar", "gradle/wrapper/gradle-wrapper.properties",
                  "gradle/libs.versions.toml", ".node-version", "settings.gradle.kts", "build.gradle.kts")
PRODUCERS = ("buildAnalysisIoHelper", "buildLlvmBehaviorHelper")
EXCLUSIONS = ["-x", ":buildAnalysisIoHelper", "-x", ":buildLlvmBehaviorHelper"]
REFERENCES = {"generateKotlinBootClasspathReference": "kotlin-boot-classpath-reference-v1.json",
              "generateGccBundledGhidraReference": "gcc-bundled-ghidra-reference-v1.json",
              "generateLlvmHostedWorkerClasspathReference": "llvm-behavior-hosted-worker-classpath-reference-v1.json"}
HELPER_OUTPUTS = {
    "buildAnalysisIoHelper": ("analysis", {"decomp-analysis-io-helper", "decomp-analysis-io-helper.sha256",
        "analysis-native-io/source.c", "analysis-native-io/build-policy.txt", "analysis-native-io/build-v1.json",
        "analysis-native-io/decomp-analysis-io-helper-v1.properties"}),
    "buildLlvmBehaviorHelper": ("behavior", {"decomp-llvm-behavior-helper", "decomp-llvm-behavior-helper.sha256",
        "decomp_llvm_behavior_helper.c", "decomp-llvm-behavior-helper-build-v2.json",
        "llvm-behavior-native-helper-deployment-reference-v1.json"}),
}
EMBEDDED_RESOURCES = {"analysis-native-io/" + name for name in
    ("source.c", "build-policy.txt", "build-v1.json", "decomp-analysis-io-helper-v1.properties")} | {
    "oracle/native-helper/" + name for name in ("decomp_llvm_behavior_helper.c", "decomp-llvm-behavior-helper-build-v2.json",
        "llvm-behavior-native-helper-deployment-reference-v1.json")}
MAX_FILE = 512 * 1024**2
MAX_INPUT_BYTES = 8 * 1024**3
MAX_INPUT_ENTRIES = 131072
MAX_JSON = 32 * 1024**2
MAX_PROTECTED_ENTRIES = 4096
MAX_PROTECTED_BYTES = 4 * 1024**3


def require(value, message):
    if not value:
        raise RuntimeError(message)


def safe_path(path, base=None):
    path = pathlib.Path(path)
    require(path.is_absolute() and ".." not in path.parts, "nonabsolute/escaped path")
    if base is not None:
        require(path.is_relative_to(base), "path escaped expected root")
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), f"symlink path: {parent}")
    return path


@contextmanager
def regular(path, limit=MAX_FILE, *, dir_fd=None):
    path = safe_path(path)
    fd = os.open(path if dir_fd is None else path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), f"nonregular file: {path}")
        require(before.st_size <= limit, f"file exceeds bound: {path}")
        yield stream, before
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()) == identity(os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False) if dir_fd is not None else path.lstat()),
                f"file changed during read: {path}")


def file_receipt(path, budget=None, copy_to=None, *, dir_fd=None):
    h = hashlib.sha256()
    with regular(path, dir_fd=dir_fd) as (stream, info):
        require(budget is None or info.st_size <= budget[0], "input byte bound exceeded")
        sink = None
        try:
            if copy_to is not None:
                safe_path(copy_to)
                sink = copy_to.open("xb")
            total = 0
            while block := stream.read(min(1024**2, MAX_FILE - total + 1)):
                total += len(block)
                require(total <= MAX_FILE, "input grew beyond bound")
                h.update(block)
                if sink is not None:
                    sink.write(block)
            require(total == info.st_size, "input size changed")
        finally:
            if sink is not None:
                sink.close()
        if budget is not None:
            budget[0] -= total
    return {"type": "file", "sha256": h.hexdigest(), "bytes": total,
            "mode": stat.S_IMODE(info.st_mode), "key": [info.st_dev, info.st_ino]}


def read_json(path):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    with regular(path, MAX_JSON) as (stream, _):
        data = stream.read(MAX_JSON + 1)
        require(len(data) <= MAX_JSON, "JSON exceeds bound")
        return json.loads(data, object_pairs_hook=pairs)


def write_json(path, value, *, immutable=False):
    safe_path(path)
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    require(len(data) <= MAX_JSON, "JSON exceeds bound")
    temporary = path.with_name(path.name + ".partial")
    with temporary.open("xb") as sink:
        sink.write(data)
    if immutable:
        # link + unlink gives atomic create-without-replacement.
        try:
            os.link(temporary, path)
        finally:
            temporary.unlink()
    else:
        temporary.replace(path)


def inventory(roots, *, max_entries=None, max_bytes=None):
    """Exact directories AND files; exceptions retain bounded partial evidence."""
    entries = {}
    remaining = [MAX_INPUT_BYTES if max_bytes is None else max_bytes]
    cap = MAX_INPUT_ENTRIES if max_entries is None else max_entries
    def visit(path):
        path = safe_path(path)
        name = str(path)
        if name in entries:
            return
        require(len(entries) < cap, "inventory entry bound exceeded")
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            entries[name] = {"type": "directory", "mode": stat.S_IMODE(info.st_mode),
                             "key": [info.st_dev, info.st_ino]}
            # Never materialize an unbounded directory listing, including duplicates.
            with os.scandir(path) as children:
                for child in children:
                    visit(pathlib.Path(child.path))
        else:
            entries[name] = file_receipt(path, remaining)
    try:
        require(len(roots) <= cap, "inventory root bound exceeded")
        for root in roots:
            visit(pathlib.Path(root))
        value = {"status": "passed", "entries": dict(sorted(entries.items()))}
        require(len(json.dumps(value).encode()) <= MAX_JSON, "inventory JSON bound exceeded")
        return value
    except Exception as failure:
        # No partial inventory can be used as a passing comparison.
        return {"status": "failed", "error": repr(failure)[:2048],
                "entries": dict(sorted(entries.items())) if len(json.dumps(entries).encode()) < MAX_JSON - 4096 else {},
                "observedEntries": len(entries)}


def difference(before, after):
    old, new = before.get("entries", {}), after.get("entries", {})
    return {"status": "passed" if before.get("status") == after.get("status") == "passed" else "failed",
            "added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()),
            "changed": {name: {key: {"before": old[name].get(key), "after": new[name].get(key)}
                               for key in old[name].keys() | new[name].keys() if old[name].get(key) != new[name].get(key)}
                        for name in sorted(old.keys() & new.keys()) if old[name] != new[name]}}


EMPTY_DIFF = {"status": "passed", "added": [], "removed": [], "changed": {}}


def protected(root, run):
    try:
        paths = []
        for subdir in ("lib", "bin"):
            directory = safe_path(root / subdir)
            with os.scandir(directory) as items:
                for index, item in enumerate(items):
                    require(index < MAX_PROTECTED_ENTRIES, "protected directory entry bound exceeded")
                    name = item.name
                    require(not (name.startswith(".install-") and name.endswith(".tmp")), "publisher temporary file remains")
                    if (subdir == "lib" and (name.endswith(".jar") or name.endswith("reference-v1.json"))) or (
                            subdir == "bin" and name in ("llm_bin_patch", "llm_bin_patch.bat")):
                        paths.append(str(pathlib.Path(item.path)))
        names = {pathlib.Path(p).name for p in paths}
        require({n for n in names if n.endswith("reference-v1.json")} == set(REFERENCES.values()), "protected reference set differs")
        require({"llm_bin_patch", "llm_bin_patch.bat"} <= names and any(n.endswith(".jar") for n in names), "protected closure incomplete")
        result = inventory(paths, max_entries=MAX_PROTECTED_ENTRIES, max_bytes=MAX_PROTECTED_BYTES)
        result["entries"] = {str(pathlib.Path(p).relative_to(run)): value for p, value in result["entries"].items()}
        return result
    except Exception as failure:
        return {"status": "failed", "error": repr(failure)[:2048], "entries": {}}


def build_controls(repo):
    return {name: file_receipt(repo / name)["sha256"] if os.path.lexists(repo / name) else None for name in BUILD_CONTROLS}


def plan_roots(plan):
    require(set(plan["producers"]) == set(PRODUCERS), "omitted/extra producer")
    roots = set(plan["installInputs"])
    for producer in plan["producers"].values():
        for group in ("inputs", "outputs", "classpath"):
            require(producer[group], f"missing producer {group}")
            roots.update(producer[group])
    roots.update(plan["mappingRoots"].values())
    roots.add(plan["originalJar"])
    return sorted(roots)


def mapping(plan, entries, run):
    required = {"stageKotlinBootRuntime", "startScripts", *REFERENCES}
    require(set(plan["mappingRoots"]) == required, "protected mapping task set differs")
    result = {}
    for task, root in plan["mappingRoots"].items():
        root = pathlib.Path(root)
        for name, receipt in entries.items():
            source = pathlib.Path(name)
            if receipt["type"] != "file" or not (source == root or source.is_relative_to(root)):
                continue
            if task == "stageKotlinBootRuntime":
                require(source.parent == root and source.suffix == ".jar", "staged runtime contains non-JAR/nested input")
                logical = "lib/" + source.name
            elif task == "startScripts":
                require(source.parent == root and source.name in ("llm_bin_patch", "llm_bin_patch.bat"), "unexpected launcher input")
                logical = "bin/" + source.name
            else:
                require(source == root and source.name == REFERENCES[task], "reference output differs")
                logical = "lib/" + source.name
            require(logical not in result, "duplicate protected mapping")
            result[logical] = {"source": name, "destination": str(run / "root-build/install/llm_bin_patch" / logical),
                               "requiredMode": 0o755 if logical == "bin/llm_bin_patch" else 0o644, **receipt}
    require({"bin/llm_bin_patch", "bin/llm_bin_patch.bat", *("lib/" + n for n in REFERENCES.values())} < result.keys(),
            "protected mapping incomplete")
    original = entries[plan["originalJar"]]
    staged = result["lib/" + pathlib.Path(plan["originalJar"]).name]
    require(all(original[k] == staged[k] for k in ("sha256", "bytes")), "original/staged app differs")
    return result


def small_bytes(path, limit=65536):
    with regular(pathlib.Path(path), limit) as (stream, _):
        data = stream.read(limit + 1)
        require(len(data) <= limit, "provenance input exceeds bound")
        return data


def validate_tools(tools, entries, read):
    require(set(tools) == {"java", "javaRelease", "node"}, "build tool set differs")
    for name in ("java", "node"):
        tool = tools[name]
        home = pathlib.Path(tool["home"])
        path = pathlib.Path(tool["path"])
        require(home.is_absolute() and '..' not in home.parts and str(home) == tool["home"] and
                path == home / "bin" / name and entries[str(path)]["type"] == "file" and
                entries[str(path)]["mode"] & 0o111, "build tool executable/home differs")
    release = tools["javaRelease"]["path"]
    require(release == str(pathlib.Path(tools["java"]["home"]) / "release"), "Java release/home differs")
    versions = re.findall(r'^JAVA_VERSION="([^"\n]+)"$', read(release).decode(), re.MULTILINE)
    require(len(versions) == 1 and re.fullmatch(r'21(?:[.+\-][^\s"]+)?', versions[0]),
            "retained JDK release is not qualified Java 21")


def validate_provenance(plan, entries, prov, read):
    """Validate actual producer schemas/tuples using original or retained bytes.

    The receipts bind compilation inputs and outputs consistently. They do not
    authenticate the compiler's implicit toolchain or historical execution.
    """
    repo = pathlib.Path(plan["repoRoot"])
    run = pathlib.Path(plan["runRoot"])
    def record(path):
        # Use the same duplicate-key rejection as retained JSON reads.
        def pairs(items):
            value = {}
            for k, v in items:
                require(k not in value, "duplicate provenance key")
                value[k] = v
            return value
        return json.loads(read(str(path)), object_pairs_hook=pairs)
    def tuple_for(path):
        item = entries[str(path)]
        require(item["type"] == "file", "provenance tuple is not a file")
        return {"fileName": path.name, "bytes": item["bytes"], "sha256": item["sha256"]}
    def successful(result, analysis):
        require(set(result) == ({"exitCode", "signal", "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256"}
                               if analysis else {"exitCode", "stdout", "stderr"}), "compiler result schema differs")
        require(type(result["exitCode"]) is int and result["exitCode"] == 0, "compiler command failed")
        if analysis:
            require(result["signal"] is None, "compiler command signaled")
        for channel in ("stdout", "stderr"):
            value = {"bytes": result[channel + "Bytes"], "sha256": result[channel + "Sha256"]} if analysis else result[channel]
            require(set(value) == ({"bytes", "sha256"} if analysis else {"fileName", "bytes", "sha256"}),
                    "compiler output schema differs")
            require(type(value["bytes"]) is int and 0 <= value["bytes"] <= 65536 and
                    re.fullmatch('[0-9a-f]{64}', value["sha256"]), "compiler output receipt differs")
            require(value["bytes"] != 0 or value["sha256"] == hashlib.sha256(b"").hexdigest(),
                    "empty compiler output has a foreign hash")
            if not analysis:
                require(value["fileName"] == channel, "compiler output name differs")
    expected_resources = {}
    for producer, (directory, _) in HELPER_OUTPUTS.items():
        analysis = directory == "analysis"
        root = run / "root-build/native" / directory
        binary = "decomp-analysis-io-helper" if analysis else "decomp-llvm-behavior-helper"
        source_name = "decomp_analysis_io_helper.c" if analysis else "decomp_llvm_behavior_helper.c"
        source = repo / "src/main/c" / source_name
        copied = root / ("analysis-native-io/source.c" if analysis else source_name)
        helper = root / binary
        checksum = root / (binary + ".sha256")
        build = root / ("analysis-native-io/build-v1.json" if analysis else "decomp-llvm-behavior-helper-build-v2.json")
        reference = build if analysis else root / "llvm-behavior-native-helper-deployment-reference-v1.json"
        require(any(source == pathlib.Path(p) or source.is_relative_to(p) for p in plan["producers"][producer]["inputs"]),
                "helper source is not a declared producer input")
        require(all(entries[str(source)][k] == entries[str(copied)][k] for k in ("sha256", "bytes")),
                "helper source copy differs from compilation input")
        require(entries[str(helper)]["mode"] == 0o755 and
                read(str(checksum)) == (entries[str(helper)]["sha256"] + "  " + binary + "\n").encode(),
                "helper output/checksum differs")
        item = prov["producers"][producer]
        data = record(reference)
        require(item["path"] == str(reference) and item["record"] == data, "producer provenance path/record differs")
        common = {"schemaVersion", "compiler", "compilation"}
        expected_keys = common | ({"kind", "binaryName", "architecture", "sourceSha256", "buildPolicySha256", "helperSha256", "helperBytes"}
            if analysis else {"provider", "protocol", "provenanceScope", "compilerToolchainClosureAuthenticated",
                              "source", "helper", "checksum", "buildRecord", "claims", "closureSha256"})
        require(set(data) == expected_keys and type(data["schemaVersion"]) is int, "producer provenance schema fields differ")
        compiler = data["compiler"]
        require(set(compiler) == {"path", "bytes", "sha256", "version", "versionCommand", "result"}, "compiler schema differs")
        require(compiler["versionCommand"] == [compiler["path"], "--version"] and
                isinstance(compiler["version"], str) and 0 < len(compiler["version"].encode()) <= 4096 and
                all(ord(c) >= 32 and ord(c) != 127 for c in compiler["version"]), "compiler identity differs")
        successful(compiler["result"], analysis)
        version_stdout_bytes = (compiler["result"]["stdoutBytes"] if analysis else
                                compiler["result"]["stdout"]["bytes"])
        require(version_stdout_bytes >= len(compiler["version"].encode()),
                "compiler version exceeds observed stdout bytes")
        compilation = data["compilation"]
        require(set(compilation) == {"arguments", "environment", "workingDirectory", "result"} |
                ({"timeoutMillis", "maximumStdoutBytes", "maximumStderrBytes"} if analysis else set()),
                "compilation schema differs")
        successful(compilation["result"], analysis)
        flags = ["-std=c11", "-O2", "-static"] + (["-no-pie"] if analysis else []) + [
            "-Wall", "-Wextra", "-Werror", "-Wformat=2", "-Wl,--build-id=none"]
        args = compilation["arguments"]
        require(len(args) == len(flags) + 4 and args[:len(flags)+1] == [compiler["path"], *flags] and args[-2] == "-o",
                "fixed compilation arguments differ")
        staged_source, staged_output = pathlib.Path(args[-3]), pathlib.Path(args[-1])
        scratch = staged_source.parent
        require(staged_source.name == source_name and staged_output == scratch / binary and
                scratch.parent == root and scratch.name.startswith(".analysis-io-build-" if analysis else ".native-helper-build-"),
                "compilation source/output relationship differs")
        require(compilation["workingDirectory"] == "/" and compilation["environment"] == {
            "HOME": str(scratch / "home"), "TMPDIR": str(scratch / "tmp"), "LANG": "C", "LC_ALL": "C",
            "PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1779182222", "TZ": "UTC"}, "compilation environment differs")
        if analysis:
            policy = root / "analysis-native-io/build-policy.txt"
            require(data["schemaVersion"] == 1 and data["kind"] == "analysis-native-io-helper-build-v1" and
                    data["binaryName"] == binary and data["architecture"] == "linux-x86-64" and
                    data["sourceSha256"] == entries[str(source)]["sha256"] and
                    data["buildPolicySha256"] == entries[str(policy)]["sha256"] and
                    data["helperSha256"] == entries[str(helper)]["sha256"] and data["helperBytes"] == entries[str(helper)]["bytes"],
                    "analysis source/policy/helper tuple differs")
            require([compilation[k] for k in ("timeoutMillis", "maximumStdoutBytes", "maximumStderrBytes")] ==
                    [30000, 65536, 65536], "analysis compilation bounds differ")
            props = {}
            for line in read(str(root / "analysis-native-io/decomp-analysis-io-helper-v1.properties")).decode().splitlines():
                key, value = line.split('=', 1)
                require(key not in props, "duplicate analysis property")
                props[key] = value
            expected = {k: str(data[k]) for k in ("schemaVersion", "sourceSha256", "buildPolicySha256", "helperSha256",
                        "helperBytes", "architecture", "binaryName")}
            expected.update(sourcePath="analysis-native-io/source.c", buildRecordPath="analysis-native-io/build-v1.json",
                            buildRecordBytes=str(entries[str(build)]["bytes"]), buildRecordSha256=entries[str(build)]["sha256"])
            require(props == expected, "analysis properties/build-record tuple differs")
            for name in ("source.c", "build-policy.txt", "build-v1.json", "decomp-analysis-io-helper-v1.properties"):
                expected_resources["analysis-native-io/" + name] = str(root / "analysis-native-io" / name)
        else:
            require(data["schemaVersion"] == 1 and data["provider"] == "llvm-behavior-native-helper-deployment-reference-v1" and
                    data["protocol"] == "decomp-llvm-behavior-helper-v2" and
                    data["provenanceScope"] == "reviewed-source-compiler-executable-and-fixed-compilation" and
                    data["compilerToolchainClosureAuthenticated"] is False, "LLVM provenance schema differs")
            for field, path in (("source", copied), ("helper", helper), ("checksum", checksum), ("buildRecord", build)):
                require(data[field] == tuple_for(path), "LLVM " + field + " tuple differs")
            build_data = record(build)
            require(build_data == {"schemaVersion": 2, "kind": "llvm-behavior-native-helper-build-record",
                    "compiler": {"executable": compiler["path"], "version": compiler["version"]},
                    "argumentTemplate": [*flags, "${SOURCE}", "-o", "${OUTPUT}"],
                    "source": tuple_for(copied), "output": tuple_for(helper)}, "LLVM build-record schema/tuple differs")
            require(data["claims"] == dict.fromkeys(("runtimeProfilePinned", "referencePinned", "startAuthorized",
                    "containmentAuthority", "scoringAuthority", "releaseEligible"), False), "LLVM unsupported authority claim")
            unsigned = {k: v for k, v in data.items() if k != "closureSha256"}
            require(data["closureSha256"] == hashlib.sha256((json.dumps(unsigned, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()).hexdigest(), "LLVM closure checksum differs")
            for path in (copied, build, reference):
                expected_resources["oracle/native-helper/" + path.name] = str(path)
    require(prov["embeddedResources"] == expected_resources, "embedded resource source paths differ")


def provenance(plan, entries):
    """Retain original compiler/version receipts and embedded resource binding."""
    validate_output_sets(plan, entries)
    provenance_paths = {}
    resources = {}
    for name in entries:
        path = pathlib.Path(name)
        if "/native/analysis/analysis-native-io/" in name and entries[name]["type"] == "file":
            resources["analysis-native-io/" + path.name] = name
            if path.name == "build-v1.json":
                provenance_paths[PRODUCERS[0]] = name
        elif "/native/behavior/" in name and path.name in (
                "decomp_llvm_behavior_helper.c", "decomp-llvm-behavior-helper-build-v2.json",
                "llvm-behavior-native-helper-deployment-reference-v1.json"):
            resources["oracle/native-helper/" + path.name] = name
            if path.name == "llvm-behavior-native-helper-deployment-reference-v1.json":
                provenance_paths[PRODUCERS[1]] = name
    require(set(provenance_paths) == set(PRODUCERS) and set(resources) == EMBEDDED_RESOURCES, "helper provenance/resource set incomplete")
    receipts = {}
    for producer, path in provenance_paths.items():
        data = read_json(pathlib.Path(path))
        compiler = data["compiler"]
        actual = file_receipt(pathlib.Path(compiler["path"]))
        require(all(actual[k] == compiler[k] for k in ("bytes", "sha256")) and actual["mode"] & 0o111,
                "compiler differs from original producer receipt")
        require(compiler["version"] and compiler["versionCommand"] == [compiler["path"], "--version"] and
                compiler["result"]["exitCode"] == 0 and data["compilation"]["result"]["exitCode"] == 0,
                "compiler/version/compilation receipt incomplete")
        receipts[producer] = {"path": path, "record": data, "compilerFile": actual}
    with regular(pathlib.Path(plan["originalJar"])) as (stream, _):
        with zipfile.ZipFile(stream) as archive:
            require(len(archive.infolist()) <= MAX_INPUT_ENTRIES, "app archive entry bound exceeded")
            for resource, path in resources.items():
                matches = [item for item in archive.infolist() if item.filename == resource]
                require(len(matches) == 1 and matches[0].file_size <= 65536, "embedded helper resource missing/duplicate/oversize")
                with archive.open(matches[0]) as member:
                    data = member.read(65537)
                require(len(data) <= 65536 and hashlib.sha256(data).hexdigest() == entries[path]["sha256"], "embedded helper differs")
    result = {"producers": receipts, "embeddedResources": resources}
    validate_provenance(plan, entries, result, small_bytes)
    return result


def validate_output_sets(plan, entries):
    for producer, (directory, expected) in HELPER_OUTPUTS.items():
        root = pathlib.Path(plan["runRoot"]) / "root-build/native" / directory
        outputs = plan["producers"][producer]["outputs"]
        require(outputs and all(pathlib.Path(p) == root or pathlib.Path(p).is_relative_to(root) for p in outputs),
                "producer output escaped fresh root")
        actual = {str(pathlib.Path(p).relative_to(root)) for p, value in entries.items()
                  if value["type"] == "file" and pathlib.Path(p).is_relative_to(root)}
        require(actual == expected, "producer output set missing/extra member")
        require(all(any(pathlib.Path(root / name) == pathlib.Path(p) or pathlib.Path(root / name).is_relative_to(p)
                        for p in outputs) for name in actual), "producer output is undeclared")


ACP_SCOPE = 'cooperative-build-producer-v1'
ACP_BINDING = 'stable-namespace-path-observations-v1'
ACP_FLAGS = ['-std=c11', '-O2', '-static', '-Wall', '-Wextra', '-Werror', '-Wl,--build-id=none']
ACP_SOURCE = 'src/main/c/decomp_acp_gate_helper.c'
ACP_PUBLICATION = 'scripts/atomic-install-acp-publication.groovy'


def validate_acp(event, plan, entries, command=None):
    """Fresh compiler execution is mandatory, independent of claimed retain outcome."""
    config = plan['acp']
    repo, run = pathlib.Path(plan['repoRoot']), pathlib.Path(plan['runRoot'])
    require(set(config) == {'compiler', 'source', 'recipe', 'publication', 'output', 'publicationScope', 'bindingEvidence'}, 'ACP plan schema differs')
    require(config['publicationScope'] == ACP_SCOPE and config['bindingEvidence'] == ACP_BINDING, 'ACP plan scope/binding differs')
    for key, relative in (('source', ACP_SOURCE), ('recipe', 'build.gradle.kts'), ('publication', ACP_PUBLICATION)):
        require(config[key] == str(repo / relative), 'ACP source/recipe path differs')
    require(config['output'] == str(run / 'root-build/native/acp/decomp-acp-gate-helper'), 'ACP final path differs')
    tasks = [t for t in event['tasks'] if t['path'] == ':buildAcpGateHelper']
    require(len(tasks) == 1 and tasks[0]['enabled'] is True and tasks[0]['executed'] is True and
            all(tasks[0][k] is False for k in ('skipped', 'upToDate', 'noSource', 'failure')), 'ACP fresh task missing/skipped')
    value = event['acp']
    require(set(value) == {'schemaVersion', 'publicationScope', 'bindingEvidence', 'commandId', 'runRoot', 'initSha256', 'startedAtUnixNs',
        'compileStartedAtUnixNs', 'compileFinishedAtUnixNs', 'finishedAtUnixNs', 'cleanupFinishedAtUnixNs',
        'compiler', 'source', 'recipe', 'publication', 'output', 'flags', 'arguments', 'exitCode', 'cleanup',
        'candidatePath', 'candidate', 'previous', 'final', 'outcome', 'candidateValidationExitCode', 'finalValidationExitCode'}, 'ACP receipt fields differ')
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 2 and type(value['commandId']) is int and value['commandId'] == event['commandId'] in (1, 2) and
            value['runRoot'] == event['runRoot'] == str(run), 'ACP receipt command role differs')
    require(value['publicationScope'] == ACP_SCOPE and value['bindingEvidence'] == ACP_BINDING, 'ACP receipt scope/binding differs')
    require(type(value['exitCode']) is int and value['exitCode'] == 0 and value['cleanup'] is True,
            'ACP fresh compiler/cleanup failed')
    require(value['candidateValidationExitCode'] == value['finalValidationExitCode'] == 120, 'ACP static/protocol validation differs')
    require(value['flags'] == ACP_FLAGS and value['output'] == config['output'], 'ACP recipe differs')
    for name in ('compiler', 'source', 'recipe', 'publication'):
        require(value[name] == {'path': config[name], 'file': entries[config[name]]}, 'ACP compiler/source/recipe inventory differs')
    require(entries[config['compiler']]['mode'] & 0o111, 'ACP compiler not executable')
    candidate = pathlib.Path(value['candidatePath'])
    require(str(candidate) == value['candidatePath'] and '..' not in candidate.parts and
            candidate.parent.parent == run / 'root-build/acp-publication-private' and
            candidate.parent.name.startswith('invocation-') and len(candidate.parent.name) <= 128 and
            candidate.name == pathlib.Path(config['output']).name, 'ACP private candidate path differs')
    require(not any(candidate.is_relative_to(pathlib.Path(root)) for root in plan_roots(plan)),
            'ACP candidate overlaps sealed input roots')
    require(value['arguments'] == [config['compiler'], *ACP_FLAGS, config['source'], '-o', str(candidate)], 'ACP compilation arguments differ')
    require(value['final'] == entries[config['output']], 'ACP final differs from independent inventory')
    for item in (value['candidate'], value['final']):
        require(set(item) == {'type', 'bytes', 'sha256', 'mode', 'key'} and item['type'] == 'file' and
                type(item['bytes']) is int and 64 <= item['bytes'] <= 4 * 1024**2 and item['mode'] == 0o755 and
                re.fullmatch('[0-9a-f]{64}', item['sha256']) and isinstance(item['key'], list) and len(item['key']) == 2 and
                all(type(i) is int and i >= 0 for i in item['key']), 'ACP bounded output receipt differs')
    require(all(value['candidate'][k] == value['final'][k] for k in ('type', 'bytes', 'sha256', 'mode')),
            'ACP candidate/final content differs')
    require(value['candidate']['key'][0] == value['final']['key'][0], 'ACP candidate crosses filesystem')
    if value['outcome'] == 'retained':
        require(value['previous'] == value['final'] and value['candidate']['key'] != value['final']['key'],
                'ACP retained identity claim differs')
    else:
        require(value['outcome'] == 'replaced' and value['candidate'] == value['final'], 'ACP replacement identity differs')
    if value['commandId'] == 2:
        require(value['outcome'] == 'retained', 'ACP strict replay did not retain prepared final')
    times = [value[k] for k in ('startedAtUnixNs', 'compileStartedAtUnixNs', 'compileFinishedAtUnixNs',
                               'finishedAtUnixNs', 'cleanupFinishedAtUnixNs')] + [tasks[0]['atUnixNs']]
    require(all(type(t) is int and t > 0 for t in times) and times == sorted(times), 'ACP execution ordering differs')
    require(tasks[0]['atUnixNs'] <= event['actionsStartedAtUnixNs'], 'ACP execution did not precede Sync guard')
    if command is not None:
        require(command['commandId'] == value['commandId'] and command['initSha256'] == value['initSha256'] and
                command['startedAtUnixNs'] <= times[0] <= times[-1] <= command['finishedAtUnixNs'], 'ACP command/init binding differs')
    else:
        require(value['initSha256'] == file_receipt(run / f"command-{value['commandId']:02d}.init.gradle")['sha256'],
                'ACP immutable init differs')
    return value


def capture(plan, repo, source_hashes, tools):
    roots = plan_roots(plan)
    for path in roots:
        safe_path(path, repo)
    roots += [str(repo / p) for p in source_hashes]
    roots += [entry["path"] for entry in tools.values()]
    roots += [plan["acp"]["compiler"]]
    # Compiler paths come from actual retained original provenance, never an override.
    initial = inventory(sorted(set(roots)))
    if initial["status"] != "passed":
        write_json(pathlib.Path(plan["runRoot"]) / "prepared-seal-failure.json", initial, immutable=True)
    require(initial["status"] == "passed", "prepared inventory failed: " + initial.get("error", ""))
    prov = provenance(plan, initial["entries"])
    roots += [p["record"]["compiler"]["path"] for p in prov["producers"].values()]
    current = inventory(sorted(set(roots)))
    if current["status"] != "passed":
        write_json(pathlib.Path(plan["runRoot"]) / "prepared-seal-failure.json", current, immutable=True)
    require(current["status"] == "passed", "prepared compiler inventory failed")
    validate_acp(read_json(pathlib.Path(plan["runRoot"]) / "command-01-events.json"), plan, current["entries"])
    validate_tools(tools, current["entries"], small_bytes)
    require(plan["frontendNodeHome"] in ("PATH", tools["node"]["home"]), "frontend Node home differs")
    return {"roots": sorted(set(roots)), "inventory": current, "provenance": prov,
            "mapping": mapping(plan, current["entries"], pathlib.Path(plan["runRoot"]))}


def check_prepared(manifest, plan):
    require(plan == manifest["plan"], "prepared task configuration/input set changed")
    check_sources(manifest)
    current = inventory(manifest["roots"])
    diff = difference(manifest["inventory"], current)
    require(diff == EMPTY_DIFF, "prepared input changed: " + json.dumps(diff)[:4096])
    return current


def check_sources(manifest):
    repo = pathlib.Path(manifest["plan"]["repoRoot"])
    names = set(subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                                       cwd=repo, timeout=30).decode().split("\0")) | set(BUILD_CONTROLS)
    current = {name for name in names if name and (name in BUILD_CONTROLS or
               name.startswith(("src/", "scripts/", "frontend/", "ghidra-bridge/", "contracts/", "oracle/")) or
               name.endswith((".gradle.kts", ".properties"))) and (repo / name).is_file() and not (repo / name).is_symlink()}
    require(current == set(manifest["sourceHashes"]), "source input set changed")
    require(build_controls(repo) == manifest["buildControls"], "build-control inputs changed")


def validate_publisher(receipt, manifest):
    require(receipt.get("commandId") == 2 and receipt.get("runRoot") == manifest["runRoot"], "publisher command role differs")
    require(receipt.get("actionsStarted") is True and receipt.get("publisherCompleted") is True and
            receipt.get("stalePruneCandidates") == [], "publisher skipped/incomplete or prune candidates remain")
    tasks = [t for t in receipt["tasks"] if t["path"] == ":installDist"]
    require(len(tasks) == 1 and tasks[0]["executed"] is True and tasks[0]["enabled"] is True and
            all(tasks[0][k] is False for k in ("skipped", "upToDate", "noSource", "failure")), "installDist actions did not execute")
    require(not any(t["path"] in {":" + p for p in PRODUCERS} for t in receipt["tasks"]), "excluded helper ran in replay")
    expected = manifest["mapping"]
    events = receipt["events"]
    require(len(events) == 4 * len(expected) + 1, "publisher event count differs (rename or missing publication)")
    require(all(event["phase"] in {"source-before-copy", "source-after-copy", "staged", "published", "lib-validated"}
                for event in events), "unexpected publisher mutation/event")
    for item in expected.values():
        for phase in ("source-before-copy", "source-after-copy", "staged", "published"):
            path = item["source"] if phase.startswith("source-") else item["destination"]
            require(sum(e["phase"] == phase and e["path"] == path for e in events) == 1, "publisher source/destination event missing/duplicate")
    lib_events = [i for i, e in enumerate(events) if e["phase"] == "lib-validated"]
    require(len(lib_events) == 1 and events[lib_events[0]]["path"] == str(pathlib.Path(manifest["runRoot"]) / "root-build/install/llm_bin_patch/lib"), "lib validation event differs")
    require(max(i for i, e in enumerate(events) if e["phase"] == "staged") <
            min(i for i, e in enumerate(events) if e["phase"] == "published"), "publication preceded staging")
    require(all(i > lib_events[0] for i, e in enumerate(events) if e["phase"] == "published" and "/bin/" in e["path"]), "launcher preceded lib validation")
    times = [receipt["actionsStartedAtUnixNs"], receipt["guardPassedAtUnixNs"],
             *[e["atUnixNs"] for e in events], receipt["publisherCompletedAtUnixNs"], tasks[0]["atUnixNs"]]
    require(all(type(t) is int and t > 0 for t in times) and times == sorted(times), "publisher event ordering differs")


def retain_inputs(manifest, run):
    """Independent byte copies survive subsequent normal installs; never restore them."""
    # Enumerate the original roots independently, before later builds overwrite them.
    # This is historical completeness consistency, not authentication of receipts.
    closure = inventory(manifest["roots"])
    require(closure["status"] == "passed" and closure == manifest["inventory"],
            "original recursive closure differs before retention")
    folder = run / "prepared-products"
    folder.mkdir()
    budget = [MAX_INPUT_BYTES]
    retained = {}
    for index, (name, claimed) in enumerate(closure["entries"].items()):
        if claimed["type"] != "file":
            continue
        target = folder / f"{index:06d}"
        actual = file_receipt(pathlib.Path(name), budget, target)
        require(actual == claimed, "prepared source changed during retention")
        target.chmod(claimed["mode"])
        retained[name] = {"path": str(target.relative_to(run)), **file_receipt(target)}
    require(inventory(manifest["roots"]) == closure, "original recursive closure changed during retention")
    write_json(run / "prepared-closure.json", {"schemaVersion": 1, "roots": manifest["roots"],
               "inventory": closure, "copies": retained}, immutable=True)
    return retained


def frontend_compare(produced, consumed):
    # Vite still runs fresh. Only avoid rewriting identical bridge inputs on replay.
    def content(root):
        snap = inventory([str(root / n) for n in ("dist", "bundle-report.json", "bundle-composition.json")])
        require(snap["status"] == "passed", "frontend inventory failed")
        return {str(pathlib.Path(p).relative_to(root)): {k: v for k, v in r.items() if k != "key"}
                for p, r in snap["entries"].items()}
    require(content(produced) == content(consumed), "fresh frontend changed prepared inputs")


def main():
    if sys.argv[1] == "frontend":
        frontend_compare(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
        return
    require(sys.argv[1] == "guard", "unknown prepared operation")
    run = safe_path(pathlib.Path(sys.argv[2]))
    manifest = read_json(run / "prepared-A.json")
    plan = read_json(run / "command-02-plan.json")
    current = inventory(manifest["roots"])
    diff = difference(manifest["inventory"], current)
    source_error = None
    try:
        check_sources(manifest)
    except Exception as failure:
        source_error = repr(failure)
    acp = None
    acp_error = None
    try:
        acp = validate_acp(read_json(run / "command-02-events.json"), plan, current['entries'])
    except Exception as failure:
        acp_error = repr(failure)[:2048]
    write_json(run / "prepared-guard.json", {"commandId": 2, "runRoot": str(run), "atUnixNs": time.time_ns(),
               "manifestSha256": file_receipt(run / "prepared-A.json")["sha256"],
               "acp": acp, "acpError": acp_error, "inventory": current, "diff": diff, "planEqual": plan == manifest["plan"], "sourceError": source_error}, immutable=True)
    require(plan == manifest["plan"] and diff == EMPTY_DIFF and source_error is None and acp_error is None, "pre-Sync sealed-input guard failed")


if __name__ == "__main__":
    main()
