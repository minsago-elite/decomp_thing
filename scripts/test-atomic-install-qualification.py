#!/usr/bin/env python3
"""Pure-Python controls for the installed qualification record selector."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
import zipfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTROL_TMP = ROOT / "build/orchestration/atomic-install-prepared-replay-remediation/tmp"
if "ATOMIC_CONTROL_EVIDENCE_ROOT" in os.environ:
    CONTROL_TMP = pathlib.Path(os.environ["ATOMIC_CONTROL_EVIDENCE_ROOT"]).resolve(strict=True)
    if not CONTROL_TMP.is_relative_to(ROOT): raise RuntimeError('control evidence must stay inside repository')
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


SEMANTIC_FIXTURE = {'args': ['list', []],
 'compiler': ['string', '/usr/bin/cc'],
 'debug': ['boolean', False],
 'debugOptions': ['implementation',
                  'org.gradle.process.internal.DefaultJavaDebugOptions_Decorated',
                  {'baseClass': 'org.gradle.process.internal.DefaultJavaDebugOptions',
                   'classSha256': 'ae5c4a7daf98189ae2e133838bc2c5b906b7ec45601410a38a5c7c4235c22d2b',
                   'jarPath': '/home/june/.gradle/wrapper/dists/gradle-9.6.1-bin/4ticwg1pgcbps2hj28r8so764/gradle-9.6.1/lib/gradle-process-services-9.6.1.jar',
                   'jarSha256': 'b7c04a9f1dacdd9230dbf58177d8195a3e9d61ed5b59d0c8eb64fb3aa0db226d'},
                  {'enabled': ['boolean', False],
                   'host': ['null'],
                   'port': ['integer', 'java.lang.Integer', '5005'],
                   'server': ['boolean', True],
                   'suspend': ['boolean', True]}],
 'debugOptions.enabled': ['boolean', False],
 'debugOptions.host': ['null'],
 'debugOptions.port': ['integer', 'java.lang.Integer', '5005'],
 'debugOptions.server': ['boolean', True],
 'debugOptions.suspend': ['boolean', True],
 'defaultCharacterEncoding': ['string', 'UTF-8'],
 'enableAssertions': ['boolean', False],
 'ignoreExitValue': ['boolean', False],
 'javaLauncher': ['implementation',
                  'org.gradle.jvm.toolchain.internal.DefaultToolchainJavaLauncher',
                  {'baseClass': 'org.gradle.jvm.toolchain.internal.DefaultToolchainJavaLauncher',
                   'classSha256': '7673c65551445a806c89e2ac6dac36b337a684ff89865c3e8ec830819f5baf7b',
                   'jarPath': '/home/june/.gradle/wrapper/dists/gradle-9.6.1-bin/4ticwg1pgcbps2hj28r8so764/gradle-9.6.1/lib/plugins/gradle-toolchains-jvm-9.6.1.jar',
                   'jarSha256': '255cb2dabf5b6df503aff83ac88baefa0e0680cab056f550eb545f93f5e79605'},
                  {'executablePath': '/opt/openjdk-bin-21.0.12.1_p1/bin/java',
                   'executableRealPath': '/opt/openjdk-bin-21.0.12.1_p1/bin/java',
                   'metadata': {'currentJvm': ['boolean', True],
                                'fallback': ['boolean', False],
                                'installationPath': '/opt/openjdk-bin-21.0.12.1_p1',
                                'installationRealPath': '/opt/openjdk-bin-21.0.12.1_p1',
                                'javaRuntimeVersion': ['string', '21.0.12.1+1-LTS'],
                                'jvmVersion': ['string', '21.0.12.1+1-LTS'],
                                'languageVersion': ['java-language', 21],
                                'vendor': ['string', 'Eclipse Temurin']}}],
 'javaLauncher.metadata': ['implementation',
                           'org.gradle.jvm.toolchain.internal.JavaToolchain',
                           {'baseClass': 'org.gradle.jvm.toolchain.internal.JavaToolchain',
                            'classSha256': 'f76c8a9033b64d172c89461bf6baeb791e87d17672a7b1b61ba0ff9ec70ffc39',
                            'jarPath': '/home/june/.gradle/wrapper/dists/gradle-9.6.1-bin/4ticwg1pgcbps2hj28r8so764/gradle-9.6.1/lib/gradle-toolchains-jvm-shared-9.6.1.jar',
                            'jarSha256': '1a94c0a887759e4de0439b6733603660a923821eec8aa5b9d824dc74588771fd'},
                           {'currentJvm': ['boolean', True],
                            'fallback': ['boolean', False],
                            'installationPath': '/opt/openjdk-bin-21.0.12.1_p1',
                            'installationRealPath': '/opt/openjdk-bin-21.0.12.1_p1',
                            'javaRuntimeVersion': ['string', '21.0.12.1+1-LTS'],
                            'jvmVersion': ['string', '21.0.12.1+1-LTS'],
                            'languageVersion': ['java-language', 21],
                            'vendor': ['string', 'Eclipse Temurin']}],
 'javaLauncher.metadata.languageVersion': ['java-language', 21],
 'javaLauncher.metadata.taskInputs': ['implementation',
                                      'org.gradle.jvm.toolchain.internal.JavaToolchainInput',
                                      {'baseClass': 'org.gradle.jvm.toolchain.internal.JavaToolchainInput',
                                       'classSha256': '890498733ffc37e9f7b0c7da59c80da0f900ab4affa1432af3b032fc11cb4049',
                                       'jarPath': '/home/june/.gradle/wrapper/dists/gradle-9.6.1-bin/4ticwg1pgcbps2hj28r8so764/gradle-9.6.1/lib/gradle-toolchains-jvm-shared-9.6.1.jar',
                                       'jarSha256': '1a94c0a887759e4de0439b6733603660a923821eec8aa5b9d824dc74588771fd'},
                                      {'implementation': ['string', 'vendor-specific'],
                                       'languageVersion': ['java-language', 21],
                                       'vendor': ['string', 'any vendor']}],
 'javaLauncher.metadata.taskInputs.implementation': ['string', 'vendor-specific'],
 'javaLauncher.metadata.taskInputs.languageVersion': ['java-language', 21],
 'javaLauncher.metadata.taskInputs.vendor': ['string', 'any vendor'],
 'jvmArgs': ['list', []],
 'mainClass': ['string', 'inert.Main'],
 'mainModule': ['null'],
 'maxHeapSize': ['null'],
 'minHeapSize': ['null'],
 'modularity': ['implementation',
                'org.gradle.internal.jvm.DefaultModularitySpec_Decorated',
                {'baseClass': 'org.gradle.internal.jvm.DefaultModularitySpec',
                 'classSha256': 'baad8b87d5baa266d400abb67d52a10ab1c4afe8f9ef1eb721e9538128756348',
                 'jarPath': '/home/june/.gradle/wrapper/dists/gradle-9.6.1-bin/4ticwg1pgcbps2hj28r8so764/gradle-9.6.1/lib/gradle-process-services-9.6.1.jar',
                 'jarSha256': 'b7c04a9f1dacdd9230dbf58177d8195a3e9d61ed5b59d0c8eb64fb3aa0db226d'},
                {'inferModulePath': ['boolean', True]}],
 'modularity.inferModulePath': ['boolean', True],
 'systemProperties': ['map', []]}

def add_semantic_fixture(plan, tools):
    prep = driver.prepared
    home = tools['java']['home']; gradle_root = str(pathlib.Path(plan['repoRoot']) / 'fixture-gradle')
    plan['declaredInputsFormat'] = 'declared-inputs-v1'
    plan['jdkBinding'] = prep.jdk_binding(pathlib.Path(home))
    plan['gradleBinding'] = {'root':gradle_root, 'version':prep.GRADLE_VERSION, 'commit':prep.GRADLE_COMMIT,
        'distributionSha256':prep.GRADLE_ZIP_SHA256, 'buildReceiptSha256':'f1ced844391f571370fe8d1606f665a6cd568b9a6e5793f954aabab7173f299a',
        'entries':{name:{'type':'file','sha256':digest,'bytes':1,'mode':0o644,'key':[1,index+1]}
                   for index,(name,digest) in enumerate(prep.GRADLE_JARS.items())}}
    for name,producer in plan['producers'].items():
        props=copy.deepcopy(SEMANTIC_FIXTURE)
        props['compiler']=['string',plan['acp']['compiler']]
        props['hostArchitecture']=['string','amd64']
        props['mainClass']=['string',producer['mainClass']]
        for key in prep.DECLARED_REGISTRY:
            pin=prep.DECLARED_CLASSES[prep.DECLARED_REGISTRY[key]]
            props[key][2]['jarPath']=gradle_root+'/'+pin['jar']
        for metadata in (props['javaLauncher'][3]['metadata'],props['javaLauncher.metadata'][3]):
            metadata['installationPath']=home;metadata['installationRealPath']=home
        props['javaLauncher'][3]['executablePath']=tools['java']['path']
        props['javaLauncher'][3]['executableRealPath']=tools['java']['path']
        producer['properties']=props;producer['orderedClasspath']=list(producer['classpath'])

def prepared_fixture(repo, run, record, output_fault=None):
    """Real bounded inventories/copies of inert fixture bytes; no build execution."""
    prep = driver.prepared
    def put(name, data=b"fixture"):
        path = run / "root-build" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path
    compiler = put("tools/compiler", b"inert compiler"); compiler.chmod(0o755)
    cc = prep.file_receipt(compiler)
    compiler_record = {"path": str(compiler), "bytes": cc["bytes"], "sha256": cc["sha256"],
                       "version": "inert cc 1", "versionCommand": [str(compiler), "--version"], "result": {"exitCode": 0}}
    resources = {}
    def encoded(value):
        return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()
    def tuple_for(path):
        return {"fileName": path.name, "bytes": path.stat().st_size, "sha256": sha(path)}
    empty = hashlib.sha256(b'').hexdigest()
    for directory, binary, source_name in (("analysis", "decomp-analysis-io-helper", "decomp_analysis_io_helper.c"),
                                           ("behavior", "decomp-llvm-behavior-helper", "decomp_llvm_behavior_helper.c")):
        analysis = directory == "analysis"
        root = run / "root-build/native" / directory
        source = repo / "src/main/c" / source_name
        helper = put(f"native/{directory}/{binary}"); helper.chmod(0o755)
        checksum = put(f"native/{directory}/{binary}.sha256", (sha(helper) + "  " + binary + "\n").encode())
        copied = put(f"native/{directory}/" + ("analysis-native-io/source.c" if analysis else source_name), source.read_bytes())
        result = {"exitCode": 0, "signal": None, "stdoutBytes": 0, "stdoutSha256": empty, "stderrBytes": 0, "stderrSha256": empty} if analysis else {
            "exitCode": 0, **{name: {"fileName": name, "bytes": 0, "sha256": empty} for name in ("stdout", "stderr")}}
        cc_result = copy.deepcopy(result)
        version_bytes = (compiler_record["version"] + "\n").encode()
        if analysis:
            cc_result.update(stdoutBytes=len(version_bytes), stdoutSha256=hashlib.sha256(version_bytes).hexdigest())
        else:
            cc_result["stdout"].update(bytes=len(version_bytes), sha256=hashlib.sha256(version_bytes).hexdigest())
        if output_fault is not None and output_fault[0] == directory:
            _, fault = output_fault
            if fault == "version-empty":
                if analysis: cc_result.update(stdoutBytes=0, stdoutSha256=empty)
                else: cc_result["stdout"].update(bytes=0, sha256=empty)
            elif fault == "extra": result["stdout"]["unexpected"] = "not in the producer schema"
            elif fault == "stdout-hash":
                if analysis: result["stdoutSha256"] = "1" * 64
                else: result["stdout"]["sha256"] = "1" * 64
            elif fault == "stderr-hash":
                if analysis: result["stderrSha256"] = "1" * 64
                else: result["stderr"]["sha256"] = "1" * 64
        cc_record = {**compiler_record, "result": cc_result}
        scratch = root / (".analysis-io-build-fixture" if analysis else ".native-helper-build-fixture")
        flags = ["-std=c11", "-O2", "-static"] + (["-no-pie"] if analysis else []) + ["-Wall", "-Wextra", "-Werror", "-Wformat=2", "-Wl,--build-id=none"]
        compilation = {"arguments": [str(compiler), *flags, str(scratch / source_name), "-o", str(scratch / binary)],
            "environment": {"HOME": str(scratch / "home"), "TMPDIR": str(scratch / "tmp"), "LANG": "C", "LC_ALL": "C",
                            "PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1779182222", "TZ": "UTC"}, "workingDirectory": "/", "result": result}
        if analysis:
            policy = put("native/analysis/analysis-native-io/build-policy.txt", b'inert fixed policy')
            compilation.update(timeoutMillis=30000, maximumStdoutBytes=65536, maximumStderrBytes=65536)
            data = {"schemaVersion": 1, "kind": "analysis-native-io-helper-build-v1", "binaryName": binary,
                "architecture": "linux-x86-64", "sourceSha256": sha(source), "buildPolicySha256": sha(policy),
                "helperSha256": sha(helper), "helperBytes": helper.stat().st_size, "compiler": cc_record, "compilation": compilation}
            build = put("native/analysis/analysis-native-io/build-v1.json", encoded(data))
            props = {k: str(data[k]) for k in ("schemaVersion", "sourceSha256", "buildPolicySha256", "helperSha256", "helperBytes", "architecture", "binaryName")}
            props.update(sourcePath="analysis-native-io/source.c", buildRecordPath="analysis-native-io/build-v1.json",
                         buildRecordBytes=str(build.stat().st_size), buildRecordSha256=sha(build))
            properties = put("native/analysis/analysis-native-io/decomp-analysis-io-helper-v1.properties",
                             ''.join(k + '=' + v + '\n' for k, v in props.items()).encode())
            for path in (copied, policy, build, properties): resources["analysis-native-io/" + path.name] = path.read_bytes()
        else:
            data = {"schemaVersion": 2, "kind": "llvm-behavior-native-helper-build-record",
                "compiler": {"executable": str(compiler), "version": cc_record["version"]},
                "argumentTemplate": [*flags, "${SOURCE}", "-o", "${OUTPUT}"], "source": tuple_for(copied), "output": tuple_for(helper)}
            build = put("native/behavior/decomp-llvm-behavior-helper-build-v2.json", encoded(data))
            data = {"schemaVersion": 1, "provider": "llvm-behavior-native-helper-deployment-reference-v1",
                "protocol": "decomp-llvm-behavior-helper-v2", "provenanceScope": "reviewed-source-compiler-executable-and-fixed-compilation",
                "compilerToolchainClosureAuthenticated": False, "source": tuple_for(copied), "helper": tuple_for(helper),
                "checksum": tuple_for(checksum), "buildRecord": tuple_for(build), "compiler": cc_record, "compilation": compilation,
                "claims": dict.fromkeys(("runtimeProfilePinned", "referencePinned", "startAuthorized", "containmentAuthority", "scoringAuthority", "releaseEligible"), False)}
            data["closureSha256"] = hashlib.sha256(encoded(data)).hexdigest()
            reference = put("native/behavior/llvm-behavior-native-helper-deployment-reference-v1.json", encoded(data))
            for path in (copied, build, reference): resources["oracle/native-helper/" + path.name] = path.read_bytes()
    original = put("libs/llm_bin_patch.jar")
    with zipfile.ZipFile(original, "w") as archive:
        for name, value in resources.items(): archive.writestr(name, value)
    stage = put("oracle/gcc/kotlin-boot-runtime/llm_bin_patch.jar", original.read_bytes())
    installed = run / "root-build/install/llm_bin_patch/lib/llm_bin_patch.jar"
    installed.write_bytes(original.read_bytes())
    mapping_roots = {"stageKotlinBootRuntime": str(stage.parent)}
    for task, name in prep.REFERENCES.items():
        source = put("generated/" + name, (installed.parent / name).read_bytes())
        mapping_roots[task] = str(source)
    for name in ("llm_bin_patch", "llm_bin_patch.bat"):
        source = put("scripts/" + name, (installed.parent.parent / "bin" / name).read_bytes())
        source.chmod(0o755 if name == "llm_bin_patch" else 0o644)
    mapping_roots["startScripts"] = str(source.parent)
    bootstrap = put("bootstrap/classes/producer.class")
    plan = {"runRoot": str(run), "repoRoot": str(repo), "originalJar": str(original), "mappingRoots": mapping_roots,
            "frontendNodeHome": "PATH", "installInputs": sorted([*mapping_roots.values(), str(run / "root-build/native")]), "producers": {}}
    for name, directory in zip(prep.PRODUCERS, ("analysis", "behavior")):
        plan["producers"][name] = {"inputs": [str(repo / "src/main/c" / ("decomp_analysis_io_helper.c" if directory == "analysis" else "decomp_llvm_behavior_helper.c"))], "outputs": [str(run / "root-build/native" / directory)],
                                   "classpath": [str(bootstrap.parent)], "mainClass": name, "properties": {"compiler": str(compiler)}}
    acp_helper = put('native/acp/decomp-acp-gate-helper', b'inert ACP fixture ' * 8); acp_helper.chmod(0o755)
    put('native/acp/decomp-acp-gate-helper.sha256', (sha(acp_helper) + '  decomp-acp-gate-helper\n').encode())
    plan['acp'] = {'publicationScope': 'cooperative-build-producer-v1', 'bindingEvidence': 'stable-namespace-path-observations-v1', 'compiler': str(compiler), 'source': str(repo / prep.ACP_SOURCE),
        'recipe': str(repo / 'build.gradle.kts'), 'publication': str(repo / prep.ACP_PUBLICATION), 'output': str(acp_helper)}
    def acp_event(index, events):
        pin = prep.file_receipt(acp_helper)
        candidate = {**pin, 'key': [pin['key'][0], pin['key'][1] + 1]} if index == 2 else dict(pin)
        base = index * 100
        events['tasks'].append({'path': ':buildAcpGateHelper', 'enabled': True, 'executed': True,
            'skipped': False, 'upToDate': False, 'noSource': False, 'failure': False, 'atUnixNs': base + 8})
        events['actionsStartedAtUnixNs'] = base + 10
        candidate_path = str(run / 'root-build/acp-publication-private' / f'invocation-fixture-{index}' / acp_helper.name)
        events['acp'] = {'schemaVersion': 2, 'publicationScope': 'cooperative-build-producer-v1', 'bindingEvidence': 'stable-namespace-path-observations-v1', 'commandId': index, 'runRoot': str(run),
            'candidateValidationExitCode': 120, 'finalValidationExitCode': 120,
            'initSha256': record['commands'][index]['initSha256'], 'flags': prep.ACP_FLAGS, 'exitCode': 0, 'cleanup': True,
            'startedAtUnixNs': base + 2, 'compileStartedAtUnixNs': base + 3, 'compileFinishedAtUnixNs': base + 4,
            'finishedAtUnixNs': base + 5, 'cleanupFinishedAtUnixNs': base + 6,
            'output': str(acp_helper), 'candidatePath': candidate_path, 'candidate': candidate, 'final': pin,
            'previous': pin if index == 2 else None, 'outcome': 'retained' if index == 2 else 'replaced',
            'arguments': [str(compiler), *prep.ACP_FLAGS, plan['acp']['source'], '-o', candidate_path],
            **{name: {'path': plan['acp'][name], 'file': prep.file_receipt(pathlib.Path(plan['acp'][name]))}
               for name in ('compiler', 'source', 'recipe', 'publication')}}
    java = put("tools/jdk/bin/java", b"inert java"); java.chmod(0o755)
    release = put("tools/jdk/release", b'JAVA_VERSION="21.0.1"\n')
    node = put("tools/node/bin/node", b"inert node"); node.chmod(0o755)
    tools = {"java": {"path": str(java), "home": str(java.parent.parent)},
             "javaRelease": {"path": str(release)}, "node": {"path": str(node), "home": str(node.parent.parent)}}
    add_semantic_fixture(plan, tools)
    for index in (1, 2): write_json(run / f"command-{index:02d}-plan.json", plan)
    events = json.loads((run / "command-01-events.json").read_text())
    for name in prep.PRODUCERS:
        events["tasks"].insert(0, {**events["tasks"][0], "path": ":" + name})
    acp_event(1, events)
    write_json(run / "command-01-events.json", events)
    record["commands"][1]["taskReceiptSha256"] = sha(run / "command-01-events.json")
    manifest = {"schemaVersion": 1, "runRoot": str(run), "preparationCommandId": 1, "preparationCommand": dict(record["commands"][1]),
                "plan": plan, "sourceHashes": record["sourceHashes"], "buildControls": prep.build_controls(repo),
                "tools": tools, "nodeVersion": (repo / ".node-version").read_text().strip(), "sealedAtUnixNs": 195}
    manifest.update(prep.capture(plan, repo, record["sourceHashes"], tools))
    write_json(run / "prepared-A.json", manifest)
    snap = prep.protected(installed.parent.parent, run)
    for prefix, value in (("protected", snap), ("prepared-input", manifest["inventory"])):
        for suffix in ("-before", "-after"): write_json(run / (prefix + suffix + ".json"), value)
        write_json(run / (prefix + "-diff.json"), prep.EMPTY_DIFF)
    write_json(run / "prepared-retained.json", prep.retain_inputs(manifest, run))
    write_json(run / "prepared-guard.json", {"commandId": 2, "runRoot": str(run), "atUnixNs": 215,
               "manifestSha256": sha(run / "prepared-A.json"), "planEqual": True, "sourceError": None,
               "inventory": manifest["inventory"], "diff": prep.EMPTY_DIFF})
    events = json.loads((run / "command-02-events.json").read_text())
    acp_event(2, events)
    events.update(actionsStarted=True, publisherCompleted=True, stalePruneCandidates=[], actionsStartedAtUnixNs=210,
                  guardPassedAtUnixNs=220, publisherCompletedAtUnixNs=270)
    for item in manifest["mapping"].values():
        for phase in ("source-before-copy", "source-after-copy", "staged"):
            events["events"].append({"phase": phase, "path": item["source"] if phase.startswith("source-") else item["destination"], "atUnixNs": 230})
    for key, item in manifest["mapping"].items():
        if key.startswith("lib/"):
            events["events"].append({"phase": "published", "path": item["destination"], "atUnixNs": 240})
    events["events"].append({"phase": "lib-validated", "path": str(installed.parent), "atUnixNs": 250})
    for key, item in manifest["mapping"].items():
        if key.startswith("bin/"):
            events["events"].append({"phase": "published", "path": item["destination"], "atUnixNs": 260})
    write_json(run / "command-02-events.json", events)
    guard = json.loads((run / 'prepared-guard.json').read_text()); guard['acp'] = events['acp']; guard['acpError'] = None
    write_json(run / 'prepared-guard.json', guard)
    record["commands"][2]["taskReceiptSha256"] = sha(run / "command-02-events.json")
    probe = record["probes"][0]
    probe.update(role="prepared-no-update", preparationCommandId=1, replayCommandId=2,
                 preparedManifestSha256=sha(run / "prepared-A.json"), readyAtUnixNs=198, releasedAtUnixNs=295)
    probe["ready"]["descriptorDigest"] = sha(original)
    probe["loaded"].update(descriptorDigest=sha(original), installedPathDigestAfterRelease=sha(original))
    for name, value in (("READY", probe["ready"]), ("READY.loaded", probe["loaded"])):
        write_json(pathlib.Path(probe["root"]) / name, value)
    record["noUpdate"].update(preparationCommandId=1, replayCommandId=2, probeIndex=0,
                evidenceHashes={name: sha(run / name) for name in ("prepared-A.json", "prepared-retained.json", "prepared-closure.json", "prepared-guard.json",
                    *[p + s + ".json" for p in ("protected", "prepared-input") for s in ("-before", "-after", "-diff")])})
    record["finalProtectedFiles"] = snap["entries"]


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
    for name in sorted({*verifier.OWNED, *driver.prepared.BUILD_CONTROLS, "src/main/c/fixture.c", driver.prepared.ACP_SOURCE, driver.prepared.ACP_PUBLICATION, "src/main/c/decomp_analysis_io_helper.c", "src/main/c/decomp_llvm_behavior_helper.c", "frontend/fixture.ts", "contracts/web/v1/contract.schema.json", "oracle/kotlin-schema-inventory-v1.json", "oracle/review.schema.json", "oracle/llvm/22.1.6/native-runtime-measurement-v2.Dockerfile"}):
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture source " + name + "\n", encoding="utf-8")
        sources[name] = sha(path)
    retained = run_dir / "owned-sources/atomic_install_child.py"
    retained.parent.mkdir()
    retained.write_bytes((repo / "scripts/atomic_install_child.py").read_bytes())
    owned = {name: sources[name] for name in verifier.OWNED}
    agent = repo / "build/atomic-install/atomic-install-probe-agent.jar"
    agent.parent.mkdir(parents=True)
    agent.write_bytes(b"synthetic inert agent receipt; never executed")
    # Fake only git's listing and HEAD, never validation, file receipts, or filters.
    # Include deleted tracked names and newly created untracked fixture sources.
    verifier.git_source_names = lambda current: set(sources) | {
        str(p.relative_to(current)) for top in ("src", "scripts", "frontend", "ghidra-bridge", "contracts", "oracle")
        for p in (current / top).rglob("*")}

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
                           "-Dorg.gradle.java.installations.paths=" + str(run_dir / "root-build/tools/jdk")]
        with mock.patch.object(driver, "WORK", run_dir), mock.patch.object(driver, "ROOT", repo):
            init = driver.write_init([None, "A", "A", "B", "A", "B", "B", "A", "A", "B", "A", "B", "B"][index],
                                     index == 3, replay=index == 2, command_id=index)
        command_args[7:7] = ["-I", str(init)]
        if index == 2: command_args.extend(driver.prepared.EXCLUSIONS)
        log = run_dir / ["agent-build.log", "install-A-1.log", "install-A-2.log", "install-B-3.log",
                         "install-A-4.log", "install-B-5.log", "install-B-6.log", "install-A-7.log",
                         "install-A-8.log", "gcc-held-install.log", "install-A-10.log", "llvm-held-install.log",
                         "distribution-contracts.log"][index]
        log.write_text("atomic-probe injected before first rename\ncompleted renames=0\n" if index == 3 else "BUILD SUCCESSFUL\n")
        status = "failed" if index == 3 else "passed"
        events = run_dir / f"command-{index:02d}-events.json"
        task = {"path": ":atomicInstallProbeAgentJar" if index == 0 else ":installDist", "enabled": True,
                "executed": True, "skipped": False, "noSource": False, "upToDate": False, "failure": index == 3,
                "atUnixNs": index * 100 + 80}
        write_json(events, {"commandId": index, "runRoot": str(run_dir), "tasks": [task], "events": []})
        commands.append({"args": command_args, "phase": PHASES[index], "status": status,
                         "commandId": index, "init": str(init), "initSha256": sha(init),
                         "initConfig": json.loads(init.with_suffix(".json").read_text()),
                         "taskReceipt": str(events), "taskReceiptSha256": sha(events),
                         "startedAtUnixNs": index * 100 + 1, "finishedAtUnixNs": index * 100 + 90,
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
    prepared_fixture(repo, run_dir, record)
    write_json(run_dir / "qualification.json", record)
    write_json(evidence / "latest-installed-run.json", {"record": str(run_dir / "qualification.json")})

    controls_dir = evidence / "driver-controls-current"
    controls_dir.mkdir()
    expected_controls = ["ACP-actual-publication-engine-inert-adversarial-controls", "distinct-buildDir-production-service-contention/release/task-failure/process-cancel/reacquire",
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

    def test_retained_child_helper_relation_beyond_resealed_membership(self):
        spec = importlib.util.spec_from_file_location('child_artifact_controls', ROOT / 'scripts/atomic_install_artifacts.py')
        artifacts = importlib.util.module_from_spec(spec); spec.loader.exec_module(artifacts)
        for mutation in ('positive', 'absent', 'tampered', 'swapped'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
                repo, run = fixture(pathlib.Path(temp))
                helper = run / 'owned-sources/atomic_install_child.py'
                if mutation == 'absent': helper.unlink()
                elif mutation == 'tampered': helper.write_bytes(b'wrong helper bytes')
                elif mutation == 'swapped': helper.write_bytes((repo / 'scripts/test-atomic-install.py').read_bytes())
                # Reseal the actual selected bytes, including malicious omission.
                with mock.patch.object(artifacts, 'rules', return_value=artifacts.rules(ROOT)):
                    sealed = artifacts.seal(repo)
                members = json.loads((repo / 'build' / artifacts.MANIFEST).read_text())['members']
                member = str(helper.relative_to(repo / 'build'))
                self.assertEqual(member in members, mutation != 'absent')
                archive = repo / 'selected.zip'
                with zipfile.ZipFile(archive, 'w') as output:
                    for name in [*members, artifacts.MANIFEST]:
                        output.write(repo / 'build' / name, name)
                self.assertEqual(artifacts.verify(archive, sealed['sha256'])['status'], 'passed')
                if mutation == 'positive':
                    self.assertEqual(verifier.select_and_verify(repo, '0123456789abcdef')['status'], 'passed')
                else:
                    with self.assertRaises(verifier.QualificationError):
                        verifier.select_and_verify(repo, '0123456789abcdef')

    def test_fully_resealed_compiler_output_contradictions(self):
        original_fixture = prepared_fixture
        faults = [(directory, fault) for directory in ("analysis", "behavior")
                  for fault in ("version-empty", "stdout-hash", "stderr-hash")]
        faults.append(("behavior", "extra"))
        for fault in faults:
            with self.subTest(fault=fault):
                def changed(repo, run, record):
                    return original_fixture(repo, run, record, output_fault=fault)
                # Producer itself must refuse. Then bypass only that validator
                # to construct fully sealed adversarial bytes for the consumer.
                with mock.patch.dict(globals(), prepared_fixture=changed):
                    with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
                        with self.assertRaisesRegex(RuntimeError, "compiler.*(output|version)"):
                            fixture(pathlib.Path(temp))
                    with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
                        with mock.patch.object(driver.prepared, "validate_provenance", return_value=None):
                            repo, _ = fixture(pathlib.Path(temp))
                        with self.assertRaisesRegex(verifier.QualificationError, "compiler.*(output|version)"):
                            verifier.select_and_verify(repo, "0123456789abcdef")

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
            path = run / "command-12.init.gradle"
            result = verifier.select_and_verify(repo, "0123456789abcdef")
            self.assertEqual(sha(path), result["commands"]["finalInitSha256"])
            self.assertIn("no historical", result["commands"]["limitation"])
            path.write_text("// overwritten historical init\n")
            with self.assertRaises(verifier.QualificationError):
                verifier.select_and_verify(repo, "0123456789abcdef")

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
    "retained_child_helper_absent": lambda repo, run, r: (run / "owned-sources/atomic_install_child.py").unlink(),
    "retained_child_helper_tampered": lambda repo, run, r: (run / "owned-sources/atomic_install_child.py").write_bytes(b"tampered helper"),
    "retained_child_helper_swapped": lambda repo, run, r: (run / "owned-sources/atomic_install_child.py").write_bytes((repo / "scripts/test-atomic-install.py").read_bytes()),
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
    "command_init_missing_file": lambda repo, run, r: (run / "command-12.init.gradle").unlink(),
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


def alter_prepared(run, record, name, mutation):
    path = run / name
    data = json.loads(path.read_text())
    mutation(data)
    write_json(path, data)
    if name in record["noUpdate"]["evidenceHashes"]:
        record["noUpdate"]["evidenceHashes"][name] = sha(path)
    if name == "prepared-A.json":
        digest = sha(path)
        record["probes"][0]["preparedManifestSha256"] = digest
        guard = json.loads((run / "prepared-guard.json").read_text())
        guard["manifestSha256"] = digest
        write_json(run / "prepared-guard.json", guard)
        record["noUpdate"]["evidenceHashes"]["prepared-guard.json"] = sha(run / "prepared-guard.json")
    if name == "command-02-events.json":
        record["commands"][2]["taskReceiptSha256"] = sha(path)
    if name == "command-01-events.json":
        record["commands"][1]["taskReceiptSha256"] = sha(path)
        alter_prepared(run, record, "prepared-A.json", lambda m: m.update(preparationCommand=dict(record["commands"][1])))


def mutate_retained(run, record, token, kind):
    receipts = json.loads((run / "prepared-retained.json").read_text())
    name = next(n for n in receipts if token in n)
    path = run / receipts[name]["path"]
    if kind == "bytes": path.write_bytes(b"mutated prepared " + token.encode())
    elif kind == "missing": path.unlink()
    elif kind == "mode": path.chmod(0o600)
    elif kind == "key":
        replacement = path.with_name(path.name + "-replacement")
        replacement.write_bytes(path.read_bytes()); replacement.chmod(path.stat().st_mode & 0o777)
        replacement.replace(path)
    elif kind == "symlink": replace_with_symlink_or_fifo(path, "symlink")
    elif kind == "fifo": replace_with_symlink_or_fifo(path, "fifo")


def rehash_altered_init(run, record):
    command = record["commands"][2]
    path = pathlib.Path(command["init"])
    path.write_text(path.read_text() + "\n// unauthorized invocation recipe\n")
    command["initSha256"] = sha(path)


# Each mutation starts from the same independently validated inert fixture.
def acp_mutation(field, value, index=2):
    return lambda repo, run, record: alter_prepared(run, record, f'command-{index:02d}-events.json',
        lambda event: event['acp'].__setitem__(field, value))

for _token in ("build-v1.json", "/tools/compiler", "/src/main/c/fixture.c", "/bootstrap/classes/",
               "/native/analysis/decomp-analysis-io-helper", "/native/behavior/decomp-llvm-behavior-helper",
               "/libs/llm_bin_patch.jar", "/generated/kotlin-boot", "/scripts/llm_bin_patch", "/tools/node"):
    NEGATIVE_CASES["prepared_bytes_" + _token.replace("/", "_")] = lambda repo, run, r, token=_token: mutate_retained(run, r, token, "bytes")
for _kind in ("mode", "key", "missing", "symlink", "fifo"):
    NEGATIVE_CASES["prepared_" + _kind] = lambda repo, run, r, kind=_kind: mutate_retained(run, r, "/libs/", kind)
NEGATIVE_CASES.update({
    "prepared_manifest_missing": lambda repo, run, r: (run / "prepared-A.json").unlink(),
    "prepared_extra_input": lambda repo, run, r: (run / "prepared-products/extra").write_bytes(b"unexpected"),
    "acp_missing_receipt": lambda repo, run, r: alter_prepared(run, r, 'command-02-events.json', lambda d: d.pop('acp')),
    "acp_missing_task": lambda repo, run, r: alter_prepared(run, r, 'command-02-events.json', lambda d: d.update(tasks=[t for t in d['tasks'] if t['path'] != ':buildAcpGateHelper'])),
    "acp_skipped_task": lambda repo, run, r: alter_prepared(run, r, 'command-02-events.json', lambda d: next(t for t in d['tasks'] if t['path'] == ':buildAcpGateHelper').update(skipped=True)),
    "acp_up_to_date_task": lambda repo, run, r: alter_prepared(run, r, 'command-01-events.json', lambda d: next(t for t in d['tasks'] if t['path'] == ':buildAcpGateHelper').update(upToDate=True)),
    "acp_old_version": acp_mutation('schemaVersion', 1),
    "acp_boolean_version": acp_mutation('schemaVersion', True),
    "acp_wrong_scope": acp_mutation('publicationScope', 'hostile-namespace-v1'),
    "acp_wrong_binding": acp_mutation('bindingEvidence', 'executed-inode-authentication'),
    "acp_extra_assurance": acp_mutation('descriptorAuthenticated', True),
    "acp_missing_scope": lambda repo, run, r: alter_prepared(run, r, 'command-02-events.json', lambda d: d['acp'].pop('publicationScope')),
    "acp_missing_binding": lambda repo, run, r: alter_prepared(run, r, 'command-02-events.json', lambda d: d['acp'].pop('bindingEvidence')),
    "acp_missing_version": lambda repo, run, r: alter_prepared(run, r, 'command-02-events.json', lambda d: d['acp'].pop('schemaVersion')),
    "acp_failed_compiler": acp_mutation('exitCode', 1),
    "acp_cleanup_failure": acp_mutation('cleanup', False),
    "acp_faked_retained": acp_mutation('previous', None),
    "acp_candidate_probe": acp_mutation("candidateValidationExitCode", 0),
    "acp_final_probe": acp_mutation("finalValidationExitCode", 0),
    "acp_wrong_init": acp_mutation('initSha256', '0' * 64),
    "acp_wrong_command": acp_mutation('commandId', 1),
    "acp_skipped_prep": acp_mutation('exitCode', None, 1),
    "acp_flags_changed": acp_mutation('flags', ['-O0']),
    "acp_late_compile": acp_mutation('compileFinishedAtUnixNs', 999),
    "acp_candidate_escape": acp_mutation('candidatePath', '/tmp/candidate'),
    "acp_false_replace": acp_mutation('outcome', 'replaced'),
    "prepared_omitted_producer": lambda repo, run, r: alter_prepared(run, r, "command-01-events.json", lambda d: d.update(tasks=[t for t in d["tasks"] if t["path"] != ":buildAnalysisIoHelper"])),
    "prepared_previous_run": lambda repo, run, r: alter_prepared(run, r, "prepared-A.json", lambda d: d.update(runRoot=str(run.parent / "installed-prior"))),
    "prepared_stale_seal": lambda repo, run, r: alter_prepared(run, r, "prepared-A.json", lambda d: d.update(sealedAtUnixNs=1)),
    "prepared_wrong_command": lambda repo, run, r: r["noUpdate"].update(preparationCommandId=0),
    "prepared_wrong_role": lambda repo, run, r: r["probes"][0].update(role="retained-gcc"),
    "prepared_wrong_probe": lambda repo, run, r: r["noUpdate"].update(probeIndex=1),
    "prepared_ready_after_replay": lambda repo, run, r: r["probes"][0].update(readyAtUnixNs=299),
    "prepared_release_before_replay": lambda repo, run, r: r["probes"][0].update(releasedAtUnixNs=199),
    "prepared_false_cleanup": lambda repo, run, r: r.update(diagnosticFailures=["overflow"]),
    "prepared_false_unchanged": lambda repo, run, r: r["noUpdate"].update(protectedUnchanged=False),
    "prepared_wrong_init_hash": lambda repo, run, r: r["commands"][2].update(initSha256="f" * 64),
    "prepared_wrong_init_role": lambda repo, run, r: r["commands"][2]["initConfig"].update(replay=False),
    "prepared_rehashed_changed_init": lambda repo, run, r: rehash_altered_init(run, r),
    "prepared_extra_exclusion": lambda repo, run, r: r["commands"][2]["args"].extend(["-x", ":buildAcpGateHelper"]),
    "prepared_missing_exclusion": lambda repo, run, r: r["commands"][2]["args"].__delitem__(slice(-2, None)),
    "prepared_global_rerun": lambda repo, run, r: r["commands"][2]["args"].insert(7, "--rerun-tasks"),
    "prepared_exclusions_normal_install": lambda repo, run, r: r["commands"][4]["args"].extend(driver.prepared.EXCLUSIONS),
    "prepared_skip_publisher": lambda repo, run, r: alter_prepared(run, r, "command-02-events.json", lambda d: d.update(publisherCompleted=False)),
    "prepared_no_actions": lambda repo, run, r: alter_prepared(run, r, "command-02-events.json", lambda d: d.update(actionsStarted=False)),
    "prepared_up_to_date": lambda repo, run, r: alter_prepared(run, r, "command-02-events.json", lambda d: d["tasks"][0].update(upToDate=True)),
    "prepared_disabled_install": lambda repo, run, r: alter_prepared(run, r, "command-02-events.json", lambda d: d["tasks"][0].update(enabled=False)),
    "prepared_rename": lambda repo, run, r: alter_prepared(run, r, "command-02-events.json", lambda d: d["events"].append({"phase": "before-rename", "path": "app.jar", "atUnixNs": 260})),
    "prepared_prune": lambda repo, run, r: alter_prepared(run, r, "command-02-events.json", lambda d: d.update(stalePruneCandidates=["stale.jar"])),
    "prepared_skipped_guard": lambda repo, run, r: alter_prepared(run, r, "prepared-guard.json", lambda d: d.update(planEqual=False)),
    "prepared_guard_after_publisher": lambda repo, run, r: alter_prepared(run, r, "prepared-guard.json", lambda d: d.update(atUnixNs=271)),
    "prepared_source_set_guard_failure": lambda repo, run, r: alter_prepared(run, r, "prepared-guard.json", lambda d: d.update(sourceError="added file")),
    "prepared_changed_snapshot": lambda repo, run, r: alter_prepared(run, r, "protected-after.json", lambda d: next(iter(d["entries"].values())).update(sha256="0"*64)),
    "prepared_changed_snapshot_key": lambda repo, run, r: alter_prepared(run, r, "protected-after.json", lambda d: next(iter(d["entries"].values())).update(key=[0, 0])),
    "prepared_changed_snapshot_mode": lambda repo, run, r: alter_prepared(run, r, "protected-after.json", lambda d: next(iter(d["entries"].values())).update(mode=0)),
    "prepared_changed_input_snapshot": lambda repo, run, r: alter_prepared(run, r, "prepared-input-after.json", lambda d: next(iter(d["entries"].values())).update(mode=0)),
    "prepared_false_empty_diff": lambda repo, run, r: alter_prepared(run, r, "protected-diff.json", lambda d: d.update(added=["stale.jar"])),
    "prepared_missing_output": lambda repo, run, r: alter_prepared(run, r, "prepared-A.json", lambda d: d["plan"]["producers"]["buildAnalysisIoHelper"]["outputs"].clear()),
    "prepared_mapping_destination": lambda repo, run, r: alter_prepared(run, r, "prepared-A.json", lambda d: next(iter(d["mapping"].values())).update(destination="/elsewhere")),
    "prepared_compiler_original": lambda repo, run, r: alter_prepared(run, r, "prepared-A.json", lambda d: d["provenance"]["producers"]["buildAnalysisIoHelper"]["record"]["compiler"].update(version="different")),
    "prepared_changed_build_control": lambda repo, run, r: (repo / "gradle/wrapper/gradle-wrapper.jar").write_bytes(b"changed wrapper"),
})


def refresh_prepared_files(run, record, manifest, retained):
    """Rehash dependent receipts so semantic negatives reach the intended gate."""
    for suffix in ("before", "after"):
        write_json(run / f"prepared-input-{suffix}.json", manifest["inventory"])
    guard = json.loads((run / "prepared-guard.json").read_text())
    guard["inventory"] = manifest["inventory"]
    write_json(run / "prepared-guard.json", guard)
    write_json(run / "prepared-retained.json", retained)
    write_json(run / "prepared-closure.json", {"schemaVersion": 1, "roots": manifest["roots"],
               "inventory": manifest["inventory"], "copies": retained})
    alter_prepared(run, record, "prepared-A.json", lambda value: (value.clear(), value.update(manifest)))
    for name in record["noUpdate"]["evidenceHashes"]:
        record["noUpdate"]["evidenceHashes"][name] = sha(run / name)


def rehash_prepared_member(repo, run, record, token, mutation=None, mode=None):
    prep = driver.prepared
    manifest = json.loads((run / "prepared-A.json").read_text())
    retained = json.loads((run / "prepared-retained.json").read_text())
    name = next(n for n in retained if n.endswith(token))
    source = pathlib.Path(name)
    if mutation: source.write_bytes(mutation(source.read_bytes()))
    if mode is not None: source.chmod(mode)
    target = run / retained[name]["path"]
    target.write_bytes(source.read_bytes()); target.chmod(source.stat().st_mode & 0o777)
    retained[name].update(prep.file_receipt(target))
    manifest["inventory"]["entries"][name] = prep.file_receipt(source)
    for item in manifest["provenance"]["producers"].values():
        if item["path"] == name: item["record"] = json.loads(source.read_bytes())
        if item["record"]["compiler"]["path"] == name: item["compilerFile"] = prep.file_receipt(source)
    refresh_prepared_files(run, record, manifest, retained)


def json_mutation(action):
    def mutate(data):
        value = json.loads(data); action(value)
        return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    return mutate


def omit_original_descendant(repo, run, record):
    manifest = json.loads((run / "prepared-A.json").read_text())
    name = next(n for n in manifest["inventory"]["entries"] if n.endswith('/bootstrap/classes/producer.class'))
    manifest["inventory"]["entries"].pop(name)
    retained = json.loads((run / "prepared-retained.json").read_text())
    (run / retained.pop(name)["path"]).unlink()
    # Preserve the independently enumerated receipt while editing all flat claims.
    closure = (run / "prepared-closure.json").read_bytes()
    refresh_prepared_files(run, record, manifest, retained)
    (run / "prepared-closure.json").write_bytes(closure)
    record["noUpdate"]["evidenceHashes"]["prepared-closure.json"] = sha(run / "prepared-closure.json")
    assert pathlib.Path(name).is_file()


NEGATIVE_CASES["recursive_descendant_omitted_from_all_flat_claims"] = omit_original_descendant
NEGATIVE_CASES["recursive_receipt_missing"] = lambda repo, run, r: (run / "prepared-closure.json").unlink()
NEGATIVE_CASES["jdk17_rehashed_release"] = lambda repo, run, r: rehash_prepared_member(repo, run, r, '/tools/jdk/release', lambda _: b'JAVA_VERSION="17.0.1"\n')
NEGATIVE_CASES["jdk_duplicate_release_version"] = lambda repo, run, r: rehash_prepared_member(repo, run, r, '/tools/jdk/release', lambda _: b'JAVA_VERSION="21.0.1"\nJAVA_VERSION="17.0.1"\n')
for _tool in ('java', 'node'):
    NEGATIVE_CASES[_tool + '_not_executable'] = lambda repo, run, r, tool=_tool: rehash_prepared_member(repo, run, r, '/bin/' + tool, mode=0o644)
    NEGATIVE_CASES[_tool + '_wrong_home'] = lambda repo, run, r, tool=_tool: alter_prepared(run, r, 'prepared-A.json', lambda m: m['tools'][tool].update(home='/foreign'))
NEGATIVE_CASES['compiler_not_executable'] = lambda repo, run, r: rehash_prepared_member(repo, run, r, '/tools/compiler', mode=0o644)
for _suffix in ('analysis/analysis-native-io/source.c', 'behavior/decomp_llvm_behavior_helper.c'):
    NEGATIVE_CASES['unrelated_source_copy_' + _suffix.split('/')[0]] = lambda repo, run, r, suffix=_suffix: rehash_prepared_member(repo, run, r, suffix, lambda _: b'unrelated source')
for _suffix in ('analysis/decomp-analysis-io-helper.sha256', 'behavior/decomp-llvm-behavior-helper.sha256'):
    NEGATIVE_CASES['wrong_checksum_' + _suffix.split('/')[0]] = lambda repo, run, r, suffix=_suffix: rehash_prepared_member(repo, run, r, suffix, lambda _: b'0' * 64 + b'  wrong\n')
for _key, _value in (('schemaVersion', 2), ('kind', 'wrong'), ('sourceSha256', '0'*64), ('helperSha256', '0'*64), ('helperBytes', 999), ('buildPolicySha256', '0'*64)):
    NEGATIVE_CASES['analysis_record_' + _key] = lambda repo, run, r, k=_key, v=_value: rehash_prepared_member(repo, run, r, 'analysis-native-io/build-v1.json', json_mutation(lambda d: d.update({k: v})))
for _key in ('source', 'helper', 'checksum', 'buildRecord'):
    NEGATIVE_CASES['llvm_tuple_' + _key] = lambda repo, run, r, key=_key: rehash_prepared_member(repo, run, r, 'llvm-behavior-native-helper-deployment-reference-v1.json', json_mutation(lambda d: d[key].update(sha256='0'*64)))
for _key, _value in (('schemaVersion', 2), ('protocol', 'wrong'), ('closureSha256', '0'*64), ('compilerToolchainClosureAuthenticated', True)):
    NEGATIVE_CASES['llvm_record_' + _key] = lambda repo, run, r, k=_key, v=_value: rehash_prepared_member(repo, run, r, 'llvm-behavior-native-helper-deployment-reference-v1.json', json_mutation(lambda d: d.update({k: v})))
for _suffix in ('analysis-native-io/build-v1.json', 'llvm-behavior-native-helper-deployment-reference-v1.json'):
    for _fault in ('minimal', 'arguments', 'environment', 'failed'):
        def bad_record(repo, run, r, suffix=_suffix, fault=_fault):
            def change(d):
                if fault == 'minimal':
                    cc, comp = d['compiler'], d['compilation']; d.clear(); d.update(compiler=cc, compilation=comp)
                elif fault == 'arguments': d['compilation']['arguments'][-3] = '/unrelated/source.c'
                elif fault == 'environment': d['compilation']['environment']['HOME'] = '/unrelated'
                else: d['compilation']['result']['exitCode'] = 7
            rehash_prepared_member(repo, run, r, suffix, json_mutation(change))
        NEGATIVE_CASES['producer_' + _suffix + '_' + _fault] = bad_record
NEGATIVE_CASES['analysis_properties_build_tuple'] = lambda repo, run, r: rehash_prepared_member(repo, run, r, 'decomp-analysis-io-helper-v1.properties', lambda b: b.replace(b'buildRecordBytes=', b'wrongBytes='))
NEGATIVE_CASES['llvm_build_record_schema'] = lambda repo, run, r: rehash_prepared_member(repo, run, r, 'decomp-llvm-behavior-helper-build-v2.json', json_mutation(lambda d: d.update(schemaVersion=1)))
for _path in ('contracts/web/v1/contract.schema.json', 'oracle/kotlin-schema-inventory-v1.json', 'oracle/review.schema.json', 'oracle/llvm/22.1.6/native-runtime-measurement-v2.Dockerfile'):
    for _operation in ('changed', 'added', 'deleted'):
        def transitive(repo, run, r, path=_path, operation=_operation):
            target = repo / path
            if operation == 'changed': target.write_bytes(b'changed recipe')
            elif operation == 'deleted': target.unlink()
            else: target.with_name('added-' + target.name).write_bytes(b'new recipe')
            names = verifier.git_source_names(repo)
            with mock.patch.object(driver, 'ROOT', repo), mock.patch.object(driver.subprocess, 'check_output', return_value=('\0'.join(names) + '\0').encode()):
                current = driver.source_hashes()
                assert current != r['sourceHashes']
                assert set(current) == verifier.current_source_paths(repo)
                try: driver.prepared.check_prepared(json.loads((run / 'prepared-A.json').read_text()), json.loads((run / 'command-02-plan.json').read_text()))
                except RuntimeError: pass
                else: raise AssertionError('producer accepted changed transitive input')
        NEGATIVE_CASES['transitive_' + _operation + '_' + _path] = transitive


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


class DeclaredInputContractControls(unittest.TestCase):
    def setUp(self):
        QualificationVerifierControls.setUp(self)

    def test_independent_exact_schema_and_missing_inputs(self):
        with tempfile.TemporaryDirectory(dir=CONTROL_TMP) as temp:
            repo,run = fixture(pathlib.Path(temp))
            plan = json.loads((run/'command-01-plan.json').read_text())
            consumers = (driver.prepared, verifier)
            for consumer in consumers: consumer.validate_semantic_plan(plan)
            mutants=[]
            for field in plan:
                value=copy.deepcopy(plan);del value[field];mutants.append(('plan.'+field,value))
            for field in plan['producers']['buildAnalysisIoHelper']['properties']:
                value=copy.deepcopy(plan);del value['producers']['buildAnalysisIoHelper']['properties'][field]
                mutants.append(('input.'+field,value))
            for wire in (['string',None],['null',None],['boolean',1],['integer','java.lang.Byte','128'],
                         ['decimal','1',True],['ieee','java.lang.Double','0'],['provider',['present']],
                         ['array','unreviewed.Component',[]],['provider',['present',['null']]],['map',[['a',['null']],['a',['null']]]],
                         ['set',[['string','a'],['string','a']]],['ordered-set',[['null']],[]]):
                value=copy.deepcopy(plan);value['producers']['buildAnalysisIoHelper']['properties']['extra']=wire
                mutants.append(('wire.'+wire[0],value))
            for name,value in mutants:
                for consumer in consumers:
                    with self.subTest(name=name,consumer=consumer.__name__), self.assertRaises((RuntimeError,TypeError,KeyError)):
                        consumer.validate_semantic_plan(value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
