#!/usr/bin/env python3
"""Separate completed-build, real installed-launcher qualification for #1834.

Run only after all source owners have stopped editing. Publisher/driver controls are
separate gates; this driver never describes a mixed installation as a snapshot.
"""
from __future__ import annotations
import importlib.util
import hashlib, json, os, pathlib, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, zipfile

_SPEC = importlib.util.spec_from_file_location("atomic_install_prepared", pathlib.Path(__file__).with_name("atomic_install_prepared.py"))
prepared = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(prepared)

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "build/orchestration/atomic-install-remediation"
WORK = ROOT / "build/tmp/atomic-install"  # Replaced with a unique directory by main.
INIT = WORK / "atomic-install.init.gradle"
AGENT = ROOT / "build/atomic-install/atomic-install-probe-agent.jar"
APP = "llm_bin_patch"
MAX_LOG = 16 * 1024 * 1024
BUILD_TIMEOUT = 1200
READY_TIMEOUT = 120
PROBE_FINISH_TIMEOUT = 120
# One update, the fresh-process READY/late-load sequence, and bounded bookkeeping.
RELEASE_TIMEOUT = BUILD_TIMEOUT + READY_TIMEOUT + PROBE_FINISH_TIMEOUT + 60
ACTIVE = set()
RECORD = {"status": "not-started", "phase": "setup", "commands": [], "transitions": [], "authorities": []}
MODEL = json.dumps({"schemaVersion":4,"inputSha256":"a"*64,"functions":[],"globals":[],"types":[]}, separators=(",",":"))
OWNED_SOURCES = ("build.gradle.kts", "scripts/test-atomic-install.py", "scripts/test-atomic-install-controls.py",
                 "scripts/atomic-install-acp-publication.groovy",
                 "src/test/java/decompengine/install/AtomicInstallProbeAgent.java")


def qualified_java_home():
    configured = os.environ.get("JAVA_HOME")
    executable = shutil.which("java") if not configured else None
    if not configured and not executable:
        raise RuntimeError("Java 21 is required for installed qualification")
    home = pathlib.Path(configured).resolve() if configured else pathlib.Path(executable).resolve().parent.parent
    if not (home / "bin/java").is_file() or not os.access(home / "bin/java", os.X_OK):
        raise RuntimeError("Selected JAVA_HOME has no executable bin/java")
    with (home / "release").open(encoding="utf-8") as source:
        release = source.read(65537)
    if len(release) > 65536 or not re.search(r'^JAVA_VERSION="21(?:[.\"+\-])', release, re.MULTILINE):
        raise RuntimeError("Selected JAVA_HOME is not a qualified Java 21 installation")
    return home


def digest(path, limit=8 * 1024**3):
    h = hashlib.sha256()
    with prepared.regular(pathlib.Path(path), limit) as (stream, info):
        total = 0
        while chunk := stream.read(min(1024 * 1024, limit - total + 1)):
            total += len(chunk)
            prepared.require(total <= limit, "digest input grew beyond byte bound")
            h.update(chunk)
        prepared.require(total == info.st_size, "digest input size changed")
    return h.hexdigest()


def source_hashes():
    # Include dirty product/test/build sources, not just the committed HEAD.
    names = set(subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT).decode().split("\0"))
    names.update(OWNED_SOURCES)
    names.update(prepared.BUILD_CONTROLS)
    return {name: digest(ROOT / name, 128 * 1024**2) for name in sorted(names) if name and
            (name in prepared.BUILD_CONTROLS or name.startswith(("src/", "scripts/", "frontend/", "ghidra-bridge/", "contracts/", "oracle/")) or name.endswith((".gradle.kts", ".properties")))
            and (ROOT / name).is_file() and not (ROOT / name).is_symlink()}


def save_record():
    WORK.mkdir(parents=True, exist_ok=True)
    target = WORK / "qualification.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(RECORD, indent=2) + "\n")
    temporary.replace(target)


def close_preserving_failure(child, record=None):
    """Keep the active error primary; cleanup is separately retained and fatal."""
    primary = sys.exception()
    try:
        child.close()
    except BaseException as cleanup:
        detail = repr(cleanup)
        RECORD.setdefault("cleanupFailures", []).append(detail)
        RECORD["status"] = "failed"
        if record is not None:
            record.setdefault("cleanupFailures", []).append(detail)
            record["status"] = "failed"
            if primary is None:
                record.setdefault("failure", detail)
        if primary is not None:
            primary.add_note("Secondary child cleanup failure: " + detail)
        else:
            raise


class Child:
    """Bounded disk + memory output; every local failure kills the group and reaps."""
    def __init__(self, args, *, env=None, cwd=ROOT, log=None):
        self.log = pathlib.Path(log or WORK / ("process-" + str(time.monotonic_ns()) + ".log"))
        self.error = None
        self.tail = bytearray()
        self.total = 0
        self.process = None
        self.reader = None
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.sink = self.log.open("xb")
        try:
            self.process = subprocess.Popen(list(map(str, args)), cwd=cwd, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
            ACTIVE.add(self)
            self.reader = threading.Thread(target=self._drain, daemon=True)
            self.reader.start()
        except BaseException:
            close_preserving_failure(self)
            raise

    def _drain(self):
        try:
            while chunk := self.process.stdout.read(65536):
                remaining = MAX_LOG - self.total
                self.sink.write(chunk[:max(0, remaining)])
                self.total += len(chunk)
                self.tail.extend(chunk)
                del self.tail[:-12000]
                if self.total > MAX_LOG:
                    raise RuntimeError(f"output exceeded {MAX_LOG} bytes: {self.log}")
        except BaseException as failure:
            self.error = failure
            self.kill_group()
        finally:
            self.sink.close()

    def kill_group(self):
        if self.process is not None:
            try: os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass

    def close(self):
        # Defer a second terminal signal until this child has been killed and reaped.
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        try:
            self.kill_group()  # Also kill descendants after the group leader has exited.
            if self.process is not None:
                self.process.wait(timeout=10)
                if self.reader is not None and self.reader.ident is not None:
                    self.reader.join(timeout=10)
                    if self.reader.is_alive(): raise RuntimeError("output collector failed to reap")
                self.process.stdout.close()
            self.sink.close()
            ACTIVE.discard(self)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def wait(self, timeout):
        try:
            code = self.process.wait(timeout=timeout)
            self.kill_group()  # No orphan may retain the pipe after a successful leader exit.
            self.reader.join(timeout=10)
            if self.reader.is_alive(): raise RuntimeError("output collector did not finish")
            if self.error: raise self.error
            return code
        finally:
            close_preserving_failure(self)

    def text(self): return self.tail.decode("utf-8", errors="replace")


def run(args, *, env=None, timeout=900, log=None, allow_failure=False):
    command = {"args": list(map(str, args)), "phase": RECORD["phase"], "status": "running",
               "commandId": len(RECORD["commands"]), "startedAtUnixNs": time.time_ns()}
    if "-I" in command["args"]:
        init = pathlib.Path(command["args"][command["args"].index("-I") + 1])
        command.update(init=str(init), initSha256=digest(init),
                       initConfig=prepared.read_json(init.with_suffix(".json")))
    RECORD["commands"].append(command)
    save_record()
    child = None
    try:
        child = Child(args, env=env, log=log)
        command["log"] = str(child.log)
        code = child.wait(timeout)
        command.update(status="passed" if code == 0 else "failed", exitCode=code, logSha256=digest(child.log))
        if code and not allow_failure: raise RuntimeError(f"exit {code}: {args[0]} (log {child.log})")
        return code, child.text()
    except BaseException as failure:
        command.update(status="failed", failure=repr(failure))
        raise
    finally:
        try:
            if child is not None: close_preserving_failure(child, command)
        finally:
            command["finishedAtUnixNs"] = time.time_ns()
            receipt = WORK / f"command-{command['commandId']:02d}-events.json"
            if receipt.exists():
                command.update(taskReceipt=str(receipt), taskReceiptSha256=digest(receipt))
            save_record()


def safe_env():
    env = {k:v for k,v in os.environ.items() if k not in
           ("JAVA_OPTS", "GRADLE_OPTS", "JDK_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "LLM_BIN_PATCH_OPTS")}
    env.update(JAVA_HOME=str(qualified_java_home()), TMPDIR=str(WORK / "tmp"),
               GRADLE_USER_HOME=str(ROOT / "build/.gradle-user-home"),
               NPM_CONFIG_CACHE=str(ROOT / "build/npm-download-cache"))
    return env


def jvm_options():
    return ["-Djava.io.tmpdir=" + str(WORK / "tmp"), "-Duser.home=" + str(WORK / "home"),
            "-XX:-UsePerfData", "-XX:-CreateCoredumpOnCrash", "-XX:-DumpReplayDataOnError",
            "-XX:ErrorFile=" + str(WORK / "hs_err_pid%p.log")]


def gradle(*args, log=None, allow_failure=False):
    env = safe_env()
    env["JAVA_OPTS"] = shlex.join(jvm_options())
    # Pin daemon JVM home/tmp too; --no-daemon may still fork a single-use daemon.
    return run([ROOT / "gradlew", "--no-daemon", "-g", env["GRADLE_USER_HOME"],
                "-Dorg.gradle.jvmargs=" + shlex.join(jvm_options()),
                "-Dorg.gradle.java.installations.auto-download=false",
                "-Dorg.gradle.java.installations.paths=" + env["JAVA_HOME"], *args],
               env=env, timeout=BUILD_TIMEOUT, log=log, allow_failure=allow_failure)


def groovy_path(path):
    return "'" + str(path).replace("\\", "\\\\").replace("'", "\\'") + "'"


def install_root():
    # All existing distribution verifiers consume this build-directory location.
    return WORK / "root-build/install" / APP


def write_init(generation, fail_before_rename=False, *, replay=False, command_id=None):
    global INIT
    command_id = len(RECORD["commands"]) if command_id is None else command_id
    INIT = WORK / f"command-{command_id:02d}.init.gradle"
    config = {"commandId": command_id, "runRoot": str(WORK), "generation": generation,
              "failBeforeRename": fail_before_rename, "replay": replay,
              "exclusions": prepared.EXCLUSIONS if replay else []}
    if generation is not None:
        gen = WORK / "markers" / generation
        gen.mkdir(parents=True, exist_ok=True)
        marker = gen / "atomic-install-generation.txt"
        if not marker.exists(): marker.write_text(generation)
        if marker.read_text() != generation: raise RuntimeError("generation marker changed")
    text = init_text(config)
    with INIT.open("x") as target:
        target.write(text)
    prepared.write_json(INIT.with_suffix(".json"), config, immutable=True)
    return INIT


def init_text(config, *, root=None, work=None):
    ROOT = root or globals()["ROOT"]
    WORK = work or globals()["WORK"]
    generation, replay = config["generation"], config["replay"]
    command_id = config["commandId"]
    gen = WORK / "markers" / str(generation)
    event_file = WORK / f"command-{command_id:02d}-events.json"
    plan_file = WORK / f"command-{command_id:02d}-plan.json"
    helper = ROOT / "scripts/atomic_install_prepared.py"
    text = f'''import groovy.json.JsonOutput
import java.nio.file.Files
import java.nio.file.StandardCopyOption
// Immutable command configuration: {json.dumps(config, sort_keys=True)}
def nowNs = {{ -> def instant = java.time.Instant.now(); instant.epochSecond * 1000000000L + instant.nano }}
def receipt = [commandId: {command_id}, runRoot: {groovy_path(WORK)}, tasks: [], events: [], actionsStarted: false, publisherCompleted: false]
def saveReceipt = {{ ->
    def data = JsonOutput.toJson(receipt)
    if (data.getBytes('UTF-8').length > 16777216) throw new GradleException('atomic receipt exceeds bound')
    def target = new File({groovy_path(event_file)})
    def stage = new File(target.path + '.partial')
    stage.setText(data, 'UTF-8')
    Files.move(stage.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
}}
gradle.taskGraph.afterTask {{ task, state ->
    if (receipt.tasks.size() >= 8192) throw new GradleException('atomic task receipt exceeds bound')
    receipt.tasks.add([path: task.path, enabled: task.enabled, skipped: state.skipped, upToDate: state.upToDate,
        noSource: state.noSource, executed: state.executed, failure: state.failure != null,
        atUnixNs: nowNs()])
    if (task.path == ':buildAcpGateHelper' && task.extensions.extraProperties.has('atomicAcpPublicationReceipt')) {{
        receipt.acp = new LinkedHashMap(task.extensions.extraProperties.get('atomicAcpPublicationReceipt'))
        receipt.acp.commandId = {command_id}
        receipt.acp.runRoot = {groovy_path(WORK)}
        receipt.acp.initSha256 = java.security.MessageDigest.getInstance('SHA-256').digest(
            new File({groovy_path(WORK / f"command-{command_id:02d}.init.gradle")}).bytes).encodeHex().toString()
    }}
    saveReceipt()
}}
'''
    if generation is None:
        return text
    text += f'''allprojects {{ p -> if (p == p.rootProject) {{
p.buildDir = new File({groovy_path(WORK / "root-build")})
p.afterEvaluate {{
def declaredProperties = [:]
gradle.taskGraph.whenReady {{ graph ->
    if (!graph.hasTask(":installDist")) return
    ['buildAnalysisIoHelper', 'buildLlvmBehaviorHelper'].each {{ name ->
        declaredProperties[name] = p.tasks.getByName(name).inputs.properties.collectEntries {{ key, value -> [(key): value.toString()] }}
    }}
}}
p.tasks.matching {{ it.name == "frontendBuild" }}.configureEach {{
    outputs.upToDateWhen {{ false }}
    doLast {{
        def produced = new File({groovy_path(ROOT / "build/frontend")})
        def consumed = new File({groovy_path(WORK / "root-build/frontend")})
'''
    if replay:
        text += f'''        p.providers.exec {{ commandLine({groovy_path(pathlib.Path(sys.executable).resolve())}, '-B', {groovy_path(helper)},
            'frontend', produced.absolutePath, consumed.absolutePath) }}.result.get().assertNormalExitValue()
'''
    else:
        text += '''        ["dist", "bundle-report.json", "bundle-composition.json"].each { name ->
            def source = new File(produced, name)
            if (!source.exists()) throw new GradleException("Missing fresh frontend output: " + name)
            p.delete(new File(consumed, name))
            p.copy { from(source); into(name == "dist" ? new File(consumed, name) : consumed) }
        }
'''
    text += f'''    }}
}}
p.tasks.matching {{ it.name == "jar" }}.configureEach {{ from(new File({groovy_path(gen)})) }}
p.tasks.matching {{ it.name == "installDist" }}.configureEach {{ install ->
    destinationDir = new File({groovy_path(WORK / "root-build/install" / APP)})
    ext.atomicInstallTestEvent = {{ phase, path ->
        if (receipt.events.size() >= 24576) throw new GradleException('atomic event receipt exceeds bound')
        receipt.events.add([phase: phase, path: path.toString(), atUnixNs: nowNs()])
        saveReceipt()
'''
    if config["failBeforeRename"]:
        text += '''        if (phase == "before-rename") throw new IllegalStateException("atomic-probe injected before first rename")
'''
    text += '''    } as java.util.function.BiConsumer
'''
    if replay:
        text += '    outputs.upToDateWhen { false }\n'
    text += f'''    doFirst {{
        receipt.actionsStarted = true
        receipt.actionsStartedAtUnixNs = nowNs()
        saveReceipt()
        def files = {{ collection -> collection.files.collect {{ it.absolutePath }}.sort() }}
        def producers = [:]
        ['buildAnalysisIoHelper', 'buildLlvmBehaviorHelper'].each {{ name ->
            def producer = p.tasks.getByName(name)
            producers[name] = [inputs: files(producer.inputs.files), outputs: files(producer.outputs.files),
                classpath: files(producer.classpath), mainClass: producer.mainClass.get(),
                properties: declaredProperties[name]]
        }}
        def roots = [:]
        ['stageKotlinBootRuntime', 'generateKotlinBootClasspathReference', 'generateGccBundledGhidraReference',
         'generateLlvmHostedWorkerClasspathReference', 'startScripts'].each {{ name ->
            def task = p.tasks.getByName(name)
            def outputs = files(task.outputs.files)
            if (outputs.size() != 1) throw new GradleException('unexpected mapping output roots: ' + name)
            roots[name] = outputs[0]
        }}
        def acpTask = p.tasks.getByName('buildAcpGateHelper')
        def acp = [publicationScope: 'cooperative-build-producer-v1', bindingEvidence: 'stable-namespace-path-observations-v1', compiler: p.file(acpTask.inputs.properties.compiler.toString()).toPath().toAbsolutePath().normalize().toRealPath().toString(),
            source: new File(p.projectDir, 'src/main/c/decomp_acp_gate_helper.c').absolutePath,
            recipe: new File(p.projectDir, 'build.gradle.kts').absolutePath,
            publication: new File(p.projectDir, 'scripts/atomic-install-acp-publication.groovy').absolutePath,
            output: new File(p.buildDir, 'native/acp/decomp-acp-gate-helper').absolutePath]
        def plan = [acp: acp, runRoot: {groovy_path(WORK)}, repoRoot: {groovy_path(ROOT)}, installInputs: files(install.inputs.files), producers: producers,
            frontendNodeHome: p.tasks.getByName('frontendBuild').inputs.properties.frontendNodeHome.toString(),
            mappingRoots: roots, originalJar: p.tasks.getByName('jar').archiveFile.get().asFile.absolutePath]
        def planText = JsonOutput.toJson(plan)
        if (planText.getBytes('UTF-8').length > 33554432) throw new GradleException('atomic plan exceeds bound')
        Files.writeString(new File({groovy_path(plan_file)}).toPath(), planText, java.nio.file.StandardOpenOption.CREATE_NEW)
'''
    if replay:
        text += f'''        p.providers.exec {{ commandLine({groovy_path(pathlib.Path(sys.executable).resolve())}, '-B', {groovy_path(helper)},
            'guard', {groovy_path(WORK)}) }}.result.get().assertNormalExitValue()
        def boundedNames = {{ directory ->
            def names = []
            def entries = Files.newDirectoryStream(directory.toPath())
            try {{
                entries.each {{ entry ->
                    if (names.size() >= 4096) throw new GradleException('protected directory exceeds bound')
                    names.add(entry.fileName.toString())
                }}
            }} finally {{ entries.close() }}
            names
        }}
        def expectedNames = boundedNames(new File(roots.stageKotlinBootRuntime)).toSet()
        def existing = boundedNames(new File(destinationDir, 'lib'))
        receipt.stalePruneCandidates = existing.findAll {{ it.endsWith('.jar') && !expectedNames.contains(it) }}.sort()
        if (!receipt.stalePruneCandidates.isEmpty()) throw new GradleException('unexpected stale prune candidates')
        receipt.guardPassedAtUnixNs = nowNs()
        saveReceipt()
'''
    text += '''    }
    // Registered after production configuration; this follows the real publisher.
    doLast {
        receipt.publisherCompleted = true
        receipt.publisherCompletedAtUnixNs = nowNs()
        saveReceipt()
    }
}
} } }
'''
    return text


def install(generation, *, fail=False, replay=False):
    write_init(generation, fail, replay=replay)
    log = WORK / f"install-{generation}-{time.monotonic_ns()}.log"
    code, output = gradle("-I", INIT, "installDist", *(prepared.EXCLUSIONS if replay else []), log=log, allow_failure=fail)
    if fail and (code == 0 or "atomic-probe injected before first rename" not in output or "completed renames=0" not in output):
        raise RuntimeError("failed-update control did not reach the intended production pre-rename seam")
    return code, output


def app_jar():
    found = []
    for path in (install_root() / "lib").glob("*.jar"):
        with zipfile.ZipFile(path) as archive:
            if "decompengine/MainKt.class" in archive.namelist(): found.append(path)
    if len(found) != 1: raise RuntimeError("expected exactly one installed app JAR")
    return found[0]


def statkey(path):
    s = path.stat(); return (s.st_dev, s.st_ino)


def protected_snapshot():
    snapshot = prepared.protected(install_root(), WORK)
    prepared.require(snapshot["status"] == "passed", "protected snapshot failed: " + snapshot.get("error", ""))
    return snapshot["entries"]


def read_evidence(path):
    with path.open("rb") as stream: data = stream.read(65537)
    if len(data) > 65536: raise RuntimeError("probe evidence exceeds bound")
    return json.loads(data)


def launch_blocked(generation, authority="none"):
    root = pathlib.Path(tempfile.mkdtemp(prefix=f"{generation}-{authority}-", dir=WORK / "barriers"))
    ready = root / "READY"; release = root / "RELEASE"; jar = app_jar()
    props = {"atomic.probe.app": str(jar), "atomic.probe.ready": str(ready), "atomic.probe.release": str(release),
             "atomic.probe.marker": generation, "atomic.probe.model": MODEL, "atomic.probe.authority": authority,
             "atomic.probe.releaseTimeoutSeconds": str(RELEASE_TIMEOUT)}
    opts = jvm_options() + ["-javaagent:" + str(AGENT)] + ["-D"+k+"="+v for k,v in props.items()]
    env = safe_env(); env["JAVA_OPTS"] = shlex.join(opts)
    probe = {"generation": generation, "authority": authority, "root": str(root), "status": "starting"}
    RECORD.setdefault("probes", []).append(probe)
    save_record()
    child = None
    try:
        child = Child([install_root() / "bin" / APP], cwd=WORK, env=env, log=root / "launcher.log")
        child.probe = probe
        probe.update(pid=child.process.pid, log=str(child.log))
        deadline = time.monotonic() + READY_TIMEOUT
        while time.monotonic() < deadline and child.process.poll() is None and not ready.exists():
            if child.error: raise child.error
            time.sleep(.05)
        if not ready.exists(): raise RuntimeError(f"agent did not reach READY: {child.log}")
        data = read_evidence(ready)
        if data["mainOrigin"] != str(jar.resolve()) or data["modelAbsentBeforeReady"] != "true" or data["archiveMarker"] != generation:
            raise RuntimeError("READY descriptor/path/absence evidence malformed")
        if data["releaseTimeoutSeconds"] != str(RELEASE_TIMEOUT):
            raise RuntimeError("agent release budget differs from the driver sequence")
        expected = {p.resolve() for p in (install_root() / "lib").glob("*.jar")}
        actual = [pathlib.Path(p).resolve() for p in data["classpath"].split(os.pathsep)]
        if len(actual) != len(expected) or set(actual) != expected:
            raise RuntimeError("installed launcher classpath is not the exact installed JAR closure")
        if data["descriptorDigest"] != digest(jar): raise RuntimeError("READY descriptor not installed generation")
        probe.update(status="ready", ready=data, readyAtUnixNs=time.time_ns())
        return child, release, data, jar  # Ownership transfers only here.
    except BaseException as failure:
        probe.update(status="failed", failure=repr(failure))
        if child is not None: close_preserving_failure(child, probe)
        raise
    finally: save_record()


def release_and_reap(child, release, generation, expected="changed"):
    try:
        child.probe["releasedAtUnixNs"] = time.time_ns()
        release.write_text(expected + "\n")
        code = child.wait(PROBE_FINISH_TIMEOUT)
        loaded = release.with_name("READY.loaded")
        if code or not loaded.exists(): raise RuntimeError(f"late-load probe failed: {child.log} (exit {code})")
        data = read_evidence(loaded)
        if data["lateResourceMarker"] != generation or data["schemaVersion"] != "4" or data["inputSha256"] != "a"*64:
            raise RuntimeError("late model/resource mismatch")
        if data["modelLoader"] != data["transformLoader"] or data["modelOrigin"] != data["transformOrigin"]:
            raise RuntimeError("late defining loader/origin mismatch")
        child.probe.update(status="passed", loaded=data, exitCode=code, logSha256=digest(child.log))
        return data
    except BaseException as failure:
        child.probe.update(status="failed", failure=repr(failure))
        raise
    finally:
        try:
            close_preserving_failure(child, child.probe)
        finally:
            save_record()


def set_phase(phase):
    RECORD["phase"] = phase; save_record()


def seal_preparation():
    command = RECORD["commands"][1]
    tasks = prepared.read_json(WORK / "command-01-events.json")["tasks"]
    for name in (*prepared.PRODUCERS, "buildAcpGateHelper"):
        events = [t for t in tasks if t["path"] == ":" + name]
        prepared.require(len(events) == 1 and events[0]["executed"] and events[0]["enabled"] and
                         not any(events[0][key] for key in ("skipped", "upToDate", "noSource", "failure")),
                         "fresh preparation did not execute helper producer: " + name)
    plan = prepared.read_json(WORK / "command-01-plan.json")
    java = qualified_java_home()
    node = pathlib.Path(shutil.which("node")).resolve()
    tools = {"java": {"path": str((java / "bin/java").resolve()), "home": str(java)},
             "javaRelease": {"path": str(java / "release")}, "node": {"path": str(node), "home": str(node.parent.parent)}}
    # Original JDK release and pinned Node version; ACP still compiles freshly on replay.
    node_version = subprocess.check_output([node, "--version"], env=safe_env(), timeout=10).decode().strip()
    prepared.require(node_version.lstrip("v") == (ROOT / ".node-version").read_text().strip().lstrip("v"), "Node version differs")
    manifest = {"schemaVersion": 1, "runRoot": str(WORK), "preparationCommandId": 1,
                "preparationCommand": dict(command), "plan": plan, "sourceHashes": source_hashes(),
                "buildControls": prepared.build_controls(ROOT), "tools": tools, "nodeVersion": node_version,
                "sealedAtUnixNs": time.time_ns()}
    prepared.require(manifest["sourceHashes"] == RECORD["sourceHashes"], "source changed during preparation")
    manifest.update(prepared.capture(plan, ROOT, manifest["sourceHashes"], tools))
    prepared.write_json(WORK / "prepared-A.json", manifest, immutable=True)
    return manifest


def live_no_update():
    prepared.require(not (WORK / "root-build").exists(), "initial A build directory is not fresh")
    install("A")
    manifest = seal_preparation()
    child = None
    primary = None
    before = prepared.protected(install_root(), WORK)
    prepared.write_json(WORK / "protected-before.json", before, immutable=True)
    prepared.write_json(WORK / "prepared-input-before.json", manifest["inventory"], immutable=True)
    try:
        prepared.require(before["status"] == "passed", "protected before snapshot failed")
        prepared.check_prepared(manifest, manifest["plan"])
        child, release, ready, jar = launch_blocked("A")
        RECORD["probes"][0].update(role="prepared-no-update", preparationCommandId=1, replayCommandId=2,
                                    preparedManifestSha256=digest(WORK / "prepared-A.json"))
        prepared.require(child.process.poll() is None, "installed probe died before replay")
        install("A", replay=True)
        prepared.require(child.process.poll() is None, "installed probe died during replay")
    except BaseException as failure:
        primary = failure
        raise
    finally:
        # Always retain diagnostics before releasing/reaping, including guard/command failures.
        diagnostic_errors = []
        for prefix, capture, old in (("protected", lambda: prepared.protected(install_root(), WORK), before),
                ("prepared-input", lambda: prepared.inventory(manifest["roots"]), manifest["inventory"])):
            try:
                after = capture()
                prepared.write_json(WORK / (prefix + "-after.json"), after, immutable=True)
                prepared.write_json(WORK / (prefix + "-diff.json"), prepared.difference(old, after), immutable=True)
            except BaseException as failure:
                diagnostic_errors.append(repr(failure))
        if diagnostic_errors:
            RECORD["diagnosticFailures"] = diagnostic_errors
            if primary is None: raise RuntimeError("no-update diagnostic capture failed: " + repr(diagnostic_errors))
    for prefix in ("protected", "prepared-input"):
        prepared.require(prepared.read_json(WORK / (prefix + "-diff.json")) == prepared.EMPTY_DIFF,
                         "no-update changed " + prefix)
    validate_replay_receipt(manifest)
    result = release_and_reap(child, release, "A", "unchanged")
    prepared.require(result["descriptorDigest"] == result["installedPathDigestAfterRelease"] == ready["descriptorDigest"],
                     "no-update retained descriptor/path differs")
    retained = prepared.retain_inputs(manifest, WORK)
    prepared.write_json(WORK / "prepared-retained.json", retained, immutable=True)
    evidence = ["prepared-A.json", "prepared-retained.json", "prepared-closure.json", "prepared-guard.json",
                *[prefix + suffix + ".json" for prefix in ("protected", "prepared-input") for suffix in ("-before", "-after", "-diff")]]
    return {"status": "passed", "probe": result, "protectedUnchanged": True,
            "preparationCommandId": 1, "replayCommandId": 2, "probeIndex": 0,
            "evidenceHashes": {name: digest(WORK / name) for name in evidence}}


def validate_replay_receipt(manifest):
    receipt = prepared.read_json(WORK / "command-02-events.json")
    prepared.validate_acp(receipt, manifest["plan"], manifest["inventory"]["entries"], RECORD["commands"][2])
    prepared.validate_publisher(receipt, manifest)


def main():
    global WORK, INIT
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    WORK = pathlib.Path(tempfile.mkdtemp(prefix="installed-", dir=EVIDENCE))
    INIT = WORK / "atomic-install.init.gradle"
    for name in ("tmp", "home", "barriers"): (WORK / name).mkdir()
    RECORD.update(status="running", runRoot=str(WORK))
    # A failed latest run can never be mistaken for a previous pass.
    (EVIDENCE / "latest-installed-run.json").write_text(json.dumps({"record": str(WORK / "qualification.json")}) + "\n")
    save_record()
    try:
        set_phase("source capture")
        RECORD.update(sourceHead=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), sourceHashes=source_hashes())
        set_phase("agent build")
        write_init(None)
        gradle("-I", INIT, "atomicInstallProbeAgentJar", log=WORK / "agent-build.log")
        RECORD["agentSha256"] = digest(AGENT)
        set_phase("initial A and no-update")
        RECORD["noUpdate"] = live_no_update()
        set_phase("failed-before-rename live A")
        child, release, ready, jar = launch_blocked("A")
        before = protected_snapshot()
        install("B", fail=True)
        if protected_snapshot() != before: raise RuntimeError("pre-rename failure changed protected targets")
        RECORD["failedBeforeRename"] = release_and_reap(child, release, "A", "unchanged")
        for old, new in (("A", "B"), ("B", "A")):
            set_phase(f"live transition {old}->{new}")
            install(old)
            child, release, ready, jar = launch_blocked(old)
            before_key = statkey(jar)
            install(new)
            new_digest = digest(jar); after_key = statkey(jar)
            if before_key == after_key or ready["descriptorDigest"] == new_digest: raise RuntimeError("app inode/bytes did not change")
            # Start a new process by the installed path while the old parent remains at READY.
            fresh, fresh_release, fresh_ready, _ = launch_blocked(new)
            fresh_result = release_and_reap(fresh, fresh_release, new)
            if fresh_ready["descriptorDigest"] != new_digest or fresh_result["descriptorDigest"] != new_digest:
                raise RuntimeError("fresh launcher did not retain new generation")
            old_result = release_and_reap(child, release, old)
            if old_result["descriptorDigest"] != ready["descriptorDigest"] or old_result["installedPathDigestAfterRelease"] != new_digest:
                raise RuntimeError("old descriptor/new path mismatch")
            RECORD["transitions"].append({"from": old, "to": new, "beforeFileKey": before_key, "afterFileKey": after_key,
                "oldParent": old_result, "newProcessByInstalledPath": fresh_result,
                "interpretation": "opened old descriptor/resource and new process by path differ; no universal old-parent rejection claimed"})
            save_record()
        for authority in ("gcc", "llvm"):
            set_phase(f"retained {authority} authority")
            install("A")
            child, release, ready, jar = launch_blocked("A", authority)
            before = protected_snapshot()
            # A real lease refusal must be an explicit production failure, never a timeout mislabeled as success.
            write_init("B")
            code, output = gradle("-I", INIT, "installDist", log=WORK / (authority + "-held-install.log"), allow_failure=True)
            unchanged = protected_snapshot() == before
            if code and not (unchanged and re.search(r"(?i)(lease|resource temporarily unavailable|device or resource busy)", output)):
                raise RuntimeError("held-authority update failed without a qualified lease-refusal diagnostic")
            result = release_and_reap(child, release, "A", "lease-refused" if code else "changed")
            if not code and result.get("authorityOutcome") != "rejected-before-authorization":
                raise RuntimeError("retained authority did not reject replaced deployment")
            RECORD["authorities"].append({"authority": authority, "installExit": code, "protectedUnchanged": unchanged, "probe": result})
            save_record()
        set_phase("archive/classpath/helper contracts")
        write_init("B")
        gradle("-I", INIT, "installDist", "distZip", "distTar", "verifyGhidraDistributionArchives",
               "verifyAnalysisIoHelperInstalled", "verifyAcpGateHelperDistribution", "verifyLlvmBehaviorHelperDistribution",
               "verifyKotlinBootClasspathDistribution", log=WORK / "distribution-contracts.log")
        for directory in (install_root() / "lib", install_root() / "bin"):
            if list(directory.glob(".install-*.tmp")): raise RuntimeError("installer left temporary files")
        RECORD["finalProtectedFiles"] = protected_snapshot()
        RECORD["archiveHashes"] = {str(p): digest(p) for p in (WORK / "root-build/distributions").iterdir() if p.is_file()}
        RECORD["finalSourceHashes"] = source_hashes()
        if RECORD["sourceHashes"] != RECORD["finalSourceHashes"]: raise RuntimeError("source changed during qualification")
        RECORD.update(status="passed", phase="complete")
    except BaseException as failure:
        RECORD.update(status="failed", failure=repr(failure))
        raise
    finally:
        cleanup = RECORD.setdefault("cleanupFailures", [])
        for child in list(ACTIVE):
            try: child.close()
            except BaseException as failure: cleanup.append(repr(failure))
        if cleanup: RECORD.update(status="failed", cleanupFailures=cleanup)
        RECORD["finalOwnedSourceHashes"] = {p: digest(ROOT / p) for p in OWNED_SOURCES if (ROOT / p).exists()}
        save_record()
        print(json.dumps({"status": RECORD["status"], "phase": RECORD["phase"], "record": str(WORK / "qualification.json")}))
        if cleanup and "failure" not in RECORD: raise RuntimeError("process cleanup failed: " + repr(cleanup))


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    try: main()
    except BaseException as failure:
        print(f"atomic-install qualification failed: {failure}", file=sys.stderr)
        sys.exit(130 if isinstance(failure, KeyboardInterrupt) else 1)
