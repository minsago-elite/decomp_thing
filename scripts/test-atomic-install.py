#!/usr/bin/env python3
"""Separate completed-build, real installed-launcher qualification for #1834.

Run only after all source owners have stopped editing. Publisher/driver controls are
separate gates; this driver never describes a mixed installation as a snapshot.
"""
from __future__ import annotations
import hashlib, json, os, pathlib, re, shlex, shutil, signal, subprocess, sys, tempfile, threading, time, zipfile

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


def digest(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()


def source_hashes():
    # Include dirty product/test/build sources, not just the committed HEAD.
    names = set(subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT).decode().split("\0"))
    names.update(OWNED_SOURCES)
    return {name: digest(ROOT / name) for name in sorted(names) if name and
            (name.startswith(("src/", "scripts/", "frontend/", "ghidra-bridge/")) or name.endswith((".gradle.kts", ".properties")))
            and (ROOT / name).is_file() and not (ROOT / name).is_symlink()}


def save_record():
    WORK.mkdir(parents=True, exist_ok=True)
    target = WORK / "qualification.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(RECORD, indent=2) + "\n")
    temporary.replace(target)


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
            self.close()
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
            self.close()

    def text(self): return self.tail.decode("utf-8", errors="replace")


def run(args, *, env=None, timeout=900, log=None, allow_failure=False):
    command = {"args": list(map(str, args)), "phase": RECORD["phase"], "status": "running"}
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
        if child is not None: child.close()
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


def write_init(generation, fail_before_rename=False):
    gen = WORK / "markers" / generation
    gen.mkdir(parents=True, exist_ok=True)
    (gen / "atomic-install-generation.txt").write_text(generation)
    text = f'''allprojects {{ p -> if (p == p.rootProject) {{
p.buildDir = new File({groovy_path(WORK / "root-build")})
p.afterEvaluate {{
p.tasks.matching {{ it.name == "frontendBuild" }}.configureEach {{
    // Vite writes to the repository's normal build/frontend path. Only copy
    // after a successful fresh build; never seed from a historical bundle.
    outputs.upToDateWhen {{ false }}
    doLast {{
        def produced = new File({groovy_path(ROOT / "build/frontend")})
        def consumed = new File({groovy_path(WORK / "root-build/frontend")})
        ["dist", "bundle-report.json", "bundle-composition.json"].each {{ name ->
            def source = new File(produced, name)
            if (!source.exists()) throw new GradleException("Missing fresh frontend output: " + name)
            p.delete(new File(consumed, name))
            p.copy {{ from(source); into(name == "dist" ? new File(consumed, name) : consumed) }}
        }}
    }}
}}
p.tasks.matching {{ it.name == "jar" }}.configureEach {{ from(new File({groovy_path(gen)})) }}
p.tasks.matching {{ it.name == "installDist" }}.configureEach {{
    destinationDir = new File({groovy_path(install_root())})
'''
    if fail_before_rename:
        text += '''    ext.atomicInstallTestEvent = { phase, path ->
        if (phase == "before-rename") throw new IllegalStateException("atomic-probe injected before first rename")
    } as java.util.function.BiConsumer
'''
    INIT.write_text(text + "}\n} } }\n")


def install(generation, *, fail=False):
    write_init(generation, fail)
    log = WORK / f"install-{generation}-{time.monotonic_ns()}.log"
    code, output = gradle("-I", INIT, "installDist", log=log, allow_failure=fail)
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
    paths = list((install_root() / "lib").glob("*.jar")) + list((install_root() / "lib").glob("*reference-v1.json"))
    paths += [install_root() / "bin" / APP, install_root() / "bin" / (APP + ".bat")]
    return {str(p.relative_to(WORK)): {"sha256": digest(p), "key": statkey(p), "mode": p.stat().st_mode & 0o777}
            for p in paths}


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
        probe.update(status="ready", ready=data)
        return child, release, data, jar  # Ownership transfers only here.
    except BaseException as failure:
        probe.update(status="failed", failure=repr(failure))
        if child is not None: child.close()
        raise
    finally: save_record()


def release_and_reap(child, release, generation, expected="changed"):
    try:
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
        child.close()
        save_record()


def set_phase(phase):
    RECORD["phase"] = phase; save_record()


def live_no_update():
    install("A")
    initial = protected_snapshot()
    child, release, ready, jar = launch_blocked("A")
    install("A")
    if protected_snapshot() != initial:
        raise RuntimeError("no-update install changed protected bytes/inodes/modes")
    result = release_and_reap(child, release, "A", "unchanged")
    return {"status": "passed", "probe": result, "protectedUnchanged": True}


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
        gradle("atomicInstallProbeAgentJar", log=WORK / "agent-build.log")
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
        cleanup = []
        for child in list(ACTIVE):
            try: child.close()
            except BaseException as failure: cleanup.append(repr(failure))
        if cleanup: RECORD.update(status="failed", cleanupFailures=cleanup)
        RECORD["finalOwnedSourceHashes"] = {p: digest(ROOT / p) for p in OWNED_SOURCES if (ROOT / p).exists()}
        save_record()
        print(json.dumps({"status": RECORD["status"], "phase": RECORD["phase"], "record": str(WORK / "qualification.json")}))
        if cleanup: raise RuntimeError("process cleanup failed: " + repr(cleanup))


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    try: main()
    except BaseException as failure:
        print(f"atomic-install qualification failed: {failure}", file=sys.stderr)
        sys.exit(130 if isinstance(failure, KeyboardInterrupt) else 1)
