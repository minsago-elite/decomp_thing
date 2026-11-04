#!/usr/bin/env python3
"""Inert driver controls; --gradle-writers adds only the publisher task, never product compilation."""
import importlib.util, json, os, pathlib, shlex, signal, subprocess, sys, tempfile, time, unittest.mock, zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("atomic_driver", ROOT / "scripts/test-atomic-install.py")
driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
PYTHON = os.environ.get("ATOMIC_CONTROL_PYTHON", "/usr/bin/python3.14" if pathlib.Path("/usr/bin/python3.14").exists() else sys.executable)
BASE = ROOT / "build/orchestration/atomic-install-remediation"
BASE.mkdir(parents=True, exist_ok=True)
WORK = pathlib.Path(tempfile.mkdtemp(prefix="driver-controls-", dir=BASE))
driver.WORK = WORK
driver.INIT = WORK / "atomic-install.init.gradle"
for path in (WORK / "tmp", WORK / "home", WORK / "barriers", driver.install_root() / "bin", driver.install_root() / "lib"):
    path.mkdir(parents=True, exist_ok=True)
passed = []


def check_failure(name, action, expected):
    try: action()
    except expected: pass
    else: raise AssertionError(name + " did not fail")
    assert not driver.ACTIVE, name + " leaked an owned child"
    passed.append(name)


def check_dead(pid):
    # A child process started with this launcher must have been reaped, not merely signaled.
    try: os.waitpid(pid, os.WNOHANG)
    except ChildProcessError: return
    raise AssertionError("child is still waitable")


def wait_file(path, child, timeout=90):
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        if child.process.poll() is not None: raise AssertionError(child.text())
        time.sleep(.05)
    assert path.exists(), str(path)


try:
    # Explicit and PATH-derived real executable homes; launcher option JSON/path roundtrip.
    jdk = WORK / "jdk with spaces"; (jdk / "bin").mkdir(parents=True)
    java = jdk / "bin/java"; java.write_text("#!/bin/sh\nexit 0\n"); java.chmod(0o755)
    (jdk / "release").write_text('JAVA_VERSION="21.0.12"\n')
    with unittest.mock.patch.dict(os.environ, {"JAVA_HOME": str(jdk)}): assert driver.qualified_java_home() == jdk
    with unittest.mock.patch.dict(os.environ, {}, clear=True), unittest.mock.patch.object(driver.shutil, "which", return_value=str(java)):
        assert driver.qualified_java_home() == jdk
    args = ['-Djson=' + driver.MODEL, '-javaagent:/path with spaces/agent.jar', '-Dpath=apostrophe\' and "quotes"']
    # GNU xargs is the unmodified Gradle launcher's tokenizer.
    result = subprocess.run(["xargs", "-n1", "printf", "%s\\n"], input=shlex.join(args), text=True, capture_output=True, check=True)
    assert result.stdout.splitlines() == args
    passed.append("explicit/derived-JDK-home-and-launcher-quote-roundtrip")

    driver.write_init("A")
    init_text = driver.INIT.read_text()
    assert driver.install_root() == WORK / "root-build/install" / driver.APP
    assert "destinationDir = new File(" + driver.groovy_path(driver.install_root()) + ")" in init_text
    assert driver.groovy_path(ROOT / "build/frontend") in init_text
    assert driver.groovy_path(WORK / "root-build/frontend") in init_text
    assert 'outputs.upToDateWhen { false }' in init_text
    assert '"dist", "bundle-report.json", "bundle-composition.json"' in init_text
    passed.append("one-install-root-and-fresh-frontend-output-wiring")
    with unittest.mock.patch.object(driver, "qualified_java_home", return_value=jdk):
        with unittest.mock.patch.dict(os.environ, {"HOME": "/unchanged-home"}):
            assert driver.safe_env()["HOME"] == "/unchanged-home"
        with unittest.mock.patch.object(driver, "run", return_value=(0, "")) as run:
            driver.gradle("help")
            assert run.call_args.kwargs["timeout"] == driver.BUILD_TIMEOUT
    assert 120 < driver.BUILD_TIMEOUT < driver.RELEASE_TIMEOUT <= 3600
    assert driver.RELEASE_TIMEOUT >= driver.BUILD_TIMEOUT + driver.READY_TIMEOUT + driver.PROBE_FINISH_TIMEOUT + 60
    passed.append("original-home-and-whole-overlap-budget")
    events = []; held = [False]
    def no_update_install(generation):
        events.append("install-" + generation)
        if events.count("install-A") == 2: assert held[0], "no live JVM during reinstall"
    def no_update_launch(generation):
        events.append("launch-" + generation); held[0] = True
        return object(), WORK / "RELEASE", {}, WORK / "app.jar"
    def no_update_release(child, release, generation, expected):
        assert held[0] and expected == "unchanged"
        events.append("release-" + generation); held[0] = False
        return {"schemaVersion": "4", "lateResourceMarker": "A"}
    with unittest.mock.patch.object(driver, "install", side_effect=no_update_install), \
         unittest.mock.patch.object(driver, "launch_blocked", side_effect=no_update_launch), \
         unittest.mock.patch.object(driver, "protected_snapshot", return_value={"inode": 1}), \
         unittest.mock.patch.object(driver, "release_and_reap", side_effect=no_update_release):
        assert driver.live_no_update()["probe"]["schemaVersion"] == "4"
    assert events == ["install-A", "launch-A", "install-A", "release-A"]
    passed.append("live-no-update-orchestration-before-reinstall-and-late-load-after")

    child = driver.Child([PYTHON, "-c", "print('complete')"], log=WORK / "success.log")
    assert child.wait(10) == 0 and child.text() == "complete\n"
    check_dead(child.process.pid)
    passed.append("bounded-process-success-reaped")
    child = driver.Child([PYTHON, "-c", "import time; time.sleep(60)"], log=WORK / "timeout.log")
    check_failure("timeout-group-kill-reap", lambda: child.wait(.05), subprocess.TimeoutExpired)
    check_dead(child.process.pid)
    child = driver.Child([PYTHON, "-c", "import time; time.sleep(60)"], log=WORK / "interrupt.log")
    original_wait = child.process.wait
    calls = [0]
    def interrupt_once(*args, **kwargs):
        calls[0] += 1
        if calls[0] == 1: raise KeyboardInterrupt()
        return original_wait(*args, **kwargs)
    with unittest.mock.patch.object(child.process, "wait", side_effect=interrupt_once):
        check_failure("interrupt-group-kill-reap", lambda: child.wait(10), KeyboardInterrupt)
    check_dead(child.process.pid)
    old_limit = driver.MAX_LOG; driver.MAX_LOG = 4096
    child = driver.Child([PYTHON, "-c", "import os; os.write(1,b'x'*1000000)"], log=WORK / "overflow.log")
    check_failure("output-bound-group-kill-reap", lambda: child.wait(10), RuntimeError)
    assert child.log.stat().st_size <= driver.MAX_LOG and len(child.tail) <= 12000
    driver.MAX_LOG = old_limit
    # A descendant retains the output pipe after its parent exits. Cleanup kills the whole group.
    child = driver.Child([PYTHON, "-c", "import os,time; p=os.fork(); time.sleep(60) if p==0 else None"], log=WORK / "descendant.log")
    assert child.wait(10) == 0
    check_dead(child.process.pid)
    passed.append("descendant-pipe-group-cleanup")

    with zipfile.ZipFile(driver.install_root() / "lib/app.jar", "w") as archive: archive.writestr("decompengine/MainKt.class", b"fixture")
    launcher = driver.install_root() / "bin" / driver.APP
    launcher.write_text("#!" + PYTHON + "\nimport os,shlex,pathlib,time\n"
        "p=dict(x[2:].split('=',1) for x in shlex.split(os.environ['JAVA_OPTS']) if x.startswith('-D'))\n"
        "pathlib.Path(p['atomic.probe.ready']).write_text('malformed READY')\n"
        "time.sleep(60)\n")
    launcher.chmod(0o755)
    with unittest.mock.patch.object(driver, "qualified_java_home", return_value=jdk):
        check_failure("malformed-READY-local-ownership-cleanup", lambda: driver.launch_blocked("A"), json.JSONDecodeError)
        with unittest.mock.patch.object(driver, "read_evidence", side_effect=OSError("injected READY read failure")):
            check_failure("READY-read-failure-local-cleanup", lambda: driver.launch_blocked("A"), OSError)
        original_sleep = time.sleep
        interrupted = [False]
        def interrupt_sleep_once(seconds):
            if not interrupted[0]:
                interrupted[0] = True
                raise KeyboardInterrupt()
            return original_sleep(seconds)
        with unittest.mock.patch.object(driver.time, "sleep", side_effect=interrupt_sleep_once):
            check_failure("READY-interrupt-local-cleanup", lambda: driver.launch_blocked("A"), KeyboardInterrupt)
    assert len(list((WORK / "barriers").iterdir())) == 3
    passed.append("unique-barriers-per-attempt")

    if "--gradle-init" in sys.argv:
        project = WORK / "init-project"; project.mkdir()
        (project / "settings.gradle").write_text("rootProject.name = 'atomic-init-control'\n")
        (project / "build.gradle").write_text('''plugins { id 'application' }
application { applicationName = 'llm_bin_patch'; mainClass = 'unused.Main' }
tasks.register('frontendBuild') {
 outputs.dir(layout.buildDirectory.dir('frontend/dist'))
 outputs.files(layout.buildDirectory.file('frontend/bundle-report.json'), layout.buildDirectory.file('frontend/bundle-composition.json'))
 doLast {
  def produced = file('build/frontend')
  def countFile = file('producer-count')
  def count = countFile.exists() ? countFile.text.toInteger() + 1 : 1
  countFile.text = count.toString()
  new File(produced, 'dist').mkdirs()
  new File(produced, 'dist/current.js').text = 'fresh-' + count
  new File(produced, 'bundle-report.json').text = '{"fresh":' + count + '}'
  new File(produced, 'bundle-composition.json').text = '{"fresh":' + count + '}'
 }
}
tasks.register('verifyDriverInit') {
 dependsOn('frontendBuild')
 doLast {
  def actual = tasks.named('installDist').get().destinationDir
  def expected = layout.buildDirectory.dir('install/llm_bin_patch').get().asFile
  assert actual == expected
  def count = file('producer-count').text.toInteger()
  def consumed = layout.buildDirectory.dir('frontend').get().asFile
  assert new File(consumed, 'dist/current.js').text == 'fresh-' + count
  assert !new File(consumed, 'dist/stale.js').exists()
  ['bundle-report.json', 'bundle-composition.json'].each { name ->
   assert new File(consumed, name).text == '{"fresh":' + count + '}'
  }
  println('driver init producer/consumer/destination agreement: ' + count)
 }
}
''')
        with unittest.mock.patch.object(driver, "ROOT", project): driver.write_init("A")
        env = driver.safe_env(); env["JAVA_OPTS"] = shlex.join(driver.jvm_options())
        for iteration in (1, 2):
            consumed_dist = WORK / "root-build/frontend/dist"
            consumed_dist.mkdir(parents=True, exist_ok=True)
            (consumed_dist / "stale.js").write_text("stale")
            command = [ROOT / "gradlew", "--offline", "--no-daemon", "-g", env["GRADLE_USER_HOME"],
                       "-Dorg.gradle.jvmargs=" + shlex.join(driver.jvm_options()), "-p", project, "-I", driver.INIT, "verifyDriverInit"]
            _, output = driver.run(command, env=env, log=WORK / f"init-{iteration}.log", timeout=120)
            assert f"driver init producer/consumer/destination agreement: {iteration}" in output
        passed.append("real-Gradle-init-fresh-producer/copy/stale-removal/repeated-build/exact-install-destination")

    if "--gradle-writers" in sys.argv:
        destination = WORK / "shared-install"
        commands = []
        def writer(name, failure=False, released=False):
            folder = WORK / name; folder.mkdir()
            ready = folder / "READY"; release = folder / "RELEASE"
            if released: release.write_text("release")
            config = {"destination": str(destination), "ready": str(ready), "release": str(release), "failure": str(failure).lower()}
            init = folder / "writer.init.gradle"
            init.write_text("allprojects { p -> if (p == p.rootProject) { p.buildDir = new File(" + driver.groovy_path(folder / "build") + ")\n"
                "p.tasks.matching { it.name == 'verifyAtomicApplicationPublication' }.configureEach {\n"
                "ext.atomicWriterControl = [" + ",".join(driver.groovy_path(k)+":"+driver.groovy_path(v) for k,v in config.items()) + "]\n} } }\n")
            env = driver.safe_env(); env["JAVA_OPTS"] = shlex.join(driver.jvm_options())
            args = [ROOT / "gradlew", "--no-daemon", "--project-cache-dir", folder / "project-cache", "-g", env["GRADLE_USER_HOME"],
                    "-Dorg.gradle.jvmargs=" + shlex.join(driver.jvm_options()), "-I", init, "verifyAtomicApplicationPublication"]
            commands.append(list(map(str, args)))
            return driver.Child(args, env=env, log=folder / "gradle.log"), ready, release
        first, ready, release = writer("writer-one"); wait_file(ready, first)
        second, _, _ = writer("writer-two")
        assert second.wait(120) != 0 and "Another installDist writer holds" in second.text()
        release.write_text("release"); assert first.wait(120) == 0
        third, _, _ = writer("writer-after-success", released=True); assert third.wait(120) == 0
        failed, _, _ = writer("writer-task-failure", failure=True)
        assert failed.wait(120) != 0 and "injected writer task failure" in failed.text()
        after_failure, _, _ = writer("writer-after-failure", released=True); assert after_failure.wait(120) == 0
        cancelled, ready, _ = writer("writer-cancelled"); wait_file(ready, cancelled)
        cancelled.close(); check_dead(cancelled.process.pid)
        after_cancel, _, _ = writer("writer-after-cancel", released=True); assert after_cancel.wait(120) == 0
        assert len(list(destination.parent.glob(".install-*.lock"))) == 1
        passed.append("distinct-buildDir-production-service-contention/release/task-failure/process-cancel/reacquire")
        (WORK / "writer-commands.json").write_text(json.dumps(commands, indent=2))
    if "--java-agent" in sys.argv:
        # Synthetic Java fixtures exercise the exact agent mechanics only, NOT installed acceptance.
        java_home = driver.qualified_java_home()
        fixture = WORK / "java-fixture"; fixture.mkdir()
        budget_source = fixture / "AtomicInstallBudgetControl.java"
        budget_source.write_text('''package decompengine.install;
public class AtomicInstallBudgetControl {
 public static void main(String[] args) {
  long budget = Long.parseLong(args[0]) * 1_000_000_000L;
  long validUpdate = 121_000_000_000L;
  if (AtomicInstallProbeAgent.releaseWaitExpired(0, validUpdate, budget)) throw new AssertionError("valid long update expired");
  if (!AtomicInstallProbeAgent.releaseWaitExpired(0, budget, budget)) throw new AssertionError("deadline not enforced");
  long nearWrap = Long.MAX_VALUE - 1_000_000_000L;
  if (AtomicInstallProbeAgent.releaseWaitExpired(nearWrap, nearWrap + validUpdate, budget)) throw new AssertionError("signed wrap");
  if (!AtomicInstallProbeAgent.releaseWaitExpired(10, 9, budget)) throw new AssertionError("backward clock");
 }
}''')
        budget_classes = fixture / "budget-classes"; budget_classes.mkdir()
        driver.run([java_home / "bin/javac", "-J-XX:-UsePerfData", "-J-Djava.io.tmpdir=" + str(WORK / "tmp"),
                    "--release", "21", "-cp", driver.AGENT, "-d", budget_classes, budget_source],
                   env=driver.safe_env(), log=fixture / "budget-compile.log", timeout=30)
        driver.run([java_home / "bin/java", *driver.jvm_options(), "-cp", str(budget_classes) + os.pathsep + str(driver.AGENT),
                    "decompengine.install.AtomicInstallBudgetControl", str(driver.RELEASE_TIMEOUT)],
                   env=driver.safe_env(), log=fixture / "budget.log", timeout=10)
        passed.append("agent-clock-121-second-update/full-expiry/signed-wrap/backward-rejection")
        sources = fixture / "src"; sources.mkdir()
        classes = fixture / "classes"; classes.mkdir()
        (sources / "MainKt.java").write_text('package decompengine; public class MainKt { public static void main(String[] a) { throw new AssertionError("production main entered"); } }')
        model_literal = json.dumps(driver.MODEL)
        (sources / "ProgramModelJson.java").write_text('''package decompengine.project;
public class ProgramModelJson {
 public static final ProgramModelJson INSTANCE = new ProgramModelJson();
 public Model read(String json) { if (!json.equals(MODEL_LITERAL)) throw new IllegalArgumentException("JSON token changed"); return new Model(); }
 public static class Model { public int getSchemaVersion() { return 4; } public String getInputSha256() { return "a".repeat(64); } }
}'''.replace("MODEL_LITERAL", model_literal))
        driver.run([java_home / "bin/javac", "-J-Djava.io.tmpdir=" + str(WORK / "tmp"), "-J-XX:-UsePerfData", "--release", "21", "-d", classes,
                    sources / "MainKt.java", sources / "ProgramModelJson.java"], env=driver.safe_env(), log=fixture / "javac.log", timeout=30)
        jar = fixture / "app.jar"
        def write_jar(marker):
            stage = fixture / "app-stage.jar"
            with zipfile.ZipFile(stage, "w") as archive:
                for path in sorted(classes.rglob("*.class")): archive.write(path, path.relative_to(classes).as_posix())
                archive.writestr("atomic-install-generation.txt", marker)
            stage.replace(jar)
        def probe(marker):
            barrier = pathlib.Path(tempfile.mkdtemp(prefix="probe-", dir=fixture))
            ready = barrier / "READY"; release = barrier / "RELEASE"
            args = [java_home / "bin/java", *driver.jvm_options(), "-javaagent:" + str(driver.AGENT),
                    "-Datomic.probe.app=" + str(jar), "-Datomic.probe.ready=" + str(ready),
                    "-Datomic.probe.release=" + str(release), "-Datomic.probe.marker=" + marker,
                    "-Datomic.probe.releaseTimeoutSeconds=" + str(driver.RELEASE_TIMEOUT),
                    "-Datomic.probe.model=" + driver.MODEL, "-cp", jar, "decompengine.MainKt"]
            child = driver.Child(args, env=driver.safe_env(), log=barrier / "agent.log")
            child.probe = {"scope": "synthetic Java agent fixture", "root": str(barrier)}
            wait_file(ready, child, 15)
            evidence = driver.read_evidence(ready)
            assert evidence["modelAbsentBeforeReady"] == "true" and evidence["archiveMarker"] == marker
            assert evidence["releaseTimeoutSeconds"] == str(driver.RELEASE_TIMEOUT)
            return child, release, evidence
        observations = []
        for old, new in (("A", "B"), ("B", "A")):
            write_jar(old)
            child, release, ready = probe(old)
            write_jar(new); current_digest = driver.digest(jar)
            fresh, fresh_release, fresh_ready = probe(new)
            fresh_result = driver.release_and_reap(fresh, fresh_release, new)
            old_result = driver.release_and_reap(child, release, old)
            assert old_result["descriptorDigest"] == ready["descriptorDigest"] != current_digest
            assert old_result["installedPathDigestAfterRelease"] == fresh_result["descriptorDigest"] == current_digest
            observations.append({"from": old, "to": new, "old": old_result, "fresh": fresh_result})
        with zipfile.ZipFile(driver.AGENT) as archive:
            assert all(name.startswith(("META-INF/", "decompengine/install/")) for name in archive.namelist() if not name.endswith('/'))
        (fixture / "synthetic-agent-results.json").write_text(json.dumps(observations, indent=2))
        passed.append("synthetic-agent-A-B-A-late-loader-origin-resource-descriptor-JSON/no-product-main")
    record = {"status": "passed", "passed": passed, "sourceHashes": {p: driver.digest(ROOT/p) for p in driver.OWNED_SOURCES}}
except BaseException as failure:
    record = {"status": "failed", "passed": passed, "failure": repr(failure)}
    raise
finally:
    for child in list(driver.ACTIVE): child.close()
    (WORK / "controls.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"record": str(WORK / "controls.json"), **record}, indent=2))
