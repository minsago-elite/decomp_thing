#!/usr/bin/env python3
"""Exercise CI Gradle dependency resolution against a loopback plugin repository."""
import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ("fixture", "archival-plugin", "1.0")
MARKER = ("fixture.archival", "fixture.archival.gradle.plugin", "1.0")
BOM = ("org.jetbrains.kotlin", "kotlin-gradle-plugins-bom", "2.4.0")
API = ("org.jetbrains.kotlin", "kotlin-gradle-plugin-api", "2.4.0")


def coordinate(group, artifact, version=None):
    xml = f"<groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
    return xml + (f"<version>{version}</version>" if version else "")


def path_for(module, extension):
    group, artifact, version = module
    return f"{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.{extension}"


def pom(module, contents=""):
    return ("<project><modelVersion>4.0.0</modelVersion>" + coordinate(*module) + contents + "</project>").encode()


def jar(files=()):
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for name, content in files:
            archive.writestr(name, content)
    return buffer.getvalue()


def fixture():
    def dependency(module, properties=""):
        return "<dependency>" + coordinate(*module) + properties + "</dependency>"

    def dependencies(modules):
        return "<dependencies>" + modules + "</dependencies>"

    def management(modules):
        return "<dependencyManagement>" + dependencies(modules) + "</dependencyManagement>"

    return {
        path_for(MARKER, "pom"): pom(MARKER, "<packaging>pom</packaging>" + dependencies(dependency(PLUGIN))),
        path_for(PLUGIN, "pom"): pom(PLUGIN, management(dependency(BOM, "<type>pom</type><scope>import</scope>"))
                                    + dependencies(dependency(API[:2]))),
        path_for(PLUGIN, "jar"): jar([("META-INF/gradle-plugins/fixture.archival.properties",
                                        "implementation-class=org.gradle.api.plugins.JavaPlugin\n")]),
        path_for(BOM, "pom"): pom(BOM, "<packaging>pom</packaging>" + management(dependency(API))),
        path_for(API, "pom"): pom(API),
        path_for(API, "jar"): jar(),
    }


@contextmanager
def serve(scenario, artifacts, statuses):
    class Handler(BaseHTTPRequestHandler):
        def respond(self, send_body):
            # A distinct repository URL per case keeps Gradle's negative-result cache isolated.
            key = self.path.removeprefix(f"/{scenario}/")
            data = artifacts.get(key)
            status = 404 if data is None else 200
            if key == path_for(BOM, "pom"):
                if scenario == "persistent" or (scenario == "recover" and len(statuses) < 3):
                    status = 429
                elif scenario in ("401", "403", "404"):
                    status = int(scenario)
                elif scenario == "malformed":
                    data = b"<project><broken>"
                statuses.append((self.command, status))
            body = data if status == 200 else b""
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if send_body:
                self.wfile.write(body)

        def do_GET(self):
            self.respond(True)

        def do_HEAD(self):
            self.respond(False)

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/{scenario}/"
        finally:
            server.shutdown()
            thread.join()


def archival_command(gradle):
    # Exercise the same timeout, resolver options and single task invocation as Docker.
    joined = (ROOT / "Dockerfile").read_text().replace(chr(92) + "\n", " ")
    prefix = "RUN --mount=type=cache,target=/root/.gradle "
    line, = [line for line in joined.splitlines() if line.startswith(prefix)]
    argv = shlex.split(line.removeprefix(prefix))
    argv[argv.index("./gradlew")] = str(gradle)
    if argv[-1] != "installDist":
        raise ValueError("expected the archival installDist task")
    return argv


def packaged_command(gradle):
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    # Join shell continuations so the later archive/evidence commands stay outside the Gradle invocation.
    lines = workflow.replace(chr(92) + "\n", " ").splitlines()
    line, = (line.strip() for line in lines if line.lstrip().startswith("./gradlew ")
             and "decompengine.web.BrowserSessionExpiryTest" in line)
    argv = shlex.split(line)
    argv[0] = str(gradle)
    return argv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradle", type=Path, default=ROOT / "gradlew", help="pinned Gradle wrapper or distribution executable")
    parser.add_argument("--target", choices=("archival", "builtin", "packaged"), default="archival")
    args = parser.parse_args()
    gradle = args.gradle.resolve()
    builtin = args.target == "builtin"
    packaged = args.target == "packaged"
    if builtin:
        command = [sys.executable, "scripts/validate-builtin-contract.py"]
    elif packaged:
        command = packaged_command(gradle)
    else:
        command = archival_command(gradle)
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    with TemporaryDirectory(prefix="archival-gradle-", dir=build) as work:
        base = Path(work)
        tmp = base / "tmp"
        tmp.mkdir()
        wrapper_cache = base / "wrapper"
        wrapper_cache.mkdir()
        env = {**os.environ, "TMPDIR": str(tmp),
               "JAVA_TOOL_OPTIONS": os.environ.get("JAVA_TOOL_OPTIONS", "") + f" -XX:-UsePerfData -Djava.io.tmpdir={tmp}"}
        artifacts = fixture()
        cases = {"recover": [429, 429, 429, 200], "persistent": [429] * 5,
                 "401": [401], "403": [403], "404": [404], "malformed": [200], "task-failure": [200]}
        for scenario, expected in cases.items():
            project = base / scenario
            project.mkdir()
            if builtin:
                (project / "scripts").mkdir()
                shutil.copyfile(ROOT / "scripts/validate-builtin-contract.py", project / "scripts/validate-builtin-contract.py")
                (project / "gradlew").symlink_to(gradle)
            if builtin or packaged:
                test_sources = project / "src/test/java"
                test_sources.mkdir(parents=True)
                (test_sources / "FixtureProbe.java").write_text("class FixtureProbe {}\n")
            # Share only the pinned wrapper distribution. Each scenario must fetch its own metadata.
            gradle_home = base / f"gradle-{scenario}"
            gradle_home.mkdir()
            (gradle_home / "wrapper").symlink_to(wrapper_cache, target_is_directory=True)
            statuses = []
            with serve(scenario, artifacts, statuses) as url:
                (project / "settings.gradle").write_text(f"""pluginManagement {{
    repositories {{ maven {{ url = uri('{url}'); allowInsecureProtocol = true }} }}
}}
rootProject.name = 'archival-resolver-control'
""")
                task = "tasks.named('test') {\n    filter { failOnNoMatchingTests = false }" if builtin or packaged else "tasks.register('installDist') {"
                (project / "build.gradle").write_text("plugins { id 'fixture.archival' version '1.0' }\n" + task + """
    doLast {
        file('task-runs').append('ran\\n')
        if (projectDir.name == 'task-failure') {
            throw new GradleException('injected archival task failure')
        }
    }
}
""")
                if packaged:
                    # The fixture applies the Java plugin. Supply the packaging tasks that exist in the real project.
                    tasks = ("installDist", "distZip", "distTar", "verifyPackagedWeb", "verifyGhidraDistributionArchives",
                             "verifyAcpGateHelperDistribution", "verifyLlvmBehaviorHelperDistribution",
                             "verifyKotlinBootClasspathDistribution")
                    with (project / "build.gradle").open("a") as script:
                        for name in tasks:
                            script.write(f"tasks.register('{name}')\n")
                result = subprocess.run(command, cwd=project, env={**env, "GRADLE_USER_HOME": str(gradle_home)},
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, timeout=150)
            ran = project / "task-runs"
            runs = ran.read_text().splitlines() if ran.exists() else []
            gradle_exit = result.returncode
            if builtin:
                # The fixture has no real contract suites. Even a successful Gradle invocation must fail validation.
                verdict = json.loads((project / "build/builtin-contract-qualification/summary.json").read_text())
                if result.returncode != 1 or verdict["passed"] or not any(reason.startswith("Missing suite:") for reason in verdict["failures"]):
                    raise AssertionError(f"{scenario}: builtin validator did not refuse the absent suite inventory")
                gradle_exit = verdict["gradleExitCode"]
            if ((gradle_exit == 0) != (scenario == "recover")
                    or statuses != [("GET", code) for code in expected]
                    or runs != (["ran"] if scenario in ("recover", "task-failure") else [])):
                raise RuntimeError(f"{scenario}: exit {result.returncode}, BOM {statuses}, task runs {runs}\n{result.stdout[-3500:]}")
            print(f"{scenario}: BOM {statuses}, {args.target} task ran {len(runs)} time(s), Gradle exit {gradle_exit}", flush=True)


if __name__ == "__main__":
    main()
