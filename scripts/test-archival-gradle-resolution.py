#!/usr/bin/env python3
"""Exercise CI Gradle dependency resolution against a loopback plugin repository.

The archival target also checks that the jittered retry window of the image build's
install script stays within its documented bounds (#2013).
"""
import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
import os
from pathlib import Path
import re
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
INSTALL = ROOT / "scripts/archival-gradle-install.sh"
# Scaled-down initial backoff for loopback controls; the tentative count is the real one.
CONTROL_BACKOFF_MS = "100"
# The documented minimum per-resource window for riding out HTTP 429 throttling.
MINIMUM_WINDOW_MS = 300_000


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


def install_constants():
    text = INSTALL.read_text()
    values = {name: int(re.search(rf"^{name}=(\d+)$", text, re.M).group(1))
              for name in ("MAX_TENTATIVES", "BACKOFF_FLOOR_MS", "BACKOFF_JITTER_MS")}
    if not text.rstrip().endswith("installDist"):
        raise ValueError("expected the archival installDist task")
    return values


def archival_command():
    # The image build runs this script as its one installDist step; check that wiring first.
    dockerfile = re.sub(r"\s*\\\n\s*", " ", (ROOT / "Dockerfile").read_text())
    run = "RUN --mount=type=cache,target=/root/.gradle sh scripts/archival-gradle-install.sh"
    if not re.search(re.escape(run) + r"\s*\n", dockerfile):
        raise ValueError("Dockerfile no longer runs the archival install script")
    return ["sh", str(INSTALL)]


def window_controls(base, env):
    constants = install_constants()
    tentatives, floor, jitter = (constants[k] for k in ("MAX_TENTATIVES", "BACKOFF_FLOOR_MS", "BACKOFF_JITTER_MS"))
    shortest = floor * (2 ** (tentatives - 1) - 1)
    if shortest < MINIMUM_WINDOW_MS:
        raise AssertionError(f"retry window {shortest} ms is below the documented {MINIMUM_WINDOW_MS} ms")
    stub = base / "print-gradle-arguments"
    stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    stub.chmod(0o755)
    picks = set()
    env = {key: value for key, value in env.items() if key != "ARCHIVAL_GRADLE_INITIAL_BACKOFF_MS"}
    for _ in range(6):
        result = subprocess.run(archival_command(), cwd=base, text=True, capture_output=True,
                                env={**env, "ARCHIVAL_GRADLEW": str(stub)}, timeout=20, check=True)
        flags = dict(line.removeprefix("-D").split("=", 1) for line in result.stdout.splitlines() if line.startswith("-D"))
        picks.add(int(flags["org.gradle.internal.repository.initial.backoff"]))
        if int(flags["org.gradle.internal.repository.max.tentatives"]) != tentatives:
            raise AssertionError(f"tentatives flag differs: {flags}")
    if not all(floor <= pick < floor + jitter for pick in picks) or len(picks) < 2:
        raise AssertionError(f"initial backoff picks {sorted(picks)} are not jittered within [{floor}, {floor + jitter})")
    print(f"window: {tentatives} tentatives, jittered initial backoff {sorted(picks)} ms, "
          f"at least {shortest // 1000} s per throttled resource", flush=True)
    return tentatives


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradle", type=Path, default=ROOT / "gradlew", help="pinned Gradle wrapper or distribution executable")
    parser.add_argument("--target", choices=("archival", "builtin"), default="archival")
    args = parser.parse_args()
    gradle = args.gradle.resolve()
    builtin = args.target == "builtin"
    command = [sys.executable, "scripts/validate-builtin-contract.py"] if builtin else archival_command()
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    with TemporaryDirectory(prefix="archival-gradle-", dir=build) as work:
        base = Path(work)
        tmp = base / "tmp"
        tmp.mkdir()
        wrapper_cache = base / "wrapper"
        wrapper_cache.mkdir()
        env = {**os.environ, "TMPDIR": str(tmp), "ARCHIVAL_GRADLEW": str(gradle),
               "ARCHIVAL_GRADLE_INITIAL_BACKOFF_MS": CONTROL_BACKOFF_MS,
               "JAVA_TOOL_OPTIONS": os.environ.get("JAVA_TOOL_OPTIONS", "") + f" -XX:-UsePerfData -Djava.io.tmpdir={tmp}"}
        # A host read-only dependency cache would let scenarios skip the loopback repository.
        env.pop("GRADLE_RO_DEP_CACHE", None)
        tentatives = 5 if builtin else window_controls(base, env)
        artifacts = fixture()
        cases = {"recover": [429, 429, 429, 200], "persistent": [429] * tentatives,
                 "401": [401], "403": [403], "404": [404], "malformed": [200], "task-failure": [200]}
        for scenario, expected in cases.items():
            project = base / scenario
            project.mkdir()
            if builtin:
                (project / "scripts").mkdir()
                shutil.copyfile(ROOT / "scripts/validate-builtin-contract.py", project / "scripts/validate-builtin-contract.py")
                (project / "gradlew").symlink_to(gradle)
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
                task = "tasks.named('test') {\n    filter { failOnNoMatchingTests = false }" if builtin else "tasks.register('installDist') {"
                (project / "build.gradle").write_text("plugins { id 'fixture.archival' version '1.0' }\n" + task + """
    doLast {
        file('task-runs').append('ran\\n')
        if (projectDir.name == 'task-failure') {
            throw new GradleException('injected archival task failure')
        }
    }
}
""")
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
