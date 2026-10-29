#!/usr/bin/env bash
# Isolated Gradle lifecycle regression; no application/native/compiler authority is exercised.
set -euo pipefail
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
mkdir -p "$project_root/build/task-tmp"
fixture="$(mktemp -d "$project_root/build/task-tmp/module-preflight.XXXXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/src/test/java" "$fixture/scripts" "$fixture/tmp"
export TMPDIR="$fixture/tmp"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$project_root/build/preflight-gradle-user-home}"
export JAVA_TOOL_OPTIONS="-XX:-UsePerfData -Djava.io.tmpdir=$TMPDIR -Djna.tmpdir=$TMPDIR"
printf "rootProject.name = 'module-preflight-regression'\n" > "$fixture/settings.gradle"
printf 'FixtureTest\n' > "$fixture/scripts/module-compilation-live-classes.txt"
cat > "$fixture/build.gradle" <<'GRADLE'
plugins { id 'java' }
repositories { mavenCentral() }
dependencies { testImplementation 'junit:junit:4.13.2' }
// Only the real init script's freshness/task lifecycle is under test. No native staging,
// compiled application inventory or installed-runtime test is substituted or credited.
tasks.register('generateAcpGateHelperChecksum')
tasks.register('stageOracleNativeLibraries')
gradle.projectsEvaluated {
    tasks.named('moduleCompilerLiveInventory') { actions.clear() }
    // The FD-policy child adds compiled deployment evidence. That remains mandatory
    // in production; this isolated fixture exercises only Test output preparation.
    tasks.named('moduleCompilerHostedCompiledEvidence') {
        setDependsOn([])
        actions.clear()
    }
    tasks.named('moduleCompilationLiveQualification', Test) {
        useJUnit()
        maxHeapSize = '128m'
    }
}
GRADLE
cat > "$fixture/src/test/java/FixtureTest.java" <<'JAVA'
public class FixtureTest {
    @org.junit.Test public void executesAfterOutputPreparation() {
        org.junit.Assert.assertTrue(true);
    }
}
JAVA
run_fixture() {
    "$project_root/gradlew" --no-daemon --console=plain --max-workers=1 \
        -Dorg.gradle.vfs.watch=false -Dorg.gradle.jvmargs="-Xmx256m -Djava.io.tmpdir=$TMPDIR" \
        --project-dir "$fixture" -I "$project_root/scripts/module-compilation-qualification.init.gradle" \
        moduleCompilationLiveQualification
}
if ! run_fixture > "$fixture/fresh.log" 2>&1; then
    cat "$fixture/fresh.log" >&2
    exit 1
fi
reports="$fixture/build/test-results/moduleCompilationLiveQualification"
python3 - "$reports/TEST-FixtureTest.xml" <<'PYTHON'
import sys
import xml.etree.ElementTree as ET
suite = ET.parse(sys.argv[1]).getroot()
assert {key: suite.attrib[key] for key in ('tests', 'failures', 'errors', 'skipped')} == {
    'tests': '1', 'failures': '0', 'errors': '0', 'skipped': '0'}
assert [test.attrib['name'] for test in suite.findall('testcase')] == ['executesAfterOutputPreparation']
PYTHON
report_sha="$(sha256sum "$reports/TEST-FixtureTest.xml")"
if run_fixture > "$fixture/stale.log" 2>&1; then
    echo 'preflight incorrectly admitted existing test reports' >&2; exit 1
fi
grep -q 'refusing existing hosted compiler test reports' "$fixture/stale.log"
[[ "$(sha256sum "$reports/TEST-FixtureTest.xml")" == "$report_sha" ]]
# Empty preexisting directories must still refuse; Gradle must not erase the evidence
# that a prior attempt prepared the output, even if it did not finish writing XML.
mv "$reports" "$fixture/retained-reports"
mkdir "$reports"
if run_fixture > "$fixture/empty.log" 2>&1; then
    echo 'preflight incorrectly admitted an existing empty report directory' >&2; exit 1
fi
grep -q 'refusing existing hosted compiler test reports' "$fixture/empty.log"
# A dangling report symlink is still preexisting state. Neither Gradle nor the
# preflight may follow it and create reports at its target.
rmdir "$reports"
ln -s "$fixture/missing-report-target" "$reports"
if run_fixture > "$fixture/symlink.log" 2>&1; then
    echo 'preflight incorrectly admitted a dangling report symlink' >&2; exit 1
fi
grep -q 'refusing existing hosted compiler test reports' "$fixture/symlink.log"
[[ -L "$reports" && ! -e "$fixture/missing-report-target" ]]
echo 'module compiler preflight: fresh execution, stale XML preservation, empty-directory and dangling-symlink refusal passed'
