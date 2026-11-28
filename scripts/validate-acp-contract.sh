#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if (($# != 0)); then
  echo "usage: scripts/validate-acp-contract.sh" >&2
  exit 64
fi
: "${DECOMP_TEST_ACP_QUOTA_TMPFS:?provision the dedicated finite ACP quota fixture first}"
export DECOMP_REQUIRE_LIVE_ACP_CONTRACT=1
# The full oracle CI role owns GCC planning's isolated JVM. This qualifier's
# required inventory below covers ACP and shared-agent suites only.
gradle_status=0
./gradlew --no-daemon test --tests 'decompengine.acp.*' --tests 'decompengine.agent.*' \
  --exclude-task :gccCompilerEnginePlanningIsolated || gradle_status=$?
# A failed test run still owns useful failure XML. Retain its summary without
# allowing report validation to turn a failed Gradle invocation into success.
export ACP_QUALIFICATION_GRADLE_EXIT_CODE="$gradle_status"

report_status=0
python3 - <<'PY' || report_status=$?
import json
import os
import pathlib
import subprocess
import xml.etree.ElementTree as ET

reports = pathlib.Path('build/test-results/test')
expected = {
    'AcpAgentHarnessTest', 'AcpCapturedRepairFilesystemTest', 'AcpDoctorPreflightTest',
    'AcpExecutionSchedulerTest', 'AcpFilesystemBrokerTest', 'AcpGateHelperArtifactTest',
    'AcpHarnessFactoryTest', 'AcpLiveContractHostTest', 'AcpOperatorSurfaceContractTest',
    'AcpPermissionPolicyTest', 'AcpSandboxPolicyTest', 'AcpTerminalBrokerTest',
    'AcpV1WireContractGoldenTest', 'LinuxBoundedSessionProcessTest',
    'LinuxBubblewrapBoundaryTest', 'LinuxFilesystemSyscallsTest',
    'MvpPatchAcpIntegrationTest', 'PinnedSystemdBusEndpointTest', 'AgentExecutionContractTest',
    'AgentSessionJournalTest', 'CandidateValidationMountPolicyTest',
    'AcpThoughtProjectionTest', 'AcpContextUsageProjectionTest',
    'AcpCurrentConfigInventoryTest',
}
suites = []
for path in sorted(reports.glob('TEST-*.xml')):
    suite = ET.parse(path).getroot()
    name = suite.attrib['name']
    if not name.startswith(('decompengine.acp.', 'decompengine.agent.')):
        raise SystemExit(f'unexpected test report in ACP qualification: {name}')
    suites.append({'name': name, **{
        field: int(suite.attrib.get(field, 0))
        for field in ('tests', 'failures', 'errors', 'skipped')
    }})
missing = sorted(expected - {suite['name'].rsplit('.', 1)[-1] for suite in suites if suite['tests'] > 0})
totals = {field: sum(suite[field] for suite in suites) for field in ('tests', 'failures', 'errors', 'skipped')}
record = {
    'schemaVersion': 1,
    'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'requiredLiveHost': True,
    'gradleExitCode': int(os.environ['ACP_QUALIFICATION_GRADLE_EXIT_CODE']),
    'totals': totals,
    'missingRequiredSuites': missing,
    'suites': suites,
    'realAgentQualified': False,
    'releaseQualified': False,
}
output = pathlib.Path('build/acp-contract-qualification')
output.mkdir(parents=True, exist_ok=True)
(output / 'summary.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'totals': totals, 'missingRequiredSuites': missing}))
if missing or totals['tests'] == 0 or any(totals[field] for field in ('failures', 'errors', 'skipped')):
    raise SystemExit('required ACP contract qualification has missing, failed or skipped tests')
if record['gradleExitCode'] != 0:
    raise SystemExit('ACP Gradle invocation failed; retained reports do not qualify this run')
PY

if ((gradle_status != 0)); then
  exit "$gradle_status"
fi
exit "$report_status"
