#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if (($# != 0)); then
  echo "usage: scripts/validate-acp-contract.sh" >&2
  exit 64
fi
: "${ORG_GRADLE_PROJECT_ciAcpFixtureJdkHome:?invoke through scripts/ci-owned-jdk.py run --}"
: "${ORG_GRADLE_PROJECT_ciAcpFixtureJdkReceipt:?owned Test JVM receipt is required}"
: "${DECOMP_TEST_ACP_QUOTA_TMPFS:?provision the dedicated finite ACP quota fixture first}"
export DECOMP_REQUIRE_LIVE_ACP_CONTRACT=1
export DECOMP_REQUIRE_NATIVE_PROVIDER_DNS=1
export DECOMP_ACP_CONTRACT_RUN_ID="$(python3 -B -c 'import uuid; print(uuid.uuid4())')"
# The full oracle CI role owns GCC planning's isolated JVM. This qualifier's
# required inventory below covers ACP and shared-agent suites only.
./gradlew --no-daemon test --tests 'decompengine.acp.*' --tests 'decompengine.agent.*' \
  --exclude-task :gccCompilerEnginePlanningIsolated
./gradlew --no-daemon verifyProviderDnsNativeQualification

python3 -B - <<'PY'
import hashlib
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
    'AcpProviderDnsProcessTest', 'AcpProviderDnsRuntimeContextTest', 'AcpProviderNativeDnsContractTest',
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
native_path = pathlib.Path('build/provider-dns-native-qualification/gate-summary.json')
native_bytes = native_path.read_bytes()
native_summary = json.loads(native_bytes)
record = {
    'schemaVersion': 1,
    'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'requiredLiveHost': True,
    'requiredNativeProviderDns': True,
    'nativeProviderDnsRunId': os.environ['DECOMP_ACP_CONTRACT_RUN_ID'],
    'nativeProviderDnsSummarySha256': hashlib.sha256(native_bytes).hexdigest(),
    'nativeProviderDnsSummary': native_summary,
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
PY
