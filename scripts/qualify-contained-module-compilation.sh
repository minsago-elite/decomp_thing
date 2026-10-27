#!/usr/bin/env bash
set -euo pipefail
if (($#)); then echo "usage: $0" >&2; exit 64; fi
: "${GITHUB_RUN_ID:?explicit hosted qualification run is required}"
: "${GITHUB_RUN_ATTEMPT:?hosted qualification attempt identity is required}"
: "${DECOMP_TEST_MODULE_COMPILE_EXT4_SCRATCH:?existing module compiler ext4 helper must run first}"
: "${DECOMP_TEST_ORACLE_EXT4_SCRATCH:?existing terminal proof ext4 helper must run first}"
project_root="$(pwd -P)"
qualification_root="$project_root/build/module-compilation-qualification"
qualification_identity="${GITHUB_RUN_ID}.${GITHUB_RUN_ATTEMPT}.module"
case_directory="$project_root/build/reports/contained-module-compilation-live/cases"
if [[ -e "$project_root/build/test-results/moduleCompilationLiveQualification" || -L "$project_root/build/test-results/moduleCompilationLiveQualification" || -e "$qualification_root/compiled-live-tests.json" || -L "$qualification_root/compiled-live-tests.json" || -e "$case_directory" || -L "$case_directory" ]]; then
  echo "refusing to reuse compiler qualification inventory or reports" >&2; exit 1
fi
mkdir -p "$qualification_root/tmp" "$qualification_root/cache" "$qualification_root/home"
export TMPDIR="$qualification_root/tmp" XDG_CACHE_HOME="$qualification_root/cache"
export JAVA_TOOL_OPTIONS="-XX:-UsePerfData -Djava.io.tmpdir=$TMPDIR -Djna.tmpdir=$TMPDIR -Duser.home=$qualification_root/home"
init="$project_root/scripts/module-compilation-qualification.init.gradle"
provisioned=false
phase=initialization
gradle_status=not-started
xml_status=not-started
required_acp_status=not-started
case_status=not-started
cleanup_status=not-started
case_index_initialized=false
cleanup() {
  if [[ "$provisioned" == true ]]; then
    provisioned=false
    cleanup_status=0
    sudo -n python3 scripts/ci-prepare-generated-c-validation.py cleanup --run-id "$qualification_identity" \
      > "$qualification_root/operator-cleanup.stdout" 2> "$qualification_root/operator-cleanup.stderr" || cleanup_status=$?
  fi
}
finish() {
  local original_status=$?
  trap - EXIT
  set +e
  if [[ "$case_index_initialized" == true ]]; then
    python3 scripts/reconcile-module-compilation-hosted-cases.py finalize \
      --directory "$case_directory" \
      --inventory "$qualification_root/compiled-live-tests.json" \
      --reports "$project_root/build/test-results/moduleCompilationLiveQualification" \
      --gradle-exit-code "$gradle_status" --phase "$phase" \
      > "$qualification_root/case-reconciliation.stdout" 2> "$qualification_root/case-reconciliation.stderr"
    case_status=$?
  fi
  cleanup
  local final_status=$original_status
  if [[ "$final_status" == 0 && "$case_status" != 0 ]]; then final_status=1; fi
  if [[ "$final_status" == 0 && "$cleanup_status" != 0 ]]; then final_status=1; fi
  python3 - "$qualification_root/qualification-exit.json" "$phase" "$original_status" \
    "$gradle_status" "$xml_status" "$required_acp_status" "$case_status" "$cleanup_status" "$final_status" <<'PYTHON'
import json
import sys
from pathlib import Path
path, phase, original, gradle, xml, required_acp, cases, cleanup, final = sys.argv[1:]
def status(value):
    return None if value == 'not-started' else int(value)
record = {'schemaVersion': 1, 'provider': 'contained-module-hosted-exit-v1', 'phase': phase,
          'originalExitCode': int(original), 'gradleExitCode': status(gradle),
          'xmlVerificationExitCode': status(xml), 'caseReconciliationExitCode': status(cases),
          'requiredAcpInventoryExitCode': status(required_acp),
          'operatorCleanupExitCode': status(cleanup), 'finalExitCode': int(final)}
with Path(path).open('x', encoding='utf-8') as output:
    json.dump(record, output, sort_keys=True, separators=(',', ':'))
    output.write('\n')
PYTHON
  local receipt_status=$?
  if [[ "$final_status" == 0 && "$receipt_status" != 0 ]]; then final_status=$receipt_status; fi
  exit "$final_status"
}
trap finish EXIT
python3 scripts/reconcile-module-compilation-hosted-cases.py initialize \
  --directory "$case_directory" --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"
case_index_initialized=true
python3 - "$qualification_root/checkout-provenance.json" <<'PYTHON'
import json
import os
from pathlib import Path
import subprocess
import sys
def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()
head, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
assert not git('status', '--porcelain', '--untracked-files=no'), 'hosted source must be a clean checkout'
value = {'schemaVersion': 1, 'provider': 'contained-module-hosted-checkout-v1',
         'headCommit': head, 'headTree': tree, 'parents': git('show', '-s', '--format=%P', 'HEAD').split(),
         'runId': os.environ['GITHUB_RUN_ID'], 'runAttempt': os.environ['GITHUB_RUN_ATTEMPT'],
         'eventSha': os.environ.get('GITHUB_SHA'), 'eventName': os.environ.get('GITHUB_EVENT_NAME'),
         'repository': os.environ.get('GITHUB_REPOSITORY'), 'workflow': os.environ.get('GITHUB_WORKFLOW')}
with Path(sys.argv[1]).open('x', encoding='utf-8') as output:
    json.dump(value, output, sort_keys=True, separators=(',', ':'))
    output.write('\n')
PYTHON
phase=prerequisites
./gradlew --no-daemon --console=plain -I "$init" moduleCompilerDeploymentManifest buildAcpGateHelper verifyAcpGateHelper
helper="$project_root/build/native/acp/decomp-acp-gate-helper"
helper_sha="$(sha256sum "$helper")"
helper_sha="${helper_sha%% *}"
sudo -n python3 scripts/ci-prepare-generated-c-validation.py prepare \
  --run-id "$qualification_identity" --uid "$(id -u)" --gid "$(id -g)" \
  --gate-helper "$helper" --gate-sha256 "$helper_sha" \
  --module-worker-classpath "$qualification_root/worker-classpath.json" \
  > "$qualification_root/operator-provisioning.json"
provisioned=true
phase=configuration
./gradlew --no-daemon --console=plain -I "$init" moduleCompilerWriteConfig
for profile in generated-c-make-v1 generated-c-ninja-v1; do
  sudo -n install --owner=root --group=root --mode=0444 \
    "$qualification_root/config/$profile.json" "/var/lib/decomp-generated-c-runtime-ci/$profile.json"
done
export GENERATED_C_MODULE_COMPILE_CONFIG_DIRECTORY=/var/lib/decomp-generated-c-runtime-ci
export GENERATED_C_MODULE_COMPILE_PROFILE=generated-c-make-v1
export GENERATED_C_MODULE_COMPILE_REQUIRE=true
phase=live-gradle
set +e
./gradlew --no-daemon --console=plain -I "$init" moduleCompilationLiveQualification \
  > "$qualification_root/live-gradle.log" 2>&1
gradle_status=$?
set -e
cat "$qualification_root/live-gradle.log"
phase=xml-verification
set +e
python3 - <<'PYTHON'
import json
from pathlib import Path
inventory = json.loads(Path('build/module-compilation-qualification/compiled-live-tests.json').read_text())
required = ('decompengine.acp.AcpAgentHarnessTest', 'public Make and Ninja archival reconstruction follows ACP file roles through verified rebuild')
assert required in {(test['class'], test['method']) for test in inventory['tests']}, 'required transferred ACP positive is absent'
PYTHON
required_acp_status=$?
python3 scripts/verify-module-compilation-live-tests.py \
  --inventory "$qualification_root/compiled-live-tests.json" \
  --reports "$project_root/build/test-results/moduleCompilationLiveQualification" \
  --output "$qualification_root/test-summary.json"
xml_status=$?
set -e
if [[ "$gradle_status" != 0 ]]; then exit "$gradle_status"; fi
if [[ "$required_acp_status" != 0 ]]; then exit "$required_acp_status"; fi
if [[ "$xml_status" != 0 ]]; then exit "$xml_status"; fi
phase=complete
