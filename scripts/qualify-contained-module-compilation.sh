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
if [[ -e "$project_root/build/test-results/moduleCompilationLiveQualification" || -e "$qualification_root/compiled-live-tests.json" ]]; then
  echo "refusing to reuse compiler qualification inventory or reports" >&2; exit 1
fi
mkdir -p "$qualification_root/tmp" "$qualification_root/cache"
export TMPDIR="$qualification_root/tmp" XDG_CACHE_HOME="$qualification_root/cache"
export JAVA_TOOL_OPTIONS="-XX:-UsePerfData -Djava.io.tmpdir=$TMPDIR -Djna.tmpdir=$TMPDIR"
init="$project_root/scripts/module-compilation-qualification.init.gradle"
provisioned=false
cleanup() {
  if [[ "$provisioned" == true ]]; then
    sudo -n python3 scripts/ci-prepare-generated-c-validation.py cleanup --run-id "$qualification_identity"
  fi
}
trap cleanup EXIT
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
./gradlew --no-daemon --console=plain -I "$init" moduleCompilerWriteConfig
for profile in generated-c-make-v1 generated-c-ninja-v1; do
  sudo -n install --owner=root --group=root --mode=0444 \
    "$qualification_root/config/$profile.json" "/opt/decomp-generated-c-validation-ci/$profile.json"
done
export GENERATED_C_MODULE_COMPILE_CONFIG_DIRECTORY=/opt/decomp-generated-c-validation-ci
export GENERATED_C_MODULE_COMPILE_PROFILE=generated-c-make-v1
export GENERATED_C_MODULE_COMPILE_REQUIRE=true
./gradlew --no-daemon --console=plain -I "$init" moduleCompilationLiveQualification
python3 - <<'PYTHON'
import json
from pathlib import Path
inventory = json.loads(Path('build/module-compilation-qualification/compiled-live-tests.json').read_text())
required = ('decompengine.acp.AcpAgentHarnessTest', 'public Make and Ninja archival reconstruction follows ACP file roles through verified rebuild')
assert required in {(test['class'], test['method']) for test in inventory['tests']}, 'required transferred ACP positive is absent'
PYTHON
python3 scripts/verify-module-compilation-live-tests.py \
  --inventory "$qualification_root/compiled-live-tests.json" \
  --reports "$project_root/build/test-results/moduleCompilationLiveQualification" \
  --output "$qualification_root/test-summary.json"

cleanup
provisioned=false
trap - EXIT
