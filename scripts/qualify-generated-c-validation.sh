#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: scripts/qualify-generated-c-validation.sh" >&2
  exit 64
fi
: "${GITHUB_RUN_ID:?This script requires an explicitly selected hosted qualification run}"
: "${GITHUB_RUN_ATTEMPT:?This script requires a hosted qualification attempt identity}"
qualification_root="$(pwd -P)/build/generated-c-public-qualification"
qualification_identity="${GITHUB_RUN_ID}.${GITHUB_RUN_ATTEMPT}"
if [[ -e "$qualification_root" || -L "$qualification_root" ]]; then
  echo "Refusing to replace existing generated-C qualification artifacts" >&2
  exit 1
fi
mkdir --mode=0700 "$qualification_root"
qualification_provisioned=false
cleanup() {
  if [[ "$qualification_provisioned" == true ]]; then
    sudo -n python3 scripts/ci-prepare-generated-c-validation.py cleanup --run-id "$qualification_identity"
  fi
}
trap cleanup EXIT

./gradlew --no-daemon --console=plain buildAcpGateHelper verifyAcpGateHelper
qualification_helper="$(pwd -P)/build/native/acp/decomp-acp-gate-helper"
qualification_helper_sha="$(sha256sum "$qualification_helper")"
qualification_helper_sha="${qualification_helper_sha%% *}"
sudo -n python3 scripts/ci-prepare-generated-c-validation.py prepare \
  --run-id "$qualification_identity" --uid "$(id -u)" --gid "$(id -g)" \
  --gate-helper "$qualification_helper" --gate-sha256 "$qualification_helper_sha" \
  >"$qualification_root/operator-provisioning.json"
qualification_provisioned=true

./gradlew --no-daemon --console=plain generatedCRepairQualification \
  -PgeneratedCQualificationAction=write-config \
  "-PgeneratedCQualificationOutput=$qualification_root/config"
sudo -n install --owner=root --group=root --mode=0444 \
  "$qualification_root/config/runtime.json" /opt/decomp-generated-c-validation-ci/runtime.json
sudo -n install --owner=root --group=root --mode=0444 \
  "$qualification_root/config/sandbox.json" /opt/decomp-generated-c-validation-ci/sandbox.json

export GENERATED_C_REPAIR_CONFIG_FILE=/opt/decomp-generated-c-validation-ci/runtime.json
export ACP_CONFIG_FILE="$qualification_root/config/acp.json"
export ACP_HARNESS=acp
./gradlew --no-daemon --console=plain generatedCRepairQualification \
  -PgeneratedCQualificationAction=qualify \
  "-PgeneratedCQualificationOutput=$qualification_root/evidence"
# A distinct JavaExec process opens the durable project again through the same public factory.
./gradlew --no-daemon --console=plain generatedCRepairQualification \
  -PgeneratedCQualificationAction=reopen \
  "-PgeneratedCQualificationOutput=$qualification_root/evidence"

cleanup
qualification_provisioned=false
trap - EXIT
