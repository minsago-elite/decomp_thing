#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

required=true
reason=no-base
base="${ANGR_DIFF_BASE:-}"
if [[ "$base" =~ ^[0-9a-f]{40}$ && "$base" != 0000000000000000000000000000000000000000 ]]; then
  if git cat-file -e "$base^{commit}" 2>/dev/null || git fetch --no-tags --depth=1 origin "$base"; then
    if git diff --quiet "$base" HEAD -- \
      .github/workflows/ci.yml Dockerfile build.gradle.kts requirements/angr-qualification.txt requirements/angr-compatibility.txt \
      scripts/ci-qualify-angr.sh scripts/select-angr-qualification.sh scripts/check-angr-pin.py \
      scripts/test-angr-qualification-selection.py \
      src/main/kotlin/decompengine/exploration src/test/kotlin/decompengine/exploration; then
      required=false
      reason=no-relevant-change
    else
      diff_status=$?
      if [[ "$diff_status" == 1 ]]; then reason=relevant-change; else reason=unavailable-comparison; fi
    fi
  else
    reason=unavailable-base
  fi
else
  base=unavailable
fi
mkdir -p build/angr-qualification
{
  printf 'checkout=%s\n' "$(git rev-parse HEAD)"
  printf 'comparisonBase=%s\nrequired=%s\nreason=%s\n' "$base" "$required" "$reason"
} > build/angr-qualification/selection.txt
printf 'required=%s\n' "$required" >> "$GITHUB_OUTPUT"
