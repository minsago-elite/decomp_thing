#!/usr/bin/env bash
set -euo pipefail

scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT

cat > "$scratch/fetch" <<'FETCH'
#!/usr/bin/env bash
set -euo pipefail
state="$1"
mode="$2"
count=0
if [[ -f "$state" ]]; then
  count="$(cat -- "$state")"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$state"
case "$mode" in
  transient-once)
    if ((count == 1)); then
      echo 'LLVM release artifact fetch failed: HTTPS exchange failed' >&2
      exit 1
    fi
    ;;
  timeout-once)
    if ((count == 1)); then
      echo 'LLVM release artifact fetch failed: HTTPS exchange exceeded its wall-clock deadline' >&2
      exit 1
    fi
    ;;
  gateway-once|integrity-after-gateway)
    if ((count == 1)); then
      echo 'LLVM release artifact fetch failed: HTTPS download returned HTTP 504' >&2
      exit 1
    fi
    if [[ "$mode" == integrity-after-gateway ]]; then
      echo 'LLVM release artifact fetch failed: HTTPS body SHA-256 differs from its release lock' >&2
      exit 1
    fi
    ;;
  gateway-always)
    echo 'LLVM release artifact fetch failed: HTTPS download returned HTTP 504' >&2
    exit 1
    ;;
  other-http)
    echo 'LLVM release artifact fetch failed: HTTPS download returned HTTP 503' >&2
    exit 1
    ;;
  integrity)
    echo 'LLVM release artifact fetch failed: HTTPS body SHA-256 differs from its release lock' >&2
    exit 1
    ;;
  transient-always)
    echo 'LLVM release artifact fetch failed: HTTPS exchange failed' >&2
    exit 1
    ;;
esac
echo 'verified full release artifact'
FETCH
chmod +x "$scratch/fetch"

for mode in transient-once timeout-once gateway-once; do
  state="$scratch/$mode.count"
  if ! bash scripts/ci-fetch-llvm-release-artifacts.sh "$scratch/fetch" "$state" "$mode" > "$scratch/$mode.log" 2>&1; then
    echo "unexpected failed $mode fetch" >&2
    cat -- "$scratch/$mode.log" >&2
    exit 1
  fi
  [[ "$(cat -- "$state")" == 2 ]]
  grep -Fq 'verified full release artifact' "$scratch/$mode.log"
  echo "passed $mode (2 attempts)"
done

for mode in integrity transient-always gateway-always other-http integrity-after-gateway; do
  state="$scratch/$mode.count"
  if bash scripts/ci-fetch-llvm-release-artifacts.sh "$scratch/fetch" "$state" "$mode" > "$scratch/$mode.log" 2>&1; then
    echo "unexpected successful $mode fetch" >&2
    exit 1
  fi
  if [[ "$mode" == integrity || "$mode" == other-http ]]; then
    [[ "$(cat -- "$state")" == 1 ]]
  elif [[ "$mode" == integrity-after-gateway ]]; then
    [[ "$(cat -- "$state")" == 2 ]]
  else
    [[ "$(cat -- "$state")" == 3 ]]
  fi
  echo "passed $mode ($(cat -- "$state") attempts)"
done

echo 'bounded LLVM release transport retry checks passed (8 controls)'
