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

for mode in transient-once timeout-once; do
  state="$scratch/$mode.count"
  bash scripts/ci-fetch-llvm-release-artifacts.sh "$scratch/fetch" "$state" "$mode" > "$scratch/$mode.log" 2>&1
  [[ "$(cat -- "$state")" == 2 ]]
  grep -Fq 'verified full release artifact' "$scratch/$mode.log"
done

for mode in integrity transient-always; do
  state="$scratch/$mode.count"
  if bash scripts/ci-fetch-llvm-release-artifacts.sh "$scratch/fetch" "$state" "$mode" > "$scratch/$mode.log" 2>&1; then
    echo "unexpected successful $mode fetch" >&2
    exit 1
  fi
  if [[ "$mode" == integrity ]]; then
    [[ "$(cat -- "$state")" == 1 ]]
  else
    [[ "$(cat -- "$state")" == 3 ]]
  fi
done

echo 'bounded LLVM release transport retry checks passed'
