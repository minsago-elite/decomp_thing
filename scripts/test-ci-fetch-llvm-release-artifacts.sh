#!/usr/bin/env bash
set -euo pipefail

scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT

mkdir "$scratch/bin"
sleep_log="$scratch/sleep.log"
export SLEEP_LOG="$sleep_log"
cat > "$scratch/bin/sleep" <<'SLEEP'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" != 1 || "$1" != 3 ]]; then
  echo "unexpected retry pause: $*" >&2
  exit 90
fi
printf '%s\n' "$1" >> "$SLEEP_LOG"
SLEEP
chmod +x "$scratch/bin/sleep"
PATH="$scratch/bin:$PATH"
export PATH

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
  http-504-once)
    if ((count == 1)); then
      echo 'LLVM release artifact fetch failed: HTTPS download returned HTTP 504' >&2
      exit 1
    fi
    ;;
  http-504-always)
    echo 'LLVM release artifact fetch failed: HTTPS download returned HTTP 504' >&2
    exit 1
    ;;
  http-504-then-integrity)
    if ((count == 1)); then
      echo 'LLVM release artifact fetch failed: HTTPS download returned HTTP 504' >&2
      exit 1
    fi
    echo 'LLVM release artifact fetch failed: HTTPS body SHA-256 differs from its release lock' >&2
    exit 1
    ;;
  http-other-*)
    code="${mode#http-other-}"
    echo "LLVM release artifact fetch failed: HTTPS download returned HTTP $code" >&2
    exit 1
    ;;
  http-504-prefix)
    echo 'prefix LLVM release artifact fetch failed: HTTPS download returned HTTP 504' >&2
    exit 1
    ;;
  http-504-suffix)
    echo 'LLVM release artifact fetch failed: HTTPS download returned HTTP 504 extra' >&2
    exit 1
    ;;
  http-5040)
    echo 'LLVM release artifact fetch failed: HTTPS download returned HTTP 5040' >&2
    exit 1
    ;;
esac
echo 'verified full release artifact'
FETCH
chmod +x "$scratch/fetch"

run_wrapper() {
  bash scripts/ci-fetch-llvm-release-artifacts.sh "$@"
}

reset_control() {
  mode="$1"
  state="$scratch/$mode.count"
  log="$scratch/$mode.log"
  : > "$sleep_log"
  rm -f -- "$state"
}

assert_attempts_and_pauses() {
  expected_attempts="$1"
  expected_pauses="$2"
  [[ "$(cat -- "$state")" == "$expected_attempts" ]]
  [[ "$(cat -- "$sleep_log")" == "$expected_pauses" ]]
}

for mode in transient-once timeout-once http-504-once; do
  reset_control "$mode"
  run_wrapper "$scratch/fetch" "$state" "$mode" > "$log" 2>&1
  assert_attempts_and_pauses 2 3
  grep -Fq 'verified full release artifact' "$log"
done

for mode in integrity; do
  reset_control "$mode"
  if run_wrapper "$scratch/fetch" "$state" "$mode" > "$log" 2>&1; then
    echo "unexpected successful $mode fetch" >&2
    exit 1
  fi
  assert_attempts_and_pauses 1 ''
done

for mode in transient-always http-504-always; do
  reset_control "$mode"
  if run_wrapper "$scratch/fetch" "$state" "$mode" > "$log" 2>&1; then
    echo "unexpected successful $mode fetch" >&2
    exit 1
  else
    status=$?
  fi
  [[ "$status" == 1 ]]
  assert_attempts_and_pauses 3 $'3\n3'
done

reset_control http-504-then-integrity
if run_wrapper "$scratch/fetch" "$state" http-504-then-integrity > "$log" 2>&1; then
  echo 'unexpected successful HTTP 504 then integrity failure' >&2
  exit 1
else
  status=$?
fi
[[ "$status" == 1 ]]
assert_attempts_and_pauses 2 3
[[ "$(grep -Fc 'HTTPS body SHA-256 differs from its release lock' "$log")" == 1 ]]

for code in 403 429 500 502 503 505; do
  mode="http-other-$code"
  reset_control "$mode"
  if run_wrapper "$scratch/fetch" "$state" "$mode" > "$log" 2>&1; then
    echo "unexpected retry success for HTTP $code" >&2
    exit 1
  fi
  assert_attempts_and_pauses 1 ''
done

for mode in http-504-prefix http-504-suffix http-5040; do
  reset_control "$mode"
  if run_wrapper "$scratch/fetch" "$state" "$mode" > "$log" 2>&1; then
    echo "unexpected retry success for near-match $mode" >&2
    exit 1
  fi
  assert_attempts_and_pauses 1 ''
done

reset_control success
run_wrapper "$scratch/fetch" "$state" success > "$log" 2>&1
assert_attempts_and_pauses 1 ''
grep -Fq 'verified full release artifact' "$log"

echo 'bounded LLVM release transport retry checks passed'
