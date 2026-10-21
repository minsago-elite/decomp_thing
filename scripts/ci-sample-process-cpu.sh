#!/usr/bin/env bash
# Diagnostic-only per-command CPU sampler for the cc1 runtime-diagnostics run. Appends to the given file,
# outside the evidence root, so it grants no qualification authority and changes no profile or bound.
# Each sample is "T <epoch>" followed by "C <command> <cumulative-cpu-seconds> <process-count>" lines for the
# twelve commands with the most cumulative CPU among live processes.
set -euo pipefail

if [[ $# != 2 || "$1" != /* || ! "$2" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: scripts/ci-sample-process-cpu.sh <absolute-output-file> <interval-seconds>" >&2
  exit 2
fi
output=$1
interval=$2

shopt -s nullglob
while :; do
  printf 'T %s\n' "$(date -u +%s)" >>"$output"
  # The contained command's own cgroup accounts for exited children too, which a live-process snapshot cannot.
  for scope in /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/decomp-gcc-cc1-*.scope; do
    {
      printf 'S %s' "${scope##*/}"
      for file in cpu.stat pids.current memory.current; do
        [[ -r "$scope/$file" ]] && printf ' | %s: %s' "$file" "$(tr '\n' ' ' <"$scope/$file")"
      done
      printf '\n'
    } >>"$output" 2>/dev/null || true
  done
  ps -eo cputimes=,comm= | awk '{ cpu[$2] += $1; count[$2]++ } END { for (name in cpu) printf "C %s %d %d\n", name, cpu[name], count[name] }' |
    sort -k3,3nr | head -12 >>"$output"
  sleep "$interval"
done
