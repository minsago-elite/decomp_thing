#!/usr/bin/env bash
# Lists the system temporary directory before and after a build command and fails when the
# command leaves new entries owned by the current user there (#2008). HotSpot's per-process
# hsperfdata files are listed too, since their directory usually exists before the build.
#
# Usage: scripts/check-system-temp-isolation.sh [command [argument...]]
# Default command: ./gradlew --no-daemon test -PciTestShard=core
# DECOMP_SYSTEM_TEMP_DIR overrides the listed directory (default /tmp, where HotSpot writes
# hsperfdata whatever TMPDIR says). Concurrent work by the same user on the host is
# indistinguishable from this build and is reported too.
set -euo pipefail

cd "$(dirname "$0")/.."

system_temp=${DECOMP_SYSTEM_TEMP_DIR:-/tmp}
report=build/system-temp-isolation
user_id=$(id -u)
user_name=$(id -un)

if [[ ! -d "$system_temp" ]]; then
  echo "system temporary directory does not exist: $system_temp" >&2
  exit 2
fi
if (($# == 0)); then
  set -- ./gradlew --no-daemon test -PciTestShard=core
fi

snapshot() {
  {
    find "$system_temp" -mindepth 1 -maxdepth 1 -user "$user_id" -printf '%P\n'
    if [[ -d "$system_temp/hsperfdata_$user_name" ]]; then
      find "$system_temp/hsperfdata_$user_name" -mindepth 1 -maxdepth 1 -printf "hsperfdata_$user_name/%P\n"
    fi
  } | LC_ALL=C sort -u
}

mkdir -p "$report"
snapshot > "$report/before.txt"
status=0
"$@" || status=$?
snapshot > "$report/after.txt"
LC_ALL=C comm -13 "$report/before.txt" "$report/after.txt" > "$report/new-entries.txt"

if [[ -s "$report/new-entries.txt" ]]; then
  echo "==> New entries in $system_temp after: $*" >&2
  sed 's/^/  /' "$report/new-entries.txt" >&2
  ((status != 0)) || status=1
else
  echo "==> No new entries in $system_temp after: $*"
fi
exit "$status"
