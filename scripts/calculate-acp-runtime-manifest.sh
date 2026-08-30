#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$#" -ne 1 ]]; then
  echo "usage: scripts/calculate-acp-runtime-manifest.sh <final-installed-path>" >&2
  exit 2
fi

target=$(realpath -e -- "$1")
distribution_lib=build/install/llm_bin_patch/lib
if [[ ! -d "$distribution_lib" ]]; then
  echo "missing installDist libraries; run ./gradlew installDist first" >&2
  exit 2
fi

jars=("$distribution_lib"/*.jar)
if [[ ! -f "${jars[0]}" ]]; then
  echo "installDist contains no runtime libraries" >&2
  exit 2
fi
classpath=$(IFS=:; echo "${jars[*]}")

work_directory=$(mktemp -d /tmp/decomp-acp-manifest.XXXXXX)
cleanup() {
  case "$work_directory" in
    /tmp/decomp-acp-manifest.*) rm -rf -- "$work_directory" ;;
    *) echo "refusing to remove unexpected manifest workspace: $work_directory" >&2 ;;
  esac
}
trap cleanup EXIT

javac -cp "$classpath" -d "$work_directory" scripts/support/AcpRuntimeManifest.java
java -cp "$work_directory:$classpath" AcpRuntimeManifest "$target"
