#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if (($# > 1)) || { (($# == 1)) && [[ "$1" != --fetch-archive ]]; }; then
  echo "usage: scripts/ci-qualify-goose-acp.sh [--fetch-archive]" >&2
  exit 64
fi
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "the pinned Goose ACP qualification target requires Linux x86-64" >&2
  exit 1
fi

readonly GOOSE_VERSION="1.46.0"
readonly GOOSE_ARCHIVE="goose-x86_64-unknown-linux-gnu.tar.bz2"
readonly GOOSE_ARCHIVE_URL="https://github.com/aaif-goose/goose/releases/download/v${GOOSE_VERSION}/${GOOSE_ARCHIVE}"
readonly GOOSE_ASSET_API_URL="https://api.github.com/repos/aaif-goose/goose/releases/assets/511784069"
readonly GOOSE_ARCHIVE_BYTES="84957951"
readonly GOOSE_ARCHIVE_SHA256="a1cf4856a765d07d6b95689a53c7bca21fcc6e6d65c0dfd064fc704052b85a7b"

for required_command in bzip2 cp curl javac java ldd ln sha256sum tar wc; do
  command -v "$required_command" >/dev/null || {
    echo "missing ACP compatibility command: $required_command" >&2
    exit 1
  }
done

compatibility_root="$(pwd)/build/acp-compatibility"
mkdir -p "$compatibility_root/results" "$compatibility_root/work"
work_directory=$(mktemp -d "$compatibility_root/work/goose-${GOOSE_VERSION}.XXXXXX")
cleanup() {
  case "$work_directory" in
    "$compatibility_root"/work/goose-"$GOOSE_VERSION".*)
      rm -rf -- "$work_directory"
      ;;
    *)
      echo "refusing to remove unexpected ACP compatibility workspace: $work_directory" >&2
      ;;
  esac
}
trap cleanup EXIT

if [[ "${1:-}" != --fetch-archive ]]; then
  result_directory=$(mktemp -d "$compatibility_root/results/goose-${GOOSE_VERSION}.XXXXXX")
  printf '%s\n' \
    "schema=decomp-engine-acp-compatibility-target-v1" \
    "agent=goose" \
    "version=$GOOSE_VERSION" \
    "archive=$GOOSE_ARCHIVE_URL" \
    "archiveSha256=$GOOSE_ARCHIVE_SHA256" \
    "argv=goose acp" \
    "case=credential-free-initialize" \
    "sessionCreated=false" \
    "modelPromptSent=false" \
    >"$result_directory/target.properties"
fi

archive_path="$work_directory/$GOOSE_ARCHIVE"
cache_directory="$compatibility_root/download-cache"
cache_archive="$cache_directory/$GOOSE_ARCHIVE"
verify_archive() {
  [[ ! -L "$1" && -f "$1" ]] || return 1
  [[ "$(wc -c <"$1")" == "$GOOSE_ARCHIVE_BYTES" ]] || return 1
  local observed_digest=""
  read -r observed_digest _ < <(sha256sum -- "$1")
  [[ "$observed_digest" == "$GOOSE_ARCHIVE_SHA256" ]]
}
if [[ -L "$cache_directory" || ( -e "$cache_directory" && ! -d "$cache_directory" ) ]]; then
  echo "pinned Goose download cache is not a regular directory" >&2
  exit 1
fi
mkdir -p "$cache_directory"
if [[ -e "$cache_archive" || -L "$cache_archive" ]]; then
  if ! verify_archive "$cache_archive"; then
    echo "pinned Goose cached archive differs from its size/SHA-256 lock" >&2
    exit 1
  fi
  cp -- "$cache_archive" "$archive_path"
  echo "Reused verified pinned Goose archive"
else
  downloaded=false
  # Two official endpoints, one attempt each, at most 240 seconds of transfer time.
  # This retries acquisition only; no agent/protocol invocation is repeated.
  for archive_url in "$GOOSE_ARCHIVE_URL" "$GOOSE_ASSET_API_URL"; do
    if curl --fail --location --max-redirs 3 --proto '=https' --proto-redir '=https' \
      --tlsv1.2 --connect-timeout 15 --max-time 120 --max-filesize "$GOOSE_ARCHIVE_BYTES" \
      --retry 0 --show-error --silent --header 'Accept: application/octet-stream' \
      --output "$archive_path" "$archive_url"; then
      if ! verify_archive "$archive_path"; then
        echo "pinned Goose downloaded archive differs from its size/SHA-256 lock" >&2
        exit 1
      fi
      downloaded=true
      break
    fi
  done
  if [[ "$downloaded" != true ]]; then
    echo "both official pinned Goose archive endpoints refused acquisition" >&2
    exit 1
  fi
  # A hard link publishes complete verified bytes atomically without replacement.
  if ! ln -- "$archive_path" "$cache_archive"; then
    if ! verify_archive "$cache_archive"; then
      echo "pinned Goose cache publication found an incompatible existing entry" >&2
      exit 1
    fi
  fi
fi
if ! verify_archive "$archive_path"; then
  echo "pinned Goose staged archive differs from its size/SHA-256 lock" >&2
  exit 1
fi
if [[ "${1:-}" == --fetch-archive ]]; then
  exit 0
fi

./gradlew --no-daemon installDist

read -r actual_archive_sha256 _ < <(sha256sum -- "$archive_path")
if [[ "$actual_archive_sha256" != "$GOOSE_ARCHIVE_SHA256" ]]; then
  echo "pinned Goose ACP archive digest mismatch" >&2
  exit 1
fi
archive_entries=$(tar --list --bzip2 --file="$archive_path")
if [[ "$archive_entries" != $'./\n./goose' ]]; then
  echo "pinned Goose ACP archive has an unexpected layout" >&2
  exit 1
fi

agent_directory="$work_directory/agent"
mkdir -p "$agent_directory"
tar \
  --extract \
  --bzip2 \
  --file="$archive_path" \
  --directory="$agent_directory" \
  --no-same-owner \
  --no-same-permissions
agent_executable="$agent_directory/goose"
if [[ -L "$agent_executable" || ! -f "$agent_executable" ]]; then
  echo "pinned Goose ACP archive omitted its real executable" >&2
  exit 1
fi
chmod 755 "$agent_executable"

distribution_lib="$(pwd)/build/install/llm_bin_patch/lib"
gate_helper="$(pwd)/build/install/llm_bin_patch/libexec/decomp-acp-gate-helper"
(
  cd "$(dirname "$gate_helper")"
  sha256sum --check --strict decomp-acp-gate-helper.sha256
)
support_classes="$work_directory/support"
mkdir -p "$support_classes"
javac \
  -Xlint:all \
  -Werror \
  -cp "$distribution_lib/*" \
  -d "$support_classes" \
  scripts/support/AcpCompatibilityJson.java \
  scripts/support/AcpCompatibilityFailureSummary.java \
  scripts/support/AcpCompatibilityFailureSummaryControls.java \
  scripts/support/AcpCompatibilityProvisioner.java \
  scripts/support/AcpCompatibilityPreflight.java \
  scripts/support/AcpCompatibilityPreflightEvidenceControls.java

java -cp "$support_classes:$distribution_lib/*" AcpCompatibilityPreflightEvidenceControls \
  >"$result_directory/diagnostic-controls.json"
java -cp "$support_classes:$distribution_lib/*" AcpCompatibilityFailureSummaryControls \
  >"$result_directory/failure-summary-controls.json"

config_file="$result_directory/config.json"
java -cp "$support_classes:$distribution_lib/*" AcpCompatibilityProvisioner \
  "$agent_executable" \
  "$gate_helper" \
  "goose-$GOOSE_VERSION" \
  "$config_file" \
  acp
executable_manifest_sha256=$(scripts/calculate-acp-runtime-manifest.sh "$agent_executable")

evidence_file="$result_directory/evidence.json"
java -cp "$support_classes:$distribution_lib/*" AcpCompatibilityPreflight \
  "$config_file" \
  "$evidence_file" \
  goose \
  "$GOOSE_VERSION" \
  "$GOOSE_ARCHIVE_URL" \
  "$GOOSE_ARCHIVE_SHA256" \
  "$executable_manifest_sha256"

(
  cd "$result_directory"
  sha256sum target.properties diagnostic-controls.json failure-summary-controls.json config.json evidence.json >ARTIFACTS.sha256
)
echo "ACP compatibility evidence: $result_directory"
