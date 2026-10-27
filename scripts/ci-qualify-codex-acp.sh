#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if (($# > 1)) || { (($# == 1)) && [[ "$1" != --fetch-archive ]]; }; then
  echo "usage: scripts/ci-qualify-codex-acp.sh [--fetch-archive]" >&2
  exit 64
fi
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "the pinned codex-acp qualification target requires Linux x86-64" >&2
  exit 1
fi

readonly CODEX_ACP_VERSION="0.16.0"
readonly CODEX_ACP_ARCHIVE="codex-acp-${CODEX_ACP_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
readonly CODEX_ACP_ARCHIVE_URL="https://github.com/zed-industries/codex-acp/releases/download/v${CODEX_ACP_VERSION}/${CODEX_ACP_ARCHIVE}"
readonly CODEX_ACP_ASSET_API_URL="https://api.github.com/repos/zed-industries/codex-acp/releases/assets/441865401"
readonly CODEX_ACP_ARCHIVE_BYTES="74262216"
readonly CODEX_ACP_ARCHIVE_SHA256="0a9ad6c31ec9b2b87dccb7e9da3faf5d387e74470d24dbced75a160ed7b22d06"
readonly CODEX_ACP_EXECUTABLE_SHA256="23a9f2af247fc61aa9a895d5ee91a62a35d05a883bddc2c85d1dc6b2be697087"
readonly CODEX_ACP_BUNDLED_BWRAP_SHA256="5a5104807cfbe9b509d0b9fa1c46054ff48dbed5393f30d261b34263ebf0e3fe"

for required_command in cp curl gzip javac java ldd ln sha256sum tar wc; do
  command -v "$required_command" >/dev/null || {
    echo "missing ACP compatibility command: $required_command" >&2
    exit 1
  }
done

compatibility_root="$(pwd)/build/acp-codex-compatibility"
mkdir -p "$compatibility_root/results" "$compatibility_root/work"
work_directory=$(mktemp -d "$compatibility_root/work/codex-acp-${CODEX_ACP_VERSION}.XXXXXX")
cleanup() {
  case "$work_directory" in
    "$compatibility_root"/work/codex-acp-"$CODEX_ACP_VERSION".*)
      rm -rf -- "$work_directory"
      ;;
    *)
      echo "refusing to remove unexpected ACP compatibility workspace: $work_directory" >&2
      ;;
  esac
}
trap cleanup EXIT

if [[ "${1:-}" != --fetch-archive ]]; then
  result_directory=$(mktemp -d "$compatibility_root/results/codex-acp-${CODEX_ACP_VERSION}.XXXXXX")
  printf '%s\n' \
    "schema=decomp-engine-acp-compatibility-target-v1" \
    "agent=codex-acp" \
    "version=$CODEX_ACP_VERSION" \
    "archive=$CODEX_ACP_ARCHIVE_URL" \
    "archiveSha256=$CODEX_ACP_ARCHIVE_SHA256" \
    "archiveEntries=codex-acp,codex-resources/bwrap" \
    "executableSha256=$CODEX_ACP_EXECUTABLE_SHA256" \
    "bundledBwrapSha256=$CODEX_ACP_BUNDLED_BWRAP_SHA256" \
    "bundledResourceMounted=false" \
    "argv=codex-acp" \
    "case=credential-free-session-authentication-boundary" \
    "initializeRequired=true" \
    "sessionCreationAttempted=true" \
    "sessionCreated=false" \
    "modelPromptSent=false" \
    "workspaceFilesystemAuthorityGranted=false" \
    "workspaceFilesystemEdits=false" \
    "terminalAuthorityGranted=false" \
    "permissionAuthorityGranted=false" \
    "credentialsForwarded=false" \
    "outerNetworkEnabled=false" \
    "oracleAccessGranted=false" \
    >"$result_directory/target.properties"
fi

archive_path="$work_directory/$CODEX_ACP_ARCHIVE"
cache_directory="$compatibility_root/download-cache"
cache_archive="$cache_directory/$CODEX_ACP_ARCHIVE"
verify_archive() {
  [[ ! -L "$1" && -f "$1" ]] || return 1
  [[ "$(wc -c <"$1")" == "$CODEX_ACP_ARCHIVE_BYTES" ]] || return 1
  local observed_digest=""
  read -r observed_digest _ < <(sha256sum -- "$1")
  [[ "$observed_digest" == "$CODEX_ACP_ARCHIVE_SHA256" ]]
}
if [[ -L "$cache_directory" || ( -e "$cache_directory" && ! -d "$cache_directory" ) ]]; then
  echo "pinned codex-acp download cache is not a regular directory" >&2
  exit 1
fi
mkdir -p "$cache_directory"
if [[ -e "$cache_archive" || -L "$cache_archive" ]]; then
  if ! verify_archive "$cache_archive"; then
    echo "pinned codex-acp cached archive differs from its size/SHA-256 lock" >&2
    exit 1
  fi
  cp -- "$cache_archive" "$archive_path"
  echo "Reused verified pinned codex-acp archive"
else
  downloaded=false
  # Two official endpoints, one attempt each, at most 240 seconds of transfer time.
  # This retries acquisition only; no agent/protocol invocation is repeated.
  for archive_url in "$CODEX_ACP_ARCHIVE_URL" "$CODEX_ACP_ASSET_API_URL"; do
    if curl --fail --location --max-redirs 3 --proto '=https' --proto-redir '=https' \
      --tlsv1.2 --connect-timeout 15 --max-time 120 --max-filesize "$CODEX_ACP_ARCHIVE_BYTES" \
      --retry 0 --show-error --silent --header 'Accept: application/octet-stream' \
      --output "$archive_path" "$archive_url"; then
      if ! verify_archive "$archive_path"; then
        echo "pinned codex-acp downloaded archive differs from its size/SHA-256 lock" >&2
        exit 1
      fi
      downloaded=true
      break
    fi
  done
  if [[ "$downloaded" != true ]]; then
    echo "both official pinned codex-acp archive endpoints refused acquisition" >&2
    exit 1
  fi
  # A hard link publishes complete verified bytes atomically without replacement.
  if ! ln --no-target-directory -- "$archive_path" "$cache_archive"; then
    if ! verify_archive "$cache_archive"; then
      echo "pinned codex-acp cache publication found an incompatible existing entry" >&2
      exit 1
    fi
  fi
fi
if ! verify_archive "$archive_path"; then
  echo "pinned codex-acp staged archive differs from its size/SHA-256 lock" >&2
  exit 1
fi
if [[ "${1:-}" == --fetch-archive ]]; then
  exit 0
fi

./gradlew --no-daemon installDist

read -r actual_archive_sha256 _ < <(sha256sum -- "$archive_path")
if [[ "$actual_archive_sha256" != "$CODEX_ACP_ARCHIVE_SHA256" ]]; then
  echo "pinned codex-acp archive digest mismatch" >&2
  exit 1
fi
archive_entries=$(tar --list --gzip --file="$archive_path")
if [[ "$archive_entries" != $'codex-acp\ncodex-resources/bwrap' ]]; then
  echo "pinned codex-acp archive has an unexpected layout" >&2
  exit 1
fi

agent_directory="$work_directory/agent"
mkdir -p "$agent_directory"
tar \
  --extract \
  --gzip \
  --file="$archive_path" \
  --directory="$agent_directory" \
  --no-same-owner \
  --no-same-permissions
agent_executable="$agent_directory/codex-acp"
bundled_bwrap="$agent_directory/codex-resources/bwrap"
if [[ -L "$agent_executable" || ! -f "$agent_executable" || \
      -L "$bundled_bwrap" || ! -f "$bundled_bwrap" ]]; then
  echo "pinned codex-acp archive omitted a real expected file" >&2
  exit 1
fi
read -r actual_executable_sha256 _ < <(sha256sum -- "$agent_executable")
read -r actual_bundled_bwrap_sha256 _ < <(sha256sum -- "$bundled_bwrap")
if [[ "$actual_executable_sha256" != "$CODEX_ACP_EXECUTABLE_SHA256" ||
      "$actual_bundled_bwrap_sha256" != "$CODEX_ACP_BUNDLED_BWRAP_SHA256" ]]; then
  echo "pinned codex-acp extracted file digest mismatch" >&2
  exit 1
fi
chmod 755 "$agent_executable" "$bundled_bwrap"

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
  scripts/support/AcpCompatibilityAuthenticationProbe.java

java -cp "$support_classes:$distribution_lib/*" AcpCompatibilityFailureSummaryControls \
  >"$result_directory/failure-summary-controls.json"

config_file="$result_directory/config.json"
java -cp "$support_classes:$distribution_lib/*" AcpCompatibilityProvisioner \
  "$agent_executable" \
  "$gate_helper" \
  "codex-acp-$CODEX_ACP_VERSION" \
  "$config_file"
executable_manifest_sha256=$(scripts/calculate-acp-runtime-manifest.sh "$agent_executable")

workspace="$work_directory/workspace"
mkdir -m 700 "$workspace"
evidence_file="$result_directory/evidence.json"
java -cp "$support_classes:$distribution_lib/*" AcpCompatibilityAuthenticationProbe \
  "$config_file" \
  "$evidence_file" \
  "$workspace" \
  "$executable_manifest_sha256"

(
  cd "$result_directory"
  sha256sum target.properties failure-summary-controls.json config.json evidence.json >ARTIFACTS.sha256
)
echo "ACP codex-acp authentication evidence: $result_directory"
