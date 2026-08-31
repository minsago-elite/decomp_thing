#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if (($# != 0)); then
  echo "usage: scripts/ci-qualify-goose-acp.sh" >&2
  exit 64
fi
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "the pinned Goose ACP qualification target requires Linux x86-64" >&2
  exit 1
fi

readonly GOOSE_VERSION="1.46.0"
readonly GOOSE_ARCHIVE="goose-x86_64-unknown-linux-gnu.tar.bz2"
readonly GOOSE_ARCHIVE_URL="https://github.com/block/goose/releases/download/v${GOOSE_VERSION}/${GOOSE_ARCHIVE}"
readonly GOOSE_ARCHIVE_SHA256="a1cf4856a765d07d6b95689a53c7bca21fcc6e6d65c0dfd064fc704052b85a7b"

for required_command in bzip2 curl javac java ldd sha256sum tar; do
  command -v "$required_command" >/dev/null || {
    echo "missing ACP compatibility command: $required_command" >&2
    exit 1
  }
done

compatibility_root="$(pwd)/build/acp-compatibility"
mkdir -p "$compatibility_root/results" "$compatibility_root/work"
work_directory=$(mktemp -d "$compatibility_root/work/goose-${GOOSE_VERSION}.XXXXXX")
result_directory=$(mktemp -d "$compatibility_root/results/goose-${GOOSE_VERSION}.XXXXXX")
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

./gradlew --no-daemon installDist

archive_path="$work_directory/$GOOSE_ARCHIVE"
curl \
  --fail \
  --location \
  --proto '=https' \
  --retry 3 \
  --show-error \
  --silent \
  --tlsv1.2 \
  --output "$archive_path" \
  "$GOOSE_ARCHIVE_URL"
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
  scripts/support/AcpCompatibilityProvisioner.java \
  scripts/support/AcpCompatibilityPreflight.java

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
  sha256sum target.properties config.json evidence.json >ARTIFACTS.sha256
)
echo "ACP compatibility evidence: $result_directory"
