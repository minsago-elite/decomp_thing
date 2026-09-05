#!/usr/bin/env bash
# Build-only Node provisioner shared by CI and Docker. Never changes a runtime image.
# Update these pins, frontend/package{,-lock}.json, .node-version and the reviewed
# official archive checksums together. No system Node/npm or moving release fallback.
set -euo pipefail

frontend_node_version=24.20.0
frontend_npm_version=11.19.0
frontend_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
frontend_repo_root=$(dirname -- "$frontend_script_dir")

if [[ $# != 1 || "$1" != /* || "$1" == / || "$1" == */ ]]; then
  echo "usage: scripts/install-frontend-node.sh <absolute-absent-install-directory>" >&2
  exit 2
fi
frontend_destination=$1
if [[ -e "$frontend_destination" || -L "$frontend_destination" ]]; then
  echo "frontend Node destination already exists; use a fresh build-tool directory: $frontend_destination" >&2
  exit 2
fi
frontend_parent=$(dirname -- "$frontend_destination")
if [[ ! -d "$frontend_parent" ]]; then
  echo "create the frontend Node destination's parent directory first: $frontend_parent" >&2
  exit 2
fi
for frontend_command in curl sha256sum tar mktemp awk uname; do
  if ! command -v "$frontend_command" >/dev/null 2>&1; then
    echo "frontend Node installation requires $frontend_command" >&2
    exit 2
  fi
done
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) frontend_arch=x64 ;;
  Linux/aarch64|Linux/arm64) frontend_arch=arm64 ;;
  *) echo "frontend Node installer supports Linux x86-64 and arm64 build hosts" >&2; exit 2 ;;
esac
frontend_archive="node-v${frontend_node_version}-linux-${frontend_arch}.tar.gz"
frontend_sha256=$(awk -v archive="$frontend_archive" '$2 == archive { print $1 }' \
  "$frontend_script_dir/frontend-node-sha256.txt")
if [[ ! "$frontend_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "missing or duplicate reviewed checksum for $frontend_archive" >&2
  exit 2
fi
frontend_stage=$(mktemp -d "$frontend_parent/.decomp-frontend-node.XXXXXX")
trap 'rm -rf -- "$frontend_stage"' EXIT

curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --tlsv1.2 --retry 3 --connect-timeout 15 --max-time 180 \
  "https://nodejs.org/download/release/v${frontend_node_version}/${frontend_archive}" \
  --output "$frontend_stage/$frontend_archive"
(
  cd -- "$frontend_stage"
  printf '%s  %s\n' "$frontend_sha256" "$frontend_archive" | sha256sum --check --strict
)
tar --extract --gzip --no-same-owner --file "$frontend_stage/$frontend_archive" \
  --directory "$frontend_stage"
frontend_extracted="$frontend_stage/node-v${frontend_node_version}-linux-${frontend_arch}"

# Validate the downloaded tool itself and every declared toolchain pin before
# publishing an installation. This uses the authenticated Node binary, not PATH.
"$frontend_extracted/bin/node" --input-type=module - \
  "$frontend_repo_root" "$frontend_node_version" "$frontend_npm_version" <<'NODE'
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
const [root, nodeVersion, npmVersion] = process.argv.slice(2);
const pkg = JSON.parse(readFileSync(join(root, 'frontend/package.json'), 'utf8'));
assert.equal(process.versions.node, nodeVersion, 'downloaded Node version differs from pin');
assert.equal(readFileSync(join(root, '.node-version'), 'utf8').trim(), nodeVersion, '.node-version differs from installer');
assert.equal(pkg.engines.node, nodeVersion, 'frontend Node engine differs from installer');
assert.equal(pkg.engines.npm, npmVersion, 'frontend npm engine differs from installer');
assert.equal(pkg.packageManager, `npm@${npmVersion}`, 'frontend package manager differs from installer');
NODE
if [[ "$("$frontend_extracted/bin/node" "$frontend_extracted/lib/node_modules/npm/bin/npm-cli.js" --version)" != "$frontend_npm_version" ]]; then
  echo "downloaded npm version differs from the reviewed pin" >&2
  exit 1
fi
mv -T --no-clobber -- "$frontend_extracted" "$frontend_destination"
if [[ -e "$frontend_extracted" ]]; then
  echo "frontend Node destination appeared during installation; existing state was preserved" >&2
  exit 1
fi
printf 'Installed build-only Node %s / npm %s at %s\n' \
  "$frontend_node_version" "$frontend_npm_version" "$frontend_destination"
