#!/usr/bin/env bash
# Host orchestration only. Installed Kotlin owns provisioning authentication, both contained
# captures, exact frozen-byte comparison, independent replay and the qualification report.
set -euo pipefail

if (($# != 1)) || [[ ! "$1" =~ ^(capture|collect|cleanup)$ ]]; then
  echo 'usage: scripts/ci-qualify-gcc-metadata-reference.sh <capture|collect|cleanup>' >&2
  exit 64
fi
mode="$1"
project_root="$(cd "$(dirname "$0")/.." && pwd -P)"
work="$project_root/build/gcc-metadata-reference"
evidence="$work/evidence"
private="$work/private"
[[ "$(realpath -m -- "$work")" == "$work" && "$(realpath -m -- "$evidence")" == "$evidence" ]]
trusted_java=/var/lib/decomp-oracle-ci-java
: "${GITHUB_RUN_ID:?GitHub run identity is required}"
: "${GITHUB_RUN_ATTEMPT:?GitHub run attempt is required}"
[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,19}$ && "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,19}$ ]]
[[ "${GITHUB_ACTIONS:-}" == true ]]
[[ "${DECOMP_GCC_METADATA_EVIDENCE_ROOT:-$evidence}" == "$evidence" ]]
installation="/var/lib/decomp-ci-application-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT/bundle"
if [[ -n "${DECOMP_GCC_CLI_INSTALLATION:-}" && "$DECOMP_GCC_CLI_INSTALLATION" != "$installation" ]]; then
  echo 'metadata qualification refuses an unexpected installed application' >&2
  exit 1
fi
extension="$installation/libexec/gcc-metadata-reference"
native="$extension/native"
deployment="$extension/deployment.json"
owner="$extension/ci-owner.txt"
first=/var/lib/decomp-gcc-metadata-reference-first-ci/scratch
replay=/var/lib/decomp-gcc-metadata-reference-replay-ci/scratch

require_private_directory() {
  local selected="$1"
  [[ -d "$selected" && ! -L "$selected" && "$(realpath -e -- "$selected")" == "$selected" ]] || return 1
  [[ "$(stat --format='%u:%g:%a' -- "$selected")" == '0:0:700' ]]
}
require_trusted_directory() {
  local selected="$1" selected_mode
  [[ -d "$selected" && ! -L "$selected" && "$(realpath -e -- "$selected")" == "$selected" ]] || return 1
  [[ "$(stat --format='%u' -- "$selected")" == 0 ]] || return 1
  selected_mode="$(stat --format='%a' -- "$selected")"
  (((8#$selected_mode & 8#022) == 0))
}
owner_text() {
  printf 'decomp-gcc-metadata-reference-ci-v1\nrun_id=%s\nrun_attempt=%s\ninstallation=%s\n' \
    "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$installation"
}
require_extension_owner() {
  require_private_directory "$extension"
  sudo -n test -f "$owner"
  ! sudo -n test -L "$owner"
  [[ "$(sudo -n stat --format='%u:%g:%a:%h' -- "$owner")" == '0:0:600:1' ]]
  [[ "$(sudo -n cat -- "$owner")" == "$(owner_text)" ]]
}

if [[ "$mode" == collect ]]; then
  mkdir -p "$evidence"
  collection_errors=0
  : > "$evidence/collection-errors.log"
  collect_item() {
    local label="$1" status
    shift
    if "$@"; then return 0; else status=$?; fi
    collection_errors=$((collection_errors + 1))
    printf '%s failed (exit %s)\n' "$label" "$status" | tee -a "$evidence/collection-errors.log" >&2
  }
  collect_capacity() {
    df -h "$2" && df -i "$2" && findmnt --json --target "$2"
  }
  # Each source is independent. Preserve all obtainable records even if a failed capture left
  # changing files or one archive fails; a nonzero final status forbids trusted scratch reset.
  if sudo -n test -d "$private"; then
    if require_private_directory "$private"; then
      collect_item 'private journals and controller records' sudo -n tar --one-file-system --numeric-owner --acls --xattrs \
        -czf "$evidence/private-records.tar.gz" -C "$private" .
      if sudo -n test -f "$private/report/qualification.json"; then
        collect_item 'qualification report' sudo -n install -o "$(id -u)" -g "$(id -g)" -m 0644 \
          "$private/report/qualification.json" "$evidence/qualification.json"
      fi
    else
      collection_errors=$((collection_errors + 1))
      printf '%s\n' 'private record root failed its owner/path checks' >> "$evidence/collection-errors.log"
    fi
  fi
  for selected in first replay; do
    selected_mount="$first"
    if [[ "$selected" == replay ]]; then selected_mount="$replay"; fi
    if mountpoint --quiet "$selected_mount"; then
      collect_item "$selected scratch records" sudo -n tar --one-file-system --numeric-owner --acls --xattrs \
        -czf "$evidence/$selected-scratch.tar.gz" -C "$selected_mount" .
      collect_item "$selected scratch host state" collect_capacity "$selected" "$selected_mount" \
        > "$evidence/$selected-scratch-host.txt"
    fi
  done
  if sudo -n test -f "$deployment"; then
    collect_item 'trusted deployment' sudo -n install -o "$(id -u)" -g "$(id -g)" -m 0644 "$deployment" "$evidence/deployment.json"
  fi
  if [[ -f "$installation/lib/kotlin-boot-classpath-reference-v1.json" ]]; then
    collect_item 'installed classpath reference' cp -- "$installation/lib/kotlin-boot-classpath-reference-v1.json" \
      "$evidence/installed-classpath-reference.json"
  fi
  # Finalize even partial archives before upload. This runs independently of earlier failures.
  for archive in "$evidence"/*.tar.gz; do
    [[ -e "$archive" ]] || continue
    collect_item "archive owner $archive" sudo -n chown "$(id -u):$(id -g)" -- "$archive"
    collect_item "archive permissions $archive" sudo -n chmod 0644 -- "$archive"
  done
  write_artifact_digests() (
    cd "$evidence" || exit 1
    shopt -s nullglob
    files=(*.json *.log *.tar.gz *.env *-host.txt)
    ((${#files[@]} > 0)) || exit 1
    sha256sum -- "${files[@]}"
  )
  collect_item 'evidence digest manifest' write_artifact_digests > "$evidence/artifact-sha256.txt"
  ((collection_errors == 0))
  exit
fi

if [[ "$mode" == cleanup ]]; then
  require_extension_owner
  sudo -n test -f "$private/report/qualification.json"
  for selected_mount in "$first" "$replay"; do
    if mountpoint --quiet "$selected_mount"; then
      echo 'metadata runtime cleanup requires both dedicated scratch mounts to be released first' >&2
      exit 1
    fi
  done
  # This is the fresh, run-marked extension inside the existing application installation. No
  # profile inputs, journals, scratch evidence or unrelated runner paths are removed here.
  sudo -n rm -rf --one-file-system -- "$extension"
  [[ ! -e "$extension" && ! -L "$extension" ]]
  exit 0
fi

: "${DECOMP_GCC_CLI_INSTALLATION:?existing installed application is required}"
[[ "${DECOMP_GCC_METADATA_FIRST_SCRATCH:-}" == "$first" ]]
[[ "${DECOMP_GCC_METADATA_REPLAY_SCRATCH:-}" == "$replay" ]]
[[ "${QUALIFICATION_REF:-}" =~ ^[0-9a-f]{40}$ ]]
[[ "$(git -C "$project_root" rev-parse HEAD)" == "$QUALIFICATION_REF" ]]
for command in jq skopeo sudo timeout mountpoint realpath stat; do command -v "$command" >/dev/null; done
require_trusted_directory "$installation"
require_trusted_directory "$installation/libexec"
require_trusted_directory "$trusted_java"
require_private_directory "$first"
require_private_directory "$replay"
[[ "$(stat --format='%d' -- "$first")" != "$(stat --format='%d' -- "$replay")" ]]
[[ ! -e "$extension" && ! -L "$extension" && ! -e "$private" && ! -L "$private" ]]
mkdir -p "$evidence" "$work/tmp"
umask 077

# Two transport-only copies make decompression explicit. The second preserves the exact config
# and uncompressed diffIDs; Kotlin independently authenticates every OCI input before extraction.
# No container, image executable, reconstructed candidate or Python oracle is run here.
image='docker://docker.io/library/gcc@sha256:2e6f4ae27ab8ad6f9617b46f0468889d368fdd91f2ea29aff98e4d5d1a3637f0'
[[ ! -e "$work/transport-dir" && ! -e "$work/oci" ]]
timeout --kill-after=10s 15m skopeo --override-os linux --override-arch amd64 copy \
  --retry-times 2 --src-no-creds --dest-decompress "$image" "dir:$work/transport-dir" \
  2>&1 | tee "$evidence/image-transport.log"
timeout --kill-after=10s 10m skopeo copy --dest-oci-accept-uncompressed-layers \
  "dir:$work/transport-dir" "oci:$work/oci:gcc" \
  2>&1 | tee -a "$evidence/image-transport.log"

reference="$installation/lib/kotlin-boot-classpath-reference-v1.json"
mapfile -t jar_names < <(jq -er '.entries[].logicalName' "$reference")
((${#jar_names[@]} > 0 && ${#jar_names[@]} <= 512))
classpath=''
for name in "${jar_names[@]}"; do
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,250}\.jar$ ]]
  [[ -f "$installation/lib/$name" && ! -L "$installation/lib/$name" ]]
  classpath+="${classpath:+:}$installation/lib/$name"
done
# The installed entrypoint authenticates this exact ordered classpath against the retained sidecar.
# Shell discovery alone supplies neither installed controller authority nor worker approval.
sudo -n install -d -o root -g root -m 0700 -- "$extension" "$private" \
  "$private/home" "$private/tmp" "$private/report" "$private/journals" \
  "$private/journals/first" "$private/journals/replay"
owner_text | sudo -n tee "$owner" >/dev/null
sudo -n chmod 0600 -- "$owner"
require_extension_owner

java=("$trusted_java/bin/java" -Xms64m -Xmx3g -XX:-UsePerfData -XX:+DisableAttachMechanism
  "-Djava.io.tmpdir=$private/tmp" "-Duser.home=$private/home"
  -Djna.nosys=true -Djna.nounpack=true "-Djna.boot.library.path=$trusted_java/lib/decomp-oracle-native"
  "-Dorg.sqlite.lib.path=$trusted_java/lib/decomp-oracle-native" -Dorg.sqlite.lib.name=libsqlitejdbc.so
  -cp "$classpath" decompengine.oracle.gcc.GccMetadataReferenceQualificationCli)
run_installed() {
  sudo -n env -i HOME="$private/home" TMPDIR="$private/tmp" USER=root LOGNAME=root \
    PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    XDG_RUNTIME_DIR=/run/user/0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus \
    "${java[@]}" "$@"
}
run_installed provision "$project_root/oracle/gcc/16.2.0" "$work/oci" "$native" "$trusted_java" "$deployment" \
  2>&1 | tee "$evidence/provision.log"
run_installed qualify "$project_root/oracle/gcc/16.2.0" "$work/oci" "$native" "$deployment" \
  "$private/journals/first" "$first" "$private/journals/replay" "$replay" "$private/report/qualification.json" \
  2>&1 | tee "$evidence/qualification.log"
sudo -n test -s "$private/report/qualification.json"
