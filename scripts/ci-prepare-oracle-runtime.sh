#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: scripts/ci-prepare-oracle-runtime.sh" >&2
  exit 64
fi

: "${GITHUB_ENV:?GITHUB_ENV must name the GitHub Actions environment file}"
: "${GITHUB_PATH:?GITHUB_PATH must name the GitHub Actions path file}"
: "${JAVA_HOME:?JAVA_HOME must name the setup-java JDK}"
for output_file in "$GITHUB_ENV" "$GITHUB_PATH"; do
  if [[ ! -f "$output_file" || ! -w "$output_file" ]]; then
    echo "GitHub Actions environment and path files must be writable regular files" >&2
    exit 1
  fi
done

for command in chmod chown cp find install realpath stat sudo; do
  command -v "$command" >/dev/null || {
    echo "required oracle runtime provisioning command is unavailable: $command" >&2
    exit 1
  }
done

trusted_java_home=/opt/decomp-oracle-ci-java
source_java_home="$(realpath -e -- "$JAVA_HOME")"
if [[ ! -x "$source_java_home/bin/java" || ! -x "$source_java_home/bin/javac" ]]; then
  echo "setup-java did not provide a complete JDK" >&2
  exit 1
fi
if [[ -e "$trusted_java_home" || -L "$trusted_java_home" ]]; then
  echo "trusted oracle JDK provisioning target already exists" >&2
  exit 1
fi

require_trusted_directory() {
  local directory="$1"
  if [[ ! -d "$directory" || -L "$directory" ||
    "$(stat --format='%u' -- "$directory")" != 0 ]]; then
    echo "oracle runtime ancestor is not a root-owned real directory: $directory" >&2
    exit 1
  fi
  local mode
  mode="$(stat --format='%a' -- "$directory")"
  if (((8#$mode & 8#022) != 0)); then
    echo "oracle runtime ancestor permits untrusted writes: $directory" >&2
    exit 1
  fi
}

for ancestor in / /opt /usr; do
  require_trusted_directory "$ancestor"
done

declare -A runtime_roots=()
for destination in /lib /lib64 /usr/lib /usr/lib64; do
  if [[ ! -d "$destination" ]]; then
    continue
  fi
  runtime_root="$(realpath -e -- "$destination")"
  case "$runtime_root" in
    /lib|/lib64|/usr/lib|/usr/lib64) ;;
    *)
      echo "unexpected fixed oracle library root: $destination -> $runtime_root" >&2
      exit 1
      ;;
  esac
  runtime_roots["$runtime_root"]=1
done
if ((${#runtime_roots[@]} == 0)); then
  echo "host has no fixed oracle system-library runtime roots" >&2
  exit 1
fi

sudo -n install -d -o root -g root -m 0700 -- "$trusted_java_home"
sudo -n cp --archive --no-preserve=ownership,links -- \
  "$source_java_home/." "$trusted_java_home/"
sudo -n chmod 0700 -- "$trusted_java_home"
runtime_roots["$trusted_java_home"]=1

for runtime_root in "${!runtime_roots[@]}"; do
  echo "Provisioning root-owned oracle runtime: $runtime_root"
  sudo -n find -P "$runtime_root" \
    \( ! -uid 0 -o \( ! -type l -perm /022 \) \) \
    -printf 'First prior trust mismatch: uid=%U mode=%m path=%p\n' -quit
  sudo -n chown --no-dereference --recursive root:root -- "$runtime_root"
  sudo -n find -P "$runtime_root" ! -type l -perm /022 -exec chmod go-w -- {} +
  remaining_mismatch="$(sudo -n find -P "$runtime_root" \
    \( ! -uid 0 -o \( ! -type l -perm /022 \) \) \
    -printf 'uid=%U mode=%m path=%p\n' -quit)"
  if [[ -n "$remaining_mismatch" ]]; then
    echo "oracle runtime retained an untrusted entry: $remaining_mismatch" >&2
    exit 1
  fi
done

sudo -n chmod 0755 -- "$trusted_java_home"
"$trusted_java_home/bin/java" -version
"$trusted_java_home/bin/javac" -version
printf 'JAVA_HOME=%s\n' "$trusted_java_home" >>"$GITHUB_ENV"
printf '%s/bin\n' "$trusted_java_home" >>"$GITHUB_PATH"
