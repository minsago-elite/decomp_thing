#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mode="${1:-acp}"
case "$mode" in
  acp)
    if [[ $# -ne 0 ]]; then
      echo "usage: $0 [browser <browser-dependencies-file>]" >&2
      exit 2
    fi
    ;;
  browser)
    if [[ $# -ne 2 || ! -r "$2" ]]; then
      echo "usage: $0 browser <readable-browser-dependencies-file>" >&2
      exit 2
    fi
    mapfile -t web_browser_dependencies < "$2"
    if ((${#web_browser_dependencies[@]} == 0)); then
      echo "browser dependency file is empty: $2" >&2
      exit 2
    fi
    for dependency in "${web_browser_dependencies[@]}"; do
      if [[ ! "$dependency" =~ [^[:space:]] ]]; then
        echo "browser dependency file contains an empty expression: $2" >&2
        exit 2
      fi
    done
    ;;
  *)
    echo "usage: $0 [browser <browser-dependencies-file>]" >&2
    exit 2
    ;;
esac

apt_root="$repo_root/build/acp-host-apt"
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg

# Use a fresh package index for both the refresh and installation.
mkdir -p "$apt_root"
work_dir="$(mktemp -d "$apt_root/run.XXXXXXXX")"
# APT may leave root-owned partial downloads on failure. Let _apt traverse its scratch directory.
trap 'sudo rm -rf -- "$work_dir"' EXIT
chmod 0755 "$work_dir"
sources_file="$work_dir/ubuntu.sources.list"
lists_dir="$work_dir/lists"
mkdir -p "$lists_dir/partial"

cat > "$sources_file" <<SOURCES
# Ubuntu 24.04 hosted runners are amd64 and use the Ubuntu archive signing key.
deb [arch=amd64 signed-by=$keyring] http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse
deb [arch=amd64 signed-by=$keyring] http://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse
deb [arch=amd64 signed-by=$keyring] http://archive.ubuntu.com/ubuntu noble-backports main restricted universe multiverse
deb [arch=amd64 signed-by=$keyring] http://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse
SOURCES

apt_options=(
  -o "Dir::Etc::sourcelist=$sources_file"
  -o 'Dir::Etc::sourceparts=-'
  -o 'APT::Update::Error-Mode=any'
  -o "Dir::State::lists=$lists_dir"
)
sudo apt-get "${apt_options[@]}" update

if [[ "$mode" == browser ]]; then
  sudo apt-get "${apt_options[@]}" satisfy -y --no-install-recommends "${web_browser_dependencies[@]}"
  sudo apt-get "${apt_options[@]}" install -y --no-install-recommends xvfb
else
  sudo apt-get "${apt_options[@]}" install -y --no-install-recommends \
    bubblewrap binutils build-essential dbus-user-session python3 systemd util-linux
fi
