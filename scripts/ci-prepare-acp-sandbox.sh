#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: scripts/ci-prepare-acp-sandbox.sh" >&2
  exit 64
fi

: "${GITHUB_ENV:?GITHUB_ENV must name the GitHub Actions environment file}"
if [[ ! -f "$GITHUB_ENV" || ! -w "$GITHUB_ENV" ]]; then
  echo "GITHUB_ENV must be an existing writable regular file" >&2
  exit 1
fi

for command in id loginctl sleep stat sudo systemctl systemd-run timeout; do
  command -v "$command" >/dev/null || {
    echo "required ACP sandbox host command is unavailable: $command" >&2
    exit 1
  }
done
if [[ ! -x /usr/bin/true ]]; then
  echo "required ACP sandbox probe executable is unavailable: /usr/bin/true" >&2
  exit 1
fi

user_name="$(id -un)"
user_id="$(id -u)"
runtime_directory="/run/user/$user_id"
bus_path="$runtime_directory/bus"

timeout --kill-after=5s 20s sudo -n loginctl enable-linger "$user_name"
timeout --kill-after=5s 20s sudo -n \
  systemctl start "user-runtime-dir@$user_id.service" "user@$user_id.service"

bus_ready=false
for ((_attempt = 0; _attempt < 30; _attempt++)); do
  if [[ -d "$runtime_directory" && -S "$bus_path" ]]; then
    bus_ready=true
    break
  fi
  sleep 1
done
if [[ "$bus_ready" != true ]]; then
  timeout --kill-after=5s 10s sudo -n \
    systemctl --no-pager --full status "user@$user_id.service" >&2 || true
  echo "systemd user D-Bus did not become ready within 30 seconds" >&2
  exit 1
fi
if [[ -L "$runtime_directory" || -L "$bus_path" ]]; then
  echo "systemd user runtime directory and D-Bus must not be symbolic links" >&2
  exit 1
fi

if [[ "$(stat --format='%u' "$runtime_directory")" != "$user_id" ]]; then
  echo "systemd user runtime directory has the wrong owner" >&2
  exit 1
fi
if [[ "$(stat --format='%a' "$runtime_directory")" != 700 ]]; then
  echo "systemd user runtime directory must have exact mode 0700" >&2
  exit 1
fi
if [[ "$(stat --format='%u' "$bus_path")" != "$user_id" ]]; then
  echo "systemd user D-Bus has the wrong owner" >&2
  exit 1
fi
if [[ ! -f /sys/fs/cgroup/cgroup.controllers || ! -r /sys/fs/cgroup/cgroup.controllers ]]; then
  echo "ACP contract tests require a readable cgroup v2 controller file" >&2
  exit 1
fi
cgroup_controllers=" $(</sys/fs/cgroup/cgroup.controllers) "
for controller in cpu memory pids; do
  if [[ "$cgroup_controllers" != *" $controller "* ]]; then
    echo "ACP contract tests require the cgroup v2 $controller controller" >&2
    exit 1
  fi
done

export XDG_RUNTIME_DIR="$runtime_directory"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$bus_path"

manager_version="$(timeout --kill-after=5s 10s systemctl --user show --property=Version --value)"
if ((${#manager_version} == 0 || ${#manager_version} > 128)) ||
  [[ ! "$manager_version" =~ ^[0-9][0-9A-Za-z.+~:_-]*$ ]]; then
  echo "systemd user manager returned an invalid version: $manager_version" >&2
  exit 1
fi

probe_unit="decomp-acp-contract-probe-$user_id-$$"
cleanup_probe() {
  timeout --kill-after=5s 10s systemctl --user stop "$probe_unit.scope" >/dev/null 2>&1 || true
}
trap cleanup_probe EXIT
# The parent user manager owns controller delegation; the production child scope is deliberately
# non-delegating and verifies this exact property before opening the sandbox gate.
timeout --kill-after=5s 20s systemd-run \
  --user \
  --scope \
  --quiet \
  --collect \
  --expand-environment=no \
  --unit="$probe_unit" \
  --property=TasksMax=16 \
  --property=MemoryMax=536870912 \
  --property=MemorySwapMax=0 \
  --property=OOMPolicy=kill \
  --property=CPUQuota=100% \
  --property=KillMode=control-group \
  --property=SendSIGKILL=yes \
  --property=RuntimeMaxSec=20s \
  --property=TimeoutStopSec=3s \
  --property=Delegate=no \
  -- \
  /usr/bin/true
cleanup_probe
trap - EXIT

{
  printf 'XDG_RUNTIME_DIR=%s\n' "$XDG_RUNTIME_DIR"
  printf 'DBUS_SESSION_BUS_ADDRESS=%s\n' "$DBUS_SESSION_BUS_ADDRESS"
  printf 'DECOMP_REQUIRE_LIVE_ACP_CONTRACT=1\n'
} >>"$GITHUB_ENV"
