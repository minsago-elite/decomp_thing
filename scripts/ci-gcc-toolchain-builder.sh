#!/usr/bin/env bash
# Isolated CI-only GCC image builder/importer. All mutable state lives below BUILD_ROOT.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin

repo="$(git rev-parse --show-toplevel)"
repo="$(realpath -e "$repo")"
build_root="$repo/build/g"
[[ ! -L "$repo/build" && ! -L "$build_root" ]] || { echo 'refuse linked repository build root' >&2; exit 1; }
canonical_build_root="$(realpath -m "$build_root")"
[[ "$canonical_build_root" == "$repo"/* ]] || { echo 'refuse build root outside repository' >&2; exit 1; }
run_id="${GITHUB_RUN_ID:-local}"
run_attempt="${GITHUB_RUN_ATTEMPT:-1}"
[[ "$run_id" =~ ^[A-Za-z0-9._-]{1,80}$ && "$run_attempt" =~ ^[0-9]{1,8}$ ]] || { echo 'invalid owned run identity' >&2; exit 1; }
short_id="$(printf '%s\0%s\0%s\0%s\0%s' "$run_id" "$run_attempt" "${GITHUB_JOB:-provenance}" "$(git rev-parse HEAD)" "$repo" | sha256sum | cut -c1-8)"
job_root="$build_root/$short_id"
volume="$job_root/v"
tools="$volume/tools"
state="$volume/s"
evidence="$job_root/evidence"
docker_bin="$tools/docker/docker"
daemon_bin="$tools/docker/dockerd"
buildctl="$tools/buildkit/bin/buildctl"
buildkitd="$tools/buildkit/bin/buildkitd"
socket="$job_root/d.sock"
bk_socket="$job_root/b.sock"
tag=decomp-gcc-oracle-toolchain:16.2.0
docker_hash=803d433f226db4776e1768fd319fc6c6e4935a456acf84fcc0080818b854bc8f
rootless_hash=15a5cb81f2c5cf15ea21427f2e8241eac0deb2221175f993b5e76926e705ec6a
buildkit_hash=f64589601e0f06164041dc6be45ed259cffb67539130e434d236551d63ab6030

die() { echo "gcc-builder: $*" >&2; exit 1; }
validate_socket_inventory() {
  local path
  # These are the only filesystem sockets enabled by this helper and pinned tools.
  # Validate the longest generated endpoints before creating owner intent or a service.
  for path in "$socket" "$bk_socket" "$job_root/r/api.sock" \
    "$job_root/x/containerd/containerd.sock" "$job_root/x/containerd/containerd.sock.ttrpc" \
    "$job_root/t/runc-console.sock"; do
    (( ${#path} <= 107 )) || die "generated Unix socket path exceeds 107 bytes: $path"
  done
}
bounded_stream() {
  python3 scripts/ci-gcc-toolchain-archive.py stream "$1" "${2:-67108864}"
}
owner_call() {
  python3 scripts/ci-gcc-toolchain-owner.py "$@"
}
need_owned_path() {
  case "$1" in "$job_root"|"$job_root"/*) ;; *) die "path escaped owned root: $1" ;; esac
  local canonical
  canonical="$(realpath -m "$1")"
  [[ "$canonical" == "$(realpath -m "$job_root")" || "$canonical" == "$(realpath -m "$job_root")"/* ]] || die "canonical path escaped owned root: $1"
}
clean_environment() {
  unset DOCKER_HOST DOCKER_CONTEXT BUILDKIT_HOST BUILDKIT_DEBUG_FORCE_OVERLAY_DIFF \
    BUILDKIT_DEBUG_FORCE_NETWORK_DRIVER BUILDKIT_DISABLE_CACHE_EXPORTS DOCKERD \
    _DOCKERD_ROOTLESS_CHILD _DOCKERD_ROOTLESS_SELINUX ROOTLESSKIT_FLAGS \
    ROOTLESSKIT_DETACH_NETNS LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH BASH_ENV ENV SHELLOPTS || true
  export DOCKER_CONFIG="$volume/docker-config"
  install -d -m 700 "$DOCKER_CONFIG"
}
monotonic_remaining() {
  python3 -c 'import sys,time; print(max(0.0, float(sys.argv[1])-time.monotonic()))' "$1"
}
deadline_open() {
  python3 -c 'import sys; print(1 if float(sys.argv[1]) > 0 else 0)' "$1"
}
bounded_call_seconds() {
  python3 -c 'import sys; print(min(5.0, float(sys.argv[1])))' "$1"
}
run_worker_call() {
  local call_timeout=$1
  shift
  timeout --signal=TERM --kill-after=1s "$call_timeout" "$buildctl" --addr "unix://$bk_socket" "$@"
}
bounded_curl() {
  curl --fail --silent --show-error --location --connect-timeout 15 --max-time 240 --max-filesize 536870912 \
    --retry 0 "$1" --output "$2"
}
check_archive() {
  local file=$1 size=$2 hash=$3
  test -f "$file" && test ! -L "$file" || die "missing/linked archive: $file"
  test "$(stat -c %s "$file")" = "$size" || die "archive size mismatch: $file"
  echo "$hash  $file" | sha256sum --check --status || die "archive authentication failed: $file"
}
check_executable() {
  local file=$1 size=$2 hash=$3
  [[ -f "$file" && ! -L "$file" && -x "$file" ]] || die "missing, linked, or non-executable tool: $file"
  test "$(stat -c %s "$file")" = "$size" || die "pinned tool size mismatch: $file"
  echo "$hash  $file" | sha256sum --check --status || die "pinned tool digest mismatch: $file"
}
capture_ambient_identity() {
  install -d -m 700 "$job_root/ambient-client"
  {
    printf 'classification=read-only ambient host identity; never used for reproduction or execution\n'
    printf 'runner.os=%s runner.arch=%s ImageOS=%s ImageVersion=%s\n' \
      "${RUNNER_OS:-unknown}" "${RUNNER_ARCH:-unknown}" "${ImageOS:-unknown}" "${ImageVersion:-unknown}"
    if [[ -x /usr/bin/docker ]]; then
      if timeout --signal=TERM --kill-after=1s 5s env -u DOCKER_HOST -u DOCKER_CONTEXT \
        DOCKER_CONFIG="$job_root/ambient-client" /usr/bin/docker --context default version \
        --format 'client={{.Client.Version}} server={{.Server.Version}} serverCommit={{.Server.GitCommit}}'; then :; else
        printf 'ambient docker version unavailable status=%s\n' "$?"
      fi
      if timeout --signal=TERM --kill-after=1s 5s env -u DOCKER_HOST -u DOCKER_CONTEXT \
        DOCKER_CONFIG="$job_root/ambient-client" /usr/bin/docker --context default info \
        --format 'name={{.Name}} driver={{.Driver}} root={{.DockerRootDir}} kernel={{.KernelVersion}}'; then :; else
        printf 'ambient docker info unavailable status=%s\n' "$?"
      fi
      if timeout --signal=TERM --kill-after=1s 5s env -u DOCKER_HOST -u DOCKER_CONTEXT \
        DOCKER_CONFIG="$job_root/ambient-client" /usr/bin/docker --context default buildx inspect; then :; else
        printf 'ambient buildx identity unavailable status=%s\n' "$?"
      fi
    else
      printf 'ambient docker client unavailable\n'
    fi
  } > "$evidence/ambient-host-identity.txt" 2>&1
}
safe_extract() {
  local archive=$1 destination=$2
  python3 - "$archive" "$destination" <<'PY'
import pathlib, sys, tarfile
archive, dest = map(pathlib.Path, sys.argv[1:])
root = dest.resolve()
with tarfile.open(archive, 'r:gz') as tf:
    members = tf.getmembers()
    if not members or len(members) > 10000:
        raise SystemExit('unsafe archive member count')
    for member in members:
        p = pathlib.PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or not p.parts:
            raise SystemExit('unsafe archive member path')
        if member.issym() or member.islnk():
            target = pathlib.PurePosixPath(member.linkname)
            if target.is_absolute() or '..' in target.parts:
                raise SystemExit('unsafe archive link')
    tf.extractall(dest, members=members, filter='data')
PY
}
init() {
  validate_socket_inventory
  if [[ -e "$job_root" ]]; then die "refusing reused/nonempty job root: $job_root"; fi
  owner_call reserve
  printf '%s\n' "run=${GITHUB_RUN_ID:-local}" "attempt=${GITHUB_RUN_ATTEMPT:-1}" \
    "revision=$(git rev-parse HEAD)" > "$job_root/owner.txt"
  install -d -m 700 "$volume" "$tools" "$state" "$job_root/source" "$job_root/tmp"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then printf 'job-root=%s\n' "$job_root" >> "$GITHUB_OUTPUT"; fi
  if [[ -n "${GITHUB_ENV:-}" ]]; then printf 'GCC_BUILDER_ROOT=%s\n' "$job_root" >> "$GITHUB_ENV"; fi
  capture_ambient_identity
  clean_environment
}
authenticate() {
  clean_environment
  local d="$tools/docker-29.7.2.tgz" r="$tools/rootless.tgz" b="$tools/buildkit.tgz"
  bounded_curl https://download.docker.com/linux/static/stable/x86_64/docker-29.7.2.tgz "$d"
  echo "$docker_hash  $d" | sha256sum --check --status || die 'Docker archive authentication failed'
  safe_extract "$d" "$tools"
  bounded_curl https://download.docker.com/linux/static/stable/x86_64/docker-rootless-extras-29.7.2.tgz "$r"
  echo "$rootless_hash  $r" | sha256sum --check --status || die 'rootless extras archive authentication failed'
  safe_extract "$r" "$tools"
  bounded_curl https://github.com/moby/buildkit/releases/download/v0.20.2/buildkit-v0.20.2.linux-amd64.tar.gz "$b"
  check_archive "$b" 82062349 "$buildkit_hash"
  install -d -m 700 "$tools/buildkit-unpack"
  safe_extract "$b" "$tools/buildkit-unpack"
  install -d -m 700 "$tools/buildkit"
  mv "$tools/buildkit-unpack/bin" "$tools/buildkit/bin"
  local rootless="$tools/docker-rootless-extras"
  check_executable "$docker_bin" 42677472 e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13
  check_executable "$daemon_bin" 99870816 c3ecdc8ac9e56b9a53ffd9fd4aece65432814597046f8d188a538be18c000df8
  test "$($docker_bin --version)" = 'Docker version 29.7.2, build a7dcaa6'
  test "$("$daemon_bin" --version)" = 'Docker version 29.7.2, build 6a43e3d'
  check_executable "$rootless/rootlesskit" 23922644 98f07e783dd6b3cd236c7865d1dce7937e645ec74a0fe2971725449af074f466
  check_executable "$rootless/dockerd-rootless.sh" 10532 904c9b9e35f6927c0a5e65afb4d35b6bc9eb1278c878044501281fc728c9be46
  echo "1c9f0dc93ebb3d75255254ec760d26a912affba7f329ab8abffe8e25eb0b3f94  $rootless/dockerd-rootless-setuptool.sh" | sha256sum --check --status
  test "$(stat -c %s "$rootless/rootlesskit")" = 23922644
  test "$(stat -c %s "$rootless/dockerd-rootless.sh")" = 10532
  test "$("$rootless/rootlesskit" --version)" = 'rootlesskit version 3.0.2'
  bash -n "$rootless/dockerd-rootless.sh" "$rootless/dockerd-rootless-setuptool.sh"
  test "$(command -v slirp4netns)" = /usr/bin/slirp4netns
  test "$(dpkg-query --show --showformat='${Version}' slirp4netns)" = 1.2.1-1build2
  test "$(slirp4netns --version | head -n 1)" = 'slirp4netns version 1.2.1'
  test "$("$buildkitd" --version)" = 'buildkitd github.com/moby/buildkit v0.20.2 97437fdd7e32f29bb80288d800cd4ffcb34e1c15'
  test "$("$buildctl" --version)" = 'buildctl github.com/moby/buildkit v0.20.2 97437fdd7e32f29bb80288d800cd4ffcb34e1c15'
  {
    printf 'docker-cli=%s\n' "$($docker_bin --version)"
    printf 'docker-daemon=%s\n' "$("$daemon_bin" --version)"
    printf 'rootlesskit=%s\n' "$("$rootless/rootlesskit" --version)"
    printf 'buildkitd=%s\n' "$("$buildkitd" --version)"
    printf 'buildctl=%s\n' "$("$buildctl" --version)"
    printf 'buildkit-archive-bytes=%s\nbuildkit-archive-sha256=%s\n' \
      "$(stat -c %s "$tools/buildkit.tgz")" "$(sha256sum "$tools/buildkit.tgz" | cut -d' ' -f1)"
    printf 'docker-archive-bytes=%s\ndocker-archive-sha256=%s\n' \
      "$(stat -c %s "$tools/docker-29.7.2.tgz")" "$(sha256sum "$tools/docker-29.7.2.tgz" | cut -d' ' -f1)"
    printf 'rootless-archive-bytes=%s\nrootless-archive-sha256=%s\n' \
      "$(stat -c %s "$tools/rootless.tgz")" "$(sha256sum "$tools/rootless.tgz" | cut -d' ' -f1)"
  } > "$evidence/tool-versions-and-archive.txt"
  sha256sum "$docker_bin" "$daemon_bin" "$rootless/rootlesskit" \
    "$buildkitd" "$buildctl" "$tools/buildkit/bin/buildkit-runc" > "$evidence/executable-sha256.txt"
}
start_rootless() {
  validate_socket_inventory
  clean_environment
  sudo -n loginctl enable-linger "$USER"
  sudo -n systemctl start "user@$(id -u).service"
  local runtime="/run/user/$(id -u)"
  test -d "$runtime"
  install -d -m 700 "$state/docker-data" "$job_root/r" "$job_root/x" "$volume/home" "$volume/docker-config"
  printf '{"features":{"containerd-snapshotter":false}}\n' > "$state/docker-daemon.json"
  owner_call launch-rootless
  local deadline
  deadline=$(python3 -c 'import time; print(time.monotonic()+60.0)')
  while :; do
    local remaining
    remaining=$(monotonic_remaining "$deadline")
    (( $(deadline_open "$remaining") )) || break
    if timeout "$(bounded_call_seconds "$remaining")" env -u DOCKER_HOST -u DOCKER_CONTEXT \
      DOCKER_CONFIG="$DOCKER_CONFIG" "$docker_bin" --host "unix://$socket" info \
      --format '{{.ServerVersion}}' >/dev/null 2>&1; then break; fi
    sleep .2
  done
  (( $(deadline_open "$(monotonic_remaining "$deadline")") )) || die 'rootless readiness deadline expired'
  local info="$evidence/docker-info.json"
  timeout --signal=TERM --kill-after=5s 30s env -u DOCKER_HOST -u DOCKER_CONTEXT \
    DOCKER_CONFIG="$DOCKER_CONFIG" "$docker_bin" --host "unix://$socket" info --format '{{json .}}' > "$info"
  python3 scripts/ci-gcc-toolchain-archive.py docker-info "$info" "$state/docker-data" "$socket" "$job_root"
  test "$(DOCKER_HOST= DOCKER_CONTEXT= "$docker_bin" --host "unix://$socket" version --format '{{.Server.Version}}')" = 29.7.2
  test "$(DOCKER_HOST= DOCKER_CONTEXT= "$docker_bin" --host "unix://$socket" version --format '{{.Server.GitCommit}}')" = 6a43e3d
  DOCKER_HOST= DOCKER_CONTEXT= "$docker_bin" --host "unix://$socket" version --format '{{json .}}' > "$evidence/docker-version.json"
  owner_call ready --role rootless > "$evidence/rootless-readiness.json"
}
start_buildkit() {
  validate_socket_inventory
  clean_environment
  cat > "$state/buildkitd.toml" <<EOF
[worker.oci]
  enabled = true
  snapshotter = "native"
  platforms = ["linux/amd64"]
  max-parallelism = 1
[worker.containerd]
  enabled = false
[grpc]
  address = ["unix://$bk_socket"]
  uid = $(id -u)
  gid = $(id -g)
EOF
  install -d -m 700 "$state/buildkit-root"
  owner_call launch-buildkit
  local deadline workers info remaining call_timeout
  deadline=$(python3 -c 'import time; print(time.monotonic()+60.0)')
  while :; do
    remaining=$(monotonic_remaining "$deadline")
    (( $(deadline_open "$remaining") )) || break
    call_timeout=$(bounded_call_seconds "$remaining")
    if run_worker_call "$call_timeout" debug workers --format '{{json .}}' >"$state/workers.json" 2>/dev/null; then
      remaining=$(monotonic_remaining "$deadline")
      (( $(deadline_open "$remaining") )) || break
      call_timeout=$(bounded_call_seconds "$remaining")
      if ! run_worker_call "$call_timeout" debug info --format '{{json .}}' >"$state/buildkit-info.txt" 2>/dev/null; then sleep .2; continue; fi
      python3 scripts/ci-gcc-toolchain-archive.py workers "$state/workers.json"
      python3 scripts/ci-gcc-toolchain-archive.py info "$state/buildkit-info.txt"
      cp "$state/workers.json" "$evidence/buildkit-workers.json"
      cp "$state/buildkit-info.txt" "$evidence/buildkit-info.txt"
      owner_call ready --role buildkit > "$evidence/buildkit-readiness.json"
      return
    fi
    sleep .2
  done
  die 'BuildKit readiness deadline expired'
}
preflight_recipe() {
  echo '8b0af79ba3426f49ba599eb0c7eea433c62ac5bb6ab5e7797f7d09d978f43543  oracle/gcc/16.2.0/build-toolchain.Dockerfile' | sha256sum --check --strict
  df -Pk "$repo" > "$evidence/disk-free.txt"
  free_kb=$(awk 'NR==2 {print $4}' "$evidence/disk-free.txt")
  (( free_kb >= 12582912 )) || die 'less than 12 GiB free for bounded native solve/export'
  sha256sum .github/workflows/gcc-oracle-model.yml oracle/gcc/16.2.0/{build-toolchain.Dockerfile,toolchain-reproduction.json,build-record.json,source-lock.json} > "$evidence/source-hashes.txt"
}
capture_toolchain_inspect() {
  local inspect_api=1.49
  local version_file="$evidence/image-inspect-api-version.json"
  local inspect_file="$evidence/image-inspect.json"
  local provenance_file="$evidence/image-inspect-api-provenance.json"
  local fingerprint_file="$evidence/executable-sha256.txt"
  local source_file="$evidence/source-hashes.txt"
  local admission version_hash fingerprint_hash source_hash

  rm -f -- "$version_file" "$inspect_file" "$provenance_file"
  timeout --signal=TERM --kill-after=5s 30s env -u DOCKER_HOST -u DOCKER_CONTEXT \
    DOCKER_CONFIG="$DOCKER_CONFIG" DOCKER_API_VERSION="$inspect_api" \
    "$docker_bin" --host "unix://$socket" version --format '{{json .}}' > "$version_file"
  admission=$(python3 - "$version_file" "$inspect_api" "$fingerprint_file" "$docker_bin" "$source_file" <<'PYVERSION'
import hashlib, json, pathlib, re, sys
def bounded(path, limit):
    with pathlib.Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise SystemExit('inspect metadata empty or exceeds bound')
    return raw
def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result
def invalid_constant(value):
    raise ValueError('invalid JSON constant')
raw = bounded(sys.argv[1], 65536)
try:
    doc = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
except (ValueError, UnicodeDecodeError):
    raise SystemExit('invalid inspect API version metadata')
def obj(parent, key):
    value = parent.get(key) if isinstance(parent, dict) else None
    if not isinstance(value, dict):
        raise SystemExit('missing version object')
    return value
def api(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})', value):
        raise SystemExit('malformed API version')
    return tuple(map(int, value.split('.')))
client = obj(doc, 'Client'); server = obj(doc, 'Server')
if client.get('Version') != '29.7.2' or client.get('GitCommit') != 'a7dcaa6':
    raise SystemExit('pinned client identity mismatch')
if server.get('Version') != '29.7.2' or server.get('GitCommit') != '6a43e3d':
    raise SystemExit('pinned server identity mismatch')
selected = api(sys.argv[2]); effective = api(client.get('ApiVersion'))
minimum = api(server.get('MinAPIVersion')); maximum = api(server.get('ApiVersion'))
if effective != selected:
    raise SystemExit('effective client API mismatch')
if not minimum <= selected <= maximum:
    raise SystemExit('selected API outside observed server range')
fingerprints = bounded(sys.argv[3], 65536)
try:
    records = [re.fullmatch(r'([0-9a-f]{64}) [ *]([^\x00]+)', line) for line in fingerprints.decode('utf-8').splitlines()]
except UnicodeDecodeError:
    raise SystemExit('malformed retained fingerprint record')
if not records or any(record is None for record in records):
    raise SystemExit('malformed retained fingerprint record')
matches = [record.group(1) for record in records if record.group(2) == sys.argv[4]]
if matches != ['e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13']:
    raise SystemExit('retained client fingerprint does not match the locked pin exactly once')
source = bounded(sys.argv[5], 65536)
print(' '.join(hashlib.sha256(value).hexdigest() for value in (raw, fingerprints, source)))
PYVERSION
  )
  [[ "$admission" =~ ^[0-9a-f]{64}\ [0-9a-f]{64}\ [0-9a-f]{64}$ ]] || die 'invalid inspect preflight byte binding'
  read -r version_hash fingerprint_hash source_hash <<< "$admission"
  timeout --signal=TERM --kill-after=5s 30s env -u DOCKER_HOST -u DOCKER_CONTEXT \
    DOCKER_CONFIG="$DOCKER_CONFIG" DOCKER_API_VERSION="$inspect_api" \
    "$docker_bin" --host "unix://$socket" image inspect "$tag" > "$inspect_file"
  python3 - "$inspect_file" "$version_file" "$provenance_file" "$docker_bin" \
    "unix://$socket" "$DOCKER_CONFIG" "$inspect_api" "$fingerprint_file" \
    "${GITHUB_RUN_ID:-local}" "${GITHUB_RUN_ATTEMPT:-1}" "$source_file" "$tag" \
    "$version_hash" "$fingerprint_hash" "$source_hash" <<'PYPROVENANCE'
import hashlib, json, pathlib, sys
def bounded(path, limit):
    with pathlib.Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise SystemExit('inspect metadata empty or exceeds bound')
    return raw
def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result
def invalid_constant(value):
    raise ValueError('invalid JSON constant')
inspect, version, output = map(pathlib.Path, sys.argv[1:4])
raw = bounded(inspect, 16 * 1024 * 1024)
version_raw = bounded(version, 65536)
fingerprints = bounded(sys.argv[8], 65536)
source = bounded(sys.argv[11], 65536)
for value, expected in zip((version_raw, fingerprints, source), sys.argv[13:16], strict=True):
    if hashlib.sha256(value).hexdigest() != expected:
        raise SystemExit('inspect preflight bytes changed during capture')
try:
    doc = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    version_doc = json.loads(version_raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
except (ValueError, UnicodeDecodeError):
    raise SystemExit('invalid inspect capture metadata')
if not isinstance(doc, list) or len(doc) != 1 or not isinstance(doc[0], dict):
    raise SystemExit('inspect response must be one image object')
def retained_file(path, value):
    return {'path': str(path), 'sha256': hashlib.sha256(value).hexdigest(), 'bytes': len(value)}
client = version_doc['Client']; server = version_doc['Server']
record = {
    'schema': 'gcc-inspect-api-provenance/v1',
    'classification': 'request enforced by command environment plus pinned CLI source; not wire-observed',
    'inputAuthority': 'fingerprint and source records are inherited mutable metadata; no fresh executable authentication or generation/receipt continuity is established',
    'selectedApi': sys.argv[7], 'effectiveApiObservedByVersionCall': client['ApiVersion'],
    'observedServerApiRange': {'minimum': server['MinAPIVersion'], 'maximum': server['ApiVersion']},
    'versionIdentities': {'clientVersion': client['Version'], 'clientBuild': client['GitCommit'], 'serverVersion': server['Version'], 'serverBuild': server['GitCommit']},
    'versionFile': retained_file(version, version_raw), 'inspectFile': retained_file(inspect, raw),
    'client': {'path': sys.argv[4], 'lockedExpectedSha256': 'e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13', 'fingerprintRecord': retained_file(sys.argv[8], fingerprints)},
    'sourceHashRecord': retained_file(sys.argv[11], source),
    'ownedHost': sys.argv[5], 'privateDockerConfig': sys.argv[6],
    'inspectArgv': [sys.argv[4], '--host', sys.argv[5], 'image', 'inspect', sys.argv[12]],
    'versionArgv': [sys.argv[4], '--host', sys.argv[5], 'version', '--format', '{{json .}}'],
    'runBinding': {'runId': sys.argv[9], 'attempt': sys.argv[10]},
    'inspectTimeout': {'signal': 'TERM', 'killAfterSeconds': 5, 'timeoutSeconds': 30},
    'strictVerifierInput': 'complete unmodified image-inspect.json bytes',
}
tmp = output.with_name(output.name + '.tmp')
created = False
try:
    with tmp.open('x', encoding='utf-8') as stream:
        created = True
        stream.write(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n')
        stream.flush()
    tmp.replace(output)
except BaseException:
    if created:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    raise
PYPROVENANCE
}

reproduce() {
  clean_environment
  preflight_recipe
  start_buildkit
  local archive="$evidence/image.docker.tar" oci="$evidence/provenance.oci.tar"
  run_solve "$archive" "$oci" || { tail -n 100 "$evidence/buildctl.log"; die 'single BuildKit solve or bounded log writer failed'; }
  test -f "$archive" && test -f "$oci" || die 'both solve outputs required'
  timeout --signal=TERM --kill-after=15s 600s python3 scripts/ci-gcc-toolchain-archive.py inspect "$archive" "$oci" "$evidence" 4294967296
  timeout --signal=TERM --kill-after=10s 120s "$docker_bin" --host "unix://$socket" image load --input "$archive" \
    >"$evidence/docker-load.txt" 2>&1
  capture_toolchain_inspect
  timeout --signal=TERM --kill-after=5s 30s env -u DOCKER_HOST -u DOCKER_CONTEXT \
    DOCKER_CONFIG="$DOCKER_CONFIG" "$docker_bin" --host "unix://$socket" history --no-trunc \
    --format '{{json .}}' "$tag" > "$evidence/image-history.jsonl"
  python3 scripts/verify-gcc-toolchain-reproduction.py --lock oracle/gcc/16.2.0/toolchain-reproduction.json \
    --build-record oracle/gcc/16.2.0/build-record.json < "$evidence/image-inspect.json"
  observed=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["Id"])' "$evidence/image-inspect.json")
  timeout --signal=TERM --kill-after=5s 120s "$docker_bin" --host "unix://$socket" run --rm \
    --platform linux/amd64 --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,noexec \
    --mount "type=bind,src=$repo,dst=/oracle,readonly" --workdir /oracle \
    --entrypoint /usr/bin/python3 "$observed" \
    scripts/verify-gcc-oracle-build-record.py \
    --source-lock oracle/gcc/16.2.0/source-lock.json \
    --build-record oracle/gcc/16.2.0/build-record.json \
    --container-digest "$observed" \
    --reproduction-lock oracle/gcc/16.2.0/toolchain-reproduction.json \
    > "$evidence/live-build-record-verification.txt" 2>&1 || die 'contained live GCC build-record verifier failed'
  printf 'GCC_TOOLCHAIN_IMAGE_ID=%s\nDECOMP_TEST_OCI_IMAGE_DIGEST=%s\n' "$observed" "$observed" >> "$GITHUB_ENV"
  printf 'DOCKER=%s\nDOCKER_HOST=unix://%s\n' "$docker_bin" "$socket" >> "$GITHUB_ENV"
}
build_solve_argv() {
  SOLVE_ARGV=("$buildctl" --addr "unix://$bk_socket" build
    --frontend dockerfile.v0
    --local "context=$repo/oracle/gcc/16.2.0" --local "dockerfile=$repo/oracle/gcc/16.2.0"
    --opt filename=build-toolchain.Dockerfile --opt platform=linux/amd64
    --opt build-arg:SOURCE_DATE_EPOCH=1786060800 --no-cache
    --opt attest:provenance=mode=min,inline-only=true
    --output "type=docker,name=$tag,dest=$1"
    --output "type=oci,name=$tag,dest=$2,attestation-inline=true"
    --metadata-file "$evidence/solve-metadata.json" --progress=plain)
}
run_solve() {
  build_solve_argv "$1" "$2"
  admit_solve_argv "$1" "$2" || die 'BuildKit solve command admission failed'
  timeout --signal=TERM --kill-after=30s 20m "${SOLVE_ARGV[@]}" 2>&1 | bounded_stream "$evidence/buildctl.log"
}
admit_solve_argv() {
  local joined=" ${SOLVE_ARGV[*]} "
  [[ "$joined" == *" --addr unix://$bk_socket "* &&
     "$joined" == *" --frontend dockerfile.v0 "* &&
     "$joined" == *" --local context=$repo/oracle/gcc/16.2.0 "* &&
     "$joined" == *" --local dockerfile=$repo/oracle/gcc/16.2.0 "* &&
     "$joined" == *" --opt filename=build-toolchain.Dockerfile "* &&
     "$joined" == *" --opt platform=linux/amd64 "* &&
     "$joined" == *" build-arg:SOURCE_DATE_EPOCH=1786060800 "* &&
     "$joined" == *" --no-cache "* && "$joined" == *" --opt attest:provenance=mode=min,inline-only=true "* &&
     "$joined" == *" --output type=docker,name=$tag,dest=$1 "* &&
     "$joined" == *" --output type=oci,name=$tag,dest=$2,attestation-inline=true "* &&
     "$joined" != *" --load "* && "$joined" != *" BUILDKIT_DEBUG_FORCE_OVERLAY_DIFF "* ]]
}
verify_archive() { check_archive "$1" "$2" "$3"; }
diagnostics() {
  [[ -d "$evidence" ]] || return 0
  printf 'exit=%s\n' "${PRIMARY_STATUS:-unknown}" > "$evidence/primary-status.txt"
  uname -a > "$evidence/uname.txt" 2>&1 || true
  cat /etc/os-release > "$evidence/os-release.txt" 2>&1 || true
  df -Pk "$repo" > "$evidence/disk-after.txt" 2>&1 || true
  printf 'runner.name=%s runner.os=%s runner.arch=%s ImageOS=%s ImageVersion=%s\n' \
    "${RUNNER_NAME:-unknown}" "${RUNNER_OS:-unknown}" "${RUNNER_ARCH:-unknown}" \
    "${ImageOS:-unknown}" "${ImageVersion:-unknown}" > "$evidence/runner-image.txt"
  if [[ -f "$job_root/owner.json" ]]; then
    for role in buildkit rootless; do
      unit=$(python3 - "$job_root/owner.json" "$role" <<'PY'
import json,pathlib,re,sys
manifest=json.loads(pathlib.Path(sys.argv[1]).read_bytes())
record=manifest.get('roles',{}).get(sys.argv[2],{})
receipt=record.get('receipt',{})
unit=receipt.get('unit','')
if unit and re.fullmatch(r'[A-Za-z0-9_.@-]+',unit): print(unit)
PY
      )
      [[ -n "$unit" ]] || continue
      if [[ "$role" == buildkit ]]; then
        timeout --signal=TERM --kill-after=2s 30s sudo -n journalctl --unit "$unit" \
          --no-pager --output=short-precise -n 12000 2>&1 | bounded_stream "$evidence/buildkitd.log" 67108864 || true
      else
        timeout --signal=TERM --kill-after=2s 30s journalctl --user --unit "$unit" \
          --no-pager --output=short-precise -n 12000 2>&1 | bounded_stream "$evidence/rootless-dockerd.log" 67108864 || true
      fi
    done
  fi
  find "$evidence" -type f -printf '%P %s bytes\n' | sort > "$evidence/file-inventory.txt"
  du -sb "$evidence" > "$evidence/evidence-byte-count.txt"
}
cleanup() {
  local failure=0
  if [[ -e "$job_root" ]]; then
    [[ -d "$job_root" && ! -L "$job_root" && -f "$job_root/owner.txt" && ! -L "$job_root/owner.txt" ]] || die 'refuse cleanup without a regular owned marker'
    grep -Fqx "run=$run_id" "$job_root/owner.txt" || die 'run ownership marker mismatch'
    grep -Fqx "attempt=$run_attempt" "$job_root/owner.txt" || die 'attempt ownership marker mismatch'
    grep -Fqx "revision=$(git rev-parse HEAD)" "$job_root/owner.txt" || die 'source revision ownership marker mismatch'
    [[ -f "$job_root/owner.json" && ! -L "$job_root/owner.json" ]] || die 'refuse cleanup without the durable service owner'
  fi
  if [[ -e "$job_root" ]]; then
    owner_call stop --role buildkit || failure=1
    owner_call stop --role rootless || failure=1
    if (( failure == 0 )); then
      if [[ "${PRIMARY_STATUS:-}" == "success" ]]; then owner_call stage-upload --success || failure=1
      else owner_call stage-upload || failure=1; fi
      owner_call release || failure=1
    fi
  fi
  if (( failure != 0 )); then echo 'owned cleanup could not prove process absence' >&2; return "$failure"; fi
  if [[ -e "$job_root" ]]; then
    need_owned_path "$job_root"
    [[ ! -f "$state/buildkitd.toml" ]] || cp "$state/buildkitd.toml" "$evidence/buildkitd.toml"
    [[ ! -f "$state/docker-daemon.json" ]] || cp "$state/docker-daemon.json" "$evidence/docker-daemon.json"
    python3 - "$job_root" <<'PY'
import pathlib,sys
root=str(pathlib.Path(sys.argv[1]).resolve())
for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
    fields=line.split()
    target=fields[4].replace('\\040',' ')
    if target==root or target.startswith(root+'/'):
        raise SystemExit('owned mount remains; quarantine retained')
PY
    if [[ -L "$socket" || -L "$bk_socket" ]]; then die 'refuse linked owned socket path'; fi
    if [[ -e "$socket" ]]; then [[ -S "$socket" ]] || die 'unexpected rootless endpoint leaf'; rm -f -- "$socket"; fi
    if [[ -e "$bk_socket" ]]; then [[ -S "$bk_socket" ]] || die 'unexpected BuildKit endpoint leaf'; sudo -n rm -f -- "$bk_socket"; fi
    if [[ -e "$state/buildkit-root" ]]; then
      need_owned_path "$state/buildkit-root"
      sudo -n rm -rf -- "$state/buildkit-root"
    fi
    for item in "$state" "$tools" "$volume/docker-config" "$volume/home" "$job_root/r" "$job_root/x"; do
      need_owned_path "$item"
      [[ ! -L "$item" ]] || die 'refuse linked cleanup path'
      [[ ! -e "$item" ]] || rm -rf -- "$item"
    done
    for item in "$job_root/ambient-client"; do
      [[ ! -e "$item" ]] || { need_owned_path "$item"; rmdir -- "$item" || die 'private client config is nonempty; cleanup retained'; }
    done
    find "$evidence" -type f -printf '%P %s bytes\n' | sort > "$evidence/file-inventory.txt"
    du -sb "$evidence" > "$evidence/evidence-byte-count.txt"
    evidence_bytes=$(cut -f1 "$evidence/evidence-byte-count.txt")
    evidence_files=$(find "$evidence" -type f | wc -l)
    if (( evidence_bytes > 13958643712 || evidence_files > 128 )); then
      printf 'evidence budget exceeded bytes=%s files=%s maxBytes=13958643712 maxFiles=128\n' \
        "$evidence_bytes" "$evidence_files" > "$evidence/artifact-budget-refusal.txt"
      failure=1
    fi
  fi
  (( failure == 0 )) || die 'owned cleanup or evidence budget failed'
}
main() {
  case "${1:-}" in
    init) init ;;
    authenticate) authenticate ;;
    start-rootless) start_rootless ;;
    reproduce) reproduce ;;
    cleanup) cleanup ;;
    diagnostics) diagnostics ;;
    verify-archive) verify_archive "${2:?archive}" "${3:?size}" "${4:?sha256}" ;;
    verify-executable) check_executable "${2:?tool}" "${3:?size}" "${4:?sha256}" ;;
    *) die 'usage: ci-gcc-toolchain-builder.sh {init|authenticate|start-rootless|reproduce|diagnostics|cleanup}' ;;
  esac
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
