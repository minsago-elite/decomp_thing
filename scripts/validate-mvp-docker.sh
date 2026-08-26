#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

config_file=${1:-.env}
if [[ ! -f "$config_file" ]]; then
  echo "missing runtime API configuration: $config_file" >&2
  echo "copy .env.example to .env and set BASE_URL, API_KEY, and MODEL" >&2
  exit 2
fi

set -a
# shellcheck disable=SC1090
source "$config_file"
set +a
: "${BASE_URL:?BASE_URL is required in $config_file}"
: "${API_KEY:?API_KEY is required in $config_file}"
: "${MODEL:?MODEL is required in $config_file}"

if [[ "$API_KEY" == "replace-me" || "$BASE_URL" == *example.com* || "$MODEL" == *model-name* ]]; then
  echo "replace the placeholder API configuration in $config_file" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker with the Compose plugin is required" >&2
  exit 2
fi
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "the MVP acceptance run requires a clean checkout" >&2
  git status --short >&2
  exit 2
fi

git submodule update --init --recursive benchmarks/fixtures/c-vul
expected_fixture_commit=$(git ls-files -s benchmarks/fixtures/c-vul | awk '{print $2}')
actual_fixture_commit=$(git -C benchmarks/fixtures/c-vul rev-parse HEAD)
if [[ -z "$expected_fixture_commit" || "$actual_fixture_commit" != "$expected_fixture_commit" ]]; then
  echo "c-vul submodule is not at the pinned gitlink commit" >&2
  exit 1
fi

validation_root=$(mktemp -d /tmp/decomp-mvp-ci.XXXXXX)
project_name="decomp-mvp-${RANDOM}-$$"
cleanup() {
  docker compose -p "$project_name" --env-file "$config_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
  case "$validation_root" in
    /tmp/decomp-mvp-ci.*) rm -rf -- "$validation_root" ;;
    *) echo "refusing to remove unexpected validation path: $validation_root" >&2 ;;
  esac
}
trap cleanup EXIT

mkdir -p "$validation_root/input" "$validation_root/output"
fixture_source_sha=$(sha256sum benchmarks/fixtures/c-vul/src/01_out_of_bounds_write.c | awk '{print $1}')

export INPUT_DIR="$validation_root/input"
export OUTPUT_DIR="$validation_root/output"
export CVUL_SOURCE_DIR
export LOCAL_UID
export LOCAL_GID
CVUL_SOURCE_DIR=$(realpath benchmarks/fixtures/c-vul/src)
LOCAL_UID=$(id -u)
LOCAL_GID=$(id -g)

docker compose -p "$project_name" --env-file "$config_file" build
compiler_version=$(docker compose -p "$project_name" --env-file "$config_file" --profile acceptance run --rm --no-deps --entrypoint clang fixture-builder --version | head -n 1)
docker compose -p "$project_name" --env-file "$config_file" --profile acceptance run --rm --no-deps fixture-builder
input_sha=$(sha256sum "$validation_root/input/binary_01" | awk '{print $1}')
printf '%s\n' \
  "fixtureCommit=$actual_fixture_commit" \
  "fixtureSourceSha256=$fixture_source_sha" \
  "compiler=$compiler_version" \
  "command=clang -O0 -Wall -Wextra -std=c11 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 /fixture/01_out_of_bounds_write.c -o /input/binary_01" \
  "inputSha256=$input_sha" \
  > "$validation_root/input/INPUT_PROVENANCE.txt"
original_output=$(docker compose -p "$project_name" --env-file "$config_file" run --rm --no-deps \
  --entrypoint /input/binary_01 binary-runner)
if [[ "$original_output" != "[03] Alexandria Stone" ]]; then
  echo "pinned acceptance input has unexpected default behavior: $original_output" >&2
  exit 1
fi

# Prove the source used to build the acceptance input is absent from both runtime services.
for service in llm-bin-patch binary-runner; do
  docker compose -p "$project_name" --env-file "$config_file" run --rm --no-deps \
    --entrypoint sh "$service" -c \
    'test ! -e /opt/fixtures/c-vul && test ! -e /workspace/benchmarks/fixtures/c-vul'
done

docker compose -p "$project_name" --env-file "$config_file" up --detach binary-runner
docker compose -p "$project_name" --env-file "$config_file" run --rm --no-deps \
  llm-bin-patch patch /input/binary_01 --output /output/mvp --yes

summary="$validation_root/output/mvp/summary/SUMMARY.md"
test -f "$summary"
test -f "$validation_root/output/mvp/decompile/decompiled.c"
test -f "$validation_root/output/mvp/patched_c/patched.c"
test -x "$validation_root/output/mvp/patched_binary/patched_binary"
test -s "$validation_root/output/mvp/evidence/cwe-787-sanitizer.txt"
test -s "$validation_root/output/mvp/evidence/approved.patch"
test -s "$validation_root/output/mvp/evidence/reconstruction-request.md"
test -s "$validation_root/output/mvp/evidence/reconstruction-response.md"
find "$validation_root/output/mvp/logs" -type f -size +0c | grep -q .

grep -q -- '- Result: PASS' "$summary"
grep -q 'CWE-787 Evidence and Source Mapping' "$summary"
grep -q 'networkIsolated=true; credentialsIsolated=true' "$summary"
grep -q "$input_sha" "$summary"
if grep -R --fixed-strings --quiet "$API_KEY" "$validation_root/output/mvp"; then
  echo "API key leaked into MVP artifacts" >&2
  exit 1
fi
if grep -R --fixed-strings --quiet "$fixture_source_sha" "$validation_root/output/mvp"; then
  echo "fixture source hash unexpectedly appeared in reconstruction artifacts" >&2
  exit 1
fi

normal_output=$(docker compose -p "$project_name" --env-file "$config_file" run --rm --no-deps \
  --entrypoint /output/mvp/patched_binary/patched_binary binary-runner)
if [[ "$normal_output" != "[03] Alexandria Stone" ]]; then
  echo "patched default output differs: $normal_output" >&2
  exit 1
fi

echo "Pinned c-vul Docker Compose MVP validation passed"
echo "summary: $summary"
