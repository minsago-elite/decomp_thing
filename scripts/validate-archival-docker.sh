#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

validation_parent="$PWD/build"
mkdir -p "$validation_parent"
for command in timeout python3 stat; do
  command -v "$command" >/dev/null || { echo "missing archival cleanup command: $command" >&2; exit 1; }
done
validation_root=$(mktemp -d "$validation_parent/decomp-archival-ci.XXXXXX")
diagnostic_directory="$validation_parent/archival-ci-diagnostics"
validation_device=""
validation_inode=""
permission_repair_attempted=0
permission_repair_status=1
image_built=0

check_root() {
  timeout --signal=TERM --kill-after=1s 2s python3 -I -B scripts/collect-archival-diagnostics.py \
    "$validation_root" "$validation_device" "$validation_inode" --check-root >/dev/null 2>&1
}

repair_permissions() {
  if ((permission_repair_attempted == 0)); then
    permission_repair_attempted=1
    if ((image_built == 0)); then
      permission_repair_status=0
    elif ! check_root; then
      permission_repair_status=2
    elif timeout --signal=TERM --kill-after=1s 10s docker run --rm --pull=never \
      --volume "$validation_root/output:/output" --entrypoint sh decomp-thing-archival-ci \
      -c 'find /output -mindepth 1 -exec chmod a+rwX {} +' >/dev/null 2>&1; then
      permission_repair_status=0
    else
      permission_repair_status=$?
    fi
  fi
  return "$permission_repair_status"
}

cleanup() {
  local status=$?
  local cleanup_failed=0
  local removal_allowed=1
  trap - EXIT
  set +e
  if [[ -d "$validation_root/output" ]]; then
    if ((status != 0)); then echo "Archival validation failed; retained build evidence follows" >&2; fi
    echo "Retaining bounded archival build and owner diagnostics" >&2
    if ! repair_permissions; then
      echo "Archival permission repair incomplete; retaining the validation tree" >&2
      removal_allowed=0
      cleanup_failed=1
    fi
    local diagnostic_file="$diagnostic_directory/${validation_root##*/}.jsonl"
    if [[ ! -L "$diagnostic_directory" ]] && mkdir -p -- "$diagnostic_directory" &&
       (umask 077; set -C; : > "$diagnostic_file"); then
      if ! timeout --signal=TERM --kill-after=1s 10s python3 -I -B scripts/collect-archival-diagnostics.py \
        "$validation_root" "$validation_device" "$validation_inode" >"$diagnostic_file" 2>/dev/null; then
        removal_allowed=0
        cleanup_failed=1
        echo "Archival diagnostic collection incomplete; retaining the validation tree" >&2
      fi
      if ! timeout --signal=TERM --kill-after=1s 2s cat -- "$diagnostic_file" >&2; then
        removal_allowed=0
        cleanup_failed=1
      fi
    else
      removal_allowed=0
      cleanup_failed=1
      echo "Archival diagnostic retention unavailable; retaining the validation tree" >&2
    fi
  fi
  if ((removal_allowed)); then
    if check_root; then
      case "$validation_root" in
        "$validation_parent"/decomp-archival-ci.*)
          if ! timeout --signal=TERM --kill-after=1s 20s rm -rf --one-file-system -- "$validation_root"; then cleanup_failed=1; fi ;;
        *) cleanup_failed=1; echo "refusing to remove unexpected validation path" >&2 ;;
      esac
    else
      cleanup_failed=1
      echo "Archival cleanup root identity is unverified; retaining the validation tree" >&2
    fi
  fi
  if ((cleanup_failed)); then
    echo "Archival cleanup is incomplete: $validation_root" >&2
    if ((status == 0)); then status=1; fi
  fi
  exit "$status"
}
trap cleanup EXIT
read -r validation_device validation_inode < <(timeout --signal=TERM --kill-after=1s 2s stat -c '%d %i' -- "$validation_root")

mkdir -p "$validation_root/input" "$validation_root/output"
gcc -O0 -g benchmarks/archival/large_project.c -o "$validation_root/input/large-symbols"
cp "$validation_root/input/large-symbols" "$validation_root/input/large-stripped"
strip --strip-all "$validation_root/input/large-stripped"
chmod -R a+rwX "$validation_root"

image=decomp-thing-archival-ci
docker build --tag "$image" .
image_built=1

run_reconstruction() {
  local binary=$1
  local output=$2
  docker run --rm \
    --volume "$validation_root/input:/input:ro" \
    --volume "$validation_root/output:/output" \
    "$image" reconstruct "/input/$binary" --output "/output/$output" --evidence-only
}

run_reconstruction large-symbols symbols-a
run_reconstruction large-symbols symbols-b
run_reconstruction large-stripped stripped-a
run_reconstruction large-stripped stripped-b

# The image uses a fixed non-root UID, while hosted runners may use another UID.
# Normalize only this disposable mount from inside the owning container before
# host-side determinism checks and cleanup.
repair_permissions

cmp "$validation_root/output/symbols-a/analysis/reports/program_model.json" \
    "$validation_root/output/symbols-b/analysis/reports/program_model.json"
cmp "$validation_root/output/symbols-a/source-tree.zip" \
    "$validation_root/output/symbols-b/source-tree.zip"
cmp "$validation_root/output/stripped-a/analysis/reports/program_model.json" \
    "$validation_root/output/stripped-b/analysis/reports/program_model.json"
cmp "$validation_root/output/stripped-a/source-tree.zip" \
    "$validation_root/output/stripped-b/source-tree.zip"

python3 - "$validation_root/output" <<'PY'
import json
import pathlib
import subprocess
import sys

from oracle.referenced_data_bytes import decode_program_model_bytes, validate_evidence

root = pathlib.Path(sys.argv[1])
for name in ("symbols-a", "stripped-a"):
    model_bytes = (root / name / "analysis/reports/program_model.json").read_bytes()
    model = decode_program_model_bytes(model_bytes)
    assert type(model["schemaVersion"]) is int and model["schemaVersion"] == 4
    byte_budget = [0, 0]
    for item in model["globals"]:
        # This is an active bundled exporter capture, whose emitted globals are
        # eligible references; generic model4 null is not a producer cutoff proof.
        assert item["byteEvidence"] is not None
        validate_evidence(item["byteEvidence"], byte_budget, schema_version=2)
    for kind in ("functions", "globals", "types"):
        assert all(item["recoveryAssessment"] == "unassessed" for item in model[kind])
        assert all(item["extractionStatus"] in ("recovered", "partial", "failed", "synthetic") for item in model[kind])
    assert len(model["functions"]) >= 50
    assert all(item["id"].startswith("fn_") and item["address"].startswith("0x") for item in model["functions"])
    assert sum(len(item["referencedGlobals"]) for item in model["functions"]) > 0
    assert sum(len(item["strings"]) for item in model["functions"]) > 0
    if name == "symbols-a":
        assert len(model["types"]) > 0
    project = root / name / "source-tree"
    assert (project / "reports/program_model.json").read_bytes() == (
        root / name / "analysis/reports/program_model.json"
    ).read_bytes()
    entities = {item["id"] for kind in ("functions", "globals", "types") for item in model[kind]}
    manifest = json.loads((project / "source_tree_manifest.json").read_text())
    confidence = json.loads((project / "reports/confidence.json").read_text())
    selected = confidence["semanticPlanningBudgetEvidence"]["selectedProfile"]
    assert selected["descriptor"]["adapterConfiguration"]["declaration-purpose"] == ["evidence-carrier-v1"]
    assert selected["sha256"] == manifest["profileSha256"]
    assert {identity for item in manifest["files"] for identity in item["entityIds"]} == entities
    assert set(manifest["unresolvedEntityIds"]) == entities
    assert set(confidence["unresolvedEntityIds"]) == entities
    implementations = [item for item in manifest["files"] if "module-implementation" in item["roles"]]
    assert implementations
    assert all(item["generator"] == "evidence-carrier:v1" and item["acceptedImplementation"] is False
               for item in implementations)
    executable = project / "build/reconstructed"
    assert executable.is_file()
    diagnostic = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5, check=False)
    assert diagnostic.returncode == 1, diagnostic
    output = (diagnostic.stdout + diagnostic.stderr).lower()
    assert "evidence-only" in output and "unresolved" in output, output
    assert (root / name / "source-tree.zip").is_file()
PY

for name in symbols-a stripped-a; do
  extract_root="$validation_root/extracted/$name"
  mkdir -p "$extract_root"
  echo "Verify and rebuild extracted archival fixture: $name"
  unzip -q "$validation_root/output/$name/source-tree.zip" -d "$extract_root"
  (cd "$extract_root" && sha256sum --check ARCHIVE_MANIFEST.sha256 && make -j2)
done

echo "Real Ghidra archival validation passed"
