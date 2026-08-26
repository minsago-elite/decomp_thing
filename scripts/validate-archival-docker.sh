#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

validation_root=$(mktemp -d /tmp/decomp-archival-ci.XXXXXX)
cleanup() {
  case "$validation_root" in
    /tmp/decomp-archival-ci.*) rm -rf -- "$validation_root" ;;
    *) echo "refusing to remove unexpected validation path: $validation_root" >&2 ;;
  esac
}
trap cleanup EXIT

mkdir -p "$validation_root/input" "$validation_root/output"
gcc -O0 -g benchmarks/archival/large_project.c -o "$validation_root/input/large-symbols"
cp "$validation_root/input/large-symbols" "$validation_root/input/large-stripped"
strip --strip-all "$validation_root/input/large-stripped"
chmod -R a+rwX "$validation_root"

image=decomp-thing-archival-ci
docker build --tag "$image" .

run_reconstruction() {
  local binary=$1
  local output=$2
  docker run --rm \
    --volume "$validation_root/input:/input:ro" \
    --volume "$validation_root/output:/output" \
    "$image" reconstruct "/input/$binary" --output "/output/$output" --evidence-only
}

run_reconstruction large-symbols symbols
run_reconstruction large-stripped stripped-a
run_reconstruction large-stripped stripped-b

cmp "$validation_root/output/stripped-a/analysis/reports/program_model.json" \
    "$validation_root/output/stripped-b/analysis/reports/program_model.json"
cmp "$validation_root/output/stripped-a/source-tree.zip" \
    "$validation_root/output/stripped-b/source-tree.zip"

python3 - "$validation_root/output" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for name in ("symbols", "stripped-a"):
    model = json.loads((root / name / "analysis/reports/program_model.json").read_text())
    assert model["schemaVersion"] == 1
    assert len(model["functions"]) >= 50
    assert all(item["id"].startswith("fn_") and item["address"].startswith("0x") for item in model["functions"])
    assert sum(len(item["referencedGlobals"]) for item in model["functions"]) > 0
    assert sum(len(item["strings"]) for item in model["functions"]) > 0
    if name == "symbols":
        assert len(model["types"]) > 0
    assert (root / name / "source-tree/build/reconstructed").is_file()
    assert (root / name / "source-tree.zip").is_file()
PY

extract_root="$validation_root/extracted"
mkdir -p "$extract_root"
unzip -q "$validation_root/output/stripped-a/source-tree.zip" -d "$extract_root"
(cd "$extract_root" && sha256sum --check ARCHIVE_MANIFEST.sha256 && make -j2)

echo "Real Ghidra archival validation passed"
