#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

evidence="$PWD/build/angr-qualification"
venv="$PWD/build/angr-qualification-venv"
mkdir -p "$evidence/tmp" "$PWD/build/pip-download-cache"
export TMPDIR="$evidence/tmp"
export PIP_CACHE_DIR="$PWD/build/pip-download-cache"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1
python3 scripts/check-angr-pin.py > "$evidence/pin-selection.json"
python3 -m venv "$venv"
export ANGR_PYTHON="$venv/bin/python"
"$ANGR_PYTHON" -m pip --disable-pip-version-check --no-input install \
  --timeout 30 --retries 2 --report "$evidence/pip-install.json" \
  --constraint requirements/angr-compatibility.txt --requirement requirements/angr-qualification.txt
"$ANGR_PYTHON" -m pip list --format=json > "$evidence/packages.json"
git rev-parse HEAD > "$evidence/checkout.txt"
git rev-parse 'HEAD^{tree}' > "$evidence/tree.txt"
sha256sum .github/workflows/ci.yml Dockerfile build.gradle.kts requirements/angr-qualification.txt requirements/angr-compatibility.txt \
  scripts/ci-qualify-angr.sh scripts/select-angr-qualification.sh scripts/check-angr-pin.py \
  src/main/kotlin/decompengine/exploration/AutomaticExploration.kt \
  src/test/kotlin/decompengine/exploration/AutomaticExplorationTest.kt > "$evidence/source-sha256.txt"
gcc --version > "$evidence/gcc-version.txt"
"$ANGR_PYTHON" - <<'PY'
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
from pathlib import Path
import angr
import archinfo
import claripy
import cle
import pyvex
import bitstring
import pycparser

expected_pins = json.loads(Path("build/angr-qualification/pin-selection.json").read_text())
assert angr.__version__ == expected_pins["angrVersion"], angr.__version__
assert importlib.metadata.version("bitstring") == expected_pins["bitstringVersion"]
assert importlib.metadata.version("pycparser") == expected_pins["pycparserVersion"]
def identity(path):
    p = Path(path).resolve(strict=True)
    return {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
record = {
    "pythonVersion": sys.version,
    "python": identity(sys.executable),
    "platform": platform.platform(),
    "modules": {m.__name__: {"version": importlib.metadata.version(m.__name__), **identity(m.__file__)}
                for m in (angr, archinfo, claripy, cle, pyvex, bitstring, pycparser)},
    "command": ["./gradlew", "--no-daemon", "realAngrQualification"],
    "interpreter": os.environ["ANGR_PYTHON"],
    "scope": "authored argv/stdin proposal fixture; no equivalence or process-attestation credit",
}
Path("build/angr-qualification/toolchain.json").write_text(json.dumps(record, indent=2) + "\n")
PY
./gradlew --no-daemon realAngrQualification
"$ANGR_PYTHON" - <<'PY'
import json
from pathlib import Path
import xml.etree.ElementTree as ET

root = Path("build/test-results/realAngrQualification")
cases = [case for report in root.glob("TEST-*.xml")
         for case in ET.parse(report).getroot().iter("testcase")]
assert len(cases) == 1, f"expected one real-tool method, found {len(cases)}"
assert all(case.find(tag) is None for case in cases for tag in ("failure", "error", "skipped")), \
    "real Angr qualification cannot receive skipped or failed test credit"
discovery = json.loads(Path("build/angr-qualification/discovery.json").read_text())
assert discovery["argvStates"] > 1 and discovery["stdinStates"] > 1
assert any(c["args"] == ["secret"] for c in discovery["candidates"])
assert any(bytes.fromhex(c["stdinHex"]).startswith(b"open\n") for c in discovery["candidates"])
Path("build/angr-qualification/qualification.json").write_text(json.dumps({
    "status": "passed", "testCount": 1, "skipped": 0,
    "scope": "actual Angr argv/stdin discovery on the retained authored fixture",
}) + "\n")
PY
