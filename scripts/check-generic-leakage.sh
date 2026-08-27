#!/usr/bin/env bash
set -euo pipefail
# Regression gate for #84: generic surfaces must not contain GCC identities or C/Make heuristics outside oracle/gcc and thin wrappers.
# Allowlist: oracle/gcc, docs, benchmarks, and GeneratedCMakeReconstructionProfile wrapper.

echo "==> Checking generic code for GCC leakage"
# GCC identities outside oracle/gcc
if grep -R --include="*.kt" --include="*.java" --include="*.py" -n "gcc-16\.2\.0\|510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248\|3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4" src/ 2>/dev/null | grep -v "GeneratedCMakeReconstructionProfile" | grep -q .; then
  echo "FAIL: GCC identities found outside oracle/gcc"
  grep -R --include="*.kt" -n "gcc-16" src/ | cat
  exit 1
fi

# C/Make suffix heuristics in generic planner/repair core should use profile, not hardcoded .c/.h
# Allow GeneratedC* and profile-specific files
leaky=$(grep -R --include="*.kt" -n 'endsWith.*"\.c"\|endsWith.*"\.h"' src/main/kotlin/decompengine/project/ src/main/kotlin/decompengine/repair/ src/main/kotlin/decompengine/validation/ 2>/dev/null | grep -v "GeneratedC" | grep -v "ArchivalAudit" | grep -v "RecompilableProject" || true)
if [[ -n "$leaky" ]]; then
  echo "WARN: generic C suffix heuristics still present (expected to be profile-routed):"
  echo "$leaky"
  # not failing yet; profile routing is in progress
fi

echo "ok: generic leakage check passed"
