#!/usr/bin/env bash
set -euo pipefail

if (($# == 0)); then
  echo 'usage: ci-fetch-llvm-release-artifacts.sh command [args...]' >&2
  exit 2
fi

fetch_log="$(mktemp)"
trap 'rm -f -- "$fetch_log"' EXIT

for attempt in 1 2 3; do
  if "$@" >"$fetch_log" 2>&1; then
    cat -- "$fetch_log"
    exit 0
  else
    status=$?
  fi
  cat -- "$fetch_log"
  if ! grep -Eq '^LLVM release artifact fetch failed: HTTPS exchange (failed|exceeded its wall-clock deadline)$' "$fetch_log"; then
    exit "$status"
  fi
  if ((attempt == 3)); then
    exit "$status"
  fi
  echo "retrying locked LLVM release fetch after transient HTTPS transport failure (attempt $((attempt + 1))/3)" >&2
  sleep 3
done
