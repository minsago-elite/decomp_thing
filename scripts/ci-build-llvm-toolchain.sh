#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: bash scripts/ci-build-llvm-toolchain.sh" >&2
  exit 64
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

for attempt in 1 2; do
  echo "LLVM toolchain image build: attempt $attempt/2, 900-second command deadline"
  if timeout --signal=INT --kill-after=30s 900s \
    docker buildx build \
      --no-cache \
      --platform linux/amd64 \
      --build-arg SOURCE_DATE_EPOCH=1779182222 \
      --load \
      --progress plain \
      --tag decomp-llvm-oracle-toolchain:22.1.6 \
      --file oracle/llvm/22.1.6/build-toolchain.Dockerfile \
      oracle/llvm/22.1.6; then
    exit 0
  else
    build_status=$?
  fi

  if ((build_status != 1 || attempt == 2)); then
    echo "LLVM toolchain image build stopped with status $build_status; no further attempt" >&2
    exit "$build_status"
  fi
  echo "LLVM toolchain build command failed; retrying the unchanged pinned recipe once" >&2
  sleep 5
done
