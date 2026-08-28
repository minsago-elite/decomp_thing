#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

clang_executable=${DECOMP_TEST_CLANG:-}
if [[ -z "$clang_executable" ]]; then
  clang_executable=$(command -v clang || true)
fi
if [[ -z "$clang_executable" || ! -x "$clang_executable" ]]; then
  echo "Clang validation requires DECOMP_TEST_CLANG or clang on PATH" >&2
  exit 1
fi
case "$clang_executable" in
  /*) ;;
  *) clang_executable=$(command -v "$clang_executable") ;;
esac

validation_root=$(mktemp -d /tmp/decomp-clang-ci.XXXXXX)
cleanup() {
  case "$validation_root" in
    /tmp/decomp-clang-ci.*) rm -rf -- "$validation_root" ;;
    *) echo "refusing to remove unexpected Clang validation path: $validation_root" >&2 ;;
  esac
}
trap cleanup EXIT

"$clang_executable" --version

strict_flags=(-std=c11 -O1 -g -Wall -Wextra -Werror)
sanitizer_flags=(-std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)

for source in src/test/fixtures/c/*.c benchmarks/archival/*.c; do
  output="$validation_root/$(basename "${source%.c}")"
  "$clang_executable" "${strict_flags[@]}" "$source" -o "$output"
done

for source in benchmarks/fixtures/c-vul/src/*.c; do
  case "$source" in
    */08_uninitialized_memory.c) continue ;;
  esac
  output="$validation_root/vul-$(basename "${source%.c}")"
  "$clang_executable" "${strict_flags[@]}" "$source" -o "$output"
done

if "$clang_executable" "${strict_flags[@]}" \
  benchmarks/fixtures/c-vul/src/08_uninitialized_memory.c \
  -o "$validation_root/uninitialized" 2>"$validation_root/uninitialized.log"; then
  echo "Clang strict warnings accepted the uninitialized-memory fixture" >&2
  exit 1
fi
grep -F "used uninitialized" "$validation_root/uninitialized.log" >/dev/null

"$clang_executable" "${sanitizer_flags[@]}" \
  benchmarks/fixtures/c-vul/src/01_out_of_bounds_write.c \
  -o "$validation_root/out-of-bounds"
if ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1 \
  "$validation_root/out-of-bounds" \
  >"$validation_root/out-of-bounds.stdout" 2>"$validation_root/out-of-bounds.stderr"; then
  echo "Clang sanitizers did not reject the out-of-bounds fixture" >&2
  exit 1
fi
grep -F "ERROR: AddressSanitizer: stack-buffer-overflow" \
  "$validation_root/out-of-bounds.stderr" >/dev/null

"$clang_executable" "${sanitizer_flags[@]}" \
  benchmarks/fixtures/c-vul/src/07_null_pointer_deref.c \
  -o "$validation_root/null-dereference"
if ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1 \
  "$validation_root/null-dereference" \
  >"$validation_root/null-dereference.stdout" 2>"$validation_root/null-dereference.stderr"; then
  echo "Clang sanitizers did not reject the null-dereference fixture" >&2
  exit 1
fi
grep -F "runtime error: member access within null pointer" \
  "$validation_root/null-dereference.stderr" >/dev/null

for diagnostics in "$validation_root"/*.stderr "$validation_root"/*.log; do
  if (($(wc -c <"$diagnostics") > 1048576)); then
    echo "Clang diagnostic output exceeded 1 MiB: $diagnostics" >&2
    exit 1
  fi
done

DECOMP_TEST_CLANG="$clang_executable" \
DECOMP_REQUIRE_CLANG_TESTS=1 \
  ./gradlew --no-daemon test --tests decompengine.project.ClangGeneratedProjectTest

echo "LLVM/Clang compatibility validation passed"
