# GCC driver clean-tree gate: unavailable production admission

This record is for issue #48 at repository revision
`bf2501568f39ab52b23492dfc37839bb81895587`, observed on 2026-09-08.

The local generated-C build contract is present and passes its focused fixture
suite. The selected `generated-c-make-v1` profile declares this command for a
future production admission:

```sh
make --jobs=4 --output-sync=target CC=cc \
  'CFLAGS=-std=c11 -g -Wall -Wextra -Werror -Iinclude'
```

The contract requires GNU Make, a C compiler available as `cc`, a POSIX shell,
`find`, `mkdir`, and `rm`;
it requires `-Werror`, sanitizes ambient build controls, records source hashes,
and expects `build/reconstructed`. The focused test uses a compatibility fixture
with its own compiler default; it also rebuilds an extracted archive and
attributes fixture compiler and linker failures to their owners. It does not
prove the future profile-selected production command.

Production admission is `unavailable` and production qualification is
`unresolved`. The repository has the locked GCC 16.2.0 oracle inputs and
reference binaries, but no complete accepted reconstructed source tree, module
plan, source manifest, unresolved inventory, generation receipt, or production
`build_contract.json`. Therefore this checkpoint records no production source
revision, output identity, return code, or module diagnostics.

The missing production input is owned by #47/#64 and its ABI/interface facts
depend on #46. #49, #50, #54, and #84 remain downstream or parallel gates; the
closed #86 and #88 regression lanes do not substitute for the GCC source build.
The full machine-readable record, including the dependency snapshot and exact
boundary statements, is
[`gcc-driver-clean-tree-gate-2026-09-08.json`](gcc-driver-clean-tree-gate-2026-09-08.json).

No ACP reconstruction agent, production compiler or linker, archive admission,
Ghidra execution, or oracle execution was performed for this record. Production
analysis remains bound to the application-bundled Ghidra APIs and does not gain
an external `GHIDRA_HOME` or `analyzeHeadless` dependency from this evidence.

Validation run:

```text
./gradlew --offline --no-daemon test --tests decompengine.project.StrictProjectBuildTest
BUILD SUCCESSFUL
```

That result is fixture-only evidence. It does not close #48, #699, or #700.
