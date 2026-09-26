# A-series issue #829 — declared-role reconstruction slice

- Milestone: A8: Reconstruct a Buildable GCC Driver Source Tree
- Status: focused implementation and unit evidence only; #829 remains open and is not production-qualified.
- Scope: `BoundedLlmModuleReconstructor` in the Make/Ninja generated-C adapters.

## Implemented and verified

- Reconstruction now checks that the planned editable implementation matches the profile declaration.
- Every workspace context path must match a declared viewable UTF-8 interface with its expected public or private interface role. Module headers must match the profile's module-interface path, and dependencies must resolve to declared module interfaces.
- The request path policy is verified to give read access only to the declared interface inputs and read/write/create access only to the planned implementation target.
- The Make-profile test verifies the exact request rules. The alternate Ninja-profile test removes `viewable` from the private interface, verifies the harness is never called, and verifies the implementation remains unresolved.

## Verification

Command:

```sh
./gradlew -PfrontendNodeHome=/home/june/.cache/decomp-toolchains/node-v24.20.0 --offline test --tests decompengine.project.SourceTreeTest --console=plain
```

Result: passed; all 46 `SourceTreeTest` tests completed successfully. `git diff --check` also passed.

## Remaining qualification

This slice does not exercise the public #63 mutation workflow, #64 reconstruction workflow, or #65 repair workflow through actual Make and Ninja ACP runs. It also does not establish contained production qualification or retained public workflow evidence. Keep #829 open until the full acceptance criterion and the issue's evidence requirements are met.
