# A-series issue #829 — declared-role reconstruction slice

- Milestone: A8: Reconstruct a Buildable GCC Driver Source Tree
- Status: focused implementation and unit evidence only; #829 remains open and is not production-qualified.
- Scope: `BoundedLlmModuleReconstructor` in the Make/Ninja generated-C adapters.

## Implemented and verified

- Reconstruction now checks that the planned editable implementation matches the profile declaration.
- Every workspace context path must match a declared viewable UTF-8 interface with its expected public or private interface role. Module headers must match the profile's module-interface path, and dependencies must resolve to declared module interfaces.
- The request path policy gives read access to declared interface inputs. The planned implementation gets write/create access from its editable role and read access only when the profile also declares it viewable.
- The Make-profile test verifies the exact request rules. One alternate Ninja-profile test removes `viewable` from the private interface, verifies the harness is never called, and verifies the implementation remains unresolved. Another removes `viewable` from the implementation, verifies that the agent can write it without receiving read access, and verifies that generation proceeds.
- The public archival service test exercises those rules through Make and Ninja builds. A fixture harness without invocation-bound ACP evidence is refused by the archive release gate after its build succeeds. With an alternate Ninja layout that hides the private interface, the harness is not called and archive publication is also refused.
- A scripted ACP v1 fixture now runs the archival service through `AcpAgentHarness`, its sandbox, and filesystem broker for both built-in profiles. It reads the three declared interfaces, confirms a confidence-report read and an unauthorized Makefile write are denied, writes only the declared module implementation, then builds, packages, extracts, verifies, and rebuilds the archive. This exercises the scripted fixture provider through the ACP transport; it is not evidence from a production ACP provider.

## Verification

Command:

```sh
./gradlew -PfrontendNodeHome=/home/june/.cache/decomp-toolchains/node-v24.20.0 --offline test --tests decompengine.project.SourceTreeTest --console=plain
```

Result: passed; all 47 `SourceTreeTest` tests completed successfully, including the nonviewable implementation case. `git diff --check` also passed.

Command:

```sh
./gradlew -PfrontendNodeHome=/home/june/.cache/decomp-toolchains/node-v24.20.0 --offline test --tests decompengine.project.ArchivalReconstructionTest --console=plain
```

Result: passed; all 6 `ArchivalReconstructionTest` tests completed successfully, including the Make/Ninja role and archive-gate workflow.

Command:

```sh
./gradlew -PfrontendNodeHome=/home/june/.cache/decomp-toolchains/node-v24.20.0 --offline test \
  --tests 'decompengine.project.ArchivalReconstructionTest.archival Make and Ninja workflows enforce role policy and reject unauthenticated agent archives' \
  --tests 'decompengine.acp.AcpAgentHarnessTest.public Make and Ninja archival reconstruction follows ACP file roles through verified rebuild' \
  --console=plain
```

Result: passed; both focused tests completed successfully after using the built-in Make/Ninja executable names instead of assuming `/usr/bin/ninja` exists.

## Remaining qualification

The new integration test uses a fixture harness; it does not exercise the public #63 mutation workflow, #64 reconstruction workflow, or #65 repair workflow through authenticated ACP runs. It proves the public service carries role-limited requests into Make/Ninja builds and rejects archive publication without invocation-bound ACP evidence. It does not establish contained production qualification or retained public workflow evidence. Keep #829 open until the full acceptance criterion and the issue's evidence requirements are met.
