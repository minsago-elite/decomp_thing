# Web bootstrap Git capability inventory

This inventory records the source contract behind the baseline fixture alignment for #1898. The fixture tests exercise API decoding and UI read gating. They do not execute Git or qualify native Git operations.

## Producers and public contract

`WebApiController` builds `/api/v1/bootstrap` by composing the registered workflow capabilities, the harness capability, and the two entries returned by `WebGitCapability.capabilities()`. Each Git entry has the same shape: `id`, `state`, `reasonCode`, `message`, `workflows`, `agentContractVersion`, and `limits`. The Git producer emits the pair in this order: `git`, then `git-import`. It does not emit `launch`.

`WebGitCapability` derives the entries from two independent facts: `GitAvailability` (server executable detection/version) and whether managed repositories and an import root are configured for the listener. The resulting states are:

| Server Git / listener configuration | `git` report | `git-import` report |
|---|---|---|
| Git executable absent | `unavailable`, `GIT_NOT_FOUND`, “Git is not installed or not executable on the server.” | Same unavailable reason and message as `git` |
| Git probe cannot produce a recognized version | `unavailable`, `GIT_PROBE_FAILED`, “The server's Git executable did not report a recognizable version.” | Same unavailable reason and message as `git` |
| Detected Git is below the minimum supported version | `unavailable`, `GIT_VERSION_UNSUPPORTED`, message identifies the detected numeric version and minimum | Same unavailable reason and message as `git` |
| A listener is given another runtime-unavailable result | `unavailable`, `GIT_RUNTIME_UNAVAILABLE`, with the message carried by that `GitAvailability.Unavailable` value | Same unavailable reason and message as `git` |
| Git is available but the listener has no managed-repository registry | `unavailable`, `GIT_REPOSITORIES_UNCONFIGURED`, “Managed repositories are not configured for this listener.” | Same unavailable reason and message as `git` |
| Git and managed repositories are available; import root is not configured | `supported`, null reason, “Git <version> is available for managed source repositories.” | `unavailable`, `GIT_IMPORT_UNCONFIGURED`, “Repository import needs an operator-configured import root on the server.” |
| Git, managed repositories, and import root are available | `supported`, null reason, “Git <version> is available for managed source repositories.” | `supported`, null reason, “Repositories placed under the server's import root can be imported by name.” |

`GitRuntime.detect()` resolves an absolute executable from the server's `PATH`, probes its version, and applies the minimum supported version, 2.36.0. Its current detection branches produce `GIT_NOT_FOUND`, `GIT_PROBE_FAILED`, and `GIT_VERSION_UNSUPPORTED`; `GIT_RUNTIME_UNAVAILABLE` is an allowed `GitAvailability.Unavailable` reason for a listener supplied by another runtime boundary, but no current source path constructs it. The numeric version may be reported separately in bootstrap runtime metadata; executable paths are not exposed. `WebGitCapability.repositories()` refuses repository routes with HTTP 503 `CAPABILITY_UNAVAILABLE`, preserving the Git-unavailable message or returning “Managed repositories are not configured for this listener.” when the registry is absent. The import capability is a separate report and does not authorize or execute an import by itself.

The baseline fixtures intentionally represent only the missing-executable case. They therefore use the exact `GIT_NOT_FOUND` pair and message above; they are not representative of every supported or unavailable production state. The explicit supported test variant in `bootstrap-git-capability-fixtures.test.tsx` changes the decoded `git` report in memory to reach the repository GET. It is a UI gate control, not a producer-generated bootstrap and not evidence that Git ran.

There are no responsive-specific bootstrap JSON documents in this change. Development and packaged-browser viewport controls reuse the same canonical bootstrap fixture at different base paths/viewports. The separate #628 simulated variant (a supported capability observation followed by a 503 `CAPABILITY_UNAVAILABLE` repository response) is not present in this branch; it belongs to #628's read-state simulation and must remain separate from the baseline fixture and from actual Git qualification.

## Fixture variants and controls

The ten baseline documents updated for #1898 are:

- `bootstrap.json`
- `bootstrap-retention.json`
- `bootstrap-scheduler-saturated.json`
- `bootstrap-scheduler-unavailable.json`
- `bootstrap-without-launch.json`
- `invalid-retention-accounting.json`
- `invalid-retention-error.json`
- `invalid-scheduler-bound.json`
- `invalid-scheduler-capacity.json`
- `invalid-scheduler-exact.json`

Each contains the canonical unavailable `git` / `git-import` pair. Their unrelated runtime, workflow, launch, limit, retention, and scheduler data is retained. Six workflow-only controls intentionally contain workflow capability entries but no Git entries:

- `bootstrap-workflow-launch.json`
- `invalid-launch-agent-contact.json`
- `invalid-launch-contract-version.json`
- `invalid-launch-multiple-workflows.json`
- `invalid-launch-unknown-tool.json`
- `invalid-launch-without-limits.json`

The other bootstrap variants remain in the manifest-driven contract suite. `contracts/web/v1/contract.schema.json` and `contracts/web/v1/verify.py` provide structural and semantic fixture validation. `frontend/tests/api-contract.test.ts` validates bootstrap fixtures through the actual response decoder as well as the shared fixture manifest.

## Generators and consumers

| Layer | Source | Responsibility |
|---|---|---|
| Runtime Git detection | `src/main/kotlin/decompengine/git/GitProcess.kt` (`GitRuntime.detect`) | Resolves and version-checks the server Git executable; supplies a bounded availability result. |
| Bootstrap Git producer | `src/main/kotlin/decompengine/web/WebGitCapability.kt` | Emits the ordered `git` and `git-import` capability pair and fixed public reasons/messages. |
| Bootstrap document producer | `src/main/kotlin/decompengine/web/WebApiController.kt` (`bootstrap`) | Adds Git reports to the public bootstrap alongside workflow and harness reports. |
| Fixture-backed development server | `frontend/dev/generate-fixtures.py` | Reads canonical `bootstrap.json`, changes simulated build/base-path metadata, then validates and records `/api/v1/bootstrap`; it does not independently define Git capability semantics. |
| Packaged-browser mock server | `scripts/packaged-browser-audit.mjs` | Loads contract fixtures into its mocked routes, including bootstrap. Its route behavior is fixture-driven and is not the production backend. |
| Shared frontend transport/decoder | `frontend/src/session/gateway.ts`, `frontend/src/api/client.ts`, `frontend/src/api/decode.ts` | Fetches `/bootstrap` through the versioned API client and validates the response contract. |
| Session projection | `frontend/src/session/session.ts` | Copies the decoded capabilities into the authenticated runtime snapshot while keeping session credentials out of that snapshot. |
| Runtime capability display | `frontend/src/routes/Runtime.tsx`, `frontend/src/jobs/WorkflowAvailability.tsx` | Displays reported capability states and workflow associations. |
| Job route and repository panel | `frontend/src/routes/Job.tsx`, `frontend/src/jobs/GitRepositoryPanel.tsx` | Passes the latest runtime reports to the panel. The panel reads repository data only when the `git` report has state `supported`; it does not gate on `git-import`. `frontend/tests/git-repository-panel.test.tsx` separately uses hand-built reports to cover `GIT_VERSION_UNSUPPORTED` with no read and a supported read path through a mocked transport; those are component controls, not decoded bootstrap producer evidence. |

The generated frontend `Capability` and `Bootstrap` types mirror the schema. These types describe report data; they do not prove that a particular executable or repository is available at the time a user acts.

## Evidence boundary

The #1898 fixture suite proves that the unavailable baseline decodes, produces no repository request, and displays its fixed refusal; it also proves that an explicit supported `git` variant reaches one repository GET through the client transport. The component suite supplies additional hand-built state controls, while development and packaged-browser checks reuse the fixture at different viewport/base-path settings. Fixture validation and packaged-browser mocks preserve test controls. None of these checks proves production Git execution, managed-repository initialization, Git import, or packaged native Git behavior; those remain separate issue scope, including #628.
