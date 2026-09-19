# D1 completion audit

The remaining D1 issue, #154, required end-to-end base-path coverage for actual
event and download consumers. Those consumers are now present and qualified.
This audit maps all six #154 criteria to current source and retained evidence;
it does not redefine D1 around the earlier shell-only checkpoint.

Verified application source: `d6867ae3696b656fa98383392858e042cf9a7953`.
UI build: `323d13cfb9cbd17714252dde962b10ae4c329aa9601bce3c7fc0443b07755d09`.
The routing, URL helper, asset-recovery and JVM transport implementations match
their already-merged master counterparts. Later stacked changes add receipt-age
and peer-session presentation without replacing those implementations.

| #154 requirement | Current evidence |
| --- | --- |
| Recognized direct links/refresh and correct namespace errors | `UploadServerSpaTest` exercises root and prefixed UI routes, API/asset errors, no-store HTML and refresh. `verifyPackagedWeb` starts actual ZIP/TAR distributions; the retained history journey opens/reloads Runtime, jobs and exact attempts under `/nested/`. |
| Immutable asset policy and fresh entry/session/capability responses | `EmbeddedWebAssetsTest` verifies exact manifest digests, immutable cache policy and ETags. SPA/API tests verify no-store HTML and private JSON envelopes. Packaged serving checks verify the actual archive bytes. |
| Conditional GET/HEAD, lengths, validators and supported encoding | JVM and packaged tests verify GET/HEAD/304 behavior, empty HEAD/304 bodies, exact lengths and strong asset validators. The adapter serves identity bytes only; it does not claim HTTP compression or vary compressed representations. |
| Recoverable old-tab/new-server failures | The new [actual two-package report](evidence/web-d1-upgrade-final-20260905.json) retains one old tab across owned JVM replacement on the same origin, observes a real old-chunk 404 without interception, one notice, zero automatic reloads/retries/mutations, and one explicit reload into the current build. |
| Consistent supported base path across consumers | The [current packaged history/session report](evidence/web-session-tabs-20260905.json) traverses real links, authenticated reads, snapshot/polling activity and native exploration artifact download at `/nested/`, preserving exact attempt identity and downloaded bytes. Root/nested URL helper and HTTP tests complement this behavioral evidence. No browser Worker/SharedWorker/ServiceWorker resources are implemented or emitted; adding one requires extending packaged namespace coverage. |
| Encoded paths, queries, trailing slashes and dotted assets | `UploadServerSpaTest`, `EmbeddedWebAssetsTest`, frontend path tests and packaged serving checks cover canonical redirects, query preservation, encoded-path rejection, unknown resources and hashed dotted filenames. |

The base-path proof now uses the real event API/client and native artifact
consumer, not just URL construction or a synthetic upstream. Successful content
and identity assertions run against a server whose private routes and cookie are
confined to the deployment prefix. Opening the Runtime view adds no bootstrap
request; events remain authenticated observations and downloads preserve their
bound report bytes. No workflow runs in these browser journeys.

## Verification performed

- `./gradlew -PfrontendNodeHome=… test --tests 'decompengine.web.*' --tests 'decompengine.jobs.AgentProgressJournal*Test' verifyPackagedWeb` passed: 163 JVM tests, plus relocated read-only ZIP and TAR serving with Node absent from application PATH. All seven current public assets match the embedded manifest.
- The full frontend suite passed: 267 tests, including URL/client, route recovery, development transport, session and current activity consumers.
- Manifest and upgrade-driver tests passed: 11 tests, including deterministic synthetic inventories and rejection of changed, omitted, duplicate, stale and source-map assets.
- The actual two-version upgrade passed against complete distribution ZIPs. The previous ZIP SHA-256 is `c9de7b71e1f265ee7eb62285fd72de497dcb7cab830f00033c40162456fea36a`; the current ZIP SHA-256 is `bd67fc9bc47682fb77e8218810057375c7176e39df22412115379c882ea6cb8f`. The old lazy Runtime chunk is genuinely absent from the new package. Both installations remain unchanged and shutdown/owned-work cleanup is confirmed.

[Audit summary](evidence/web-d1-completion-20260905.json) binds the packaged
results and verification-log digest. Browser qualification used Chrome
149.0.7827.55, Node 24.20.0 and JDK 21 on Linux, with test-only `--no-sandbox`.
It is not a claim of all-browser, optional reverse-proxy or full D-series release
qualification.

## Other D1 issues

The six other D1 issues are closed with their own completion evidence, reviewed
alongside their current source:

- #151: pinned toolchain/lockfile, strict build/test commands, local-only Preact
  shell and release module inventory in `frontend/package.json`, README and Vite
  build guards. The current frontend and browser checks pass.
- #152: Gradle install/build/manifest/Sync dependencies, stale-resource removal
  and duplicate rejection remain in `build.gradle.kts`; current ZIP/TAR builds
  and synthetic inventory rejection tests pass.
- #153: classloader-based manifest allowlisting and bounded resource serving
  remain covered by JVM class-directory/JAR tests and current packaged serving.
- #155: explicit Vite backend/fixture modes remain isolated from production;
  real local transport and shared-schema fixture tests are included in the
  passing frontend suite. Their earlier browser/HMR evidence remains recorded.
- #156: the supported Linux POSIX thin-JAR distribution contract remains in
  `docs/web-packaging.md`; runtime-reference generation follows the final JAR.
  Current relocated ZIP/TAR launch and shutdown checks pass. Earlier dedicated
  runtime-closure evidence remains recorded; this audit does not claim a new
  Docker or unsupported standalone-fat-JAR qualification.
- #157: deterministic archive ordering/timestamps, canonical asset manifests,
  source-map rejection and third-party inventory policy remain implemented.
  Current synthetic determinism/integrity tests and exact packaged asset/build
  identity checks pass; earlier clean-build byte comparisons remain recorded.

With #154's last criterion now evidenced, D1's supported embedded-SPA delivery
outcome is complete. D2–D13 application, workflow, Git, security and release
outcomes remain tracked independently and are not closed by this audit.
