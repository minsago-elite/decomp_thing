# D2 #473 HTTP negotiation checkpoint — 2026-09-19

This is local, PR-candidate evidence for [#473](https://github.com/minsago-elite/decomp_thing/issues/473),
the error/negotiation slice of [#159](https://github.com/minsago-elite/decomp_thing/issues/159).
It is not merged behavior, browser qualification, a D2/D13 release claim, or evidence that
unimplemented capabilities exist. The test listener uses inert jobs and no live agents.

## Real HTTP route matrix

`WebNegotiationMatrixTest` sends requests through actual loopback listeners and checks status,
`Allow`, JSON content type, no-store policy, matching request IDs and, where applicable, the
legacy versus v1 envelope. It preserves the seeded job record byte-for-byte.

| Surface | Covered behavior |
| --- | --- |
| v1 JSON reads (`bootstrap`, job, unknown route/major) | exact/wildcard Accept, specific `q=0` exclusion, overlong/repeated Accept, invalid query, missing resource and unavailable capability as explicit 404 |
| v1 read-only and artifact routes | unsupported methods as 405 with `Allow`, HEAD without a body, binary download accepts `application/octet-stream` but rejects HTML/JSON before artifact storage lookup |
| v1 and legacy mutation admission | JSON session/upload and legacy multipart Content-Type errors as typed 415; no workflow execution is invoked |
| legacy JSON job and event reads | supported ranges, exclusion, unsupported methods, HEAD metadata, old success shape, 404 unknown route and 400 repeated Accept |
| legacy `POST /jobs` | JSON success/error for explicit JSON or `application/*`; HTML redirect/error when JSON is excluded but HTML admitted; 406 when neither representation is admitted |
| error classes | real v1 HTTP 400/404/405/406/415 and 429 (`SESSION_LIMIT`, retry header/body); existing `WebApiControllerTest` verifies 409 idempotency/artifact conflicts; a separate real listener injects a 500 through the shared v1 error renderer and verifies safe JSON/request-ID behavior |

The 500 case exercises the renderer with a deliberately injected `WebAccessDenied`; it does not
claim to fault-inject an unexpected production controller exception. The controller's generic
catch maps that path to `INTERNAL_ERROR`, but broader failure-injection qualification remains
appropriate before a release claim.

## Necessary handler corrections

- The bounded raw exploration download now checks `Accept` against its actual
  `application/octet-stream` response before reading artifact storage. Existing download tests
  explicitly request that media type; ordinary browser `*/*` downloads continue to work.
- The legacy dual-format upload no longer treats a textual `application/json;q=0` substring as
  a request for JSON. It uses the bounded shared media-range parser before consuming the body,
  and retains the HTML default when Accept is absent or only `*/*`.

The legacy-mode server does not expose v1 job routes. The matrix asserts that limitation rather
than advertising a broken successor link. Deprecation/successor links, a real sunset release/date,
complete legacy URL migration and D13 release parity remain outside this checkpoint. No new
workflow, Git, revision or acceptance authority was added.

## Verification

- Bun 1.3.1 offline dependency install, generated API check, TypeScript no-emit check, Vite
  production build and bundle report passed in this `/tmp` worktree. The repository's pinned
  Node manifest verifier checked the Bun-built assets; no frontend source or lockfile changed.
- `./gradlew compileTestKotlin --offline` passed with the Bun-built assets.
- `./gradlew test --tests decompengine.web.WebNegotiationMatrixTest --tests
  decompengine.web.WebApiControllerTest --tests decompengine.web.UploadServerTest --offline
  --no-daemon -PfrontendNodeHome=/tmp/decomp-node-24 -x frontendInstall -x frontendBuild
  -x verifyFrontendToolchain` passed: 4 + 12 + 47 = 63 tests, zero failures/skips.

One intervening rerun exposed an unrelated timing-sensitive `UploadServerTest` shutdown case:
its second `stop()` observed an active request immediately after releasing a blocked worker.
That case passed in isolation, and the final full 63-test selection passed without changing
shutdown code. This is a suite stability caveat, not evidence of a #473 route regression.

The Kotlin suites use synthetic ELF fixtures, temporary owned stores, disposable listeners and
inert analyzer/reconstructor callbacks. They do not require an external Ghidra installation.
