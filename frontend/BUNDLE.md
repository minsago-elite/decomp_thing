# Frontend bundle evidence

Measured for the #161 SPA-session / #159 generated-client checkpoint on
2026-09-05, Linux x86-64, Node 24.20.0, npm 11.19.0, Vite 8.2.2 and TypeScript
6.0.3. Sizes below are bytes; gzip uses Node zlib level 9 for a repeatable
measurement. They do not claim server compression.

| Initial import closure | Raw bytes | Gzip bytes | D1 gzip ceiling |
| --- | ---: | ---: | ---: |
| JavaScript | 67,956 | 20,324 | 51,200 |
| CSS | 3,409 | 1,342 | 10,240 |

The strict shared-schema decoder, bounded native fetch and page-local session
state add 9,965 gzip JavaScript bytes to the earlier 10,359-byte recovery shell.
No npm dependency was added. The runtime page remains a separate lazy chunk and
the local SVG remains a file. There are no downloaded fonts or workers in this
slice; packaged-resource tests must include them when later features add them.

Contributing production module counts are `application`: 25, `preact`: 3 and
`preact-iso`: 2. Application modules include the generated schema and Vite's preload
helper. `preact-render-to-string` satisfies the router peer dependency and contributes
no browser modules. No React compatibility, fixture, debug or test module is emitted.
Shipped code notices remain in `THIRD_PARTY_NOTICES.txt` for distribution.

This checkpoint passed the shared-schema generator drift check, strict typecheck,
typed lint and 125 tests covering shell/navigation/recovery, development transport,
contracts/native fetch and session state/controls. The session race correction also passed deferred-response regressions and an
independent review. The development fixture test was rerun in an isolated source
copy with its build parent absent, fixing the initial hosted-CI regression.
The production build emptied its output and passed the existing byte/module/sentinel gates. Exact dependency-lock
installation and different-Node rejection were verified in #151; dependencies did
not change. The #155 build, before session wiring, also proved development endpoint
and environment sentinels absent while preserving the prior six asset hashes.

The earlier packaged ZIP browser checkpoint used Chrome 149.0.7827.55 at `/nested/`,
a relocated read-only installation, unrelated cwd and application PATH without
Node/npm. It verified home, local icon/CSS, exact identities and lazy-chunk recovery:
one notice, no automatic reload/retry during five seconds and one successful explicit
reload. Exact archive/JAR/build identities and the tracked recreation command are in
[packaged browser evidence](../docs/web-packaging.md). That historical artifact
predates this session payload; its hashes must not be attributed to this build.
The current source also prevents route-focus scrolling while a version notice is
active. Authenticated packaged-session journeys require the matching server build.

| Output | Raw bytes | Gzip bytes | SHA-256 |
| --- | ---: | ---: | --- |
| `.vite/manifest.json` | 609 | 258 | `cb2a6d3b6570fdf8e36c2a256ecaf31d4f311a179d7e6a3d2b19f1e3bdfe1889` |
| `assets/index-CXRA2Hc9.css` | 3,409 | 1,342 | `fd73d7bfddf9749103bd04b94f39ccdb39fe57a49a8828a77d001a0bdb318acb` |
| `assets/index-D9ex1CGJ.js` | 67,956 | 20,324 | `b297c9c1b372df3e8d77a47e032a8fda21c316e237ede501bda369d11a4c67f6` |
| `assets/mark-DPpOXuhp.svg` | 289 | 207 | `0a7608e6061d66bfeff7515d0a300d5b31c593beee2e8cf0ff2decc7567c979c` |
| `assets/Runtime-CL7vCQbI.js` | 1,048 | 458 | `bf59bb8fb346764db9dea5867acfc1080df40f01ab52ac1eb4fa30b283176471` |
| `index.html` | 664 | 377 | `fbac8436570275010ea938f89cd89f25d994d5e08c19ef93f1ce49374dad5697` |

Recreate the report with `npm --prefix frontend run build`; generated metadata
lives at `build/frontend/bundle-report.json` and `bundle-composition.json`, outside
the served `dist/` tree. These asset identities describe this frontend checkpoint
and must be refreshed when frontend source changes. They do not qualify the full
workbench, accessibility conformance or the native/runtime distribution closure.
