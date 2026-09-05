# Frontend bundle evidence

Measured for the #154 base-path and resource-identity URL checkpoint on
2026-09-05, Linux x86-64, Node 24.20.0, npm 11.19.0, Vite 8.2.2 and TypeScript
6.0.3. Sizes below are bytes; gzip uses Node zlib level 9 for a repeatable
measurement. They do not claim server compression.

| Initial import closure | Raw bytes | Gzip bytes | D1 gzip ceiling |
| --- | ---: | ---: | ---: |
| JavaScript | 70,606 | 21,198 | 51,200 |
| CSS | 3,409 | 1,342 | 10,240 |

The centralized URL and resource-identity checks add 874 gzip JavaScript bytes
to the preceding 20,324-byte session/client checkpoint.
No npm dependency was added. The runtime page remains a separate lazy chunk and
the local SVG remains a file. There are no downloaded fonts or workers in this
slice; packaged-resource tests must include them when later features add them.

Contributing production module counts are `application`: 25, `preact`: 3 and
`preact-iso`: 2. Application modules include the generated schema and Vite's preload
helper. `preact-render-to-string` satisfies the router peer dependency and contributes
no browser modules. No React compatibility, fixture, debug or test module is emitted.
Shipped code notices remain in `THIRD_PARTY_NOTICES.txt` for distribution.

This checkpoint passed the shared-schema generator drift check, strict typecheck,
typed lint and 156 tests covering shell/navigation/recovery, development transport,
contracts/native fetch and session state/controls. The session race correction also passed deferred-response regressions and an
independent review. The development fixture test was rerun in an isolated source
copy with its build parent absent, fixing the initial hosted-CI regression.
The production build emptied its output and passed the existing byte/module/sentinel gates. Exact dependency-lock
installation and different-Node rejection were verified in #151; dependencies did
not change. The #155 build, before session wiring, also proved development endpoint
and environment sentinels absent while preserving the prior six asset hashes.

The earlier pre-merge session ZIP passed actual Chrome 149.0.7827.55 browser
journeys at `/nested/`, from a relocated read-only installation, unrelated cwd
and application PATH without Node/npm. Home/icon/CSS and lazy Runtime showed
exact UI build `0568621730b941560737aa57653d6e5a5c2dca8d9ce8370350a7556bc8bdf039`
and application `0.1.0`. A missing Runtime chunk produced one visible notice,
no automatic retry/reload in five seconds and one successful explicit reload;
the title stayed in the viewport after the focus correction.

Both direct JVM and real Vite-to-JVM journeys verified fragment removal before
fetch, cookie authentication, GET-only session restoration, explicit logout,
consumed-link denial and empty local/session storage and no job/native action.
The direct report is `build/packaged-browser-OgbK9x/report.json`; the actual proxy
report is `build/proxy-browser-jroRhh/report.json` and also confirms HMR connected
and backend bootstrap 200 without a CORS allowance. Exact pre-merge ZIP/JAR
identities, limits and tracked `--mode session`/`--mode proxy` recreation commands
are in [packaged browser evidence](../docs/web-packaging.md). Later distributions
require their own verification; matching frontend assets do not establish the
identity of a changed native/runtime closure. The subsequent merged package was
separately verified with the official pinned Chrome: direct session/recovery at
`build/packaged-browser-u6h1zm/report.json`, and real proxy at
`build/packaged-browser-elCmmT/report.json`. The packaging document records its
new ZIP/JAR hashes and unchanged UI build identity; both runs confirmed shutdown
and owned-work cleanup. Those browser artifacts precede this URL-helper payload;
the current six-file UI build is
`ac0b11282638ddd059e46c25af43bf8947c4b41d4e0e445df30689b3d33680aa`.

| Output | Raw bytes | Gzip bytes | SHA-256 |
| --- | ---: | ---: | --- |
| `.vite/manifest.json` | 609 | 257 | `c2b1138c95eee4638501f9ed7ed6610f77f64083eb67c1b7864ed79b4ad71468` |
| `assets/index-CXRA2Hc9.css` | 3,409 | 1,342 | `fd73d7bfddf9749103bd04b94f39ccdb39fe57a49a8828a77d001a0bdb318acb` |
| `assets/index-DDdkV_rX.js` | 70,606 | 21,198 | `61795bb2e750a67cd6615a437171ed68c1c3a09b2a222faeb36f2ae149d5ffdb` |
| `assets/mark-DPpOXuhp.svg` | 289 | 207 | `0a7608e6061d66bfeff7515d0a300d5b31c593beee2e8cf0ff2decc7567c979c` |
| `assets/Runtime-D1QAqjiL.js` | 1,048 | 457 | `1b7cc2d8efe4bbb8ba7b27bbe6378cdd01809f81dc857bb3775d84cba22ad69d` |
| `index.html` | 664 | 378 | `abdc2564552152b76492b9463b94a34d2928d580f836bd79c8894b9046a14ffe` |

Recreate the report with `npm --prefix frontend run build`; generated metadata
lives at `build/frontend/bundle-report.json` and `bundle-composition.json`, outside
the served `dist/` tree. These asset identities describe this frontend checkpoint
and must be refreshed when frontend source changes. They do not qualify the full
workbench, accessibility conformance or the native/runtime distribution closure.
