# Frontend bundle evidence

Measured for the #154 recovery / #157 build-identity frontend checkpoint on
2026-09-05, Linux x86-64, Node 24.20.0, npm 11.19.0, Vite 8.2.2 and TypeScript
6.0.3. Sizes below are bytes; gzip uses Node zlib level 9 for a repeatable
measurement. They do not claim server compression.

| Initial import closure | Raw bytes | Gzip bytes | D1 gzip ceiling |
| --- | ---: | ---: | ---: |
| JavaScript | 26,150 | 10,359 | 51,200 |
| CSS | 3,374 | 1,332 | 10,240 |

The runtime page is a separate lazy chunk. The local SVG is emitted as a separate
file. There are no downloaded fonts or workers in this slice; packaged-resource
tests must include them when later features add them.

Contributing production module counts: `application`: 14, `preact`: 3, `preact-iso`: 2. Application modules
include Vite's emitted preload helper. Counts are stable across checkout paths;
intermediate rendered module lengths need not be, even with identical final bytes.
`preact-render-to-string` satisfies the router peer dependency and contributes no
browser modules. No React compatibility, fixture, debug or test module is emitted.
Shipped code notices are recorded in `THIRD_PARTY_NOTICES.txt` for distribution.

The current gate passed strict typecheck, typed lint and 31 component/path/recovery/
identity tests. Two builds that each empty their output directory reproduced all
six output SHA-256s and the complete machine-readable report. Fresh locked
installation and different-Node rejection were verified in #151; this checkpoint
does not change the dependency lock. The #151 environment-sentinel check established
that the empty public environment prefix does not inject `VITE_*` values.

Chrome 149.0.7827.55 passed the final packaged ZIP at `/nested/`, using a relocated
read-only installation, unrelated working directory and application PATH without
Node/npm. Home, local icon/CSS and lazy Runtime rendered with exact embedded
UI/application identities. Intercepting only the Runtime chunk with a 404 yielded
one notice and no automatic retry/reload during five seconds; removing interception
and clicking Reload application once restored Runtime with one document request.
No mutations or external application requests occurred, installation bytes stayed
unchanged and no job-data directory was created. The tracked dependency-free driver
reproduced this result once. Exact archive/JAR/build identities, command and limits
are in [packaged browser evidence](../docs/web-packaging.md). This qualifies the
D1 public shell/recovery path; it does not simulate a full server-version upgrade
or establish authenticated workflow, browser performance or accessibility gates.

| Output | Raw bytes | Gzip bytes | SHA-256 |
| --- | ---: | ---: | --- |
| `.vite/manifest.json` | 609 | 257 | `fdbf46002af0b6ac0a9bdc21b39d5a8cc4166e045c6b56a9d1b89d92635e8cdc` |
| `assets/index-4GS293OH.css` | 3,374 | 1,332 | `eafe3e15d2ce4c61d9342d4199c46552b181fda92748c112628e8bee131237c6` |
| `assets/index-Qot48nQH.js` | 26,150 | 10,359 | `da333e03c96c813ac1f7619a0907ca8c9c366c01e31b4581436d909f6afebf75` |
| `assets/mark-DPpOXuhp.svg` | 289 | 207 | `0a7608e6061d66bfeff7515d0a300d5b31c593beee2e8cf0ff2decc7567c979c` |
| `assets/Runtime-DlzLaqGO.js` | 1,048 | 458 | `6aaef44f2b4f6db5f97dd6fe467bc54b968ac9c533851f810a06b4b355b3fd84` |
| `index.html` | 664 | 378 | `9d21c8a0bc96b89ffd61194ae8acbe59409cafccd549fe9aec2a63e679f98952` |

Recreate the report with `npm --prefix frontend run build`; generated metadata
lives at `build/frontend/bundle-report.json` and `bundle-composition.json`, outside
the served `dist/` tree. These asset identities describe this frontend checkpoint
and must be refreshed when frontend source changes. They do not qualify the full
workbench, accessibility conformance or the native/runtime distribution closure.
