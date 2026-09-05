# Initial shell bundle evidence

Measured for #151 on 2026-09-05, Linux x86-64, Node 24.20.0, npm 11.19.0,
Vite 8.2.2 and TypeScript 6.0.3. Sizes below are bytes; gzip uses Node zlib level 9
for an explicit, repeatable measurement. They do not claim server compression.

| Initial import closure | Raw bytes | Gzip bytes | D1 gzip ceiling |
| --- | ---: | ---: | ---: |
| JavaScript | 23,826 | 9,600 | 51,200 |
| CSS | 3,014 | 1,231 | 10,240 |

The runtime page is a separate lazy chunk (573 raw / 325 gzip bytes). The local
SVG is 289 raw / 207 gzip bytes. There are no downloaded fonts or workers in this
slice; packaged-resource tests must include them when later features add them.

Production module owners are application code (including Vite's emitted preload
helper), `preact` and `preact-iso`: 10, 3 and 2 contributing modules respectively.
Composition uses stable module counts because the bundler's intermediate rendered
lengths can vary with checkout paths even when final asset bytes are identical.
`preact-render-to-string` satisfies the router peer dependency and contributes no
browser modules. No React compatibility, fixture, debug or test module is emitted.

Verification used a fresh `npm ci --ignore-scripts`, strict typecheck, typed lint,
13 component/path tests and a build from an absent `build/frontend/dist/` directory.
The fresh installation reproduced the shell output. After the final narrow-screen
CSS adjustment, isolated and workspace builds reproduced all six output SHA-256s
and the complete machine-readable report. A `VITE_PRIVATE_TEST` environment variable
set to a test sentinel did not change bytes or appear in output. The toolchain
check correctly rejected the host's different Node 26.7.0. Production dependency
audit returned zero advisories at the time of this run; this is a dated observation,
not a guarantee about future advisories. The production shell was also visually
inspected in Chrome for Testing 149.0.7827.55 at 1280×900 and 390×844.

| Output | Raw bytes | Gzip bytes | SHA-256 |
| --- | ---: | ---: | --- |
| `.vite/manifest.json` | 609 | 255 | `5e3586064131411e57ea07b0f6cacae9d9aada46a5732f6967510ff811ccf4a5` |
| `assets/index-D1lA0jr0.js` | 23,826 | 9,600 | `8a9088a3840eccde32518ca6f1c2ecc657b8307bdd046a50698898ee78a2220e` |
| `assets/index-DHa-GeQ1.css` | 3,014 | 1,231 | `69d7cb588c22c563be053109662335ea4fc8a995c8ce92aa6e4ebe645f879ca8` |
| `assets/mark-DPpOXuhp.svg` | 289 | 207 | `0a7608e6061d66bfeff7515d0a300d5b31c593beee2e8cf0ff2decc7567c979c` |
| `assets/Runtime-DVupSY2j.js` | 573 | 324 | `e2134666c849187175ffb049bf1ed2dfca3dd01473c0e6252c26505b737d86a7` |
| `index.html` | 664 | 374 | `9bad8507dcba6adc9b4e5fe8ee8b517c0cfd22faf630d71a70072d2c97fefbbd` |

Recreate the report with `npm --prefix frontend run build`; generated metadata
lives at `build/frontend/bundle-report.json` and `bundle-composition.json`, outside
the served `dist/` tree. These asset identities describe the initial D1 shell and
should be replaced by release-specific evidence when frontend source changes.
This gate does not qualify packaged JVM serving, full workbench behavior,
accessibility conformance or browser performance.
