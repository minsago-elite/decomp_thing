# Packaged session-status accessibility evidence (#1895)

This records local fixture evidence for the packaged SPA session-status and
connection-notice boundary. It is not hosted CI, production-provider, or full
WCAG qualification.

## Source and artifact binding

- Implementation commit: `e67d016b8729fda68f46ad5c5c2d21750df8992c`
- Base: master `2b1121999c806d5b3f89d3723fca8a39879c49b1`, integrated into PR
  #1908 by merge commit `802a9f2302c753a5e04ef08470bac735053975a8`.
- Packaged audit report `driverCommit` equals the implementation commit above.
- Distribution ZIP SHA-256:
  `bfb2a05356fa1cc56aed1718e9014b44828f4eca20c4a4dcde281d4be366dd5a`
- Application JAR SHA-256:
  `13dcced0f81b990896d80e93e529964ceb22119bbafff4ea0831d1ed1c3ea5e3`
- Frontend asset build ID: `bbbf1f098b193bbf2db5d488bead1296e04b5db5c806cc04464b299c44b4e619`
- Audit driver SHA-256: `648b37983acd320e0201cff6a767331f76081dd5e3ad2920301111fd8a755823`
- Audit test SHA-256: `dcae37187d6c99c2124f79e0c14dc3b753ae902e60c257a68e60d007d1986f1d`

## Verification

- `node --test scripts/test-packaged-browser-audit.mjs`: 28 passed.
- `git diff --check`: passed.
- `./gradlew distZip` with the pinned Node 24.20.0/npm 11.19.0 toolchain:
  passed.
- Packaged `--mode audit` with Chrome 149 and the bundled JVM: passed. The
  report records 120 layout, 48 contrast, and 24 focus measurements; 30
  validated screenshots; trusted offline and online events; the named
  connection region and status; an authenticated session retained after
  reconnect; and successful browser/application shutdown and scratch cleanup.
- The audit includes a real in-app session revalidation after reconnection.
  It does not claim that the server cancels work when the browser goes offline.

The local report and screenshots are retained in the ignored build output at
`build/d11-1895-master-merge/qualify-e67/build/packaged-browser-PYy8jp/`.
The report SHA-256 is
`cf0c11e41d07bd860f73675a8364acd3854beeb50db7e44b1e0ba017961392e7`.

This local packaged run is fixture evidence only. The PR's required hosted
checks and review threads remain the merge gate; this document does not mark
the issue or its broader accessibility scope complete.
