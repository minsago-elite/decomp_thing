# #501 draft: exact metadata and unavailable presentation

This is a focused draft checkpoint for [#501](https://github.com/minsago-elite/decomp_thing/issues/501), not full acceptance or production qualification. The Job API does not supply a durable input-file digest, so the page labels that value unavailable rather than substituting the job-version or report-artifact digest.

## Implementation and assertions

- The job overview still shows the exact job identity, supported ELF fields, and hexadecimal entry address directly from the validated v1 Job envelope. The input SHA-256 field explicitly says it is not reported by the Job API.
- Dashboard and overview share exact formatting: all decimal byte digits remain intact, timestamps retain fractional precision and their original offsets in semantic `<time dateTime>` elements, and every job status has a readable label. No `Number` conversion or floating-point byte-unit estimate is used.
- A corrupt stored job or malformed/unsupported Job response shows a metadata limitation and no binary facts. Invalid, partial, or unknown exploration reports without summaries show a limitation and never render missing metrics as zero.

## Verification

From `/tmp/decomp-d-501/frontend`:

```sh
/home/june/.bun/bin/bun install --no-save --ignore-scripts
/home/june/.bun/bin/bunx --bun tsc --noEmit
/home/june/.bun/bin/bunx --bun eslint . --max-warnings 0
/home/june/.bun/bin/bun ../scripts/generate-web-api.mjs --check
/home/june/.bun/bin/bun ./node_modules/vite/bin/vite.js build
/home/june/.bun/bin/bun scripts/bundle-report.mjs
/tmp/decomp-node-24/bin/node ./node_modules/vitest/vitest.mjs run tests/metadata-format.test.ts tests/job-dashboard.test.tsx tests/run.test.tsx
```

The three affected Vitest files passed 29/29. Bun typecheck, lint, generated-contract check, and production build passed; the initial JavaScript bundle stayed below its budget. Bun's Vitest startup failed before tests with host-name DNS errors on this machine, so the repository's pinned Node 24.20.0 ran Vitest. Bun's transient lockfile was removed; `package-lock.json` was unchanged.

The full pinned-Node suite, rerun with subprocess and loopback permissions, passed 357/358. Its only failure was the pre-existing upload-progress timer assertion in `tests/upload.test.tsx:159` (two GETs instead of one), already tracked by [#526](https://github.com/minsago-elite/decomp_thing/issues/526) and [PR #1068](https://github.com/minsago-elite/decomp_thing/pull/1068); no upload code changed here. The earlier sandboxed full run also had permission-only subprocess/listener failures and is not counted as a product regression.

## Remaining boundary

V1 streamed upload computes an input SHA-256 and stores it in some private idempotency receipts, while historical jobs have no such recorded digest. The versioned Job contract exposes neither a verified current-file hash nor a provenance-labelled upload-time hash. A future change must decide which claim it can support, handle historical null values, bind persistence and response versions correctly, and test stale or changed bytes. This draft does not mark #501 complete. Packaged-browser and cross-browser metadata qualification were not rerun here.
