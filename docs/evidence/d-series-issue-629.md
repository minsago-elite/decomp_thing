# D11 issue #629: job lifecycle checkpoint

**Date:** 2026-11-12  
**Base:** `master` at `2b1121999c806d5b3f89d3723fca8a39879c49b1`  
**Scope:** frontend-only job organization and deletion presentation. The working source was an
isolated archive derived from the base above; no backend, API contract, or generated file changed.

## Changes qualified locally

- A newer version of the same job preserves edited fields in memory and shows the verified
  current label and archive state. A deliberate save uses the currently observed version; no
  mutation is replayed automatically.
- A 412 is treated as a rejected write. A readback is adopted only when it names the same job
  and supplies a different opaque version. Untouched form fields follow that readback; edited
  fields remain. A missing, stale, foreign, or cancelled readback says current values could not
  be verified.
- A 2xx organization response emits a library-change hint, including when its body is malformed
  or does not confirm the requested values. The UI reports “Saved” only after a bound,
  value-matching acknowledgement and readback. Same-tab refreshes from that acknowledged
  mutation are not misreported as concurrent edits.
- Deletion operation states and protection reasons use fixed client copy. Unknown values use a
  generic fallback; free-form server messages are not rendered.

## Verification

Using the repository-pinned Node 24.20.0 / npm 11.19.0 toolchain:

- `npm test -- --run tests/job-lifecycle-629.test.tsx tests/job-lifecycle.test.tsx tests/job-deletion-reconciliation.test.tsx` — **3 files, 62 tests passed**.
- `npm test` — **85 test files, 1,227 tests passed**.
- `npm run typecheck` — passed; generated web API contracts verified.
- `npm run lint` — passed with zero warnings.

The new tests use the production API client and real components with mocked `fetch`; they do
not run a browser or live server. This checkpoint does not close #629. It does not qualify
screen-reader behavior, real multi-tab timing, hosted exact-head CI, or the full identity-bound
command matrix.
