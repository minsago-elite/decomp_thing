# D11 #1877 WebKit request-context diagnostics — 2026-11-12

## Scope

Source checkpoint: `3e53e0d7250c8cf45ef80d330ff8d4554308ebf3`, based on diagnostic commit
`9c3b99efcc9d90ea1461f696f6833db0cea18a54` and ultimately on master
`2b1121999c806d5b3f89d3723fca8a39879c49b1`.

This change adds event-only, bounded diagnostics to the packaged cross-engine runner. It records
fixed route, method, origin-class, resource-type, response-status and failure labels; page route
phase; main-frame navigation overlap for cancelled requests; and a page-error correlation only
when the error text contains the matching request path. Raw URLs, query strings, request bodies,
error text, hostnames and path identifiers are not included in the new `pageExceptionContexts`
report field. API-path matching occurs transiently in memory. If collection exceeds a bound or an
event cannot be classified, the snapshot says `countsIncomplete` rather than implying complete
observation.

The instrumentation makes no requests, waits, page evaluations or policy changes. It is additive:
the runner keeps its existing exception list and continues to fail on every observed page exception,
CSP violation and missing CSP policy. An unmatched page error remains a failure and is reported as
unmatched; an observed event is never suppressed by this diagnostic.

## Incident context

The retained WebKit failure in [run 41675144716](https://github.com/minsago-elite/decomp_thing/actions/runs/41675144716),
artifact `13250073383`, reports a Fetch API access-control error while loading a nested job-run
endpoint. That report does not retain request/page/phase linkage sufficient to distinguish a
same-origin policy refusal, a navigation cancellation or missing collector attribution.
Later cross-engine run
[42139840189](https://github.com/minsago-elite/decomp_thing/actions/runs/42139840189) passed for
Firefox and WebKit and observed no page exceptions. The original failure has therefore not been
reproduced, and this change does not establish its cause or a source repair.

## Verification at source checkpoint

On Node `v26.12.1`, from the clean source snapshot at the source checkpoint:

- `node --check scripts/packaged-browser-exception-context.mjs` — passed.
- `node --check scripts/packaged-browser-engines.mjs` — passed.
- `node --test scripts/test-packaged-browser-exception-context.mjs` — 6 passed.
- `node scripts/test-packaged-browser-engine-adapter.mjs` — 6 passed.
- `node scripts/test-packaged-browser-audit.mjs` — 28 passed.

The new controls exercise a WebKit-style access-control page error correlated with a failed run
read, an HTTP refusal, cross-origin classification, cancellation overlapping navigation, bounded
collection and runner wiring. They use fake event emitters. They do not reproduce the historical
browser incident, prove Playwright/WebKit event ordering, or qualify the packaged Firefox/WebKit
journeys at this new source checkpoint. The existing exact-head browser run remains required.

## Remaining acceptance

Keep #1877 open. The original failure is not causally diagnosed; no repair is proposed. The next
qualification must run the packaged Firefox and WebKit journeys with this exact source, inspect
`pageExceptionContexts`, and retain the normal failure outcome if the policy error or another
unexpected browser exception recurs. Chromium remains a separate required journey.
