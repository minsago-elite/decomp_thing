# Authenticated server instance comparison

Tracking: [D4.4 #179](https://github.com/minsago-elite/decomp_thing/issues/179).

SPA bootstrap now includes optional `serverInstanceId`, a random 32-character hexadecimal value generated once for each UploadServer API-controller lifetime. Authenticated sessions on the same server observe the same value. Reopening the server over the same job store generates a new value; it is not derived from stored jobs, credentials, build IDs, paths or process identifiers. Unauthenticated bootstrap requests remain denied. The value confers no authorization and is never accepted as a request credential.

The browser session retains the last successfully authenticated value in page memory. After a later successful bootstrap, a changed value produces a distinct session notice: the application restarted or was replaced, and this session is connected to the new instance. The raw value is excluded from observable session snapshots, rendered text, browser storage and peer messages. Disposal forgets the baseline. Existing request-generation and abort checks prevent obsolete bootstrap completions from changing session state.

Initial connection does not infer a restart. Failed reads, retention gaps, lost streams and expired/missing sessions do not establish an instance change. A bootstrap without the optional field clears the comparison baseline, so an unsupported-server interval is not treated as evidence of restart. The notice describes the most recent successful comparison and clears on a subsequent successful check of the same instance. There are no new automatic requests or mutation retries.

This signal becomes available after authentication succeeds on the new instance. It does not diagnose an unavailable server before reconnection, refresh a consumed sign-in link, authorize any retained action or replace attempt/revision reconciliation. A fresh operator sign-in link remains necessary when restart invalidates the old session.

Verification covers real HTTP bootstrap stability across sessions and changed identity across two server lifetimes on the same store, with old-cookie and unauthenticated rejection. Session/component tests cover unchanged/changed values, missing-field compatibility, failed reads, exclusion of raw identifiers and the visible notice. Full real-browser stop/restart/sign-in/attempt reconciliation remains a separate D4 qualification requirement; this change does not complete #179.

[Retained evidence](evidence/web-server-instance-20260908/manifest.json): 357 frontend tests, lint/typechecked build, 50 positive/42 negative contract fixtures, 299 selected JVM tests, distZip and packaged history browser passed. The browser journey supplies regression coverage; the full stop/restart/sign-in scenario remains unqualified.
