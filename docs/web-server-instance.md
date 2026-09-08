# Authenticated server instance comparison

Tracking: [D4.4 #179](https://github.com/minsago-elite/decomp_thing/issues/179).

SPA bootstrap now includes optional `serverInstanceId`, a random 32-character hexadecimal value generated once for each UploadServer API-controller lifetime. Authenticated sessions on the same server observe the same value. Reopening the server over the same job store generates a new value; it is not derived from stored jobs, credentials, build IDs, paths or process identifiers. Unauthenticated bootstrap requests remain denied. The value confers no authorization and is never accepted as a request credential.

The browser session retains the last successfully authenticated value in page memory. After a later successful bootstrap, a changed value produces a distinct session notice: the application restarted or was replaced, and this session is connected to the new instance. The raw value is excluded from observable session snapshots, rendered text, browser storage and peer messages. Disposal forgets the baseline. Existing request-generation and abort checks prevent obsolete bootstrap completions from changing session state.

Initial connection does not infer a restart. Failed reads, retention gaps, lost streams and expired/missing sessions do not establish an instance change. A bootstrap without the optional field clears the comparison baseline, so an unsupported-server interval is not treated as evidence of restart. The notice describes the most recent successful comparison and clears on a subsequent successful check of the same instance. There are no new automatic requests or mutation retries.

This signal becomes available after authentication succeeds on the new instance. It does not diagnose an unavailable server before reconnection, refresh a consumed sign-in link, authorize any retained action or replace attempt/revision reconciliation. A fresh operator sign-in link remains necessary when restart invalidates the old session.

Verification covers real HTTP bootstrap stability across sessions and changed identity across two server lifetimes on the same store, with old-cookie and unauthenticated rejection. Session/component tests cover unchanged/changed values, missing-field compatibility, failed reads, exclusion of raw identifiers and the visible notice. The packaged browser qualification below adds the graceful restart journey for a terminal fixture; #179 remains open.

[Retained evidence](evidence/web-server-instance-20260908/manifest.json): 357 frontend tests, lint/typechecked build, 50 positive/42 negative contract fixtures, 299 selected JVM tests, distZip and packaged history browser passed. That original browser journey supplies regression coverage; the later restart evidence below extends its scope.

The [packaged restart evidence](evidence/web-packaged-server-restart-20260908/manifest.json) qualifies stopping a confirmed live server with SIGTERM while a same-tab activity stream is open, retaining the displayed rows during reconnection, and explicitly pausing during the outage. Restarting the same installation/store on the same origin rejects the prior cookie. Private content clears, with no automatic requests observed during the following three seconds.

A fresh operator handoff is supplied through the existing document’s fragment handler. The fragment is scrubbed, the changed-instance notice appears, and the same attempt facts and exact 200/5 activity pages are recovered without a document reload. The tab issues one session-exchange POST and no workflow mutations. Owned workflow, job, input and progress bytes remain unchanged; browser storage stays empty. Existing privacy, pinning and peer/unannounced-session-revocation checks also pass, with shutdown and cleanup confirmed.

This covers a terminal inert fixture and graceful shutdown. Active-work recovery, abrupt crashes, actual expiry and conflicting workflow commands remain unqualified. A full reload forgets the page-memory instance baseline. The earlier intermittent appended-SSE timeout remains unresolved despite this passing run.
