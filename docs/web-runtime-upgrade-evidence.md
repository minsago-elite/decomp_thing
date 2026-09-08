# Runtime snapshot and packaged upgrade evidence

The application at `7038a7f` presents the authenticated bootstrap's readiness,
capabilities, platform, server identity and upload ceiling on Runtime. It reuses
session state: route navigation sends no additional request, no doctor probe and
no workflow request. Logout, expiry and failed session checks remove that snapshot.
The explicit projection excludes CSRF and bootstrap credentials. A different
reported UI build produces a notice without automatic reload.

This is reported session-time information, not a continuously polled health check.
Production workflow capabilities remain unavailable until their owning adapters
are qualified; showing their explanations does not enable them (#166).

## Actual two-version replacement (#154)

[Retained upgrade evidence](evidence/web-upgrade-20260905.json) records a passed
Chrome 149.0.7827.55 journey driven by pinned Node 24.20.0 and Java 21 on Linux.
The browser sandbox was disabled for this isolated test environment. This is not
cross-browser qualification or optional remote-deployment acceptance.

Two complete distribution ZIPs were independently extracted and launched on the
same origin under `/nested/`. The old tab remained alive through server replacement.
Its old Runtime chunk received a real HTTP 404; no requests were intercepted.
The tab displayed one visible recovery notice and made no automatic reload,
chunk retry or mutation during five seconds of observation. One explicit reload
loaded the replacement Runtime chunk and the current build identity.
Both read-only installations remained unchanged; no job data was created.
Owned JVM/browser shutdown and extraction cleanup were confirmed.

The retained record identifies both ZIPs, application JARs and UI builds by hash.
Its source-report hash binds the local full request report; transient host paths
and resource-availability figures are omitted from the committed summary.
The two UI identities correspond to actual changed application code, not a
manifest-only change or an injected chunk failure.

## Verification scope

- 157 frontend tests, lint and generated-contract/type checks passed.
- 93 web/jobs JVM tests passed against the updated assets.
- `verifyPackagedWeb` passed for ZIP and TAR: classpath assets, exact resource
  hashes, GET/HEAD/304, direct Runtime links and namespace errors from an unrelated
  working directory with a read-only installation and no Node on application PATH.
- Root/nested routing, encoded paths, queries, trailing slashes, dotted asset
  names, cache policy and no-store session/bootstrap envelopes have focused
  JVM tests. Resource URL helpers cover exact event/download identities and
  deployment prefixes in frontend tests.

The D1 base-path acceptance item still needs end-to-end event/download journeys
when those D2/D4/D6 endpoints land. URL-construction tests alone do not qualify
those future consumers. No worker resources are currently supported. This evidence
does not close all of D1 or the broader D-series release gates.

The [packaged session journey](evidence/web-runtime-session-20260905.json) also
passed with the same current ZIP/JAR/UI identities: authenticated Runtime displays
the server's unavailable-capability explanation and upload ceiling, route opening
adds zero fetches, and logout removes the private runtime section. Cookie reload,
consumed sign-in-link denial, fragment removal, no browser credential storage and
no automatic mutation retries remain covered. The driver waits for a document body
before evaluating readiness during navigation; it still fails actual page errors.
