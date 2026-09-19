# Browser session expiry and explicit reauthentication — #481 draft checkpoint

Status: focused draft qualification passed on Linux/Chrome. This checkpoint does **not** close #481 or certify an operator-visible same-process link-reissue workflow.

## Test command and result

Run from the `/tmp/decomp-d-481` worktree:

```sh
DECOMP_BROWSER_CHROME=/home/june/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome DECOMP_BROWSER_JS_RUNTIME=/home/june/.bun/bin/bun ./gradlew test --tests decompengine.web.BrowserSessionExpiryTest -PfrontendNodeHome=/tmp/decomp-node-24 -Pkotlin.daemon.jvmargs=-Xmx4096m --max-workers=1 --console=plain
```

The first run completed successfully in 2m 3s; a post-redaction rerun completed in 6s. The final JUnit XML at `build/test-results/test/TEST-decompengine.web.BrowserSessionExpiryTest.xml` reports 2 tests, 0 skipped, 0 failures, 0 errors. The first test exercised actual HTTP exchange, private read, server-enforced absolute expiry/401/cookie clearing and a fresh exchange using the injected monotonic clock. The second used real Chrome against the running JVM and bundled SPA assets, with Bun driving Chrome DevTools. It observed a private Runtime page before expiry, advanced the test-owned server clock eight hours, reloaded, observed the server's 401 and expired-session UI with private Runtime content removed, then navigated to a freshly issued explicit link and regained the private Runtime page. No workflow or upload was executed. Chrome ran with test-only `--no-sandbox` and background networking disabled.

Browser identity: Chrome for Testing 149.0.7827.55, SHA-256 `2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801`; Bun 1.3.1, SHA-256 `d8fff2cc6c325ad5ec1c153ad7c1437dbe13d4168ffd0e3df62c5d9325bf210e`.

The browser driver asserts one initial and one fresh session POST, no mutation or token replay during expiry, an HttpOnly/Strict base-path cookie before and after reauthentication, cookie removal on the expired 401, empty local/session storage, fragment removal, no credential in network URL path/query, no token in rendered text, and no page exceptions. Bootstrap links travel only through a private test process stdin pipe, never process arguments or retained evidence. Unexpected diagnostics redact both fragment-form and bare token values. The retained JUnit result was scanned for bootstrap fragments and contained none. The temporary Chrome profile was removed after confirmed process shutdown.

## Boundary and remaining work

The production CLI currently prints only one five-minute, one-use bootstrap link at server startup. Its consumed link cannot reauthenticate after a later session expiry. The test calls the existing trusted in-process `UploadServer.issueBrowserBootstrap()` method to issue a second link; it does not demonstrate that a user can obtain one from an already-running CLI. A reviewed operator-only reissue path or documented safe restart/recovery procedure is still needed before marking #481's reauthentication acceptance complete. No unauthenticated HTTP mint route was introduced. The test checks its own diagnostics, not every production log sink. This run is not a packaged ZIP installation check, cross-browser coverage, idle-expiry browser check, remote/proxy qualification, or production deployment evidence.
