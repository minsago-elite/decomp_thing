# Upload workbench checkpoint

The Workspace includes a labelled native file picker and single-file drop target.
Server-advertised complete-request limits and ELF guidance appear before submission.
The size hint leaves format and actual multipart-byte validation to the server.
Selecting a file does not upload or run it; the Upload binary button starts admission.

The typed multipart client supplies CSRF and an explicit idempotency key, lets the
browser choose its multipart boundary, and rejects If-Match on resource creation.
It retains the existing same-origin, redirect-rejecting, bounded-response fetch
transport, with a 120-second deadline. Only a validated `201 job` response leads to
the durable job route. Server errors are translated into bounded local guidance next
to the control; response bodies and credentials are never displayed as diagnostics.

Files and keys stay in view memory. On failure or cancellation, the original file and
key remain paired for an explicit retry. Replacement is disabled until Choose another
file discards this context, explains possible prior publication, and restores picker
focus. Session loss disables submission while retaining this pair; reconnection on the
same view enables it again. Stop transfer cancels transport without claiming that an
already-published job was removed. Unmount aborts pending transport. Reload/leaving the
view discards retry context; the page explains that users must inspect Uploaded jobs
before resubmitting. Pending/uncertain submissions register a browser unload warning.

## Verification and remaining qualification

Frontend tests cover multipart headers and resource-creation preconditions, explicit
submission/navigation, retained same-key retries, deliberate replacement, cancellation,
session loss/reconnection, authoritative format errors and unmount cancellation.

`scripts/check-packaged-web-browser.mjs --mode upload` extends the packaged session
journey with a synthetic inert ELF header. It uses keyboard submission, intentionally
loses a successful response after server publication, retries through the UI and checks
one unchanged job identity, uploaded status, no workflow artifacts, no browser storage,
and successful job-route reload. This is an isolated test; the fixture is never executed.

This checkpoint does not complete #169. Fetch does not expose reliable upload-byte
progress: the current UI uses an indeterminate transfer/publication wait and explicitly
does not claim a byte percentage. Measured transfer progress, broader accessibility and
failure qualification (including large/oversized and stalled browser transfers), and
recovery across discarded views remain open. The underlying API still has the #162
crash-orphan maintenance and total storage-quota work recorded separately.

All 169 frontend tests, lint, the distribution build (including type checking), and
the [packaged upload journey](evidence/web-upload-ui-20260905.json) passed. The browser
used pinned Node 24.20.0, JDK 21 and the isolated test-only `--no-sandbox` setting.
