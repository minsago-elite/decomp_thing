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

File bytes stay in view memory. Before sending, the view retains one bounded ticket
in sessionStorage per deployment path: schema version, idempotency key, filename,
size and creation time. No binary bytes or session credentials enter storage. The
record is limited to 2 KiB and a 24-hour retry window; invalid, future-dated, expired
or unavailable records block new admission until explicit reconciliation/discard.
Storage failure prevents sending an upload without retained retry context.

On failure or cancellation, the original file and key remain paired for explicit
retry. Reload or navigation preserves the ticket, asks the user to reselect the
original filename/size, and never sends automatically. These local checks are hints;
the server remains authoritative for the exact content digest. Session loss disables
submission while retaining context. Closing a tab or clearing its storage may lose
the ticket; users must inspect Uploaded jobs before starting another upload then.

Choose another file explicitly discards the ticket and restores picker focus.
Confirmed publication clears it before navigating; if clearing fails, a later retry
still uses the original key. Stop transfer cancels transport without claiming removal
of a published job. Unmount aborts pending transport. Pending/uncertain submissions
register a browser unload warning.

## Verification and remaining qualification

Frontend tests cover multipart headers and resource-creation preconditions, explicit
submission/navigation, retained same-key retries, deliberate replacement, cancellation,
session loss/reconnection, authoritative format errors and unmount cancellation.

`scripts/check-packaged-web-browser.mjs --mode upload` extends the packaged session
journey with a synthetic inert ELF header. It uses keyboard submission, intentionally
loses a successful response after server publication, retries through the UI and checks
one unchanged job identity, uploaded status, no workflow artifacts, cleared browser recovery storage,
and successful job-route reload. This is an isolated test; the fixture is never executed.

This checkpoint does not complete #169. Fetch does not expose reliable upload-byte
progress: the current UI uses an indeterminate transfer/publication wait and explicitly
does not claim a byte percentage. Measured transfer progress, broader accessibility and
real stalled-network qualification remain open. The underlying API still has the #162
crash-orphan maintenance and total storage-quota work recorded separately.

At the initial checkpoint, all 169 frontend tests, lint, the distribution build (including type checking), and
the [packaged upload journey](evidence/web-upload-ui-20260905.json) passed. The browser
used pinned Node 24.20.0, JDK 21 and the isolated test-only `--no-sandbox` setting.

The [expanded packaged failure journey](evidence/web-upload-failures-20260905.json)
passed against the integrated JVM. It submitted an invalid ELF and a 32 MiB payload
whose multipart overhead exceeds the request limit; both received authoritative
server rejection beside the picker. The oversized case first displayed the advisory
size hint and still exercised server enforcement. Neither created a job or retained
staging. Explicit file replacement restored keyboard focus. A simulated stalled fetch
settled on Stop transfer, removed the spinner and retained the selected file until
explicit discard. This simulation does not qualify physical network interruption.

At the rejection checkpoint, all 175 frontend tests and lint passed, including capacity/storage/session rejection
context, same-key retry, multiple-drop rejection and single-drop selection without
implicit admission. The distribution build also passed. Measured progress remains unqualified, so #169 is still open.

All 179 frontend tests, lint and the distribution build passed for tab recovery.
The [packaged reload recovery journey](evidence/web-upload-recovery-20260905.json)
lost a real successful publication response, reloaded, restored the local session and
ticket without resubmitting, reselected the fixture, and replayed the same key into
exactly one durable job. Success removed the ticket. Invalid/oversized rejection and
explicit stop checks also passed. Unit tests cover deployment isolation, malformed,
oversized, future/expired tickets, denied storage and different-file selection.
