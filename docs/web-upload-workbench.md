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

The workbench now shows [server-observed request progress](web-upload-progress.md),
including measured bytes without a known total for chunked bodies, and separates
receiving from validation/publication. The #169 upload journey is qualified by the
combined evidence below. The underlying API still has #162 crash-orphan and total
quota work open; these checks do not establish every workbench release gate.

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
implicit admission. The distribution build also passed. That checkpoint preceded server-observed progress; #169 is still open.

All 179 frontend tests, lint and the distribution build passed for tab recovery.
The [packaged reload recovery journey](evidence/web-upload-recovery-20260905.json)
lost a real successful publication response, reloaded, restored the local session and
ticket without resubmitting, reselected the fixture, and replayed the same key into
exactly one durable job. Success removed the ticket. Invalid/oversized rejection and
explicit stop checks also passed. Unit tests cover deployment isolation, malformed,
oversized, future/expired tickets, denied storage and different-file selection.

The [measured transfer and cancellation journey](evidence/web-upload-progress-20260905.json)
passed against the packaged application. With a 512 KiB inert fixture and browser
network throughput limited to 32 KiB/s, the UI reported 8,192 actual request bytes
received while publication was still pending. Stop transfer cancelled the real request,
removed staging and left no job. Explicit retry retained its idempotency key, used a
fresh progress identity and published exactly one uploaded job without execution. The
same journey retained lost-response/reload replay and invalid/oversized rejection checks.

All 133 web/jobs tests, 183 frontend tests, lint and distZip passed. The shared verifier
accepted 32 valid fixtures and rejected 19 invalid fixtures, including progress byte
ceilings and publication-identity consistency. Session isolation, bounded cache/expiry,
monotonic counts and progress-poll cancellation have focused tests. This evidence closes
#169's core picker, validation, progress, cancellation/retry and no-implicit-execution
criteria; #162's remaining storage and process-crash requirements remain separate.
