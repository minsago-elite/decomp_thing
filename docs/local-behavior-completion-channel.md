# Local behavior completion channel

The Bubblewrap completion parser accepts at most 4 KiB of strict UTF-8 JSON lines:
one launch record and one terminal record, each newline-terminated. It checks
closed field sets, integer types, positive PID/namespace identifiers, duplicate
keys and independent JSON resource bounds. The selected runner configuration uses
PID and mount namespaces, so both identifiers are required in the launch record.
The identifiers are observations, not containment attestations.

The terminal application exit must agree with the outer wrapper exit. Values
0–127 are distinguishable from missing completion evidence, including genuine
application exit 124. Bubblewrap encodes signal death as 128+signal; those values
remain unusable here, including genuine application exits in that range. Missing,
truncated, duplicated, contradictory or excessive records cannot yield a parsed
completion observation.

The [Bubblewrap 0.11.2 source](https://github.com/containers/bubblewrap/blob/v0.11.2/bubblewrap.c)
closes its JSON status descriptor in the sandbox child and guards terminal reporting
with an internal setup/exec signal. The local probe recorded in #354 distinguished
genuine exits 1 and 124 from exec failure and watchdog termination even when their
wrapper exits matched.

`SandboxRunner` opens a private temporary status file through a fixed shell launcher
and supplies descriptor 3 to Bubblewrap. Dynamic arguments remain separate argv
values. The application child does not retain that descriptor. The local deadline
starts before launch; capture is bounded to 4 KiB and the temporary file and directory
are removed on success or failure. Cleanup attempts both owned paths and preserves
the execution error as primary if removal also fails. A cleanup failure after
success prevents publication; unrelated directory contents are never recursively
deleted. Existing stream bounds and process cleanup apply.

Schema-4 behavior records bind the launcher's identity and retain the exact launcher
argv, channel locator and status bytes alongside the logical sandbox request.
Closed validation checks both command recipes and the launch/terminal pair.
Historical schemas remain readable but unresolved in archival audit.

Parsing does not authenticate a channel or caller-provided JSON. The retained record
is a local observation, not hosted/native authority. Application stdout/stderr do
not serve as completion evidence. A matching terminal status does not override a
local deadline failure. Production executable/runtime identity remains a separate
requirement, including protection against same-user replacement between checks.
