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

Parsing does not authenticate a channel. This layer is not yet wired into
`SandboxRunner`; its existing reserved-status guard remains active. Integration
must separately own and bound the channel, bind the launcher/tool and command,
start the local deadline before launch, retain complete I/O and cleanup, and
version behavior evidence so historical missing completion remains unresolved.
Application stdout/stderr and caller-provided JSON cannot serve as completion
authority. A matching terminal status does not override a local deadline failure.
Production executable/runtime identity remains a separate requirement.
