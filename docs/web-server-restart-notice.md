# Changed application instance notice

After a successful authenticated bootstrap, the session notice reports when a known application instance ID differs from the previously known ID in the same page lifecycle. The application may have restarted or been replaced. This observation does not prove a physical restart, current workflow readiness, or the outcome of any command.

The notice uses a derived boolean and fixed interface copy. It includes no instance IDs or credentials. Existing Runtime metadata remains unchanged. A first bootstrap, missing identity metadata, and unchanged identity metadata do not produce this notice. Missing identity metadata still causes the existing conservative invalidation of instance-bound views.

The existing session generation replaces private views and aborts obsolete reads. The selected URL is retained. The notice creates no bootstrap request, timer, retry, or mutation; it clears on the next successful unchanged bootstrap. Disconnect and expiry notices retain their existing meanings.

`session-restart-notice.test.tsx` contains three controlled tests covering the notice, unknown identity handling, and a late old run response after replacement. They use mock gateways, DTO responses, JSDOM, and fake clocks. They do not qualify actual server restart, browser transport, dropped streams, multiple tabs, bounded reconnect jitter, conflicting commands, or the full reconnect requirements.
