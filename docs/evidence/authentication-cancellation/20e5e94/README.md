# Inspection-bound cancellation evidence

Source 20e5e94 was tested immediately before commit with no intervening source
changes: eight JVM tests passed with zero failures/errors/skips, and Chromium
153.0.8010.12 passed sixteen mocked browser scenarios. Reports, screenshot, trace,
result and SHA-256 digests are retained here.

The server regression starts a replacement inspection, rejects missing identity,
rejects the completed inspection ID twice without signaling the replacement, then
accepts the replacement ID. Admission/status/terminal responses retain that identity.
Existing tests cover cancellation cleanup and ownership. The browser verifies each
cancel header against the displayed mock inspection ID, retries failed polling and
cancellation, and keeps cancellation disabled while admission identity is missing
until a successful poll recovers it. No external agent or uploaded target executes.

This is a stack-tip checkpoint. Backport to the original #279 interface, descendant
propagation and shared-service integration #360 remain pending. Full CI omitted
because its patch lane executes vulnerability reproduction.
