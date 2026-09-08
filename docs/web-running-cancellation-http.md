# Running cancellation over authenticated HTTP

The HTTP cancellation fixture can run an inert adapter on an explicitly owned test thread. The adapter remains live after interruption until the test releases it; separate cases then confirm interruption exit or return successful completion. No production adapter is registered and no native workflow is executed.

The tests send stale and foreign commands before cancellation and verify unchanged durable bytes with zero signals. Two concurrent identical authenticated PUTs must produce one original response and one replay, one receipt acknowledgement and exactly one interrupt. Both responses remain cancelling while the test worker is alive. The private policy read reports cancellation pending.

A pin publication changes the current run version while cancellation is pending. Replaying the original command must return that newer current version without repeating interruption or changing bytes. After explicit worker release, the policy reports cancelled or completed according to the actual outcome, without granting acceptance. Starting a newer queued attempt and replaying the old command must leave that newer attempt and all durable bytes unchanged.

Verification: 7 HTTP cancellation tests and 8 service cancellation tests passed, with zero failures/skips. The selected service suite includes the separate synthetic non-null accepted-reference and diagnostic preservation cases. The new HTTP cases do not themselves contain an accepted prior revision and do not establish the original acceptance attestation's correctness.

This test-only checkpoint is tracked by #485 and stacked after the packaged terminal replay checkpoint #1070. Broader running-worker browser, registered production-adapter and accepted-evidence HTTP qualification remains open. No frontend test or packaged-browser rerun for this test-only change; the parent retains its browser report tied to its earlier archive.
