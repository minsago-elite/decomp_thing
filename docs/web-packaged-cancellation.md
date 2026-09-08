# Packaged cancellation receipt replay

The packaged `history` browser mode now includes cancellation recovery on an inert completed attempt. Production workflow adapters remain unregistered. The driver first verifies the real terminal eligibility response offers no new cancellation. It then explicitly seeds the bounded tab recovery metadata to exercise the retained-intent UI path.

The first explicit retry reaches the real JVM cancellation endpoint. A test-only fetch wrapper consumes and drops its successful response after the server publishes a terminal acknowledgement receipt. Reload must retain the original key/version without sending a mutation. A fresh status read and explicit retry must receive the real replay header and completed acknowledgement/current state. Replay must change no durable bytes, and the receipt publication must preserve every attempt record, accepted reference, input and diagnostic bytes. Browser recovery storage must be empty after confirmed replay.

The surrounding history mode also runs existing history/activity/pin checks and a real graceful restart of the packaged server. This does not make the seeded intent an actual interrupted running-worker cancellation or qualify receipt replay under a different browser session. The completed fixture has no accepted reference; unchanged-null checks do not establish non-null acceptance preservation. Service tests retain the independent synthetic accepted-reference preservation evidence.

Verification is pending until the rebuilt archive completes this journey and confirmed shutdown/cleanup produces a terminal report. The driver syntax checks pass. No real running-worker or cancel/complete-race browser qualification is claimed by this terminal fixture.
