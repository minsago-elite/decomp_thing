# Activity replay and job navigation controls

Activity rows expose the state and acceptance recorded by a validated `run.state`
event. The labels identify historical event data. The current snapshot retains
its own state/acceptance and revision validation remains a separate authority.

`frontend/tests/activity-replay-lifecycle.test.tsx` extends the existing mocked
client, controlled event connection and virtual-clock fixtures with five schedules:

| Schedule | Observable checks |
| --- | --- |
| Running poll record, streamed completion, older running and terminal replay | One row for each state; terminal cursor retained on pause/resume; focus retained; snapshot remains explicitly historical |
| Streamed completion followed by an unseen lower sequence | Explicit refusal; verified running/completed rows retained; stream cancelled; no automatic retry |
| Polled completion followed by older running-page replay | No duplicate or regressive row; resume uses terminal cursor; no stream acquisition |
| Job A poll pending, actual App history navigation to job B, old response completes | A signal aborted; B rows and metadata retained; no old row or extra reads |
| Job A stream fetch pending, navigation to B, old response arrives with queued A event | A signal aborted; late body cancelled; B rows and metadata retained; no old row or extra reads |

All delivery and clock advances are controlled in memory. The App route tests use
synthetic session DTOs and mocked bootstrap/read/fetch callbacks. No HTTP service,
provider, native process or real browser is started by these controls. They make
no claim about native/authenticated integration, accepted reconstruction or
release qualification. Existing contract fixtures and prior assertions are retained.

The added controls require their own ordinary frontend and complete pipeline
qualification before landing. Source inspection alone is not a test result.
