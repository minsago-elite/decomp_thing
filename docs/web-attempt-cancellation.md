# Service-owned attempt cancellation

Tracking: [D2 cancellation #485](https://github.com/minsago-elite/decomp_thing/issues/485), prerequisite for [D4 controls #180](https://github.com/minsago-elite/decomp_thing/issues/180).

`WebJobService.cancelDurable` is an internal service operation bound to an exact job, run and expected run version. It reads the named attempt before selecting an owned task. Unknown versions fail without signalling a worker; an already terminal attempt is returned unchanged and cannot affect a newer run. A nonterminal attempt without an owned task requires recovery.

Cancellation first atomically records `cancelling` and updates the owned task's current version. Only after publication succeeds does it signal the worker. A queued task is removed from an owned executor and finished as cancelled; a borrowed executor that later dispatches the old runnable encounters an already terminal task and performs no execution.

A running worker remains cancelling until its adapter exits. Its cancellation acknowledgement has no terminal timestamp and does not allow another workflow for the same job. An adapter exiting through interruption after the request records cancelled. An adapter that clears interruption and completes records completed, so completion racing with cancellation is not relabeled as a successful cancellation. Shutdown retains its separate interrupted outcome. The existing trusted adapter contract requires children to stop before execution returns.

A known pre-rename publication failure leaves the attempt and worker unchanged. An uncertain publication blocks further mutations and prevents the old task from publishing another outcome; storage must be reopened to reconcile. There is no automatic retry of a state publication. The operation does not publish acceptance or delete diagnostics.

This is service-layer implementation only. No HTTP route, browser control or production adapter registration is introduced here. The subsequent [durable receipt integration](web-cancellation-receipts.md) supplies actor-scoped replay within the service. Those remain necessary for #485/#180 completion, together with HTTP/session/race qualification against registered production adapters. No production workflow capability is enabled by this change.

Additional service tests preserve an existing synthetic accepted reference, its original attempt record, and diagnostic bytes across both queued and running cancellation and a subsequent store reopen. They do not establish the correctness of the underlying acceptance attestation; the fixture supplies that reference through the trusted store API.

An uncertain running cancellation test injects failure after rename, verifies that cancellation is not signalled, and confirms shutdown retains ownership while the worker remains live. When the worker later returns, it cannot overwrite uncertain metadata with completion. Reopening reconciles the abandoned attempt as interrupted. These tests qualify the internal state/ownership boundary; HTTP command replay and UI controls remain open.
