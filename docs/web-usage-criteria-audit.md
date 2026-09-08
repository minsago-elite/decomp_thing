# D4 reported usage criteria audit

Tracking: [D4.6 #181](https://github.com/minsago-elite/decomp_thing/issues/181).

The monetary-estimate criterion is satisfied for the current application: no configured price/version basis is supplied, and no monetary estimate is displayed. This is a conditional display requirement, not a requirement to introduce a pricing configuration. Provider-reported `reportedCostAmount` and `reportedCostCurrency` remain observations in the wire contract; they do not establish a configured estimate basis.

`ObservedUsage` renders exact token/tool/duration values and an explicit cost-unavailable explanation. It does not render the reported monetary fields or calculate a price from token counts. `ActivityRow` does not provide a generic field dump that bypasses that choice. The source audit found no other application monetary-estimate renderer. The existing usage test supplies reported cost without a pricing basis and verifies its omission; the activity integration test now covers agent receipts, context observations and unrelated message rows together while preserving exact large token values.

| #181 criterion | Current evidence and remaining scope |
| --- | --- |
| Approximate queue position | Open. Aggregate scheduler depth is labeled approximate; per-attempt position is unavailable. |
| Usage/limit units, source and measurement time | Open. Supported counters and scheduler samples have labels, while provider measurement time and broader resource usage remain unavailable. |
| Monetary estimate label and configured basis | Qualified for the current no-basis state. No estimate is shown. Adding price/version configuration or another monetary renderer requires new qualification before displaying estimates. |
| Separate budget, timeout, cancellation and infrastructure outcomes | Open. Receipt classifications are distinct, but full durable workflow outcomes and command scenarios need broader verification. |
| Resource privacy | Open. The scheduler projection is bounded and excludes job identities/host diagnostics; full resource surfaces are not implemented. |
| Coalesced metric updates and unchanged acceptance evidence | Open. Existing session-time scheduler snapshots and bounded activity observation cover part of the scope, not all future live metrics. |

Validation is frontend integration and source inspection. This audit changes no runtime code, pricing behavior or wire schema. The separately running real-time idle-expiry journey is unrelated and is not claimed as evidence for this criterion. No JVM or packaged browser rerun is needed for this test/documentation checkpoint; the full D4 milestone remains open.
