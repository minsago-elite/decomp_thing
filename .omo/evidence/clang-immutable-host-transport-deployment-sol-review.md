# Independent transport/deployment addendum review

Verdict: ITERATE

Exact plan SHA256: `c84a5837ccf430e855e0579a0d0b64f607d48b8db1b6f5c885cd4fc6bae4062d`. Base checkout HEAD independently confirmed7208cd75. Read-only review inspected addendum, reviewed host backend anchors and prior approved plan. Only this review file was written; no source/Git/GitHub/root/Docker/native/acquisition activity. No agents spawned.

The plan supplies concrete actions, a separately reviewed bootstrap privilege profile, approved genesis, authenticated input/result authority, a durable unknown-create recovery barrier and honest unavailable prerequisites. Existing anchors are real: DockerBackend has named/token-correlated attempts, protected stage-parent FD and bounded sealed CLI execution; public entrypoints still gate unavailable transport. The new v2 monitor, transport, journal, receipts and artifact paths are new work and are correctly distinguished from the v1 no-cap backend.

Three startability/resource clarifications remain:

## 1. Journal ownership must begin before input capture

The state machine starts at INPUT_CAPTURED, but the protocol creates/copies up to3GiB payload staging plus other input artifacts before that state exists. Quota reservation is described transactionally without specifying a durable job/artifact ownership state for an interrupted capture. A service crash midway through exclusive staging-file creation must not leave unowned files/quota or force unsafe directory sweeping.

Add durable ADMITTED/INPUT_CAPTURING states before any broker stage/file/volume creation, with exact random names/tokens and held-parent identity, quota reservation and per-artifact capture intent committed before mutation. Partial capture failure/restart/disconnect must replay cleanup through those rows. Include capture-stage crash points (before/after create, partial write, fsync, freeze, rename) and foreign name replacement preservation, not just daemon/create and post-INPUT_CAPTURED transitions. Receipt/artifact state ordering should explicitly account for these earliest mutations.

## 2. Bound hostile input reads independently of supervisor progress

Regular-file fstat and bounded byte counts do not bound read latency for a caller-controlled FD (e.g. FUSE/network/unsupported filesystem). Section4 promises a capture deadline but does not select an enforcement path. Do not run a potentially indefinitely blocked client pread in the root service event loop/thread and assume a monotonic clock interrupts it.

Select an explicit accepted input filesystem policy (reject unknown/FUSE/network representations before reads), or isolate capture in a supervised restricted helper with real deadlines, bounded concurrent outstanding reads/resources and quarantine semantics for a nonterminating I/O task. The supervisor must still process cancellation/status and cannot report cleanup/completion for a live blocked helper. Approve no filesystem fallback silently. Add actual bounded-pipe/helper or adversarial delayed-read fixtures proving deadline/cancel progress plus separately gated deployment controls for supported source filesystems.

## 3. Disambiguate framing capacity and final receipt graph

Specify that BEGIN carries bounded counts/summary and each FD_BATCH carries only that batch's bounded ordered role/identity rows, with complete transcript accumulation across frames. A single1712-row manifest can exceed64KiB/4096nodes despite fitting declared FD limits. Add a positive maximum-capacity framing fixture and per-frame/aggregate count/depth/node/byte limits, so implementations need not choose between violating frame caps and rejecting supported inputs.

Also state which receipt is embedded in the final provenance archive. A final result receipt cannot both bind the archive's exact content digest and be a member of those same archive bytes. Select an acyclic graph: archive embeds prior action/evidence receipts; a detached final packaging receipt signs the completed immutable archive digest and is returned alongside it. Or explicitly select another non-self-referential format. Add tests showing exact archive digest binding and rejection of swapped archive/receipt pairs without a self-excluded hash convention.

These changes do not require acquisition or production approvals. Existing v1 source/limits stay intact; v2 resource quotas/action policy require their own schemas and review as planned. The2100s aggregate deadline and20GiB reservation are explicit hard new requirements, not evidence that real two-clean-build qualification fits them. Real deployment must demonstrate capacity, namespace mapping/filter inspection, daemon epoch barrier, quota/verity and exact offline package operation support; otherwise remain blocked. Keep empty exception registry, no raw host fallback, strict source expiry and acquisition pause unchanged.

---

# Revision 2 terminal rereview

Verdict: ITERATE — one narrow transcript-preimage clarification only.

Exact revision SHA256: `03719f794e6f0261ad44a858c9957d16aa96515cfda3003ce8adbadf47b2f911`. Independently verified the original first38,859bytes retain SHA256c84a5837ccf430e855e0579a0d0b64f607d48b8db1b6f5c885cd4fc6bae4062d. Initial review above remains unchanged. This rereview was read-only except this append; no source/Git/native/Docker/root/acquisition operations or agents.

R1 is resolved: durable admission/capture operation intents precede storage/helper mutation; exact trusted filesystem markers and identity correlation govern recovery, and pre-marker ambiguity explicitly quarantines rather than deleting by name. Required crash controls cover earliest staging transitions.

R2 is resolved: potentially blocking client-FD metadata/read operations move into a separate restricted native helper, with approved filesystem allowlist, one-helper/read bound, supervisor-owned deadlines, responsive status/cancellation, pidfd-confirmed exit and retained quarantine/quota for unkillable I/O. No root dispatcher pread or unchecked helper diagnostic authorizes content.

R3 framing capacity and archive receipt graph are resolved:1,720rows fit54bounded batches with aggregate limits; archive contains prior receipts only and a detached final receipt signs exact frozen archive bytes. No self-excluded hash convention is permitted. Capacity/time maxima remain hard refusal limits, not real deployment evidence.

One new ambiguity remains in R3's transcript definition: BEGIN includes an expected ordered transcript digest, while the next paragraph hashes the BEGIN summary into that same transcript. If that summary includes its declared digest, construction requires a hash fixed point. Explicitly define the hashed BEGIN projection to exclude its transcript-digest field; exclude any COMMIT supplied transcript-digest field as well. Include only the exact declared non-digest fields, ordered length-prefixed batch headers/rows and COMMIT counts. Both supplied digests are compared with the independently computed result after hashing and never enter their own preimage. No zero-filled or selectively rewritten header workaround.

Add a fixed golden transcript vector generated independently from canonical non-digest fields, plus a control demonstrating changing only the supplied BEGIN/COMMIT digest rejects without changing the independently computed digest. Keep action/approval/nonces/counts/boundaries covered. After this explicit small correction, no further plan redesign is requested. All production authority/native/deployment gates and acquisition/expiry holds remain unchanged.

---

# Revision 3 terminal rereview

Verdict: OKAY for the staged implementation plan. No further plan iteration requested.

Exact addendum SHA256: `f21b76c1a1735ebea63d44cf5e44be82209855e70855277183bf7956eaf42cf1`;63,512bytes. Initial and Revision2 ITERATE reviews above remain preserved. Original38,859byte prefix independently retains its stated hash. No source/Git/native/Docker/root/acquisition operations or new agents; only this review append was written.

The final transcript ambiguity is resolved. Exact BEGIN and COMMIT_INPUTS wire schemas are specified; their hash projections exclude only their top-level transcriptSha256 fields, retaining all approval/source/content identities. Every canonical JSON object uses an explicit four-byte big-endian length prefix after a fixed raw domain. Both supplied transcript digests are compared only after independent preimage calculation. Unknown/missing fields, inconsistent arithmetic and malformed semantic order reject independently of a matching hash.

Independently extracted the four literal golden objects without using production code: lengths500/62/192/67bytes; whole domain+prefix+objects preimage877bytes; SHA256c180ad9f17f798417ebac6218e25ed42f991ab88c09124026e2aadd4d2a1841d. These match the normative plan values. Positive wire exchange and digest-only/covered-field/semantic-negative controls are concrete and startable.

Prior corrections remain resolved: durable admission/capture ownership before mutations, restricted bounded helper capture with responsive dispatcher/quarantine, capacity-safe manifest batching, and acyclic prior-receipts→archive→detached-final-receipt graph. Implementation checkpoints still require assigned ownership, exact-source independent review and meaningful controls. This approves design only; it does not establish transport implementation, installed approvals, source/package/native qualification, real namespace/runtime/quota/verity behavior or deployment. Public gates, acquisition pause and strict expiry refusal remain in force.
