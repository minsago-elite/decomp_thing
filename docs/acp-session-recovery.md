# Durable ACP session recovery

The reconstruction workflow can now retain an ACP conversation reference across
harness process restarts. `BoundedLlmModuleReconstructor` supplies a local
`AgentSessionContinuation` only when it has configured factory provenance and a
workflow evidence fingerprint. Requests without that descriptor retain their
one-invocation behavior.

The reference is scoped to the absolute project path, module, recovered-input
identity, reconstruction profile, and module evidence fingerprint. A changed
workflow uses a distinct journal; older evidence remains on disk. Each journal
also binds the exact configured factory descriptor, initialized protocol version,
peer implementation name/version/title, and negotiated capabilities. A peer's
self-reported name is identity data, not independent authentication.

## Durable state and acceptance

Journals live outside the generated project and its agent grants, under
`<project-parent>/.decomp-agent-sessions/<project-path-sha>/<module-id-sha>/<workflow-sha>/`.
They are excluded from project archives. The owner-private directory contains a
lock and a canonical, self-hashed, atomically replaced and fsynced `session.json`.
The snapshot retains the exact identity, session ID, decision history, completed
turns, pending request hash, last durable event sequence, cleanup disposition, and
accepted source/request/receipt hashes. Receipt request binding includes the
continuation descriptor; requests without one preserve their earlier binding.

Admission reconciles current source and declared read-only evidence against the
stored inventory before launching a process. Inventories allow at most 4,096
members, 16 MiB per file and 32 MiB total, with a ten-second hashing deadline and
64 KiB cancellation/deadline checkpoints. Linked paths are rejected. Journal
snapshots are bounded to 1 MiB, with at most 256 decisions and completed turns;
reaching a bound stops the operation instead of silently dropping history.
These checks bound ordinary local work; they do not provide kernel-enforced
filesystem I/O deadlines or an independent remote persistence authority.

A completed ACP turn does not accept its edits. SourceTree validates the candidate
and publishes the accepted checkpoint before acknowledging acceptance in the
journal. On restart a verified cached checkpoint repeats that acknowledgement;
identical request, receipt, source and inventory are a zero-write no-op. The agent
is not dispatched again. A rejected candidate can reconcile the workflow-restored
baseline without advancing the accepted identity.

Unexplained source edits retain their bytes in place. The journal records expected
and observed hashes in `quarantine.json` and blocks further use. This is a blocked
recovery disposition, not a copied artifact or permission change. Recovery errors
remain typed through the harness and reconstruction; they cannot become an
unresolved candidate or replace the accepted project checkpoint.

## Conversation decisions

| Condition | Recorded action |
| --- | --- |
| First use | Create a new session. |
| Completed, cleanup-verified turn and exact identity; peer advertises `loadSession` | Use pinned SDK 0.30.1 stable-v1 `session/load` with the retained ID. |
| Peer does not advertise loading | Create a new session from current project evidence; record that conversation was not restored. |
| Cleanly interrupted turn | Create a new session from project evidence; retain the interrupted turn's cursor and disposition. |
| Advertised load fails | Retain the failure and stop; require explicit `NEW_SESSION_FROM_PROJECT_EVIDENCE` policy before recreating. |
| Agent/configuration/capability identity changes | Quarantine the existing session. |
| Prior process cleanup is unknown | Block restart pending contained-lifecycle reconciliation. |

A successful load sets the generic result's `resumeReference` to the loaded
session ID. A new session never sets that field. Restored SDK updates pass through
the same bounded update translator as other updates. This checkpoint does not
claim that replayed historical events are a new accepted turn or that a project
checkpoint restores a conversation. Draft v2 resume APIs are not used.

Closing a journal releases only its local lock. Every harness invocation still
cleans up its owned process, filesystem and terminals. Neither action deletes the
remote session or accepted project evidence. There is no remote session-delete
operation or operator discard/recovery UI in this checkpoint. Retained journals
must not be silently removed as a substitute for recovering unknown process
ownership.

## Verification and remaining scope

`AgentSessionJournalTest` covers retained identity and acceptance, idempotent
acknowledgement, unsupported-load decisions, explicit recreation after failure,
clean interruption, unknown-cleanup refusal, unexplained source/metadata changes,
exclusive ownership, cancellation and aggregate hashing limits.
`AcpAgentHarnessTest` uses benign scripted peers in fresh contained subprocesses
for advertised load, unavailable-load fallback and load failure. The stable-v1
wire corpus contains 52 messages, including three new load request/empty-response/configured-response entries. `SourceTreeTest` proves
that a lost acknowledgement after durable acceptance is replayed without another
reconstruction and that recovery failures preserve source without publishing an
unresolved checkpoint.

The 2026-09-05 focused checkpoint passed 105 tests across these seven suites with
zero failures, errors or skips and `DECOMP_REQUIRE_LIVE_ACP_CONTRACT=1`.

Issue #68 remains open. Abrupt host death currently blocks when cleanup cannot be
verified; #71 still needs durable process-ownership reconciliation and restart
proof. Captured repair requests intentionally reject continuation descriptors:
their logical source is held in the validated mutation authority, so #237/#65
need snapshot-backed session reconciliation rather than host-path hashing.
Remote close/delete semantics, an operator recovery surface, separate-JVM crash
matrix coverage, and independently qualified external-agent persistence remain
outstanding. #62 wire/runtime checks and #67 external-agent qualification are
prerequisites for broader claims; this local session journal does not establish
#72 production release eligibility.

Separate-JVM journal-owner tests now halt without running `finally` before a prompt, after a
persisted streaming event, and after a plain-text edit. On restart, the journal lock can be acquired,
but missing cleanup proof blocks workspace reconciliation and no completed turn or accepted revision
is inferred. Repeated reopen attempts preserve source bytes and the recorded event cursor. These
fixtures do not launch an ACP peer or prove cleanup of surviving descendants; automatic host-death
recovery and exactly-once workflow acceptance still require their separate lifecycle qualification.

The journal-only crash fixture also halts immediately before or after acceptance acknowledgement,
following a synthetic completed cleanup-verified turn and an externally supplied text commitment.
Restart supplies that same commitment to the public acknowledgement API. A missing acknowledgement
is completed; replay after publication preserves journal bytes and modification time, retains one
completed turn, and reconciles the unchanged text. This tests the journal's idempotent acknowledgement,
not source checkpoint durability, compiler/behavior validation, or exactly-once workflow dispatch.
The fixture releases the journal lock for the public API before these two halt points.

Admission checks for `session.json.pending` and `quarantine.json.pending` while holding the journal
lock, before loading or creating session state. Either remnant blocks opening with a fixed inspection
message, even when an older session record is readable. Admission preserves the remnant, old journal
and workspace bytes, and releases ownership on failure. It does not promote or delete a candidate,
or automatically decide whether an interrupted write is safe to retry.
