# Private-control concurrency security plan review

Verdict: OKAY

Exact reviewed plan SHA256: `59b20924924ca96edfe838fb3977854c4b518a70fce3e683bee2a2502abd525a`.
Authoritative source: `05b073fc8378bd2faaf0ee4163cf055ba61e11da`, inspected using git show. Read the isolated worktree AGENTS.md. Verified diagnosis SHA256 `dcf0f61f3904133e3ce139a4d8fffe58e26ae508ad9d991a6e1dbe493817b832`. Read current GitHub #1508 and #238: both OPEN in OPEN milestone 16. Acceptance matches the planned narrow correction and does not establish parent production qualification.

No blocking plan defect found. This approves the design for implementation review; it does not approve unwritten code, prove runtime support, or satisfy hosted qualification.

## Source and diagnosis grounding

Exact-base LinuxBubblewrapBoundary.kt:1987 rejects any global generation change; 2266 and 2294 increment around creation and publication. ManifestControlIdentity.requireUnchanged separately checks retained descriptor identity and named location, so merely dropping epoch equality cannot permit proved legitimate deletion. deleteAndProve:2187 onward is currently both method-synchronized and registry-locked, closes original descriptors and removes registry membership after unlink proof. The plan covers both independent causes and the new lock inversion risk.

The retained diagnosis identifies the exact 9cfc provider-head failure, including both SANDBOX_LAUNCH refusals and bounded generation/identity causes. The plan correctly keeps the lower fae-head cause UNKNOWN and does not convert similar symptoms into a proven common cause. No privileged execution, native tests, provider/model/authentication call or CI run was launched during review.

## Security and concurrency argument

Registry changes remain transactional and independently authenticated. Per-record unforgeable identity plus LIVE/PROVED_DELETED state prevents a path, inode, or descriptor integer from transferring deletion proof to a replacement. Retained descriptors pin the original inode, and scope-owned references bound tombstone lifetime. Epoch is only a reconciliation notification, with explicit nonreuse/overflow handling; it is not deletion or identity proof.

Deletion proof remains descriptor-bound and atomic relative to checkpoint identity inspection: the monitor spans contents drain, quarantine selection, exact unlink and link-count/name-absence verification. Failed cleanup stays protected LIVE, and prior failure provenance survives later remediation. Partial creation without proved cleanup introduces bounded sticky poison rather than disappearing from security accounting. Poison must deny subsequent authority admission, not merely subsequent creation.

Scope admission pins and authenticates file or directory roots and publishes a root lease in the same registry transaction as control admission. Active leases prevent new controls entering already-admitted recursive source authority, including namespace overlap, ancestor overlap, physical bind aliases and nested mounted subtree coverage. Initial admission and later creation share the physical-coverage helper; inability to authenticate coverage denies admission. Existing owner exemption is limited to the admitted record and cannot exempt a replacement.

Refresh validates the original mount view, complete LIVE set and every retained live identity. Only the exact PROVED_DELETED record can be removed. It commits one replacement map and closes newly acquired descriptors on failure, preserving old ownership until close. requireDescriptor performs reconciliation, identity checks and overlap decision under one monitor, avoiding a mixed snapshot. Recomputed fast-path eligibility cannot retain stale cross-mount assumptions. Scope close detaches leases/descriptors reliably even after cancellation.

Mount epoch and registry epoch remain separate: independently retained mount events are sticky/fatal, their handle is not refreshed away, and finish still compares complete mountinfo. The plan expressly retains existing limits on detecting hostile move-and-restore between observations and does not claim prevention of arbitrary host writes.

Whole invocations, callbacks, process waits, hashing and copying stay outside the registry lock. Deletion's bounded drain remains an explicit critical section required for proof; it is not whole-invocation serialization. Lock order is registry then descriptor, with no registry acquisition of a per-control monitor. Removing the existing deleteAndProve method-monitor inversion is specifically required. Implementation review must confirm no transitive helper reverses this order.

## Resource accounting and executable controls

128 scopes times (128 retained control descriptors + root + mount event) equals the stated 16,640 persistent scope descriptor ceiling. Temporary refresh ownership is bounded by 128 additions under the single registry transaction; unchanged entries should be retained. Registry and staging ownership are explicitly additional. Retired records remain bounded by scope snapshots rather than historical churn. Admission before descriptor allocation, partial-open cleanup, cancellation-safe close, low-RLIMIT failure and bounded poison address failure paths. This is an ownership ceiling rather than an assertion that the host can support that many open descriptors.

Both named test paths exist at the exact base. LinuxBubblewrapBoundaryTest.kt:790-805 and 850-871 contain the old generation-drift refusal premises; the initially-empty case is around 980-993. AcpAgentHarnessTest.kt:856 has the existing overlapping receipt/callback test. LinuxBubblewrapBoundaryTest.kt:1377 has the live concurrent launch control. The plan targets these concrete locations, preserves neighboring hostile identity and mount controls, and requires actual callback barrier overlap with both successful receipts, so sequential success cannot substitute.

The deterministic matrix exercises admission/publication/deletion boundaries, unchanged bytes and digests, positive disjoint churn, persistent additions, retained deletions, more than 128 historical records, simultaneous scopes, nested bind aliases in both admission orders, poisoned partial creation, equal-key replacement seams, mount restore, capacity and descriptor recovery. Existing 64 MiB integrity and 4096-file scale gates stay intact, with no deadline increase. Unsupported privileged mount environments remain explicit rather than silently passing.

The DNS port is separately scoped and requires composed-source compilation, native/security controls, independent review and final hosted contract at its own source hash. Focused standalone evidence cannot qualify the dirty composed DNS source. Final source review must verify the design's atomic proof, refresh cleanup, mount closure, poison enforcement, record-scoped owner identity, lock order and descriptor limits before merging; required Actions and automatic review remain gates.

## Review scope

Only this review artifact was written. No source, Git or GitHub state was changed. No implementation tests were run because this is a plan-only review. No milestone or parent acceptance is marked complete.
