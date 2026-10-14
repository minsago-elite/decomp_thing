# Independent journal admission/intent source review

Verdict: ITERATE — one service-lifetime mutation gate missing.

Exact verified pins:

- scripts/oracle/clang_18_1_3_journal.py: `c53eebd1de7dd584fd1db3355ae8de85e796c83d1b92a4a4f4a0e01ec517d0e1`
- oracle/clang/18.1.3/test_journal.py: `5be0222c277b63939a7c1c3eefd2db2694660ca7ca8d480d6869ff8eaa712eaa`

Read-only source/Git/remote review; only this review file written, test state was repository-local and removed. No root/Docker/native/package/acquisition/auth operations or agents. Independently ran10journal tests: pass,0failures/errors/skips,1.036s, including actual child os._exit/reopen controls.

## J1 — P2: reopened service can issue new mutation intents for an old lifetime

Journal construction binds only deployment digest. admit stores bootId/generation/supervisor/daemon facts, but intent never compares them with any current authenticated service lifetime. It checks only state/version and a monotonic deadline from the persisted job. A new connection/service generation can obtain the old job via pending/job and create a new stage/spool intent without reconciliation. After a host reboot, the persisted prior-boot monotonic deadline can also appear to be in the future.

Independent inert control: openJournal; admitjob; closeJournal; opennewJournal withsame deployment; callintent(oldJob,version0,stage). It succeeds withINTENT. There is no constructor/current-lifetime parameter that could distinguish a different boot/generation/supervisor/daemon, so callers cannot ask this API to enforce the required distinction. This is an API authority/recovery-invariant gap, not evidence that an unprivileged client can bypass the private root-owned state directory.

Bind each journal instance to independently supplied/authenticated current boot/generation/supervisor/daemon lifetime facts. Admission must agree with that active binding; new resource intents must require the row's matching active lifetime and completion of required startup reconciliation. Reopened previous-generation/old-boot jobs remain read-only reconciliation/quarantine input and must not gain fresh mutation authority merely through known IDs/versions. Quarantine recovery can remain available without reviving operations. Persist any recovery gate needed to prevent reopening from silently restoring mutation eligibility. None of this needs a physical quota/helper/daemon implementation or real production credentials.

Add actual close/reopen tests with distinct generations/boots/supervisor start identities and daemon identities, including a prior-boot deadline numerically in the future. Every attempted fresh intent refuses and reservation remains retained; matching active-lifetime admission/new intent succeeds. Recovery must still quarantine the previous row without deleting or releasing quota. Keep deployment mismatch and stale-version controls.

## Confirmed scoped properties

FULL/WAL, foreign keys, application/schema IDs and an exclusive no-follow single-link/private lock are implemented. Private held-parent ownership is additional authority defense, with complete ancestor/deployment genesis honestly external. Initial schema/authority installation is transactional; admission and resource rows commit before returning an intent, and no stage/spool resource mutation occurs in the module. SQL bindings and expected-version transaction checks prevent record injection/stale updates. One nonterminal job blocks other admission; random identities are persisted, source spool rows match admitted identity/size and duplicate logical spool operations refuse. Sticky quarantine retains the logical20GiB reservation with no release/revival/cleanup API.

Existing tests demonstrate committed WAL survival and uncommitted rollback across actual process death, including conservative preservation/quarantine of inert unmarked/foreign resources. These are process-crash controls, not power-loss or physical quota proof. They do not yet cover J1.

Transport-validated/independently approved closure and held parent facts remain explicit service prerequisites; this journal does not authenticate approvals, inspect caller payloads or grant production execution capability. Trusted markers and post-mutation identity states, helper ownership, installed service/peer lifetime, physical quota, artifact/verity/receipts and daemon recovery remain unfinished. No launcher invokes this module. Overall host/payload/loader findings, acquisition pause and expiry holds remain open/unchanged.

---

# J1 correction terminal rereview

Verdict: CLEAR for the narrow source-only journal admission/intent checkpoint.

Exact independently verified corrected pins:

- scripts/oracle/clang_18_1_3_journal.py: `7a41958f96c4843d894f945c83976a3b2787d3c4b8bf066ec304d2b076e2b7a4`
- oracle/clang/18.1.3/test_journal.py: `e53ddfb5b0da31de27c11025c7b0c73992cec9e2a1137a68a19caa3f2ece1c91`

Both adjacent transport hashes match journal-v2-freeze.json. Original ITERATE report bytes above independently matched their frozen SHA256 before this append and remain preserved. No source/Git/remote/Actions/auth/model/root/Docker/native/acquisition mutation or agents; only this review append was written. All test state remained inside the repository.

J1 is corrected. Constructor requires validated current boot/generation/supervisor PID+startTicks+UID/GID and dedicated daemon instance/service/data-root digests. Canonical serialization freezes this trusted service-fact binding. Admission facts must match it; resource intents compare persisted facts with the active binding.

In addition, constructor transactionally sets recovery_required on every preexisting nonterminal row before returning. Even a matching-lifetime reopen cannot resume old resource mutation, and this API cannot clear the durable gate. A future numeric monotonic deadline from a prior boot confers no permission. Read-only reconciliation and sticky quarantine remain available, preserving reservation and ownership. No fresh mutation, quota release or false cleanup authority is added.

Independently ran13journal tests: pass,0failures/errors/skips,1.265s, including distinct boot/generation/supervisor-start/daemon instance/service/data-root reopen controls; raw SQLite observation of the already committed gate; copied/frozen lifetime facts; matching current admission/intent positive; real os._exit WAL survival/rollback. Unchanged14transport tests independently pass,0failures/errors/skips,0.161s.

Schema version2 intentionally refuses version1/unknown journals without automatic migration. This is honest and fail-closed for this undeployed library checkpoint; any future administrator migration/reconciliation requires separately reviewed ownership-preserving handling. Refusal must not become an excuse to delete old journals/resources or drop their reservations.

No remaining scoped findings. Authentication of supplied current lifetime facts and complete ancestor/deployment/source authority remains an installed-supervisor prerequisite; this parameter is not proof of kernel identity. Physical quota, trusted marker reconciliation, post-intent states, capture helper, peer lifetime, artifact/verity/receipts and dedicated daemon recovery remain unimplemented. No production launcher invokes this module, no native or overall host/payload/loader completion is inferred, and acquisition/expiry holds remain unchanged.
