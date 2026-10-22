# Issue97 Actions host inspection001 independent source review

Verdict: **CLEAR_SCOPED** — source is suitable for root's separately released, read-only Actions host observation at the exact reviewed commit. This is not capture/profile/executor/native qualification or issue97 acceptance. No source changes, tests, host queries, network, JVM/native execution, Actions or Git operations were performed by this reviewer.

## Reviewed boundary

- Workflow job775 onward is selected only by explicit workflow_dispatch choice `runtime-capture-host-preflight`; all three older jobs exclude that choice. The diff retains their dictionaries. New job uses ubuntu-22.04 as a temporary unqualified candidate, contents:read,3minute job timeout, sparse checkout of only workflow+helper, persist-credentials:false, repository-owned observation HOME/TMPDIR/XDG/cache/artifacts, and always-upload of a distinctly UNQUALIFIED7day artifact. The observation invocation has timeout88s then2s KILL, bounding the process group to90s; setup/checkout/upload are bounded by the3minute job, not included in that90s probe claim.
- `capture_reference_runtime.py:446–459,990–1035`: inspect-only workflow identity is opt-in. Default capture provenance remains strict; argument modes are mutually exclusive. Inspect branch cannot fall through to preflight/preparation/controller/worker. Both normal and failure receipts keep authority false; normal refusal returns78, an exception returns1, and no terminal receipt after cancellation/outer timeout must remain unknown. A successful metadata collection returns0 without approving any capability.
- `:461–524`: file reads reserve per-file limits before consuming, use nonblocking/nofollow leaf descriptors, require regular kind and descriptor/name stability, and charge actual reads to one128MiB budget with at most one overflow sentinel. Metadata<=64KiB, cgroup files<=4KiB, tool hashes<=32MiB. Cooperative checks use one80second end. Fixed metadata/proc paths are public host facts; subordinate-ID retention is filtered to caller numeric UID/literal runner, bounded1024rows with range checks, and honestly disclaims caller-name authentication.
- The only query recipes are fixed dpkg-query metadata and systemctl show of existing user manager/service. They have no shell, helper-version execution, service creation/start, namespace/OCI/target route, install or acquisition. Each receives a closed environment and <=8seconds/8192bytes per stream. The existing command helper uses nonblocking bounded capture and bounded child reap; the outer probe timeout supplies the hard overall boundary even if startup/read/cleanup exceeds cooperative timing. Manager query is skipped unless the fixed existing current-UID bus is observed as an owned socket. No bus is created.
- Tool symlink resolution is used only to observe/hash a fixed requested tool's resolved system path; it cannot create execution/profile authority. Cgroup paths are bounded/canonical without `..`; directory acquisition uses nofollow component traversal. Later file reads reopen fixed paths and leaf nofollow rather than retaining a complete parent-chain authority. These are diagnostic snapshots with possible races, not trusted containment/delegation receipts; output expressly disclaims writable delegation and containment. Root/work directories are canonical repository-owned leaves, and receipt publication uses exclusive pending creation+noreplace link. No reviewed branch writes to system metadata paths.

## Evidence and limits

Author's retained receipt reports26 guarded pure tests,0 failures/errors/skips/forbidden attempts, including19 prior capture controls. I inspected the new controls and retained log/receipt; I did not rerun them. They exercise mocked context routing, fixed query argv, unknown/refusal preservation, limits/FIFO/deadline, allocation filtering, and all-false authority fields. The static-check record and source diff show unchanged SOURCE_PINS/constants and old function bodies except intentional public_environment/main routing. This source review cannot establish actual Actions image packages, user bus, systemd delegation, namespace availability, or feasible executor provisioning. Missing facts/refusals are observations to retain, not evidence for a retry/profile approval. No precise hosted success or production fix is predicted.

No blocking source finding within this read-only observation scope. Root must choose the reviewed immutable ref and release the single observation; this review neither dispatches it nor authorizes full capture. P1 host/executor feasibility remains open.

## Exact pins

Freeze SHA-256: `07b8684b6b0a1f81fc525437533e1f5118b56a9ad2682e0772f546f54bec98c1`. Every freeze source/evidence row was independently byte-size/hash checked; frozen source snapshots equal current files.

| Path | SHA-256 |
|---|---|
| `.github/workflows/llvm-oracle-model.yml` | `af8680c3d833aac49974dbb90bc1df480c51c37ac4fcff06bcc2a233aa3d0b48` |
| `oracle/llvm/capture_reference_runtime.py` | `492be8d2db0c65868ee50ca8fc007c4e27b2eedced4a26f6881e563710270a0b` |
| `tests/oracle/test_capture_llvm_reference_runtime.py` | `9cd2f3e24e37894c79e1a250bd01ba6a86cd40a8182521dcf33cb82c1eb37125` |
| `build/issue97-actions-host-inspection-001/before.json` | `59de0d623be9e6a0ec21f4c4efc81e36e4f763f80a6e4a507b2a0658ad0d80ed` |
| `build/issue97-actions-host-inspection-001/capture_reference_runtime.py.diff` | `4a42ffc88ea96cbd398e450af5e055416c5c182a19892223a518842b6fe77c18` |
| `build/issue97-actions-host-inspection-001/llvm-oracle-model.yml.diff` | `219d6f906d0f980172d0e318b228a743ca3a168664687496f55735e9f952d0b0` |
| `build/issue97-actions-host-inspection-001/pure-tests-001.json` | `b1533fe622c8ddc105e6f649bfeaa09d84ec9ab29bd81e9c5d74ad432b46e1b9` |
| `build/issue97-actions-host-inspection-001/pure-tests-001.log` | `1173b2441533f9ac0bb090e5742799df55fff99a61599e8a2f81049539faf812` |
| `build/issue97-actions-host-inspection-001/report.md` | `30d91bc148656b72fd2573636e1f565a07014093702c92f1e1abb6e9b799e0ef` |
| `build/issue97-actions-host-inspection-001/static-checks.json` | `39d93b4cbdbec548c75a218340724c59d472c9c9d9e6886412203f4e919c0023` |
| `build/issue97-actions-host-inspection-001/test_capture_llvm_reference_runtime.py.diff` | `bbbf5eae0cda0d44d6661eac7e0f9a7615a7815aa7a05ae5676278e47a0cbda9` |
