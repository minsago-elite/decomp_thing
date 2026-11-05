# Clang host protocol/backend checkpoint

This is a narrow reviewed checkpoint, not completed host qualification. Authenticated privileged transport, durable supervisor reconciliation/deployment, approved production inputs and actual runtime qualification remain unfinished; host/payload/loader findings remain open. Acquisition and strict expiry holds remain unchanged.

## host-checkpoint-summary.md

SHA256 `9dfa8834220942e3bcf3f7a9c47eab927fdab1e6996ed6717402ef95d2c33bc9`

# Host approval / immutable backend checkpoint (production incomplete)

Implemented root-installed approval-anchor → exact approved index → action-selected environment lock → complete approved action/source closure. Caller records, self-consistent replacement locks/recipes and environment variables do not authorize inputs. Approval files and all ancestors are opened without following links and require root ownership with no caller write permission. Independent approval and signing-key audit occurs at administrator installation: the root-installed anchor pins exact approved index bytes. This checkout neither installs approvals nor substitutes its policy JSON for that authority.

Approved source FDs are read within byte/count budgets, compared with the root-approved complete closure and copied into sealed memfds. Backend consumes those immutable bytes. Real FD tests reject mutation after capture and verify actual cleanup on success/failure.

Concrete Docker backend is implemented: independently approved runtime CLI is checked from root-protected storage and executed from a sealed executable snapshot; a dedicated local root-only mode 0600 daemon socket supplies actual image/container measurements. Image config/diff IDs/platform and approved OCI manifest association are checked. Root supervisor supplies an authenticated held root-owned stage-parent directory FD; caller pathnames cannot authorize staging. Sealed inputs are materialized through held FDs under protected directories and the daemon binds the held root descriptor. Fixed container execution is unprivileged UID/GID 65532, read-only, no network/capabilities/new privileges, bounded CPU/memory/process/disk/output/time, private namespaces and a fixed initial environment clearing loader/tool injections before env -i starts. Container configuration is remeasured before and after execution; child stdout cannot supply its identity. CLI I/O is bounded while reading; timeout/overflow kills CLI descendants and the finally path reconciles every attempted create through daemon-authenticated name/token ownership and removes only its immutable ID. Stage cleanup refuses replacement names and closes held FDs.

Public provisioning/packaging/check-host-execution now refuse before mutable host execution. Even a successful approval lookup cannot fall through into old code. Legacy implementation functions have explicit _unqualified names and are exercised only as inert unit fixtures. Acquisition pause still refuses first; a future unpause also meets the immutable host gate. Workflow removes mutable host apt installation and checks the independent executor before acquisition. Worker/policy/environment recipe bytes are required in record recipe shape and captured provenance archives, with exact schema inventory updated.

Verification: 207 offline tests passed in 13.823 seconds; 16 new host controls include actual sealed CLI execution after source-path replacement, real process output/time limits, source closure/approval attacks, kernel seals/FD cleanup, trusted daemon response/isolation controls, protected stage foreign-name cleanup and public no-fallback checks. Root ownership/daemon responses are simulated; no Docker daemon, root process, native Clang or production approval was exercised. Independent cached JVM JSON Schema validator passed 31 cases, including new required host recipe fields. All 79 schema inventory digests match; git diff --check passes. Public check-host-execution returns exit 1 with explicit unavailable executor error.

## Unfinished production source / evidence scope

This is a passing protocol/backend checkpoint, not completion of the host finding or qualification. Missing work is explicit:

1. Administrator-approved environment construction from authenticated exact package/dependency inputs, package manifest, image/config/diff-ID digests, approval key/index/lock/action manifests and installed launcher bytes. Policy and construction recipe retain null approval values and qualificationEnabled: false. No values are invented or acquired.
2. Production privileged service/launcher startup and request protocol: authenticate caller/allowed action, receive bounded client source/input FDs, obtain the supervisor-authenticated stage-parent FD from deployment, invoke execute_installed_action only from its independently approved installed path with isolated interpreter configuration, and return authoritative result/artifact descriptors over an authenticated root service boundary. The code deliberately does not expose an unreviewed privileged CLI/FD transport.
3. Complete rootfs/acquisition/output artifact mount/FD transport, bounded extraction/export, returned supervisor receipt authentication and consumer integration. Public functions remain blocked rather than continuing the old host paths. The generic backend action stdout is not an accepted provenance receipt. Native bootstrap privilege/profile needs its own reviewed action; this fixed unprivileged container profile is not silently broadened.
4. Actual root-only runtime deployment and attack controls: inspect real daemon canonicalization/configuration, sealed CLI behavior, checked mounts/namespaces/resource limits, timeout/OOM/descendant/container cleanup, transient same-UID input/CLI/data swaps and authoritative root-origin results. Mock daemon responses cannot qualify these.
5. Authenticated package payload replay and immutable loader compilation/runtime source closure are later separate checkpoints. No successful Noble install, native driver/runtime replay, cross-host reproducibility or loader acceptance is claimed.

No Git/GitHub mutation, privilege escalation, package/archive acquisition, /etc write or files outside repository were performed. Acquisition pause and current-clock key-expiry refusal remain unchanged. Exact source hashes are in host-freeze-sha256.json; logs host-all-tests.log, host-focused-tests.log, host-production-gate.log, host-schema-inventory-check.log and host-schema-crosscheck/results.log.


## Independent review corrections

H1: attempt name and independent label token are allocated and retained before calling create. Even if daemon creation commits before the CLI times out, overflows, disconnects or emits a malformed identity, finally inspects the attempt through the trusted daemon and authenticates its name, ownership token and immutable object ID before removal. Exact-method inert controls reproduce every lost-result case; owned objects are removed, while foreign collisions are never removed. An unavailable or ambiguous daemon prevents an accepted result and retains in-memory pending ownership. The unfinished production supervisor must journal this ownership before create and reconcile late completion or supervisor crashes; no persistent production reconciliation is claimed here.

H2: both pull_request and push filters explicitly include scripts/oracle/clang_18_1_3_worker.py. The static regression checks each event section separately, so one filter cannot mask omission from the other. Worker/policy/environment source closures remain recipe-bound.

## host-freeze-sha256.json

SHA256 `b213a169cf9fd84197a9d016a4fb48c9400fc4c7aa6e5ea35022ab960a008802`

```json
{
  "scripts/oracle/clang_18_1_3_worker.py": "82a8f0de75f937525fdf1510d3328f2d297d0cacc207ec404cd0f3ac6399131f",
  "scripts/oracle/provision_clang_18_1_3.py": "f5bb2417c845802a782ec23b749674b3ac879109e3f4b1c90f233055e1e9e65d",
  "oracle/clang/18.1.3/test_provisioning.py": "90b81628592a9e56617500fab462988533b91de9f4b8a5888bf38c7ceb47750a",
  "oracle/clang/18.1.3/build-record.schema.json": "ba1a763ddc614f5aae8dfc3e684f32d6d4a3e3929cecc2a33eb0e3c2e516eae1",
  "oracle/kotlin-schema-inventory-v1.json": "2b51e1a4a33f190f8981dfe9925e38da3ef1124dfd45743d287cb632aa0c5537",
  "oracle/clang/18.1.3/host-execution-policy.json": "3bf9c90fe74c1535ca44d62b0153a40f7fac94acb7a5e24b23101ff60ba3f63b",
  "oracle/clang/18.1.3/immutable-host-environment.json": "03c801e83a977858bb6a4c47f00e7fc710e7fb63d86c8bb85178a65290cd3d80",
  ".github/workflows/generic-template-toolchain.yml": "2a2e25b8e53b7634309b64c47a72b68fded2b2e88a2e60b818563ed8f692cee2"
}

```
## host-sol-review.md

SHA256 `69827669fc8736817c5683ccd80e00bef9b230bd0e79f2941a220c1b72e01f5f`

# Independent corrected host protocol/backend checkpoint review

Status: CLEAR for the narrow implemented protocol/backend checkpoint at the eight-source freeze below. No approval of production deployment or overall host-tool finding closure.

## Corrections verified

H1: execute allocates a random attempt name plus independent ownership token and records pending ownership before create. Cleanup runs after create failures as well as success, reads trusted daemon inspect metadata, requires matching name/token/expected immutable ID, and removes only that immutable ID. Timeout/overflow/disconnect/malformed-result controls model daemon commit before lost CLI reply. Foreign-token collisions are preserved; unavailable/ambiguous reconciliation refuses success and retains pending ownership. Child stdout supplies no authorization. This corrects the earlier silent cleanup skip.

Pending ownership is in-memory only. A late daemon completion, process crash, service restart or unavailable daemon still requires the explicitly unfinished durable supervisor journal/reconciliation protocol. That requirement is documented in the updated checkpoint summary and production remains gated. Do not describe this checkpoint as crash-safe or unconditional production cleanup.

H2: both pull_request and push path filters now include scripts/oracle/clang_18_1_3_worker.py. Static regression checks both event sections independently.

## Independent evidence

All16 HostWorkerProtocolTests independently pass,0failures/errors/skips,0.165s: host-sol-corrected-tests.log. They include lost-create-result/foreign-collision/pending-ownership controls, actual sealed fake-CLI execution, actual subprocess time/output limits and descriptor lifecycle; root approval ownership and daemon responses are modeled. No Docker daemon, root process, native/bootstrap or acquisition execution was performed. git diff --check independently passes. Source/Git/GitHub review was read-only; only repo-contained review evidence was written.

The implemented root-owned anchor/index→approved lock/action/source closure, sealed input/CLI snapshots, fixed root-only socket/environment/container spec and held staging descriptor retain their previous reviewed authority boundaries. Public gates refuse; no mutable-host fallback was introduced. Artifact/launcher FD transport, authenticated returned receipt integration, approvals/install/deployment, durable attempt journaling and real runtime qualification remain unimplemented. Missing approval values are not minted. Authenticated payload and immutable loader stages remain separate unfinished work; acquisition and expired-key holds remain unchanged.

Exact verified corrected source SHA256:

- scripts/oracle/clang_18_1_3_worker.py: `82a8f0de75f937525fdf1510d3328f2d297d0cacc207ec404cd0f3ac6399131f`
- scripts/oracle/provision_clang_18_1_3.py: `f5bb2417c845802a782ec23b749674b3ac879109e3f4b1c90f233055e1e9e65d`
- oracle/clang/18.1.3/test_provisioning.py: `90b81628592a9e56617500fab462988533b91de9f4b8a5888bf38c7ceb47750a`
- oracle/clang/18.1.3/build-record.schema.json: `ba1a763ddc614f5aae8dfc3e684f32d6d4a3e3929cecc2a33eb0e3c2e516eae1`
- oracle/kotlin-schema-inventory-v1.json: `2b51e1a4a33f190f8981dfe9925e38da3ef1124dfd45743d287cb632aa0c5537`
- oracle/clang/18.1.3/host-execution-policy.json: `3bf9c90fe74c1535ca44d62b0153a40f7fac94acb7a5e24b23101ff60ba3f63b`
- oracle/clang/18.1.3/immutable-host-environment.json: `03c801e83a977858bb6a4c47f00e7fc710e7fb63d86c8bb85178a65290cd3d80`
- .github/workflows/generic-template-toolchain.yml: `2a2e25b8e53b7634309b64c47a72b68fded2b2e88a2e60b818563ed8f692cee2`

---

## Historical initial review (superseded by corrected verdict above)

# Independent host protocol/backend checkpoint review

Status: CHANGES NEEDED for the initial freeze in host-freeze-sha256.json (worker d6120a11d2e907e67f55b28ecd6316d8dce6fef6d6ff026eae9272f8d35d1229).

## H1 — P2: creation failure can skip daemon object cleanup

DockerBackend.execute initializes container=None and sets it only after command(create) returns and its stdout parses as a valid container ID. A daemon can complete creation before its CLI times out, disconnects, exceeds output allowance or returns malformed output. Those error branches reach finally with container=None and never issue rm. The daemon object retains the deleted stage bind configuration and resource/metadata allocation; repeated failed requests accumulate objects. The currently claimed unconditional cleanup does not hold.

Independent inert control models daemon creation followed by a CLI timeout, executes the actual execute method, and records only create with daemon object left=True. Evidence: host-sol-create-failure-control.log. No Docker daemon or privileged command was used. Establish a random attempt identity/name and ownership correlation before invoking create, then safely clean the exact attempt even if ID response is unavailable. Add timeout/malformed-result and foreign-name collision controls; never delete a pre-existing unrelated object.

## H2 — P2: new worker changes do not trigger primary workflow

Both pull_request and push path filters in generic-template-toolchain.yml omit scripts/oracle/clang_18_1_3_worker.py. Changes confined to the new security-sensitive module therefore skip its primary offline/qualification workflow. Add the worker path to both filters and assert this in the workflow coverage test.

## Evidence and limits

Independently reran all15 HostWorkerProtocolTests: pass,0failures/errors/skips,0.225s; host-sol-focused-tests.log. Existing tests do not exercise H1. Reviewed approval anchor/index/lock/action source closure, actual sealed input/CLI FD capture, protected directory/stage authority, fixed daemon endpoint/environment/container spec and bounded command loop. No additional scoped findings so far.

This is a read-only source/Git/GitHub review with evidence writes only inside repository build directory. Approval ownership/daemon metadata are modeled. No root/Docker/native/bootstrap/acquisition execution. Public gates are deliberately unavailable; authenticated launcher request/FD/artifact transport, deployment and actual runtime qualification remain unimplemented. Even a corrected narrow checkpoint cannot close the overall host-tool finding.

Exact initial eight-source freeze:

- scripts/oracle/clang_18_1_3_worker.py: `d6120a11d2e907e67f55b28ecd6316d8dce6fef6d6ff026eae9272f8d35d1229`
- scripts/oracle/provision_clang_18_1_3.py: `f5bb2417c845802a782ec23b749674b3ac879109e3f4b1c90f233055e1e9e65d`
- oracle/clang/18.1.3/test_provisioning.py: `c93adaa5b0d713cf51f01987a1bec94834c2d3414014f474b1e264fc43d0da4a`
- oracle/clang/18.1.3/build-record.schema.json: `ba1a763ddc614f5aae8dfc3e684f32d6d4a3e3929cecc2a33eb0e3c2e516eae1`
- oracle/kotlin-schema-inventory-v1.json: `2b51e1a4a33f190f8981dfe9925e38da3ef1124dfd45743d287cb632aa0c5537`
- oracle/clang/18.1.3/host-execution-policy.json: `3bf9c90fe74c1535ca44d62b0153a40f7fac94acb7a5e24b23101ff60ba3f63b`
- oracle/clang/18.1.3/immutable-host-environment.json: `03c801e83a977858bb6a4c47f00e7fc710e7fb63d86c8bb85178a65290cd3d80`
- .github/workflows/generic-template-toolchain.yml: `51db95472b43c07efc27298d77ebff7d9f3de320725310d0b014c48121aace0b`

