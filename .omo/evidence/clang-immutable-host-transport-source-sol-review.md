# Independent v2 input transport source review

Verdict: ITERATE — one bounded protocol-contract correction.

Reviewed exact source pins:

- scripts/oracle/clang_18_1_3_transport.py: `20eed008f547c7739ba31d6cc40df8af01f8e2cc7c1dcb0409cc5c0a98f32bbd`
- oracle/clang/18.1.3/test_transport.py: `6b8b92c05ecf3567e475b122d0ab6535f104aba79aa337bf582c493b8a4bbb04`

All five adjacent/new hashes in transport-v2-freeze.json independently match. Review owned only this evidence file; no source/Git/remote/privileged/native/Docker/acquisition operations or agents. Independently ran test_transport.py:12tests pass,0failures/errors/skips,0.109s, including actual1720memfds/54SCM_RIGHTS batches.

## T1 — P2: approved closure validation does not enforce fixed role/category/byte limits

InputTranscript.__init__ accepts any nonempty ASCII role up to16characters. It checks only sum(counts)==number-of-rows, not row role/category counts. Each row's bytes is allowed up to20GiB, with no16MiB-per-source/64MiB-source-total or1GiB-per-payload/3GiB-payload-total constraints. Thus malformed expectations can be treated as a valid protocol closure despite violating the approved plan's fixed role enum and hard resource classes.

Independent constructor controls using the literal golden BEGIN/ROW produce:

- role=unreviewed, bytes3: accepted.
- role=recipe, bytes17MiB, matchingtotal: accepted.
- role=payload, recipeSourcecount1/packagePayloadcount0: accepted.

These are approved-expectation validation failures, not evidence that an untrusted caller can replace a correctly supplied expected closure: wire rows still must exactly match expected rows. The correction belongs at this protocol boundary so future approval resolution cannot accidentally widen immutable transport caps, and the documented role/count/resource contract is actually enforced.

Define the complete fixed role enum and its category mapping (recipe/source, package/source-payload, additional artifact/report), reject unknown roles, derive exact category counts from rows, and apply per-row plus aggregate byte caps before copying/retaining the closure or receiving rights. Additional rootfs/OCI/report roles need their exact2GiB/1MiB caps. Preserve the20GiB job reservation as a separate outer bound. Add positive per-role boundary and negative unknown-role, category-spoof, per-file/aggregate overflow controls. Do not inspect clientFD content/stat to implement these declaration checks; actual content/filesystem/open-file identity verification remains restricted-helper work.

## Confirmed implemented boundaries

Received SCM_RIGHTS are atomically CLOEXEC, bounded to32per frame and closed on malformed/truncated/unexpected ancillary/JSON/timeout/disconnect paths. Accepted rights remain explicitly receiver-owned until close; wrapper cleanup closes retained rights on later-frame failures. No dispatcher pread/fstat of clientFD is present. Actual open-file-identity duplication checks are honestly deferred to capture helper.

Duplicate-key JSON, bounded frames/depth/nodes/messages/canonical transcript bytes, integer/bool distinction, ordered expected-row comparisons and exact BEGIN/COMMIT hash projections are present. Literal golden-vector test independently validates the877byte preimage and expected digest. Maximum-capacity framing has a real positive control. Deadline checks use monotonic socket readiness and nonblocking recvmsg.

Kernel SO_PEERCRED helper validates UID and Unix seqpacket type only; protected installed socket authority, approved caller/action policy and pidfd/start-time cancellation remain explicitly unimplemented supervisor prerequisites. A valid transcript does not authenticate FD contents or authorize execution. No privileged availability, self-authorizing record/approval or v1 fallback was introduced.

All broader genesis/journal/capture/receipt/action/runtime/deployment/native gates remain open. This is a source-only library checkpoint and cannot close the overall host/payload/loader findings. Acquisition pause and strict expiry policy are unchanged.

---

# Revision 2 terminal source rereview

Verdict: CLEAR for this source-only v2 input transport library checkpoint.

Exact independently verified pins:

- scripts/oracle/clang_18_1_3_transport.py: `b6563082935f7d1602d09aa796a9379d67582ca8d18cc11326499ff232f80a41`
- oracle/clang/18.1.3/test_transport.py: `ab3f3a84a347311aea3fb5b81a51b8da17defa228e1a25074dae8d9c889f7385`

Initial ITERATE review above remains preserved. T1 is corrected: immutable fixed role/category tables enforce16MiB recipe/source and1GiB payload/source-payload per-file caps,64MiB and3GiB shared class caps, exact1MiB report/record and2GiB rootfs/OCI caps, category count limits and exact declared-versus-derived category counts. Checks complete before expected-closure copying or FD receipt. The20GiB outer bound remains separate. Unknown generic artifact roles are rejected.

Independently reran all14 transport tests: pass,0failures/errors/skips,0.155s, including1720distinct memfds/54batches. Repeated the three original independent constructor controls: unknown role,17MiB recipe and payload-as-recipe category mismatch now all refuse at their intended checks. New tests cover exact role boundaries, aliases sharing category aggregate budgets and count overflow. No remaining scoped findings.

This approval does not establish file content/open-file identity/capture-helper verification, installed peer/socket authority, durable admission, transport deployment, returned receipt authentication, privilege/runtime/action integration or native qualification. No backend execution or public availability is added. All broader gates, acquisition pause and strict expiry policy remain unchanged. Rereview used no source/Git/remote/root/Docker/native/acquisition writes/runs or agents; only this review append was written.
