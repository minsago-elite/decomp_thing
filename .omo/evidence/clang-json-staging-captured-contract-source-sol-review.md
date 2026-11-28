# Clang JSON, staging and captured-contract source review

**CLEAR_SCOPED** on freeze `ee8c1f79884e22588825de02147b1a8abb7e54d658b417e057a2ffaa52ba5364`, for the five specified JSON/OCI-size/mode/contract-snapshot findings. No blocking defect found in this three-file correction. This is not whole-Clang acceptance, production/native qualification, or resolution of the complete automatic-review set.

Read-only source and retained-evidence inspection, 2026-10-14, GPT-6.1 Sol. No source changes, tests/imported product execution, JVM/native/proc/Docker/acquisition/network/auth/model/Git/remote operations. Only this scoped review Markdown was written in wt59. Root retains all integration/remote custody.

## Exact source and evidence

| Input | SHA256 |
| --- | --- |
| Source freeze | `ee8c1f79884e22588825de02147b1a8abb7e54d658b417e057a2ffaa52ba5364` |
| Provisioner | `11a7d5c390ca870f412e16521eadd53f699befc9f24a2d53e93d2b51afdc9c18` |
| Worker | `28a13c4041c53c5f032f77d41d0b4caa271dbf35aa208656328d0ebfb732073a` |
| test_provisioning.py | `7cc24c85b2c271c940f282cc035979d4b4ca98f1867c7fd6b1eccaaa83a86a5a` |
| Exact source delta | `fbd0703f99cb7a6cbced0b7f379b9bd8af2ac9b7085f584721a602237e17d740` |
| Author report | `fe134878f5936cba1981475a210f3928bcc9cdb5bedf47b172d6630463da97ef` |
| Retained focused result / log | `75ea1ae9efc5a861ebdd35c6221beebbddf0ba57d4c2b8ede9d5ff2b155da713` / `a78ddbe463b1247dc3578def053c7f1ec5554b3b20f43c75a83a12858deec8a1` |
| Retained old-counterexample result / log | `c37ebce757f5a987ed4eebecc608b95a37282255d5fdb1599c7b0bb7e3496a7a` / `6f920fa89a5f72cba4d1c0f4ba8194dc3033f9810b331cc7774f1541008b3051` |
| Root resolution map | `7a71a1d06d34b3965bed215187db11a1cf9bbc3495075393ed9dce3208199240` |
| Root full review-thread capture | `cd14a00a1bf50bd6af7a828cd5f18f0d2ce528c229175154c95b5b7f7cdd3605` |

The three source paths are `scripts/oracle/provision_clang_18_1_3.py`, `scripts/oracle/clang_18_1_3_worker.py`, and `oracle/clang/18.1.3/test_provisioning.py`. Evidence is beneath `build/clang1813-json-staging-capture-correction/`. Root thread capture is `build/active-review-checkpoint/sol-current-review-threads-20261014.json`; map is `build/clang-e376-hosted-diagnosis/automatic-review-resolution-map.md`.

Independently recomputed all three live source pins and all22 frozen evidence pins/sizes. Reconstructed the exact unified delta from before snapshots and current source; it equals the retained delta byte-for-byte. Parsed source AST without importing/executing modules. Both production functions' changed call graphs and actual consumer ordering were inspected, not inferred from test names. Baseline f5bb/82a8/bd40 bytes are retained separately; root-reported integrated HEAD dd9d is metadata, not a new execution receipt.

## Five reviewed findings

### Non-finite JSON — PRRT_kwDOTCeevs6sMqaM

Provisioner259–279 now supplies rejecting `parse_constant` and a `parse_float` which converts then requires `math.isfinite`. This rejects nested NaN/Infinity/-Infinity and ordinary JSON number tokens whose exponent overflows Python float (1e400/-1e400). Worker52–75 applies the corresponding finite-float check in addition to its existing duplicate/constant rejection and top-level-object requirement. Provisioner254–256 now uses `allow_nan=False`; worker's canonical encoder already did. Finite numeric behavior and duplicate-key rejection are retained. Unknown/invalid inputs do not obtain a digest by encoding NaN again.

All `json.loads` entry points in these two modules route through these shared decoders. The separate frontend pretty encoder is used for the constructed resource-directory preimage, not an alternate raw candidate decoder; this review does not claim it is a general hostile-object serializer. Malformed UTF-8/syntax/type errors still refuse or abort; no exception path publishes authenticated success. This is finite JSON validation, not a claim that every generic dictionary has a closed schema.

### Exact OCI sizes — PRRT_kwDOTCeevs6sL7VU

Provisioner3389–3392 and3419–3421 require `type(size) is int` for manifest and layer, before equality. Thus booleans and integral floats cannot exploit Python numeric equality; absent/null/string/negative sizes also fail. Existing config exact-integer check remains. Both manifest digest/raw length and layer member length/hash/diffID checks remain. No byte/hash/media/reference/member-set predicate was removed.

The underlying verifier still authenticates a capped regular nofollow archive descriptor, bounds headers/members/small metadata, authenticates consumed chunks, streams compressed/expanded layer bytes, and rechecks archive bytes/identity on success. Existing consumer shape checks and exact config semantics remain. This correction is not represented as a complete newly closed OCI metadata schema.

### Canonical OCI modes — PRRT_kwDOTCeevs6sL7VI

Provisioner3179–3220 explicitly chmods all three archived layout directories0755, regardless of mkdir umask. Every new blob/layout/index file is exclusively created with O_NOFOLLOW/O_CLOEXEC, wrapped in an owning file context, descriptor-fchmod0644 before writing, then closed. This covers every file included by the OCI producer; parent directories outside the archived layout are not claimed canonical. An exception does not return a successful layout identity; partial on-disk outputs are not thereby proved cleaned up. This does not add a retained pathname lifetime proof to the unqualified producer.

### Canonical staged modes — PRRT_kwDOTCeevs6sMqaO

Worker426–462 retains trusted held-parent/root ownership, random exclusive root creation and nofollow child opens. It repairs root permissions before opening under a maximally restrictive umask, then confirms owner and fchmods the held descriptor. Each nested directory is repaired before open when newly created, reauthenticated after open, and descriptor-fchmod0755. Every exclusive staged file is descriptor-fchmod0444 before writing; final root remains0555. Thus the actual published modes, rather than requested creation modes, provide directory traversal/read permissions for the unprivileged container user.

Files are entered into known-name cleanup lists before their new chmod/write step; with-context/finally closes the file/directory/root/parent descriptors. Existing sealed-source validation,16MiB per-input read cap, held-FD staging path, known-name unlinking and foreign root-name identity refusal remain. New chmod failures do not yield the tree. The retained tests inspect real mode bits/payloads and teardown under022/077/0777, using inert worker fixtures; they do not execute UID65532 in a real container or establish Docker/native qualification.

### One admitted raw contract — PRRT_kwDOTCeevs6sMqaH

The same operation-local `captured` map now flows from `read_contract` through every changed parse-plus-recipe consumer: compare-runs, verify-record, loader input, verify-image, snapshot metadata command/report and the gated unqualified producer. Existing packaging retains the same map. `recipe_identity` receives the capture rather than reopening selected contract. Noncanonical raw whitespace is therefore included in identity; this is not a hash of JSON reserialization.

`require_contract_snapshot` at4595–4601 also binds low-level validate/compare/metadata callers: it reads from the capture (or admits a new capture if absent), revalidates the contract, and requires canonical semantic equality with the supplied parsed dictionary. A replacement supplying a different digest cannot certify the old semantics. `snapshot_metadata_selection` hashes the admitted raw bytes for both contract identity and recipe. Loader input captures the record before validation and uses those same bytes for `buildRecordSha256` at4895; it does not reopen a replaced record for that digest.

New command record reads use `read_provenance_report` and existing immutable-byte capture: nofollow/nonblocking/CLOEXEC regular descriptor, capped read, cumulative capture cap, owning context closure, UTF-8/strict JSON then object check. Existing finite build-record closed-schema validation remains before recipe equality and output. Shared capture does not authenticate a signature, approve altered contract semantics, bind transitive helper execution to its source, or make all recipe inputs immutable deployed runtime authority.

## Retained test evidence and limits

The inspected actual focused runner/log reports22/22 methods successful, zero failures/errors/skips/forbidden events:9new plus13existing. Selection includes finite/exponent/encoder controls, rehashed float/bool/other descriptor types, cross-umask archived bytes and nested worker permissions, raw contract/record replacement and forgery refusal, existing duplicate-member/selected-contract/held-FD cleanup controls. The actual old-source runner loads the preserved production modules with current fixtures:7methods expose24expected assertion failures, zero errors/skips/forbidden attempts. Its assertions/log show the intended old behaviors rather than import failures. Initial fixture-output publication mistake and earlier six-control generation remain distinct evidence. No reviewer rerun was performed.

Boundedness is scoped: the new captured command reads retain the existing1GiB per-input read cap and3GiB retained-byte admission ceiling (large but finite). The unchanged helper checks cumulative admission after reading the next capped object; this is not a pre-reserved3GiB peak-allocation guarantee. Unchanged `compare_build_runs` still reads its two held record files without a new size cap; unchanged OCI production still buffers rootfs/gzip bytes. This review does not certify universal resource bounds or extend this fix to those existing paths. No integrity check was removed to accommodate tests.

Independently compared full before/after AST source segments for `_execute_approved_protocol`, `require_acquisition_access`, `require_immutable_host_execution`, `root_owned`, `run_probe_sandboxed`, `verify_detached_signature` and `verify_gpgv`: all exactly unchanged. The existing634 inode/race publication fixture is also byte-identical. Acquisition pause, signature/expiry refusal, immutable-host/public producer refusal and other preserved gates remain. Host construction closure, authenticated installed payloads, loader source/transitive classpath capture, rootfs packaging lifetime, workflow triggers/offline loader compile/output placement and other unresolved map findings are not cleared here.

**Conclusion:** CLEAR_SCOPED for these five corrections at the exact source pins above. Root must separately handle integration, automatic-thread replies/state, complete required hosted checks and all remaining acceptance/qualification gates.
