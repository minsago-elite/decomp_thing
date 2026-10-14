# Task6 real-input plan independent Sol review

**Terminal verdict: ITERATE.** The proposed route preserves the full #1510 outcome and is materially executable through bounded OCI inspection, reviewed hermetic assembly, a nonempty application-committed selector, protected real issuance and mandatory isolated native qualification. Two approval/data-flow gaps below must be made explicit before adopting this as the complete implementation route. This is a plan verdict, not runtime/source/acquisition/permission approval.

I did not author the reviewed plan or either supporting audit. Review was read-only except this report. No network, acquisition, native/JVM execution, authentication/model operation, remote action, source change or approval was performed. All files read/written were inside the repository. No other owner's files were edited.

## Exact review inputs

The following SHA256 identities and sizes were recomputed; all four proposal pins matched their freeze. All five stable structural-checkpoint source pins also matched their actual worktree files.

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| `.omo/plans/provider-dns-task6-real-input-approval.md` | 17468 | `f25abb6fd458888db5ced0b7e54891218cdb97fc75f7c6a7b1a6c79a461a3e3d` |
| `build/provider-dns-task6-runtime-planning/proposal-freeze.json` | 955 | `c517d4150c34a8cb3188799c9246c44f914b02eabf062ae4a5caf1909d7fb8f9` |
| `.omo/evidence/provider-dns-runtime-input-source-audit.md` | 18784 | `5b3ad0d140734cf88c070bc339143815514b79674bcfb865a91d8db6eab5718a` |
| `.omo/evidence/provider-dns-resolver-policy-source-audit.md` | 23043 | `09992efd2277db9b514620f74df797c5c8bee1ad320761e4532bf0cab066ac8c` |
| `build/provider-dns-task6-runtime-planning/current-scope.json` | 4603 | `14d66434ed8010ee266f832936cbb736e1eb195f8d06c667385e138d5863c43d` |
| `.omo/plans/provider-dns-task6-closed-runtime-profile.md` | 22581 | `f037aa12734376227689e78c4d21da7dcee81f0aa58ebbaa7c6b190bfde2a35f` |
| `.claude/worktrees/provider-dns-task6-runtime/build/provider-dns-task6-contract/checkpoint-freeze.json` | 1707 | `8a6c640f424591f971ed6227d2827fd75995e5ba75c96e11435f79c659aa9903` |

Snapshot #1510/#958 and milestone16 are OPEN. This review uses that pinned snapshot; it makes no newer live status claim. Stable candidate source is `src/main/kotlin/decompengine/acp/AcpProviderDnsRuntimeProfile.kt`, SHA256 `1778f5c656eb1842570f3ee0d3638bc25b046ce469cd952bb38296612595d566`, under `.claude/worktrees/provider-dns-task6-runtime/`. Its `requireApproved` lines33–37 unconditionally throw. Lines39–49 accept structural hash declarations, not their real-world authority; lines142–185 parse resolver syntax only. These are the actual starting semantics, not a usable runtime.

## Blocking findings

### R1 — Declare the acquisition/review path for matching source and patches

**Anchors:** proposal lines24,32,40,44–48,54,58,66; runtime audit lines57,63,75; resolver audit lines55–66,110.

The single external acquisition described at lines40/44 fetches the named OCI graph/payload. Yet step2 must record corresponding source/patch provenance, step3's gate requires authenticated source semantic closure, and step4 must analyze the chosen matching JDK/libc implementation. The current plan neither establishes those sources are inside the OCI payload nor defines the branch for obtaining them if absent. The supporting audits explicitly say their OpenJDK/glibc sources are unbound mechanism examples. Actual payload versions and source availability are unknown, so this is an unspecified route, not a claim that the candidate lacks source.

As written an executor reaches a gate requiring source evidence it has no specified bounded acquisition path to obtain, or might substitute package version strings, unrelated upstream examples or an undeclared later download. The inspector/source-lock implementation is the next assigned task, so its authority and input states need an explicit route now.

**Required correction:** make OCI preflight produce either (a) independently authenticated in-payload matching source/patch/build-provenance receipts, or (b) a bounded source-discovery proposal listing exact source artifacts, expected identities/trust roots, relationship to selected binary build IDs and verification procedure. For branch(b), name a separate source-policy/input review and custodian-authorized repository-local acquisition before semantic review/native execution. State fixed source metadata/compressed/expanded/entry/depth/inspection/time/memory/disk limits or explicitly charge this phase to the existing complete-lane ceilings; reject missing/unverifiable provenance without executing or using audit examples as a substitute. No source URL/digest need be invented before the real OCI metadata is known. The reviewed route must explain how those currently unknown identities will be obtained and approved.

### R2 — Specify an acyclic commitment and review-receipt construction order

**Anchors:** proposal lines24,56,62,72; resolver audit lines103,110–113; stable candidate source lines42–49.

The proposal adopts an approval record binding `applicationBuildSha256`, runtime manifest and an `independentReviewReceiptSha256`, then embeds the approved record/manifest identities in application resources. The inherited candidate also requires `applicationBuildSha256`. The exact hash domains and construction order are undefined. If applicationBuildSha256 hashes the final application containing those commitments, this is a self-containing hash cycle. If independent review hashes the complete approval record which itself embeds that review hash, that is a second cycle. Neither cycle is proven unavoidable—the terms could be defined safely—but the next consumer schema task cannot resolve them by guessing a weaker identity or accepting self-asserted hashes.

**Required correction:** add a small explicit directed construction order and exact domain definitions. For example, authenticate a pre-commitment application code/build-input identity excluding generated approval resources; produce runtime/worker/input/source manifests; produce a resolver approval core without its review envelope; independently review/hash that exact core and inputs; create an approval envelope referencing core+review; embed its digest in the final application; record the final application artifact hash in an external qualification/distribution receipt. Any equivalent acyclic scheme is acceptable if it retains exact runtime/worker/resolver/application binding and defines what the issuer compares. A review receipt must identify the exact reviewed core/tuple, not a final object containing its own hash. Do not silently reinterpret a final artifact digest as a source/version label.

## Scope and execution constraints that pass plan review

- **Explicit amendment, no v1 laundering:** proposal lines20–26 names the committed `eclipse-temurin:21-jdk-jammy@sha256:55fb9bf738f5d9b4a6c01b39337e3070d3e27370dd3c478fd1d5d3cd2233c6d8` only as a candidate family. Child/config/layers, native objects, matching sources and DNS applicability are unacquired and unapproved. OCI toolchain policy is an explicit reviewed amendment; new runtime/input contracts preserve v1 parser/refusal controls. No OCI digest masquerades as a vendor archive.
- **Production traversal/source objects:** lines22,36,54 preserve strict NOFOLLOW and reject output links/aliases/special files. Exact direct regular source-object to fixed destination mapping requires review; SONAME link copying and ambient library/cache resolution remain forbidden. Builder links are a separately reviewed trusted toolchain feature, not runtime source authority.
- **Bounds:** lines26/34 require actual-size review instead of implicitly admitting a >16MiB libjvm. The acquisition caps distinguish metadata, compression, expansion, member/map work and record size. The 8GiB complete-lane disk requirement expressly includes container stores and both builds. These are separate from unchanged runtime ceilings at stable source lines14–21. The numbers do not guarantee the unknown image fits; rejection/recipe review is an accepted outcome. Before acquisition/build, the exact reviewed recipe must demonstrate measured or conservative peak accounting, including compressed blobs, diffID verification, rootfs/imported engine layers, writable layers, sources, both outputs, archives and retained logs. Free-space preflight alone is not enforcement: the inspector/engine/workspaces need a hard bounded reservation/quota or equivalent checked admission throughout; an ambient external Docker store or host fallback cannot satisfy the repository-only policy. This is an execution gate already required by lines34/36, not permission to widen any cap.
- **Closure and determinism:** lines38,44–58 require actual ELF providers/versions/search/loading behavior, pinned jlink/plugins/tools, empty environment and network-off two-build byte equality. Required filenames and synthetic DLOPEN edges cannot replace semantic evidence. Actual loader launch remains a separate isolated gate. Audit OpenJDK/glibc examples establish review obligations only, not candidate binary binding.
- **Resolver authority:** lines60–68 keep exact bytes/ownership grammar separate from policy-owner/deployment permission. No actual operator resolver/network decision exists; it is needed later at gate4. That absence does not require user confirmation during this plan review and does not block inert schema/inspector implementation. No public/documentation/host-stub address should be guessed. The dotless private UTS state, absent ambient config/daemon/library inputs, negative/search and UDP/TCP behavior require actual matching-source and native evidence.
- **Full #1510 outcome:** lines70–82 explicitly require a real nonempty immutable application selector and real factory -> sandbox/boundary -> context -> broker/HTTP -> worker -> cleanup composition. Existing stable factory has no DNS issuer (`AcpHarnessFactory.kt:159–171`, SHA256 `17224f99f0a1518a69846942ec9e845431ee25294d5af35367b0da4c26076557`); HTTP still resolves in the parent (`AcpProviderBroker.kt:978`, SHA256 `b5a564d98daec26d4a398afc882b390caf4228355d11babfab89edffedbfedc2`). Hence candidate parsing or another permanently empty registry cannot count as completion. Existing boundary consumes by exact object/request/deadline (`LinuxBubblewrapBoundary.kt:1677–1694`, SHA256 `5e109d13583a0609a9a723b846847d6a0cd56299ec27be17d5ed4dd5f49861d0`). Plan preserves sole issuer, one-use transfer before backend/secrets, one context/eight dispatches/one unverified ticket, shared deadline, revocation/quarantine and retained late-owner cleanup.
- **Native qualification:** lines78–82 require exact supported package and protected issuer on an observable isolated Actions host. Missing profile, skipped native controls or unreadable namespace membership fail. Reflection, full-host-JDK fixture, ordinary java-version success, synthetic-only receipts and seven inaccessible desktop processes cannot substitute. Separate fixture resolver/network authority permits isolated testing without granting production DNS or real provider/model/Task8 authority.

## Disposition

Revise only R1/R2 and refreeze the plan/proposal pins for another independent review. The next work remains the bounded typed input-lock/static inspector and resolver approval consumer schema, followed by explicitly reviewed/authorized candidate acquisition. The full #1510 acceptance boundary remains appropriate. No current runtime, resolver or usable issuer is approved by this report.


---

# Corrected-plan re-review — terminal OKAY

**Current terminal verdict: OKAY for the corrected plan only.** This supersedes the initial plan verdict for the exact new plan/freeze below. The initial ITERATE analysis above is preserved unchanged; it still describes its original f25abb6f proposal. R1 and R2 are resolved at plan level. No remaining blocking finding was identified in the corrected executable route. This verdict authorizes no acquisition, source change, toolchain/native/JVM execution, resolver/network policy, usable runtime, production issuance, authentication/model call, remote action or release.

## New and preserved identities

Recomputed exact corrected inputs:

- Plan `.omo/plans/provider-dns-task6-real-input-approval.md`: 23,155 bytes, SHA256 `0c72f8dd58f2f45ee3f88e410131821a37f95e5a67d73c464bc5f9b994c803c5`.
- Freeze `build/provider-dns-task6-runtime-planning/proposal-freeze.json`: 1,530 bytes, SHA256 `39b8294355a4b1c1011e2317f91076479ad7246447d5e90f6420757cc0576776`.
- All four current freeze pins match their actual bytes/lengths. Both source audits and the current-scope snapshot are unchanged at the full hashes listed in the initial input table above. The new freeze still declares `sourceAuthority=false`, `acquisitionAuthorized=false`, `nativeExecutionAuthorized=false`, `usableRuntimeApproved=false`.

The preserved historical copies were independently recomputed and remain exact:

- `build/provider-dns-task6-runtime-planning/plan-initial.md`: `f25abb6fd458888db5ced0b7e54891218cdb97fc75f7c6a7b1a6c79a461a3e3d`.
- `build/provider-dns-task6-runtime-planning/proposal-freeze-initial.json`: `c517d4150c34a8cb3188799c9246c44f914b02eabf062ae4a5caf1909d7fb8f9`.
- `build/provider-dns-task6-runtime-planning/initial-independent-review.md`: `7988d031f370627663b0d8abea53a841706269c0ff84c3e65655b80b9671638f`; this owned report's pre-append bytes match that initial review exactly.

## Finding resolution

**R1 resolved — explicit matching-source route, corrected plan lines42–52.** OCI receipt is observation only. Line46 now defines authenticated vendor/OpenJDK/native/distro source and patch discovery, a proposed exact source lock, reviewed trust roots and binary-to-source relationships. Unverifiable mappings reject; image strings and nearby upstream tags cannot supply authority. Line48 explicitly places independent source-lock review before a separate custodian-assigned bounded Actions acquisition, reauthentication and retained matching-source receipt. Toolchain/native/JVM execution and source-semantic approval wait for this gate. Already retained source bytes may avoid redundant fetching only when their authenticated subject/source/patch relationship and independent inspectability satisfy the same obligation. Candidate and source stages share aggregate input/expanded-stream/disk/time ceilings, so later acquisition grants no fresh budget. These steps provide the missing route without inventing unacquired vendor identities.

**R2 resolved — normative acyclic construction, corrected plan lines66,76,88–104.** A is explicitly a closed application-input identity with only schema-declared generated outputs excluded; it cannot be the final self-containing app artifact or use caller-selected exclusions. I contains prior authenticated inputs; M commits A/I and output closure; P commits A/M plus immutable policy semantics; both M/P forbid downstream review/envelope/final hashes. Detached E commits those cores and prior receipts; receipts cite relevant cores, never E. Final F packages A/I/M/P/E and contains no own final hash. External Q commits F and qualification/release evidence and is never embedded into F. Line102 gives the actual review/core/evidence ordering; line104 requires new-version semantics, preserves unsupported v1 meaning, and requires mixed-identity/self-reference/substituted-core/unknown-root controls. Thus neither review-envelope nor final-app self-hashing is needed. Line76 also holds production release/deployment behind external qualification/release evidence.

## Retained implementation and acceptance gates

The unchanged conditions remain necessary; plan approval supplies no missing actual evidence:

- Explicit reviewed OCI source/toolchain amendment and new schema precede use. Production NOFOLLOW and direct regular source-object mapping remain strict. No SONAME link copy, host JDK/library/cache/config fallback or source digest as approval.
- The named Temurin index digest remains a candidate only. Platform child/payload/tools/native/source identities, actual libjvm size, link-free output and ELF/dlopen/NSS/UTS semantics remain unacquired/unproved. The audit's upstream source examples remain mechanism obligations, not binary binding.
- The exact source/inspection/engine recipe must meet the complete-lane 8GiB disk, memory/CPU/PID/time and decoded-work caps, including duplicated container stores, retained sources, two outputs and archives. My initial quota/accounting execution obligation remains: account and enforce actual peak usage under repository-owned stores before/during the authorized lane; reject an incompatible recipe instead of borrowing host storage or raising caps. Unknown candidate fit is a later measured gate, not a promise that maxima fit simultaneously.
- #958 still needs the real operator/deployment resolver/network decision at corrected lines64–72. No such decision is present, no nameserver is selected by this review, and it is not required to ask the user for confirmation during this read-only re-review. Separate authenticated fixture policy permits isolated qualification only.
- Full #1510 completion still requires the nonempty authenticated application selector and actual protected factory/boundary/context/broker/HTTP/worker composition, all exact ownership/deadline/one-use/secret-order constraints and retained cleanup through late owners. Source checkpoints and staged-B/concurrency prerequisites still need their own terminal reviews.
- Exact supported-profile two-build/native/negative-search/UDP-TCP/cancellation/deadline evidence, observable namespace destruction, required hosted checks and resolved independent/automatic reviews remain mandatory. Missing profile, skipped controls, partial desktop visibility, synthetic-only candidate success or reflection cannot replace them. Issues1510/958/238 and broader release claims stay open until their full evidence exists; real provider credentials/model/Task8 remain separately authorized.

The corrected next handoff at line108 is startable: implement the bounded typed inspector/input lock and acyclic approval core/envelope in the dedicated worktree, review the exact source/recipe/amendment, then obtain the specifically assigned candidate receipt and matching-source inputs through their separate gates. No narrower substitute outcome has been accepted.
