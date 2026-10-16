# Issue #1506 correction source review — GPT-6.1 Sol

Verdict: **CLEAR** for the exact source correction freeze below. No unresolved source finding remains from F1/F2 or the corrected COPY association. This is an independent source/evidence review, not issue closure, hosted qualification, an authenticated model trial, or a behavioral/ABI result.

Reviewed the live [#1506](https://github.com/minsago-elite/decomp_thing/issues/1506), [PR #1509](https://github.com/minsago-elite/decomp_thing/pull/1509), the referenced-byte plan, prior independent contract findings, hosted failure diagnosis and original same-fixture reproduction. Both issue and PR remain OPEN. The live acceptance criteria govern; the plan's older LOAD/STORE-only proposal does not describe the subsequently diagnosed direct-memory COPY operation. The corrected closed contract adds explicit direct-read/direct-write origins rather than inferring types or object extents.

Only this report was written. No source, Git/GitHub, CI, provider/authentication, model or candidate execution or mutation occurred; no descendants were spawned. Verification used retained source, logs, reports and digests. The actual corrected same-stripped-input replay is independently owned and is not counted as execution by this review.

## Immutable bindings and retained verification

| Artifact | SHA256 |
| --- | --- |
| 23-path source-freeze-013.json | `a5b5bfd54cc7b4c403899e37b509565a35205c206e343cd150b546d60fef0532` |
| verification-receipt-013.json | `673be25da2701a5102e39e07abcd403e7bdb849cf239a5b703c208f5248b0b3f` |
| review-handoff-013.md | `fb2e195e7ae5eeaec5ca302343c7a6370a8f8bb8be03814c06f2108b1417f77b` |
| Final exporter source | `4546507e7d20a6eb1ac766edcfc7d8041b4f2a294e35232902f8bda1e667512b` |
| Earlier independent contract findings | `0978dff93bae3a2aa4d35959db2e3f238c53a5a3575b662e932674b010487cfb` |

Base: `87050ae41a246547a4364c7971ba9e07de380408`. I independently rehashed every one of the 23 present/deleted source states and all 39 bound evidence files, before and after inspection. All match. The source freeze binds corrections to that base; the relocated old implementation receipt remains historical evidence rather than current source authority.

Independently summed the bound JUnit XML: focused-007 has 103 tests, zero failures/errors and five opt-in skips; profile-009 has 19 tests, zero failures/errors/skips; controlled-listing-012 has one test, zero failures/errors/skips. Their successful logs include the existing neutrality task. The final controlled-listing process log confirms the real ProgramDB assertion; the earlier controlled-listing-010/011 failures remain retained and are not counted as passes. No full suite or fresh hosted pass is inferred from these local subsets.

## Prior findings and exporter correction

**F1 — resolved.** `ReferencedByteEvidenceAdmission.kt:27` performs path-aware lexical admission before each input chunk is returned to Jackson. Both byte-stream and Reader generic paths are wrapped (`CheckpointedProgramModelJson.kt:46,65`); `ProgramModelJson.read(String)` now avoids making an entire extra UTF-8 copy and preserves its historical BOM behavior. Window 33, segment 257, model window 4097 and requested byte 65537 are refused before descending into their forbidden payload. Closed evidence keys, scalar/string and number caps bound token payloads. Counters persist across chunks and globals, including BOM handling. Typed evidence validation/budget charging at the first completed evidence object (`CheckpointedProgramModelJson.kt:113`) prevents retaining later globals after a malformed record. Existing generic document/token/depth constraints and cancellation checkpoints remain.

The input wrapper can read one bounded 64 KiB byte/character chunk from an already supplied input before refusal; that chunk is scanned before Jackson receives it. This is bounded read-ahead, not a claim that caller-supplied input storage is eliminated. The negative controls deliberately append malformed million-character payloads and assert the early named bound on both generic readers; exact aggregate boundaries and byte/text BOM paths also pass.

**F2 — resolved.** `GeneratedCModulePrompt.kt:46` first admits decoded bytes and the entire module's rendered evidence size, including fixed prefixes, before creating any per-global rendered evidence string. `ReferencedDataByteEvidence.kt:97,110` counts and renders through the same incremental writer. All emitted dynamic values are validated ASCII addresses, integers, closed enums or hex, so character count is exact UTF-8 byte count. Arithmetic is checked. Only bounded per-segment chunks are created during counting; neither the complete global string nor its additional UTF-8 byte array is constructed first. Rendering begins only after every module global passes. Exact-length/one-byte-less counting and the formerly over-budget valid segmented global are covered, alongside the exact decoded-byte boundary and historical absence.

**Actual direct-memory COPY gap — resolved in source.** `ExportProgramModel.java:909,915` matches a real memory varnode to the exact referenced address/address space and derives width from its size. COPY inputs and outputs receive distinct direct-read/direct-write origin labels. LOAD/STORE retain the exact constant-space/pointer rule. Dynamic pointers, conflicting/multiple associations, unsupported operations touching the reference, or inconsistent COPY sizes remain unknown. No width is guessed from listing text, declared symbol size, register width or neighboring addresses.

The bounded prepass (`ExportProgramModel.java:981`) still charges reference occurrences and windows before deduplication or memory reads, applies checked aggregate requested-byte accounting, rejects excessive requests explicitly, checks cancellation and reads actual initialized/readable memory without zero fill. Unsupported address-space aliases refuse. Shared-global controls retain distinct origins, widths and interior references; reversed traversal leaves canonical output unchanged, while existing string reuse does not mint global byte windows.

## Compatibility, migration and evidence scope

The typed evidence contract remains closed: exact canonical address/span/origin/hex/length, known versus unknown width, complete ordered segment coverage, explicit missing reasons and omission iff unknown; listing initializer text remains separate. The new width labels are accepted by the common validator used by generic/streaming models, capture, resume and canonical serialization. Exact rendered records continue entering existing authenticated fingerprints and commitments; mixed generations and stale state remain refused by the inspected capture/resume paths. This correction does not change those authentication boundaries or select an external Ghidra installation.

The active exporter-12 source digest, nested compiler-engine profile digest, full structural profile digest and fixed production pins match atomically. Historical exporter-11 profile files remain byte-identical to the base. `SourceTree.kt:1126` now permits schema 3 in the otherwise unchanged checkpoint identity requirements; the regression retains identity and resumes without reconstructor redispatch. Hosted profile/call-site schema expectations were corrected to active schema 3, with determinism and input binding checks retained. The old benchmark receipt was moved byte-identically into `oracle/gcc`; the neutrality policy itself was not weakened.

The real ProgramDB control explicitly creates one-byte Undefined1 listing data with exact `00h` initializer, uses an actual SLEIGH-decoded eight-byte memory read and real memory/reference APIs, then proves the exporter preserves both initializer and full eight-byte evidence without rewriting listing data. It is an authored controlled listing, not a claim that unmodified stripped analysis naturally produces one-byte listing data. The original stripped fixture's assembly literal is unchanged (SHA256 `35899c307260972734262c3e769a1015ea55266c49b40b4e1b41559fbbdd3fe0`), and exact address/eight-byte/hex expectations remain; only the truthful direct-read origin expectation and explanatory symbol-size wording changed.

## Live acceptance and remaining gates

1. The closed byte-evidence contract is reviewed and supported by source/negative controls; it supplies recovered input only, with initializer and semantic authority kept separate.
2. Bundled Ghidra Java APIs export bounded actual memory evidence, including the newly supported direct COPY width, explicit unknown/missing states and named bound refusal. No private oracle/source dependency or production GHIDRA_HOME/analyzeHeadless requirement was introduced.
3. Propagation and schema/exporter compatibility are supported by the inspected model/stream/capture/fingerprint/resume/prompt source and focused tests. Historical generations remain separately identified, and schema-3 module checkpoints now resume.
4. Deterministic memory/bound/mutation controls and the controlled real one-byte-listing fixture are supported. The independently assigned corrected unmodified stripped-input replay is a separate qualification artifact; it is not substituted by the ProgramDB control or pooled into these test counts. Full capture/resume/prompt integration and hosted qualification remain coordinator gates.
5. Relevant Actions, automatic review resolution and merge remain pending; this source CLEAR does not satisfy that final acceptance criterion. The earlier authenticated SANDBOX_LAUNCH failure's narrower cause remains unproven by these source changes, and no auth rerun is claimed.

Keep #1506 OPEN until its complete source, independent replay, relevant hosted verification and automatic review evidence satisfy the live criteria. A later ACP measurement needs a new frozen experiment and separate authorization, preserving #1504 unchanged. Oracle, ABI, scoring and release authority remain false; A13 #909/#912 and production transport qualification are not supplied by this work.
