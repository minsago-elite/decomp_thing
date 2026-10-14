# GCC source/build ownership: offline input checkpoint (#1513)

This checkpoint parses small pinned metadata, a **proposed/unapproved** profile and caller-supplied action observations. It performs no acquisition, signature/archive verification, build, compiler invocation, runtime/image admission, tracing, source extraction, model acquisition or oracle/candidate comparison. #1513 and #692 remain incomplete.

The normative implementation plan is `.omo/plans/gcc-source-build-ownership-inventory.md`, SHA256 `58f817f0cae0d7c1ea2e41491d2a6eef575011857889c224fc0c2582e071668d`. Production still requires one complete admitted actual capture reproducing the exact rich/stripped pair and two independent complete raw-to-canonical replays. Extra full builds need a concrete remaining-risk justification.

## Inputs and types

`GccSourceBuildOwnershipProfile.load` reads the closed version-1 profile at `oracle/gcc/16.2.0/source-build-ownership-profile-v1.json`. Status is fixed to `proposed-offline-only`; every approval/authority flag is false. All ten source/runtime/collector/exact-pair/closure/ownership/replay/isolation/review gates remain mandatory. Listed operation ceilings are proposed limits from the reviewed plan, not actual host/runtime admission or measured sufficiency. Loading the profile does not approve it or permit an operation.

The profile pins exact historical source-lock, build-record, toolchain-reproduction, Dockerfile and oracle-manifest bytes. `GccSourceBuildOwnershipInputs.observe` consumes only explicitly supplied byte arrays for those five roles, bounds them before copying, checks their exact checked generation and reads the source/reproduction/artifact cross-bindings. It never follows their filenames or adjacent files. Matching metadata hashes is not verification of the locked source archive/signatures, image rootfs/config, live tool bytes or either binary. `sourceAuthenticated`, `runtimeAuthenticated`, `captureAuthenticated` and `ownershipComplete` stay false. Caller-provided replacement pins, even self-consistently rehashed, are rejected.

Historical image ID `sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248` remains distinct from proposed effective reproduction ID `sha256:807f16e03368e1e0ff3c904f21f1a13c260d78a8b7226a52284a2ee68a4d1511`. Neither is treated as an available/pullable image. Future real runtime admission must verify the separately locked recipe/config/ordered rootfs layers and live tools through the reviewed bridge, preserve historical provenance, and reproduce full rich SHA256 `8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b` and stripped SHA256 `3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4`.

## Action receipt-input contract

`GccSourceBuildOwnershipActionReceipt.parseObservation` accepts `schemaVersion:1`, schema `gcc-source-build-ownership-action-observation-v1`, and `evidenceKind:untrusted-offline-observation`. Despite its receipt-input class/schema filename, **the result is not an execution receipt**. No constructor or wire field can supply an authenticated runtime bridge, collector completion or closure proof. Completion state is `not-authenticated`, collector/bridge receipts are null and every authority flag is false. A successful supplied exit code grants no authority.

The exact closed fields bind the proposed profile and metadata-set digests, phase/role, target claim, scoped cwd, configuration claim, optional source claim, tool identity claim, historical/effective runtime claims, byte-preserving argv/environment strings, input/output file claims, ordered raw response bytes and exit-code claim. Response hex length and SHA256 are checked against actual supplied response bytes and a corresponding exact input claim. No response grammar is interpreted; this checkpoint does not claim the compiler consumed those bytes or that an `@` spelling reached a tool. Actual command expansion, producer/input ownership and source/frontend semantics remain later gates.

Paths are canonical relative identities under explicit source/generated/build/toolchain/external namespaces; traversal, empty components, backslashes, control characters and absolute paths are rejected. Input/output paths must be unique within an observation. Multiple consumed versions at one path require a future versioned relation and cannot be collapsed silently here. Unknown fields/kinds/roles, missing fields, duplicate JSON keys, invalid UTF-8, NUL strings, environment names outside the public build allowlist, bad hex/digests and bounds failures refuse without returning a partial observation. Diagnostics do not echo supplied source/argv/environment values.

The closed public build environment allowlist is `PATH`, `LANG`, `LC_ALL`, `TZ`, `SOURCE_DATE_EPOCH`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS` and `LDFLAGS`. All other names refuse before canonical observation bytes or candidate identities are retained; no credential-name blacklist or wildcard is used. Adding another public build variable requires an explicit reviewed contract amendment. Values remain untrusted supplied build configuration, not proof of safe contents, capture or execution. The original frozen checkpoint remains historical evidence; this correction does not authorize a real build.

Two domain-separated candidate digests commit the complete canonical observation: `actionCandidateId` for any action and `compileIdentityCandidateId` only for a `source-compile` role with its exact source input claim. These are **descriptor candidates**, not final action execution identities, TU owner units, equality/alias proofs, ODR identities, physical-CU joins or denominator rows. Command/environment/configuration/target/source/object/runtime differences remain visible; object key order does not affect canonical bytes. Generator compilation has no source-TU owner candidate. A source-only record cannot be smuggled in as an action owner role. These descriptors preserve uncertainty; a future authenticated producer must independently prove stable TU/build/role/variant/linked-object identities from real evidence.

## Bounds and schema integration

Caller-lowerable observation bounds cap one record at 8 MiB/100,000 JSON nodes, 16,384 argv words, 4,096 environment entries, 4,096 input claims and separately 4,096 output claims, and 256 response records. UTF-8 byte guards, canonical output guards and collection limits apply before a result escapes. The profile caps metadata at 128 KiB each/256 KiB aggregate and profile bytes at 64 KiB. These finite parsing limits do not qualify operation CPU/RSS, aggregate multi-shard processing or runtime containment.

The two additive schemas are registered with exact schema-byte hashes in the shared Kotlin catalog/inventory. Registration establishes executable shape validation only; it does not register a production adapter, authorize capture, approve a profile or attest an observation. Existing historical formats/pins remain unchanged. These offline v1 types cannot be promoted by setting a flag true; a future actual authority-bearing API/contract must receive independent review and the complete qualified source/runtime/collector/replay/isolation evidence.

## Required production handoff

### Supplied reproduction-description comparison

`GccSourceBuildReproductionEvidenceV1.compare` binds the same five exact metadata
snapshots to a bounded caller-supplied six-field inspect projection (`Id`,
`Created`, `Architecture`, `Os`, `Config`, `RootFS`). `RootFS` has exactly `Type`
and ordered `Layers`; full Docker inspect documents are not silently projected.
The API performs no Docker, filesystem, acquisition or process operation.
Malformed/extra/duplicate keys and bounds refuse; well-formed image/platform/
creation/Config/layer drift returns explicit mismatch labels, never approval.
Config is an opaque bounded JSON object. Its digest uses the historical compact,
sorted, ASCII-escaped Python encoding rather than the pretty oracle artifact
format; unsupported fractional/exponent Config scalars refuse. Limits are
caller-lowerable at 128 KiB/10,000 nodes/depth32, including bounded canonical
expansion. Returned lists and Config bytes are immutable snapshots, with no
serialized result format or new schema/issuer.

Every source/runtime/capture/ownership/approval flag remains false even for a
matching description. An authenticated live runtime bridge, signed source,
exact pair, collector closure and independent ownership/isolation evidence are
still missing. No actual approved `807f` Config preimage is retained in this
checkpoint: tests use authored Config bytes, preserve the real lock and require
the resulting `config-digest` mismatch. Independent compact-encoding vectors
are contract controls, not a full approved-description positive or live image
qualification. The historical five metadata commitments remain unchanged.

All original requirements remain: authenticated signed source; actual approved runtime and reproduction bridge; qualified lossless process/file-version collector; complete compile/source/generated/header/response/object/archive/link inventory and dispositions; exact pinned-pair reproduction; independently replayed object-to-linked-DWARF/CU/declaration/use ownership; positive source-only/generated/external/split/LTO accounting; distinct nominal/ODR authority; immutable independently verified ownership handoff before #692 scoring; hard operation/aggregate bounds and complete CI/independent review.

Original source, build/debug objects and nominal truth remain trusted-oracle only. This checkpoint adds no route to recovery/ACP prompts/workspaces, candidate compilers, AST probes or runtime callers. Hidden-source canary, macro/include/probe, descriptor/mount/transport leakage controls still need real isolation qualification. Oracle construction/verification may precede model existence; comparisons against recovered facts and scoring wait for a separately frozen model. No population, semantic identity, model binding, seal, score, production verification or release eligibility is supplied by this checkpoint.

## Verification scope

Focused authored tests exercise exact pinned metadata observation, attempted hash/approval/receipt forgery, source/action binding, variant distinction, response bytes, path/unknown/duplicate/UTF-8 refusal, immutable snapshots and exact/one-over parsing limits. The existing schema inventory test checks all schema files/catalog identities. These tests do not execute or reproduce GCC, authenticate source signatures or qualify a collector, hidden-source isolation, full population or recovered model. Direct cached Kotlin/JUnit checks, if used locally, are explicitly separate from a later exact-head Gradle/Actions gate.

The local source checkpoint executed **26 JUnit-annotated assertion methods: 16 new offline methods and 10 existing schema catalog/inventory methods**, with zero failures or skipped methods. A narrow reflection runner invoked the actual test assertions using freshly compiled changed classes before hashed copied cached dependencies. This was Kotlin 2.4.0 compilation and direct assertion execution, not a JUnit engine, complete Gradle build or Actions qualification. Exact dependency/source/command/class/log hashes and the preserved earlier failed schema run are under ignored `build/gcc-source-build-ownership-checks/`; independent source review remains required. Long response hex and deep scoped path controls avoid recursively repeated schema regexes while typed validators retain exact hex/digest/canonical-path checks.
