# Oracle and ACP trust boundary

The target production architecture has two deliberately separate execution boundaries:

1. Kotlin/JVM code generates, validates, reconciles, scores, and publishes authenticated oracle evidence.
2. ACP v1 agents consume selected evidence and edit candidate reconstruction workspaces under bounded authority.

An ACP agent is never an oracle authority. Agent output is a candidate until deterministic host validation accepts it.
The Kotlin oracle migration tracked by issue #136 is not complete, so the repository's remaining Python oracle
entrypoints are migration/compatibility implementations and cannot authorize a new Kotlin-only release.

## Authoritative data flow

```text
rich reference binary + authenticated source/build records
                         |
                         v
              deterministic Kotlin oracle
          generate -> reconcile -> validate -> publish
                         |
                         | immutable, authenticated evidence
                         v
               ACP reconstruction/repair turn
                         |
                         | candidate workspace changes + ACP evidence
                         v
              deterministic Kotlin validation
                  build -> replay -> score
                         |
                         v
                 accepted revision or rollback
```

Oracle truth, exclusions, source locks, artifact manifests, shard indexes, scores, and release manifests are never
writable ACP inputs. A workflow may expose the minimum required subset as read-only context. The host independently
checks every digest and binding before using it and again before accepting a candidate.

## First-class ACP contract

ACP is the default production transport for every model-driven reconstruction and repair operation. An omitted harness
selection means ACP. Missing, malformed, unauthenticated, or unsupported ACP provisioning fails before a model-driven
operation starts. Unknown harness names never fall back to another transport.

The legacy OpenAI-compatible HTTP adapter is a deprecated compatibility mode. It requires an explicit
`legacy-openai` selection, must pass the same workflow acceptance contract, and cannot claim ACP provenance. Evidence-
only reconstruction is agent-free and is not a harness fallback.

One trusted factory owns harness selection and construction for CLI, web, reconstruction, repair, and patch workflows.
Provisioning uses structured ordered arguments, explicit environment provenance, authenticated executable/runtime
manifests, stable ACP v1 capability requirements, bounded lifecycle/resource settings, and the verified Linux
bubblewrap/cgroup boundary. Provider credentials belong to the ACP agent's own configuration and are not inherited by
the engine process boundary.

Accepted model-driven artifacts bind at least:

- ACP protocol and SDK versions, agent implementation identity, and negotiated capabilities;
- session and turn references, stop reason, bounded events, usage, and truncation state;
- exact authorized changes and their before/after hashes;
- filesystem, terminal, permission, and sandbox decisions and cleanup evidence; and
- deterministic build, behavior, structural-score, acceptance, or rollback results.

## Kotlin oracle contract

A release that claims Kotlin oracle authority must not import, launch, or require Python. JSON remains the versioned
interchange format, while canonical bytes, schema validation, sharding, hashing, atomic publication, and release
decisions move to Kotlin/JVM. Large evidence is processed with bounded streaming and authenticated scratch storage
rather than complete in-memory materialization.

That migration is currently partial. Source and release acquisition, LLVM artifact-manifest/ELF-twin verification,
scope and inventory controls, full-tree data truth/reconciliation/baselines, bounded completed-run verification, and
GCC planning have Kotlin/JVM paths. A bounded raw-artifact Kotlin generator and its narrow Gradle/CLI entry point now
regenerate the checked LLVM function-recovery v1 bytes exactly in the required workflow. Call truth, production
structural adapter replay, some ELF/DWARF observation generation, and full-tree release orchestration still have Python
entrypoints. Those entrypoints may preserve historical production evidence and differential parity, but they do not
satisfy the Kotlin-only authority requirement for the next release.

The required LLVM push/pull-request lane runs full-tree scope verification, DWARF and source-inventory regeneration,
and function-oracle regeneration through stable Kotlin/JVM Gradle entrypoints. The similarly named Python wrappers are
retained only for legacy migration compatibility and are not invoked as production generators by that lane. They
cannot authorize or enter a Kotlin-only release.
That lane and the manual clean-rebuild workflow authenticate the LLVM source lock, local OpenPGP key/tag evidence,
detached archive signature, strict TAR/XZ profile, and locked source markers through one descriptor-bound Kotlin/JVM
materializer. They also fetch the hash-locked LLVM release artifacts through bounded Kotlin/JVM HTTPS and
descriptor-bound no-replace publication. The Python source and release-asset materializers are retained only for
legacy compatibility. The required LLVM lane also authenticates the stable toolchain recipe, Dockerfile, historical
build-record binding, and fresh linux/amd64 image identity through Kotlin/JVM; the fresh image digest is deliberately
not equated with the historical artifact-producing image digest. Both required LLVM lanes now verify the exact
manifest, source/local evidence, build-record semantics, full and stripped ELF bytes, and derived equivalence through
the fixed no-argument Kotlin/JVM `verifyLlvmOracleArtifacts` gate. Descriptor and terminal checks detect every
substitution or mutation visible at their checkpoints, but do not claim exclusion of a cooperating same-UID/root
writer that transiently mutates and perfectly restores bytes. Other Python workflow gates remain in place until live
behavior execution and release-stage semantics have complete Kotlin replacements; both required LLVM workflows now
run the descriptor-pinned Kotlin/JVM build-record verifier inside the authenticated rebuild image, and the clean
rebuild no longer invokes the Python tool recorder. Remaining Python compatibility regressions stay explicitly
non-authoritative; keeping those regression checks does not promote their outputs to new release authority. Retained Python LLVM
manifest/function generators are explicitly differential migration compatibility and cannot certify a release.

The full-tree build-planning boundary also has a Kotlin-owned isolated Ninja
compilation-database query. ACP remains the first-class candidate
producer/operator, while a dedicated bubblewrap/cgroup purpose authenticates the
recorded Ninja executable, exact loader profile, read-only manifest
materialization, fixed direct invocation, byte-exact stdout, separate bounded
stderr, cleanup, and terminal absence. Its persisted receipt is non-bearer audit
evidence and authenticates neither build-graph origin nor compiler execution;
all eight downstream blockers remain active. No Python implementation, shell,
caller command, mount, staging root, or callback participates in that reference
query authority.

During migration, existing Python outputs may be retained as explicitly non-authoritative differential fixtures. They
cannot enter a new release as truth or validation evidence. A stage becomes authoritative only after frozen-fixture
parity, fail-closed mutation coverage, worker-count determinism, repeated byte-identical output, and a Kotlin-only
production run all pass.

Full-tree function-truth v2 now also has an internal Kotlin/SQLite reconciliation slice. It re-derives the ELF index
and every DWARF observation shard from pinned raw artifacts, accepts only the exact generic four-member bounded-run
tree, stores RVAs as unsigned fixed-width SQLite keys, rejects identity-prefix collisions and the historical
coalesced-DWARF-only producer/validator contradiction, and publishes deterministic no-replace bytes. It neither
imports nor invokes Python, and ACP supplies no callback, fact, policy, validation, or publication decision. This is
still migration evidence rather than release authority: its typed receipt fixes `authoritativeReleaseEvidence=false`,
it assumes cooperation from the owning Unix principal, and it lacks the aggregate ext4 lease/all-shard lifecycle in
issue #138. Historical roots with unauthenticated `control/`, `usage/`, or `execution-evidence.json` members fail
closed. The stable v2 disk schema predates authority metadata and still contains `complete=true`; canonical-path
presence is therefore never a bearer capability, and an ACP consumer must not infer authority from those bytes.
The companion Kotlin validator treats an existing truth tree only as read-only candidate bytes. Its expected shard
membership, bindings, counts, hashes, and complete projection come from a fresh raw ELF/DWARF reconciliation inside
bounded private scratch; the candidate index contributes no expected fact. Kotlin exact-compares the closed tree,
rejects missing, extra, aliased, noncanonical, or self-consistently forged members, reauthenticates the raw inputs and
candidate at the terminal boundary, deletes only its private derived projection, and returns another explicitly
non-authoritative receipt. That receipt is a detached point-in-time comparison: it retains no candidate lease and
cannot authorize later scoring. Validation failure never repairs, quarantines, renames, or republishes the candidate.
The Kotlin function-baseline v1 path does not reuse that detached receipt and then reopen the candidate. Instead,
function truth holds the candidate/raw-input guards, exact-compares the candidate with its private raw-rederived
projection, and passes only that private projection into a fixed SQLite baseline composition. Kotlin derives every
per-shard denominator, stripped-symbol survival decision, exclusion, and persistent mismatch identity there; it
strict-canonical-validates the staged report against an explicit truth-index artifact digest and terminally rechecks
the raw inputs, derived projection, candidate, and exact report bytes before and after the no-replace move. The
callable producer accepts raw inputs rather than a caller-constructed projection; the lower projection publisher is
private. Malformed aggregate equations, duplicate shards/mismatches, uncovered or wrongly assigned missing and
fabricated counts, truth-population or persistent-mismatch drift, denominator or exclusion drift, shard disappearance,
and recovered/fabricated regressions fail closed. The resulting receipt still retains no candidate lease and grants
neither downstream scoring nor release authority. SQLite scratch has a hard page ceiling and no transient rollback
journal, and generation checkpoints the raw-derived tree, database, and staged report. Those checkpoints are not an
aggregate descriptor lease across the full lifecycle; issue #138 remains the explicit blocker rather than an
authority claim by this migration slice.

For A15 candidate behavior, Kotlin now has a descriptor-bound
[pre-START admission](llvm-candidate-execution-prestart.md) which authenticates an opaque candidate and the exact
input-only command, corpus, runtime-policy, and budget commitments, publishes a mode-0400 non-release receipt, and
refuses to launch. Runtime identity and containment remain explicitly unobserved, and exit, timeout, resource, stream,
and artifact outcomes remain null. The existing caller-observation comparison is still non-authoritative; neither
checkpoint substitutes for the pending authenticated generic runner or grants ACP oracle/scoring authority.

## Release invariant

A release fails closed if either boundary is ambiguous: missing Kotlin oracle provenance, writable oracle inputs,
unverified shard/digest bindings, missing ACP provenance for agent-generated content, an implicit legacy transport,
unaccounted workspace changes, incomplete cleanup evidence, or validation/score mismatch. Agent completion by itself is
never acceptance evidence.

The live work and acceptance criteria are tracked in GitHub issues
[#72](https://github.com/minsago-elite/decomp_thing/issues/72) and
[#136](https://github.com/minsago-elite/decomp_thing/issues/136).
