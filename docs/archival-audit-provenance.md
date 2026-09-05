# Archival audit: source provenance and unresolved implementations

The A5 audit consumes a schema-3 source manifest and its explicitly selected
reconstruction profile. Program-model and module-plan paths come from that
profile, not fixed source suffixes. The archive packager passes the same profile
into the audit that it uses for payload validation.

Every declared file is read through the existing bounded descriptor-backed stable
file reader and compared with its manifest SHA-256. The profile's file, count and
aggregate payload limits apply. The manifest, model and plan are parsed with
duplicate-object-key rejection; metadata is strict UTF-8. The model input identity
must equal the manifest input. Before audit publication, the manifest and all
declared file hashes are rechecked. Missing, changed, indirect or cross-paired
inputs fail without overwriting a previously published audit.

Module identities, source/header paths, function/global/type populations and
dependency cycles are checked structurally. Source paths and roles must agree
with the profile and manifest; implementation ownership is unique. A mention of
an entity ID in free-text boundary evidence or an unrelated source comment cannot
replace an exact ownership reference. Declared source/interface roles determine
provenance rather than a recursive `.c`/`.h` scan. This authenticates declared
candidate ownership, not the semantic correctness of a function body.

The unresolved population is the union of model recovery failures, manifest
unresolved entities, manifest unresolved implementations, entities belonging to
unaccepted implementation files, and missing model/source provenance. Therefore
a fully recovered model cannot hide evidence-only or rejected code, even if its
manifest's explicit unresolved-implementation list is empty. Conversely, an
accepted flag cannot erase an explicit unresolved fact. Unknown entity references
are rejected. Audit JSON escapes all emitted identifiers.

This remains a cooperative filesystem observation, not an exclusive writer lease,
independent source attestation, oracle certification or proof of equivalence.
Archive build validation and agent execution-evidence verification remain separate
requirements. No recovery/confidence value becomes a measured behavioral score.

## Verification scope and remaining behavior work

The focused audit, archive, reconstruction and profile selection passes 30 tests
without failures or skips. Ten new regressions cover evidence-only and accepted
implementations, explicit unresolved facts, globals/types, substring false credit,
stale/missing/indirect files, rehashed cross-pairs, duplicate plan fields, alternate
declared source suffixes and JSON escaping. Deterministic cross-root archive and
clean rebuild tests continue to pass.
The `4389da3` commit message mistakenly counts 31 focused passes; its retained XML
contains 30. The separate wider selection below includes one additional passing
scale-integration case and two unavailable-sandbox failures.

A wider local run executes 33 tests with 31 passes and two failures because
`/usr/bin/bwrap` is unavailable. Those two existing scale-integration tests stop
at behavioral execution; their runtime/audit assertions are not claimed verified.

This checkpoint addresses the source/implementation-accounting slice of #37.
The existing behavior-report loader still needs #36's closed, execution- and
revision-bound record before it can attribute results to these module hashes.
Malformed/stale/foreign behavior handling and evidence-scoped isolation claims
remain incomplete. This change does not close #36, #37 or the A5 milestone.
