# Structural call population v1

This component implements the representability and conservation prerequisite in
[#1726](https://github.com/minsago-elite/decomp_thing/issues/1726). It accepts a
closed diagnostic ledger and derives deterministic zero-credit partitions. It
does not authenticate call sources, enable the production `CALLS` domain, or
establish the #681/#691 accuracy gate. The original internal, external and
indirect populations and the 90% requirement remain unchanged.

## Selected mapping

`StructuralSelectedBoundaryProjectionV1.project(VerifiedStructuralInputsV1)`
consumes the actual opaque selected-boundary admission. It copies and validates
the exact selected report and model commitments. Its immutable maps retain every
scored oracle/recovered function, including false negatives and false positives,
even when the function has no calls. Exact and near correspondences come from
that report; names do not rematch identities. Original exclusion evidence is
retained separately. Only one captured twin is available.

The projection's `productionVerified` property describes **selected mapping
provenance only**. It grants no call evidence authority. Internal observation and
report parsers are fixture/review helpers and always return an unverified
projection. The constructor checks the live capability, including when invoked
through the JVM synthetic constructor bridge; serialized flags cannot substitute
for it.

A future native adapter must freeze the native stream and its paired model,
then obtain this mapping by replaying boundaries from that exact model. It cannot
reuse the admission from a separate full export.

## Closed input and original observations

The input schema is
`src/main/resources/project/structural-call-population-input-v1.schema.json`.
The implementation additionally enforces cross-record conservation, identity,
coordinate and aggregate limits that JSON Schema cannot express. Input must use
the existing `OracleJson` canonical encoding. Unknown fields fail closed.

`binding` retains the input, exact model, selected observation and optional
external namespace SHA-256 commitments. Each `sources` row declares its role,
artifact hash, byte count, normalization-policy hash and complete raw record-ID
census. A raw reference is the pair `(sourceId, recordId)`. Every declared record
must occur exactly once in a normalized site or an explicit owner exclusion.
Multiple raw references in a single site explicitly record deduplication; two
sites at the same alignable physical anchor are rejected. Source declarations
are commitments, not proof that bytes were read or that the census is complete.

Each side retains normalized sites with:

- An optional selected caller identity, original typed owner coordinate and
  separate optional instruction and return coordinates. A resolved caller must
  match the retained owner's selected start. `image` coordinates are image RVAs;
  other address-space identities remain uninterpreted.
- A category (`internal`, `external`, `indirect`, or `unknown`) and evidence state.
  Oracle states are `observable`/`oracle-unobservable`; recovered states are
  `recovered`/`recovered-unknown`. Unknown or unobservable target values are null.
- A canonical proven target set, when present. Function targets belong to that
  side's complete selected universe. External tokens require an explicit shared
  namespace commitment; names alone are not accepted as identity. Indirect sets
  require a nonempty set, not an inferred target or guessed singleton.
- Original source references for all fields, including off-canonical targets
  whose typed semantic value remains unavailable. Unavailable semantic values
  must not remove the raw observation.

An exclusion is legal only for the exact owner present in the selected boundary
exclusion/ignored-recovery partition. Missing oracle membership, an unresolved
target, a PLT address, or a synthetic external address cannot justify exclusion.
Unowned or off-canonical callers instead have a null selected identity and retain
their raw owner and source references. Missing oracle regions with an unknown
number of sites are explicit `coverageGaps`; they do not invent a guessed count
of calls or a complete denominator.

## Coordinate reconciliation and outcomes

The caller correspondence and physical image coordinate form the anchor. A
call instruction and return PC are distinct coordinate kinds. Only independent
oracle rows that explicitly contain both can reconcile the kinds; the pairs
must be one-to-one. No instruction width is assumed. Recovery cannot add a pair
to oracle evidence. Conflicting pairs, non-image coordinates, and coordinates
outside executable image ranges stay unaligned. Pre-entry sites retain their
original image coordinate without unsigned subtraction or wraparound. This
algebra does not prove instruction decoding or function ownership; authenticated
source producers must establish those facts before any production admission.

Every oracle site has one row. Missing recovery is `recovered-unknown`;
`oracle-unobservable` has zero credit even when recovery claims a value. Matching
physical sites compare category and mapped target sets; unequal values are
`contradicted`, equal values are `exact`. The shared six outcome counters retain
`abi-equivalent` (always zero for this call contract) and `fabricated`.

Positive-only evidence cannot justify `fabricated`. Every unmatched recovered
site remains in `unresolvedRecovered` with a reason and zero credit, and remains
in the recovered denominator. No oracle placeholder is manufactured for it.
The internal `deriveFixtureWithNegativeSites` test seam accepts explicitly scoped
authored negative controls, labels their report as fixture-only, and never
authenticates negative coverage. Public derivation has no negative-coverage input;
public report validation rejects fixture-negative reports.

## Derived report and limits

`StructuralCallPopulationV1.derive` returns canonical report bytes containing
the complete input populations and source commitments, normalized outcome rows,
unresolved recovery rows, exclusions, coverage gaps, all six outcome counters,
raw census reconciliation and full selected function counts. Report binding
includes the exact input document hash. `validateReport` recomputes the full
report and requires byte equality; a self-consistently edited report is rejected.

Aggregate and per-category metrics count every normalized oracle/recovered site
on its respective side, including unknown, unobservable, unowned and unlocated
records. Only `exact` rows receive credit. `claimPrecision` is the conservative
credited-claims ratio, not a resolved truth precision estimate when evidence is
incomplete. `oracleRecall` is the credited fraction of recorded oracle obligations;
coverage gaps prevent interpreting it as recall over a complete source program.
Ratios are exact integer numerator/denominator pairs; a zero denominator is null.
Exclusions and explicit deduplication are retained and separately reconcilable.

Hard ceilings are 32 MiB input, 64 MiB report, 256 sources, 100,000 raw records,
100,000 combined normalized sites, 16 targets per site, JSON depth 16 and one
million JSON nodes. Callers can lower these bounds. A declared source artifact
size is bounded to 1 GiB; no source artifact is loaded by this component.

All reports set `productionVerified`, `scored`, `complete`, `releaseEligible`,
and `negativeCoverageAuthenticated` to false. `otherTwinAvailable` is false.
Changing those fields is not an admission mechanism.

## Remaining production obligations

The production owner must replay and authenticate each frozen raw source, prove
its census and normalization policy, bind it to the same selected model, and
independently reproduce this ledger. Positive-only machine witnesses must remain
distinct from independently authenticated negative coverage; validating a JSON
boolean or this component's output cannot mint that authority. A future negative
capability needs a source-bound closed scope and independent replay, not the
fixture seam.

The independent producer owns ELF decoding, instruction ownership and positive
evidence. External relocation/version identity composition and any physical to
semantic thunk relation remain independently proven obligations. Existing #904
through #908 retain coordinate/internal mapping, external namespace, indirect
and thunk semantics, full-population scoring and qualification ownership. None
of those issues, #681, or #691 is completed by this diagnostic foundation.
