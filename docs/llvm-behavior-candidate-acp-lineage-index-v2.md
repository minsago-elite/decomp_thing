# LLVM behavior candidate ACP lineage index v2

`candidate-acp-lineage-index-v2.json` is the Kotlin/JVM-owned semantic commitment to every
accepted ACP contribution in one reconstructed candidate archive. It makes ACP a required,
first-class candidate producer/operator without giving ACP any oracle, reference-authoring,
policy, validation, observation, START, containment, terminal-absence, scoring, certification, or
release authority.

At this checkpoint, `candidateContribution=authenticated-session-change-provenance`. The broader
build/artifact contribution is named only by the later admission record after those independent
hosted facts have actually been verified and cross-bound.

The production publisher accepts exactly two raw `Path` values:

1. the reconstruction archive; and
2. a dedicated `0700` output directory's `candidate-acp-lineage-index-v2.json` path.

It accepts no parsed document, claimed digest, callback, project directory, local build record,
hosted receipt, executable, reference input, or oracle value. The verifier independently accepts
only the raw archive and raw index paths.

The Kotlin CLI is exposed through Gradle:

```sh
mkdir -m 700 /absolute/path/to/lineage-output
./gradlew generateLlvmBehaviorCandidateAcpLineageIndexV2 \
  -PcandidateArchive=/absolute/path/to/candidate.zip \
  -PcandidateLineageIndex=/absolute/path/to/lineage-output/candidate-acp-lineage-index-v2.json
```

## Archive authentication

Kotlin descriptor-pins the single-link archive, streams that inode into a private read-only
snapshot, and sends the snapshot through `ArchivalBundleVerifier` with the fixed generated-C
reconstruction profile. That gate verifies the stored ZIP layout and hash manifest, source-tree
manifest, reconstruction checkpoints, all ACP schema-v2 receipts, accepted repair graph and
history, and exact workflow changes. The recomputed build-source revision is also compared with
the identities from the authenticated archive payload.

The complete stored ZIP is bounded at 1.5 GiB. This accommodates the archive verifier's 1 GiB
payload ceiling plus the repeated path/header overhead of a maximum-size 128 MiB hash manifest,
while bounding the descriptor-pinned snapshot before extraction.

`reports/build_contract.json` remains an internal archive-consistency check inherited from the
archive verifier. It is not projected as hosted-build provenance and cannot establish the identity
of an executable, compiler, linker, runtime, runner, or hosted workflow.

## Constant-size lineage commitment

Detailed receipts remain inside the archive. The index therefore stores counts and four bounded,
domain-separated aggregates instead of copying an unbounded receipt list:

- `receiptSetSha256` binds workflow/task identity, receipt path/bytes/hash, request, prompt, exact
  result-change aggregate, schema version, terminal outcome, and release-complete state;
- `sessionSetSha256` binds factory implementation/configuration/descriptor, negotiated agent
  commitments and capabilities, session commitment, and optional resume commitment;
- `changeSetSha256` binds the exact accepted clear workflow changes plus repair parent/result
  revisions; and
- `lineageSetSha256` joins the receipt, session, and change leaves for every contribution.

Leaves are length-delimited, domain-separated, sorted by digest, and folded with their exact count.
`candidateSourceLineageSha256` additionally binds the archive, archive manifest, source-tree
manifest, fixed reconstruction profile, full source revision, optional repair head, schema, counts,
and all four aggregates. At least one accepted ACP contribution is mandatory.

## Deliberately false claims

This checkpoint establishes only `candidateLineageBound=true`. It fixes all of the following false:

- hosted clean build and admitted executable;
- PREPARED, runtime identity, live containment, terminal absence, START, and observations;
- reference truth; and
- scoring, certification, and release eligibility.

The next #140 trust link is a separately authenticated hosted clean-build attestation that binds
this exact index and archive to the exact candidate executable. A later candidate admission must
verify that receipt and executable before any PREPARED or START transition.

Publication uses descriptor-bound, crash-recoverable, no-replace immutable state. A retry may
recover or accept only byte-identical canonical JSON; conflicting output, hard links, aliases,
noncanonical JSON, and unknown or legacy material fail closed.
