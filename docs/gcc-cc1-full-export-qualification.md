# Live GCC cc1 full-export qualification

The `cc1-live-full-export` job in `gcc-cc1-full-export.yml` is opt-in. Add the
`qualify:cc1-full-export` label to a pull request to run it; later pushes to
that PR rerun the qualification while the label remains. The ordinary PR matrix
does not build a compiler engine or run this production-sized export.

The job restores the full/stripped `cc1` pair from an Actions cache keyed by the
source lock, build records, toolchain recipe, compiler-engine profile, and cc1
manifest. It checks both cached files against the checked cc1 manifest before
use. On a miss or invalid cache entry, it verifies the pinned GCC source,
reproduces the pinned toolchain image, and rebuilds only `cc1`; it does not build
the unused `lto1` pair for this slice.

The live qualification provisions a dedicated 12 GiB ext4 scratch mount, the
root-owned application runtime, and the repository-bundled Ghidra release. It
runs the installed `gcc-engine-full-export cc1` command once. The resulting
Actions artifact retains the canonical model, full-export result and tree
manifest, structural binding, operation intent and receipts, and launcher
transcript. Model copying is descriptor-bound, bounded to the exporter limit,
and checked against the result digest.

This lane records an authenticated contained export. It does not perform the
independent boundary or identity-map replay, create `VerifiedStructuralInputsV1`,
score the production model, or establish release eligibility. The result and
qualification summary keep `complete`, `scored`, `benchmarkAccepted`, and
`releaseEligible` false. Issue #679 remains open until the remaining replay and
scoring evidence exists.
