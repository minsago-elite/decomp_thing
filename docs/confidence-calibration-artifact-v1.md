# Confidence calibration artifact v1

`confidence-calibration-artifact.schema.json` defines a reusable, closed contract for
calibration evidence. An artifact is parsed only from canonical, bounded JSON, validated
against the bundled schema and checked for sample-count/rate consistency, disjoint fit and
validation sample identities, contiguous score bands covering `[0, 1]`, and partition totals.

Each band reports fit and held-out validation error rates. Rates are the error count divided
by sample count, rounded to 12 decimal places using half-up rounding. A band is eligible only
when both sample counts meet the artifact's per-band minimums and the absolute difference
between fit and validation error rates is within the declared tolerance. The reported
probability is `1 - fitErrorRate`; the held-out validation error rate and its recomputed
Wilson 95% interval are the supporting check. Each partition lists sorted, unique SHA-256
sample identities; its count must equal that list length, and the two lists must be disjoint.
The separate partition hashes must also differ. The v1 artifact admits at most 4,096 samples
per partition and 1 MiB of canonical bytes. A trusted producer must bind the listed sample
identities to its underlying observations; this structural check cannot establish that
provenance by itself.

The consumer must pin the exact artifact SHA-256 outside the artifact, through a trusted
manifest or equivalent policy. It must also supply the exact runtime scope. Scope includes
the benchmark revision and input, target ABI, oracle ID and digest, score definition and dimension, plus
the distribution profile and evidence identity. Digest authentication does not itself
establish that a distribution is representative: the artifact must additionally state that
distribution verification passed. Unverified distributions, scope mismatches, out-of-range
scores, insufficient support, and rates outside tolerance return `uncalibrated` with a null
probability. The schema requires out-of-distribution handling to use this fail-closed action.

This contract and its tests are draft implementation evidence only. Their authored samples
are synthetic and test the validator and math; they are not a GCC calibration set. The repo
still lacks authenticated production score samples from #40 and a qualified GCC distribution,
so there is no production artifact and existing report scores remain uncalibrated. Report,
CLI and web integration remains assigned to #687; empirical tolerance qualification remains
assigned to #685.
