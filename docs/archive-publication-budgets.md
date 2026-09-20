# Archive publication budgets

Archive creation and verification admit the selected immutable `ReconstructionProfile` against
the independent `ReconstructionHostSafetyLimits` policy before they inspect or publish archive
data. The effective entry, per-file byte and aggregate byte limits are the smaller of the
caller-supplied archive limits and the selected profile limits; host admission remains a separate
check and is never represented as a modified profile.

`reports/archival_audit.json` records the profile ID and digest, the exact profile archive
limits, the host archive ceilings, the effective limits and the pre-publication outcome.
`reconstruction.json` and the returned `ArchivalBundle` retain the corresponding `published`
outcome after the atomic archive move. These records describe local archive checks and do not
claim production containment, whole-process resource qualification or behavioral equivalence.

Focused evidence is in `ArchivalBundleTest`: host admission is rejected before a missing project
is touched, a one-entry profile exhausts during direct publication, and a successful fixture
retains the profile, host and effective limit commitments.
