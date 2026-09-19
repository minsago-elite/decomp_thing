# Issue #124 evidence slice

[`docs/evidence/issue-124-link-program-reference-v1.json`](evidence/issue-124-link-program-reference-v1.json)
binds the checked LLVM 22.1.6 `link-program` reference case to the exact corpus
and report bytes, source input, argv, produced executable identity, and observed
exit and stream digests. The report records this reference case as passed.

This is reference evidence only. No authenticated candidate run is bound to the
same case, so artifact comparison remains unresolved and `releaseEligible` is
false. The record also leaves the required IR, assembly, ELF/relocation/unwind/
ABI projections and single-mutation reports unavailable. A reference observation
does not grant scoring or release authority.
