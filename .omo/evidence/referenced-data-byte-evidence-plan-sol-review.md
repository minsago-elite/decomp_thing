# Referenced data byte evidence plan review

Verdict: OKAY

Reviewed revised plan SHA256: `c68ecc031b4dec4598c026af6d6a0bad2f510c0faba250db13e44d220544e585`.
Previous reviewed hash: `355d25a77a53f495932f1a2da43f548da973da97209b88d187275cc110a38f23` (ITERATE; resolved below).
Authoritative source revision: `05b073fc8378bd2faaf0ee4163cf055ba61e11da`; inspected with `git show`, without trusting checkout source. Read repository AGENTS.md. Read discovery receipt. GitHub read checks confirm #1506 OPEN and milestone 14 OPEN, with acceptance matching this plan. No dependency closure is asserted or needed for this review. No source, Git, or GitHub mutations performed.

## Contract clarification resolved

The revised plan explicitly closes omissionReason to null or unknown_access_width and requires the latter iff any window has unknown width. It specifies all-known, mixed, and all-unknown cases, keeps known-width missing ranges in segment reasons, rejects empty schema-3 windows, and requires qualifying references to supply an origin. Unknown windows have no segments; known windows have complete nonempty coverage. The validation matrix includes positive and negative cases for every listed relation, including invalid enum values. These revisions resolve the sole previous ITERATE finding without changing the intended evidence authority or historical compatibility.

## Verified strengths and execution references

All six existing source paths and all nine named existing test classes exist in the authoritative revision. The optional sibling files/classes are explicitly new, so they are executable tasks rather than broken references. BundledGhidraTest is at src/test/kotlin/decompengine/analysis/BundledGhidraTest.kt and has actual installed/bundled opt-in machinery. Workflow selection is correctly deferred until inspecting available .github/workflows configuration.

ExportProgramModel.java:874-881 normalizes globals to containing data and retains display initializer. Lines 909-937 scan instruction references and write first-owner records, including a string-reference bypass. The complete bounded prepass and exact target origin address directly address those concrete behaviors. Fingerprinting observes exact rendered globals at 269-272 and frames their records at 297-299; the plan appropriately demands inspection of exporter-identity binding before retaining the domain. Export-wide failures must continue to escape the existing recoverable data-reference catch; the explicit failure-before-completion requirement covers that implementation concern.

ProgramModel.kt restricts schemas to 1..2 at 51 and 169 and has schema-2 status/recoveryAssessment branches. CanonicalProgramModelStreaming.kt has the corresponding closed schema gate at 154, initializer parsing at 264-268, and schema-specific rendering at 505/534/551. The plan explicitly addresses these gates while preserving historical output. Full capture has exact global fields at 134 and 561 and the schema/exporter pair check at 421; resume has exact fields at 1285 and canonical renderer at 1480. Their nested record parsers and historical compatibility are correctly included. GeneratedCModulePrompt.kt:16 currently supplies initializer only; the proposed typed evidence rendering and pre-invocation budgets cover the missing prompt surface.

The proposed evidence is explicitly non-authoritative and does not assert object extent, type, floating-point meaning, ABI, oracle or release truth. Exact lowercase hex, requested lengths, segment coverage, address overflow, partial missing ranges, initialized/readable checks, and zero values are specified. Unknown width cannot silently become a guessed extent. Original initializer stays separate.

Per-window, per-global and aggregate limits include duplicate occurrence work, checked arithmetic, failure without truncation, cancellation and prompt limits. Stable prepass output avoids first-owner/batch-dependent byte loss. The named tests include actual stripped eight-byte fixtures, interior origins, ambiguous accesses, multiple widths, unavailable ranges, exact/one-over limits, authenticated mutation rejection, capture/resume equality and prompt byte equality. These are meaningful behavioral gates rather than solely source-string tests. Actual implementation review should ensure fixture instructions reliably yield statically associable LOAD/STORE p-code and that real-Ghidra CI does not skip the new fixture.

## Re-review boundary

The closed-contract ambiguity is resolved at the revised hash above. The ordered tasks are sufficiently concrete and correctly cover the issue acceptance criteria. No plan blocker remains. This review did not run builds or tests because it changes no implementation and approves no implementation evidence.
