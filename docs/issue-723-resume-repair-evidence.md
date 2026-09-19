# Issue #723 resume and repair evidence

This is one small repository evidence slice for #723. It records existing fixture and
validator contracts; it is not production qualification.

## Recorded facts

- `SourceTreeTest`'s `interrupted generation preserves accepted module bytes and resumes at the unfinished module` fixture interrupts `parse`, records the accepted `render` source SHA-256, resumes with the same reconstructor identity, asserts that `render` is not regenerated, and checks that its hash is unchanged. The resumed manifest has no unresolved implementation IDs and the interrupted attempt record is removed.
- The same test fixture leaves the interrupted module as the only unfinished work. This is bounded module ownership evidence for the fixture, not complete cc1 or lto1 engine ownership evidence.
- `GccCompilerEngineResumeEvidenceValidationTest`'s `interrupted 513-function prefix and resumed fresh outputs compare only as raw bytes` fixture validates a 512-function frozen prefix, resumed reuse count, and byte-identical final model and module-plan hashes. The asserted authority is `non-authoritative-byte-assessment`.

These facts support preserving an already accepted module hash across fixture resume and checking
resume/fresh output byte identity in the hostile-byte validator. They do not establish that a
production engine ran, stopped, resumed, repaired through ACP, or retained deterministic ownership
for every planned entity.

## Production gap

The current GCC resume validator accepts captured bytes only. The repository documents that it has
no accepted interruption/resume evidence schema, process or bundled-Ghidra controller, authenticated
oracle publication path, or production repair handoff. The existing source-tree test uses a local
fixture reconstructor. Production qualification still requires isolated bundled-Ghidra worker
execution, authenticated oracle boundaries and provenance, descriptor/inode-pinned containment and
whole-worker interruption/absence proof, no-replace evidence publication, and independent interrupted,
resumed, fresh, and bounded-repair runs for both `cc1` and `lto1`.

Status for #723: fixture contract recorded; production acceptance remains unresolved.
