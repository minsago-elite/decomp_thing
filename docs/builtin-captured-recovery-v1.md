# Built-in captured repair recovery v1

`BuiltinCapturedRepairHarness` now accepts optional journal/checkpoint configuration and a
`BuiltinCapturedResume` containing a checkpoint reference and detached candidate source bytes.
Execution still enters through `CapturedRepairStagingAuthority`. Ordinary execution remains
unavailable because it has no captured mutation authority.

The authority receives the original accepted source as `initialFiles` on every invocation. The
adapter checks that source against the journal's initial snapshot identity, including on resume.
The separate resume payload supplies checkpoint candidates; it never replaces the accepted
baseline. This distinction preserves exact before/after hashes and lets a later reversion remove
an earlier patch instead of treating that patch as accepted source.

The tool session hashes a detached snapshot of the actual captured filesystem while callbacks are
open. Checkpoint state schema 2 additionally binds the repair resource budget and the bounded sink's
effective replacement allowlist. Changing either prevents restoration/provider execution even if
the request's path rules and model-visible tool schemas remain unchanged. Earlier schema-1 states
are rejected rather than migrated without the missing authority binding.

During resume, the loop first verifies the journal, state, request and tool authority as described
in the [checkpoint contract](builtin-checkpoint-v1.md). The adapter then:

1. Requires the exact accepted file inventory and the checkpoint's candidate snapshot hash.
2. Validates UTF-8, file/staging/patch ceilings and effective write policy before restoring files.
3. Reconstructs changed candidates through the existing ACP filesystem callbacks and
   `BoundedRepairOutput`. Shrinking files precede growing files, keeping intermediate stage size
   within the same quota as the accepted and final trees.
4. Rechecks the resulting snapshot before the loop appends RESUME and calls the provider.

All resumed edits continue through the same shared sink. Previously staged patches still consume
its quotas. A provider refusal, failure or cancellation retains all candidate changes against the
original accepted base; it does not accept them. Failed restoration affects only the fresh captured
stage, leaving the accepted source and unconsumed checkpoint available to the workflow.

Restoration callbacks appear in a separate immutable `restorationAudit`; model-issued callbacks
remain in `filesystemAudit`. Both use the same shared audit record schema and policy decisions.
Restaging does not fabricate new model calls or charge an already-completed tool action twice.
The namespace anchor remains virtual and is never written as a host directory.

Eight integration cases cover fresh-stage readback and hashes, reversion, quota conservation,
budget and effective-allowlist binding, invalid inventory/content/accepted baseline, shrink-before-
grow ordering, detached inputs and failure/refusal/cancellation after continuation. The local v6
core inventory has 99 cases: 93 passed, six live-terminal skips, no failures/errors. Three existing
ACP captured-filesystem cases also passed in the combined selection (102 total, 96 passed, six skips):

```sh
./gradlew --offline test --tests 'decompengine.builtin.*' --tests 'decompengine.agent.*' \
  --tests 'decompengine.acp.AcpCapturedRepairFilesystemTest' --console=plain
```

The v6 hosted lane must pass independently. #75 and #77 remain open: durable source-blob/archive
rehydration, repair-history transcript references, compile/full retained-regression acceptance,
publication/rollback lineage, factory selection and comparative ACP qualification are still required.
The caller currently obtains candidate bytes from trusted workflow storage or the prior captured
execution; the adapter does not recover missing source from hashes or redacted transcript text.

The subsequent [checkpoint source store](builtin-source-store-v1.md) can persist exact candidates
before checkpoint publication and load them by a verified snapshot identity. A configured fresh
adapter may use `BuiltinCapturedResume.fromStore(reference)`. Project archive export/verification
and full repair acceptance remain separate requirements.
