# GCC compiler-engine resume validation

This checkpoint contains only a Kotlin hostile-byte validator for one compiler engine at a time.
Callers must validate `cc1` and `lto1` independently; passing one engine says nothing about the
other. It accepts already captured bytes and performs no process, path, filesystem, or publication
work.

The validator enforces the exact compact schema-2 exporter-state and schema-1 progress encodings.
Progress is always assessed together with fresh raw state bytes: its total must equal the state
function count, planning recovery has zero `recovered` functions, and completed/reused positions must
be terminal or 512-aligned contiguous-prefix positions. A `complete` progress artifact must cover the
entire state.
The returned state, progress, and completed-run objects are explicitly labelled
`non-authoritative-byte-assessment`; no operation accepts one of those objects as an input or as a
construction token.

The one-shot completed-run assessment snapshots caller-owned arrays and then validates raw state,
progress, every checkpoint and fragment, and the final model. It requires a full ordered contiguous
batch sequence to the state function count, one exact state binding, one inventory binding, strict
cross-batch function order, and unique first ownership of every global and type. It independently
recomputes the newline-framed function-inventory digest, the exact
`ExporterSemanticFingerprintV1` canonical byte count and SHA-256, and the exact planning batch
commitment. Function order and global/type merge keys come only from canonical embedded identities,
never caller labels. Parsed state, progress, checkpoint, and fragment snapshots are size/digest
rechecked before final assembly. The caller-supplied batch list is copied with a hard 256-entry
iteration cap and rejected if its declared and observed counts differ.

State is bounded before UTF-8 decoding at 64 KiB, progress at 1 MiB, each checkpoint at 256 KiB,
and each planning fragment at 64 MiB. The run-wide retained checkpoint/fragment budget and the
complete framed program-model budget are each 512 MiB. Planning coordinates are nonnegative,
aligned 512-function batches; only the terminal batch may be short, and no coordinate may exceed the
state function count or the 131,072-function hard limit.

Function, global, type, and failure fragments are parsed as the exact canonical record arrays emitted
by `ExportProgramModel.java`. Embedded identities must be sorted and unique and must equal checkpoint
identities; function statuses and counts are checked (planning records may be only `partial` or
`failed`, never full-mode `recovered`), and failure identities must equal the failed function
identities. The completed-run operation compares the supplied model byte-for-byte with the bounded
exporter framing assembled from those validated records. Standalone state assessment only parses the
state’s claimed commitments; commitment reproduction occurs only in the one-shot completed-run
assessment.

There is no accepted pretermination or resume-evidence schema in this checkpoint, and the validator
cannot publish `complete: true` evidence. No production request, launcher, process-controller, or
publisher API is present; the future cgroup-backed design will define that surface.

Three host authorities remain required before real interruption acceptance work:

- descriptor/inode-pinned cgroup-v2 or systemd containment, freeze/snapshot, whole-cgroup kill, and
  cgroup/unit absence proof;
- no-replace evidence publication with exact-identity rollback or quarantine after a post-rename
  durability failure;
- separate forced-interruption, resume, and fresh-control Ghidra runs for both `cc1` and `lto1`.

Until those land, this code is reusable validation infrastructure only and is not A10 evidence.
