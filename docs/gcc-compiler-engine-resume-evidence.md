# GCC compiler-engine resume validation

This checkpoint contains only a Kotlin hostile-byte validator for one compiler engine at a time.
Callers must assess `cc1` and `lto1` independently; passing one engine says nothing about the other.
It accepts already captured bytes and performs no process, path, filesystem, request, controller, or
publication work.

The validator enforces the exact compact schema-2 exporter-state and schema-1 progress encodings.
Progress is always assessed together with fresh raw state bytes: its total must equal the state
function count, planning recovery has zero `recovered` functions, and completed/reused positions must
be terminal or 512-aligned contiguous-prefix positions. A `complete` progress artifact must cover the
entire state. The returned state, progress, completed-run, interrupted-prefix, and resume-equivalence
objects are explicitly labelled `non-authoritative-byte-assessment`; no operation accepts one of
those objects as an input or as a construction token.

The one-shot completed-run assessment snapshots caller-owned arrays and then validates raw state,
progress, every checkpoint and fragment, and the final model. It requires a full ordered contiguous
batch sequence to the state function count, one exact state binding, one inventory binding, strict
cross-batch function order, and unique first ownership of every global, type, and failure. It
independently recomputes the newline-framed function-inventory digest, the exact
`ExporterSemanticFingerprintV1` canonical byte count and SHA-256, and the exact planning batch
commitment. Function order and global/type merge keys come only from canonical embedded identities,
never caller labels. Parsed state, progress, checkpoint, and fragment snapshots are size/digest
rechecked before final assembly. The caller-supplied batch list is copied with a hard 256-entry
iteration cap and rejected if its declared and observed counts differ.

The interrupted-prefix assessment is narrower. It requires `phase=planning`, zero reused records,
at least one complete 512-function checkpoint, and a completed position strictly below the state
total. The supplied checkpoints must cover exactly the observed prefix from zero in full 512-record
batches. Their recovery counts must equal progress, their embedded function identities must remain
strictly ordered, and global, type, and failure evidence must have one first owner across the prefix.
Every checkpoint must declare the same syntactically valid inventory SHA-256. The returned field is
therefore named `declaredInventorySha256`: a prefix cannot reproduce the full inventory digest from
the unobserved suffix.

The resume-equivalence assessment accepts fresh raw bytes for the interrupted prefix, the completed
resumed leg, and a completed fresh-control leg. It never accepts an interrupted-prefix or completed-run
assessment. All arrays are snapshotted before validation, and all three caller-supplied batch lists are
copied with the same manual hard iteration cap. The operation then:

- applies the interrupted-prefix checks to the first leg and the complete one-shot validation to both
  final legs;
- requires byte-identical exporter state across all three legs;
- requires every frozen checkpoint and function/global/type/failure fragment to be a byte-identical
  prefix of the resumed run;
- requires resumed `reused` to equal the interrupted completed position and fresh `reused` to be zero;
- requires byte-identical final program models and byte-identical bounded module plans.

The full resumed validation reproduces the inventory digest declared by the frozen prefix because the
prefix artifacts and exporter state are exact. Module plans receive only bounded byte-equality here;
this validator does not parse them, authenticate their origin, or prove their ownership semantics.

State is bounded before UTF-8 decoding at 64 KiB, progress at 1 MiB, each checkpoint at 256 KiB,
and each planning fragment at 64 MiB. The per-leg retained checkpoint/fragment budget, complete
framed program-model budget, and per-plan byte budget are each 512 MiB. A resume comparison also has
a 2-GiB aggregate snapshot budget across all interrupted, resumed, fresh, model, and plan arrays.
Planning coordinates are nonnegative, aligned 512-function batches; only the terminal batch may be
short, and no coordinate may exceed the state function count or the 131,072-function hard limit.

Function, global, type, and failure fragments are parsed as the exact canonical record arrays emitted
by `ExportProgramModel.java`. Embedded identities must be sorted and unique and must equal checkpoint
identities; function statuses and counts are checked (planning records may be only `partial` or
`failed`, never full-mode `recovered`), and failure identities must equal the failed function
identities. The completed-run operation compares the supplied model byte-for-byte with the bounded
exporter framing assembled from those validated records. Standalone state assessment only parses the
state’s claimed commitments; commitment reproduction occurs only in the one-shot completed-run
assessment.

There is no accepted interruption or resume-evidence schema in this checkpoint, and a successful
assessment does not prove that any process ran, was interrupted, terminated, resumed from disk, or
used a fresh analysis state. The validator cannot publish `complete: true` evidence. No production
request, launcher, process-controller, cgroup, Ghidra runner, path reader, descriptor pin, or publisher
API is present. The separate [pre-START containment contract](gcc-compiler-engine-containment.md)
now fixes the identities and lifecycle facts that a future host controller must establish, but its
caller-supplied receipts are explicitly non-authoritative and it exposes no START transition.

Three host authorities remain required before real interruption acceptance work:

- descriptor/inode-pinned cgroup-v2 or systemd containment, freeze/snapshot, whole-cgroup kill, and
  cgroup/unit absence proof;
- no-replace evidence publication with exact-identity rollback or quarantine after a post-rename
  durability failure;
- separate forced-interruption, resume, and fresh-control Ghidra runs for both `cc1` and `lto1`.

Until those land, this code is reusable validation infrastructure only and is not A10 evidence.
