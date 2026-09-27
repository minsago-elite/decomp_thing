# Extracted program model v2

Schema 2 separates the extraction label from recovery assessment. It preserves the
schema-1 entity facts and order, replacing each `status` field with
`extractionStatus` followed by `recoveryAssessment: "unassessed"`. The historical
labels recovered, partial, failed and synthetic describe extraction/completion;
none certifies source or ABI accuracy. Unknown type strings remain retained facts.

The closed JSON shape is defined in
[`extracted-program-model-v2.schema.json`](../oracle/extracted-program-model-v2.schema.json).
Canonical typed and bounded streaming readers support versions 1 and 2. Schema-1
canonical bytes and digests remain unchanged. Schema-2 canonical serialization
uses the same whitespace, ordering and escaping rules with the two explicit fields.
The streaming reader charges the added fields against its existing resource bounds.
JSON Schema describes shape; canonical readers additionally enforce exact bytes,
entity ordering, identity uniqueness and their applicable resource limits.

An extracted model cannot declare an assessed result. Exact, ABI-equivalent,
contradicted and unobservable findings belong to separately validated structural
oracle evidence. Such evidence must retain its facts and identities when joined to
the extracted model; rejecting an assessment claim in this input format does not
authorize dropping a discrepancy from the oracle. No calibrated probability can
be derived from the extraction status.

Exporter version 12 emits schema 2 in full and planning modes. Its function/global/type
fragments explicitly retain unassessed recovery, and fragment validation requires
those fields. Resume state and GCC profile admission pin exporter version 12;
version-11 and earlier state is rejected without rewriting it or replacing the previous model.
The Kotlin resume verifier reconstructs schema-2 bytes from the retained fragments.
Existing byte commitments cover the new fields, while the exporter version and
script digest distinguish the producer contract. Typed
entity `status` properties remain historical extraction labels for compatibility.
Version 12 retains the original Ghidra type path as a JSON string with escaped
forward slashes in the declaration comment. This preserves paths containing quotes,
backslashes, line breaks or comment delimiters, and permits exact UTF-8 path hashing
against the type ID. The program-model schema remains version 2.
For schema 2, the source manifest, project/module confidence report, human unresolved
report and archival audit include every extracted entity in the unresolved recovery
population. Successful compilation can accept an implementation without changing
that population. Human reports retain the extraction label alongside `unassessed`.
The authored regression covers functions, globals and types, including packaging,
extraction and consumer re-audit.

## Call-target evidence boundary

Canonical `fn_` call IDs encode a Ghidra function entry-point offset; their format
alone does not authenticate a target, its address space, or a scored call edge.
The exporter retains non-external call targets, including thunks, while omitting
thunks from the exported function inventory. A valid call can therefore lack a
matching function record. Bundled Ghidra 12.1.3 can also create ordinary thunks in
an artificial, uninitialized RAM block named `EXTERNAL`, outside file-backed
executable segments. That block differs from Ghidra's external address space,
whose function targets the exporter excludes. Neither inventory membership nor
file-backed executable-range membership is implied by a canonical call ID.
Independent call-target qualification requires retained target and thunk
provenance; the current model and profile binding do not supply that evidence or
grant scoring authority.

Historical schema-1 reports retain their extraction-based unresolved accounting for
compatibility; their labels still contain no independently scored assessment. A
validated assessment join, historical report migration and production qualification
remain tracked in #363 and #42. Schema-2 unresolved accounting alone does not supply
the authenticated assessment evidence needed to resolve an entity.

New confidence and archival audit reports include a separate `recoveryAssessment`
population for both model versions. Its closed
[`unassessed-recovery-population.schema.json`](../oracle/unassessed-recovery-population.schema.json)
binds the model version and exact model SHA-256, lists every model entity as
unassessed, and has no assessed entities. The producer derives this population from
the model rather than consuming an archived assessment claim. Existing historical
diagnostic unresolved lists can be empty while this population remains completely
unassessed. Neither successful compilation nor a legacy `recovered` label upgrades
it. Previously written reports remain unchanged until regenerated or re-audited.

New human unresolved reports state the complete unassessed entity count and its
function/global/type breakdown before presenting diagnostic or implementation
findings. An empty historical extraction-status list is labelled as such. The
reconstruction CLI reports unassessed recovery accuracy, and the source-file view
states that scored recovery evidence is unavailable there. These presentations do
not turn the retained heuristics or accepted implementation flags into assessments.

Live benign authored programs verify bundled Java-API Ghidra full/planning export,
canonical streaming parity and deterministic resume. Planning resume also checks
that historical exporter state is refused and prior bytes are preserved. This is
local exporter qualification; existing authenticated production profiles and their
GCC/LLVM artifacts must be regenerated and qualified for the new exporter identity.

The generated-C dependency index accepts both model versions with their exact entity
fields. Schema 2 requires unassessed recovery and retains the same ownership and
dependency entries as schema 1 for identical extracted facts. Indexing does not
grant assessment or repair acceptance. Docker archival validation expects current
schema-2 exports and explicit unassessed fields; that script requires its separate
container qualification environment.

The legacy Python function-boundary diagnostic reader accepts both versions for its
function projection. It requires schema-2 functions to remain unassessed and uses
the extraction label only as retained input metadata. The authored twin fixtures
produce identical diagnostic reports under both versions, including all metrics,
exclusions and the non-production verification state. This reader does not validate
global/type recovery or replace the bounded canonical production ingestion path.
