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

This checkpoint adds reader and wire-contract support. The exporter continues to
emit schema 1. Its retained fragments, resume configuration, semantic commitments
and production replay must migrate together before switching the producer. Typed
entity `status` properties remain historical extraction labels for compatibility.
Downstream unresolved accounting still needs the separate validated assessment
dimension; accepting schema 2 does not complete that migration. Historical schema-1
records likewise contain no independently scored assessment. These remaining steps
are tracked in #363 and #42.
