# Issue 462 evidence record

This record captures the smallest verified join boundary currently available for
#462. It is fixture evidence only; it does not qualify a production assessment.

The frozen structural fixture is scored by the JVM `StructuralRecoveryV1`
contract in `src/main/kotlin/decompengine/oracle/structural/StructuralRecoveryV1.kt`.
Its parity test reads
`src/test/resources/oracle/structural-v1/expected-score.json` and verifies the
stable function-boundary mapping plus the reviewed global/type identity map.
The checked report digest is
`2dbff117253ba927a84df1e428f62d97b1f0efde049d4e6b78dc050dc5456ce6`.

The existing fixture facts are preserved per entity and per dimension. Its
aggregate partition is: 24 oracle facts, 26 recovered facts, 14 exact, 4
ABI-equivalent, 3 recovered-unknown, 1 oracle-unobservable, 2 contradicted,
and 3 fabricated. Missing recovered facts remain `recovered-unknown`, an
unobservable oracle fact remains `oracle-unobservable`, and a mismatched
concrete claim remains `contradicted`; these outcomes are not collapsed into
success.

The extracted schema-2 model still requires
`recoveryAssessment: "unassessed"`. The production boundary is unavailable:
`StructuralReplayAdapterRegistry.production` is intentionally empty and
`VerifiedStructuralInputsV1` has no creator. Therefore this record binds only
the existing fixture report and cannot attach authenticated production findings
or change model assessment state. Dependencies #40 and #136 still own the
authenticated exporter, loader, replay, and oracle authority required for that
gate.
