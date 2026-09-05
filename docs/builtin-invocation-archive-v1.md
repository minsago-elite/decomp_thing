# Built-in invocation archive v1

`BuiltinInvocationArchiveDocument` captures a bounded portable terminal invocation artifact from an
invocation-bound receipt and its exact durable journal. It includes trusted workflow/task/prompt and
request/source/provider/model identities, the committed journal records, terminal outcome and usage,
candidate-change commitments, and shared captured filesystem/restoration/context audit commitments.
It contains no journal path, runtime endpoint, environment map or exception cause. The journal's
existing redaction applies to request/response payloads; path and callback identifiers in the new
metadata are commitments rather than plaintext.

The loop now collects final captured changes and callback audits after cleanup and commits them in
TERMINAL. This includes staged edits from refused, cancelled and failed turns. Failed outcomes keep
an empty shared result-change digest while retaining their separate candidate changes. A candidate
is not promoted to accepted source by appearing in either collection. Checkpoints additionally retain
shared audit snapshots so a resumed journal keeps callback decisions from earlier segments. The new
checkpoint field is optional when reading older schema-2 states; missing historical audit evidence
is not supplied or invented during recovery.

Capture verifies the runtime journal against the receipt commitment before rendering. Independent
verification receives the expected workflow identities and journal commitment from a trusted caller;
it never chooses these from the artifact it is checking. It validates bounded strict JSON, complete
record inventory, canonical record bytes/length, sequence and hash chain, request identity, operation
pairing, terminal metadata, changes, audit schemas and usage. For a successful candidate transcript it
also rebuilds request/retry counts, usage totals, proposed/authorized tool calls, result correlation,
unique executed IDs and completion validation. Only the finite object/string/integer/enum/length/range
schema vocabulary used by current built-in tools is interpreted; archive-authored references, regexes
and other executable or unsupported schema extensions are rejected.

The verifier performs no filesystem access or tool execution. The resulting immutable artifact can
be verified after its runtime journal is removed. Edits, missing/reordered/duplicate records, altered
receipt counters/changes/outcomes, substituted identities and cross-paired tool results fail. The
tool-result and schema-extension tests also rebuild a valid hash chain and supply its new commitment,
ensuring semantic verification adds checks beyond detecting an unchanged outer digest.

`candidateEvidenceComplete` means the terminal transcript is internally consistent, cleaned up and
free of indeterminate operations for a completed candidate turn. It is not factory provenance, a
compile/behavior result, accepted revision lineage or release qualification. Both the artifact's
`releaseQualified` and verified document's `releaseComplete` remain false. The current adapter handles
terminal journals; suspended checkpoints and damaged/torn journal prefixes remain private recovery
evidence and are not silently recast as terminal artifacts. Older terminal records lacking the new
final metadata cannot be exported through this version.

Seven archive tests cover portable verification/redaction, final failed/refused candidates, identity
substitution, terminal metadata changes, journal inventory/hash tamper, rehashed action/schema attacks
and parser/size/count bounds. The captured-resume integration test also verifies an archive retaining
the earlier segment's callback audit. Core v8 contains 115 cases: 109 passed locally, six live-terminal
skips, no failures/errors. Three shared ACP captured-filesystem cases also passed (118 combined,
112 passed, six skips):

```sh
./gradlew --offline test --tests 'decompengine.builtin.*' --tests 'decompengine.agent.*' \
  --tests 'decompengine.acp.AcpCapturedRepairFilesystemTest' --console=plain
```

#75/#77 remain open. [Repair receipt persistence](builtin-repair-persistence-v1.md) now retains these
artifacts and their independent journal references in the graph, rejected history and project archives.
Accepted-candidate lineage still requires ACP release facts. Factory provenance, built-in acceptance
after compilation/full retained-regression validation, accepted rollback lineage and comparative
release evidence still require implementation and qualification.
