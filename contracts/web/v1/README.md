# Workbench v1 design fixtures

These synthetic documents specify the D0.4 boundary in
[docs/web-api.md](../../../docs/web-api.md). They do not claim implemented endpoints,
successful agent execution, accepted release evidence or available Git support.

`contract.schema.json` is the source schema (JSON Schema draft-07). Its definitions
name representative DTOs. Response and event fixtures are their JSON wire shape.
Request fixtures use `{apiVersion, kind, data}` to select the appropriate definition;
only `data` is sent as the HTTP request body. Headers, status codes and concurrency
transactions are specified in the API document and need D2 HTTP integration tests.

Run from the repository root:

```sh
python3 contracts/web/v1/verify.py
```

The verifier uses `fastjsonschema==2.22.2`, already pinned in
`requirements/oracle-generation.txt`; no production dependency is added. It compiles
the schema, requires exact manifest coverage, validates all positive fixtures and
rejects every declared negative fixture. It additionally checks cross-record
relationships such as report/artifact bindings, ordered poll pages and Git object
lengths for the declared object format. The `valid` field in `fixtures.json` describes
schema/presentation validity, not whether the example was executed or accepted.

`outcomes.json` is the versioned #604 index of seven deterministic web outcomes:
successful, empty, partial, interrupted, failed, denied and unsupported. It refers
to positive wire documents in the fixture manifest rather than duplicating them.
The Python verifier checks the required kind and state for each outcome as well as
schema validity, manifest membership and absence of credential/private-path/binary
payload fields. `frontend/tests/api-outcomes.test.ts` decodes those same documents
with generated frontend response types in CI. All identities, timestamps, names and
digests are synthetic; the "accepted" report is a contract example, not actual
release evidence. The index is fixed data, not a clock, identity or event factory.

Keep changes to the source schema, positive/negative examples, field-provenance table
and eventual DTO/type generation together. The schema permits values above JavaScript's
safe integer range; bounded server admission still rejects resources beyond configured
limits. Unknown producer fields intentionally fail this schema's drift check. A reader
may ignore additive response fields under the documented compatibility rules, while
unknown discriminators and evidence semantics remain unsupported. Do not use fixture
validation as a replacement for persistence, authorization, digest or runtime tests.

`workflow.observation` is the bounded display-journal event variant for D4. Its
writer identity is separate from the web attempt; numeric counts stay decimal
strings and `authority` is fixed to `observations`. Reported phases and source
commitments do not confer workflow acceptance. Unsupported payload fields need
explicit omission accounting, separate from event-retention gaps. See
[`docs/web-progress-adapter.md`](../../../docs/web-progress-adapter.md).

The `event-observation-public-metadata` and `event-observation-plan-metadata` fixtures
capture the public producer output after raw labels, prose, paths and plan entries are omitted.
The retained-record input examples that contain those fields are declared invalid as public
contract documents and remain only as projection-test inputs. Typed state and explicit SHA-256
commitments are public; a digest never promotes the committed label or prose.

A progress snapshot with zero retained events can still acknowledge a nonzero logical
watermark after omissions. Its oldestCursor is null, while throughCursor/throughSequence
identify the cutover. Only nextSequence zero requires a null cutover when progress metadata
is present. EVENT_GAP recovery can likewise have a null oldestCursor and a non-null latestCursor.
These positions acknowledge missing history; they do not create an event or acceptance evidence.
