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

Keep changes to the source schema, positive/negative examples, field-provenance table
and eventual DTO/type generation together. The schema permits values above JavaScript's
safe integer range; bounded server admission still rejects resources beyond configured
limits. Unknown producer fields intentionally fail this schema's drift check. A reader
may ignore additive response fields under the documented compatibility rules, while
unknown discriminators and evidence semantics remain unsupported. Do not use fixture
validation as a replacement for persistence, authorization, digest or runtime tests.
