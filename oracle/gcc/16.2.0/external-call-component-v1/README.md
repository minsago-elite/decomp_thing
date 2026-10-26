# Retained external-call component evidence

This directory retains a standalone external-call composition run of producer
commit `2ea80eced566aa590e6ae26988da897bb4a438c7`. `evidence.json` binds the exact request,
report, rich ELF, runtime identities, source tree, and eleven producer source
files. Its `sourceEvidence` binds the existing machine-call evidence in that
commit; the verifier follows that evidence to its original producer commit and
checks the original request, report, canonical oracle, and artifact manifest.

`driver-report.json.gz` decompresses to 21,980,778 bytes with SHA-256
`e4d43d13254e4420429c1597c21c5d40fdc1c9963456b0a79edffa4f00e34203`.
`driver-request.json` preserves the exact original request. Absolute paths in
requests record capture locations; the offline verifier never dereferences them.
Both recorded source commits must be available in the local Git object database.
A shallow checkout must obtain that history first; verification never fetches it.

Run the bounded offline verifier from the repository:

```sh
python3 scripts/verify-machine-call-component-evidence.py \
  oracle/gcc/16.2.0/external-call-component-v1/evidence.json
```

To recover the exact report into an existing repository-local directory, add
`--extract-report build/driver-external-calls.json`. Extraction creates a new file
after verification and refuses to replace an existing file. The verifier checks
single-member gzip bounds, exact byte commitments, canonical JSON, source and
input Git blobs, source-call preservation, object-local import namespace
identities, request/runtime consistency, retained counts, and authority flags.
It performs no network access, ELF analysis, or decoder execution.

The report retains all 15,376 physical sites from its
source report and emits 15,376 composition records.
Its section-declared inventory contains 165
dynamic symbols, 157 relocations,
15 version requirements, and
0 version definitions. The object-local
namespace contains 151 eligible undefined dynamic
symbol requests. These are retained populations, not a completeness or accuracy
denominator.

| Composition disposition | Sites |
| --- | ---: |
| `retained-canonical-target` | 11,174 |
| `static-import-request-reference` | 2,932 |
| `unresolved-memory-transfer` | 909 |
| `unresolved-slot-without-relocation` | 12 |
| `unresolved-source-caller` | 335 |
| `unresolved-source-target-exclusion` | 11 |
| `unresolved-weak-runtime-target` | 3 |

A `static-import-request-reference` joins authenticated instruction bytes to a
constant memory slot and that slot's supported active relocation and undefined
symbol request. Direct calls can retain one supported forwarding instruction;
that instruction adds evidence to the source site and is not counted as a second
call. Symbol/version/provider-request spelling comes from ELF metadata. The
component does not identify the pointer's runtime value, the actual provider, an
IFUNC implementation, interposition outcome, or whether a weak reference resolves
to null. Original caller and instruction-boundary uncertainty remains explicit.

The raw inventory retains these limitations:

- `dynamic-hash-population-not-reconciled`
- `runtime-provider-and-interposition-unresolved`

This is component evidence. `complete`, `releaseEligible`,
`negativeCompleteness`, and `sourceCallPopulationComplete` remain false;
containment remains `external-owner-required`. `sourceCallRecordsEnumerated`
means the committed source records were all retained, not that every real call
was found. The producer JAR digest is a launch-time build observation; it is not
a source-to-binary attestation. The verifier neither rebuilds that JAR nor grants
production admission, scoring authority, runtime binding authority, or negative
coverage. Parent containment and independent consumer qualification remain
separate work.
