# GCC ABI recovery coverage evidence

This checkpoint records the current repository evidence for issue #46 at
commit `bf2501568f39ab52b23492dfc37839bb81895587`. It is a bounded tracker
slice: it records the observable boundary and unresolved ABI populations; it
does not claim that #46, #692, #693, #694, or #695 is complete.

## Authenticated input boundary

The GCC 16.2.0 profile supplies one authenticated rich/stripped driver pair.
The pair is the only binary authority used by the checked function oracle.

| Field | Current value |
| --- | --- |
| Source revision | `78d4ac73dd391005b895a6148cd9831e28e1208b` |
| Source lock SHA-256 | `e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc` |
| Oracle manifest SHA-256 | `c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9` |
| Rich driver | 20,713,760 bytes; SHA-256 `8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b` |
| Stripped driver | 2,349,296 bytes; SHA-256 `3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4` |
| ELF identity | `ET_EXEC`, `0x400000` image base, executable RVA range `0x3000..0x10eac9` |
| Target descriptor | `oracle/targets/sysv-amd64-v1.json`, SHA-256 `d251d5e6a0edc17655c355fb8fd757d557f064a6e67095ad53c8ca1e7569a343` |

The source, manifest, and artifact hashes above are copied from the checked
profile and its retained oracle manifest. No external `GHIDRA_HOME` or
`analyzeHeadless` installation is part of this evidence slice. A future
production model must bind its bundled-Ghidra exporter and loader receipt to
these inputs before it can become scoreable evidence.

## Current coverage

The checked `oracle/gcc/16.2.0/function-recovery-oracle.json` is an
authenticated boundary/name oracle. Its exact SHA-256 is
`b49b8a72a96580bd8727d9dc530753f40f78185a656f472ebe83a7a1f6fc9aae`, and its
`oracle.artifactManifestSha256` matches the manifest above.

| Population | Current coverage | State for #46 |
| --- | ---: | --- |
| Function records | 12,844 | Retained boundary/name oracle records |
| Scoreable physical function starts | 3,284 | Defined boundary denominator for boundary/name scoring |
| Reviewed compiler-generated exclusions | 140 | Explicitly excluded, not scored |
| Inline-only exclusions | 9,420 | Explicitly excluded, not scored |
| Function aliases | 24,163 | Retained as per-alias evidence; aliases at one RVA do not inflate the boundary denominator |
| GCC production prototype facts | Not established | Unresolved; no checked GCC structural oracle population |
| GCC production global storage/type facts | Not established | Unresolved; no checked GCC structural oracle population |
| GCC production shared aggregate/enum/typedef facts | Not established | Unresolved; no checked GCC structural oracle population |
| Authenticated GCC ABI score | Not established | The existing schema-v1 production measurement is `artifact-verified-model-unattested` with `productionVerified: false` |
| Strict generated-C declaration build | Not established | Fixture source checks do not qualify recovered GCC declarations |

The generic structural contract defines twenty dimensions, including function
prototypes and ABI classes, global storage/linkage/type, aggregate layout,
enum values, and typedef targets. It also requires an explicit evidence state:
oracle facts are `observable` or `oracle-unobservable`, recovered facts are
`recovered` or `recovered-unknown`, and comparison outcomes keep
`contradicted`, `fabricated`, and unobservable facts distinct from credit.
The checked structural JSON is a neutral fixture with five functions, one
global, three types, and 24 facts. It is contract evidence only; it is not a
GCC production population.

The documented boundary measurement reports rich exact boundaries `3283/3284`
and stripped exact boundaries `3268/3284`, but its model provenance remains
unattested. Those counts must not be reused as prototype or global/type
accuracy scores. No checked GCC production structural-oracle, recovered-model,
identity-map, or structural-score artifact currently establishes those
denominators.

## One actionable acceptance boundary

The next admissible boundary is an authenticated GCC production structural
oracle for the same manifest and target descriptor. It must retain a complete
per-entity/per-dimension population for the observable denominator, mark
unobservable facts with no value, preserve per-fact evidence locators, and
record the exporter, bundled-Ghidra loader, normalization profile, artifact,
and exact generation identities. Its generation must be reproducible from the
recorded inputs and fail closed when an input or identity changes.

Until that one denominator artifact exists, #692 remains open and #693/#694
cannot claim a 90% ABI or global/type result; #695 cannot claim a strict
generated-C declaration result. Missing or ambiguous prototypes, calling
conventions, source-level types, storage facts, and shared-type facts remain
unresolved rather than being filled with placeholders or removed from a
denominator.

## Reproducibility checks

The coverage counts and identity bindings in this document were checked with
the following bounded reads from the repository-controlled profile:

```bash
sha256sum oracle/gcc/16.2.0/function-recovery-oracle.json \
  oracle/gcc/16.2.0/oracle-manifest.json \
  oracle/targets/sysv-amd64-v1.json

jq '{records:(.functions|length), scoreable:([.functions[] | select(.exclusion == null)] | length), exclusions:(.functions | map(select(.exclusion != null) | .exclusion.kind) | group_by(.) | map({kind: .[0], count: length})), aliases:(.functions | map(.aliases|length) | add)}' \
  oracle/gcc/16.2.0/function-recovery-oracle.json
```

This is evidence of the current denominator boundary and availability state,
not a production ABI qualification. No broad test suite or full GCC analysis
was run for this documentation-only checkpoint; validation is limited to the
hash/count reads above and `git diff --check`.

Refs #46
