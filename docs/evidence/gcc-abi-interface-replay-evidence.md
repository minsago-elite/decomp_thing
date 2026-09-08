# GCC ABI interface replay evidence

This is a tiny fixture-backed evidence record for issue #680. It exercises the
existing program-neutral interface contract; it does not claim a GCC
production score or close the issue.

## Record

```yaml
record: gcc-abi-interface-replay-evidence-v1
status: unresolved
scope: checked-in neutral structural fixture only
productionAuthority: false
productionVerified: false
```

The checked fixture inputs and target descriptor have these exact identities:

| Input | SHA-256 |
| --- | --- |
| `oracle/targets/sysv-amd64-v1.json` | `d251d5e6a0edc17655c355fb8fd757d557f064a6e67095ad53c8ca1e7569a343` |
| `tests/oracle/fixtures/structural_recovery/oracle.json` | `9a479186e5d0595a0820e399e2d789f2a108497f0089f4b64e8247e3fbfa129d` |
| `tests/oracle/fixtures/structural_recovery/identity-map.json` | `836f2f29dc233c29a9da8356c7f4f8d51d0d7c80ce8c338963568f2b7ec93ae9` |
| `tests/oracle/fixtures/structural_recovery/recovered.json` | `ea0cbf88f2212a271e966e348be00ac943aa0c375ffe631d32fdf44b87996a65` |
| selected boundary report | `b05d85d9f21e704c2581b84ded3ea5442eb4695ed75e74d25778e417a5a8d593` |

## One interface slice

The selected boundary mapping joins oracle function `die-cu0-10-alpha` to
recovered function `fn_0000000000400010`. The five ABI interface dimensions
are scored from their existing evidence locators:

| Dimension | Oracle projection | Recovered projection | Outcome |
| --- | --- | --- | --- |
| prototype | `prototype:signed-i32-from-signed-i32` | `prototype:signed-i32-from-signed-i32` | exact |
| calling convention | `convention:sysv`, ABI `sysv-amd64` | `convention:__cdecl`, ABI `sysv-amd64` | ABI-equivalent |
| variadic | `false` | `false` | exact |
| parameter 0 ABI class | `signed-i32`, `INTEGER`, 32-bit size/alignment | `int32`, `INTEGER`, 32-bit size/alignment | ABI-equivalent |
| return ABI class | `signed-i32`, `INTEGER`, 32-bit size/alignment | `signed-i32`, `INTEGER`, 32-bit size/alignment | exact |

This entity therefore receives `5/5` interface credit: three exact and two
ABI-equivalent outcomes. The fixture-wide report retains 24 oracle facts and
26 recovered facts: 14 exact, 4 ABI-equivalent, 3 recovered-unknown, 1
oracle-unobservable, 2 contradicted, and 3 fabricated. Credit is `18/24`;
claim precision is `18/26`. These figures are fixture measurements only.

The scorer keeps unknown, unobservable, contradicted, and fabricated states in
the report and denominator. It joins the function through the selected
boundary mapping, uses the explicit SysV AMD64 descriptor, and records
fixture-only verification (`productionVerified: false`).

## Unavailable production gates

The production result remains unavailable. The production registry is
intentionally empty in
`src/main/kotlin/decompengine/oracle/structural/StructuralReplayAdapterRegistry.kt`;
its test-only fixed transcript cannot create production capability. The
generic fixture scorer also refuses production-scoped inputs.

The repository has no checked authenticated GCC production structural
oracle/recovered model/identity-map/score for these interface facts and no
host-owned replay receipt binding the exporter, bundled-Ghidra loader and
target, image base, input binary, sandbox, output tree, model, and identity
mapping. The fixture hashes above therefore cannot promote a caller-supplied
JSON model into production authority. Missing or ambiguous interface facts
remain unresolved until that gate exists.

Any future production adapter must use the bundled Ghidra Java APIs inside the
isolated worker boundary. It must not require `GHIDRA_HOME` or delegate to an
external `analyzeHeadless` installation; authenticated oracle evidence remains
separate from candidate or fixture data.

Refs #680
