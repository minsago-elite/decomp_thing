# GCC ABI signature verification evidence

This is a small evidence slice for #693 at repository revision
`bf2501568f39ab52b23492dfc37839bb81895587`. It records the checked inputs and
the production acceptance boundary; it does not claim the 90% threshold.

## Checked facts

| Input | Repository fact |
| --- | --- |
| GCC source | `16.2.0`, revision `78d4ac73dd391005b895a6148cd9831e28e1208b` |
| Oracle manifest | `oracle/gcc/16.2.0/oracle-manifest.json`, SHA-256 `c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9` |
| Function boundary/name oracle | `oracle/gcc/16.2.0/function-recovery-oracle.json`, SHA-256 `b49b8a72a96580bd8727d9dc530753f40f78185a656f472ebe83a7a1f6fc9aae` |
| Target descriptor | `oracle/targets/sysv-amd64-v1.json`, SHA-256 `d251d5e6a0edc17655c355fb8fd757d557f064a6e67095ad53c8ca1e7569a343` |
| Rich/stripped artifacts | SHA-256 `8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b` / `3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4` |

The checked boundary oracle contains 12,844 records, 3,284 scoreable physical
starts, 140 reviewed compiler-generated exclusions, 9,420 inline-only
exclusions, and 24,163 aliases. These are boundary/name facts and do not form
a signature accuracy denominator.

## Signature contract and current gate

The structural contract scores these function dimensions:

- `function.prototype`
- `function.calling-convention`
- `function.variadic`
- `function.parameter-abi-class`
- `function.return-abi-class`

The production denominator must come from an authenticated structural oracle
bound to the manifest and target descriptor. Each oracle fact is either
`observable` with a value or `oracle-unobservable` with no value. Each recovered
fact is either `recovered` with a value or `recovered-unknown` with no value;
unknown and unobservable facts stay visible and receive no credit. An
`abi-equivalent` result requires different source projections and equal,
non-null ABI projections allowed by the selected target descriptor.

The production gate is currently unavailable. This checkout contains no
GCC production structural oracle, recovered production model with bound
exporter/loader attestation, reviewed identity map, structural score, or
strict generated-C declaration diagnostics. Therefore the signature numerator,
signature denominator, per-entity findings, and 90% result are unresolved.

`oracle/gcc/16.2.0/compiler-engines.json` retains the bundled Ghidra identity
and archive digest, but this record does not qualify a production analysis. A
future score must preserve that bundled runtime boundary and authenticated
oracle provenance; it must not depend on `GHIDRA_HOME` or external
`analyzeHeadless` execution.

## Reproduction of the checked facts

```bash
sha256sum oracle/gcc/16.2.0/oracle-manifest.json \
  oracle/gcc/16.2.0/function-recovery-oracle.json \
  oracle/targets/sysv-amd64-v1.json

python3 - <<'PY'
import json
from pathlib import Path

records = json.loads(Path("oracle/gcc/16.2.0/function-recovery-oracle.json").read_text())["functions"]
print(len(records))
print(sum(item["exclusion"] is None for item in records))
print(sum(len(item["aliases"]) for item in records))
PY
```

Refs #693
