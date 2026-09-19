# GCC driver clean-build evidence

This is the small evidence record for #699 at repository revision
`bf2501568f39ab52b23492dfc37839bb81895587`. Its status is **unresolved**.
It records checked repository facts; it does not claim a genuine reconstructed
driver, a production build, or release eligibility.

## Authenticated input boundary

The checked source anchor is
[`oracle/gcc/16.2.0/source-lock.json`](../oracle/gcc/16.2.0/source-lock.json):

- oracle: `gcc-driver-16.2.0`;
- GCC revision: `78d4ac73dd391005b895a6148cd9831e28e1208b`;
- source archive SHA-256:
  `e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e`.

[`oracle-manifest.json`](../oracle/gcc/16.2.0/oracle-manifest.json) binds that
source lock and `build-record.json`, and records the reference rich/stripped
driver pair. The pair's recorded identities are 20,713,760 bytes with SHA-256
`8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b` and
2,349,296 bytes with SHA-256
`3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4`.
These are oracle inputs, not reconstructed-source outputs.

## Build contract available in this repository

The registered `generated-c-make-v1` profile records `cc`, GNU Make, C11,
`-g -Wall -Wextra -Werror -Iinclude`, and project-relative path mapping.
`GeneratedCBuildInvocation` declares GNU Make, the configured compiler, a POSIX
shell, `find`, `mkdir`, and `rm` as dependencies. The strict fixture contract
records the effective command, source revision SHA-256, source stability,
linked artifact identity, and owner-attributable diagnostics under
`reports/build/modules/`; `reports/build_contract.json` maps sources to owners.
`StrictProjectBuildTest` also checks the documented four-way parallel command,
warnings-as-errors, link-failure ownership, and clean extracted fixture rebuild.

This contract is sufficient to describe a future accepted production receipt:
the receipt must bind the exact source revision, profile and effective flags,
declared dependency inventory, successful output identity, source stability, and
every module's diagnostics. A fixture receipt cannot fill those fields for the
genuine driver.

## Production gate status

The following states remain explicit and unresolved:

| Gate | Current repository fact | Required evidence |
| --- | --- | --- |
| Genuine source and ABI | #46 and #47 remain open; no complete accepted reconstructed driver tree is checked in | #46 ABI/interface facts plus #47/#64 accepted source, provenance, and unresolved inventory |
| Clean production build/link | Existing strict-build tests use authored fixtures; no fresh isolated genuine-driver compile/link receipt is present | Exact parallel command, tool/runtime inventory, output identity, source stability, and per-module diagnostics |
| Contained production toolchain | #49 retains a test-only C validator and an unavailable production qualification gate | Authenticated compiler/runtime/header closure and bounded whole-process-tree cleanup |
| Archive and release | #50 and #54 remain open and consume the missing genuine build | Independent archive rebuild and the authenticated structural/behavior release gate |

No unresolved entity is treated as a successful implementation, and no fixture
result is promoted to production evidence. Analysis remains behind the bundled
Ghidra Java API boundary; this record adds no `GHIDRA_HOME` or external
`analyzeHeadless` dependency and does not weaken authenticated oracle
boundaries or provenance.
