# Exact signed GCC source verification

`GccSignedSource.open` authenticates the existing GCC 16.2.0 source lock, vendored release key, annotated tag, detached archive signature, compressed archive, three revision/version markers and four license texts. It returns a held object with a private JVM constructor. Every access first requires its exact object identity to have been issued after complete factory verification, then rechecks every retained descriptor. Closing revokes issuance before releasing descriptors. Verification and private identity registration share one owner, with no unchecked registration accessor. Its canonical JSON is diagnostic evidence; neither a report nor a constructor clone can acquire issuance.

The release uses distinct primary and signing keys. `GccSourceOpenPgp` verifies the pinned DSA primary's retained identity certifications and subkey bindings, the RSA signing subkey's embedded primary-key cross-certification, and the exact RSA/SHA256 tag/archive signatures. The historical primary certifications use SHA1; this closed, byte-pinned release profile does not authorize arbitrary legacy keys or signatures. The tag object is reconstructed from its exact payload and signature and bound to revision `78d4ac73dd391005b895a6148cd9831e28e1208b`.

This result authenticates source bytes only. It does not extract files, filter source by permissions, execute a compiler, authenticate a runtime or build, establish translation-unit/object/link ownership, populate declaration/use identities, bind a model, seal, score or authorize a release. Those gates remain under #1513 and #692, including the full admitted source population, generic-template identities and ODR correspondence. A recovered type graph, physical CU, module or path is not a precise source owner.

## Closed GCC archive profile

The exact archive has 165,079 logical members (158,985 regular files and 6,094 directories) and 330,158 raw headers. Each logical member is preceded by one local PAX header. The supported PAX sequence is optional `path`, then `mtime`, `atime`, `ctime`. `path` occurs when the logical name exceeds the USTAR field or is one of three reviewed UTF-8 names, binds that field's exact byte prefix and is validated as the final canonical path. Non-ASCII paths are limited to `gcc/testsuite/gdc.test/runnable/imports/你好.d` and `gcc/testsuite/go.test/test/fixedbugs/issue27836.dir/{Äfoo.go,Ämain.go}`. Strict UTF-8 decoding and exact byte comparisons perform no Unicode normalization or case folding; all other non-ASCII names are refused. Duplicate paths, missing parents, path aliases, unknown/duplicate/reordered keys, global PAX, GNU extensions, sparse entries, links and special files are refused.

The actual archive has 14,905,270 PAX payload bytes, a maximum PAX payload of 232 bytes, and 863 path records: 860 long ASCII paths and three short UTF-8 paths. Expanded bytes are 1,201,551,360. Raw directory names end in `/`; normalized tar-library names can conceal that byte. Each regular mode is 0644 or 0755; directories are 0755. The scanner checks the reviewed ownership/header encodings without using mode bits to choose the source population.

| Independent bound | Ceiling |
| --- | ---: |
| Compressed archive | 512 MiB (actual source additionally pinned to 107,200,820 bytes) |
| Expanded bytes including headers, metadata and padding | 4 GiB |
| XZ decoder memory | 256 MiB |
| Logical members / PAX headers | 200,000 each |
| Raw headers | 400,000 |
| One retained PAX payload | 1 MiB |
| Aggregate PAX payload | 32 MiB |
| Logical entry bytes | 512 MiB |
| Path / component | 4,096 / 255 UTF-8 bytes |
| Charged path index | 64 MiB |
| Retained selected contents | 1 MiB |
| Charged work | 100,000,000 units |
| Verification and held-object lifetime | 300 seconds |

Callers can lower these bounds. The PAX payload and index charges bound retained attacker-controlled material; they are not JVM RSS guarantees. The dedicated qualification worker has a 512 MiB heap ceiling and records measured process high-water RSS separately. Metadata is consumed one bounded record at a time. No full metadata population or extracted source tree is retained. The existing LLVM archive profile and its single global-PAX-header limit are unchanged.

## Focused qualification

The `gccSignedSourceQualification` Gradle task requires `DECOMP_GCC_SIGNED_SOURCE_ARCHIVE` and `DECOMP_GCC_SIGNED_SOURCE_SIGNATURE` as absolute paths. It always executes the four source-related test classes in one bounded worker. The actual-source test opens two independent held verifications and requires byte-identical canonical reports, exercises all five phase substitutions and post-handoff substitution, and checks result copy isolation, genuine factory issuance, revocation on close, and refusal of retained-report constructor clones. Compiled-API controls refuse public synthetic construction paths and unchecked issuer accessors; private-reflection controls independently refuse empty-guard fabricated results before their caller checkpoint executes. Authored archive/crypto controls cover malformed inputs and exact/one-over resource boundaries.

The `GCC signed source qualification` workflow runs on its explicit `qualify:gcc-signed-source` PR label or manual dispatch and checks out the exact requested source head. `ci-fetch-gcc-signed-source.py` restores/fetches only the two exact files beneath `build/gcc-signed-source-inputs`; its transport hash checks confer no authority. Every cached or downloaded input is reauthenticated by Kotlin. The new workspace cache is saved only after that gate succeeds, and transport evidence states which route actually occurred.

`validate-gcc-signed-source.py` clears stale results, executes the task, requires the complete actual XML inventory with zero failures/errors/skips, checks both reports and lifecycle proof, and requires a clean unchanged source head. Retained evidence is in `build/gcc-signed-source-qualification` and `build/test-results/gccSignedSourceQualification`. A successful run closes only this source-verification increment (#1748).
