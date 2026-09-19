# Oracle cutover evidence record for #136

This is a small migration record captured from repository commit `bf2501568f39ab52b23492dfc37839bb81895587` on 2026-09-08. It is evidence of existing contracts, not production release evidence.

```yaml
schemaVersion: 1
issue: 136
kind: oracle-cutover-evidence
authority: non-authoritative-migration-evidence
releaseEligible: false
state: unresolved
```

The current Kotlin/JVM artifact layer establishes these facts:

- `OracleJson` bounds UTF-8 input, rejects duplicate keys through its strict parser, and requires canonical bytes in `parseCanonical` (`src/main/kotlin/decompengine/oracle/core/OracleJson.kt`).
- `OracleArtifacts` snapshots exact bytes with a SHA-256 digest, authenticates bounded reads before and after opening the file, and publishes through a durable same-directory atomic move (`src/main/kotlin/decompengine/oracle/core/OracleArtifacts.kt`). Its source documents the cooperating file and directory owners that remain in the trust boundary.
- `OracleSchemas` resolves schema names from the bundled JVM classpath, validates only after strict parsing, and hashes the canonical policy together with the exact bundled schema bytes (`src/main/kotlin/decompengine/oracle/core/OracleSchemas.kt`).

The repository also records the remaining authority boundary. The LLVM workflow installs and runs Python only as explicitly non-authoritative compatibility checks (`.github/workflows/llvm-oracle-model.yml`), so this evidence does not establish a Python-free production release graph. The A13 production evidence set, all-shard production generation and validation, release orchestration, and the complete hosted parity/determinism gates remain unresolved.

Production qualification is unavailable for this record. No bundled-Ghidra production analysis, authenticated ACP read-only benchmark mount, Kotlin-only A13 regeneration, or hosted release gate was run here. Any future production path must retain bundled Ghidra Java API isolation, authenticated oracle boundaries, provenance bindings, and explicit unresolved states; this record cannot authorize or certify those outcomes.
