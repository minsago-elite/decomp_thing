# Built-in durable journal v1

`BuiltinAgentHarness` accepts an optional trusted `BuiltinJournalConfiguration`. A configured
invocation requires a fresh journal file and writes its execution evidence before returning a
receipt. A storage, serialization, integrity or close failure cannot produce a successful receipt.
The default factory does not configure journals yet. The captured-repair wrapper accepts explicit
trusted configuration as described in [captured recovery](builtin-captured-recovery-v1.md).
For fresh graph-owned repair attempts, [repair lineage provisioning](builtin-repair-lineage-v1.md)
derives the journal identity from the shared request and captured bytes instead of caller placeholders.

The caller supplies provider/model names and SHA-256 identities for the initial source snapshot,
staged workspace and last accepted revision. START binds those identities to the shared immutable
request/access-policy digest. These are trusted caller assertions, not source verification or
publication authorization. Configuration containing a declared secret in an identity is rejected.

Records use UTF-8 JSON lines with sorted object keys, explicit version/sequence/kind, the previous
record digest, payload and SHA-256 of the canonical record without its own digest. Each append is
forced to storage before execution proceeds; creation also forces the containing directory. Limits
apply to original and redacted record serialization, total bytes and record count. Exhaustion leaves
the committed prefix intact when no write began; a partial write remains invalid evidence.

The Linux/POSIX storage boundary requires an existing owner-only directory outside every declared
workspace, a fresh owner-only regular file, no symlink components, one hard link, and an exclusive
file lock. Appends check file identity and length. The workflow must protect the directory and its
ancestors from replacement by tools or other writers; this API is not a sandbox against the owning
user or an attacker who controls an ancestor. It never overwrites or automatically repairs evidence.

The loop records:

- The initial context checkpoint, full structured messages/tool schemas, context hash, usage and
  remaining limits, linked to START's source/stage/provider/revision identities.
- Every state transition and model request, retry, assembled response, tool proposal and usage.
- Tool policy decisions and full tool intent before execution, followed by bounded results.
- Completion-validation intent and its result with candidate change hashes and an explicit lack of
  publication authority, then the terminal stop, usage and cleanup outcome.

Declared secrets are redacted in strings and object keys, including the JSON-escaped spelling used
inside structured text. Overlapping matches are covered; colliding redacted keys fail closed. A full
assembled model response is redacted as one payload, so a secret split across streamed deltas cannot
leak through separate journal records. An interrupted response leaves a pending request without raw
partial text. Exceptions, credentials, runtime endpoints and environment maps are never recorded.
Callers must declare their sensitive inputs; arbitrary encodings of secrets are not classified.

Receipts contain only record count, byte count, head digest, terminal-record completeness and an
indeterminate-operation flag. Completeness means that a terminal record was persisted; it does not
mean a successful execution, resolved side effect, accepted source revision or qualified release.

Inspection requires a commitment from a separate trusted source plus the expected request and
workflow identities. It verifies the exact file length/count/head, every record's encoding and chain,
and operation pairing under bounded parsing. An active writer, altered identities, edits, truncation,
extra bytes or malformed records fail validation. A terminal failure does not clear an unresolved
model request, tool operation or completion validation. Reading evidence never executes an effect.

Only the initial context checkpoint is emitted. There is no automatic restart API, trusted checkpoint
commitment store, stage rehydration, post-edit snapshot checkpoint, accepted/rejected publication
record or archive integration yet. Redacted messages cannot silently substitute for original source
inputs. Wall-clock remaining limits are measured, so complete live journals are not promised to be
byte-identical across runs; canonical serialization is deterministic for identical record inputs.
These gaps keep #75 open.

Eleven journal tests cover deterministic serialization, identities, nested/overlapping/escaped
redaction, tamper/truncation/appends, active writers and unsafe storage, all storage ceilings, pending
operations, actual-loop full transcripts, interrupted tool effects, pre-call admission, post-effect
write failure, partial streams and interrupted completion validation. The v4 required-host inventory
has 81 cases. Local verification passes 75 with six live-terminal skips on the host without bwrap:

```sh
./gradlew --offline test --tests 'decompengine.builtin.*' --tests 'decompengine.agent.*' --console=plain
```

The v4 hosted result must be attached separately; local skips do not qualify its required lane.

The subsequent [checkpoint continuation contract](builtin-checkpoint-v1.md) adds opt-in actual-stage
snapshot checks, separately persisted commitments and a validated resume API. The earlier recovery
limitations above describe this journal's initial checkpoint; the continuation contract states what
is now implemented and what still requires workflow/source/archive integration.

Journal v4 required-host run
[33951760152](https://github.com/minsago-elite/decomp_thing/actions/runs/33951760152), at
`41158e92fad44e30c0b7d15dec7c167445410348`, passed 81 cases with zero failures, errors or skips.
Downloaded artifact `9965204620`, digest
`sha256:59bb36124ba1bdbcf5f88cd89349bcaa5fa04d0615381385f9761f3ee03c72f8`, was independently checked
against every suite XML digest and actual case count. This is dated v4 evidence; it does not
qualify the subsequent checkpoint v5 inventory.
