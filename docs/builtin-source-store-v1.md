# Built-in checkpoint source store v1

`BuiltinCapturedRepairHarness` can receive a `BuiltinSourceStoreConfiguration` alongside its journal
and checkpoint configuration. Before publishing each checkpoint, it stores the exact captured
source snapshot. A fresh adapter can then use `BuiltinCapturedResume.fromStore(reference)` without
receiving candidate bytes from the prior invocation. The original accepted source remains the
staging authority's baseline and must still be supplied and verified independently.

The store contains immutable UTF-8 source blobs named by their content SHA-256 and deterministic
snapshot manifests named by the complete source snapshot hash. Manifests bind the root, relative
path, size and hash of each file. Identical file bodies share a blob; older snapshots remain intact.
The snapshot identity in the journal binds this storage evidence to the request, provider/model,
accepted revision, stage and loop state. The store's limits also enter the captured tool-authority
binding, so they cannot silently increase on continuation.

Publication happens in this order:

1. Bound file count, individual and total source bytes, UTF-8 and declared-secret checks before
   persisting project bytes. Bound the serialized manifest as well.
2. Under an exclusive store lock, inventory physical entries and bytes, including unreferenced or
   partial blobs. Validate any content-addressed entry being reused against its actual bytes.
3. Admit all new entries/bytes together, then create and force missing blobs before the manifest.
   Existing entries are never overwritten. Force the directory before returning.
4. The loop writes its checkpoint record and separately publishes the durable commitment only after
   source publication succeeds. Cancellation keeps its explicit stop classification.

Recovery bounds the manifest and file inventory, reads exact blob lengths, recomputes every content
hash and the full snapshot identity, and checks the canonical manifest encoding. Missing, altered,
truncated or malformed evidence fails before stage restoration or provider execution. The captured
adapter then rehydrates the verified bytes through its existing shared callbacks and bounded sink;
source retrieval does not replay model tool calls or grant publication authority.

The existing directory must be private and owned by the current user, outside tool workspaces and
disjoint from journal/checkpoint directories. Files use mode 0600, no-follow opens, regular-file and
single-link checks, descriptor reads and identity/size checks. An active store writer fails bounded
admission. The workflow must protect directory ancestors, as for the journal and checkpoint store.
There is no background writer, eviction, automatic corruption repair or unbounded directory walk.
Interrupted entries consume physical capacity until a separate authorized lifecycle operation handles
them; they cannot be silently adopted as valid content or ignored by quota accounting.

Only supplied project source enters this store. Provider keys, endpoints, environment maps and
transient runtime configuration are never serialized. Declared secrets in source contents, root/path
names or their JSON-escaped spelling cause rejection before source publication. The store does not
redact source and later pretend that altered bytes are the original program. Arbitrary encodings of
undeclared secrets are not classified. This private store is not automatically added to a downloadable
archive or used as proof that an oracle/reference or candidate revision has been accepted.

Nine tests cover reopening/deduplication and immutable snapshots, each storage ceiling, corrupt/
missing/truncated blobs and manifests, unsafe storage and active locks, orphan capacity accounting,
declared-secret rejection, captured continuation from only a durable reference, failed publication,
recovery after damaged evidence is corrected, and cancellation during capture. Local core v7 has
108 cases: 102 passed, six live-terminal skips, no failures/errors. Including the three existing ACP
captured-filesystem cases gives 111 total, 105 passed and six skips:

```sh
./gradlew --offline test --tests 'decompengine.builtin.*' --tests 'decompengine.agent.*' \
  --tests 'decompengine.acp.AcpCapturedRepairFilesystemTest' --console=plain
```

Required-host v7 qualification remains separate. #75/#77 still require project archive manifest and
verification integration, original/redacted-context recovery rules, repair-history transcript linkage,
compile/full retained-regression acceptance, publication/rollback lineage and comparative release
evidence. Source blobs make checkpoint candidates durable; they do not close those acceptance gaps.
