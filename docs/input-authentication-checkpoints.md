# Checkpoints during pinned input authentication

`StableControlFile.openWithCheckpoint(path, maximumBytes, label, checkpoint)`
lets a caller check its deadline or cancellation during initial and terminal
authentication. The callback runs before each authentication and after each
bounded hashing read, at most 1 MiB, plus once after hashing. It receives a short
stage description. The caller owns the deadline and failure policy.

The existing three-argument `open` factory keeps its behavior with a no-op
callback. Descriptor selection, permissions, retained read leases, mutation
checks and identity verification remain unchanged. The private constructor and
existing private selection helper retain their access boundaries. Callback
failures follow the existing open/use cleanup paths; closing a handle does not
invoke the callback. Initial failures retain the existing control-exception
wrapper and cause; terminal callback exceptions propagate to the caller.

These are cooperative checks between operations. They do not interrupt a blocked
native read or establish whole-process resource limits. This infrastructure is
part of [#84](https://github.com/minsago-elite/decomp_thing/issues/84) and is now used
by the analyzer's [bounded ELF inspection](bounded-elf-metadata.md).

## Focused verification

```sh
./gradlew --no-daemon test \
  --tests 'decompengine.oracle.fulltree.StableControlFileCheckpointTest' \
  --tests 'decompengine.oracle.fulltree.StableControlFileTest.stable input hashing checkpoints every MiB' \
  --tests 'decompengine.oracle.fulltree.StableControlFileTest.public surface exposes no descriptor or selection mutation seam'
```

The five selected tests cover ordinary authored-file hashing, callback delivery,
failed-open recovery, terminal cancellation, closed-handle behavior and the
existing JVM access surface. They do not exercise concurrent mutation or prove
descriptor/lease leak absence independently. No production binary analysis or
release qualification is established by these tests.
