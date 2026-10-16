# Owned mount-event poll call consolidation

`ManifestDirectoryScope` already owns one eight-byte poll scratch alongside its borrowed
mount-event descriptor. The scratch now encodes the same complete native-order `pollfd`
into a reusable eight-byte heap array and copies it with one `Memory.write`, replacing
three native field writes. It resets descriptor, requested `POLLPRI | POLLERR` and zero
`revents` once before the existing EINTR loop. Interrupted attempts retain the original
loop behavior; the next logical poll resets all eight bytes again.

The owned call optionally uses `LinuxOwnedMountPollDirect`, registered against the
existing libc proxy's `NativeLibrary`. Its ABI remains `Pointer`, `NativeLong`, `int`
with descriptor count one and timeout zero. Failure to register selects the original
proxy. Initial libc loading still occurs outside that optional failure handler. The
bridge declares no `LastErrorException`; the caller reads errno immediately after a
negative return, before any other native-memory or cleanup call.

The scope still performs every poll and root/registry/generation/identity checkpoint.
Raw results and all event bits remain intact, including zero-result behavior. EINTR
retries, invalid/hangup refusals, original diagnostic primary identity, query/close
serialization, idempotent native-buffer cleanup and borrowed descriptor ownership are
unchanged. Generic mount and pidfd poll callers retain their original implementations.

## Qualification boundary

The four added syscall controls cover the complete reusable reset and raw events,
reset placement across EINTR, an exact copy failure without a fabricated syscall
observation, and the actual direct ABI with immediate EFAULT errno and stale-errno
success. Existing native test bodies and assertions remain. Required Actions must
execute these controls and the existing boundary/harness tests; source inspection
alone does not qualify the change.

One bulk write and direct dispatch describe source-level call consolidation. There
is no controlled timing comparison or attribution of the ordinary prelaunch timeout
to these calls. The existing 25-second deadline, buffers, hashes and query cadence
remain. Reliable deadline fit, controller/own-proc measurement, provider/model/auth
behavior and production qualification require their own evidence.

## Upstream ABI reference

The pinned JNA 5.19.1 release resolves to
`1a91122853f6ab6f1fb2a4a284a6cf2ed8af0a4d`.
[Native registration](https://github.com/java-native-access/jna/blob/1a91122853f6ab6f1fb2a4a284a6cf2ed8af0a4d/src/com/sun/jna/Native.java)
supports IntegerType argument conversion and an existing NativeLibrary binding.
[The direct dispatcher](https://github.com/java-native-access/jna/blob/1a91122853f6ab6f1fb2a4a284a6cf2ed8af0a4d/native/dispatch.c)
captures errno after the native call. The ABI test exercises this release in the
required native lane rather than accepting a silently selected proxy fallback.
