package decompengine.acp;

import com.sun.jna.Pointer;

/** Private ABI bridge for the existing owned statx query; registration belongs to its Kotlin caller. */
final class LinuxOwnedStatxDirect {
    private LinuxOwnedStatxDirect() {
        throw new AssertionError("no instances");
    }

    // No LastErrorException: preserve raw return values and immediate per-thread errno handling.
    static native int statx(int fd, byte[] path, int flags, int mask, Pointer statistics);
}
