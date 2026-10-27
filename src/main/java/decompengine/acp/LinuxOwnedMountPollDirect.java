package decompengine.acp;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/** Private ABI bridge; registration uses the existing libc library in the Kotlin caller. */
final class LinuxOwnedMountPollDirect {
    private LinuxOwnedMountPollDirect() {
        throw new AssertionError("no instances");
    }

    // No LastErrorException: preserve raw returns and the caller's immediate per-thread errno read.
    static native int poll(Pointer descriptors, NativeLong count, int timeout);
}
