package decompengine.project

import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes

/**
 * Proof that a reconstruction workspace owns the canonical output directory.
 * Instances can only be minted by the workspace open path.
 */
internal sealed class ReconstructionPublicationLock private constructor(
    private val root: Path,
    private val input: Path,
    private val inputIdentity: Identity,
    private val inputSha256: String,
    private val rootIdentity: Identity,
    private val channel: FileChannel,
    private val lock: FileLock,
) {
    @Volatile
    private var closed = false

    /** Revalidate the capability immediately before any output publication or movement. */
    @Synchronized
    fun validate() {
        check(!closed) { "reconstruction output ownership is closed" }
        check(channel.isOpen && lock.isValid) { "reconstruction output ownership lock is no longer valid" }
        check(root.toRealPath() == root) { "reconstruction output root changed its canonical path" }
        check(input.toRealPath() == input) { "reconstruction input changed its canonical path" }
        check(identity(root) == rootIdentity) { "reconstruction output root identity changed" }
        check(identity(input) == inputIdentity) { "reconstruction input identity changed" }
    }

    /**
     * Borrow the already-held workspace lease for publication. This does not acquire another
     * operating-system lock; it verifies that the caller names this exact root and input
     * commitment, and that the input bytes still have that commitment.
     */
    @Synchronized
    fun borrow(requestedRoot: Path, requestedInputSha256: String): ReconstructionPublicationLock {
        validate()
        require(requestedRoot.toAbsolutePath().normalize() == root) {
            "publication root must use the workspace's canonical path"
        }
        require(requestedInputSha256 == inputSha256) {
            "publication input identity does not match the workspace"
        }
        check(sha256(input) == inputSha256) { "reconstruction input bytes changed during the workspace lease" }
        return this
    }

    @Synchronized
    fun closeOwnership() {
        closed = true
    }

    private data class Identity(val device: Any?, val inode: Any?, val fileKey: Any?)

    companion object {
        /** Called only by ReconstructionOutputWorkspace.openInternal after acquiring its lock. */
        internal fun opened(
            root: Path,
            input: Path,
            inputSha256: String,
            channel: FileChannel,
            lock: FileLock,
        ): ReconstructionPublicationLock {
            val canonicalRoot = root.toRealPath()
            val canonicalInput = input.toRealPath()
            val identity = identity(canonicalRoot)
            val inputIdentity = identity(canonicalInput)
            return Opened(canonicalRoot, canonicalInput, inputIdentity, inputSha256, identity, channel, lock)
        }

        private fun sha256(path: Path): String {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            Files.newInputStream(path, java.nio.file.StandardOpenOption.READ, NOFOLLOW_LINKS).use { stream ->
                val bytes = ByteArray(65_536)
                while (true) {
                    val count = stream.read(bytes)
                    if (count < 0) break
                    digest.update(bytes, 0, count)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        private fun identity(path: Path): Identity {
            val attrs = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
            // Unix dev/ino are the stable directory identity required for publication. fileKey
            // remains a portability fallback for filesystems without the Unix attribute view.
            val device = runCatching { Files.getAttribute(path, "unix:dev", NOFOLLOW_LINKS) }.getOrNull()
            val inode = runCatching { Files.getAttribute(path, "unix:ino", NOFOLLOW_LINKS) }.getOrNull()
            return Identity(device, inode, attrs.fileKey())
        }

        private class Opened(
            root: Path,
            input: Path,
            inputIdentity: Identity,
            inputSha256: String,
            identity: Identity,
            channel: FileChannel,
            lock: FileLock,
        ) : ReconstructionPublicationLock(root, input, inputIdentity, inputSha256, identity, channel, lock)
    }
}
