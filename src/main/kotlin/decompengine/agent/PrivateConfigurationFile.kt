package decompengine.agent

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxResourceLimitException
import decompengine.acp.permissions
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes

/** Descriptor-bound, owner-only configuration read shared by harness provisioning. */
internal fun readPrivateConfigurationFile(
    path: Path,
    maximumBytes: Int,
    label: String,
    afterPinned: () -> Unit = {},
    afterRead: () -> Unit = {},
): ByteArray {
    require(maximumBytes in 1..4 * 1024 * 1024)
    require(path.isAbsolute && path.normalize() == path)
    try {
        val authorized = LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)
            ?: throw IllegalArgumentException("$label does not exist")
        authorized.use { pinned ->
            requirePrivateConfigurationIdentity(pinned.identity, label)
            afterPinned()
            LinuxFilesystemSyscalls.openReadableFrom(pinned).use { readable ->
                val identityBefore = LinuxFilesystemSyscalls.identity(readable.fd)
                requirePrivateConfigurationIdentity(identityBefore, label)
                require(identityBefore.key == pinned.identity.key && identityBefore.mountId == pinned.identity.mountId) {
                    "$label identity changed before it was read"
                }
                val descriptorPath = LinuxFilesystemSyscalls.stableDescriptorPath(readable.fd)
                val before = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                require(before.isRegularFile && !before.isSymbolicLink) {
                    "$label must name a regular file without following links"
                }
                require(before.size() in 1..maximumBytes.toLong()) {
                    "$label must contain between 1 and $maximumBytes bytes"
                }
                val bytes = try {
                    LinuxFilesystemSyscalls.read(readable, maximumBytes + 1) {}
                } catch (failure: LinuxResourceLimitException) {
                    throw IllegalArgumentException(
                        "$label exceeds the $maximumBytes-byte limit",
                        failure,
                    )
                }
                afterRead()
                val identityAfter = LinuxFilesystemSyscalls.identity(readable.fd)
                val after = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                require(
                    identityAfter == identityBefore &&
                        after.isRegularFile &&
                        !after.isSymbolicLink &&
                        after.fileKey() == before.fileKey() &&
                        after.size() == before.size() &&
                        after.lastModifiedTime() == before.lastModifiedTime() &&
                        bytes.size.toLong() == before.size()
                ) { "$label changed while it was read" }
                return bytes
            }
        }
    } catch (failure: IllegalArgumentException) {
        throw failure
    } catch (failure: Exception) {
        throw IllegalArgumentException("$label could not be read securely", failure)
    }
}

private fun requirePrivateConfigurationIdentity(identity: LinuxFileIdentity, label: String) {
    require(identity.isRegularFile && !identity.isDirectory && !identity.isSymbolicLink) {
        "$label must name a regular file without following links"
    }
    require(identity.mode.permissions and 0x3f == 0) {
        "$label must not grant group or other permissions"
    }
    val currentUid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
    require(identity.uid == currentUid) { "$label must be owned by the current user" }
    require(identity.linkCount == 1) { "$label must have exactly one filesystem link" }
}
