package decompengine.oracle.fulltree

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions

/** Filesystem construction only. This does not issue a lease, borrow or execution capability. */
internal fun createContainedCommandControlDirectory(parent: LinuxDescriptor, name: String): LinuxDescriptor {
    require(validContainedControlName(name)) { "contained control directory name is not a canonical execution name" }
    requireCurrentControlParent(parent)
    LinuxFilesystemSyscalls.createDirectory(parent.fd, name, 448)
    val child = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
    try {
        LinuxFilesystemSyscalls.chmod(child, 448)
        require(child.identity.uid == parent.identity.uid && child.identity.mountId == parent.identity.mountId &&
            child.identity.mode.permissions == 448 && LinuxFilesystemSyscalls.directoryEntryNames(child, 1).isEmpty()) {
            "contained control directory differs from its retained parent"
        }
        for (entry in listOf("state", "reports", "tmp")) {
            LinuxFilesystemSyscalls.createDirectory(child.fd, entry, 448)
            LinuxFilesystemSyscalls.openDirectoryAt(child.fd, entry).use { directory ->
                LinuxFilesystemSyscalls.chmod(directory, 448)
                require(directory.identity.uid == child.identity.uid && directory.identity.mountId == child.identity.mountId &&
                    directory.identity.mode.permissions == 448) { "contained control child identity differs" }
                LinuxFilesystemSyscalls.synchronize(directory)
            }
        }
        LinuxFilesystemSyscalls.synchronize(child)
        LinuxFilesystemSyscalls.synchronize(parent)
        requireContainedControlDirectory(parent, name, child)
        return child
    } catch (failure: Throwable) {
        child.close()
        throw failure // Partial construction remains for explicit recovery; never erase ambiguous residue.
    }
}

internal fun requireContainedControlDirectory(parent: LinuxDescriptor, name: String, child: LinuxDescriptor) {
    requireCurrentControlParent(parent)
    val current = child.whileOpen(LinuxFilesystemSyscalls::identity)
    require(current.copy(linkCount = child.identity.linkCount) == child.identity && current.isDirectory &&
        current.uid == parent.identity.uid && current.mountId == parent.identity.mountId && current.mode.permissions == 448) {
        "contained control descriptor identity changed"
    }
    LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name).use { named ->
        require(named.identity == current) { "contained control directory name was replaced" }
    }
}

private fun requireCurrentControlParent(parent: LinuxDescriptor) {
    val current = parent.whileOpen(LinuxFilesystemSyscalls::identity)
    require(current.copy(linkCount = parent.identity.linkCount) == parent.identity &&
        current.isDirectory && current.mode.permissions == 448) { "contained control parent must remain private and unchanged" }
}
