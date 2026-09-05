package decompengine.oracle.fulltree

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Read-only restrictions within an already-authorized run root; never grants a new writable path. */
internal class ContainedCommandPriorControls(activeName: String?, previous: Map<String, LinuxFileIdentity>) {
    private val entries = previous.toSortedMap().toMap()
    init {
        require(entries.size <= 256) { "prior contained controls exceed their count bound" }
        require(entries.isEmpty() || activeName != null) { "prior controls require a separate active control directory" }
        require(activeName == null || validContainedControlName(activeName)) { "active contained control name is invalid" }
        entries.forEach { (name, id) ->
            require(validContainedControlName(name) && name != activeName) { "prior contained control name is invalid or active" }
            require(id.isDirectory && !id.isSymbolicLink && id.mode.permissions == 448) { "prior control identity is not private" }
        }
    }
    val isEmpty: Boolean get() = entries.isEmpty()

    fun verify(parent: LinuxDescriptor) {
        val current = parent.whileOpen(LinuxFilesystemSyscalls::identity)
        require(current.copy(linkCount = parent.identity.linkCount) == parent.identity && current.mode.permissions == 448) {
            "prior-control parent identity changed"
        }
        for ((name, expected) in entries) {
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name).use { child ->
                require(child.identity == expected && child.identity.uid == current.uid && child.identity.mountId == current.mountId) {
                    "prior contained control directory changed identity"
                }
            }
        }
    }

    fun toJson() = JsonArray(entries.map { (name, id) -> containedControlIdentityJson(name, id) })

    /** Applied after the root's writable bind, so each prior subtree is read-only in the child. */
    fun mountArguments(root: Path): List<String> = entries.keys.flatMap { name ->
        val path = root.resolve(name).toString()
        listOf("--ro-bind", path, path)
    }
}

internal fun validContainedControlName(name: String): Boolean = name.matches(Regex("control-[a-f0-9]{64}"))

internal fun containedControlIdentityJson(name: String, id: LinuxFileIdentity) = JsonObject(mapOf(
    "name" to JsonPrimitive(name), "device" to JsonPrimitive(id.key.device), "inode" to JsonPrimitive(id.key.inode),
    "mountId" to JsonPrimitive(id.mountId), "uid" to JsonPrimitive(id.uid), "gid" to JsonPrimitive(id.gid),
    "mode" to JsonPrimitive(id.mode.permissions), "linkCount" to JsonPrimitive(id.linkCount),
))
