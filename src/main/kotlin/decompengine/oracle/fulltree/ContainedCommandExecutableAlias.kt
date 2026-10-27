package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** A digest-identical owned snapshot, bound read-only at an existing root-runtime executable path. */
internal data class ContainedCommandExecutableAlias(val source: Path, val destination: Path) {
    fun json() = JsonObject(mapOf("source" to JsonPrimitive(source.toString()), "destination" to JsonPrimitive(destination.toString())))
}

internal fun requireContainedCommandExecutableAliases(
    inputs: List<KotlinSystemdCgroupCommandInput>,
    aliases: List<ContainedCommandExecutableAlias>,
) {
    require(aliases.size <= 1) { "contained command permits at most one pinned executable alias" }
    aliases.forEach { alias ->
        require(alias.source != alias.destination) { "executable snapshot must differ from its runtime source" }
        val source = inputs.single { it.path == alias.source }
        val destination = inputs.single { it.path == alias.destination }
        require(source.bytes == destination.bytes && source.sha256 == destination.sha256) {
            "executable alias must preserve the exact pinned runtime bytes"
        }
        requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(alias.destination)).use { original ->
            require(original.identity.uid == 0 && original.identity.isRegularFile && !original.identity.isSymbolicLink &&
                original.identity.linkCount == 1 && original.identity.mode and 0x12 == 0 && original.identity.mode and 0x49 != 0) {
                "executable alias destination must be a pinned single-linked host-root executable"
            }
        }
    }
}
