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
    require(aliases.size <= 2) { "contained command permits at most two pinned executable aliases" }
    require(aliases.map { it.source }.distinct().size == aliases.size) { "executable aliases have duplicate runtime sources" }
    require(aliases.map { it.destination }.distinct().size == aliases.size) { "executable aliases have duplicate destinations" }
    for (leftIndex in aliases.indices) for (rightIndex in leftIndex + 1 until aliases.size) {
        val left = aliases[leftIndex]
        val right = aliases[rightIndex]
        require(left.source != right.destination && left.destination != right.source &&
            !left.destination.startsWith(right.destination) && !right.destination.startsWith(left.destination)) {
            "executable aliases have chained or overlapping destinations"
        }
    }
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

/** Keep historical runtime-closure names byte-stable as alias cardinality grows. */
internal fun containedCommandRuntimeProvider(baseProvider: String, aliases: List<ContainedCommandExecutableAlias>): String =
    when (aliases.size) {
        0 -> baseProvider
        1 -> "kotlin-lease-contained-command-runtime-owned-executable-v1"
        2 -> "kotlin-lease-contained-command-runtime-owned-executable-v2"
        else -> throw IllegalArgumentException("contained command permits at most two pinned executable aliases")
    }
