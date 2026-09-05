package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal data class GccBundledCliOptions(
    val engineId: String, val binary: Path, val profile: Path, val archive: Path,
    val output: Path, val scratch: Path, val diskPolicy: FullTreeDiskScratchPolicy,
    val resumeAfterCheckpoint: Long?,
) {
    companion object {
        fun parse(arguments: List<String>): GccBundledCliOptions {
            require(arguments.size in 2..32 && arguments.sumOf { it.toByteArray().size.toLong() + 1 } <= 65536)
            val positionals = mutableListOf<String>()
            val values = linkedMapOf<String, String>()
            val allowed = setOf("--profile", "--ghidra-archive", "--output", "--scratch", "--resume-after-checkpoint",
                "--scratch-min-bytes", "--scratch-max-bytes", "--scratch-min-inodes", "--scratch-max-inodes")
            var index = 0
            while (index < arguments.size) {
                val argument = arguments[index++]
                require(argument.isNotBlank() && argument.none { it.code < 32 || it.code == 127 })
                if (argument.startsWith('-')) {
                    require(argument in allowed && argument !in values) { "unknown or duplicate option: $argument" }
                    require(index < arguments.size && !arguments[index].startsWith('-')) { "$argument requires a value" }
                    val value = arguments[index++]
                    require(value.isNotBlank() && value.none { it.code < 32 || it.code == 127 })
                    values[argument] = value
                } else positionals += argument
            }
            require(positionals.size == 2 && positionals[0] in setOf("cc1", "lto1")) { "expected cc1 or lto1 and its stripped binary" }
            fun path(value: String) = Path.of(value).toAbsolutePath().normalize()
            fun required(name: String) = path(requireNotNull(values[name]) { "$name is required" })
            fun number(name: String, default: Long? = null): Long? = values[name]?.let {
                require(it.matches(Regex("[1-9][0-9]*"))) { "$name requires a positive decimal integer" }
                it.toLong()
            } ?: default
            val threshold = number("--resume-after-checkpoint")?.also { GccBundledCheckpointTrigger(it) }
            return GccBundledCliOptions(positionals[0], path(positionals[1]), required("--profile"), required("--ghidra-archive"),
                required("--output"), required("--scratch"), FullTreeDiskScratchPolicy(
                    number("--scratch-min-bytes", 8L * 1024 * 1024 * 1024)!!,
                    number("--scratch-max-bytes", 64L * 1024 * 1024 * 1024)!!,
                    number("--scratch-min-inodes", 32768)!!, number("--scratch-max-inodes", 1_000_000)!!), threshold).also {
                require(it.diskPolicy.maximumFilesystemBytes <= 1024L * 1024 * 1024 * 1024 &&
                    it.diskPolicy.maximumFilesystemInodes <= 2_000_000)
                require(!it.output.startsWith(it.scratch) && !it.scratch.startsWith(it.output)) { "output and scratch must be disjoint" }
                listOf(it.binary, it.profile, it.archive).forEach { input ->
                    require(!input.startsWith(it.output) && !input.startsWith(it.scratch)) { "inputs must be outside output and scratch" }
                }
            }
        }
    }
}

/** Immutable CLI selection and directory identity, committed as part of the operation request. */
internal class GccBundledCliInvocation(val options: GccBundledCliOptions, arguments: List<String>,
    identities: Map<Path, LinuxFileIdentity>) {
    private val directories = java.util.Map.copyOf(identities)
    val path: Path = options.output.resolve("invocation.json")
    private val encoded = OracleJson.canonicalBytes(JsonObject(mapOf(
        "provider" to JsonPrimitive("gcc-bundled-cli-invocation-v1"), "schemaVersion" to JsonPrimitive(1),
        "argv" to JsonArray((listOf("gcc-engine-plan") + arguments).map(::JsonPrimitive)),
        "engineId" to JsonPrimitive(options.engineId), "binary" to JsonPrimitive(options.binary.toString()),
        "profile" to JsonPrimitive(options.profile.toString()), "archive" to JsonPrimitive(options.archive.toString()),
        "output" to JsonPrimitive(options.output.toString()), "scratch" to JsonPrimitive(options.scratch.toString()),
        "resumeMode" to JsonPrimitive(if (options.resumeAfterCheckpoint == null) "fresh" else "same-owner-checkpoint"),
        "resumeAfterCheckpoint" to JsonPrimitive(options.resumeAfterCheckpoint),
        "directories" to JsonArray(directories.entries.sortedBy { it.key.toString() }.map { (path, identity) ->
            JsonObject(mapOf("path" to JsonPrimitive(path.toString()), "device" to JsonPrimitive(identity.key.device),
                "inode" to JsonPrimitive(identity.key.inode), "mountId" to JsonPrimitive(identity.mountId),
                "uid" to JsonPrimitive(identity.uid), "gid" to JsonPrimitive(identity.gid), "mode" to JsonPrimitive(identity.mode)))
        }),
    )))
    val canonicalBytes: ByteArray get() = encoded.copyOf()

    init {
        require(directories.keys == setOf(options.output, options.output.resolve("inputs"), options.output.resolve("journal")))
        require(GccBundledCliOptions.parse(arguments) == options) { "CLI argv differs from its selected options" }
    }

    fun requireCurrent() {
        directories.forEach { (path, expected) ->
            require(path.toRealPath() == path)
            LinuxFilesystemSyscalls.openRoot(path).use { current ->
                require(current.identity.copy(linkCount = expected.linkCount) == expected) { "CLI directory identity changed" }
            }
        }
    }
}
