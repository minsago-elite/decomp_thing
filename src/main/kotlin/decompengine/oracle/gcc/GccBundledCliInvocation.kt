package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal data class GccBundledCliOptions(
    val engineId: String, val binary: Path, val profile: Path, val archive: Path,
    val output: Path, val scratch: Path, val diskPolicy: FullTreeDiskScratchPolicy,
    val resumeAfterCheckpoint: Long?, val fullRecoveryExport: Boolean = false,
    val runtimeDiagnostics: Boolean = false,
    val nativeCallObservations: Boolean = false,
    /** A later invocation's selection of one unfinished interrupted operation; never part of a retained invocation. */
    val recoverOperationId: String? = null,
) {
    val commandName: String get() = when {
        nativeCallObservations -> "gcc-engine-native-calls"
        runtimeDiagnostics -> "gcc-engine-runtime-diagnostic"
        fullRecoveryExport -> "gcc-engine-full-export"
        else -> "gcc-engine-plan"
    }

    companion object {
        fun engineUsage(fullRecoveryExport: Boolean, runtimeDiagnostics: Boolean = false,
            nativeCallObservations: Boolean = false): String = when {
            runtimeDiagnostics -> "cc1"
            fullRecoveryExport || nativeCallObservations -> "<cc1|driver>"
            else -> "<cc1|lto1>"
        }

        fun engineArgumentUsage(fullRecoveryExport: Boolean, nativeCallObservations: Boolean = false): String =
            engineUsage(fullRecoveryExport = fullRecoveryExport, nativeCallObservations = nativeCallObservations)
                .removeSurrounding("<", ">")

        fun parse(arguments: List<String>, fullRecoveryExport: Boolean = false,
            runtimeDiagnostics: Boolean = false, nativeCallObservations: Boolean = false): GccBundledCliOptions {
            require(!runtimeDiagnostics || fullRecoveryExport) { "runtime diagnostics require full recovery" }
            require(!nativeCallObservations || (!fullRecoveryExport && !runtimeDiagnostics)) {
                "distinct export commands cannot be combined"
            }
            require(arguments.size in 2..32 && arguments.sumOf { it.toByteArray().size.toLong() + 1 } <= 65536)
            val positionals = mutableListOf<String>()
            val values = linkedMapOf<String, String>()
            val allowed = setOf("--profile", "--ghidra-archive", "--output", "--scratch", "--resume-after-checkpoint",
                "--scratch-min-bytes", "--scratch-max-bytes", "--scratch-min-inodes", "--scratch-max-inodes", "--recover-operation")
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
            require(positionals.size == 2 && positionals[0] in setOf("cc1", "lto1", "driver")) {
                "expected cc1, lto1 or driver and its stripped binary"
            }
            require(!fullRecoveryExport || positionals[0] in setOf("cc1", "driver")) {
                "full-recovery structural export requires cc1 or driver"
            }
            require(!runtimeDiagnostics || positionals[0] == "cc1") { "runtime diagnostics require cc1" }
            require(positionals[0] != "driver" || fullRecoveryExport || nativeCallObservations) {
                "driver admission requires a fresh full-recovery or native-call export"
            }
            require(!nativeCallObservations || positionals[0] in setOf("cc1", "driver")) {
                "native call observations require cc1 or driver"
            }
            fun path(value: String) = Path.of(value).toAbsolutePath().normalize()
            fun required(name: String) = path(requireNotNull(values[name]) { "$name is required" })
            fun number(name: String, default: Long? = null): Long? = values[name]?.let {
                require(it.matches(Regex("[1-9][0-9]*"))) { "$name requires a positive decimal integer" }
                it.toLong()
            } ?: default
            val threshold = number("--resume-after-checkpoint")?.also { GccBundledCheckpointTrigger(it) }
            require(!fullRecoveryExport || threshold == null) { "full-recovery export cannot resume from a planning checkpoint" }
            require(!nativeCallObservations || threshold == null) { "native call observations cannot resume from a planning checkpoint" }
            val recovery = values["--recover-operation"]?.also {
                require(it.matches(Regex("[a-f0-9]{64}"))) { "--recover-operation requires a 64-character lowercase hex operation ID" }
                require(!fullRecoveryExport && !runtimeDiagnostics && !nativeCallObservations && threshold != null) {
                    "--recover-operation requires the original interrupted gcc-engine-plan selection with --resume-after-checkpoint"
                }
            }
            return GccBundledCliOptions(positionals[0], path(positionals[1]), required("--profile"), required("--ghidra-archive"),
                required("--output"), required("--scratch"), FullTreeDiskScratchPolicy(
                    number("--scratch-min-bytes", 8L * 1024 * 1024 * 1024)!!,
                    number("--scratch-max-bytes", 64L * 1024 * 1024 * 1024)!!,
                    number("--scratch-min-inodes", 32768)!!, number("--scratch-max-inodes", 1_000_000)!!), threshold,
                fullRecoveryExport = fullRecoveryExport, runtimeDiagnostics = runtimeDiagnostics,
                nativeCallObservations = nativeCallObservations, recoverOperationId = recovery).also {
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

/** The launcher's process working directory: its canonical path and the identity of the directory it names. */
internal data class GccBundledCliWorkingDirectory(val path: Path, val identity: LinuxFileIdentity) {
    init {
        require(path.isAbsolute && path.normalize() == path) { "CLI working directory must be canonical" }
    }

    fun toJson(): JsonObject = JsonObject(mapOf(
        "path" to JsonPrimitive(path.toString()), "device" to JsonPrimitive(identity.key.device),
        "inode" to JsonPrimitive(identity.key.inode), "mountId" to JsonPrimitive(identity.mountId),
        "uid" to JsonPrimitive(identity.uid), "gid" to JsonPrimitive(identity.gid), "mode" to JsonPrimitive(identity.mode),
    ))

    companion object {
        fun current(): GccBundledCliWorkingDirectory {
            val path = Path.of("").toAbsolutePath().toRealPath()
            // /proc/self/cwd is the kernel's record of this process's working directory, not a pathname guess.
            require(Files.isSameFile(path, Path.of("/proc/self/cwd"))) { "CLI working directory differs from the process working directory" }
            return GccBundledCliWorkingDirectory(path, LinuxFilesystemSyscalls.openRoot(path).use { it.identity })
        }
    }
}

/** Immutable CLI selection, working directory and directory identity, committed as part of the operation request. */
internal class GccBundledCliInvocation(val options: GccBundledCliOptions, arguments: List<String>,
    identities: Map<Path, LinuxFileIdentity>,
    val workingDirectory: GccBundledCliWorkingDirectory = GccBundledCliWorkingDirectory.current()) {
    private val directories = java.util.Map.copyOf(identities)
    val path: Path = options.output.resolve("invocation.json")
    private val encoded = OracleJson.canonicalBytes(JsonObject(mapOf(
        "provider" to JsonPrimitive("gcc-bundled-cli-invocation-v2"), "schemaVersion" to JsonPrimitive(2),
        "workingDirectory" to workingDirectory.toJson(),
        "argv" to JsonArray((listOf(options.commandName) + arguments)
            .map(::JsonPrimitive)),
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
        require(options.recoverOperationId == null) { "a later-invocation recovery selection is never a retained invocation" }
        require(directories.keys == setOf(options.output, options.output.resolve("inputs"), options.output.resolve("journal")))
        require(GccBundledCliOptions.parse(arguments, fullRecoveryExport = options.fullRecoveryExport,
            runtimeDiagnostics = options.runtimeDiagnostics, nativeCallObservations = options.nativeCallObservations) == options) {
            "CLI argv differs from its selected options"
        }
    }

    fun requireCurrent() {
        directories.forEach { (path, expected) ->
            require(path.toRealPath() == path)
            LinuxFilesystemSyscalls.openRoot(path).use { current ->
                require(current.identity.copy(linkCount = expected.linkCount) == expected) { "CLI directory identity changed" }
            }
        }
    }

    fun requireCheckpointSelection(minimumCompletedFunctions: Long) {
        require(options.resumeAfterCheckpoint == minimumCompletedFunctions) {
            "checkpoint threshold differs from the bound CLI selection"
        }
    }
}
