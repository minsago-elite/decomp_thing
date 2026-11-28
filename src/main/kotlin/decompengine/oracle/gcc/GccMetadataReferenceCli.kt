package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.reference.ReferenceCorpusCoordinator
import decompengine.oracle.reference.ReferenceCorpusDeployment
import decompengine.oracle.reference.ReferenceCorpusRetainedFailure
import decompengine.oracle.reference.ReferenceNativeRuntime
import decompengine.oracle.reference.ReferenceNativeRuntimeStage
import java.io.PrintStream
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Fixed GCC metadata reference owner. Staging is transport only; capture requires trusted provisioning. */
object GccMetadataReferenceCli {
    private const val USAGE = "Usage: stage <profileRoot> <uncompressedOciLayout> <freshStagingRoot> | " +
        "capture <profileRoot> <ociLayout> <provisionedRuntimeRoot> <deploymentJson> <journalRoot> <scratchMount>"

    @JvmStatic
    fun main(arguments: Array<String>) {
        val command = parseArguments(arguments)
        // Parse and authenticate deployment authority before allocating or admitting capture inputs.
        val deployment = if (command is Command.Capture) ReferenceCorpusDeployment.open(command.deploymentJson) else null
        GccMetadataReferenceProfile.open(command.profileRoot).use { profile ->
            when (command) {
                is Command.Stage -> writeStage(ReferenceNativeRuntime.materialize(command.ociLayout, command.stagingRoot, profile), System.out)
                is Command.Capture -> ReferenceNativeRuntime.admit(command.ociLayout, command.runtimeRoot, profile).use { runtime ->
                    val selected = requireNotNull(deployment)
                    val output = try {
                        ReferenceCorpusCoordinator.capture(profile, runtime, selected.configuration,
                            command.journalRoot, command.scratchMount, selected.expectedCgroupParent)
                    } catch (failure: ReferenceCorpusRetainedFailure) {
                        // Keep the cleanup owner alive through one explicit whole-cgroup absence attempt.
                        try { failure.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
                        System.err.println("Reference capture failed; journal and scratch remain retained for trusted reset.")
                        throw failure
                    }
                    println("Captured reference observations: $output")
                    println("Reference capture does not qualify a candidate or authorize release.")
                }
            }
        }
    }

    internal sealed class Command(val profileRoot: Path, val ociLayout: Path) {
        class Stage(profileRoot: Path, ociLayout: Path, val stagingRoot: Path) : Command(profileRoot, ociLayout)
        class Capture(profileRoot: Path, ociLayout: Path, val runtimeRoot: Path, val deploymentJson: Path,
            val journalRoot: Path, val scratchMount: Path) : Command(profileRoot, ociLayout)
    }

    internal fun parseArguments(arguments: Array<String>): Command {
        require(arguments.isNotEmpty()) { USAGE }
        require((arguments[0] == "stage" && arguments.size == 4) ||
            (arguments[0] == "capture" && arguments.size == 7)) { USAGE }
        fun path(index: Int): Path {
            val raw = arguments[index]
            require(raw.isNotEmpty() && raw.length <= 4096 && raw.none { it.code < 32 || it.code == 127 }) { USAGE }
            val path = Path.of(raw)
            require(path.isAbsolute && path.normalize() == path && path.toString() == raw && path != Path.of("/")) {
                "CLI paths must be exact normalized absolute non-root paths. $USAGE"
            }
            return path
        }
        return when (arguments[0]) {
            "stage" -> Command.Stage(path(1), path(2), path(3))
            else -> Command.Capture(path(1), path(2), path(3), path(4), path(5), path(6))
        }
    }

    /** Streaming JSON keeps even the maximum staged namespace from requiring a second large tree. */
    internal fun writeStage(stage: ReferenceNativeRuntimeStage, output: PrintStream) {
        // PrintStream.print uses the console's charset; protocol bytes must always remain UTF-8.
        fun writeUtf8(value: String) = output.write(value.toByteArray(Charsets.UTF_8))
        writeUtf8("{\n")
        writeUtf8("  \"executionAdmitted\": false,\n")
        writeUtf8("  \"provisioningEntries\": [\n")
        stage.provisioningEntries.forEachIndexed { index, entry ->
            val bytes = OracleJson.canonicalBytes(JsonObject(mapOf(
                "relativePath" to JsonPrimitive(entry.relativePath), "kind" to JsonPrimitive(entry.kind),
                "uid" to JsonPrimitive(entry.uid), "gid" to JsonPrimitive(entry.gid), "mode" to JsonPrimitive(entry.mode),
            )))
            val lines = bytes.decodeToString().trimEnd('\n').lines()
            lines.forEachIndexed { lineIndex, line ->
                writeUtf8("    $line")
                if (lineIndex == lines.lastIndex && index != stage.provisioningEntries.lastIndex) writeUtf8(",")
                writeUtf8("\n")
            }
        }
        writeUtf8("  ],\n")
        val tail = OracleJson.canonicalBytes(JsonObject(mapOf(
            "root" to JsonPrimitive(stage.root.toString()), "schemaVersion" to JsonPrimitive("reference-native-runtime-stage-v1"),
            "stageIdentitySha256" to JsonPrimitive(stage.identitySha256),
        ))).decodeToString().trimEnd('\n').lines()
        tail.drop(1).forEach { writeUtf8("$it\n") }
        check(!output.checkError()) { "could not write reference staging plan" }
    }
}
