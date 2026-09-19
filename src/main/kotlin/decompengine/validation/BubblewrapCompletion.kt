package decompengine.validation

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal const val MAXIMUM_BUBBLEWRAP_COMPLETION_BYTES = 4096

/** Own only these two paths; retain the execution failure if cleanup also fails. */
internal fun <T> withCompletionChannel(action: (Path) -> T): T {
    val directory = Files.createTempDirectory("behavior-completion-")
    val channel = directory.resolve("status.jsonl")
    var primaryFailure: Throwable? = null
    try {
        Files.createFile(channel)
        return action(channel)
    } catch (failure: Throwable) {
        primaryFailure = failure
        throw failure
    } finally {
        var cleanupFailure: Throwable? = null
        for (path in listOf(channel, directory)) {
            try {
                Files.deleteIfExists(path)
            } catch (failure: Throwable) {
                val prior = cleanupFailure
                if (prior == null) cleanupFailure = failure else prior.addSuppressed(failure)
            }
        }
        cleanupFailure?.let { failure ->
            val primary = primaryFailure
            if (primary != null) primary.addSuppressed(failure) else throw failure
        }
    }
}

internal fun completionLaunchCommand(command: List<String>, launcher: java.nio.file.Path, channel: java.nio.file.Path): List<String> {
    require(command.size >= 3)
    return listOf(launcher.toString(), "-c", "exec 3>\"${'$'}1\"; shift; exec \"${'$'}@\"", "behavior-completion", channel.toString()) +
        command.take(3) + listOf("--json-status-fd", "3") + command.drop(3)
}

/** Parsed observations only: the caller must independently own and bound the channel. */
internal data class BubblewrapCompletionObservation(val childPid: Int, val applicationExitCode: Int)

internal fun parseBubblewrapCompletion(bytes: ByteArray, wrapperExitCode: Int): BubblewrapCompletionObservation {
    require(bytes.isNotEmpty() && bytes.size <= MAXIMUM_BUBBLEWRAP_COMPLETION_BYTES) {
        "bubblewrap completion channel is absent or exceeds its byte bound"
    }
    val text = bytes.decodeToString(throwOnInvalidSequence = true)
    require(text.endsWith('\n')) { "bubblewrap completion channel is truncated" }
    val lines = text.dropLast(1).split('\n')
    require(lines.size == 2) { "bubblewrap completion requires exactly one launch and one terminal record" }
    val limits = StrictJsonLimits(
        maximumInputBytes = MAXIMUM_BUBBLEWRAP_COMPLETION_BYTES,
        maximumCanonicalBytes = MAXIMUM_BUBBLEWRAP_COMPLETION_BYTES,
        maximumDepth = 2,
        maximumNodes = 32,
        maximumStringBytes = 32,
        maximumTotalStringBytes = 256,
        maximumNumberCharacters = 20,
    )
    fun record(line: String): JsonObject = OracleJson.parse(line.toByteArray(Charsets.UTF_8), limits) as? JsonObject
        ?: throw IllegalArgumentException("bubblewrap completion record must be an object")
    fun JsonObject.integer(key: String): Long {
        val value = getValue(key) as? JsonPrimitive
        require(value != null && !value.isString) { "bubblewrap completion $key must be an integer" }
        return requireNotNull(value.longOrNull) { "bubblewrap completion $key must be an integer" }
    }
    val launch = record(lines[0])
    val namespaceKeys = setOf("mnt-namespace", "pid-namespace", "net-namespace", "ipc-namespace", "uts-namespace", "cgroup-namespace")
    require(launch.keys.containsAll(setOf("child-pid", "mnt-namespace", "pid-namespace")) &&
        launch.keys.all { it == "child-pid" || it in namespaceKeys }) { "unexpected bubblewrap launch record" }
    val childPid = launch.integer("child-pid")
    require(childPid in 1..Int.MAX_VALUE.toLong()) { "invalid bubblewrap child PID" }
    for (key in launch.keys - "child-pid") require(launch.integer(key) > 0) { "invalid bubblewrap namespace identifier" }
    val terminal = record(lines[1])
    require(terminal.keys == setOf("exit-code")) { "unexpected bubblewrap terminal record" }
    val exitCode = terminal.integer("exit-code")
    // Bubblewrap folds signal termination into 128+signal. Until raw wait status
    // is retained, genuine application exits in that range also stay unqualified.
    require(exitCode in 0..127) { "bubblewrap termination is not an unambiguous normal application exit" }
    require(exitCode == wrapperExitCode.toLong()) { "wrapper and application completion disagree" }
    return BubblewrapCompletionObservation(childPid.toInt(), exitCode.toInt())
}
