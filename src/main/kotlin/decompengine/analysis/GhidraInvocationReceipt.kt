package decompengine.analysis

import java.util.Collections

internal enum class GhidraCommandKind { BUNDLED_JAVA, CUSTOM, CONTROLLED_TEST_JAVA }
internal enum class GhidraProcessStarterKind { DEFAULT_PROCESS_BUILDER, INJECTED }

internal class PreparedGhidraCommand private constructor(
    val command: List<String>,
    val kind: GhidraCommandKind,
    val mainClassIndex: Int?,
    val analysisArgumentsIndex: Int?,
): List<String> by command {
    override fun toString(): String = "PreparedGhidraCommand(kind=$kind, elements=${command.size})"

    init {
        if (kind == GhidraCommandKind.CUSTOM) require(mainClassIndex == null && analysisArgumentsIndex == null)
        else require(mainClassIndex != null && analysisArgumentsIndex != null && mainClassIndex in command.indices &&
            analysisArgumentsIndex in command.indices && analysisArgumentsIndex > mainClassIndex && mainClassIndex > 0 &&
            command[mainClassIndex].isNotEmpty() && command[analysisArgumentsIndex] == "analyze") {
            "Ghidra invocation command layout is invalid"
        }
    }

    companion object {
        fun custom(command: List<String>, checkpoint: (() -> Unit)? = null) =
            PreparedGhidraCommand(immutableBoundedStrings(command, checkpoint), GhidraCommandKind.CUSTOM, null, null)
        fun bundled(command: List<String>, mainClassIndex: Int, analysisArgumentsIndex: Int, checkpoint: (() -> Unit)? = null) =
            PreparedGhidraCommand(immutableBoundedStrings(command, checkpoint), GhidraCommandKind.BUNDLED_JAVA, mainClassIndex, analysisArgumentsIndex)
        fun controlledTest(command: List<String>, mainClassIndex: Int, analysisArgumentsIndex: Int, checkpoint: (() -> Unit)? = null) =
            PreparedGhidraCommand(immutableBoundedStrings(command, checkpoint), GhidraCommandKind.CONTROLLED_TEST_JAVA, mainClassIndex, analysisArgumentsIndex)

        fun validateWorkingDirectory(value: String, command: PreparedGhidraCommand, checkpoint: () -> Unit) {
            require(value.length <= 65_536) {
                "Ghidra invocation working directory exceeds the retained diagnostic bound"
            }
            var i = 0
            var nextCheckpoint = 0
            while (i < value.length) {
                if (i >= nextCheckpoint) {
                    checkpoint()
                    nextCheckpoint = i + 1023 // A surrogate pair may cross the threshold by one unit.
                }
                val ch = value[i]
                require(ch != '\u0000') { "Ghidra invocation contains an invalid diagnostic character" }
                if (Character.isHighSurrogate(ch)) {
                    require(i + 1 < value.length && Character.isLowSurrogate(value[i + 1])) {
                        "Ghidra invocation contains an invalid diagnostic character"
                    }
                    i++
                } else require(!Character.isLowSurrogate(ch)) {
                    "Ghidra invocation contains an invalid diagnostic character"
                }
                i++
            }
            var commandCharacters = 0
            command.command.forEach { item ->
                checkpoint()
                commandCharacters = Math.addExact(commandCharacters, item.length)
            }
            require(commandCharacters + value.length <= 131_072) {
                "Ghidra invocation exceeds the retained character bound"
            }
        }
    }
}

internal class GhidraInvocationReceipt private constructor(
    val prepared: PreparedGhidraCommand,
    val workingDirectory: String,
    val exitCode: Int,
    val starterKind: GhidraProcessStarterKind,
) {
    override fun toString(): String = "GhidraInvocationReceipt(kind=${prepared.kind}, exitCode=$exitCode)"

    companion object {
        fun captured(command: PreparedGhidraCommand, directory: String, exitCode: Int, starter: GhidraProcessStarterKind) =
            GhidraInvocationReceipt(command, directory, exitCode, starter)
    }
}

internal data class ModelWithInvocationReceipt(val model: decompengine.project.RecoveredProgramModel, val receipt: GhidraInvocationReceipt?)

private fun immutableBoundedStrings(source: List<String>, checkpoint: (() -> Unit)?): List<String> {
    require(source.size <= 256) { "Ghidra invocation exceeds the retained element bound" }
    val snapshot = ArrayList<String>(source.size)
    var total = 0
    source.forEach { value ->
        checkpoint?.invoke()
        require(value.length <= 65_536) { "Ghidra invocation element exceeds the retained character bound" }
        total = Math.addExact(total, value.length)
        require(total <= 131_072) { "Ghidra invocation exceeds the retained character bound" }
        var i = 0
        var nextCheckpoint = 0
        while (i < value.length) {
            if (i >= nextCheckpoint) {
                checkpoint?.invoke()
                nextCheckpoint = i + 1023
            }
            val ch = value[i]
            require(ch != '\u0000') { "Ghidra invocation contains an invalid diagnostic character" }
            if (Character.isHighSurrogate(ch)) {
                require(i + 1 < value.length && Character.isLowSurrogate(value[i + 1])) {
                    "Ghidra invocation contains an invalid diagnostic character"
                }
                i++
            } else require(!Character.isLowSurrogate(ch)) { "Ghidra invocation contains an invalid diagnostic character" }
            i++
        }
        snapshot += value
    }
    return Collections.unmodifiableList(snapshot)
}
