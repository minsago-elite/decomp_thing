package decompengine.builtin

import decompengine.agent.AgentWorkspacePath
import java.util.Collections
import java.util.TreeMap

/** Candidate bytes supplied by trusted workflow storage; acceptance still comes from the original base. */
class BuiltinCapturedResume(val checkpoint: BuiltinCheckpointReference, files: Map<String, ByteArray>) {
    private val captured: Map<String, ByteArray>
    init {
        require(files.size <= 100_000)
        var bytes = 0L
        files.forEach { (path, content) ->
            AgentWorkspacePath("project", path)
            require('\\' !in path && path.split('/').none { it in setOf("", ".", "..") })
            require(content.size <= 256L * 1024 * 1024 - bytes); bytes += content.size
        }
        captured = Collections.unmodifiableMap(files.mapValuesTo(TreeMap()) { (_, content) -> content.copyOf() })
    }
    internal fun files(): Map<String, ByteArray> = captured.mapValuesTo(TreeMap()) { (_, content) -> content.copyOf() }
    override fun toString() = "BuiltinCapturedResume(checkpoint=$checkpoint, source=redacted)"
}
