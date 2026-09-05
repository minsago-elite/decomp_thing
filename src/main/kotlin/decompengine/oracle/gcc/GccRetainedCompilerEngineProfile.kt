package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifactSnapshot
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Retained profile inputs and derived policy; this handle does not authorize worker START. */
internal class GccRetainedCompilerEngineProfile private constructor(
    val suite: GccCompilerEngineSuite,
    private val guards: Map<Path, StableControlFile>,
    policy: ByteArray,
) : AutoCloseable {
    private val encoded = policy.copyOf()
    private var closed = false
    private var poisoned = false

    @Synchronized
    fun requireCurrent() {
        check(!closed && !poisoned) { "retained GCC profile is closed or invalidated" }
        try {
            guards.forEach { (path, guard) -> guard.verifyUnchanged("retained GCC profile $path") }
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    @Synchronized
    fun policyBytes(): ByteArray {
        requireCurrent()
        return encoded.copyOf()
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        guards.values.toList().asReversed().forEach { guard ->
            runCatching { guard.close() }.exceptionOrNull()?.let { next ->
                if (failure == null) failure = next else if (failure !== next) failure!!.addSuppressed(next)
            }
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(path: Path): GccRetainedCompilerEngineProfile {
            requireGccBundledOperationPath(path)
            val guards = linkedMapOf<Path, StableControlFile>()
            var totalBytes = 0L
            try {
                val suite = GccCompilerEngineProfileLoader { selected, maximum, label ->
                    requireGccBundledOperationPath(selected)
                    require(selected.toRealPath() == selected) { "retained GCC profile path contains indirection" }
                    val guard = guards[selected] ?: run {
                        require(guards.size < 16) { "retained GCC profile exceeds its file bound" }
                        StableControlFile.open(selected, maximum.toLong(), label).also { opened ->
                            guards[selected] = opened
                            totalBytes = Math.addExact(totalBytes, opened.size)
                            require(totalBytes <= 128L * 1024 * 1024) { "retained GCC profile exceeds its aggregate byte bound" }
                        }
                    }
                    require(guard.size <= maximum) { "retained GCC profile file exceeds its role bound" }
                    guard.verifyUnchanged("before parsing $label")
                    val snapshot = OracleArtifactSnapshot(guard.readExactly(0, guard.size.toInt(), label))
                    require(snapshot.sha256 == guard.authenticatedSha256) { "retained GCC profile changed during parsing" }
                    guard.verifyUnchanged("after parsing $label")
                    snapshot
                }.load(path)
                val reconstruction = suite.reconstructionProfile()
                val policy = OracleJson.canonicalBytes(JsonObject(mapOf(
                    "provider" to JsonPrimitive("gcc-retained-planner-profile-v1"),
                    "schemaVersion" to JsonPrimitive(1),
                    "profileSha256" to JsonPrimitive(suite.profileSha256),
                    "plannerId" to JsonPrimitive(suite.analysis.plannerId),
                    "plannerVersion" to JsonPrimitive(suite.analysis.plannerVersion),
                    "reconstructionProfileSha256" to JsonPrimitive(reconstruction.sha256),
                    "reconstructionProfile" to OracleJson.parse(reconstruction.canonicalJson().toByteArray()),
                    "inputs" to JsonArray(guards.entries.sortedBy { it.key.toString() }.map { (input, guard) ->
                        JsonObject(mapOf(
                            "path" to JsonPrimitive(input.toString()),
                            "bytes" to JsonPrimitive(guard.size),
                            "sha256" to JsonPrimitive(guard.authenticatedSha256),
                        ))
                    }),
                )))
                return GccRetainedCompilerEngineProfile(suite, guards.toMap(), policy).also { it.requireCurrent() }
            } catch (failure: Throwable) {
                guards.values.toList().asReversed().forEach { guard ->
                    runCatching { guard.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
                }
                throw failure
            }
        }
    }
}
