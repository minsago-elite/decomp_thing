package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifactSnapshot
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Export identity only; a target projection grants neither planning nor production authority. */
internal data class GccBundledExportTarget(
    val id: String,
    val profileId: String,
    val buildOutput: String,
    val buildRecordPath: Path,
    val buildRecordSha256: String,
    val oracleManifestPath: Path,
    val oracleManifestSha256: String,
    val fullArtifact: GccCompilerEngineArtifactBinding,
    val strippedArtifact: GccCompilerEngineArtifactBinding,
) {
    init { require(id in setOf("driver", "cc1", "lto1")) }

    fun authenticateStrippedArtifact(path: Path): AuthenticatedGccCompilerEngineArtifact =
        authenticateLargeArtifact(path, strippedArtifact, "GCC $id stripped artifact")

    fun authenticateFullArtifact(path: Path): AuthenticatedGccCompilerEngineArtifact =
        authenticateLargeArtifact(path, fullArtifact, "GCC $id DWARF-rich artifact")

    fun toPolicyJson(): JsonObject = JsonObject(mapOf(
        "id" to JsonPrimitive(id),
        "profileId" to JsonPrimitive(profileId),
        "buildOutput" to JsonPrimitive(buildOutput),
        "buildRecordSha256" to JsonPrimitive(buildRecordSha256),
        "oracleManifestSha256" to JsonPrimitive(oracleManifestSha256),
        "fullArtifact" to fullArtifact.toPolicyJson(),
        "strippedArtifact" to strippedArtifact.toPolicyJson(),
    ))

    private fun GccCompilerEngineArtifactBinding.toPolicyJson(): JsonObject = JsonObject(mapOf(
        "path" to JsonPrimitive(relativePath),
        "bytes" to JsonPrimitive(bytes),
        "sha256" to JsonPrimitive(sha256),
    ))
}

/** Retained profile inputs and derived policy; this handle does not authorize worker START. */
internal class GccRetainedCompilerEngineProfile private constructor(
    val suite: GccCompilerEngineSuite,
    private val driverTarget: GccBundledExportTarget?,
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
    fun target(targetId: String): GccBundledExportTarget {
        requireCurrent()
        driverTarget?.let { selected ->
            require(targetId == selected.id) { "GCC target differs from the retained driver selection" }
            return selected
        }
        val engine = suite.engine(targetId)
        return GccBundledExportTarget(engine.id, "gcc-${engine.id}-${suite.version}", engine.buildOutput,
            engine.buildRecordPath, engine.buildRecordSha256, engine.oracleManifestPath, engine.oracleManifestSha256,
            engine.fullArtifact, engine.strippedArtifact)
    }

    @Synchronized
    fun exportWallClockMillis(targetId: String, fullRecovery: Boolean): Long {
        target(targetId)
        require(targetId != "driver" || fullRecovery) { "GCC driver requires full-recovery export" }
        require(!fullRecovery || targetId != "lto1") { "full-recovery export is unsupported for lto1" }
        return if (fullRecovery && targetId == "cc1") suite.budgets.fullRecoveryCc1ExportWallClockMillis
        else suite.budgets.exportWallClockMillis
    }

    @Synchronized
    fun requirePlanningTarget(targetId: String): GccCompilerEngine {
        requireCurrent()
        require(driverTarget == null && targetId != "driver") {
            "GCC driver export does not authorize compiler-engine planning"
        }
        return suite.engine(targetId)
    }

    @Synchronized
    fun bindInvocation(
        engineId: String,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        budgets: GccCompilerEngineContainmentBudgets,
        fullRecoveryExport: Boolean,
    ): ByteArray {
        requireCurrent()
        val engine = target(engineId)
        val byRole = artifacts.associateBy { it.role }
        require(byRole.size == artifacts.size) { "planner profile invocation repeats artifact roles" }
        val controls = mapOf(
            GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE to suite.profilePath,
            GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK to suite.sourceLockPath,
            GccCompilerEngineContainmentArtifactRole.BUILD_RECORD to engine.buildRecordPath,
            GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST to engine.oracleManifestPath,
            GccCompilerEngineContainmentArtifactRole.TOOLCHAIN_REPRODUCTION to suite.toolchainReproductionPath,
        )
        controls.forEach { (role, path) ->
            val artifact = byRole.getValue(role)
            val guard = guards.getValue(path)
            require(artifact.path == path && artifact.bytes == guard.size && artifact.sha256 == guard.authenticatedSha256) {
                "GCC operation $role differs from its retained planner profile"
            }
        }
        val binary = byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY)
        require(binary.bytes == engine.strippedArtifact.bytes && binary.sha256 == engine.strippedArtifact.sha256) {
            "GCC operation engine differs from its retained planner profile"
        }
        val archive = byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE)
        require(archive.bytes == suite.analysis.ghidraArchive.bytes && archive.sha256 == suite.analysis.ghidraArchive.sha256 &&
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE).sha256 == suite.analysis.exporterSha256
        ) { "GCC operation analysis tools differ from its retained planner profile" }
        require(budgets.wallClockMillis <= exportWallClockMillis(engineId, fullRecoveryExport) &&
            budgets.maximumResidentBytes <= suite.budgets.exportMaximumResidentBytes
        ) { "GCC operation exceeds its retained profile resource ceilings" }
        requireCurrent()
        return encoded.copyOf()
    }

    @Synchronized
    fun requireDisjoint(roots: List<Path>) {
        requireCurrent()
        require(guards.keys.none { input -> roots.any { root -> input.startsWith(root) || root.startsWith(input) } }) {
            "GCC planner profile overlaps an excluded operation root"
        }
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
        fun open(path: Path): GccRetainedCompilerEngineProfile = openRetained(path, null)

        fun open(path: Path, targetId: String): GccRetainedCompilerEngineProfile {
            require(targetId in setOf("driver", "cc1", "lto1")) { "GCC export target is unsupported" }
            return openRetained(path, targetId)
        }

        private fun openRetained(path: Path, targetId: String?): GccRetainedCompilerEngineProfile {
            requireGccBundledOperationPath(path)
            val guards = linkedMapOf<Path, StableControlFile>()
            var totalBytes = 0L
            try {
                val loader = GccCompilerEngineProfileLoader { selected, maximum, label ->
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
                }
                val suite = loader.load(path)
                val driver = if (targetId == "driver") loader.loadDriverTarget(suite) else null
                val reconstruction = suite.reconstructionProfile()
                val policy = OracleJson.canonicalBytes(JsonObject(mapOf(
                    "provider" to JsonPrimitive(if (driver == null) "gcc-retained-planner-profile-v1" else "gcc-retained-export-target-profile-v1"),
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
                ) + (driver?.let { mapOf("target" to it.toPolicyJson()) } ?: emptyMap())))
                return GccRetainedCompilerEngineProfile(suite, driver, guards.toMap(), policy).also { it.requireCurrent() }
            } catch (failure: Throwable) {
                guards.values.toList().asReversed().forEach { guard ->
                    runCatching { guard.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
                }
                throw failure
            }
        }
    }
}
