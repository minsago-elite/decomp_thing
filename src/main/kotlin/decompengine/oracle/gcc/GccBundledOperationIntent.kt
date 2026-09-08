package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeDiskScratchOperation
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class GccBundledOperationIntent(
    val operationId: String,
    val engineId: String,
    val runKind: GccCompilerEngineContainmentRunKind,
    artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
    val bundledRuntime: GccBundledGhidraRuntime,
    val budgets: GccCompilerEngineContainmentBudgets,
    val diskPolicy: FullTreeDiskScratchPolicy,
    plannerProfile: GccRetainedCompilerEngineProfile? = null,
    val cliInvocation: GccBundledCliInvocation? = null,
) {
    val artifacts: List<GccCompilerEngineContainmentArtifactIdentity>
    val environment: Map<String, String> = java.util.Map.copyOf(mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"))
    val workScopeSha256: String
    val requestSha256: String
    private val encoded: ByteArray
    private val profilePolicy: ByteArray?

    val canonicalBytes: ByteArray
        get() = encoded.copyOf()

    init {
        require(operationId.matches(Regex("[0-9a-f]{64}"))) { "GCC bundled operation ID is invalid" }
        require(engineId in setOf("cc1", "lto1")) { "GCC bundled engine ID is invalid" }
        require(bundledRuntime.invocationVersion in 1..3) { "fresh operation intent cannot select the resume-only runtime" }
        require(runKind != GccCompilerEngineContainmentRunKind.RESUMED) { "GCC bundled prepared operations require fresh analysis" }
        require(budgets.wallClockMillis % 1_000L == 0L) { "GCC bundled wall budget must use whole seconds" }
        require(diskPolicy.maximumFilesystemBytes <= 1024L * 1024 * 1024 * 1024 &&
            diskPolicy.maximumFilesystemInodes <= 2_000_000L && diskPolicy.requiredAvailableInodes >= 128L
        ) { "GCC bundled disk policy exceeds its bounded analysis envelope" }
        val copied = arrayListOf<GccCompilerEngineContainmentArtifactIdentity>()
        for (artifact in artifacts) {
            require(copied.size < GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.size) { "GCC bundled intent has too many artifacts" }
            requireGccBundledOperationPath(artifact.path)
            copied.add(artifact)
        }
        require(copied.size == GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.size &&
            copied.map { it.role }.toSet() == GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES &&
            copied.map { it.path }.toSet().size == copied.size
        ) { "GCC bundled intent must bind every distinct artifact role and path exactly once" }
        this.artifacts = java.util.List.copyOf(copied.sortedBy { it.role.wireName })
        bundledRuntime.requireArtifacts(this.artifacts)
        profilePolicy = plannerProfile?.bindInvocation(engineId, this.artifacts, budgets)
        val byRole = this.artifacts.associateBy { it.role }
        cliInvocation?.let { invocation ->
            val selected = invocation.options
            require(profilePolicy != null && selected.engineId == engineId && selected.diskPolicy == diskPolicy &&
                selected.binary == byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).path &&
                selected.profile == byRole.getValue(GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE).path &&
                selected.archive == byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE).path &&
                (selected.resumeAfterCheckpoint != null) == (runKind == GccCompilerEngineContainmentRunKind.INTERRUPTED)) {
                "CLI selection differs from operation intent"
            }
            invocation.requireCurrent()
        }
        workScopeSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-work-scope-v1"),
            "engineId" to JsonPrimitive(engineId),
            "engineSha256" to JsonPrimitive(byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).sha256),
            "profileSha256" to JsonPrimitive(byRole.getValue(GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE).sha256),
            "sourceLockSha256" to JsonPrimitive(byRole.getValue(GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK).sha256),
        ))))
        encoded = OracleJson.canonicalBytes(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(if (profilePolicy == null) 1 else 2),
            "provider" to JsonPrimitive(if (profilePolicy == null) "gcc-bundled-operation-intent-v1" else "gcc-bundled-operation-intent-v2"),
            "operationId" to JsonPrimitive(operationId),
            "engineId" to JsonPrimitive(engineId),
            "runKind" to JsonPrimitive(runKind.wireName),
            "workScopeSha256" to JsonPrimitive(workScopeSha256),
            "artifacts" to JsonArray(this.artifacts.map { artifact -> JsonObject(mapOf(
                "role" to JsonPrimitive(artifact.role.wireName),
                "path" to JsonPrimitive(artifact.path.toString()),
                "bytes" to JsonPrimitive(artifact.bytes),
                "sha256" to JsonPrimitive(artifact.sha256),
            )) }),
            "bundledRuntime" to bundledRuntime.toJson(),
            "budgets" to JsonObject(mapOf(
                "wallClockMillis" to JsonPrimitive(budgets.wallClockMillis),
                "maximumResidentBytes" to JsonPrimitive(budgets.maximumResidentBytes),
                "pidsMax" to JsonPrimitive(budgets.pidsMax),
            )),
            "diskPolicy" to JsonObject(mapOf(
                "requiredAvailableBytes" to JsonPrimitive(diskPolicy.requiredAvailableBytes),
                "maximumFilesystemBytes" to JsonPrimitive(diskPolicy.maximumFilesystemBytes),
                "requiredAvailableInodes" to JsonPrimitive(diskPolicy.requiredAvailableInodes),
                "maximumFilesystemInodes" to JsonPrimitive(diskPolicy.maximumFilesystemInodes),
            )),
            "environment" to JsonObject(environment.mapValues { JsonPrimitive(it.value) }),
        ) + (profilePolicy?.let { mapOf("plannerProfile" to OracleJson.parseCanonical(it)) } ?: emptyMap()) +
            (cliInvocation?.let { mapOf("cliInvocation" to OracleJson.parseCanonical(it.canonicalBytes)) } ?: emptyMap())), GCC_BUNDLED_INTENT_LIMITS)
        requestSha256 = OracleArtifacts.sha256(encoded)
    }

    /** Reopen and retain the independently parsed closure; serialized policy is never a START token. */
    fun openPlannerProfile(excludedRoots: List<Path>): GccRetainedCompilerEngineProfile? {
        val expected = profilePolicy ?: return null
        val path = artifacts.single { it.role == GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE }.path
        val retained = GccRetainedCompilerEngineProfile.open(path)
        try {
            retained.requireDisjoint(excludedRoots + bundledRuntime.root)
            require(retained.bindInvocation(engineId, artifacts, budgets).contentEquals(expected)) {
                "GCC planner profile differs from its prepared operation intent"
            }
            return retained
        } catch (failure: Throwable) {
            runCatching { retained.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
            throw failure
        }
    }

    fun diskOperation(): FullTreeDiskScratchOperation = FullTreeDiskScratchOperation(
        operationId, requestSha256, engineId, workScopeSha256,
    )
}

internal fun requireGccBundledOperationPath(path: Path) {
    require(path.isAbsolute && path.normalize() == path && path != Path.of("/") && path.nameCount <= 32 &&
        path.toString().toByteArray(Charsets.UTF_8).size <= 4096 &&
        path.toString().none { it.code < 32 || it.code == 127 || it == ':' || it == '\\' }
    ) { "GCC bundled operation path is not canonical" }
}

private val GCC_BUNDLED_INTENT_LIMITS = StrictJsonLimits(
    maximumInputBytes = 256 * 1024,
    maximumCanonicalBytes = 256 * 1024,
    maximumDepth = 16,
    maximumNodes = 8192,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = 192 * 1024,
    maximumNumberCharacters = 32,
)
