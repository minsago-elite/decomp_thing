package decompengine.repair

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxResourceLimitException
import decompengine.acp.permissions
import decompengine.project.AcpExecutionReceiptDocument
import decompengine.project.AgentTurnIntent
import decompengine.project.AcpChangeAssessment
import decompengine.project.agentFileChangeSetSha256
import decompengine.project.verifyAcpExecutionReceiptDocument
import decompengine.project.UniqueJsonObjectKeyValidator
import decompengine.project.ReconstructionProfile
import decompengine.project.ProjectFileRole
import decompengine.project.moduleIdForPath
import decompengine.project.sha256
import decompengine.agent.receiptCommitmentBytes
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentTurnIdentity
import decompengine.agent.isCanonicalAgentTurnId
import decompengine.agent.AgentWorkspacePath
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.FileSystems
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.Collections
import java.util.TreeMap
import java.util.TreeSet
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.math.min

internal const val MAXIMUM_REPAIR_PROJECTION_BYTES: Long = 64L * 1024 * 1024
internal const val MAXIMUM_REPAIR_ACP_RECEIPT_BYTES: Long = 64L * 1024 * 1024
internal const val MAXIMUM_REPAIR_INTENT_BYTES: Int = 1024 * 1024
internal const val MAXIMUM_REPAIR_ASSESSMENT_BYTES: Int = 1024 * 1024
private const val MAXIMUM_REPAIR_STATE_NON_RECEIPT_ENTRIES = 16

/** Existing revision-directory traversal role; blob and declared-body populations keep their own D. */
internal fun repairRevisionDirectoryEntryLimit(budget: RepairResourceBudget): Int =
    Math.addExact(Math.multiplyExact(budget.maximumRevisionNodes, 3), MAXIMUM_REPAIR_STATE_NON_RECEIPT_ENTRIES)

/** History schema is independent from the graph schema: graph v7 adds the provenance columns. */
private fun repairHistorySchemaForGraph(graphSchema: Int): Int =
    if (graphSchema >= 7) 4 else minOf(graphSchema, 3)
private val REPAIR_BLOB_DIGEST = Regex("[0-9a-f]{64}")
private val BLOB_ATOMIC_TEMPORARY = Regex("\\.([0-9a-f]{64})\\.repair-atomic\\.tmp")
private val REPAIR_RECEIPT_PATH =
    Regex("reports/repair-revisions/revision_[A-Za-z0-9_]+\\.acp-receipt\\.json")
private val REPAIR_INTENT_PATH =
    Regex("reports/repair-revisions/revision_[A-Za-z0-9_]+\\.acp-intent\\.json")
private val REPAIR_ASSESSMENT_PATH =
    Regex("reports/repair-revisions/revision_[A-Za-z0-9_]+\\.acp-assessment\\.json")
internal const val TRACE_REPAIR_ACP_RECEIPT_KIND = "decomp-engine.trace-repair-acp-execution-receipt"
internal const val TRACE_REPAIR_ACP_TASK_FIELD = "attemptId"

/**
 * Hard limits for one repair index, context window, patch attempt, and durable revision graph.
 *
 * Defaults are deliberately large enough to index a large recovered program while keeping any one
 * agent request and patch bounded. Limits are persisted in the graph; reopening a graph with a
 * different budget is rejected so restart cannot silently change repair semantics.
 */
data class RepairResourceBudget(
    val maximumIndexedModules: Int = 100_000,
    val maximumIndexedEntities: Int = 2_000_000,
    val maximumDependencyEdges: Long = 20_000_000,
    val maximumSourceFiles: Int = 500_000,
    val maximumSourceFileBytes: Long = 128L * 1024 * 1024,
    val maximumSourceBytes: Long = 4L * 1024 * 1024 * 1024,
    val maximumIndexEvidenceBytes: Long = 512L * 1024 * 1024,
    val maximumDiagnosticCharacters: Int = 1_000_000,
    val maximumRegressionInputBytes: Long = 1024L * 1024,
    val maximumRegressionInputs: Int = 10_000,
    val maximumRegressionArguments: Int = 100_000,
    val maximumRequestBytes: Long = 4L * 1024 * 1024,
    val maximumResponseBytes: Long = 16L * 1024 * 1024,
    val maximumProjectionBytes: Long = MAXIMUM_REPAIR_PROJECTION_BYTES,
    val maximumContextModules: Int = 64,
    val maximumContextFiles: Int = 256,
    val maximumContextBytes: Long = 2L * 1024 * 1024,
    val maximumStagingDirectories: Int = 512,
    val maximumStagingBytes: Long = 2L * 1024 * 1024,
    val maximumPatchFiles: Int = 32,
    val maximumPatchBytes: Long = 2L * 1024 * 1024,
    val maximumBehaviorStdoutBytes: Long = 8L * 1024 * 1024,
    val maximumBehaviorStderrBytes: Long = 8L * 1024 * 1024,
    val maximumBehaviorOutputBytes: Long = 16L * 1024 * 1024,
    val maximumBehaviorExecutionMillis: Long = 5_000,
    val maximumDiscoveryEntries: Int = 1_000_000,
    val maximumDiscoveryDirectories: Int = 100_000,
    val maximumDiscoveryDepth: Int = 128,
    val maximumStateDirectoryEntries: Int = 1_000_000,
    val maximumGraphLockWaitMillis: Long = 10_000,
    val maximumRevisionNodes: Int = 10_000,
    val maximumGraphBytes: Long = 256L * 1024 * 1024,
    val maximumStoredBlobBytes: Long = 4L * 1024 * 1024 * 1024,
) {
    init {
        require(maximumIndexedModules in 1..1_000_000)
        require(maximumIndexedEntities in 1..10_000_000)
        require(maximumDependencyEdges in 1..100_000_000)
        require(maximumSourceFiles in 1..2_000_000)
        require(maximumSourceFileBytes in 1 until Int.MAX_VALUE.toLong())
        require(maximumSourceBytes >= maximumSourceFileBytes)
        require(maximumIndexEvidenceBytes in 1 until Int.MAX_VALUE.toLong())
        require(maximumDiagnosticCharacters in 1..10_000_000)
        require(maximumRegressionInputBytes > 0)
        require(maximumRegressionInputs in 1..1_000_000)
        require(maximumRegressionArguments in 1..10_000_000)
        require(maximumRequestBytes in maximumRegressionInputBytes until Int.MAX_VALUE.toLong())
        require(maximumResponseBytes in 1 until Int.MAX_VALUE.toLong())
        require(maximumProjectionBytes in 1..MAXIMUM_REPAIR_PROJECTION_BYTES)
        require(maximumContextModules in 1..maximumIndexedModules)
        require(maximumContextFiles in 1..maximumSourceFiles)
        require(maximumContextBytes > 0 && maximumContextBytes <= maximumSourceBytes)
        require(maximumStagingDirectories in 1..maximumSourceFiles)
        require(maximumStagingBytes > 0 && maximumStagingBytes <= maximumSourceBytes)
        require(maximumPatchFiles in 1..maximumContextFiles)
        require(maximumPatchBytes > 0 && maximumPatchBytes <= maximumContextBytes)
        require(maximumBehaviorStdoutBytes in 1 until Int.MAX_VALUE.toLong())
        require(maximumBehaviorStderrBytes in 1 until Int.MAX_VALUE.toLong())
        require(maximumBehaviorOutputBytes >= maxOf(maximumBehaviorStdoutBytes, maximumBehaviorStderrBytes) &&
            maximumBehaviorOutputBytes < Int.MAX_VALUE.toLong())
        require(maximumBehaviorExecutionMillis in 1..3_600_000)
        require(maximumDiscoveryEntries in 1..2_000_000)
        require(maximumDiscoveryDirectories in 1..maximumDiscoveryEntries)
        require(maximumDiscoveryDepth in 1..1024)
        require(maximumStateDirectoryEntries in 1..2_000_000)
        require(maximumGraphLockWaitMillis in 1..60_000)
        require(maximumRevisionNodes in 2..1_000_000)
        require(maximumGraphBytes in 1 until Int.MAX_VALUE.toLong())
        require(maximumStoredBlobBytes >= maximumSourceBytes)
    }
}

class RepairBudgetExceededException(message: String) : IllegalArgumentException(message)

/** A contained stable read found no admissible regular file (missing, linked, special or escaping). */
internal class StableFileUnavailableException(message: String) : IllegalArgumentException(message)

/** A contained stable read observed its file or a path binding change; nothing read may be used. */
internal class StableFileChangedException(message: String) : IllegalArgumentException(message)

private inline fun requireUnchanged(condition: Boolean, message: () -> String) {
    if (!condition) throw StableFileChangedException(message())
}

class RepairGraphLockTimeoutException(message: String) : IllegalStateException(message)

/** Optional source-bound diagnostic ownership supplied by a profile. */
class RepairFailureOwnership(
    moduleIds: List<String> = emptyList(),
    val includesSharedContext: Boolean = false,
) {
    val moduleIds: List<String> = immutableList(moduleIds)

    init {
        require(this.moduleIds == this.moduleIds.distinct().sorted())
        this.moduleIds.forEach(::requireValidProfileModuleId)
    }
}

/** Program-neutral ownership and dependency evidence for one repair module. */
class RepairModuleEvidence(
    id: String,
    ownedPaths: List<String>,
    dependencyContextPaths: List<String> = emptyList(),
    entityIds: List<String> = emptyList(),
    dependencyModuleIds: List<String> = emptyList(),
) {
    val id: String = id
    val ownedPaths: List<String> = immutableList(ownedPaths)
    val dependencyContextPaths: List<String> = immutableList(dependencyContextPaths)
    val entityIds: List<String> = immutableList(entityIds)
    val dependencyModuleIds: List<String> = immutableList(dependencyModuleIds)

    init {
        requireValidProfileModuleId(id)
        require(ownedPaths == ownedPaths.map(::normalizedRelative).distinct().sorted())
        require(dependencyContextPaths == dependencyContextPaths.map(::normalizedRelative).distinct().sorted())
        require(entityIds == entityIds.distinct().sorted())
        require(entityIds.none { it.isBlank() })
        require(dependencyModuleIds == dependencyModuleIds.distinct().sorted())
        dependencyModuleIds.forEach(::requireValidProfileModuleId)
        require(id !in dependencyModuleIds) { "repair module cannot depend on itself: $id" }
    }

    override fun equals(other: Any?): Boolean = other is RepairModuleEvidence &&
        id == other.id && ownedPaths == other.ownedPaths &&
        dependencyContextPaths == other.dependencyContextPaths && entityIds == other.entityIds &&
        dependencyModuleIds == other.dependencyModuleIds

    override fun hashCode(): Int = listOf(
        id,
        ownedPaths,
        dependencyContextPaths,
        entityIds,
        dependencyModuleIds,
    ).hashCode()
}

/** Program-neutral relevance and dependency evidence for one indexed entity. */
class RepairEntityEvidence(
    id: String,
    relevanceTokens: List<String> = emptyList(),
    dependencyEntityIds: List<String> = emptyList(),
) {
    val id: String = id
    val relevanceTokens: List<String> = immutableList(relevanceTokens)
    val dependencyEntityIds: List<String> = immutableList(dependencyEntityIds)

    init {
        require(id.isNotBlank()) { "repair entity ID must not be blank" }
        require(relevanceTokens == relevanceTokens.filter { it.isNotBlank() }.distinct().sorted())
        require(dependencyEntityIds == dependencyEntityIds.distinct().sorted())
        require(dependencyEntityIds.none { it.isBlank() })
    }

    override fun equals(other: Any?): Boolean = other is RepairEntityEvidence &&
        id == other.id && relevanceTokens == other.relevanceTokens &&
        dependencyEntityIds == other.dependencyEntityIds

    override fun hashCode(): Int = listOf(id, relevanceTokens, dependencyEntityIds).hashCode()
}

/**
 * A resolved, language-neutral description of the files and dependency evidence that participate
 * in repair. Callers may derive this from a compiler database, build graph, source manifest, or
 * another program-specific evidence source. The revision graph persists the profile identity and
 * the digest of this complete resolved layout, so restart cannot silently change its meaning.
 */
class RepairIndexLayout(
    sourcePaths: List<String>,
    editablePaths: List<String>,
    modules: List<RepairModuleEvidence> = emptyList(),
    entities: List<RepairEntityEvidence> = emptyList(),
    sharedContextPaths: List<String> = emptyList(),
    sharedInvalidationPaths: List<String> = emptyList(),
    pathDependencies: Map<String, List<String>> = emptyMap(),
    fallbackModuleIdsByPath: Map<String, String> = emptyMap(),
    behaviorRootModuleIds: List<String> = emptyList(),
    behaviorRootEntityIds: List<String> = emptyList(),
) {
    val sourcePaths: List<String> = immutableList(sourcePaths)
    val editablePaths: List<String> = immutableList(editablePaths)
    val modules: List<RepairModuleEvidence> = immutableList(modules)
    val entities: List<RepairEntityEvidence> = immutableList(entities)
    val sharedContextPaths: List<String> = immutableList(sharedContextPaths)
    val sharedInvalidationPaths: List<String> = immutableList(sharedInvalidationPaths)
    val pathDependencies: Map<String, List<String>> = immutableStringListMap(pathDependencies)
    val fallbackModuleIdsByPath: Map<String, String> = Collections.unmodifiableMap(TreeMap(fallbackModuleIdsByPath))
    val behaviorRootModuleIds: List<String> = immutableList(behaviorRootModuleIds)
    val behaviorRootEntityIds: List<String> = immutableList(behaviorRootEntityIds)

    init {
        require(sourcePaths.isNotEmpty()) { "repair index profile has no source inputs" }
        require(sourcePaths == sourcePaths.map(::normalizedRelative).distinct().sorted()) {
            "repair index profile source paths must be normalized, unique, and sorted"
        }
        require(sourcePaths.none(::isReservedRepairInternalPath)) {
            "repair index profile source paths collide with repair-owned state or projections"
        }
        require(editablePaths == editablePaths.map(::normalizedRelative).distinct().sorted()) {
            "repair index profile editable paths must be normalized, unique, and sorted"
        }
        require(editablePaths.all { it in sourcePaths }) { "repair editable paths must be source inputs" }
        require(sharedContextPaths == sharedContextPaths.map(::normalizedRelative).distinct().sorted())
        require(sharedContextPaths.all { it in sourcePaths }) { "shared repair context must be source input" }
        require(sharedInvalidationPaths == sharedInvalidationPaths.map(::normalizedRelative).distinct().sorted())
        require(sharedInvalidationPaths.all { it in editablePaths }) {
            "shared invalidation paths must be editable source inputs"
        }
        require(modules.map { it.id } == modules.map { it.id }.distinct().sorted()) {
            "repair module evidence must have unique sorted IDs"
        }
        require(entities.map { it.id } == entities.map { it.id }.distinct().sorted()) {
            "repair entity evidence must have unique sorted IDs"
        }
        val moduleIds = modules.mapTo(hashSetOf()) { it.id }
        val entityIds = entities.mapTo(hashSetOf()) { it.id }
        val ownedEntityIds = modules.flatMap { it.entityIds }
        require(ownedEntityIds.distinct().size == ownedEntityIds.size) {
            "repair entity has more than one module owner"
        }
        require(ownedEntityIds.toSet() == entityIds) {
            "repair module entity ownership must exactly cover entity evidence"
        }
        modules.forEach { module ->
            require(module.ownedPaths.all { it in sourcePaths }) { "module owned paths must be source inputs" }
            require(module.dependencyContextPaths.all { it in sourcePaths }) {
                "module dependency context paths must be source inputs"
            }
            require(module.dependencyModuleIds.all { it in moduleIds }) {
                "module dependency evidence references an unknown module"
            }
        }
        entities.forEach { entity ->
            require(entity.dependencyEntityIds.all { it in entityIds }) {
                "entity dependency evidence references an unknown entity"
            }
        }
        val explicitlyOwnedPaths = modules.flatMap { it.ownedPaths }
        val explicitlyOwnedPathSet = explicitlyOwnedPaths.toHashSet()
        require(explicitlyOwnedPathSet.size == explicitlyOwnedPaths.size) {
            "repair path has more than one explicit module owner"
        }
        pathDependencies.forEach { (path, dependencies) ->
            require(normalizedRelative(path) == path && path in sourcePaths)
            require(dependencies == dependencies.map(::normalizedRelative).distinct().sorted())
            require(dependencies.all { it in sourcePaths }) { "path dependencies must be source inputs" }
        }
        fallbackModuleIdsByPath.forEach { (path, moduleId) ->
            require(normalizedRelative(path) == path && path in sourcePaths)
            requireValidProfileModuleId(moduleId)
        }
        require(fallbackModuleIdsByPath.keys.none { it in explicitlyOwnedPathSet }) {
            "fallback module paths must not already have an explicit module owner"
        }
        require(fallbackModuleIdsByPath.keys.none { it in sharedContextPaths || it in sharedInvalidationPaths }) {
            "fallback module paths must be applicable unowned, non-shared source inputs"
        }
        require(fallbackModuleIdsByPath.values.distinct().size == fallbackModuleIdsByPath.size) {
            "fallback module IDs must be injective"
        }
        require(fallbackModuleIdsByPath.values.none { it in moduleIds }) {
            "fallback module ID collides with an explicit module ID"
        }
        require(behaviorRootModuleIds == behaviorRootModuleIds.distinct().sorted())
        behaviorRootModuleIds.forEach(::requireValidProfileModuleId)
        val declaredModuleIds = moduleIds + fallbackModuleIdsByPath.values
        require(behaviorRootModuleIds.all { it in declaredModuleIds }) {
            "behavior root references an unknown declared module"
        }
        require(behaviorRootEntityIds == behaviorRootEntityIds.distinct().sorted())
        require(behaviorRootEntityIds.all { it in entityIds })
    }

    override fun equals(other: Any?): Boolean = other is RepairIndexLayout &&
        sourcePaths == other.sourcePaths && editablePaths == other.editablePaths &&
        modules == other.modules && entities == other.entities &&
        sharedContextPaths == other.sharedContextPaths &&
        sharedInvalidationPaths == other.sharedInvalidationPaths &&
        pathDependencies == other.pathDependencies &&
        fallbackModuleIdsByPath == other.fallbackModuleIdsByPath &&
        behaviorRootModuleIds == other.behaviorRootModuleIds &&
        behaviorRootEntityIds == other.behaviorRootEntityIds

    override fun hashCode(): Int = listOf(
        sourcePaths,
        editablePaths,
        modules,
        entities,
        sharedContextPaths,
        sharedInvalidationPaths,
        pathDependencies,
        fallbackModuleIdsByPath,
        behaviorRootModuleIds,
        behaviorRootEntityIds,
    ).hashCode()

    internal fun canonicalSha256(maximumBytes: Long, configurationPrefix: String? = null): String =
        boundedCanonicalSha256(
            maximumBytes,
            if (configurationPrefix == null) "repair index layout" else "repair profile configuration",
        ) {
            configurationPrefix?.let { prefix ->
                append(prefix)
                append('\u0000')
            }
            writeCanonicalTo(this)
        }

    private fun writeCanonicalTo(sink: BoundedCanonicalDigest) = with(sink) {
        fun appendList(label: String, values: List<String>) {
            append('[').append(label).append("]\n")
            values.forEach { append(it.length).append(':').append(it).append('\n') }
        }
        fun appendMap(label: String, values: Map<String, List<String>>) {
            append('[').append(label).append("]\n")
            values.forEach { (key, entries) ->
                append(key.length).append(':').append(key).append('|')
                entries.forEach { append(it.length).append(':').append(it).append(',') }
                append('\n')
            }
        }
        appendList("sources", sourcePaths)
        appendList("editable", editablePaths)
        append("[modules]\n")
        modules.forEach { module ->
            append(module.id.length).append(':').append(module.id).append('|')
            module.ownedPaths.forEach { append(it.length).append(':').append(it).append(',') }
            append('|')
            module.dependencyContextPaths.forEach { append(it.length).append(':').append(it).append(',') }
            append('|')
            module.entityIds.forEach { append(it.length).append(':').append(it).append(',') }
            append('|')
            module.dependencyModuleIds.forEach { append(it.length).append(':').append(it).append(',') }
            append('\n')
        }
        append("[entities]\n")
        entities.forEach { entity ->
            append(entity.id.length).append(':').append(entity.id).append('|')
            entity.relevanceTokens.forEach { append(it.length).append(':').append(it).append(',') }
            append('|')
            entity.dependencyEntityIds.forEach { append(it.length).append(':').append(it).append(',') }
            append('\n')
        }
        appendList("shared-context", sharedContextPaths)
        appendList("shared-invalidation", sharedInvalidationPaths)
        appendMap("path-dependencies", pathDependencies)
        append("[fallback-modules]\n")
        fallbackModuleIdsByPath.forEach { (path, moduleId) ->
            append(path.length).append(':').append(path).append('|')
                .append(moduleId.length).append(':').append(moduleId).append(",\n")
        }
        appendList("behavior-root-modules", behaviorRootModuleIds)
        appendList("behavior-root-entities", behaviorRootEntityIds)
    }
}

private class BoundedCanonicalDigest(
    private val maximumBytes: Long,
    private val subject: String,
) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var byteCount = 0L
    private val output = object : OutputStream() {
        override fun write(value: Int) {
            requireCapacity(1)
            digest.update(value.toByte())
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            requireCapacity(length)
            digest.update(bytes, offset, length)
        }

        private fun requireCapacity(length: Int) {
            if (length.toLong() > maximumBytes - byteCount) {
                throw RepairBudgetExceededException("$subject exceeds $maximumBytes canonical bytes")
            }
            byteCount += length
        }
    }
    private val writer = OutputStreamWriter(output, Charsets.UTF_8)

    fun append(value: CharSequence): BoundedCanonicalDigest = apply { writer.append(value) }
    fun append(value: Char): BoundedCanonicalDigest = apply { writer.append(value) }
    fun append(value: Int): BoundedCanonicalDigest = append(value.toString())

    fun finish(): String {
        writer.flush()
        return digest.digest().toHexLower()
    }
}

private inline fun boundedCanonicalSha256(
    maximumBytes: Long,
    subject: String,
    body: BoundedCanonicalDigest.() -> Unit,
): String = BoundedCanonicalDigest(maximumBytes, subject).apply(body).finish()

private fun RepairIndexLayout.deepFrozenCopy(): RepairIndexLayout = this

/**
 * The declarative profile's explicit policy for a layout with no module evidence is one exact module
 * per non-shared source path. The generic index loader never invents ownership: this transformation
 * happens at the profile boundary and is included in the resolved-layout/configuration digest.
 */
private fun RepairIndexLayout.withDeclarativePerPathModules(): RepairIndexLayout {
    if (modules.isNotEmpty() || fallbackModuleIdsByPath.isNotEmpty()) return this
    val sharedPaths = sharedContextPaths.toHashSet().apply { addAll(sharedInvalidationPaths) }
    val declaredFallbacks = sourcePaths
        .filterNot { it in sharedPaths }
        .associateWithTo(TreeMap()) { path -> exactPathModuleId(path) }
    if (declaredFallbacks.isEmpty()) return this
    return RepairIndexLayout(
        sourcePaths = sourcePaths,
        editablePaths = editablePaths,
        modules = modules,
        entities = entities,
        sharedContextPaths = sharedContextPaths,
        sharedInvalidationPaths = sharedInvalidationPaths,
        pathDependencies = pathDependencies,
        fallbackModuleIdsByPath = declaredFallbacks,
        behaviorRootModuleIds = behaviorRootModuleIds,
        behaviorRootEntityIds = behaviorRootEntityIds,
    )
}

private fun exactPathModuleId(path: String): String =
    "path_${path.toByteArray(Charsets.UTF_8).toHexLower()}"

/** Program/layout-specific indexing is an explicit injected boundary, not repair-core policy. */
interface RepairIndexProfile {
    fun resolve(projectRoot: Path, budget: RepairResourceBudget): RepairIndexLayout

    /** Recovery-only dependency resolution over authorized, hash-checked target preimages.
     * Source-sensitive profiles override this; the resulting full index must still match the
     * persisted immutable binding. This callback does not grant writes or acceptance authority. */
    fun resolveForRecovery(
        projectRoot: Path,
        budget: RepairResourceBudget,
        sourcePaths: List<String>,
        editablePaths: List<String>,
        readSource: (String) -> ByteArray,
    ): RepairIndexLayout = resolve(projectRoot, budget)

    /** Adapter-specific admission of already bounded source bytes before validation or publication. */
    fun validateSourceContent(path: String, bytes: ByteArray) {}

    /** The source-tree contract, when this repair profile owns generated reconstruction output. */
    fun reconstructionProfile(): ReconstructionProfile? = null

    /**
     * Content-independent authorization used only before crash recovery may write a source path.
     * Dynamic/content-sensitive profiles must validate the persisted source/editable layout without
     * consulting the possibly dirty live source tree. The safe default denies recovery writes.
     */
    fun authorizesRecoveryLayout(
        sourcePaths: List<String>,
        editablePaths: List<String>,
        budget: RepairResourceBudget,
    ): Boolean = false

    /** Stable implementation/schema identity; override for persistent graphs. */
    fun profileId(): String = this::class.qualifiedName ?: this::class.simpleName ?: "repair-index-profile"

    /** Project-independent configuration fingerprint. Changing behavior requires changing this. */
    fun configurationSha256(): String = sha256(profileId().toByteArray(Charsets.UTF_8))

    /** Budget-aware fingerprinting for profiles whose canonical configuration can be large. */
    fun configurationSha256(budget: RepairResourceBudget): String = configurationSha256()

    /** Optional source-bound build/diagnostic ownership evidence. */
    fun failureOwnership(
        projectRoot: Path,
        sourceRevisionSha256: String,
        budget: RepairResourceBudget,
    ): RepairFailureOwnership = RepairFailureOwnership()

    /** Optional compiler/tool-specific diagnostic filtering before symbol/path matching. */
    fun diagnosticEvidence(hint: String): String = hint
}

/** A fully declarative profile suitable for arbitrary source layouts and build systems. */
class DeclarativeRepairIndexProfile(
    private val id: String,
    layout: RepairIndexLayout,
) : RepairIndexProfile {
    private val layout = layout.withDeclarativePerPathModules().deepFrozenCopy()

    init {
        require(id.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) { "invalid repair profile ID" }
    }

    override fun profileId(): String = id
    override fun configurationSha256(): String = configurationSha256(RepairResourceBudget())
    override fun configurationSha256(budget: RepairResourceBudget): String =
        layout.canonicalSha256(budget.maximumIndexEvidenceBytes, id)
    override fun resolve(projectRoot: Path, budget: RepairResourceBudget): RepairIndexLayout = layout
    override fun authorizesRecoveryLayout(
        sourcePaths: List<String>,
        editablePaths: List<String>,
        budget: RepairResourceBudget,
    ): Boolean = sourcePaths == layout.sourcePaths && editablePaths == layout.editablePaths
}

private fun requireValidProfileModuleId(id: String) {
    require(id.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]*"))) { "invalid repair profile module ID: $id" }
}

data class RepairContextSelection(
    val readablePaths: List<String>,
    val writablePaths: List<String>,
    val seedModules: List<String>,
    val dependencyModules: List<String>,
    val deferredModules: List<String>,
    val totalBytes: Long,
    val indexSha256: String,
    val sourceRevisionSha256: String,
) {
    init {
        require(readablePaths == readablePaths.distinct().sorted())
        require(writablePaths == writablePaths.distinct().sorted())
        require(writablePaths.all { it in readablePaths })
    }

    fun toContextJson(): String = buildString {
        append("{\"indexSha256\":\"").append(indexSha256).append("\",")
        append("\"sourceRevisionSha256\":\"").append(sourceRevisionSha256).append("\",")
        append("\"seedModules\":").append(seedModules.jsonArray()).append(',')
        append("\"dependencyModules\":").append(dependencyModules.jsonArray()).append(',')
        append("\"deferredModules\":").append(deferredModules.jsonArray()).append(',')
        append("\"readablePaths\":").append(readablePaths.jsonArray()).append(',')
        append("\"writablePaths\":").append(writablePaths.jsonArray()).append(',')
        append("\"totalBytes\":").append(totalBytes).append('}')
    }
}

private fun RepairContextSelection.deepFrozenCopy(): RepairContextSelection = copy(
    readablePaths = immutableList(readablePaths),
    writablePaths = immutableList(writablePaths),
    seedModules = immutableList(seedModules),
    dependencyModules = immutableList(dependencyModules),
    deferredModules = immutableList(deferredModules),
)

internal data class IndexedSource(val path: String, val bytes: Long, val sha256: String)

private data class IndexedModule(
    val id: String,
    val ownedPaths: List<String>,
    val dependencyContextPaths: List<String>,
    val entityIds: List<String>,
    val dependencies: List<String>,
)

private fun IndexedModule.deepFrozenCopy(): IndexedModule = copy(
    ownedPaths = immutableList(ownedPaths),
    dependencyContextPaths = immutableList(dependencyContextPaths),
    entityIds = immutableList(entityIds),
    dependencies = immutableList(dependencies),
)

/** Recovery-only immutable path inventory and bounded authenticated preimage reader. */
internal interface RepairRecoverySourceView {
    val sourcePaths: List<String>
    val editablePaths: List<String>
    fun readSource(relative: String): ByteArray
}

/** Profile lookups may repeat; retain only distinct authenticated inputs, never snapshot reads. */
private class RecoveryProfileSourceCache(
    private val sourceView: RepairRecoverySourceView,
    private val budget: RepairResourceBudget,
) {
    private val allowed: Set<String>
    private val sources = hashMapOf<String, ByteArray>()
    private var retainedBytes = 0L

    init {
        val paths = sourceView.sourcePaths
        require(paths.size <= budget.maximumSourceFiles &&
            paths == paths.map(::normalizedRelative).distinct().sorted()) {
            "recovery profile source inventory is unnormalized or over budget"
        }
        allowed = paths.toHashSet()
    }

    @Synchronized
    fun readSource(relative: String): ByteArray {
        require(relative == normalizedRelative(relative) && relative in allowed) {
            "recovery profile source path is not authorized"
        }
        sources[relative]?.let { return it.copyOf() }
        require(sources.size < budget.maximumSourceFiles) { "recovery profile exceeds its source-file budget" }
        val observed = sourceView.readSource(relative)
        if (observed.size.toLong() > budget.maximumSourceFileBytes) {
            throw RepairBudgetExceededException("recovery profile source exceeds its per-file byte budget")
        }
        val nextBytes = Math.addExact(retainedBytes, observed.size.toLong())
        if (nextBytes > budget.maximumSourceBytes) {
            throw RepairBudgetExceededException("recovery profile sources exceed their aggregate byte budget")
        }
        retainedBytes = nextBytes
        val owned = observed.copyOf()
        sources[relative] = owned
        return owned.copyOf() // Never expose the retained bytes to a mutable profile callback.
    }
}

/** Sparse index constructed only for a gate-authenticated, lock-owning graph. */
internal class ModuleRepairIndex private constructor(
    projectRootCandidate: Path?,
    profileCandidate: RepairIndexProfile?,
    profileIdCandidate: String?,
    profileSha256Candidate: String?,
    budgetCandidate: RepairResourceBudget?,
    modulesCandidate: Map<String, IndexedModule>?,
    sourcesCandidate: Map<String, IndexedSource>?,
    editableCandidate: Set<String>?,
    ownerByPathCandidate: Map<String, String>?,
    ownerByTokenCandidate: Map<String, Set<String>>?,
    pathsByFileNameCandidate: Map<String, List<String>>?,
    dependentsByModuleCandidate: Map<String, List<String>>?,
    behaviorRootModulesCandidate: List<String>?,
    sharedContextPathsCandidate: Set<String>?,
    sharedInvalidationPathsCandidate: Set<String>?,
    indexSha256Candidate: String?,
    sourceRevisionSha256Candidate: String?,
) {
    private val projectRoot: Path
    internal val profile: RepairIndexProfile
    val profileId: String
    val profileSha256: String
    val budget: RepairResourceBudget
    private val modules: Map<String, IndexedModule>
    private val sources: Map<String, IndexedSource>
    private val editable: Set<String>
    private val ownerByPath: Map<String, String>
    private val ownerByToken: Map<String, Set<String>>
    private val pathsByFileName: Map<String, List<String>>
    private val dependentsByModule: Map<String, List<String>>
    private val behaviorRootModules: List<String>
    private val sharedContextPaths: Set<String>
    private val sharedInvalidationPaths: Set<String>
    val indexSha256: String
    val sourceRevisionSha256: String

    init {
        SecureRepairRuntime.consumeIndexConstruction()
        projectRoot = requireNotNull(projectRootCandidate)
        profile = requireNotNull(profileCandidate)
        profileId = requireNotNull(profileIdCandidate)
        profileSha256 = requireNotNull(profileSha256Candidate)
        budget = requireNotNull(budgetCandidate)
        modules = Collections.unmodifiableMap(
            TreeMap(requireNotNull(modulesCandidate).mapValues { (_, module) -> module.deepFrozenCopy() }),
        )
        sources = Collections.unmodifiableMap(TreeMap(requireNotNull(sourcesCandidate)))
        editable = Collections.unmodifiableSet(TreeSet(requireNotNull(editableCandidate)))
        ownerByPath = Collections.unmodifiableMap(TreeMap(requireNotNull(ownerByPathCandidate)))
        ownerByToken = Collections.unmodifiableMap(
            TreeMap(requireNotNull(ownerByTokenCandidate).mapValues { (_, owners) ->
                Collections.unmodifiableSet(TreeSet(owners))
            }),
        )
        pathsByFileName = immutableStringListMap(requireNotNull(pathsByFileNameCandidate))
        dependentsByModule = immutableStringListMap(requireNotNull(dependentsByModuleCandidate))
        behaviorRootModules = immutableList(requireNotNull(behaviorRootModulesCandidate))
        sharedContextPaths = Collections.unmodifiableSet(TreeSet(requireNotNull(sharedContextPathsCandidate)))
        sharedInvalidationPaths = Collections.unmodifiableSet(TreeSet(requireNotNull(sharedInvalidationPathsCandidate)))
        indexSha256 = requireNotNull(indexSha256Candidate)
        sourceRevisionSha256 = requireNotNull(sourceRevisionSha256Candidate)
    }

    val editablePaths: Set<String> get() = Collections.unmodifiableSet(TreeSet(editable))
    val sourcePaths: List<String> get() = immutableList(sources.keys.sorted())
    val moduleIds: List<String> get() = immutableList(modules.keys.sorted())

    fun select(failureKind: String, diagnosticHint: String? = null): RepairContextSelection {
        require(failureKind in setOf("compile", "behavior")) { "unsupported repair failure kind: $failureKind" }
        val hint = diagnosticHint.orEmpty()
        if (hint.length > budget.maximumDiagnosticCharacters) {
            throw RepairBudgetExceededException(
                "repair diagnostic contains ${hint.length} characters; limit=${budget.maximumDiagnosticCharacters}",
            )
        }
        val indexedHint = if (failureKind == "compile") profile.diagnosticEvidence(hint) else hint
        if (indexedHint.length > budget.maximumDiagnosticCharacters) {
            throw RepairBudgetExceededException(
                "profile-filtered repair diagnostic contains ${indexedHint.length} characters; " +
                    "limit=${budget.maximumDiagnosticCharacters}",
            )
        }
        val explicitlyMentionedPaths = mentionedPaths(indexedHint)
        val boundOwnership = if (failureKind == "compile") boundFailureOwnership() else RepairFailureOwnership()
        val hasProfileBoundOwnership =
            boundOwnership.moduleIds.isNotEmpty() || boundOwnership.includesSharedContext
        val exactPathOwners = explicitlyMentionedPaths.mapNotNullTo(TreeSet(), ownerByPath::get)
        val hasExactPathEvidence = explicitlyMentionedPaths.isNotEmpty()
        val rawTokenOwners = if (!hasProfileBoundOwnership && !hasExactPathEvidence) {
            unambiguousRawTokenOwners(indexedHint)
        } else {
            emptyList()
        }
        val explicitOwners = when {
            hasProfileBoundOwnership -> boundOwnership.moduleIds
            hasExactPathEvidence -> exactPathOwners.toList()
            else -> rawTokenOwners
        }
        val sharedWritable = when {
            hasProfileBoundOwnership && boundOwnership.includesSharedContext ->
                sharedInvalidationPaths.toCollection(TreeSet<String>())
            hasExactPathEvidence ->
                explicitlyMentionedPaths.filterTo(TreeSet<String>()) { it in sharedInvalidationPaths }
            else -> TreeSet<String>()
        }
        val seeds = when {
            explicitOwners.isNotEmpty() -> explicitOwners.toList()
            sharedWritable.isNotEmpty() -> emptyList()
            failureKind == "compile" -> throw IllegalArgumentException(
                "compile repair selection requires exact diagnostic or profile-owned module evidence",
            )
            behaviorRootModules.isNotEmpty() -> behaviorRootModules
            else -> throw IllegalArgumentException(
                "behavior repair selection without diagnostic ownership requires explicit profile-declared roots",
            )
        }.distinct().sorted()
        if (seeds.size > budget.maximumContextModules) {
            throw RepairBudgetExceededException(
                "repair identifies ${seeds.size} required modules; context module limit=${budget.maximumContextModules}",
            )
        }

        val dependencyCandidates = when {
            failureKind == "behavior" -> transitiveDependencies(seeds)
            else -> seeds.flatMap { modules[it]?.dependencies.orEmpty() }.distinct().sorted()
        }.filterNot { it in seeds }
        val capacity = budget.maximumContextModules - seeds.size
        val selectedDependencies = dependencyCandidates.take(capacity)
        val deferred = dependencyCandidates.drop(capacity).toMutableList()
        val writable = TreeSet<String>()
        seeds.flatMapTo(writable) { moduleEditablePaths(it) }
        writable += sharedWritable
        require(writable.isNotEmpty()) {
            "repair ownership evidence does not authorize any editable source path"
        }

        val readable = TreeSet<String>()
        seeds.flatMapTo(readable) { moduleOwnedPaths(it) }
        if (hasExactPathEvidence && !hasProfileBoundOwnership) readable += explicitlyMentionedPaths
        readable += writable
        sharedContextPaths.filterTo(readable) { it in sources }
        val optionalGroups = selectedDependencies.map { moduleId ->
            val readablePaths = if (failureKind == "compile") {
                modules[moduleId]?.dependencyContextPaths.orEmpty().filter { it in sources }
            } else {
                moduleOwnedPaths(moduleId)
            }
            moduleId to readablePaths.distinct().sorted()
        }
        enforceRequiredContextBudget(readable)
        optionalGroups.forEach { (moduleId, readablePaths) ->
            val additions = readablePaths.filterNot { it in readable }
            val proposedFiles = readable.size + additions.size
            val proposedBytes = contextBytes(readable) + additions.sumOf { sources.getValue(it).bytes }
            if (proposedFiles <= budget.maximumContextFiles && proposedBytes <= budget.maximumContextBytes) {
                readable += additions
            } else {
                deferred += moduleId
            }
        }
        require(writable.all { it in readable }) {
            "repair writable authority must be a subset of retained readable context"
        }
        val retainedDependencyModules = selectedDependencies.filterNot { it in deferred }.sorted()
        val total = contextBytes(readable)
        return RepairContextSelection(
            readablePaths = readable.toList(),
            writablePaths = writable.toList(),
            seedModules = seeds,
            dependencyModules = retainedDependencyModules,
            deferredModules = deferred.distinct().sorted(),
            totalBytes = total,
            indexSha256 = indexSha256,
            sourceRevisionSha256 = sourceRevisionSha256,
        ).deepFrozenCopy()
    }

    fun changedModules(paths: Collection<String>): List<String> =
        paths.mapNotNull(ownerByPath::get).distinct().sorted()

    fun downstreamInvalidations(paths: Collection<String>): List<String> {
        val changed = changedModules(paths).toSet()
        val sharedChanged = paths.any { it in sharedInvalidationPaths || (it in editable && ownerByPath[it] == null) }
        if (sharedChanged) return modules.keys.filterNot { it in changed }.sorted()
        val invalidated = TreeSet<String>()
        val queue = ArrayDeque(changed.sorted())
        while (queue.isNotEmpty()) {
            dependentsByModule[queue.removeFirst()].orEmpty().forEach { dependent ->
                if (dependent !in changed && invalidated.add(dependent)) queue.addLast(dependent)
            }
        }
        return invalidated.toList()
    }

    internal fun sourceSnapshot(): List<IndexedSource> {
        val observedLayout = profile.resolve(projectRoot, budget).deepFrozenCopy()
        val observedProfileSha256 = profile.configurationSha256(budget)
        require(observedProfileSha256 == profileSha256) {
            "repair index profile changed after the dependency index was created"
        }
        val observedPaths = observedLayout.sourcePaths
        require(observedPaths == sources.keys.sorted()) {
            "repair source input set changed after the dependency index was created"
        }
        return captureSourceSnapshot(projectRoot, observedPaths, budget, profile)
    }

    internal fun belongsTo(root: Path): Boolean = projectRoot == root.toAbsolutePath().normalize()

    private fun moduleOwnedPaths(moduleId: String): List<String> {
        val module = modules[moduleId] ?: return emptyList()
        return module.ownedPaths.filter { it in sources }.distinct().sorted()
    }

    private fun moduleEditablePaths(moduleId: String): List<String> =
        moduleOwnedPaths(moduleId).filter { it in editable }

    private fun enforceRequiredContextBudget(paths: Set<String>) {
        if (paths.size > budget.maximumContextFiles) {
            throw RepairBudgetExceededException(
                "required repair context has ${paths.size} files; limit=${budget.maximumContextFiles}",
            )
        }
        val bytes = contextBytes(paths)
        if (bytes > budget.maximumContextBytes) {
            throw RepairBudgetExceededException(
                "required repair context has $bytes bytes; limit=${budget.maximumContextBytes}",
            )
        }
    }

    private fun contextBytes(paths: Collection<String>): Long = paths.fold(0L) { total, path ->
        Math.addExact(total, sources.getValue(path).bytes)
    }

    private fun transitiveDependencies(seeds: List<String>): List<String> {
        val visited = seeds.toMutableSet()
        val ordered = mutableListOf<String>()
        val queue = ArrayDeque(seeds.sorted())
        while (queue.isNotEmpty()) {
            modules[queue.removeFirst()]?.dependencies.orEmpty().forEach { dependency ->
                if (visited.add(dependency)) {
                    ordered += dependency
                    queue.addLast(dependency)
                }
            }
        }
        return ordered
    }

    private fun mentionedPaths(hint: String): Set<String> {
        if (hint.isEmpty()) return emptySet()
        val result = TreeSet<String>()
        val candidates = TreeSet<String>()
        PATH_TOKEN.findAll(hint).forEach { match ->
            candidates += match.value.trimEnd(':', ',', ')', ']', '"', '\'')
        }
        candidates += diagnosticLinePathCandidates(hint)
        candidates.forEach { candidate ->
            if (candidate in sources) result += candidate
            val sameNamePaths = pathsByFileName[candidate.substringAfterLast('/')].orEmpty()
            require('/' in candidate || sameNamePaths.size <= 1) {
                "repair diagnostic path is ambiguous and requires a qualified indexed path: $candidate"
            }
            sameNamePaths.forEach { path ->
                if (candidate == path || '/' !in candidate) result += path
            }
        }
        return result
    }

    private fun diagnosticLinePathCandidates(hint: String): Set<String> {
        val candidates = TreeSet<String>()
        var probes = 0
        hint.lineSequence().forEach { line ->
            if (line.length > MAXIMUM_DIAGNOSTIC_LINE_CHARACTERS) {
                throw RepairBudgetExceededException(
                    "repair diagnostic line contains ${line.length} characters; " +
                        "limit=$MAXIMUM_DIAGNOSTIC_LINE_CHARACTERS",
                )
            }
            fun probe(endExclusive: Int) {
                probes = Math.addExact(probes, 1)
                if (probes > MAXIMUM_DIAGNOSTIC_PATH_PROBES) {
                    throw RepairBudgetExceededException(
                        "repair diagnostic path probing exceeds $MAXIMUM_DIAGNOSTIC_PATH_PROBES candidates",
                    )
                }
                val rawCandidate = line.substring(0, endExclusive).trim()
                if (rawCandidate.isNotEmpty()) {
                    candidates += rawCandidate
                    val displayCandidate = rawCandidate
                        .trim('"', '\'', '`', '(', ')', '[', ']', '{', '}', '<', '>', ',')
                    if (displayCandidate.isNotEmpty()) candidates += displayCandidate
                }
            }
            line.indices.filter { line[it] == ':' }.forEach(::probe)
            if (line.isNotBlank()) probe(line.length)
        }
        return candidates
    }

    private fun hintRelevanceTokens(hint: String): Set<String> = RELEVANCE_TOKEN.findAll(hint)
        .map { it.value }
        .filter { it.length >= 3 }
        .toSet()

    private fun unambiguousRawTokenOwners(hint: String): List<String> {
        val owners = TreeSet<String>()
        hintRelevanceTokens(hint).forEach { token ->
            val tokenOwners = ownerByToken[token].orEmpty()
            require(tokenOwners.size <= 1) {
                "repair diagnostic token is ambiguous across indexed owners: $token"
            }
            tokenOwners.singleOrNull()?.let(owners::add)
        }
        require(owners.size <= 1) {
            "repair diagnostic contains multiple unbound relevance-token owners; " +
                "use exact indexed paths or profile-authenticated ownership"
        }
        return owners.toList()
    }

    private fun boundFailureOwnership(): RepairFailureOwnership {
        val evidence = profile.failureOwnership(projectRoot, sourceRevisionSha256, budget)
        if (evidence.moduleIds.size > budget.maximumContextModules) {
            throw RepairBudgetExceededException(
                "repair failure ownership identifies ${evidence.moduleIds.size} modules; " +
                    "limit=${budget.maximumContextModules}",
            )
        }
        val unknown = evidence.moduleIds.filterNot { it in modules }
        require(unknown.isEmpty()) {
            "repair failure ownership references unknown modules: ${unknown.joinToString(", ")}"
        }
        return RepairFailureOwnership(
            moduleIds = evidence.moduleIds,
            includesSharedContext = evidence.includesSharedContext,
        )
    }

    companion object {
        private val PATH_TOKEN = Regex("(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+")
        private val RELEVANCE_TOKEN = Regex("[A-Za-z0-9_][A-Za-z0-9_.:-]*")
        private const val MAXIMUM_DIAGNOSTIC_LINE_CHARACTERS = 16_384
        private const val MAXIMUM_DIAGNOSTIC_PATH_PROBES = 4_096

        /** JVM bridge: authenticate before inspecting any path, profile, or budget. */
        fun loadAuthorized(
            runtimeIdentity: Any?,
            graphAuthorityCandidate: Any?,
            projectDirCandidate: Path?,
            profileCandidate: RepairIndexProfile?,
            budgetCandidate: RepairResourceBudget?,
        ): ModuleRepairIndex = loadIndexAuthorized(runtimeIdentity, graphAuthorityCandidate,
            projectDirCandidate, profileCandidate, budgetCandidate, null)

        /** Separate bridge retains runtime identity and registered-profile authority. */
        fun loadRecoveryAuthorized(
            runtimeIdentity: Any?,
            graphAuthorityCandidate: Any?,
            projectDirCandidate: Path?,
            profileCandidate: RepairIndexProfile?,
            budgetCandidate: RepairResourceBudget?,
            sourceViewCandidate: RepairRecoverySourceView?,
        ): ModuleRepairIndex {
            SecureRepairRuntime.requireRuntimeIdentity(runtimeIdentity)
            SecureRepairRuntime.requireGraphAuthority(graphAuthorityCandidate)
            return loadIndexAuthorized(runtimeIdentity, graphAuthorityCandidate, projectDirCandidate,
                profileCandidate, budgetCandidate, requireNotNull(sourceViewCandidate))
        }

        private fun loadIndexAuthorized(
            runtimeIdentity: Any?,
            graphAuthorityCandidate: Any?,
            projectDirCandidate: Path?,
            profileCandidate: RepairIndexProfile?,
            budgetCandidate: RepairResourceBudget?,
            sourceView: RepairRecoverySourceView?,
        ): ModuleRepairIndex {
            SecureRepairRuntime.requireRuntimeIdentity(runtimeIdentity)
            SecureRepairRuntime.requireGraphAuthority(graphAuthorityCandidate)
            val projectDir = requireNotNull(projectDirCandidate) { "repair project path is required" }
            val profile = requireNotNull(profileCandidate) { "repair profile is required" }
            val budget = requireNotNull(budgetCandidate) { "repair resource budget is required" }
            val root = projectDir.toAbsolutePath().normalize()
            val pinnedRoot = isPinnedRepairRootPath(root)
            require(pinnedRoot || !Files.isSymbolicLink(root)) { "repair project root must not be a symbolic link" }
            require(pinnedRoot || Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                "repair project root is not a directory: $root"
            }
            openRepairRootDirectory(root).use { descriptor ->
                require(descriptor.identity.isDirectory && !descriptor.identity.isSymbolicLink) {
                    "repair project root is not a descriptor-authenticated directory"
                }
            }
            val profileId = profile.profileId()
            require(profileId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) { "invalid repair profile ID" }
            val layout = (if (sourceView == null) profile.resolve(root, budget) else {
                val profileSources = RecoveryProfileSourceCache(sourceView, budget)
                profile.resolveForRecovery(root, budget, sourceView.sourcePaths, sourceView.editablePaths,
                    profileSources::readSource)
            }).deepFrozenCopy()
            if (sourceView != null) require(layout.sourcePaths == sourceView.sourcePaths &&
                layout.editablePaths == sourceView.editablePaths) { "recovery index source view changed its authorized paths" }
            val sourcePaths = layout.sourcePaths
            if (sourcePaths.size > budget.maximumSourceFiles) {
                throw RepairBudgetExceededException(
                    "repair profile has ${sourcePaths.size} source inputs; limit=${budget.maximumSourceFiles}",
                )
            }
            if (layout.modules.size > budget.maximumIndexedModules) {
                throw RepairBudgetExceededException(
                    "repair profile has ${layout.modules.size} modules; limit=${budget.maximumIndexedModules}",
                )
            }
            if (layout.entities.size > budget.maximumIndexedEntities) {
                throw RepairBudgetExceededException(
                    "repair profile has ${layout.entities.size} entities; limit=${budget.maximumIndexedEntities}",
                )
            }
            val explicitlyOwnedPaths = layout.modules.flatMapTo(hashSetOf()) { it.ownedPaths }
            val sharedPathSet = layout.sharedContextPaths.toHashSet().apply {
                addAll(layout.sharedInvalidationPaths)
            }
            val requiredFallbackPaths = sourcePaths
                .filter { it !in explicitlyOwnedPaths && it !in sharedPathSet }
                .toSortedSet()
            require(layout.fallbackModuleIdsByPath.keys == requiredFallbackPaths) {
                val missing = requiredFallbackPaths - layout.fallbackModuleIdsByPath.keys
                val unexpected = layout.fallbackModuleIdsByPath.keys - requiredFallbackPaths
                "repair profile must explicitly and exactly map every unowned, non-shared source path; " +
                    "missing=${missing.take(8)} unexpected=${unexpected.take(8)}"
            }
            val prospectiveModuleCount = Math.addExact(layout.modules.size, layout.fallbackModuleIdsByPath.size)
            if (prospectiveModuleCount > budget.maximumIndexedModules) {
                throw RepairBudgetExceededException(
                    "repair index has $prospectiveModuleCount modules; limit=${budget.maximumIndexedModules}",
                )
            }
            var declaredDependencyReferences = 0L
            fun chargeDependencyReferences(count: Int) {
                if (count.toLong() > budget.maximumDependencyEdges - declaredDependencyReferences) {
                    throw RepairBudgetExceededException(
                        "repair profile exceeds ${budget.maximumDependencyEdges} declared dependency references",
                    )
                }
                declaredDependencyReferences += count
            }
            layout.modules.forEach { chargeDependencyReferences(it.dependencyModuleIds.size) }
            layout.entities.forEach { chargeDependencyReferences(it.dependencyEntityIds.size) }
            layout.pathDependencies.values.forEach { chargeDependencyReferences(it.size) }
            val profileSha256 = profile.configurationSha256(budget)
            require(profileSha256.matches(Regex("[0-9a-f]{64}"))) { "invalid repair profile fingerprint" }
            val layoutSha256 = layout.canonicalSha256(budget.maximumIndexEvidenceBytes)
            val snapshot = captureSourceSnapshot(root, sourcePaths, budget, profile, sourceView)
            val sourceMap = snapshot.associateBy { it.path }
            val editable = layout.editablePaths.toCollection(TreeSet())
            require(editable.isNotEmpty()) { "repair index profile has no editable source inputs" }

            val entitiesById = layout.entities.associateBy { it.id }
            val ownerByEntity = layout.modules.flatMap { module -> module.entityIds.map { it to module.id } }.toMap()
            val indexed = TreeMap<String, IndexedModule>()
            layout.modules.forEach { module ->
                indexed[module.id] = IndexedModule(
                    module.id,
                    module.ownedPaths,
                    module.dependencyContextPaths,
                    module.entityIds,
                    module.dependencyModuleIds,
                )
            }

            val ownerByPath = TreeMap<String, String>()
            indexed.values.forEach { module ->
                module.ownedPaths.forEach { path ->
                    require(ownerByPath.put(path, module.id) == null) { "repair path has multiple module owners: $path" }
                }
            }
            layout.fallbackModuleIdsByPath.forEach { (path, id) ->
                require(id !in indexed) {
                    "repair fallback module ID collision for $path: $id"
                }
                val module = IndexedModule(id, listOf(path), emptyList(), emptyList(), emptyList())
                indexed[id] = module
                ownerByPath[path] = id
            }
            if (indexed.size > budget.maximumIndexedModules) {
                throw RepairBudgetExceededException(
                    "repair index has ${indexed.size} modules; limit=${budget.maximumIndexedModules}",
                )
            }
            val semanticDependencies = indexed.keys.associateWith { sortedSetOf<String>() }
            indexed.values.forEach { module ->
                semanticDependencies.getValue(module.id) += module.dependencies
                module.entityIds.asSequence().mapNotNull(entitiesById::get).forEach { entity ->
                    entity.dependencyEntityIds.mapNotNullTo(
                        semanticDependencies.getValue(module.id),
                        ownerByEntity::get,
                    )
                }
                semanticDependencies.getValue(module.id).remove(module.id)
            }
            val pathDependencies = derivePathDependencies(layout.pathDependencies, indexed, ownerByPath, budget)
            indexed.replaceAll { id, module ->
                module.copy(dependencies = (semanticDependencies.getValue(id) + pathDependencies.getValue(id)).distinct().sorted())
            }
            val entityReferenceCount = layout.entities.sumOf { it.dependencyEntityIds.size.toLong() }
            val declaredModuleReferenceCount = layout.modules.sumOf { it.dependencyModuleIds.size.toLong() }
            val edgeCount = Math.addExact(
                Math.addExact(entityReferenceCount, declaredModuleReferenceCount),
                pathDependencies.values.sumOf { it.size.toLong() },
            )
            if (edgeCount > budget.maximumDependencyEdges) {
                throw RepairBudgetExceededException(
                    "repair index has $edgeCount dependency edges; limit=${budget.maximumDependencyEdges}",
                )
            }
            val dependents = indexed.keys.associateWith { mutableListOf<String>() }
            indexed.values.forEach { module ->
                module.dependencies.forEach { dependency -> dependents.getValue(dependency) += module.id }
            }
            val ownerTokens = TreeMap<String, MutableSet<String>>()
            indexed.values.forEach { module ->
                ownerTokens.getOrPut(module.id) { sortedSetOf() } += module.id
                module.entityIds.forEach { id ->
                    ownerTokens.getOrPut(id) { sortedSetOf() } += module.id
                    entitiesById.getValue(id).relevanceTokens.forEach { token ->
                        ownerTokens.getOrPut(token) { sortedSetOf() } += module.id
                    }
                }
            }
            val behaviorRoots = buildList {
                layout.behaviorRootModuleIds.forEach { moduleId ->
                    require(moduleId in indexed) { "behavior root references an unresolved module: $moduleId" }
                    add(moduleId)
                }
                layout.behaviorRootEntityIds.forEach { entityId ->
                    add(requireNotNull(ownerByEntity[entityId]) { "behavior root entity has no module owner: $entityId" })
                }
            }.distinct().sorted()
            val canonicalIndexSha256 = boundedCanonicalSha256(
                budget.maximumIndexEvidenceBytes,
                "repair dependency index",
            ) {
                fun appendJoined(values: Collection<String>) {
                    values.forEachIndexed { index, value ->
                        if (index > 0) append(',')
                        append(value)
                    }
                }
                append("[profile]\n").append(profileId).append('|').append(profileSha256)
                    .append('|').append(layoutSha256).append('\n')
                indexed.values.forEach { module ->
                    append(module.id.length).append(':').append(module.id).append('|')
                    appendJoined(module.ownedPaths)
                    append('|')
                    appendJoined(module.dependencyContextPaths)
                    append('|')
                    appendJoined(module.entityIds)
                    append('|')
                    appendJoined(module.dependencies)
                    append('\n')
                }
                append("[paths]\n")
                sourcePaths.forEach { path -> append(path).append('|').append(ownerByPath[path].orEmpty()).append('\n') }
                append("[tokens]\n")
                ownerTokens.forEach { (token, owners) ->
                    append(token.length).append(':').append(token).append('|')
                    appendJoined(owners)
                    append('\n')
                }
                append("[behavior-roots]\n")
                appendJoined(behaviorRoots)
                append('\n')
            }
            val verifiedSnapshot = captureSourceSnapshot(root, sourcePaths, budget, profile, sourceView)
            require(revisionSha256(verifiedSnapshot) == revisionSha256(snapshot)) {
                "repair source inputs changed while dependency evidence was indexed"
            }
            return try {
                SecureRepairRuntime.authorizeIndexConstruction(graphAuthorityCandidate)
                ModuleRepairIndex(
                    projectRootCandidate = root,
                    profileCandidate = profile,
                    profileIdCandidate = profileId,
                    profileSha256Candidate = profileSha256,
                    budgetCandidate = budget,
                    modulesCandidate = indexed.toSortedMap(),
                    sourcesCandidate = sourceMap,
                    editableCandidate = editable,
                    ownerByPathCandidate = ownerByPath,
                    ownerByTokenCandidate = ownerTokens.mapValues { it.value.toSet() },
                    pathsByFileNameCandidate = sourcePaths.groupBy { it.substringAfterLast('/') }.mapValues { it.value.sorted() },
                    dependentsByModuleCandidate = dependents.mapValues { it.value.distinct().sorted() },
                    behaviorRootModulesCandidate = behaviorRoots,
                    sharedContextPathsCandidate = layout.sharedContextPaths.toSet(),
                    sharedInvalidationPathsCandidate = layout.sharedInvalidationPaths.toSet(),
                    indexSha256Candidate = canonicalIndexSha256,
                    sourceRevisionSha256Candidate = revisionSha256(snapshot),
                )
            } finally {
                SecureRepairRuntime.clearConstructionAuthorization()
            }
        }

        private fun derivePathDependencies(
            pathEdges: Map<String, List<String>>,
            modules: Map<String, IndexedModule>,
            ownerByPath: Map<String, String>,
            budget: RepairResourceBudget,
        ): Map<String, List<String>> {
            val edgeCount = pathEdges.values.sumOf { it.size.toLong() }
            if (edgeCount > budget.maximumDependencyEdges) {
                throw RepairBudgetExceededException(
                    "repair profile path dependencies exceed ${budget.maximumDependencyEdges} edges",
                )
            }
            var traversalCount = 0L
            var derivedDependencyCount = 0L
            return modules.keys.associateWith { moduleId ->
                val module = modules.getValue(moduleId)
                val visited = TreeSet<String>()
                val queue = ArrayDeque(module.ownedPaths.sorted())
                val dependencies = TreeSet<String>()
                while (queue.isNotEmpty()) {
                    val path = queue.removeFirst()
                    if (!visited.add(path)) continue
                    traversalCount = Math.addExact(traversalCount, 1L)
                    if (traversalCount > budget.maximumDependencyEdges) {
                        throw RepairBudgetExceededException(
                            "repair include-closure traversal exceeds ${budget.maximumDependencyEdges} entries",
                        )
                    }
                    ownerByPath[path]?.takeIf { it != moduleId }?.let(dependencies::add)
                    pathEdges[path].orEmpty().forEach(queue::addLast)
                }
                derivedDependencyCount = Math.addExact(derivedDependencyCount, dependencies.size.toLong())
                if (derivedDependencyCount > budget.maximumDependencyEdges) {
                    throw RepairBudgetExceededException(
                        "repair module include dependencies exceed ${budget.maximumDependencyEdges} edges",
                    )
                }
                dependencies.toList()
            }
        }
    }
}

data class RevisionFileDelta(
    val path: String,
    val beforeSha256: String?,
    val beforeBytes: Long?,
    val afterSha256: String,
    val beforeBlobSha256: String?,
    val afterBlobSha256: String,
    val afterBytes: Long,
)

/** Durable identity of the accepted inode a pending repair is allowed to restore. */
data class RepairPreimageMetadata(
    val metadataVersion: Int,
    val device: Long,
    val inode: Long,
    val mode: Int,
    val uid: Int,
    val gid: Int,
    val size: Long,
    val atimeSeconds: Long?,
    val atimeNanoseconds: Int?,
    val mtimeSeconds: Long,
    val mtimeNanoseconds: Int,
    val ctimeSeconds: Long,
    val ctimeNanoseconds: Int,
    val retainedName: String,
    val xattrPolicy: String = "NONE",
    val ancestorMetadata: List<RepairAncestorMetadata> = emptyList(),
) {
    init {
        require(metadataVersion in 1..2)
        require(device >= 0 && inode >= 0 && size >= 0)
        if (metadataVersion == 1) require(atimeSeconds == null && atimeNanoseconds == null)
        else {
            require(atimeSeconds != null && atimeNanoseconds != null)
            require(atimeNanoseconds in 0 until 1_000_000_000)
        }
        require(mtimeNanoseconds in 0 until 1_000_000_000)
        require(ctimeNanoseconds in 0 until 1_000_000_000)
        require(retainedName.matches(Regex("\\.[A-Za-z0-9_-]+-[0-9a-f]{64}\\.preimage")))
        require(xattrPolicy == "NONE")
        require(ancestorMetadata.map { it.path } == ancestorMetadata.map { it.path }.distinct().sortedBy { it.count { c -> c == '/' } })
    }

    internal fun matches(state: decompengine.acp.LinuxFileState, includeAtime: Boolean = true): Boolean =
        state.identity.key.device == device && state.identity.key.inode == inode &&
            state.identity.mode == mode && state.identity.uid == uid && state.identity.gid == gid &&
            state.size == size && state.modificationTimeSeconds == mtimeSeconds &&
            state.modificationTimeNanoseconds == mtimeNanoseconds &&
            (metadataVersion == 1 || !includeAtime || state.accessTimeSeconds == atimeSeconds &&
                state.accessTimeNanoseconds == atimeNanoseconds) &&
            (state.changeTimeSeconds > ctimeSeconds ||
                state.changeTimeSeconds == ctimeSeconds && state.changeTimeNanoseconds >= ctimeNanoseconds)

    internal fun matchesExactly(state: decompengine.acp.LinuxFileState): Boolean =
        state.identity.key.device == device && state.identity.key.inode == inode &&
            state.identity.mode == mode && state.identity.uid == uid && state.identity.gid == gid &&
            state.size == size && state.modificationTimeSeconds == mtimeSeconds &&
            state.modificationTimeNanoseconds == mtimeNanoseconds &&
            (metadataVersion == 1 || state.accessTimeSeconds == atimeSeconds &&
                state.accessTimeNanoseconds == atimeNanoseconds) &&
            state.changeTimeSeconds == ctimeSeconds && state.changeTimeNanoseconds == ctimeNanoseconds
}

/** Exact descriptor-bound metadata for each parent directory entry in an authorized path. */
data class RepairAncestorMetadata(
    val path: String,
    val device: Long,
    val inode: Long,
    val mode: Int,
    val uid: Int,
    val gid: Int,
    val linkCount: Int,
    val mountId: Long,
    val size: Long,
    val mtimeSeconds: Long,
    val mtimeNanoseconds: Int,
    val ctimeSeconds: Long,
    val ctimeNanoseconds: Int,
    val atimeSeconds: Long? = null,
    val atimeNanoseconds: Int? = null,
    val entryCount: Int? = null,
    val entriesSha256: String? = null,
) {
    init {
        require(path == "." || path == normalizedRelative(path))
        require(device >= 0 && inode >= 0 && mountId >= 0 && size >= 0 && linkCount >= 1)
        require(mtimeNanoseconds in 0 until 1_000_000_000)
        require(ctimeNanoseconds in 0 until 1_000_000_000)
        require((atimeSeconds == null) == (atimeNanoseconds == null))
        require(atimeNanoseconds == null || atimeNanoseconds in 0 until 1_000_000_000)
        require((entryCount == null) == (entriesSha256 == null))
        require(entryCount == null || entryCount >= 0)
        require(entriesSha256 == null || entriesSha256.matches(REPAIR_BLOB_DIGEST))
    }
}

enum class ModuleRevisionStatus { ROOT, ACCEPTED, REJECTED, PROVISIONAL, LEGACY_UNVERIFIED }

data class ModuleRevisionNode(
    val id: String,
    val parentId: String?,
    val ordinal: Int,
    val status: ModuleRevisionStatus,
    val sourceRevisionSha256: String,
    val changes: List<RevisionFileDelta>,
    val changedModules: List<String>,
    val invalidatedModules: List<String>,
    val evidenceKind: String?,
    val evidenceArtifact: String?,
    val recoveredAfterCrash: Boolean,
    val evidenceSummary: String? = null,
    val repairMetadata: RevisionRepairMetadata? = null,
    val validationProof: RepairValidationProof? = null,
    val rollbackRecord: RepairRollbackRecord? = null,
    /** Physical preimages displaced by this node's publication, distinct from logical ACP changes. */
    val publicationChanges: List<RevisionFileDelta> = emptyList(),
    /** Durable identity commitments required to finish cleaning retained physical preimages. */
    val publicationPreimageMetadata: Map<String, RepairPreimageMetadata> = emptyMap(),
)

enum class RepairRollbackState {
    RESTORE_IN_PROGRESS,
    RESTORE_FAILED_UNRESOLVED,
    RESTORED_VERIFIED,
    RESTORED_AFTER_FAILURE,
    NOT_REQUIRED_VERIFIED,
}

enum class RepairRollbackStage { SOURCE_RESTORE, SOURCE_VERIFICATION }

enum class RepairRollbackFailureCode {
    RESTORE_OPERATION_FAILED,
    UNRECOGNIZED_SOURCE_STATE,
    TARGET_DIGEST_MISMATCH,
}

private class RepairRollbackException(
    val rollbackStage: RepairRollbackStage,
    val failureCode: RepairRollbackFailureCode,
    message: String,
) : IllegalStateException(message)

/** Durable, allowlisted evidence that one attempt restored its exact authorized source revision. */
data class RepairRollbackRecord(
    val schemaVersion: Int = 1,
    val attemptId: String,
    val runId: String?,
    val targetRevisionId: String,
    val expectedSourceRevisionSha256: String,
    val state: RepairRollbackState,
    val failureStage: RepairRollbackStage? = null,
    val failureCode: RepairRollbackFailureCode? = null,
    val observedSourceRevisionSha256: String? = null,
    val legacyPendingStateUnknown: Boolean = false,
    val candidateSourceInstallStarted: Boolean? = false,
) {
    init {
        require(schemaVersion == 1)
        require(attemptId.matches(Regex("revision_[A-Za-z0-9_]+")))
        require(runId == null || runId.matches(Regex("run_[0-9]{8}")))
        require(targetRevisionId.matches(Regex("(?:root|revision)_[A-Za-z0-9_]+")))
        require(expectedSourceRevisionSha256.matches(Regex("[0-9a-f]{64}")))
        require(observedSourceRevisionSha256 == null ||
            observedSourceRevisionSha256.matches(Regex("[0-9a-f]{64}")))
        require((failureStage == null) == (failureCode == null))
        if (failureStage != null) require((failureStage to requireNotNull(failureCode)) in RECOVERY_FAILURE_PAIRS) {
            "rollback failure stage/code pair is invalid"
        }
        require(legacyPendingStateUnknown || candidateSourceInstallStarted != null) {
            "native rollback requires a known source-install marker"
        }
        when (state) {
            RepairRollbackState.RESTORE_FAILED_UNRESOLVED -> require(failureCode != null)
            RepairRollbackState.RESTORED_AFTER_FAILURE -> require(failureCode != null)
            RepairRollbackState.RESTORED_VERIFIED,
            RepairRollbackState.NOT_REQUIRED_VERIFIED -> require(failureCode == null)
            RepairRollbackState.RESTORE_IN_PROGRESS -> Unit
        }
        if (state in setOf(RepairRollbackState.RESTORED_VERIFIED,
                RepairRollbackState.RESTORED_AFTER_FAILURE, RepairRollbackState.NOT_REQUIRED_VERIFIED)) {
            require(observedSourceRevisionSha256 == expectedSourceRevisionSha256)
        }
        if (state == RepairRollbackState.NOT_REQUIRED_VERIFIED) {
            require(candidateSourceInstallStarted == false) {
                "not-required rollback requires an unstarted source-install marker"
            }
        }
        if (state == RepairRollbackState.RESTORED_VERIFIED) {
            require(candidateSourceInstallStarted != false) {
                "failure-free restored rollback has an unstarted source-install marker"
            }
        }
    }
}

data class ModuleRevisionGraphSnapshot(
    val profileId: String,
    val profileSha256: String,
    val indexSha256: String,
    val headId: String,
    val nextOrdinal: Int,
    val nodes: List<ModuleRevisionNode>,
    val pendingAttemptId: String?,
    val storedBlobBytes: Long,
    val regressionCorpusSha256: String,
    val schemaVersion: Int = 2,
    val provisionalHeadId: String? = null,
    val fullyAcceptedHeadId: String? = null,
    val runs: List<RepairRunState> = emptyList(),
)

class RetainedRegressionCorpus(inputs: Collection<ProcessInput>, val sha256: String) {
    private val content = immutableList(inputs.map(ProcessInput::deepCopy))

    /** Each read is detached so even mutation of a returned stdin array cannot alter this value. */
    val inputs: List<ProcessInput> get() = immutableList(content.map(ProcessInput::deepCopy))
}

/** Data-only snapshot issued to one secure repair session for exploration-before-repair flows. */
class RepairExplorationSnapshotData(
    val formatVersion: Int,
    val projectPath: String,
    inputs: Collection<ProcessInput>,
    val corpusSha256: String,
    val graphSha256: String,
    val profileSha256: String,
    val indexSha256: String,
    val headId: String,
    val originalBinarySha256: String,
) {
    private val corpus = RetainedRegressionCorpus(inputs, corpusSha256)
    val inputs: List<ProcessInput> get() = corpus.inputs
}

class ModuleRevisionAttempt internal constructor(val id: String)

internal sealed interface ModuleRevisionFaultPoint {
    data class BeforePreimageRead(val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class BeforeDescriptorBoundRead(val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class AfterDescriptorBoundRead(val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class BeforePublicationExchange(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class AfterPublicationExchange(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class AfterPublicationTargetDirectorySync(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class AfterPublicationMove(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class BeforeOwnedEntryUnlink(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class BeforeRollbackExchange(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data object BeforeHeadIndexValidation : ModuleRevisionFaultPoint
    data object AfterHeadIndexValidation : ModuleRevisionFaultPoint
    data object BeforeSchema6DecisionPersist : ModuleRevisionFaultPoint
    data object BeforeSchema6DecisionValidation : ModuleRevisionFaultPoint
    data object Schema6DecisionPrevalidated : ModuleRevisionFaultPoint
    data class AfterPublicationStageIntentPersist(val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class AfterPublicationStage(val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class BeforeUndecidedStageUnlink(val path: String) : ModuleRevisionFaultPoint
    data object AfterCandidateStatePersist : ModuleRevisionFaultPoint
    data object AfterHeadPersist : ModuleRevisionFaultPoint
    data object BeforeRecoveredAcceptancePersist : ModuleRevisionFaultPoint
    data object AfterRecoveredAcceptancePersist : ModuleRevisionFaultPoint
    data object BeforeSourceManifestSync : ModuleRevisionFaultPoint
    data object BeforeCompatibilityLogSync : ModuleRevisionFaultPoint
    data class AfterStateTemporaryDirectorySync(val scope: String, val name: String) : ModuleRevisionFaultPoint
    data class AfterStatePublicationExchange(val scope: String, val name: String) : ModuleRevisionFaultPoint
    data class AfterStatePublicationDirectorySync(val scope: String, val name: String) : ModuleRevisionFaultPoint
}

internal fun interface ModuleRevisionFaultInjector {
    fun hit(point: ModuleRevisionFaultPoint)
}

data class RevisionRepairMetadata(
    val iterationIndex: Int,
    val failureKind: String,
    val prompt: String,
    val summary: String?,
    val retainedRegressionIds: List<String>,
    val before: RepairEvidence?,
    val regressionCorpusSha256: String? = null,
    val agentInvocation: RepairAgentInvocationBinding? = null,
    val turnIntent: RepairAgentTurnIntentBinding? = null,
    val publicationMode: RepairPublicationMode = RepairPublicationMode.ACP_RELEASE,
    val runId: String? = null,
) {
    init {
        require(iterationIndex > 0)
        require(failureKind in setOf("compile", "behavior"))
        require(retainedRegressionIds == retainedRegressionIds.distinct())
        require(regressionCorpusSha256 == null || regressionCorpusSha256.matches(Regex("[0-9a-f]{64}")))
    }
}

enum class RepairPublicationMode { ACP_RELEASE, TEST_ONLY_NON_RELEASE }

enum class RepairAgentAssessmentStatus { PENDING, ACCEPTED, REJECTED, PROVISIONAL }

/** Content-addressed reference to the host-authored intent persisted before provider dispatch. */
data class RepairAgentTurnIntentBinding(
    val intentPath: String,
    val intentSha256: String,
    val turnId: String,
) {
    init {
        require(intentPath.matches(REPAIR_INTENT_PATH)) { "repair ACP intent path is invalid" }
        require(intentSha256.matches(REPAIR_BLOB_DIGEST)) { "repair ACP intent digest is invalid" }
        require(decompengine.agent.isCanonicalAgentTurnId(turnId)) { "repair ACP intent turn id is invalid" }
    }
}

/**
 * Content-addressed link from a repair assessment to its immutable schema-v2 ACP invocation.
 * The raw provider evidence remains a separate artifact and is never rewritten as workflow state
 * advances from pending to accepted or rejected.
 */
data class RepairAgentInvocationBinding(
    val receiptPath: String,
    val receiptSha256: String,
    val receiptSchemaVersion: Int,
    val requestSha256: String,
    val resultChangesSha256: String,
    val terminalOutcome: String,
    val receiptReleaseComplete: Boolean,
    val assessmentStatus: RepairAgentAssessmentStatus,
    val intentPath: String? = null,
    val intentSha256: String? = null,
    val turnId: String? = null,
    val assessmentPath: String? = null,
    val assessmentSha256: String? = null,
) {
    init {
        require(receiptPath.matches(REPAIR_RECEIPT_PATH)) { "repair ACP receipt path is invalid" }
        require(receiptSha256.matches(REPAIR_BLOB_DIGEST)) { "repair ACP receipt digest is invalid" }
        require(receiptSchemaVersion in 2..3) { "repair ACP receipt schema is unsupported" }
        require((intentPath == null) == (intentSha256 == null)) { "repair ACP intent reference is incomplete" }
        intentPath?.let { require(it.matches(REPAIR_INTENT_PATH)) { "repair ACP intent path is invalid" } }
        intentSha256?.let { require(it.matches(REPAIR_BLOB_DIGEST)) { "repair ACP intent digest is invalid" } }
        turnId?.let { require(decompengine.agent.isCanonicalAgentTurnId(it)) { "repair ACP turn id is invalid" } }
        require((intentPath == null) == (turnId == null)) { "repair ACP turn identity reference is incomplete" }
        require((assessmentPath == null) == (assessmentSha256 == null)) { "repair ACP assessment reference is incomplete" }
        assessmentPath?.let { require(it.matches(REPAIR_ASSESSMENT_PATH)) { "repair ACP assessment path is invalid" } }
        assessmentSha256?.let { require(it.matches(REPAIR_BLOB_DIGEST)) { "repair ACP assessment digest is invalid" } }
        require(requestSha256.matches(REPAIR_BLOB_DIGEST)) { "repair ACP request digest is invalid" }
        require(resultChangesSha256.matches(REPAIR_BLOB_DIGEST)) {
            "repair ACP result-change digest is invalid"
        }
        require(terminalOutcome.matches(Regex("(?:returned|failed)-[a-z0-9-]+"))) {
            "repair ACP terminal outcome is invalid"
        }
        if (assessmentStatus == RepairAgentAssessmentStatus.ACCEPTED) {
            require(receiptReleaseComplete && terminalOutcome == "returned-completed") {
                "only a release-complete returned ACP invocation may be accepted"
            }
        }
    }
}

class RepairAgentEvidencePersistenceException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

private data class PendingAttempt(
    val id: String,
    val parentId: String,
    val ordinal: Int,
    val allowedPaths: List<String>,
    val parentSourceRevisionSha256: String,
    val preimages: List<RevisionFileDelta>,
    val candidateSourceRevisionSha256: String?,
    val candidateChanges: List<RevisionFileDelta>,
    val repairMetadata: RevisionRepairMetadata?,
    val detached: Boolean = false,
    val promotionChanges: List<RevisionFileDelta> = emptyList(),
    val rollbackRecord: RepairRollbackRecord? = null,
    val legacyRecoveryRequired: Boolean = false,
    val preimageMetadata: Map<String, RepairPreimageMetadata>? = null,
    val promotionPreimageMetadata: Map<String, RepairPreimageMetadata>? = null,
    /** Present only after the durable schema-6 acceptance decision has been written. */
    val acceptanceDecision: RepairAcceptanceDecision? = null,
    /** Compact exact metadata commitment for the full accepted source tree at attempt admission. */
    val sourceWitnessSha256: String? = null,
    /** Schema-6 private inodes authenticated before they are linked into publication staging. */
    val predecisionStageFiles: List<RepairPredecisionStage> = emptyList(),
)

/** The point of no return for a schema-6 detached candidate. */
private data class RepairAcceptanceDecision(
    val proof: RepairValidationProof,
    val evidenceKind: String,
    val evidenceSummary: String,
    val evidenceArtifact: String?,
    val promotionChanges: List<RevisionFileDelta>,
    val intendedHeadId: String,
    val intendedRunId: String?,
    val intendedRunStatus: RepairRunStatus?,
    val stagedFiles: List<RepairStagedFile> = emptyList(),
    val committedNode: ModuleRevisionNode? = null,
    val committedRun: RepairRunState? = null,
) {
    init {
        require(evidenceKind.isNotBlank())
        require(intendedHeadId.matches(Regex("revision_[A-Za-z0-9_]+")))
        require(intendedRunId == null || intendedRunId.matches(Regex("run_[0-9]{8}")))
        require((intendedRunId == null) == (intendedRunStatus == null))
        require(intendedRunStatus == null || intendedRunStatus == RepairRunStatus.FULLY_ACCEPTED)
        require((intendedRunId == null) == (committedRun == null))
        require(committedRun == null || committedRun.id == intendedRunId &&
            committedRun.status == intendedRunStatus && committedRun.acceptedHeadId == intendedHeadId)
        require(promotionChanges.isNotEmpty())
        require(promotionChanges.map { it.path } == promotionChanges.map { it.path }.distinct().sorted())
        require(stagedFiles.map { it.path } == promotionChanges.map { it.path })
        require(stagedFiles.map { it.stagingName }.distinct().size == stagedFiles.size)
        require(committedNode == null || committedNode.id == intendedHeadId)
    }
}

private data class RepairStagedFile(
    val path: String,
    val stagingName: String,
    val device: Long,
    val inode: Long,
    val mountId: Long,
    val mode: Int,
    val uid: Int,
    val gid: Int,
    val linkCount: Int,
    val sha256: String,
    val size: Long,
    val atimeSeconds: Long,
    val atimeNanoseconds: Int,
    val mtimeSeconds: Long,
    val mtimeNanoseconds: Int,
    val parentDevice: Long,
    val parentInode: Long,
    val parentMountId: Long,
) {
    init {
        require(path == normalizedRelative(path))
        require(stagingName.matches(Regex("\\.revision_[A-Za-z0-9_]+-[0-9a-f]{64}\\.preimage")))
        require(device >= 0 && inode >= 0 && mountId >= 0 && linkCount == 1 && size >= 0)
        require(parentDevice >= 0 && parentInode >= 0 && parentMountId >= 0)
        require(sha256.matches(REPAIR_BLOB_DIGEST))
        require(atimeNanoseconds in 0 until 1_000_000_000 && mtimeNanoseconds in 0 until 1_000_000_000)
    }
}

/** Inode identity durably registered before its private staging name is created. */
internal data class RepairPredecisionStage(
    val path: String,
    val stagingName: String,
    val device: Long,
    val inode: Long,
    val mountId: Long,
    val mode: Int,
    val uid: Int,
    val gid: Int,
    val sha256: String,
    val size: Long,
) {
    init {
        require(path == normalizedRelative(path))
        require(stagingName.matches(Regex("\\.revision_[A-Za-z0-9_]+-[0-9a-f]{64}\\.preimage")))
        require(device >= 0 && inode >= 0 && mountId >= 0 && mode >= 0 && uid >= 0 && gid >= 0 && size >= 0)
        require(sha256.matches(REPAIR_BLOB_DIGEST))
    }
}

/** A durable acceptance decision exists, but source publication could not be safely completed. */
class RepairAcceptancePendingException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

private fun validatePendingPreimageAggregate(
    allowedPaths: List<String>,
    preimages: List<RevisionFileDelta>,
    budget: RepairResourceBudget,
    metadata: Map<String, RepairPreimageMetadata>? = null,
) {
    require(allowedPaths == allowedPaths.distinct().sorted() && allowedPaths.isNotEmpty())
    require(preimages.map { it.path } == allowedPaths) {
        "pending repair preimages do not exactly cover authorized paths"
    }
    if (metadata != null) {
        require(metadata.keys.sorted() == allowedPaths) {
            "pending repair metadata does not exactly cover authorized paths"
        }
        preimages.forEach { preimage ->
            require(metadata.getValue(preimage.path).size == preimage.afterBytes) {
                "pending repair metadata size differs from its content commitment"
            }
        }
    }
    if (allowedPaths.size > budget.maximumContextFiles) {
        throw RepairBudgetExceededException(
            "pending repair has ${allowedPaths.size} preimages; limit=${budget.maximumContextFiles}",
        )
    }
    val bytes = preimages.fold(0L) { total, preimage -> Math.addExact(total, preimage.afterBytes) }
    if (bytes > budget.maximumContextBytes) {
        throw RepairBudgetExceededException(
            "pending repair preimages contain $bytes bytes; limit=${budget.maximumContextBytes}",
        )
    }
    if (bytes > budget.maximumStagingBytes) {
        throw RepairBudgetExceededException(
            "pending repair preimages contain $bytes bytes; staging limit=${budget.maximumStagingBytes}",
        )
    }
}

private data class RevisionGraphState(
    val budget: RepairResourceBudget,
    val profileId: String,
    val profileSha256: String,
    val editablePaths: List<String>,
    val indexSha256: String,
    val retainedRegressionInputs: List<ProcessInput>,
    val regressionCorpusSha256: String,
    val headId: String,
    val nextOrdinal: Int,
    val nodes: List<ModuleRevisionNode>,
    val pending: PendingAttempt?,
    val storedBlobBytes: Long,
    val schemaVersion: Int = 2,
    val provisionalHeadId: String? = null,
    val fullyAcceptedHeadId: String? = null,
    val acceptedProof: RepairValidationProof? = null,
    val runs: List<RepairRunState> = emptyList(),
)

private fun deriveSchema6PromotionChanges(state: RevisionGraphState, pending: PendingAttempt): List<RevisionFileDelta> {
    val baseSources = revisionSourcesAt(state.nodes, revisionCanonicalBase(state.nodes, state.headId))
    val finalSources = revisionSourcesAt(state.nodes, pending.parentId).toMutableMap()
    pending.candidateChanges.forEach { change ->
        finalSources[change.path] = IndexedSource(change.path, change.afterBytes, change.afterSha256)
    }
    return finalSources.toSortedMap().mapNotNull { (path, after) ->
        val before = baseSources.getValue(path)
        if (before == after) null else RevisionFileDelta(
            path, before.sha256, before.bytes, after.sha256, before.sha256, after.sha256, after.bytes,
        )
    }
}

private fun discardUndecidedPublicationStages(
    store: RepairStateStore,
    changes: List<RevisionFileDelta>,
    attemptId: String,
    registeredStages: List<RepairPredecisionStage> = emptyList(),
) {
    val stagesByPath = registeredStages.associateBy { it.path }
    require(stagesByPath.size == registeredStages.size &&
        registeredStages.map { it.path } == changes.map { it.path }.filter { it in stagesByPath }.sorted()) {
        "schema-6 predecision stage manifest is duplicate or outside the publication plan"
    }
    val registeredNames = registeredStages.map { it.stagingName }.toSet()
    val unexpected = store.publicationStagingEntries(100_000).filter {
        it.startsWith(".$attemptId-") && it !in registeredNames
    }
    require(unexpected.isEmpty()) { "schema-6 predecision staging contains uncommitted attempt entries" }
    changes.sortedBy { it.path }.forEach { change ->
        val expectedName = sourceTransactionPreimageName(change.path, attemptId)
        val registered = stagesByPath[change.path]
        if (registered != null) {
            require(registered.stagingName == expectedName && registered.sha256 == change.afterSha256 &&
                registered.size == change.afterBytes) {
                "schema-6 predecision stage manifest differs from its candidate: ${change.path}"
            }
        }
        store.discardUndecidedPublicationStage(expectedName, change.afterSha256, change.afterBytes, registered)
    }
}

private fun verifySchema6PendingWitness(
    projectRoot: Path,
    state: RevisionGraphState,
    pending: PendingAttempt,
    budget: RepairResourceBudget,
) {
    require(state.schemaVersion >= 6 && pending.detached && pending.acceptanceDecision == null)
    val published = revisionSourcesAt(state.nodes, revisionCanonicalBase(state.nodes, state.headId))
    val metadata = requireNotNull(pending.preimageMetadata)
    metadata.forEach { (path, witness) ->
        val expected = requireNotNull(published[path]) { "schema-6 witness path is absent from its accepted base: $path" }
        val observed = readStableRegularFile(projectRoot, path, budget.maximumSourceFileBytes,
            requireNoExtendedAttributes = true)
        require(observed.sha256 == expected.sha256 && observed.bytes.size.toLong() == expected.bytes &&
            witness.matchesExactly(observed.state) &&
            witness.ancestorMetadata == captureSchema6AncestorMetadata(projectRoot, path, budget.maximumStateDirectoryEntries)) {
            "schema-6 undecided source differs from its exact attempt witness: $path"
        }
    }
    val expectedDigest = requireNotNull(pending.sourceWitnessSha256) {
        "schema-6 pending attempt is missing its complete source-tree metadata commitment"
    }
    require(schema6SourceWitnessSha256(projectRoot, published, budget) == expectedDigest) {
        "schema-6 accepted source tree differs from its exact attempt-time metadata commitment"
    }
}

private fun schema6SourceWitnessSha256(
    projectRoot: Path,
    sources: Map<String, IndexedSource>,
    budget: RepairResourceBudget,
): String {
    require(sources.isNotEmpty() && sources.size <= budget.maximumSourceFiles) {
        "schema-6 source witness exceeds its bounded file inventory"
    }
    var totalBytes = 0L
    val digest = MessageDigest.getInstance("SHA-256")
    val ancestorCache = HashMap<String, RepairAncestorMetadata>()
    fun update(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        digest.update(bytes.size.toString().toByteArray(Charsets.US_ASCII))
        digest.update(':'.code.toByte())
        digest.update(bytes)
    }
    sources.toSortedMap().forEach { (path, expected) ->
        val observed = readStableRegularFile(projectRoot, path, budget.maximumSourceFileBytes,
            requireNoExtendedAttributes = true)
        totalBytes = Math.addExact(totalBytes, observed.bytes.size.toLong())
        require(totalBytes <= budget.maximumSourceBytes && observed.sha256 == expected.sha256 &&
            observed.bytes.size.toLong() == expected.bytes) {
            "schema-6 source witness content differs from its accepted revision: $path"
        }
        update(path)
        update(expected.sha256)
        update(expected.bytes.toString())
        update(observed.state.toString())
        val parentPaths = listOf(".") + path.split('/').dropLast(1).mapIndexed { index, _ ->
            path.split('/').take(index + 1).joinToString("/")
        }
        if (parentPaths.any { it !in ancestorCache }) {
            captureSchema6AncestorMetadata(projectRoot, path, budget.maximumStateDirectoryEntries)
                .forEach { ancestorCache.putIfAbsent(it.path, it) }
        }
        update(parentPaths.map { requireNotNull(ancestorCache[it]) }.toString())
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

private fun captureSchema6AncestorMetadata(projectRoot: Path, relative: String, maximumEntries: Int): List<RepairAncestorMetadata> {
    val parts = normalizedRelative(relative).split('/')
    val root = openRepairRootDirectory(projectRoot)
    val owned = mutableListOf<LinuxDescriptor>()
    val result = mutableListOf<RepairAncestorMetadata>()
    try {
        fun capture(path: String, directory: LinuxDescriptor) {
            val state = LinuxFilesystemSyscalls.fileState(directory)
            val names = LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(directory, maximumEntries).sorted()
            val id = state.identity
            result += RepairAncestorMetadata(
                path, id.key.device, id.key.inode, id.mode, id.uid, id.gid, id.linkCount, id.mountId, state.size,
                state.modificationTimeSeconds, state.modificationTimeNanoseconds,
                state.changeTimeSeconds, state.changeTimeNanoseconds,
                state.accessTimeSeconds, state.accessTimeNanoseconds, names.size, repairDirectoryEntriesSha256(names),
            )
        }
        capture(".", root)
        var parent = root
        parts.dropLast(1).forEachIndexed { index, component ->
            parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component)
            owned += parent
            capture(parts.take(index + 1).joinToString("/"), parent)
        }
        return immutableList(result)
    } finally {
        owned.asReversed().forEach(LinuxDescriptor::close)
        root.close()
    }
}

/** The only failure transition: callers publish this entire candidate in one canonical write. */
private fun withCommittedRollbackFailure(candidate: RevisionGraphState, record: RepairRollbackRecord): RevisionGraphState {
    val pending = requireNotNull(candidate.pending)
    require(record.state == RepairRollbackState.RESTORE_FAILED_UNRESOLVED)
    val target = if (pending.detached) candidate.headId else pending.parentId
    validatePendingRollbackRecord(record, pending, target,
        revisionSha256(revisionSourcesAt(candidate.nodes, target).values))
    val marked = candidate.copy(pending = pending.copy(rollbackRecord = record))
    val runId = record.runId ?: return marked // Standalone attempts never fabricate runs.
    val run = requireNotNull(candidate.runs.lastOrNull())
    require(run.id == runId && run.status in setOf(RepairRunStatus.RUNNING,
        RepairRunStatus.VALIDATION_FAILED, RepairRunStatus.ROLLBACK_FAILED))
    require(run.rollbackFailureAttemptId == null || run.rollbackFailureAttemptId == pending.id)
    return marked.copy(runs = candidate.runs.dropLast(1) + run.copy(
        schemaVersion = maxOf(run.schemaVersion, 2), status = RepairRunStatus.ROLLBACK_FAILED,
        rollbackFailureAttemptId = pending.id, rollbackResolution = record.state))
}

/** Resolution changes the derived index, never the historical failed terminal outcome. */
private fun withFinalizedRollback(candidate: RevisionGraphState, record: RepairRollbackRecord): RevisionGraphState {
    val run = candidate.runs.singleOrNull { it.id == record.runId } ?: return candidate
    if (run.status != RepairRunStatus.ROLLBACK_FAILED) return candidate // No schema-1 history inference.
    require(run.rollbackFailureAttemptId == record.attemptId && record.state == RepairRollbackState.RESTORED_AFTER_FAILURE)
    return candidate.copy(runs = candidate.runs.map {
        if (it.id == run.id) it.copy(rollbackResolution = record.state) else it
    })
}

private fun reservedRollbackRecord(candidate: RevisionGraphState, pending: PendingAttempt): RepairRollbackRecord {
    val record = pending.rollbackRecord ?: initialRollbackRecord(candidate, pending, pending.legacyRecoveryRequired)
    return record.copy(state = RepairRollbackState.RESTORE_FAILED_UNRESOLVED,
        failureStage = RepairRollbackStage.SOURCE_VERIFICATION,
        failureCode = RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
        observedSourceRevisionSha256 = record.expectedSourceRevisionSha256)
}


private val RESTART_RECOVERY_EVIDENCE = RepairEvidence("crash-recovery", "restored pending repair preimages after restart")
private val RESTART_INTERRUPTION_EVIDENCE = RepairEvidence("interrupted", "repair run reopened without a completed terminal publication")

private fun rollbackOutcomeRecord(record: RepairRollbackRecord, observed: String): RepairRollbackRecord = record.copy(
    state = when {
        record.failureCode != null -> RepairRollbackState.RESTORED_AFTER_FAILURE
        record.candidateSourceInstallStarted == false -> RepairRollbackState.NOT_REQUIRED_VERIFIED
        else -> RepairRollbackState.RESTORED_VERIFIED
    },
    observedSourceRevisionSha256 = observed,
)

private fun finishedRunCandidate(candidate: RevisionGraphState, status: RepairRunStatus, evidence: RepairEvidence?): RevisionGraphState {
    require(status != RepairRunStatus.RUNNING && status != RepairRunStatus.FULLY_ACCEPTED)
    val run = requireNotNull(candidate.runs.lastOrNull())
    if (run.terminal) return candidate
    require(status != RepairRunStatus.ROLLBACK_FAILED) { "rollback failure requires a committed attempt record" }
    require(candidate.pending == null || status == RepairRunStatus.VALIDATION_FAILED)
    return candidate.copy(runs = candidate.runs.dropLast(1) + run.copy(status = status,
        acceptedHeadId = candidate.fullyAcceptedHeadId, provisionalHeadId = candidate.provisionalHeadId,
        lastEvidence = evidence))
}

private fun finalizedRepairNode(
    pending: PendingAttempt,
    status: ModuleRevisionStatus,
    evidence: RepairEvidence?,
    recovered: Boolean,
    rollbackRecord: RepairRollbackRecord?,
    changedModules: () -> List<String>,
    invalidatedModules: () -> List<String>,
    normalizeText: (String) -> String = { it },
    normalizePath: (String) -> String = { it },
): ModuleRevisionNode {
    val assessment = when (status) {
        ModuleRevisionStatus.ACCEPTED -> RepairAgentAssessmentStatus.ACCEPTED
        ModuleRevisionStatus.PROVISIONAL -> RepairAgentAssessmentStatus.PROVISIONAL
        ModuleRevisionStatus.REJECTED -> RepairAgentAssessmentStatus.REJECTED
        ModuleRevisionStatus.LEGACY_UNVERIFIED -> error("new repair cannot finalize as legacy unverified")
        ModuleRevisionStatus.ROOT -> error("pending repair cannot finalize as a root node")
    }
    val finalizedMetadata = pending.repairMetadata?.let { metadata ->
        val invocation = metadata.agentInvocation
        if (status == ModuleRevisionStatus.ACCEPTED &&
            metadata.publicationMode == RepairPublicationMode.ACP_RELEASE
        ) {
            requireNotNull(invocation) {
                "agent-driven repair cannot be accepted without invocation-bound ACP evidence"
            }
            require(invocation.receiptReleaseComplete && invocation.terminalOutcome == "returned-completed") {
                "agent-driven repair cannot be accepted with incomplete ACP invocation evidence"
            }
        }
        metadata.copy(agentInvocation = invocation?.copy(assessmentStatus = assessment))
    }
    // A pre-schema-5 pending record has no durable inode/metadata witness.  Recovery may
    // restore its content, but must not manufacture schema-5 physical-publication authority.
    val hasPhysicalPreimageCommitment = if (pending.detached) pending.promotionPreimageMetadata != null
        else pending.preimageMetadata != null
    val physicalChanges = if (!hasPhysicalPreimageCommitment) emptyList() else when {
        status == ModuleRevisionStatus.ACCEPTED || pending.rollbackRecord?.candidateSourceInstallStarted == true ->
            if (pending.detached) pending.promotionChanges else pending.candidateChanges
        else -> emptyList()
    }
    val allPhysicalMetadata = if (pending.detached) pending.promotionPreimageMetadata else pending.preimageMetadata
    val physicalPreimageMetadata = physicalChanges.mapNotNull { change ->
        allPhysicalMetadata?.get(change.path)?.let { change.path to it }
    }.toMap()
    return ModuleRevisionNode(
        id = pending.id,
        parentId = pending.parentId,
        ordinal = pending.ordinal,
        status = status,
        sourceRevisionSha256 = pending.candidateSourceRevisionSha256 ?: pending.parentSourceRevisionSha256,
        changes = pending.candidateChanges,
        changedModules = changedModules(),
        invalidatedModules = invalidatedModules(),
        evidenceKind = evidence?.kind?.let(normalizeText),
        evidenceArtifact = evidence?.artifactPath?.let(normalizePath),
        recoveredAfterCrash = recovered,
        evidenceSummary = evidence?.summary?.let(normalizeText),
        repairMetadata = finalizedMetadata,
        rollbackRecord = rollbackRecord?.copy(),
        publicationChanges = immutableList(physicalChanges.map(RevisionFileDelta::copy)),
        publicationPreimageMetadata = immutableRepairMap(physicalPreimageMetadata),
    )
}


private fun renderCompatibilityProjection(
    candidates: List<ModuleRevisionNode>,
    maximumBytes: Long,
): ByteArray {
    val nodes = candidates.filter { it.status != ModuleRevisionStatus.ROOT && it.changes.isNotEmpty() }
    var projectedBytes = 0L
    nodes.forEach { node ->
        projectedBytes = Math.addExact(
            projectedBytes,
            compatibilityRevisionRecord(node).toByteArray(Charsets.UTF_8).size.toLong(),
        )
        if (projectedBytes > maximumBytes) {
            throw RepairBudgetExceededException(
                "source revision compatibility projection exceeds $maximumBytes bytes",
            )
        }
    }
    val payload = buildString(projectedBytes.toInt()) {
        nodes.forEach { append(compatibilityRevisionRecord(it)) }
    }.toByteArray(Charsets.UTF_8)
    if (payload.size.toLong() > maximumBytes) {
        throw RepairBudgetExceededException(
            "source revision compatibility projection exceeds $maximumBytes bytes",
        )
    }
    return payload
}


private fun compatibilityRevisionRecord(node: ModuleRevisionNode): String = buildString {
    append("{\"iteration\":").append(node.repairMetadata?.iterationIndex ?: node.ordinal)
    append(",\"revisionId\":\"").append(node.id.jsonEscape()).append("\"")
    append(",\"accepted\":").append(node.status == ModuleRevisionStatus.ACCEPTED)
    append(",\"evidenceKind\":")
        .append(node.evidenceKind?.let { "\"${it.jsonEscape()}\"" } ?: "null")
    append(",\"evidenceArtifact\":")
        .append(node.evidenceArtifact?.let { "\"${it.jsonEscape()}\"" } ?: "null")
    append(",\"changes\":[")
    node.changes.forEachIndexed { index, change ->
        if (index > 0) append(',')
        append("{\"path\":\"").append(change.path.jsonEscape()).append("\"")
        append(",\"beforeSha256\":\"").append(change.beforeSha256).append("\"")
        append(",\"afterSha256\":\"").append(change.afterSha256).append("\"}")
    }
    append("]}\n")
}

private enum class RecoveryPublicationCase { MARKED, FAILURE_PENDING, RESOLVED_FAILURE_FINAL, DIRECT_FINAL, INTERRUPTED_FINAL }

/** Stream at most fifteen real producer size shapes. Placeholders are never publications. */
private fun forEachRecoveryPublicationCandidate(
    candidate: RevisionGraphState,
    changedModules: () -> List<String>,
    invalidatedModules: () -> List<String>,
    consume: (RecoveryPublicationCase, RevisionGraphState) -> Unit,
) {
    require(candidate.schemaVersion >= 4)
    val originalPending = requireNotNull(candidate.pending)
    val prior = originalPending.rollbackRecord ?: initialRollbackRecord(candidate, originalPending, originalPending.legacyRecoveryRequired)
    val markedRecord = if (prior.failureCode != null) prior else prior.copy(state = RepairRollbackState.RESTORE_IN_PROGRESS)
    val pending = originalPending.copy(rollbackRecord = markedRecord)
    val marked = candidate.copy(pending = pending)
    consume(RecoveryPublicationCase.MARKED, marked)
    fun final(record: RepairRollbackRecord, base: RevisionGraphState): RevisionGraphState {
        val actualPending = requireNotNull(base.pending)
        val node = finalizedRepairNode(actualPending, ModuleRevisionStatus.REJECTED, RESTART_RECOVERY_EVIDENCE,
            true, record, changedModules, invalidatedModules)
        return withFinalizedRollback(base.copy(nodes = base.nodes + node, pending = null), record)
    }
    RECOVERY_FAILURE_PAIRS.forEach { (stage, code) ->
        listOf<String?>(null, markedRecord.expectedSourceRevisionSha256).forEach { observation ->
            val failedRecord = markedRecord.copy(state = RepairRollbackState.RESTORE_FAILED_UNRESOLVED,
                failureStage = stage, failureCode = code, observedSourceRevisionSha256 = observation)
            val failed = withCommittedRollbackFailure(marked, failedRecord)
            consume(RecoveryPublicationCase.FAILURE_PENDING, failed)
            if (observation != null) {
                val resolved = rollbackOutcomeRecord(failedRecord, failedRecord.expectedSourceRevisionSha256)
                consume(RecoveryPublicationCase.RESOLVED_FAILURE_FINAL, final(resolved, failed))
            }
        }
    }
    val outcome = rollbackOutcomeRecord(markedRecord, markedRecord.expectedSourceRevisionSha256)
    val direct = final(outcome, marked)
    consume(RecoveryPublicationCase.DIRECT_FINAL, direct)
    if (direct.runs.lastOrNull()?.terminal == false) {
        consume(RecoveryPublicationCase.INTERRUPTED_FINAL,
            finishedRunCandidate(direct, RepairRunStatus.INTERRUPTED, RESTART_INTERRUPTION_EVIDENCE))
    }
}

private fun deriveRepairIterations(
    nodes: List<ModuleRevisionNode>,
    budget: RepairResourceBudget,
    schemaVersion: Int,
    readBlob: (String) -> ByteArray,
): List<RepairIteration> {
    requireBoundedIterationProjection(nodes, budget)
    return immutableList(nodes.mapNotNull { node ->
        val metadata = node.repairMetadata ?: return@mapNotNull null
        val patches = node.changes.map { change ->
            RepairPatch(change.path, readBlob(change.afterBlobSha256))
        }
        RepairIteration(
            index = metadata.iterationIndex,
            failureKind = metadata.failureKind,
            prompt = metadata.prompt,
            summary = metadata.summary ?: if (node.recoveredAfterCrash) {
                "repair attempt interrupted before the agent summary was durably recorded"
            } else {
                "repair attempt ${node.id}"
            },
            patches = patches,
            retainedRegressionIds = metadata.retainedRegressionIds,
            before = metadata.before,
            after = node.evidenceKind?.let { kind ->
                RepairEvidence(kind, node.evidenceSummary.orEmpty(), node.evidenceArtifact)
            },
            succeeded = node.status == ModuleRevisionStatus.ACCEPTED && node.evidenceKind == "valid",
            agentInvocation = metadata.agentInvocation?.copy(),
            publicationMode = metadata.publicationMode,
            disposition = when (node.status) {
                ModuleRevisionStatus.ACCEPTED -> if (schemaVersion >= 3) RepairAttemptDisposition.FULLY_ACCEPTED else RepairAttemptDisposition.LEGACY_UNVERIFIED
                ModuleRevisionStatus.PROVISIONAL -> RepairAttemptDisposition.PROVISIONAL
                ModuleRevisionStatus.REJECTED -> RepairAttemptDisposition.REJECTED
                else -> RepairAttemptDisposition.LEGACY_UNVERIFIED
            },
            revisionId = node.id,
            parentRevisionId = node.parentId,
            runId = metadata.runId,
        )
    }.also { iterations ->
        require(iterations.map { it.index } == iterations.map { it.index }.distinct().sorted()) {
            "repair graph iteration indexes are not unique and ordered"
        }
    }.map(RepairIteration::deepFrozenCopy))
}

private fun requireBoundedIterationProjection(
    nodes: List<ModuleRevisionNode>,
    budget: RepairResourceBudget,
) {
    var projectedBytes = 128L
    fun addText(value: String?) {
        if (value == null) return
        projectedBytes = Math.addExact(
            projectedBytes,
            Math.multiplyExact(value.toByteArray(Charsets.UTF_8).size.toLong(), 6L),
        )
    }
    nodes.forEach { node ->
        val metadata = node.repairMetadata ?: return@forEach
        projectedBytes = Math.addExact(projectedBytes, 1024L)
        addText(metadata.failureKind)
        addText(metadata.prompt)
        addText(metadata.summary)
        addText(metadata.before?.kind)
        addText(metadata.before?.summary)
        addText(metadata.before?.artifactPath)
        addText(node.evidenceKind)
        addText(node.evidenceSummary)
        addText(node.evidenceArtifact)
        metadata.retainedRegressionIds.forEach(::addText)
        node.changes.forEach { change ->
            projectedBytes = Math.addExact(projectedBytes, 256L)
            addText(change.path)
            projectedBytes = Math.addExact(projectedBytes, Math.multiplyExact(change.afterBytes, 2L))
        }
        if (projectedBytes > budget.maximumProjectionBytes) {
            throw RepairBudgetExceededException(
                "repair history projection exceeds ${budget.maximumProjectionBytes} bytes",
            )
        }
    }
}

private fun recoverPersistedInvocationBinding(
    pending: PendingAttempt,
    schemaVersion: Int,
    store: RepairStateStore,
    expectedProfileSha256: String? = null,
): PendingAttempt {
    val metadata = pending.repairMetadata ?: return pending
    val intentName = "${pending.id}.acp-intent.json"
    val receiptName = "${pending.id}.acp-receipt.json"
    val assessmentName = "${pending.id}.acp-assessment.json"
    val hasIntent = store.revisionFileExists(intentName)
    val hasReceipt = store.revisionFileExists(receiptName)
    val hasAssessment = store.revisionFileExists(assessmentName)
    if (schemaVersion < 2) {
        require(!hasIntent && !hasReceipt && !hasAssessment && metadata.agentInvocation == null) {
            "legacy repair graph contains unbound invocation evidence"
        }
        return pending
    }
    if (!hasIntent && !hasReceipt && !hasAssessment) return pending
    require(schemaVersion >= 6 || !hasIntent && !hasAssessment) {
        "legacy repair graph contains unsupported schema-7 turn evidence"
    }

    val intentFile = if (hasIntent) store.readRevisionFile(intentName, MAXIMUM_REPAIR_INTENT_BYTES.toLong()) else null
    val intent = intentFile?.let { AgentTurnIntent.parse(it.bytes) }
    intent?.let {
        require(it.taskId == pending.id && it.attemptId == pending.id &&
            it.beforeSha256 == pending.parentSourceRevisionSha256 &&
            (expectedProfileSha256 == null || it.profileSha256 == expectedProfileSha256)) {
            "recovered repair intent is cross-paired with its pending attempt"
        }
    }
    val recoveredIntentBinding = intentFile?.let { file ->
        RepairAgentTurnIntentBinding(
            "reports/repair-revisions/$intentName",
            file.sha256,
            requireNotNull(intent).turnId,
        )
    }
    require(metadata.turnIntent == null || metadata.turnIntent == recoveredIntentBinding || recoveredIntentBinding == null) {
        "persisted repair intent binding conflicts with its immutable document"
    }
    val intentBinding = metadata.turnIntent ?: recoveredIntentBinding

    if (!hasReceipt) {
        require(!hasAssessment) { "repair assessment exists without its invocation receipt" }
        return if (intentBinding == metadata.turnIntent) pending else pending.copy(
            repairMetadata = metadata.copy(turnIntent = intentBinding),
        )
    }

    val receipt = store.readRevisionFile(receiptName, MAXIMUM_REPAIR_ACP_RECEIPT_BYTES)
    val verified = verifyAcpExecutionReceiptDocument(
        receipt.bytes,
        TRACE_REPAIR_ACP_RECEIPT_KIND,
        TRACE_REPAIR_ACP_TASK_FIELD,
        pending.id,
    )
    require(verified.promptSha256 == metadata.prompt) {
        "recovered repair ACP receipt is cross-paired with a different workflow prompt"
    }
    require(intent == null || intent.requestSha256 == verified.requestSha256) {
        "recovered repair receipt request differs from its pre-dispatch intent"
    }
    require(intent == null || (verified.schemaVersion == 3 &&
        verified.turnIdentity?.turnId == intent.turnId &&
        verified.turnIdentity.taskId == intent.taskId &&
        verified.turnIdentity.requestSha256 == intent.requestSha256)) {
        "recovered repair receipt turn identity differs from its pre-dispatch intent"
    }
    val oldBinding = metadata.agentInvocation
    val binding = RepairAgentInvocationBinding(
        receiptPath = "reports/repair-revisions/$receiptName",
        receiptSha256 = receipt.sha256,
        receiptSchemaVersion = verified.schemaVersion,
        requestSha256 = verified.requestSha256,
        resultChangesSha256 = verified.resultChangesSha256,
        terminalOutcome = verified.terminalOutcome,
        receiptReleaseComplete = verified.releaseComplete,
        assessmentStatus = RepairAgentAssessmentStatus.PENDING,
        intentPath = intentBinding?.intentPath,
        intentSha256 = intentBinding?.intentSha256,
        turnId = intentBinding?.turnId,
    )
    val oldReceiptBinding = oldBinding?.copy(
        assessmentStatus = RepairAgentAssessmentStatus.PENDING,
        assessmentPath = null,
        assessmentSha256 = null,
    )
    require(oldReceiptBinding == null || oldReceiptBinding == binding) {
        "persisted repair receipt binding conflicts with its immutable document"
    }
    val assessmentFile = if (hasAssessment) {
        store.readRevisionFile(assessmentName, MAXIMUM_REPAIR_ASSESSMENT_BYTES.toLong())
    } else null
    val assessedBinding = assessmentFile?.let { file ->
        val parsed = AcpChangeAssessment.parse(file.bytes)
        val intentValue = requireNotNull(intent) { "repair assessment exists without its pre-dispatch intent" }
        require(parsed.turnId == intentValue.turnId && parsed.intentSha256 == intentValue.sha256 &&
            parsed.receiptSha256 == receipt.sha256 && parsed.changesSha256 == verified.resultChangesSha256 &&
            parsed.beforeSha256 == intentValue.beforeSha256 &&
            intentValue.policySha256 == verified.accessPolicySha256 &&
            parsed.policySha256 == verified.accessPolicySha256 &&
            parsed.sessionIdSha256 == verified.sessionIdCommitmentSha256?.let {
                sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
            } &&
            parsed.updatesSha256 == verified.updatesSha256 &&
            parsed.normalizedStopReason == verified.terminalOutcome
                .takeIf { it.startsWith("returned-") }
                ?.removePrefix("returned-")
                ?.let { decompengine.agent.AgentStopReason.valueOf(it.uppercase().replace('-', '_')) }) {
            "recovered repair assessment is cross-paired with its immutable intent or receipt"
        }
        binding.copy(
            assessmentPath = "reports/repair-revisions/$assessmentName",
            assessmentSha256 = file.sha256,
        )
    } ?: binding
    if (assessmentFile == null) {
        require(oldBinding?.assessmentPath == null && oldBinding?.assessmentSha256 == null) {
            "persisted repair assessment binding has no immutable document"
        }
    } else {
        val oldAssessmentPath = oldBinding?.assessmentPath
        val oldAssessmentSha = oldBinding?.assessmentSha256
        require((oldAssessmentPath == null && oldAssessmentSha == null) ||
            (oldAssessmentPath == assessedBinding.assessmentPath && oldAssessmentSha == assessedBinding.assessmentSha256)) {
            "persisted repair assessment binding conflicts with its immutable document"
        }
    }
    return pending.copy(repairMetadata = metadata.copy(
        turnIntent = intentBinding,
        agentInvocation = assessedBinding,
    ))
}

private fun RevisionRepairMetadata.deepFrozenCopy(): RevisionRepairMetadata = copy(
    retainedRegressionIds = immutableList(retainedRegressionIds),
    before = before?.copy(),
)

private fun ModuleRevisionNode.deepFrozenCopy(): ModuleRevisionNode = copy(
    changes = immutableList(changes.map(RevisionFileDelta::copy)),
    changedModules = immutableList(changedModules),
    invalidatedModules = immutableList(invalidatedModules),
    repairMetadata = repairMetadata?.deepFrozenCopy(),
    rollbackRecord = rollbackRecord?.copy(),
    publicationChanges = immutableList(publicationChanges.map(RevisionFileDelta::copy)),
    publicationPreimageMetadata = immutableRepairMap(publicationPreimageMetadata),
)

private fun <K, V> immutableRepairMap(values: Map<K, V>): Map<K, V> =
    Collections.unmodifiableMap(LinkedHashMap(values))

private fun PendingAttempt.deepFrozenCopy(): PendingAttempt = copy(
    allowedPaths = immutableList(allowedPaths),
    preimages = immutableList(preimages.map(RevisionFileDelta::copy)),
    candidateChanges = immutableList(candidateChanges.map(RevisionFileDelta::copy)),
    promotionChanges = immutableList(promotionChanges.map(RevisionFileDelta::copy)),
    repairMetadata = repairMetadata?.deepFrozenCopy(),
    rollbackRecord = rollbackRecord?.copy(),
    acceptanceDecision = acceptanceDecision?.copy(
        promotionChanges = immutableList(acceptanceDecision.promotionChanges.map(RevisionFileDelta::copy)),
    ),
    predecisionStageFiles = immutableList(predecisionStageFiles.map(RepairPredecisionStage::copy)),
    preimageMetadata = preimageMetadata?.toSortedMap()?.mapValues { (_, metadata) ->
        metadata.copy(ancestorMetadata = immutableList(metadata.ancestorMetadata.map(RepairAncestorMetadata::copy)))
    }?.toMap(),
    promotionPreimageMetadata = promotionPreimageMetadata?.toSortedMap()?.mapValues { (_, metadata) ->
        metadata.copy(ancestorMetadata = immutableList(metadata.ancestorMetadata.map(RepairAncestorMetadata::copy)))
    }?.toMap(),
)

private fun RevisionGraphState.deepFrozenCopy(): RevisionGraphState = copy(
    editablePaths = immutableList(editablePaths),
    retainedRegressionInputs = immutableList(retainedRegressionInputs.map(ProcessInput::deepCopy)),
    nodes = immutableList(nodes.map(ModuleRevisionNode::deepFrozenCopy)),
    pending = pending?.deepFrozenCopy(),
    runs = immutableList(runs.map { it.copy(lastEvidence = it.lastEvidence?.copy()) }),
)

private fun initialRollbackRecord(
    state: RevisionGraphState,
    pending: PendingAttempt,
    legacyPendingStateUnknown: Boolean,
): RepairRollbackRecord {
    val targetId = if (pending.detached) state.headId else pending.parentId
    val targetSources = revisionSourcesAt(state.nodes, targetId)
    return RepairRollbackRecord(
        attemptId = pending.id,
        runId = pending.repairMetadata?.runId,
        targetRevisionId = targetId,
        expectedSourceRevisionSha256 = revisionSha256(targetSources.values),
        state = RepairRollbackState.RESTORE_IN_PROGRESS,
        legacyPendingStateUnknown = legacyPendingStateUnknown,
        candidateSourceInstallStarted = when {
            pending.candidateSourceRevisionSha256 == null -> false
            legacyPendingStateUnknown -> null
            else -> false
        },
    )
}

private fun revisionSourcesAt(nodes: List<ModuleRevisionNode>, nodeId: String): Map<String, IndexedSource> {
    val byId = nodes.associateBy { it.id }
    val lineage = ArrayList<ModuleRevisionNode>()
    var cursor: ModuleRevisionNode? = requireNotNull(byId[nodeId]) { "repair revision does not exist: $nodeId" }
    while (cursor != null) {
        require(lineage.size < nodes.size) { "repair revision lineage contains a cycle" }
        require(cursor.status != ModuleRevisionStatus.REJECTED) { "rejected revision cannot seed repair" }
        lineage += cursor
        cursor = cursor.parentId?.let { requireNotNull(byId[it]) }
    }
    val result = TreeMap<String, IndexedSource>()
    lineage.asReversed().forEach { node -> node.changes.forEach {
        result[it.path] = IndexedSource(it.path, it.afterBytes, it.afterSha256)
    } }
    return result
}

private fun revisionCanonicalBase(nodes: List<ModuleRevisionNode>, nodeId: String): String {
    val byId = nodes.associateBy { it.id }
    var node = requireNotNull(byId[nodeId])
    var depth = 0
    while (node.status == ModuleRevisionStatus.PROVISIONAL) {
        require(depth++ < nodes.size)
        node = requireNotNull(byId[node.parentId])
    }
    require(node.status != ModuleRevisionStatus.REJECTED)
    return node.id
}

/** Immutable recovery authorization written before the first graph journal. */
private data class RepairRecoveryBinding(
    val profileId: String,
    val profileSha256: String,
    val budgetSha256: String,
    val sourcePaths: List<String>,
    val editablePaths: List<String>,
    val indexSha256: String,
)

private data class RepairRootIdentity(val device: Long, val inode: Long)

/** JVM-local exclusion keyed by a descriptor-observed directory identity, not a pathname alias. */
private interface RepairRootCoordination : AutoCloseable {
    fun enterOperation()
    fun exitOperation()
}

private object RepairRootCoordinator {
    private class Entry {
        val permit = Semaphore(1, true)
        var references = 0
        var openingThread: Thread? = null
        val operationThreads = mutableMapOf<Thread, Int>()
    }

    private val registry = mutableMapOf<RepairRootIdentity, Entry>()

    fun acquire(
        rootDescriptor: LinuxDescriptor,
        deadlineNanos: Long,
        maximumWaitMillis: Long,
    ): RepairRootCoordination {
        require(rootDescriptor.identity.isDirectory && !rootDescriptor.identity.isSymbolicLink) {
            "repair project root is not a descriptor-authenticated directory"
        }
        val identity = rootDescriptor.identity.rootIdentity()
        val entry = synchronized(registry) {
            registry.getOrPut(identity, ::Entry).also { it.references = Math.addExact(it.references, 1) }
        }
        var acquired = false
        try {
            val current = Thread.currentThread()
            synchronized(entry) {
                if (entry.openingThread === current || entry.operationThreads.containsKey(current)) {
                    error("repair revision graph cannot be opened reentrantly for the same project root")
                }
            }
            try {
                val remaining = deadlineNanos - System.nanoTime()
                if (remaining <= 0 || !entry.permit.tryAcquire(remaining, TimeUnit.NANOSECONDS)) {
                    throw repairGraphLockTimeout(maximumWaitMillis)
                }
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IllegalStateException("repair revision graph lock acquisition was interrupted", interrupted)
            }
            acquired = true
            synchronized(entry) {
                check(entry.openingThread == null && entry.operationThreads.isEmpty()) {
                    "repair root coordinator granted an already-owned lease"
                }
                entry.openingThread = current
            }
            require(LinuxFilesystemSyscalls.identity(rootDescriptor.fd).rootIdentity() == identity) {
                "pinned repair project root identity changed while waiting for JVM coordination"
            }
            return Lease(identity, entry)
        } catch (failure: Throwable) {
            if (acquired) {
                synchronized(entry) {
                    entry.openingThread = null
                    entry.operationThreads.clear()
                }
                entry.permit.release()
            }
            releaseReference(identity, entry)
            throw failure
        }
    }

    private fun LinuxFileIdentity.rootIdentity(): RepairRootIdentity =
        RepairRootIdentity(key.device, key.inode)

    private fun releaseReference(identity: RepairRootIdentity, entry: Entry) {
        synchronized(registry) {
            check(entry.references > 0) { "repair root coordinator reference count underflow" }
            entry.references--
            if (entry.references == 0) check(registry.remove(identity, entry)) {
                "repair root coordinator registry changed unexpectedly"
            }
        }
    }

    private class Lease(
        private val identity: RepairRootIdentity,
        private val entry: Entry,
    ) : RepairRootCoordination {
        private var closed = false

        override fun enterOperation() {
            synchronized(entry) {
                check(!closed) { "repair root coordination lease is closed" }
                val current = Thread.currentThread()
                entry.operationThreads[current] = Math.addExact(entry.operationThreads[current] ?: 0, 1)
            }
        }

        override fun exitOperation() {
            synchronized(entry) {
                val current = Thread.currentThread()
                val depth = entry.operationThreads[current]
                    ?: error("repair root coordination operation was not entered")
                if (depth == 1) entry.operationThreads.remove(current) else entry.operationThreads[current] = depth - 1
            }
        }

        @Synchronized
        override fun close() {
            if (closed) return
            synchronized(entry) {
                check(entry.operationThreads.isEmpty()) {
                    "repair root coordination still has an active graph operation"
                }
                entry.openingThread = null
                closed = true
            }
            try {
                // Semaphore permits are deliberately not thread-owned: a graph may be opened on
                // one thread and closed on another after the graph monitor excludes operations.
                entry.permit.release()
            } finally {
                releaseReference(identity, entry)
            }
        }

    }
}

private fun acquireRepairProjectRootLock(
    projectRoot: LinuxDescriptor,
    deadlineNanos: Long,
    maximumWaitMillis: Long,
): LinuxDescriptor {
    val lock = LinuxFilesystemSyscalls.openDirectoryAt(projectRoot.fd, ".")
    var acquired = false
    try {
        val currentRoot = LinuxFilesystemSyscalls.identity(projectRoot.fd)
        require(
            currentRoot.key == projectRoot.identity.key && currentRoot.mountId == projectRoot.identity.mountId &&
                currentRoot.isDirectory && !currentRoot.isSymbolicLink &&
                lock.identity.key == currentRoot.key && lock.identity.mountId == currentRoot.mountId &&
                lock.identity.isDirectory && !lock.identity.isSymbolicLink,
        ) {
            "repair project root lock does not identify the pinned project root"
        }
        while (true) {
            val remaining = deadlineNanos - System.nanoTime()
            if (remaining <= 0) throw repairGraphLockTimeout(maximumWaitMillis)
            if (LinuxFilesystemSyscalls.tryExclusiveLock(lock)) {
                acquired = true
                return lock
            }
            val afterAttempt = deadlineNanos - System.nanoTime()
            if (afterAttempt <= 0) throw repairGraphLockTimeout(maximumWaitMillis)
            try {
                TimeUnit.NANOSECONDS.sleep(minOf(REPAIR_LOCK_POLL_NANOS, afterAttempt))
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IllegalStateException("repair revision graph lock acquisition was interrupted", interrupted)
            }
        }
    } catch (failure: Throwable) {
        if (acquired) runCatching { LinuxFilesystemSyscalls.unlock(lock) }
        lock.close()
        throw failure
    }
}

private fun repairGraphLockTimeout(maximumWaitMillis: Long) = RepairGraphLockTimeoutException(
    "repair revision graph lock was not available within $maximumWaitMillis ms",
)

private val REPAIR_LOCK_POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(20)

/**
 * Crash-consistent source transaction journal and deterministic module revision DAG.
 *
 * A project-scoped file lock serializes attempts. Candidate bytes are content-addressed and the
 * pending journal is durable before source installation. Reopening after an interrupted attempt
 * restores every authorized preimage and records one deterministic recovered rejection.
 */
internal class ModuleRevisionGraph private constructor(
    graphAuthorityCandidate: Any?,
    projectRootCandidate: Path?,
    portableProjectRootCandidate: Path?,
    rootDescriptorCandidate: LinuxDescriptor?,
    indexCandidate: ModuleRepairIndex?,
    stateStoreCandidate: RepairStateStore?,
    lockDescriptorCandidate: LinuxDescriptor?,
    rootCoordinationCandidate: RepairRootCoordination?,
    faultInjectorCandidate: ModuleRevisionFaultInjector?,
) : AutoCloseable {
    private enum class Lifecycle { OPEN, POISONED, CLOSING, CLOSED }

    private var lifecycle: Lifecycle
    private var operationDepth: Int
    private var operationThread: Thread?
    private val graphAuthority: Any
    private val rootDescriptor: LinuxDescriptor
    private val projectRoot: Path
    private val portableProjectRoot: Path
    private val index: ModuleRepairIndex
    private val stateStore: RepairStateStore
    private val lockDescriptor: LinuxDescriptor
    private val rootCoordination: RepairRootCoordination
    private val faultInjector: ModuleRevisionFaultInjector?
    private var state: RevisionGraphState

    init {
        // Kotlin emits a synthetic marker constructor for private constructors. The Java-owned,
        // one-shot construction scope makes that bytecode path fail before component use.
        SecureRepairRuntime.consumeGraphConstruction()
        SecureRepairRuntime.requireGraphAuthority(graphAuthorityCandidate)
        lifecycle = Lifecycle.OPEN
        operationDepth = 0
        operationThread = null
        graphAuthority = requireNotNull(graphAuthorityCandidate)
        rootDescriptor = requireNotNull(rootDescriptorCandidate)
        projectRoot = requireNotNull(projectRootCandidate)
        portableProjectRoot = requireNotNull(portableProjectRootCandidate)
        index = requireNotNull(indexCandidate)
        stateStore = requireNotNull(stateStoreCandidate)
        lockDescriptor = requireNotNull(lockDescriptorCandidate)
        rootCoordination = requireNotNull(rootCoordinationCandidate)
        faultInjector = faultInjectorCandidate
        state = loadOrInitialize().deepFrozenCopy()
    }

    init {
        validateLoadedState()
        synchronized(this) { bindPendingOrphanTurnIntentForRecovery() }
        cleanupUnreferencedValidationArtifacts()
        cleanupSourceTemporaries(state.pending)
        recoverPendingAttempt()
        cleanupCommittedPreimages()
        state.runs.lastOrNull()?.takeUnless { it.terminal }?.let {
            finishRun(RepairRunStatus.INTERRUPTED, RESTART_INTERRUPTION_EVIDENCE)
        }
        cleanupUnreferencedBlobs()
        cleanupGraphTemporaries()
        requireCurrentHead()
        try {
            synchronizeSourceManifest()
        } catch (_: Exception) {
            // Derived projection; retried on a later open.
        }
        try {
            synchronizeCompatibilityLog()
        } catch (_: Exception) {
            // Derived projection; retried on a later open.
        }
    }

    val snapshot: ModuleRevisionGraphSnapshot
        @Synchronized get() = graphOperation {
            ModuleRevisionGraphSnapshot(
                state.profileId,
                state.profileSha256,
                state.indexSha256,
                state.headId,
                state.nextOrdinal,
                immutableList(state.nodes.map(ModuleRevisionNode::deepFrozenCopy)),
                state.pending?.id,
                state.storedBlobBytes,
                state.regressionCorpusSha256,
                state.schemaVersion,
                state.provisionalHeadId,
                state.fullyAcceptedHeadId,
                immutableList(state.runs),
            )
        }

    /** The immutable source-tree contract admitted by this graph's repair index, when present. */
    internal val declaredRoleProfile: ReconstructionProfile?
        get() = index.profile.reconstructionProfile()

    /** Preserve the original bytes before assigning honest authority to legacy head records. */
    @Synchronized
    fun enableRunContract() = graphOperation {
        require(state.pending == null)
        upgradeGraphToRollbackContract(allowPending = false)
    }

    /** Upgrade before a new repair dispatch so even an imported legacy graph gets v7 turn evidence. */
    @Synchronized
    internal fun enableDurableTurnProvenance() = graphOperation {
        require(state.pending == null) {
            "durable turn provenance cannot be enabled while a repair attempt is pending"
        }
        upgradeGraphToRollbackContract(allowPending = false)
        if (state.schemaVersion >= 7) return@graphOperation
        val upgraded = state.copy(schemaVersion = 7)
        // Existing records remain historical and unassessed. Schema 7 adds nullable turn
        // references for them; it does not synthesize identities or assessments. New attempts
        // admitted after this exchange use the detached schema-6 publication contract and are
        // required to bind their own v7 intent/receipt/assessment records.
        persist(upgraded)
    }

    private fun upgradeGraphToRollbackContract(allowPending: Boolean) {
        if (state.schemaVersion >= 5) return
        require(allowPending || state.pending == null)
        // A pending attempt has already crossed the write-ahead boundary.  Startup recovery
        // records its own marker without upgrading its source schema; manufacturing a new
        // "legacy origin" for that marker would either lose the true schema-1..3 origin or
        // classify a native schema-4 rollback record as legacy.  Preserve the source bytes at
        // admission time and leave pending recovery in its original rollback contract.
        if (state.pending != null) return
        preserveLegacyRunState()
        persist(rollbackContractState())
    }

    /** Construct the exact upgrade without publishing it, so rejection can preflight all bytes. */
    private fun rollbackContractState(): RevisionGraphState {
        if (state.schemaVersion >= 5) return state
        // A pending pre-v5 attempt has no durable filesystem-metadata witness. Preserve its
        // legacy schema during content-only recovery instead of claiming v5 verification.
        if (state.pending != null) {
            return state
        }
        val upgradedNodes = if (state.schemaVersion < 3) state.nodes.map { node ->
            if (node.status == ModuleRevisionStatus.ACCEPTED) node.copy(status = ModuleRevisionStatus.LEGACY_UNVERIFIED)
            else node
        } else state.nodes
        return state.copy(schemaVersion = 5, nodes = upgradedNodes)
    }

    private fun preserveLegacyRunState() {
        stateStore.preserveLegacyState(
            "graph",
            stateStore.readGraph(state.budget.maximumGraphBytes),
            state.budget.maximumGraphBytes,
        )
        val historyPath = projectRoot.resolve("reports/repair_history.json")
        if (state.schemaVersion < 3 && Files.exists(historyPath, LinkOption.NOFOLLOW_LINKS)) {
            stateStore.preserveLegacyState(
                "history",
                readStableRegularFile(projectRoot, "reports/repair_history.json", state.budget.maximumProjectionBytes).bytes,
                state.budget.maximumProjectionBytes,
            )
        }
    }

    @Synchronized
    fun beginRun(maximumAttempts: Int, maximumWallMillis: Long): RepairRunState = graphOperation {
        enableRunContract()
        require(state.pending == null && state.runs.lastOrNull()?.terminal != false)
        require(maximumAttempts > 0 && maximumWallMillis > 0)
        require(state.runs.size < state.budget.maximumRevisionNodes)
        val now = System.currentTimeMillis()
        val run = RepairRunState("run_${(state.runs.size + 1).toString().padStart(8, '0')}",
            RepairRunStatus.RUNNING, state.headId, state.fullyAcceptedHeadId, null,
            state.regressionCorpusSha256, maximumAttempts, 0, now, Math.addExact(now, maximumWallMillis))
        persist(state.copy(provisionalHeadId = null, runs = state.runs + run))
        run
    }

    @Synchronized
    fun finishRun(status: RepairRunStatus, evidence: RepairEvidence?): RepairRunState = graphOperation {
        require(status != RepairRunStatus.RUNNING && status != RepairRunStatus.FULLY_ACCEPTED)
        val run = requireNotNull(state.runs.lastOrNull())
        if (run.terminal) return@graphOperation run
        require(status != RepairRunStatus.ROLLBACK_FAILED) { "rollback failure requires a committed attempt record" }
        require(state.pending == null || status == RepairRunStatus.VALIDATION_FAILED)
        val next = finishedRunCandidate(state, status, portableEvidence(evidence))
        val finished = next.runs.last()
        persist(next)
        try { synchronizeRepairHistory() } catch (_: Exception) { /* Canonical terminal record is already durable. */ }
        finished
    }

    @Synchronized
    fun bindExpectedObservations(digest: String) = graphOperation {
        require(digest.matches(REPAIR_BLOB_DIGEST))
        val run = requireNotNull(state.runs.lastOrNull())
        require(!run.terminal)
        require(run.expectedObservationsSha256 == null || run.expectedObservationsSha256 == digest) {
            "retained expected behavior changed during the repair run"
        }
        if (run.expectedObservationsSha256 == null) persist(state.copy(runs = state.runs.dropLast(1) +
            run.copy(expectedObservationsSha256 = digest)))
    }

    @Synchronized
    fun bindOriginalBinary(digest: String) = graphOperation {
        require(digest.matches(REPAIR_BLOB_DIGEST))
        val run = requireNotNull(state.runs.lastOrNull())
        require(!run.terminal)
        require(run.originalBinarySha256 == null || run.originalBinarySha256 == digest) {
            "original binary identity changed during the repair run"
        }
        if (run.originalBinarySha256 == null) persist(state.copy(runs = state.runs.dropLast(1) + run.copy(originalBinarySha256 = digest)))
    }

    private fun portableEvidence(evidence: RepairEvidence?): RepairEvidence? = evidence?.let {
        RepairEvidence(portableEvidenceText(it.kind), portableEvidenceText(it.summary), it.artifactPath?.let(::portableEvidencePath))
    }

    private fun captureAncestorMetadata(relative: String): List<RepairAncestorMetadata> {
        return captureSchema6AncestorMetadata(projectRoot, relative, state.budget.maximumStateDirectoryEntries)
    }

    private fun stagePublicationFiles(
        pending: PendingAttempt,
        changes: List<RevisionFileDelta>,
        contents: Map<String, ByteArray>,
        metadata: Map<String, RepairPreimageMetadata>,
    ): Pair<PendingAttempt, List<RepairStagedFile>> {
        val stageIdentity = stateStore.publicationStagingIdentity()
        val result = mutableListOf<RepairStagedFile>()
        var registeredPending = pending.copy(
            rollbackRecord = pending.rollbackRecord?.copy(candidateSourceInstallStarted = false),
            predecisionStageFiles = emptyList(),
        )
        if (pending.predecisionStageFiles.isNotEmpty()) {
            // A prior predecision cleanup may have removed only a prefix before failing. Keep
            // every surviving inode bound until the complete old stage set is authenticated
            // and removed; only then may a retry replace the manifest with a new stage set.
            discardUndecidedPublicationStages(
                stateStore, changes, pending.id, pending.predecisionStageFiles,
            )
            persist(state.copy(pending = registeredPending))
        }
        changes.sortedBy { it.path }.forEachIndexed { indexInPublication, change ->
            val preimage = requireNotNull(metadata[change.path])
            val expectedParent = requireNotNull(preimage.ancestorMetadata.lastOrNull()) {
                "schema-6 publication witness has no target parent: ${change.path}"
            }
            val parts = normalizedRelative(change.path).split('/')
            val opened = mutableListOf<LinuxDescriptor>()
            try {
                var parent = openRepairRootDirectory(projectRoot)
                opened += parent
                parts.dropLast(1).forEach { segment ->
                    parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
                    opened += parent
                }
                val parentState = LinuxFilesystemSyscalls.fileState(parent)
                require(parentState.identity.key.device == expectedParent.device &&
                    parentState.identity.key.inode == expectedParent.inode &&
                    parentState.identity.mountId == expectedParent.mountId &&
                    parentState.identity.mode == expectedParent.mode &&
                    parentState.identity.uid == expectedParent.uid && parentState.identity.gid == expectedParent.gid &&
                    parentState.size == expectedParent.size &&
                    parentState.modificationTimeSeconds == expectedParent.mtimeSeconds &&
                    parentState.modificationTimeNanoseconds == expectedParent.mtimeNanoseconds &&
                    parentState.changeTimeSeconds == expectedParent.ctimeSeconds &&
                    parentState.changeTimeNanoseconds == expectedParent.ctimeNanoseconds &&
                    parentState.accessTimeSeconds == expectedParent.atimeSeconds &&
                    parentState.accessTimeNanoseconds == expectedParent.atimeNanoseconds) {
                    "schema-6 target parent changed before publication staging: ${change.path}"
                }
                require(stageIdentity.mountId == parent.identity.mountId &&
                    stageIdentity.key.device == parent.identity.key.device &&
                    preimage.ancestorMetadata.none { it.device == stageIdentity.key.device && it.inode == stageIdentity.key.inode }) {
                    "schema-6 private staging must be on the target mount and outside witnessed source ancestors"
                }
                val source = requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, parts.last())) {
                    "schema-6 source disappeared before staging: ${change.path}"
                }
                source.use { held ->
                    val sourceState = LinuxFilesystemSyscalls.fileState(held)
                    require(sourceState.identity.key.device == preimage.device && sourceState.identity.key.inode == preimage.inode &&
                        sourceState.identity.mountId == expectedParent.mountId && preimage.matchesExactly(sourceState) &&
                        sourceState.identity.linkCount == 1 && sourceState.size == change.beforeBytes &&
                        LinuxFilesystemSyscalls.sha256WithoutAtime(held, sourceState.size) == change.beforeSha256) {
                        "schema-6 source differs from its durable attempt witness: ${change.path}"
                    }
                }
                val name = preimage.retainedName
                val bytes = requireNotNull(contents[change.path])
                require(bytes.size.toLong() == change.afterBytes && sha256(bytes) == change.afterSha256)
                val staged = stateStore.stagePublicationFile(name, bytes, preimage.mode.permissions) { identity ->
                    require(identity.isRegularFile && identity.linkCount == 0 && identity.mode.permissions == preimage.mode.permissions &&
                        identity.uid == preimage.uid && identity.gid == preimage.gid &&
                        identity.mountId == parent.identity.mountId && identity.key.device == parent.identity.key.device) {
                        "schema-6 unlinked staged inode has unexpected metadata: ${change.path}"
                    }
                    val registered = RepairPredecisionStage(
                        change.path, name, identity.key.device, identity.key.inode, identity.mountId,
                        identity.mode, identity.uid, identity.gid, change.afterSha256, change.afterBytes,
                    )
                    require(registeredPending.predecisionStageFiles.none { it.path == change.path })
                    val next = registeredPending.copy(predecisionStageFiles = immutableList(
                        registeredPending.predecisionStageFiles + registered,
                    ))
                    // The exact inode identity is durable before linkat gives it a name.
                    persist(state.copy(pending = next))
                    registeredPending = next
                    faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationStageIntentPersist(change.path, indexInPublication))
                }
                faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationStage(change.path, indexInPublication))
                require(staged.mountId == parent.identity.mountId && staged.key.device == parent.identity.key.device &&
                    staged.mode.permissions == preimage.mode.permissions && staged.uid == preimage.uid && staged.gid == preimage.gid &&
                    staged.linkCount == 1) {
                    "schema-6 staged inode does not preserve source ownership/mode or share its mount: ${change.path}"
                }
                val stagedState = stateStore.publicationStageState(name)
                result += RepairStagedFile(change.path, name, staged.key.device, staged.key.inode, staged.mountId,
                    staged.mode, staged.uid, staged.gid, staged.linkCount, change.afterSha256, change.afterBytes,
                    stagedState.accessTimeSeconds, stagedState.accessTimeNanoseconds,
                    stagedState.modificationTimeSeconds, stagedState.modificationTimeNanoseconds,
                    parent.identity.key.device, parent.identity.key.inode, parent.identity.mountId)
            } finally {
                opened.asReversed().forEach(LinuxDescriptor::close)
            }
        }
        // Staging is private, so the original source and every witnessed ancestor must still match.
        changes.forEach { change ->
            val committed = requireNotNull(metadata[change.path])
            val source = readStableRegularFile(projectRoot, change.path, state.budget.maximumSourceFileBytes,
                requireNoExtendedAttributes = true)
            require(source.sha256 == change.beforeSha256 && source.bytes.size.toLong() == change.beforeBytes &&
                committed.matchesExactly(source.state) && committed.ancestorMetadata == captureAncestorMetadata(change.path)) {
                "schema-6 source changed while its replacement was staged: ${change.path}"
            }
        }
        return registeredPending.copy(
            rollbackRecord = pending.rollbackRecord,
            predecisionStageFiles = immutableList(registeredPending.predecisionStageFiles),
        ) to immutableList(result)
    }

    private fun cleanupUndecidedPublicationStages(
        originalState: RevisionGraphState,
        changes: List<RevisionFileDelta>,
        attemptId: String,
    ) {
        val currentPending = state.pending?.takeIf { it.id == attemptId }
        discardUndecidedPublicationStages(stateStore, changes, attemptId,
            currentPending?.predecisionStageFiles.orEmpty())
        if (currentPending?.predecisionStageFiles.orEmpty().isNotEmpty()) {
            val originalPending = originalState.pending?.takeIf { it.id == attemptId }
                ?: error("predecision stage cleanup lost its original pending attempt")
            persist(state.copy(pending = originalPending))
        }
    }

    @Synchronized
    internal fun validationInvocation(attempt: ModuleRevisionAttempt?): RepairValidationInvocation = graphOperation {
        val run = requireNotNull(state.runs.lastOrNull()).also { require(!it.terminal) }
        val pending = attempt?.let(::requirePending)
        require(pending == null || pending.repairMetadata?.runId == run.id)
        val candidate = pending?.id ?: workingHeadId()
        val source = pending?.let { requireNotNull(it.candidateSourceRevisionSha256) }
            ?: state.nodes.single { it.id == candidate }.sourceRevisionSha256
        RepairValidationInvocation("validation_" + java.util.UUID.randomUUID().toString().replace("-", ""),
            run.id, candidate, source, state.profileSha256, state.indexSha256, run.regressionCorpusSha256)
    }

    /** Retain only the publication returned for this exact call, before failure unwinding. */
    @Synchronized
    internal fun recordValidationDiagnostic(invocation: RepairValidationInvocation,
        publication: RepairValidationDiagnosticPublication) = graphOperation {
        require(publication.invocation == invocation)
        val run = requireNotNull(state.runs.lastOrNull()).also { require(!it.terminal) }
        val pending = state.pending?.takeIf { it.id == invocation.candidateRevisionId }
        val node = state.nodes.singleOrNull { it.id == invocation.candidateRevisionId }
        require((pending != null) != (node != null))
        require(if (pending != null) pending.repairMetadata?.runId == run.id
            else node?.id == run.baselineId || node?.repairMetadata?.runId == run.id)
        val source = pending?.candidateSourceRevisionSha256 ?: requireNotNull(node).sourceRevisionSha256
        val retention = planRepairValidationDiagnosticRetention(publication, state.budget.maximumIndexEvidenceBytes)
        val binding = retention.binding
        requireRepairValidationDiagnosticAssociation(binding, run.id, state.profileSha256, state.indexSha256,
            run.regressionCorpusSha256, invocation.candidateRevisionId, requireNotNull(source))
        require(run.validationDiagnostic == null || run.validationDiagnostic == binding)
        retention.retain(
            read = { path, limit -> readStableRepairFile(path.parent, path.fileName.toString(), limit) },
            write = { name, bytes ->
                if (name.endsWith(".validation-failure.json")) stateStore.writeImmutableValidationDiagnostic(name, bytes)
                else stateStore.writeImmutableValidationReceipt(name, bytes)
            },
            readRetained = { name, limit -> stateStore.readValidationReport("reports/$name", limit) },
        )
        persist(requireCommitReadyState(state.copy(runs = state.runs.dropLast(1) +
            run.copy(schemaVersion = maxOf(run.schemaVersion, 3), validationDiagnostic = binding))))
    }

    /** Captured after the caller's existing proof and case gates, before any disposition. */
    @Synchronized
    internal fun recordValidationObservation(invocation: RepairValidationInvocation, proof: RepairValidationProof,
        outcome: RepairValidationObservedOutcome, primary: RepairValidationPublishedArtifact,
        diff: RepairValidationPublishedArtifact?) = graphOperation {
        val run = requireNotNull(state.runs.lastOrNull()).also { require(!it.terminal) }
        val pending = state.pending?.takeIf { it.id == invocation.candidateRevisionId }
        val node = state.nodes.singleOrNull { it.id == invocation.candidateRevisionId }
        require((pending != null) != (node != null))
        require(if (pending != null) pending.repairMetadata?.runId == run.id
            else node?.id == run.baselineId || node?.repairMetadata?.runId == run.id)
        val source = requireNotNull(pending?.candidateSourceRevisionSha256 ?: node?.sourceRevisionSha256)
        requireValidationProof(source, proof, full = false)
        val retention = planRepairValidationObservationRetention(invocation, proof, outcome, primary, diff,
            state.budget.maximumIndexEvidenceBytes)
        val observation = retention.observation
        requireRepairValidationObservationAssociation(observation, run.id, state.profileSha256, state.indexSha256,
            run.regressionCorpusSha256, invocation.candidateRevisionId, source, run.originalBinarySha256)
        cleanupUnreferencedValidationArtifacts()
        val existing = run.validationObservations.entries.singleOrNull { it.invocation.id == invocation.id }
        if (existing != null) {
            require(existing == observation)
            return@graphOperation
        }
        try {
            retention.retain(
                read = { path, limit -> readStableRepairFile(path.parent, path.fileName.toString(), limit) },
                write = { name, bytes ->
                    if (name.startsWith("repair-revisions/validation-diffs/"))
                        stateStore.writeImmutableValidationDiff(name.removePrefix("repair-revisions/validation-diffs/"), bytes)
                    else {
                        require(name.startsWith("repair-revisions/validation-receipts/"))
                        stateStore.writeImmutableNormalValidationReceipt(name.removePrefix("repair-revisions/validation-receipts/"), bytes)
                    }
                },
                readRetained = { name, limit ->
                    if (name.startsWith("repair-revisions/validation-diffs/"))
                        stateStore.readImmutableValidationDiff(name.removePrefix("repair-revisions/validation-diffs/"), limit)
                    else {
                        require(name.startsWith("repair-revisions/validation-receipts/"))
                        stateStore.readImmutableNormalValidationReceipt(name.removePrefix("repair-revisions/validation-receipts/"), limit)
                    }
                },
            )
            persist(requireCommitReadyState(state.copy(runs = state.runs.dropLast(1) + run.copy(schemaVersion = 4,
                validationObservations = run.validationObservations.appended(observation)))))
        } catch (failure: Throwable) {
            // A graph write may have committed before reporting failure. Never delete from stale in-memory state.
            // Reopen under the existing authenticated lock to recover against the actual committed graph.
            lifecycle = Lifecycle.POISONED
            throw failure
        }
    }

    private fun workingHeadId(): String = state.provisionalHeadId ?: state.headId

    private fun sourcesAt(nodeId: String): Map<String, IndexedSource> = revisionSourcesAt(state.nodes, nodeId)

    @Synchronized
    fun candidateSources(attempt: ModuleRevisionAttempt? = null): Map<String, ByteArray> = graphOperation {
        requireCurrentHead()
        val pending = attempt?.let(::requirePending)
        val sources = sourcesAt(pending?.parentId ?: workingHeadId()).toMutableMap()
        pending?.candidateChanges?.forEach { sources[it.path] = IndexedSource(it.path, it.afterBytes, it.afterSha256) }
        Collections.unmodifiableMap(sources.toSortedMap().mapValues { (path, source) ->
            readBlob(source.sha256).also { index.profile.validateSourceContent(path, it) }
        })
    }

    @Synchronized
    fun recordProvisional(attempt: ModuleRevisionAttempt, evidence: RepairEvidence, proof: RepairValidationProof): ModuleRevisionNode = graphOperation {
        val pending = requirePending(attempt)
        require(state.schemaVersion >= 3 && pending.detached && pending.promotionChanges.isEmpty())
        requireValidationProof(pending.candidateSourceRevisionSha256, proof, full = false)
        requireCurrentHead()
        val node = finalizeNode(pending, ModuleRevisionStatus.PROVISIONAL, evidence, false).copy(validationProof = proof)
        val run = state.runs.lastOrNull()?.takeUnless { it.terminal }
        persist(requireCommitReadyState(state.copy(nodes = state.nodes + node, pending = null,
            provisionalHeadId = node.id, runs = if (run == null) state.runs else state.runs.dropLast(1) +
                run.copy(provisionalHeadId = node.id, lastEvidence = portableEvidence(evidence)))))
        node.deepFrozenCopy()
    }

    private fun requireValidationProof(sourceRevision: String?, proof: RepairValidationProof, full: Boolean) {
        require(proof.sourceRevisionSha256 == sourceRevision && proof.profileSha256 == state.profileSha256 &&
            proof.indexSha256 == state.indexSha256 && proof.regressionCorpusSha256 == state.regressionCorpusSha256)
        require(proof.cleanupVerified) { "validation cleanup has not been verified" }
        require(listOf(proof.runtimeSha256, proof.evidenceSha256).all { it.matches(REPAIR_BLOB_DIGEST) })
        if (full) require(proof.originalBinarySha256?.matches(REPAIR_BLOB_DIGEST) == true &&
            proof.rebuiltBinarySha256?.matches(REPAIR_BLOB_DIGEST) == true && state.retainedRegressionInputs.isNotEmpty()) {
            "full repair promotion requires built executable and complete nonempty retained behavior evidence"
        }
    }

    @Synchronized
    fun retainRegressionInputs(inputs: Collection<ProcessInput>): RetainedRegressionCorpus = graphOperation {
        require(state.pending == null) { "cannot change retained regression inputs while an attempt is pending" }
        val merged = TreeMap<String, ProcessInput>()
        state.retainedRegressionInputs.forEach { merged[it.id] = it.deepCopy() }
        inputs.forEach { candidate ->
            validateRegressionInput(candidate)
            val copied = candidate.deepCopy()
            val existing = merged.putIfAbsent(copied.id, copied)
            require(existing == null || existing == copied) {
                "regression input id ${copied.id} refers to different input data"
            }
        }
        val canonical = merged.values.map(ProcessInput::deepCopy)
        validateRegressionCorpus(canonical, state.budget)
        val digest = regressionCorpusSha256(canonical)
        if (canonical != state.retainedRegressionInputs || digest != state.regressionCorpusSha256) {
            val retainedState = state.copy(retainedRegressionInputs = canonical, regressionCorpusSha256 = digest)
            persist(requireCommitReadyState(retainedState))
        }
        RetainedRegressionCorpus(canonical, digest)
    }

    @Synchronized
    fun retainedRegressionCorpus(): RetainedRegressionCorpus = graphOperation {
        RetainedRegressionCorpus(state.retainedRegressionInputs, state.regressionCorpusSha256)
    }

    /** Capture the graph and retained inputs in one graph operation under the lifetime root lock. */
    @Synchronized
    fun captureExplorationSnapshot(originalBinarySha256: String): RepairExplorationSnapshotData = graphOperation {
        require(originalBinarySha256.matches(REPAIR_BLOB_DIGEST)) { "exploration binary digest is invalid" }
        RepairExplorationSnapshotData(
            1,
            portableProjectRoot.toAbsolutePath().normalize().pathString,
            state.retainedRegressionInputs,
            state.regressionCorpusSha256,
            sha256(renderGraph(state).toByteArray(Charsets.UTF_8)),
            state.profileSha256,
            state.indexSha256,
            state.headId,
            originalBinarySha256,
        )
    }

    /** Must run before any graph mutation while the caller retains this graph's root lock. */
    @Synchronized
    fun requireCurrentExplorationSnapshot(snapshot: RepairExplorationSnapshotData) = graphOperation {
        require(snapshot.formatVersion == 1 &&
            snapshot.projectPath == portableProjectRoot.toAbsolutePath().normalize().pathString &&
            snapshot.graphSha256 == sha256(renderGraph(state).toByteArray(Charsets.UTF_8)) &&
            snapshot.corpusSha256 == state.regressionCorpusSha256 &&
            snapshot.profileSha256 == state.profileSha256 && snapshot.indexSha256 == state.indexSha256 &&
            snapshot.headId == state.headId) {
            "retained exploration snapshot is stale for the current repair graph"
        }
    }

    @Synchronized
    fun selectContext(failureKind: String, diagnosticHint: String? = null): RepairContextSelection = graphOperation {
        require(state.pending == null) { "cannot select repair context while an attempt is pending" }
        val observedRevision = revisionSha256(requireCurrentHead())
        require(index.sourceRevisionSha256 == observedRevision) {
            "reopen the revision graph before selecting context for a newly accepted head"
        }
        val selected = index.select(failureKind, diagnosticHint)
        if (state.provisionalHeadId == null) selected.deepFrozenCopy() else {
            val sources = sourcesAt(workingHeadId())
            val bytes = selected.readablePaths.fold(0L) { total, path -> Math.addExact(total, sources.getValue(path).bytes) }
            require(bytes <= state.budget.maximumContextBytes && bytes <= state.budget.maximumStagingBytes)
            selected.copy(totalBytes = bytes, sourceRevisionSha256 = revisionSha256(sources.values)).deepFrozenCopy()
        }
    }

    @Synchronized
    internal fun requireContextBinding(context: RepairContextSelection) = graphOperation {
        require(state.pending == null) { "cannot bind repair context while an attempt is pending" }
        require(context.indexSha256 == index.indexSha256) {
            "repair dependency evidence changed after context selection"
        }
        requireCurrentHead()
        val observedRevision = revisionSha256(sourcesAt(workingHeadId()).values)
        require(context.sourceRevisionSha256 == observedRevision) {
            "repair sources changed after context selection"
        }
    }

    /** Capture the complete selected staging context before any durable attempt exists. */
    @Synchronized
    internal fun preflightStagingContext(context: RepairContextSelection): Map<String, ByteArray> = graphOperation {
        requireContextBinding(context)
        if (context.readablePaths.size > state.budget.maximumContextFiles) {
            throw RepairBudgetExceededException(
                "repair staging context has ${context.readablePaths.size} files; " +
                    "limit=${state.budget.maximumContextFiles}",
            )
        }
        val captured = TreeMap<String, ByteArray>()
        var total = 0L
        context.readablePaths.forEach { relative ->
            val bytes = if (state.schemaVersion >= 3) readBlob(sourcesAt(workingHeadId()).getValue(relative).sha256) else
                readStableRegularFile(projectRoot, relative, state.budget.maximumSourceFileBytes).bytes
            total = Math.addExact(total, bytes.size.toLong())
            if (total > state.budget.maximumContextBytes) {
                throw RepairBudgetExceededException(
                    "repair staging context contains $total bytes; limit=${state.budget.maximumContextBytes}",
                )
            }
            if (total > state.budget.maximumStagingBytes) {
                throw RepairBudgetExceededException(
                    "repair staging context contains $total bytes; limit=${state.budget.maximumStagingBytes}",
                )
            }
            index.profile.validateSourceContent(relative, bytes)
            captured[relative] = bytes.copyOf()
        }
        require(total == context.totalBytes) { "repair staging context changed after selection" }
        requireCurrentHead()
        require(revisionSha256(sourcesAt(workingHeadId()).values) == context.sourceRevisionSha256) {
            "repair sources changed while the staging context was captured"
        }
        Collections.unmodifiableMap(
            captured.mapValuesTo(TreeMap<String, ByteArray>()) { (_, bytes) -> bytes.copyOf() },
        )
    }

    @Synchronized
    fun beginAttempt(
        allowedPaths: Collection<String>,
        repairMetadata: RevisionRepairMetadata? = null,
    ): ModuleRevisionAttempt = graphOperation {
        require(state.pending == null) { "revision graph already has a pending attempt" }
        if (repairMetadata != null) require(state.schemaVersion >= 2) {
            "legacy repair revision graphs are non-release, read-only and cannot record agent attempts"
        }
        if (state.nodes.size >= state.budget.maximumRevisionNodes) {
            throw RepairBudgetExceededException("revision graph reached its node budget")
        }
        if (allowedPaths.size > state.budget.maximumContextFiles) {
            throw RepairBudgetExceededException(
                "pending repair has ${allowedPaths.size} authorized paths; limit=${state.budget.maximumContextFiles}",
            )
        }
        val allowed = allowedPaths.map(::normalizedRelative).distinct().sorted()
        require(allowed.isNotEmpty()) { "repair attempt must authorize at least one source path" }
        val indexedEditablePaths = index.editablePaths
        require(allowed.all { it in indexedEditablePaths }) { "repair attempt authorizes a non-editable source path" }
        val frozenMetadata = repairMetadata?.deepFrozenCopy()
        frozenMetadata?.let { metadata ->
            require(receiptCommitmentBytes(metadata.prompt).size.toLong() <= state.budget.maximumRequestBytes) {
                "repair prompt exceeds the request-byte budget"
            }
            val expectedIteration = Math.addExact(
                state.nodes.mapNotNull { it.repairMetadata?.iterationIndex }.maxOrNull() ?: 0,
                1,
            )
            require(metadata.iterationIndex == expectedIteration) {
                "repair iteration index is stale: expected=$expectedIteration observed=${metadata.iterationIndex}"
            }
            require(metadata.retainedRegressionIds == state.retainedRegressionInputs.map { it.id }) {
                "repair attempt is not bound to the complete retained regression corpus"
            }
            require(metadata.regressionCorpusSha256 == state.regressionCorpusSha256) {
                "repair attempt retained regression corpus changed after request construction"
            }
        }
        requireCurrentHead()
        // Schema 6 makes every new candidate detached until its explicit acceptance decision.
        // Historical schema-1..5 graphs retain their prior publication semantics.
        val detached = state.schemaVersion >= 6 || state.schemaVersion >= 3 &&
            (state.runs.lastOrNull()?.terminal == false || workingHeadId() == state.provisionalHeadId)
        val currentHeadSnapshot = sourcesAt(workingHeadId()).values.toList()
        val parent = state.nodes.single { it.id == workingHeadId() }
        val ordinal = state.nextOrdinal
        val idMaterial = parent.id + "\n" + ordinal + "\n" + allowed.joinToString("\n")
        val attemptId = "revision_${ordinal.toString().padStart(8, '0')}_${sha256(idMaterial.toByteArray()).take(16)}"
        val snapshotByPath = currentHeadSnapshot.associateBy { it.path }
        val preimages = allowed.map { path ->
            val indexedSource = snapshotByPath.getValue(path)
            RevisionFileDelta(
                path,
                indexedSource.sha256,
                indexedSource.bytes,
                indexedSource.sha256,
                indexedSource.sha256,
                indexedSource.sha256,
                indexedSource.bytes,
            )
        }
        validatePendingPreimageAggregate(allowed, preimages, state.budget)
        val capturedPreimages = if (detached) emptyList() else allowed.mapIndexed { preimageIndex, path ->
            faultInjector?.hit(ModuleRevisionFaultPoint.BeforePreimageRead(path, preimageIndex))
            val source = readStableRegularFile(
                projectRoot,
                path,
                state.budget.maximumSourceFileBytes,
                requireNoExtendedAttributes = true,
                afterAuthorization = {
                    faultInjector?.hit(ModuleRevisionFaultPoint.BeforeDescriptorBoundRead(path, preimageIndex))
                },
                afterRead = {
                    faultInjector?.hit(ModuleRevisionFaultPoint.AfterDescriptorBoundRead(path, preimageIndex))
                },
            )
            val indexedSource = snapshotByPath.getValue(path)
            require(source.sha256 == indexedSource.sha256 && source.bytes.size.toLong() == indexedSource.bytes) {
                "repair source changed while its preimage was captured: $path"
            }
            source
        }
        val detachedDecisionPreimageMetadata = if (detached && state.schemaVersion >= 6) {
            // Provisional nodes advance headId but are deliberately detached from the canonical
            // source tree. The physical publication witness must compare the working view with
            // the fully accepted source head, not with the logical graph head.
            val publishedHeadId = revisionCanonicalBase(state.nodes, state.headId)
            val publishedSources = sourcesAt(publishedHeadId)
            val workingSources = sourcesAt(workingHeadId())
            val provisionalDeltaPaths = (publishedSources.keys + workingSources.keys).filter { path ->
                publishedSources[path]?.let { before -> workingSources[path]?.let { after ->
                    before.sha256 == after.sha256 && before.bytes == after.bytes
                } } != true
            }
            val decisionWitnessPaths = (allowed + provisionalDeltaPaths).distinct().sorted()
            decisionWitnessPaths.associateWith { path ->
                val observed = readStableRegularFile(
                    projectRoot, path, state.budget.maximumSourceFileBytes, requireNoExtendedAttributes = true,
                )
                val published = publishedSources.getValue(path)
                require(observed.sha256 == published.sha256 && observed.bytes.size.toLong() == published.bytes) {
                    "published source changed while its schema-6 decision preimage was captured: $path"
                }
                val fileState = observed.state
                RepairPreimageMetadata(
                    metadataVersion = 2,
                    device = observed.identity.key.device,
                    inode = observed.identity.key.inode,
                    mode = fileState.identity.mode,
                    uid = fileState.identity.uid,
                    gid = fileState.identity.gid,
                    size = fileState.size,
                    atimeSeconds = fileState.accessTimeSeconds,
                    atimeNanoseconds = fileState.accessTimeNanoseconds,
                    mtimeSeconds = fileState.modificationTimeSeconds,
                    mtimeNanoseconds = fileState.modificationTimeNanoseconds,
                    ctimeSeconds = fileState.changeTimeSeconds,
                    ctimeNanoseconds = fileState.changeTimeNanoseconds,
                    retainedName = sourceTransactionPreimageName(path, attemptId),
                    ancestorMetadata = captureAncestorMetadata(path),
                )
            }
        } else null
        capturedPreimages.forEach { source ->
            require(storeBlob(source.bytes) == source.sha256) { "repair preimage blob digest changed while stored" }
        }
        val verifiedSnapshot = if (state.schemaVersion >= 3) sourcesAt(workingHeadId()) else index.sourceSnapshot().associateBy { it.path }
        require(revisionSha256(verifiedSnapshot.values) == parent.sourceRevisionSha256) {
            "repair source tree changed while attempt preimages were captured"
        }
        preimages.forEach { preimage ->
            val verified = verifiedSnapshot.getValue(preimage.path)
            require(verified.sha256 == preimage.beforeSha256 && verified.bytes == preimage.beforeBytes) {
                "repair preimage no longer matches the source tree: ${preimage.path}"
            }
        }
        val portableMetadata = frozenMetadata?.let { metadata ->
            metadata.copy(
                failureKind = portableEvidenceText(metadata.failureKind),
                prompt = repairPromptCommitment(portableEvidenceText(metadata.prompt)),
                summary = metadata.summary?.let(::portableEvidenceText),
                retainedRegressionIds = immutableList(metadata.retainedRegressionIds.map(::portableEvidenceText)),
                before = metadata.before?.let { before ->
                    before.copy(
                        kind = portableEvidenceText(before.kind),
                        summary = portableEvidenceText(before.summary),
                        artifactPath = before.artifactPath?.let(::portableEvidencePath),
                    )
                },
                regressionCorpusSha256 = metadata.regressionCorpusSha256,
                runId = state.runs.lastOrNull()?.takeUnless { it.terminal }?.id,
            )
        }
        val pending = PendingAttempt(
            attemptId,
            parent.id,
            ordinal,
            allowed,
            parent.sourceRevisionSha256,
            preimages,
            null,
            emptyList(),
            portableMetadata,
            detached = detached,
            preimageMetadata = detachedDecisionPreimageMetadata ?: if (detached) emptyMap() else capturedPreimages.zip(allowed).associate { (source, path) ->
                val state = source.state
                path to RepairPreimageMetadata(
                    metadataVersion = 2,
                    device = source.identity.key.device,
                    inode = source.identity.key.inode,
                    mode = state.identity.mode,
                    uid = state.identity.uid,
                    gid = state.identity.gid,
                    size = state.size,
                    atimeSeconds = state.accessTimeSeconds,
                    atimeNanoseconds = state.accessTimeNanoseconds,
                    mtimeSeconds = state.modificationTimeSeconds,
                    mtimeNanoseconds = state.modificationTimeNanoseconds,
                    ctimeSeconds = state.changeTimeSeconds,
                    ctimeNanoseconds = state.changeTimeNanoseconds,
                    retainedName = sourceTransactionPreimageName(path, attemptId),
                )
            },
            sourceWitnessSha256 = if (detached && state.schemaVersion >= 6) {
                schema6SourceWitnessSha256(projectRoot, sourcesAt(revisionCanonicalBase(state.nodes, state.headId)), state.budget)
            } else null,
        )
        val run = state.runs.lastOrNull()?.takeUnless { it.terminal }
        run?.let {
            if (it.remainingAttempts <= 0) throw RepairBudgetExceededException("repair run attempt budget exhausted")
            if (System.currentTimeMillis() >= it.deadlineEpochMillis) throw RepairBudgetExceededException("repair run wall budget exhausted")
        }
        // Do not mutate a legacy graph merely because a caller supplied an invalid attempt.
        // Upgrade only after path, content, metadata and aggregate-budget preflight completed.
        if (state.schemaVersion < 5) upgradeGraphToRollbackContract(allowPending = false)
        val pendingState = state.copy(
            nextOrdinal = ordinal + 1, pending = if (detached && state.schemaVersion >= 6) {
                pending.copy(rollbackRecord = initialRollbackRecord(state, pending, false))
            } else pending,
            runs = if (run == null) state.runs else state.runs.dropLast(1) + run.copy(attemptedCount = run.attemptedCount + 1))
        requireRecoverablePendingState(pendingState)
        persist(pendingState)
        return ModuleRevisionAttempt(attemptId)
    }

    @Synchronized
    fun annotateAttempt(attempt: ModuleRevisionAttempt, summary: String) = graphOperation {
        val pending = requirePending(attempt)
        val metadata = requireNotNull(pending.repairMetadata) { "repair attempt has no iteration metadata" }
        require(metadata.summary == null) { "repair attempt summary is already recorded" }
        val annotatedState = state.copy(
            pending = pending.copy(
                repairMetadata = metadata.copy(summary = portableEvidenceText(summary)),
            ),
        )
        requireRecoverablePendingState(annotatedState)
        persist(annotatedState)
    }

    /**
     * Persists the host-authored turn intent and binds it into the pending graph before any
     * provider dispatch. The immutable document remains if the graph exchange fails, making the
     * turn safely classifiable as interrupted/unknown on recovery.
     */
    @Synchronized
    internal fun persistAndBindAgentTurnIntent(
        attempt: ModuleRevisionAttempt,
        intent: AgentTurnIntent,
    ): RepairAgentTurnIntentBinding = graphOperation {
        require(state.schemaVersion >= 6) { "legacy repair graph schema cannot bind durable turn intents" }
        val pending = requirePending(attempt)
        val metadata = requireNotNull(pending.repairMetadata) { "repair attempt has no iteration metadata" }
        require(metadata.turnIntent == null && metadata.agentInvocation == null) {
            "repair attempt already has turn evidence"
        }
        require(intent.attemptId == pending.id && intent.taskId == pending.id &&
            intent.requestSha256.matches(REPAIR_BLOB_DIGEST) &&
            intent.beforeSha256 == pending.parentSourceRevisionSha256 &&
            intent.profileSha256 == state.profileSha256) {
            "repair turn intent is not bound to the admitted attempt"
        }
        val fileName = "${pending.id}.acp-intent.json"
        val path = "reports/repair-revisions/$fileName"
        val bytes = intent.canonicalBytes()
        require(bytes.size <= MAXIMUM_REPAIR_INTENT_BYTES) { "repair turn intent exceeds its 1 MiB limit" }
        try {
            stateStore.writeImmutableRevisionFile(fileName, bytes, MAXIMUM_REPAIR_INTENT_BYTES.toLong())
            val observed = stateStore.readRevisionFile(fileName, MAXIMUM_REPAIR_INTENT_BYTES.toLong())
            require(observed.sha256 == intent.sha256 && observed.bytes.contentEquals(bytes)) {
                "published repair turn intent differs from its descriptor"
            }
            val parsed = AgentTurnIntent.parse(observed.bytes)
            require(parsed.turnId == intent.turnId && parsed.requestSha256 == intent.requestSha256) {
                "published repair turn intent is cross-paired"
            }
        } catch (failure: Exception) {
            throw RepairAgentEvidencePersistenceException("repair turn intent could not be persisted before dispatch", failure)
        }
        val binding = RepairAgentTurnIntentBinding(path, intent.sha256, intent.turnId)
        try {
            val bound = state.copy(
                schemaVersion = 7,
                pending = pending.copy(repairMetadata = metadata.copy(turnIntent = binding)),
            )
            requireRecoverablePendingState(bound)
            persist(bound)
        } catch (failure: Exception) {
            throw RepairAgentEvidencePersistenceException("repair turn intent was preserved but graph binding failed", failure)
        }
        binding
    }

    @Synchronized
    internal fun createAndPersistAgentTurnIntent(
        attempt: ModuleRevisionAttempt,
        identity: AgentTurnIdentity,
        workflowId: String,
        policySha256: String,
    ): AgentTurnIntent {
        val (beforeSha256, profileSha256) = graphOperation {
            val pending = requirePending(attempt)
            pending.parentSourceRevisionSha256 to state.profileSha256
        }
        val intent = AgentTurnIntent.create(
            identity = identity,
            workflowId = workflowId,
            attemptId = attempt.id,
            profileSha256 = profileSha256,
            policySha256 = policySha256,
            beforeSha256 = beforeSha256,
        )
        persistAndBindAgentTurnIntent(attempt, intent)
        return intent
    }

    /**
     * Durably publishes the immutable invocation before the graph assessment refers to it. If the
     * second (graph) publication fails, the raw receipt intentionally remains available for audit;
     * callers must propagate [RepairAgentEvidencePersistenceException] without fallback/retry.
     */
    @Synchronized
    internal fun persistAndBindAgentInvocation(
        attempt: ModuleRevisionAttempt,
        document: AcpExecutionReceiptDocument,
    ): RepairAgentInvocationBinding = graphOperation {
        require(state.schemaVersion >= 2) {
            "legacy repair revision graphs are read-only and cannot record ACP invocations"
        }
        val pending = requirePending(attempt)
        val metadata = requireNotNull(pending.repairMetadata) { "repair attempt has no iteration metadata" }
        require(metadata.agentInvocation == null) { "repair attempt already has invocation evidence" }
        val intentBinding = metadata.turnIntent
        if (state.schemaVersion >= 7) {
            requireNotNull(intentBinding) { "repair invocation cannot be persisted without its pre-dispatch turn intent" }
            val intent = AgentTurnIntent.parse(
                stateStore.readRevisionFile(
                    "${pending.id}.acp-intent.json", MAXIMUM_REPAIR_INTENT_BYTES.toLong(),
                ).bytes,
            )
            require(document.requestSha256 == intent.requestSha256 &&
                document.turnIdentity?.turnId == intent.turnId &&
                document.turnIdentity.taskId == pending.id &&
                document.turnIdentity.requestSha256 == intent.requestSha256) {
                "repair ACP receipt turn/request identity differs from its pre-dispatch intent"
            }
            require(document.schemaVersion == 3) { "schema-7 repair requires a turn-bound ACP receipt" }
        }
        val fileName = "${pending.id}.acp-receipt.json"
        val receiptPath = "reports/repair-revisions/$fileName"
        val bytes = document.json.toByteArray(Charsets.UTF_8)
        require(bytes.size.toLong() <= MAXIMUM_REPAIR_ACP_RECEIPT_BYTES) {
            "repair ACP receipt exceeds its $MAXIMUM_REPAIR_ACP_RECEIPT_BYTES-byte limit"
        }
        require(sha256(bytes) == document.sha256) { "repair ACP receipt changed after rendering" }
        val verifiedDocument = verifyAcpExecutionReceiptDocument(
            bytes,
            TRACE_REPAIR_ACP_RECEIPT_KIND,
            TRACE_REPAIR_ACP_TASK_FIELD,
            pending.id,
        )
        require(verifiedDocument.requestSha256 == document.requestSha256 &&
            verifiedDocument.promptSha256 == metadata.prompt &&
            verifiedDocument.resultChangesSha256 == document.resultChangesSha256 &&
            verifiedDocument.terminalOutcome == document.terminalOutcome &&
            verifiedDocument.releaseComplete == document.releaseComplete
        ) { "repair ACP receipt descriptor disagrees with its rendered document" }
        try {
            stateStore.writeImmutableRevisionFile(fileName, bytes, MAXIMUM_REPAIR_ACP_RECEIPT_BYTES)
            val observed = stateStore.readRevisionFile(fileName, MAXIMUM_REPAIR_ACP_RECEIPT_BYTES)
            require(observed.sha256 == document.sha256 && observed.bytes.contentEquals(bytes)) {
                "published repair ACP receipt differs from the invocation document"
            }
        } catch (failure: Exception) {
            throw RepairAgentEvidencePersistenceException(
                "repair ACP invocation evidence could not be persisted before assessment",
                failure,
            )
        }
        val binding = RepairAgentInvocationBinding(
            receiptPath = receiptPath,
            receiptSha256 = document.sha256,
            receiptSchemaVersion = document.schemaVersion,
            requestSha256 = document.requestSha256,
            resultChangesSha256 = document.resultChangesSha256,
            terminalOutcome = document.terminalOutcome,
            receiptReleaseComplete = document.releaseComplete,
            assessmentStatus = RepairAgentAssessmentStatus.PENDING,
            intentPath = intentBinding?.intentPath,
            intentSha256 = intentBinding?.intentSha256,
            turnId = intentBinding?.turnId,
        )
        val boundState = state.copy(
            pending = pending.copy(
                repairMetadata = metadata.copy(agentInvocation = binding),
            ),
        )
        try {
            requireRecoverablePendingState(boundState)
            persist(boundState)
        } catch (failure: Exception) {
            throw RepairAgentEvidencePersistenceException(
                "repair ACP invocation receipt was preserved but its pending assessment could not be persisted",
                failure,
            )
        }
        binding.copy()
    }

    /** Persist an immutable post-validation assessment before any acceptance/publication decision. */
    @Synchronized
    internal fun persistAndBindAgentAssessment(
        attempt: ModuleRevisionAttempt,
        assessment: AcpChangeAssessment,
    ): RepairAgentInvocationBinding = graphOperation {
        require(state.schemaVersion >= 7) { "repair graph schema cannot bind durable assessments" }
        val pending = requirePending(attempt)
        val metadata = requireNotNull(pending.repairMetadata)
        val invocation = requireNotNull(metadata.agentInvocation) {
            "repair assessment cannot be persisted without invocation evidence"
        }
        require(invocation.assessmentPath == null && invocation.assessmentSha256 == null) {
            "repair attempt already has a durable assessment"
        }
        require(assessment.turnId == metadata.turnIntent?.turnId &&
            assessment.intentSha256 == metadata.turnIntent.intentSha256 &&
            assessment.receiptSha256 == invocation.receiptSha256 &&
            assessment.beforeSha256 == pending.parentSourceRevisionSha256) {
            "repair assessment is cross-paired with its pending attempt"
        }
        if (assessment.afterSha256 != null) {
            require(assessment.afterSha256 == pending.candidateSourceRevisionSha256) {
                "repair assessment candidate commitment differs from graph"
            }
        }
        if (assessment.eligibility in setOf(
                decompengine.project.AcpChangePublicationEligibility.PROVISIONAL,
                decompengine.project.AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION,
            )) {
            require(assessment.afterSha256 != null && pending.candidateSourceRevisionSha256 != null) {
                "publishable repair assessment requires a persisted candidate"
            }
        }
        val fileName = "${pending.id}.acp-assessment.json"
        val path = "reports/repair-revisions/$fileName"
        val bytes = assessment.canonicalBytes()
        require(bytes.size <= MAXIMUM_REPAIR_ASSESSMENT_BYTES) {
            "repair assessment exceeds its 1 MiB limit"
        }
        try {
            stateStore.writeImmutableRevisionFile(fileName, bytes, MAXIMUM_REPAIR_ASSESSMENT_BYTES.toLong())
            val observed = stateStore.readRevisionFile(fileName, MAXIMUM_REPAIR_ASSESSMENT_BYTES.toLong())
            require(observed.sha256 == assessment.sha256 && observed.bytes.contentEquals(bytes) &&
                AcpChangeAssessment.parse(observed.bytes).canonicalBytes().contentEquals(bytes)) {
                "published repair assessment differs from its descriptor"
            }
        } catch (failure: Exception) {
            throw RepairAgentEvidencePersistenceException("repair assessment could not be persisted before decision", failure)
        }
        val updated = invocation.copy(assessmentPath = path, assessmentSha256 = assessment.sha256)
        val boundState = state.copy(pending = pending.copy(repairMetadata = metadata.copy(agentInvocation = updated)))
        try {
            requireRecoverablePendingState(boundState)
            persist(boundState)
        } catch (failure: Exception) {
            throw RepairAgentEvidencePersistenceException("repair assessment was preserved but graph binding failed", failure)
        }
        updated
    }

    @Synchronized
    fun installCandidate(
        attempt: ModuleRevisionAttempt,
        replacements: Map<String, ByteArray>,
    ): List<RevisionFileDelta> = graphOperation {
        val pending = requirePending(attempt)
        require(pending.candidateSourceRevisionSha256 == null) { "repair candidate is already installed" }
        val normalized = replacements.entries.associate { normalizedRelative(it.key) to it.value.copyOf() }
        require(normalized.size == replacements.size) { "repair candidate changes a source path more than once" }
        require(normalized.isNotEmpty()) { "repair candidate does not change a source file" }
        require(normalized.keys.all { it in pending.allowedPaths }) { "repair candidate changes an unauthorized source path" }
        if (normalized.size > state.budget.maximumPatchFiles) {
            throw RepairBudgetExceededException(
                "repair candidate changes ${normalized.size} files; limit=${state.budget.maximumPatchFiles}",
            )
        }
        normalized.forEach { (path, bytes) ->
            if (bytes.size.toLong() > state.budget.maximumSourceFileBytes) {
                throw RepairBudgetExceededException(
                    "repair candidate file $path has ${bytes.size} bytes; limit=${state.budget.maximumSourceFileBytes}",
                )
            }
        }
        val patchBytes = normalized.values.fold(0L) { total, bytes -> Math.addExact(total, bytes.size.toLong()) }
        if (patchBytes > state.budget.maximumPatchBytes) {
            throw RepairBudgetExceededException(
                "repair candidate contains $patchBytes replacement bytes; limit=${state.budget.maximumPatchBytes}",
            )
        }
        normalized.forEach { (path, bytes) -> index.profile.validateSourceContent(path, bytes) }
        requireCurrentHead()
        val preimages = pending.preimages.associateBy { it.path }
        val replacementDigests = normalized.mapValues { (_, replacement) -> sha256(replacement) }
        val blobReservation = reserveBlobPublications(replacementDigests.values)
        val changes = normalized.entries.sortedBy { it.key }.mapNotNull { (path, replacement) ->
            val before = preimages.getValue(path)
            val afterSha = replacementDigests.getValue(path)
            if (afterSha == before.beforeSha256 && replacement.contentEquals(readBlob(before.beforeBlobSha256!!))) return@mapNotNull null
            val blob = storeBlob(replacement, blobReservation)
            RevisionFileDelta(
                path,
                before.beforeSha256,
                before.beforeBytes,
                afterSha,
                before.beforeBlobSha256,
                blob,
                replacement.size.toLong(),
            )
        }
        require(changes.isNotEmpty()) { "repair candidate replacements are byte-identical to the accepted revision" }
        val expectedSources = sourcesAt(pending.parentId).toMutableMap()
        changes.forEach { change -> expectedSources[change.path] = IndexedSource(change.path, change.afterBytes, change.afterSha256) }
        val candidateRevision = revisionSha256(expectedSources.values.sortedBy { it.path })
        val candidatePending = pending.copy(
            candidateSourceRevisionSha256 = candidateRevision,
            candidateChanges = changes,
        )
        val projectedBlobBytes = referencedBlobBytes(state.nodes, candidatePending)
        if (projectedBlobBytes > state.budget.maximumStoredBlobBytes) {
            deleteUnreferencedCandidateBlobs(changes)
            throw RepairBudgetExceededException(
                "repair revision blobs require $projectedBlobBytes bytes; limit=${state.budget.maximumStoredBlobBytes}",
            )
        }
        val candidateStatePending = if (!pending.detached && state.schemaVersion >= 4) {
            val rollbackRecord = candidatePending.rollbackRecord ?: initialRollbackRecord(
                state,
                candidatePending,
                candidatePending.legacyRecoveryRequired,
            )
            candidatePending.copy(
                rollbackRecord = rollbackRecord.copy(candidateSourceInstallStarted = true),
            )
        } else candidatePending
        val candidateState = state.copy(pending = candidateStatePending)
        try {
            requireRecoverablePendingState(candidateState)
        } catch (failure: Exception) {
            deleteUnreferencedCandidateBlobs(changes)
            throw failure
        }
        persist(candidateState)
        faultInjector?.hit(ModuleRevisionFaultPoint.AfterCandidateStatePersist)
        if (pending.detached) return@graphOperation immutableList(changes.map(RevisionFileDelta::copy))
        try {
            installFiles(
                changes.associate { it.path to readBlob(it.afterBlobSha256) },
                changes.associate { it.path to requireNotNull(it.beforeSha256) },
                transactionId = pending.id,
                phase = "candidate",
                preimageMetadata = pending.preimageMetadata.orEmpty(),
            )
            val observed = revisionSha256(index.sourceSnapshot())
            require(observed == candidateRevision) {
                "installed repair candidate is not source-bound: expected=$candidateRevision observed=$observed"
            }
            val candidateIndex = SecureRepairRuntime.loadIndex(graphAuthority, projectRoot, index.profile, state.budget)
            require(candidateIndex.indexSha256 == index.indexSha256) {
                "repair candidate changes compiler/source dependency evidence; split dependency changes into a reviewed graph migration " +
                    "(expected=${index.indexSha256}, observed=${candidateIndex.indexSha256})"
            }
        } catch (failure: Exception) {
            try {
                val rollback = rollbackPending(candidatePending)
                val active = requireNotNull(state.pending)
                persist(state.copy(pending = active.copy(rollbackRecord = rollback)))
            } catch (rollbackFailure: Exception) {
                failure.addSuppressed(rollbackFailure)
            }
            throw failure
        }
        immutableList(changes.map(RevisionFileDelta::copy))
    }

    @Synchronized
    fun accept(attempt: ModuleRevisionAttempt, evidence: RepairEvidence?, proof: RepairValidationProof? = null,
        cancellationCheck: () -> Unit = {}): ModuleRevisionNode = graphOperation {
        cancellationCheck()
        var pending = requirePending(attempt)
        val acceptanceBaseState = state
        if (pending.acceptanceDecision != null) {
            throw RepairAcceptancePendingException(
                "repair acceptance decision is already durable; only roll-forward recovery is permitted",
            )
        }
        require(state.runs.none { it.id == pending.repairMetadata?.runId && it.status == RepairRunStatus.ROLLBACK_FAILED }) {
            "a failed rollback attempt must be restored and finalized before further acceptance"
        }
        pending.repairMetadata?.takeIf { it.publicationMode == RepairPublicationMode.ACP_RELEASE }?.let { metadata ->
            val invocation = requireNotNull(metadata.agentInvocation) {
                "agent-driven repair cannot be accepted without invocation-bound ACP evidence"
            }
            require(invocation.assessmentStatus == RepairAgentAssessmentStatus.PENDING &&
                invocation.receiptReleaseComplete && invocation.terminalOutcome == "returned-completed"
            ) { "agent-driven repair cannot be accepted with incomplete ACP invocation evidence" }
            require(invocation.resultChangesSha256 == pendingAgentChangeSetSha256(pending)) {
                "agent-driven repair candidate differs from its ACP result change set"
            }
            validateAgentInvocationBinding(
                invocation,
                pending.id,
                metadata.turnIntent,
                metadata.prompt,
                RepairAgentAssessmentStatus.PENDING,
                verifyReceiptContents = true,
            )
        }
        val candidate = requireNotNull(pending.candidateSourceRevisionSha256) { "repair candidate has not been installed" }
        var prevalidatedNode: ModuleRevisionNode? = null
        var prevalidatedAcceptance: PreparedRevisionGraphState? = null
        var preparedDecisionWrite: PreparedRevisionGraphState? = null
        if (pending.detached) {
            require(evidence?.kind == "valid") { "only full retained behavior validation may promote source" }
            requireValidationProof(candidate, requireNotNull(proof), full = true)
            if (pending.repairMetadata?.publicationMode == RepairPublicationMode.ACP_RELEASE) {
                require(proof.assurance == RepairValidationAssurance.STRICT_CONTAINED)
            }
            val promotion = if (state.schemaVersion >= 6) deriveSchema6PromotionChanges(state, pending) else {
                val baseSources = requireCurrentHead().associateBy { it.path }
                val finalSources = sourcesAt(pending.parentId).toMutableMap()
                pending.candidateChanges.forEach { finalSources[it.path] = IndexedSource(it.path, it.afterBytes, it.afterSha256) }
                finalSources.toSortedMap().mapNotNull { (path, after) ->
                    val before = baseSources.getValue(path)
                    if (before == after) null else RevisionFileDelta(path, before.sha256, before.bytes,
                        after.sha256, before.sha256, after.sha256, after.bytes)
                }
            }
            require(promotion.isNotEmpty())
            cancellationCheck()
            val promotionBytes = promotion.associate { change ->
                cancellationCheck()
                change.path to readBlob(change.afterBlobSha256).also {
                    index.profile.validateSourceContent(change.path, it)
                }
            }
            if (state.schemaVersion >= 6) {
                val finalSources = sourcesAt(pending.parentId).toMutableMap()
                pending.candidateChanges.forEach { change ->
                    finalSources[change.path] = IndexedSource(change.path, change.afterBytes, change.afterSha256)
                }
                val candidateView = object : RepairRecoverySourceView {
                    override val sourcePaths: List<String> get() = index.sourcePaths
                    override val editablePaths: List<String> get() = index.editablePaths.sorted()
                    override fun readSource(relative: String): ByteArray {
                        require(relative == normalizedRelative(relative))
                        val source = requireNotNull(finalSources[relative]) {
                            "candidate source view path is absent: $relative"
                        }
                        return readBlob(source.sha256).also { bytes ->
                            require(bytes.size.toLong() == source.bytes && sha256(bytes) == source.sha256)
                        }
                    }
                }
                val candidateIndex = SecureRepairRuntime.loadRecoveryIndex(
                    graphAuthority, projectRoot, index.profile, state.budget, candidateView,
                )
                require(candidateIndex.sourceRevisionSha256 == candidate &&
                    candidateIndex.profileId == state.profileId &&
                    candidateIndex.profileSha256 == state.profileSha256 &&
                    candidateIndex.sourcePaths == index.sourcePaths &&
                    candidateIndex.editablePaths.sorted() == state.editablePaths &&
                    candidateIndex.indexSha256 == state.indexSha256) {
                    "repair candidate changes compiler/source dependency evidence or differs from its validation proof"
                }
            }
            val promotionPreimageMetadata = promotion.associate { change ->
                val observed = readStableRegularFile(
                    projectRoot,
                    change.path,
                    state.budget.maximumSourceFileBytes,
                    requireNoExtendedAttributes = true,
                )
                if (state.schemaVersion >= 6) {
                    require(change.path in pending.preimageMetadata.orEmpty()) {
                        "schema-6 promotion path lacks an attempt-time metadata witness: ${change.path}"
                    }
                    val captured = requireNotNull(pending.preimageMetadata?.get(change.path)) {
                        "schema-6 promotion is missing its attempt-time source witness: ${change.path}; " +
                            "captured=${pending.preimageMetadata?.keys?.sorted()}"
                    }
                    require(observed.sha256 == change.beforeSha256 && observed.bytes.size.toLong() == change.beforeBytes &&
                        captured.matchesExactly(observed.state) &&
                        captured.ancestorMetadata == captureAncestorMetadata(change.path)) {
                        "schema-6 source or ancestor metadata changed after attempt start: ${change.path}"
                    }
                    change.path to captured
                } else {
                require(observed.sha256 == change.beforeSha256 && observed.bytes.size.toLong() == change.beforeBytes) {
                    "promotion source changed while its preimage metadata was captured: ${change.path}"
                }
                change.path to RepairPreimageMetadata(
                    metadataVersion = 2,
                    device = observed.identity.key.device,
                    inode = observed.identity.key.inode,
                    mode = observed.state.identity.mode,
                    uid = observed.state.identity.uid,
                    gid = observed.state.identity.gid,
                    size = observed.state.size,
                    atimeSeconds = observed.state.accessTimeSeconds,
                    atimeNanoseconds = observed.state.accessTimeNanoseconds,
                    mtimeSeconds = observed.state.modificationTimeSeconds,
                    mtimeNanoseconds = observed.state.modificationTimeNanoseconds,
                    ctimeSeconds = observed.state.changeTimeSeconds,
                    ctimeNanoseconds = observed.state.changeTimeNanoseconds,
                    retainedName = sourceTransactionPreimageName(change.path, pending.id),
                )
                }
            }
            pending = pending.copy(
                promotionChanges = promotion,
                promotionPreimageMetadata = promotionPreimageMetadata,
                rollbackRecord = (pending.rollbackRecord ?: initialRollbackRecord(state, pending, false))
                    .copy(candidateSourceInstallStarted = true),
            )
            val promotionState = if (state.schemaVersion >= 6) {
                val (stagedPending, stagedFiles) = try {
                    stagePublicationFiles(pending, promotion, promotionBytes, promotionPreimageMetadata)
                } catch (failure: Exception) {
                    // Staging is outside the source tree and may be safely discarded before a
                    // decision exists. Any failed authentication leaves the graph unavailable.
                    runCatching { cleanupUndecidedPublicationStages(acceptanceBaseState, promotion, pending.id) }
                        .exceptionOrNull()?.let(failure::addSuppressed)
                    throw failure
                }
                pending = stagedPending
                try {
                    cancellationCheck()
                    // Staging is intentionally off-tree. Revalidate both the complete live
                    // canonical source/index and the attempt-time metadata witness after those
                    // writes, immediately before the durable acceptance decision.
                    faultInjector?.hit(ModuleRevisionFaultPoint.BeforeSchema6DecisionValidation)
                    verifySchema6PendingWitness(projectRoot, state, pending, state.budget)
                    val canonicalBase = revisionCanonicalBase(state.nodes, pending.parentId)
                    val expectedCanonicalRevision = state.nodes.single { it.id == canonicalBase }.sourceRevisionSha256
                    val freshCanonical = SecureRepairRuntime.loadIndex(
                        graphAuthority, projectRoot, index.profile, state.budget,
                    )
                    require(freshCanonical.sourceRevisionSha256 == expectedCanonicalRevision &&
                        freshCanonical.profileId == state.profileId &&
                        freshCanonical.profileSha256 == state.profileSha256 &&
                        freshCanonical.sourcePaths == index.sourcePaths &&
                        freshCanonical.editablePaths.sorted() == state.editablePaths &&
                        freshCanonical.indexSha256 == state.indexSha256) {
                        "canonical source or dependency evidence changed before schema-6 acceptance decision"
                    }
                    val finalSources = sourcesAt(pending.parentId).toMutableMap()
                    pending.candidateChanges.forEach { change ->
                        finalSources[change.path] = IndexedSource(change.path, change.afterBytes, change.afterSha256)
                    }
                    val finalCandidateView = object : RepairRecoverySourceView {
                        override val sourcePaths: List<String> get() = index.sourcePaths
                        override val editablePaths: List<String> get() = index.editablePaths.sorted()
                        override fun readSource(relative: String): ByteArray {
                            require(relative == normalizedRelative(relative))
                            val source = requireNotNull(finalSources[relative]) {
                                "candidate source view path is absent: $relative"
                            }
                            return readBlob(source.sha256).also { bytes ->
                                require(bytes.size.toLong() == source.bytes && sha256(bytes) == source.sha256)
                            }
                        }
                    }
                    val finalCandidateIndex = SecureRepairRuntime.loadRecoveryIndex(
                        graphAuthority, projectRoot, index.profile, state.budget, finalCandidateView,
                    )
                    require(finalCandidateIndex.sourceRevisionSha256 == candidate &&
                        finalCandidateIndex.profileId == state.profileId &&
                        finalCandidateIndex.profileSha256 == state.profileSha256 &&
                        finalCandidateIndex.sourcePaths == index.sourcePaths &&
                        finalCandidateIndex.editablePaths.sorted() == state.editablePaths &&
                        finalCandidateIndex.indexSha256 == state.indexSha256) {
                        "candidate dependency evidence changed before schema-6 acceptance decision"
                    }
                } catch (failure: Exception) {
                    runCatching { cleanupUndecidedPublicationStages(acceptanceBaseState, promotion, pending.id) }
                        .exceptionOrNull()?.let(failure::addSuppressed)
                    throw failure
                }
                try {
                    val acceptedEvidence = requireNotNull(portableEvidence(evidence))
                    val decidedNode = finalizeNode(pending, ModuleRevisionStatus.ACCEPTED, acceptedEvidence,
                        recovered = false).copy(validationProof = proof)
                    val activeRun = state.runs.lastOrNull()?.takeUnless { it.terminal }
                    val acceptedState = state.copy(headId = decidedNode.id, nodes = state.nodes + decidedNode,
                        pending = null, provisionalHeadId = null,
                        fullyAcceptedHeadId = decidedNode.id,
                        acceptedProof = proof,
                        runs = if (activeRun == null) state.runs else state.runs.dropLast(1) + activeRun.copy(
                            status = RepairRunStatus.FULLY_ACCEPTED,
                            acceptedHeadId = decidedNode.id,
                            provisionalHeadId = state.provisionalHeadId,
                            lastEvidence = acceptedEvidence,
                        ))
                    prevalidatedNode = decidedNode
                    prevalidatedAcceptance = requireCommitReadyState(acceptedState)
                    val decision = RepairAcceptanceDecision(
                        proof = proof,
                        evidenceKind = acceptedEvidence.kind,
                        evidenceSummary = acceptedEvidence.summary,
                        evidenceArtifact = acceptedEvidence.artifactPath,
                        promotionChanges = immutableList(promotion.map(RevisionFileDelta::copy)),
                        intendedHeadId = pending.id,
                        intendedRunId = activeRun?.id,
                        intendedRunStatus = RepairRunStatus.FULLY_ACCEPTED.takeIf { activeRun != null },
                        stagedFiles = stagedFiles,
                        committedNode = decidedNode,
                        committedRun = activeRun?.let { acceptedState.runs.lastOrNull() },
                    )
                    pending = pending.copy(acceptanceDecision = decision)
                    pending = pending.copy(predecisionStageFiles = emptyList())
                    validateSchema6DecisionNode(pending, decision)
                    state.copy(pending = pending)
                } catch (failure: Exception) {
                    runCatching { cleanupUndecidedPublicationStages(acceptanceBaseState, promotion, pending.id) }
                        .exceptionOrNull()?.let(failure::addSuppressed)
                    throw failure
                }
            } else {
                cancellationCheck()
                state.copy(pending = pending)
            }
            // Schema 6 persists an accepted graph and its complete publication plan as the
            // decision. A rollback-shaped recoverability projection is no longer applicable:
            // after this point recovery may only roll that recorded decision forward.
            if (state.schemaVersion >= 6) {
                try {
                    // Prepare and admit the exact decision bytes before entering the ambiguous
                    // durable-write boundary. Then run the final live-source check after all
                    // candidate-index and accepted-state work has completed.
                    preparedDecisionWrite = prepareStateForPersistence(promotionState)
                } catch (failure: Exception) {
                    val decisionPending = promotionState.pending
                    if (decisionPending != null) {
                        runCatching { cleanupUndecidedPublicationStages(acceptanceBaseState, promotion, decisionPending.id) }
                            .exceptionOrNull()?.let(failure::addSuppressed)
                    }
                    throw failure
                }
            } else requireRecoverablePendingState(promotionState)
            var decisionChecksPassedImmediatelyBeforePublication = false
            try {
                if (state.schemaVersion >= 6) {
                    persist(requireNotNull(preparedDecisionWrite)) {
                        faultInjector?.hit(ModuleRevisionFaultPoint.Schema6DecisionPrevalidated)
                        faultInjector?.hit(ModuleRevisionFaultPoint.BeforeSchema6DecisionPersist)
                        val witnessPending = requireNotNull(promotionState.pending).copy(acceptanceDecision = null)
                        val canonicalBase = revisionCanonicalBase(state.nodes, witnessPending.parentId)
                        val expectedCanonicalRevision = state.nodes.single { it.id == canonicalBase }.sourceRevisionSha256
                        val finalCanonical = SecureRepairRuntime.loadIndex(
                            graphAuthority, projectRoot, index.profile, state.budget,
                        )
                        require(finalCanonical.sourceRevisionSha256 == expectedCanonicalRevision &&
                            finalCanonical.profileId == state.profileId &&
                            finalCanonical.profileSha256 == state.profileSha256 &&
                            finalCanonical.sourcePaths == index.sourcePaths &&
                            finalCanonical.editablePaths.sorted() == state.editablePaths &&
                            finalCanonical.indexSha256 == state.indexSha256) {
                            "canonical source or dependency evidence changed at the schema-6 decision boundary"
                        }
                        // This must be the final live-tree observation. The canonical index
                        // load above reads the live source tree; check the complete file and
                        // ancestor witness after it, once the graph temp is durable and just
                        // before the decision record replaces the live graph.
                        verifySchema6PendingWitness(projectRoot, state, witnessPending, state.budget)
                        // Validation, state preparation, stage writes, and the final source
                        // observation may consume the remaining run budget or race with
                        // cancellation. This is the last cancellable point before the durable
                        // acceptance decision; after the graph exchange recovery must roll
                        // the accepted publication forward.
                        cancellationCheck()
                        decisionChecksPassedImmediatelyBeforePublication = true
                    }
                }
                else persist(promotionState)
            } catch (failure: Throwable) {
                if (state.schemaVersion >= 6 && !decisionChecksPassedImmediatelyBeforePublication) {
                    val decisionPending = promotionState.pending
                    if (decisionPending != null) {
                        runCatching { cleanupUndecidedPublicationStages(acceptanceBaseState, promotion, decisionPending.id) }
                            .exceptionOrNull()?.let(failure::addSuppressed)
                    }
                    throw failure
                }
                if (state.schemaVersion < 6) throw failure
                lifecycle = Lifecycle.POISONED
                if (failure !is Exception) throw failure
                throw RepairAcceptancePendingException(
                    "repair acceptance decision write is ambiguous; graph is unavailable and rollback is forbidden",
                    failure,
                )
            }
            try {
                if (state.schemaVersion >= 6) {
                    rollForwardRepairPublication(projectRoot, stateStore, requireNotNull(pending.acceptanceDecision), faultInjector)
                } else {
                    installFiles(promotionBytes,
                        promotion.associate { it.path to requireNotNull(it.beforeSha256) }, pending.id, "promotion",
                        preimageMetadata = promotionPreimageMetadata)
                }
            } catch (failure: Exception) {
                if (state.schemaVersion < 6) throw failure
                throw RepairAcceptancePendingException(
                    "repair acceptance decision is durable; publication recovery is required and rollback is forbidden",
                    failure,
                )
            }
        }
        fun requireAcceptingIndex() {
            val acceptingIndex = SecureRepairRuntime.loadIndex(graphAuthority, projectRoot, index.profile, state.budget)
            require(acceptingIndex.sourceRevisionSha256 == candidate) {
                "accepted source tree changed after candidate installation (expected=$candidate observed=${acceptingIndex.sourceRevisionSha256})"
            }
            require(
                acceptingIndex.profileId == state.profileId &&
                    acceptingIndex.profileSha256 == state.profileSha256 &&
                    acceptingIndex.sourcePaths == index.sourcePaths &&
                    acceptingIndex.editablePaths.sorted() == state.editablePaths &&
                    acceptingIndex.indexSha256 == state.indexSha256,
            ) { "repair dependency/profile evidence changed after candidate installation" }
        }
        if (prevalidatedAcceptance == null) {
            faultInjector?.hit(ModuleRevisionFaultPoint.BeforeHeadIndexValidation)
            requireAcceptingIndex()
            faultInjector?.hit(ModuleRevisionFaultPoint.AfterHeadIndexValidation)
            // Historical schema-1..5 publication keeps its pre-existing commit-gap checks.
            requireAcceptingIndex()
            cancellationCheck()
        }
        val node = prevalidatedNode ?: finalizeNode(pending, ModuleRevisionStatus.ACCEPTED, evidence,
            recovered = false).copy(validationProof = proof)
        val preparedAcceptance = prevalidatedAcceptance ?: run {
            val activeRun = state.runs.lastOrNull()?.takeUnless { it.terminal }
            val acceptedState = state.copy(headId = node.id, nodes = state.nodes + node, pending = null,
                provisionalHeadId = null, fullyAcceptedHeadId = if (pending.detached) node.id else state.fullyAcceptedHeadId,
                acceptedProof = proof ?: state.acceptedProof,
                runs = if (activeRun == null) state.runs else state.runs.dropLast(1) + activeRun.copy(
                    status = RepairRunStatus.FULLY_ACCEPTED,
                    acceptedHeadId = node.id,
                    provisionalHeadId = state.provisionalHeadId,
                    lastEvidence = portableEvidence(evidence),
                ))
            requireCommitReadyState(acceptedState)
        }
        if (state.schemaVersion >= 6) {
            try {
                persist(preparedAcceptance)
            } catch (failure: Throwable) {
                lifecycle = Lifecycle.POISONED
                if (failure !is Exception) throw failure
                throw RepairAcceptancePendingException(
                    "repair acceptance decision is durable but graph-head publication is ambiguous; rollback is forbidden",
                    failure,
                )
            }
        } else {
            persist(preparedAcceptance)
        }
        // The accepted graph head is the canonical commit record. Its preimage links are
        // now cleanup residue rather than rollback authority; an ordinary cleanup failure
        // must not turn a durably accepted repair into an API-level rejection. Startup and
        // the next graph mutation retry this authenticated cleanup and fail closed if the
        // retained entries cannot be reconciled.
        try {
            cleanupCommittedPreimages()
        } catch (_: Exception) {
            // Retain the committed result; cleanup is retried before the next mutation/open.
        }
        try {
            faultInjector?.hit(ModuleRevisionFaultPoint.AfterHeadPersist)
        } catch (crash: Error) {
            throw crash
        } catch (_: Exception) {
            // The graph head is already durable; an injected ordinary post-commit failure is a
            // recoverable projection failure and cannot change the successful commit result.
        }
        // The graph head is the commit record. Derived views are recoverable projections and must
        // never turn a durably committed attempt into an ambiguous API failure.
        try {
            faultInjector?.hit(ModuleRevisionFaultPoint.BeforeSourceManifestSync)
            synchronizeSourceManifest()
        } catch (crash: Error) {
            throw crash
        } catch (_: Exception) {
            // Rebuilt on the next graph open.
        }
        try {
            faultInjector?.hit(ModuleRevisionFaultPoint.BeforeCompatibilityLogSync)
            synchronizeCompatibilityLog()
        } catch (crash: Error) {
            throw crash
        } catch (_: Exception) {
            // Rebuilt on the next graph open.
        }
        node.deepFrozenCopy()
    }

    @Synchronized
    fun acceptAssessedBaseline(proof: RepairValidationProof, evidence: RepairEvidence,
        cancellationCheck: () -> Unit = {}): RepairRunState = graphOperation {
        cancellationCheck()
        require(state.schemaVersion >= 3 && state.pending == null && state.provisionalHeadId == null)
        requireValidationProof(revisionSha256(requireCurrentHead()), proof, full = true)
        val run = requireNotNull(state.runs.lastOrNull())
        require(!run.terminal)
        val accepted = run.copy(status = RepairRunStatus.FULLY_ACCEPTED, acceptedHeadId = state.headId,
            lastEvidence = portableEvidence(evidence))
        val prepared = requireCommitReadyState(state.copy(fullyAcceptedHeadId = state.headId, acceptedProof = proof,
            runs = state.runs.dropLast(1) + accepted))
        cancellationCheck()
        persist(prepared)
        accepted
    }

    @Synchronized
    fun reject(attempt: ModuleRevisionAttempt, evidence: RepairEvidence? = null): ModuleRevisionNode = graphOperation {
        val pending = requirePending(attempt)
        if (pending.acceptanceDecision != null) {
            throw RepairAcceptancePendingException(
                "repair acceptance decision is durable; rejection and rollback are forbidden",
            )
        }
        // Invalid caller evidence must not publish a rollback marker or change source bytes.
        validateEvidence(evidence)
        if (state.schemaVersion < 4) preserveLegacyRunState()
        val rollbackState = rollbackContractState()
        requireRecoverablePendingState(rollbackState)
        val previewPending = requireNotNull(rollbackState.pending)
        val reservedFailure = withCommittedRollbackFailure(rollbackState, reservedRollbackRecord(rollbackState, previewPending))
        val reservedOutcome = requireNotNull(reservedFailure.pending?.rollbackRecord)
            .copy(state = RepairRollbackState.RESTORED_AFTER_FAILURE)
        val reservedNode = finalizeNode(previewPending, ModuleRevisionStatus.REJECTED, evidence,
            recovered = false, rollbackRecord = reservedOutcome)
        requireCommitReadyState(withFinalizedRollback(reservedFailure.copy(nodes = reservedFailure.nodes + reservedNode, pending = null), reservedOutcome))
        val successRecord = rollbackOutcomeRecord(previewPending.rollbackRecord ?:
            initialRollbackRecord(rollbackState, previewPending, previewPending.legacyRecoveryRequired),
            requireNotNull(reservedFailure.pending?.rollbackRecord).expectedSourceRevisionSha256)
        val successNode = finalizeNode(previewPending, ModuleRevisionStatus.REJECTED, evidence,
            recovered = false, rollbackRecord = successRecord)
        requireCommitReadyState(withFinalizedRollback(rollbackState.copy(nodes = rollbackState.nodes + successNode,
            pending = null), successRecord))
        val rollbackRecord = rollbackPending(pending)
        val recoveredPending = requirePending(attempt)
        val node = finalizeNode(
            recoveredPending,
            ModuleRevisionStatus.REJECTED,
            evidence,
            recovered = false,
            rollbackRecord = rollbackRecord,
        )
        val preparedRejection = requireCommitReadyState(withFinalizedRollback(
            state.copy(nodes = state.nodes + node, pending = null), rollbackRecord))
        persist(preparedRejection)
        cleanupCommittedPreimages()
        try {
            synchronizeCompatibilityLog()
        } catch (_: Exception) {
            // Derived projection; retried on a later open.
        }
        node.deepFrozenCopy()
    }

    @Synchronized
    fun derivedRepairIterations(): List<RepairIteration> = graphOperation {
        derivedRepairIterations(state)
    }

    private fun derivedRepairIterations(candidate: RevisionGraphState): List<RepairIteration> =
        deriveRepairIterations(candidate.nodes, candidate.budget, candidate.schemaVersion, ::readBlob)

    @Synchronized
    fun synchronizeCompatibilityLog() = graphOperation {
        stateStore.writeReport(
            "source_revisions.jsonl",
            renderCompatibilityProjection(state.nodes, state.budget.maximumProjectionBytes),
        )
    }

    @Synchronized
    internal fun synchronizeRepairHistory() = graphOperation {
        stateStore.writeReport(
            "repair_history.json",
            renderRepairHistoryProjection(
                derivedRepairIterations(),
                retainedRegressionCorpus().inputs,
                state.budget.maximumProjectionBytes,
                repairHistorySchemaForGraph(state.schemaVersion),
                state.runs,
            ).toByteArray(Charsets.UTF_8),
        )
    }

    /**
     * Reconcile every reader-visible projection of the canonical graph before a publication
     * lease may be retired. The graph commit is authoritative; these files are derived, but a
     * cooperating reader must not be admitted while one still describes an older accepted head.
     */
    @Synchronized
    internal fun synchronizePublicationProjections() = graphOperation {
        synchronizeSourceManifest()
        synchronizeCompatibilityLog()
        synchronizeRepairHistory()
    }

    private fun requireProjectableState(candidate: RevisionGraphState) {
        renderRepairHistoryProjection(
            derivedRepairIterations(candidate),
            candidate.retainedRegressionInputs,
            candidate.budget.maximumProjectionBytes,
            repairHistorySchemaForGraph(candidate.schemaVersion),
            candidate.runs,
        )
        renderCompatibilityProjection(candidate.nodes, candidate.budget.maximumProjectionBytes)
    }

    private fun requireCommitReadyState(candidate: RevisionGraphState): PreparedRevisionGraphState =
        prepareStateForPersistence(candidate).also { prepared ->
            requireProjectableState(prepared.state)
        }

    @Synchronized
    override fun close() {
        if (lifecycle == Lifecycle.CLOSED) return
        if (operationDepth > 0 && operationThread === Thread.currentThread()) {
            error("revision graph cannot be closed reentrantly during an active operation")
        }
        check(operationDepth == 0) { "revision graph still has an active operation" }
        lifecycle = Lifecycle.CLOSING
        try {
            runCatching { LinuxFilesystemSyscalls.unlock(lockDescriptor) }
            lockDescriptor.close()
            stateStore.close()
        } finally {
            try {
                rootDescriptor.close()
            } finally {
                // Mark the old object closed before releasing JVM-local ownership. A newly
                // admitted graph can never overlap an object that still reports itself as open.
                lifecycle = Lifecycle.CLOSED
                rootCoordination.close()
            }
        }
    }

    private fun loadOrInitialize(): RevisionGraphState {
        if (stateStore.graphExists()) {
            return readBoundedRevisionGraph(stateStore, index.budget).second
        }
        val snapshot = index.sourceSnapshot()
        val blobReservation = reserveBlobPublications(snapshot.map { it.sha256 })
        val rootChanges = snapshot.map { source ->
            val observed = readStableRegularFile(projectRoot, source.path, index.budget.maximumSourceFileBytes)
            require(observed.sha256 == source.sha256 && observed.bytes.size.toLong() == source.bytes) {
                "repair root source changed while its content blob was captured: ${source.path}"
            }
            val blob = storeBlob(observed.bytes, blobReservation)
            RevisionFileDelta(source.path, null, null, source.sha256, null, blob, source.bytes)
        }
        val verifiedSnapshot = index.sourceSnapshot()
        require(revisionSha256(verifiedSnapshot) == revisionSha256(snapshot)) {
            "repair root source tree changed while its content blobs were captured"
        }
        val sourceRevision = revisionSha256(snapshot)
        val rootId = "root_${sha256((index.indexSha256 + "\n" + sourceRevision).toByteArray()).take(24)}"
        val node = ModuleRevisionNode(
            rootId,
            null,
            0,
            ModuleRevisionStatus.ROOT,
            sourceRevision,
            rootChanges,
            emptyList(),
            emptyList(),
            "initial-source",
            "source_tree_manifest.json".takeIf { stateStore.rootFileExists(it) },
            false,
            "imported source tree; no full repair validation is implied",
        )
        val initial = RevisionGraphState(
            index.budget,
            index.profileId,
            index.profileSha256,
            index.editablePaths.sorted(),
            index.indexSha256,
            emptyList(),
            regressionCorpusSha256(emptyList()),
            rootId,
            1,
            listOf(node),
            null,
            referencedBlobBytes(listOf(node), null),
            schemaVersion = 6,
        )
        requireProjectableState(initial)
        val payload = renderGraph(initial).toByteArray(Charsets.UTF_8)
        if (payload.size.toLong() > index.budget.maximumGraphBytes) {
            throw RepairBudgetExceededException("initial repair graph exceeds ${index.budget.maximumGraphBytes} bytes")
        }
        stateStore.writeGraph(payload)
        return initial
    }

    private fun validateLoadedState(verifyBlobContents: Boolean = true) {
        require(state.schemaVersion in 1..7) { "unsupported repair revision graph schema" }
        require(state.budget == index.budget) { "revision graph resource budget differs from the requested budget" }
        require(state.profileId == index.profileId && state.profileSha256 == index.profileSha256) {
            "revision graph repair index profile does not match current project evidence"
        }
        require(state.editablePaths == index.editablePaths.sorted()) {
            "revision graph editable paths do not match the repair index profile"
        }
        require(state.indexSha256 == index.indexSha256) { "revision graph dependency index does not match current project evidence" }
        validateRegressionCorpus(state.retainedRegressionInputs, state.budget)
        require(state.regressionCorpusSha256 == regressionCorpusSha256(state.retainedRegressionInputs)) {
            "revision graph retained regression corpus digest does not match its inputs"
        }
        require(state.nodes.isNotEmpty() && state.nodes.first().status == ModuleRevisionStatus.ROOT)
        require(state.nodes.map { it.id }.distinct().size == state.nodes.size) { "revision graph node IDs are not unique" }
        require(state.nodes.size <= state.budget.maximumRevisionNodes) { "revision graph exceeds its node budget" }
        val referencedBlobCount = referencedBlobDigests(state.nodes, state.pending).size
        if (referencedBlobCount > state.budget.maximumStateDirectoryEntries) {
            throw RepairBudgetExceededException(
                "repair graph references $referencedBlobCount blobs; " +
                    "state directory entry limit=${state.budget.maximumStateDirectoryEntries}",
            )
        }
        val ids = hashSetOf<String>()
        var previousOrdinal = -1
        var previousRepairIteration = 0
        var derivedHeadId: String? = null
        var acceptedSources = sortedMapOf<String, IndexedSource>()
        state.nodes.forEachIndexed { indexInGraph, node ->
            require(node.id.matches(Regex("(?:root|revision)_[A-Za-z0-9_]+"))) { "revision graph node ID is invalid" }
            require(node.sourceRevisionSha256.matches(Regex("[0-9a-f]{64}"))) { "revision graph source digest is invalid" }
            require(node.ordinal == previousOrdinal + 1) { "revision graph ordinals are not contiguous" }
            previousOrdinal = node.ordinal
            if (indexInGraph == 0) {
                require(node.parentId == null && node.ordinal == 0 && node.status == ModuleRevisionStatus.ROOT)
                require(node.changedModules.isEmpty() && node.invalidatedModules.isEmpty()) {
                    "revision graph root cannot record module invalidations"
                }
                derivedHeadId = node.id
            } else {
                require(node.parentId in ids && node.status != ModuleRevisionStatus.ROOT &&
                    revisionCanonicalBase(state.nodes.take(indexInGraph), requireNotNull(node.parentId)) == derivedHeadId) {
                    "revision graph node is not attached to the accepted head: ${node.id}"
                }
                require(state.schemaVersion >= 3 || node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.REJECTED))
                if (node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.LEGACY_UNVERIFIED)) derivedHeadId = node.id
                val changedPaths = node.changes.map { it.path }
                require(node.changedModules == index.changedModules(changedPaths)) {
                    "revision graph changed-module projection does not match the dependency index: ${node.id}"
                }
                require(node.invalidatedModules == index.downstreamInvalidations(changedPaths)) {
                    "revision graph downstream invalidation does not match the dependency index: ${node.id}"
                }
            }
            require(node.changes.map { it.path } == node.changes.map { it.path }.distinct().sorted()) {
                "revision graph node changes are not unique and sorted: ${node.id}"
            }
            require(node.publicationChanges.map { it.path } ==
                node.publicationChanges.map { it.path }.distinct().sorted()) {
                "revision graph physical publication changes are not unique and sorted: ${node.id}"
            }
            if (state.schemaVersion >= 5) {
                require(node.publicationPreimageMetadata.keys.sorted() == node.publicationChanges.map { it.path }.sorted()) {
                    "schema-5 physical preimage metadata does not exactly cover publication changes: ${node.id}"
                }
                node.publicationChanges.forEach { change ->
                    val metadata = node.publicationPreimageMetadata.getValue(change.path)
                    require(metadata.size == change.beforeBytes &&
                        metadata.retainedName == sourceTransactionPreimageName(change.path, node.id)) {
                        "schema-5 physical preimage metadata is not bound to its publication: ${node.id}:${change.path}"
                    }
                }
            }
            require((node.evidenceKind == null) == (node.evidenceSummary == null)) {
                "revision graph evidence kind and summary must both be present or absent: ${node.id}"
            }
            validateEvidence(node.evidenceKind?.let { RepairEvidence(it, node.evidenceSummary.orEmpty(), node.evidenceArtifact) })
            validateRepairMetadata(node.repairMetadata)
            node.repairMetadata?.let { metadata ->
                if (state.schemaVersion == 1) {
                    require(metadata.agentInvocation == null) {
                        "legacy repair graph contains schema-v2 ACP invocation evidence"
                    }
                } else {
                    val expectedAssessment = when (node.status) {
                        ModuleRevisionStatus.ACCEPTED -> RepairAgentAssessmentStatus.ACCEPTED
                        ModuleRevisionStatus.LEGACY_UNVERIFIED -> RepairAgentAssessmentStatus.ACCEPTED
                        ModuleRevisionStatus.PROVISIONAL -> RepairAgentAssessmentStatus.PROVISIONAL
                        ModuleRevisionStatus.REJECTED -> RepairAgentAssessmentStatus.REJECTED
                        ModuleRevisionStatus.ROOT -> error("repair graph root cannot contain iteration metadata")
                    }
                    requireRecordedAcceptedInvocation(node.status, metadata, node.id)
                if (state.schemaVersion >= 7) metadata.turnIntent?.let { binding ->
                    validateTurnIntentBinding(binding, node.id, null)
                }
                    metadata.agentInvocation?.let { invocation ->
                        validateAgentInvocationBinding(
                            invocation,
                            node.id,
                            metadata.turnIntent,
                            metadata.prompt,
                            expectedAssessment,
                            verifyBlobContents,
                        )
                        if (node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.PROVISIONAL)) {
                            requireRecordedFinalizedChanges(invocation, node.changes, node.id)
                        }
                    }
                }
            }
            node.repairMetadata?.let { metadata ->
                require(metadata.iterationIndex == previousRepairIteration + 1) {
                    "repair graph iteration indexes are not contiguous"
                }
                previousRepairIteration = metadata.iterationIndex
            }
            node.changes.forEach { validateDelta(it) }
            node.publicationChanges.forEach { validateDelta(it) }
            if (indexInGraph == 0) {
                require(node.changes.map { it.path } == index.sourcePaths) {
                    "revision graph root does not cover the exact indexed source set"
                }
                require(node.changes.all { it.beforeSha256 == null }) {
                    "revision graph root contains a preimage"
                }
                require(node.repairMetadata == null && !node.recoveredAfterCrash) {
                    "revision graph root cannot contain repair-attempt metadata"
                }
                acceptedSources = node.changes.associateTo(sortedMapOf()) { change ->
                    change.path to IndexedSource(change.path, change.afterBytes, change.afterSha256)
                }
                require(node.sourceRevisionSha256 == revisionSha256(acceptedSources.values)) {
                    "revision graph root source digest does not match its deltas"
                }
            } else {
                val parentSources = revisionSourcesAt(state.nodes.take(indexInGraph), requireNotNull(node.parentId))
                val candidateSources = parentSources.toMutableMap()
                node.changes.forEach { change ->
                    val before = parentSources.getValue(change.path)
                    require(change.beforeSha256 == before.sha256 && change.beforeBytes == before.bytes) {
                        "revision graph delta is not bound to its accepted parent: ${node.id}:${change.path}"
                    }
                    candidateSources[change.path] = IndexedSource(change.path, change.afterBytes, change.afterSha256)
                }
                require(node.sourceRevisionSha256 == revisionSha256(candidateSources.values)) {
                    "revision graph node source digest does not match its deltas: ${node.id}"
                }
                if (node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.LEGACY_UNVERIFIED)) {
                    require(node.changes.isNotEmpty()) { "accepted repair node has no source changes: ${node.id}" }
                    acceptedSources = candidateSources.toSortedMap()
                }
            }
            node.rollbackRecord?.let { record ->
                require(state.schemaVersion >= 4 && node.status == ModuleRevisionStatus.REJECTED) {
                    "rollback outcome is attached to a non-rejected or legacy revision: ${node.id}"
                }
                require(record.attemptId == node.id && record.runId == node.repairMetadata?.runId)
                require(record.state in setOf(
                    RepairRollbackState.RESTORED_VERIFIED,
                    RepairRollbackState.RESTORED_AFTER_FAILURE,
                    RepairRollbackState.NOT_REQUIRED_VERIFIED,
                )) { "finalized rollback has a non-final outcome: ${node.id}" }
                require(record.targetRevisionId == derivedHeadId) {
                    "rollback target differs from the published head: ${node.id}"
                }
                val targetSources = revisionSourcesAt(state.nodes.take(indexInGraph), record.targetRevisionId)
                require(record.expectedSourceRevisionSha256 == revisionSha256(targetSources.values)) {
                    "rollback expected digest differs from its target revision: ${node.id}"
                }
                requireLegacyRollbackInstallMarker(record, node.changes.isNotEmpty())
                if (record.state == RepairRollbackState.NOT_REQUIRED_VERIFIED) {
                    require(record.failureCode == null && record.candidateSourceInstallStarted == false)
                }
            }
            ids += node.id
        }
        require(state.headId in ids) { "revision graph head does not exist" }
        require(state.headId == derivedHeadId) { "revision graph head is not derived from its ordered nodes" }
        require(state.nodes.single { it.id == state.headId }.status != ModuleRevisionStatus.REJECTED) {
            "revision graph head cannot be rejected"
        }
        require(state.nextOrdinal > previousOrdinal) { "revision graph next ordinal is not ahead of completed nodes" }
        state.pending?.let { pending ->
            if (state.schemaVersion >= 5) {
                require(pending.preimageMetadata != null) {
                    "schema-5 pending repair is missing its preimage metadata commitment"
                }
                if (pending.detached) {
                    if (state.schemaVersion < 6) require(pending.preimageMetadata.isEmpty()) {
                        "legacy detached repair cannot invent a physical metadata commitment"
                    } else {
                        val published = sourcesAt(revisionCanonicalBase(state.nodes, state.headId))
                        val working = sourcesAt(pending.parentId)
                        val provisionalDeltaPaths = (published.keys + working.keys).filter { path ->
                            published[path]?.let { before -> working[path]?.let { after ->
                                before.sha256 == after.sha256 && before.bytes == after.bytes
                            } } != true
                        }
                        val expectedWitnessPaths = (pending.allowedPaths + provisionalDeltaPaths).distinct().sorted()
                        require(pending.preimageMetadata.keys.sorted() == expectedWitnessPaths) {
                            "schema-6 attempt witness does not cover allowed paths and provisional promotion paths"
                        }
                        pending.preimageMetadata.forEach { (path, metadata) ->
                            require(metadata.size == published.getValue(path).bytes)
                        }
                        require(pending.sourceWitnessSha256?.matches(REPAIR_BLOB_DIGEST) == true) {
                            "schema-6 attempt is missing its complete accepted-source witness commitment"
                        }
                    }
                } else {
                    validatePendingPreimageAggregate(pending.allowedPaths, pending.preimages, state.budget,
                        pending.preimageMetadata)
                }
                if (pending.promotionChanges.isNotEmpty()) require(
                    pending.promotionPreimageMetadata?.keys?.sorted() == pending.promotionChanges.map { it.path }.sorted(),
                ) { "schema-5 promotion is missing its physical preimage metadata commitment" }
                pending.promotionChanges.forEach { change ->
                    require(pending.promotionPreimageMetadata?.get(change.path)?.size == change.beforeBytes) {
                        "schema-5 promotion preimage metadata size differs from its content commitment: ${change.path}"
                    }
                    if (state.schemaVersion >= 6) require(
                        pending.promotionPreimageMetadata?.get(change.path) == pending.preimageMetadata?.get(change.path),
                    ) { "schema-6 promotion metadata differs from the attempt-time witness: ${change.path}" }
                }
            }
            require(pending.id.matches(Regex("revision_[A-Za-z0-9_]+"))) { "pending repair attempt ID is invalid" }
            if (state.schemaVersion >= 6) {
                if (pending.acceptanceDecision != null) {
                    require(pending.predecisionStageFiles.isEmpty()) {
                        "schema-6 committed decision retains a predecision-only stage manifest"
                    }
                } else {
                    val predecision = pending.predecisionStageFiles
                    require(predecision.map { it.path } == pending.promotionChanges.take(predecision.size).map { it.path }) {
                        "schema-6 predecision stage manifest is not a sorted publication prefix"
                    }
                    predecision.zip(pending.promotionChanges).forEach { (staged, change) ->
                        val sourceMetadata = requireNotNull(pending.promotionPreimageMetadata?.get(change.path))
                        require(staged.path == change.path &&
                            staged.stagingName == sourceTransactionPreimageName(change.path, pending.id) &&
                            staged.sha256 == change.afterSha256 && staged.size == change.afterBytes &&
                            staged.mode == sourceMetadata.mode && staged.uid == sourceMetadata.uid &&
                            staged.gid == sourceMetadata.gid) {
                            "schema-6 predecision stage is not bound to its candidate and source metadata: ${change.path}"
                        }
                    }
                }
            } else require(pending.predecisionStageFiles.isEmpty()) {
                "legacy repair record contains schema-6 staging metadata"
            }
            pending.acceptanceDecision?.let { decision ->
                require(state.schemaVersion >= 6 && pending.detached) {
                    "acceptance decision is only valid for a schema-6 detached candidate"
                }
                require(decision.intendedHeadId == pending.id)
                require(decision.promotionChanges == pending.promotionChanges) {
                    "schema-6 acceptance decision differs from its exact promotion changes"
                }
                require(pending.repairMetadata?.runId == null || decision.intendedRunId == pending.repairMetadata.runId) {
                    "schema-6 acceptance decision run transition differs from pending attempt"
                }
                require(decision.intendedRunStatus == RepairRunStatus.FULLY_ACCEPTED.takeIf { decision.intendedRunId != null })
                validateAcceptanceRunTransition(state, decision)
                require(decision.proof.sourceRevisionSha256 == pending.candidateSourceRevisionSha256 &&
                    decision.proof.profileSha256 == state.profileSha256 &&
                    decision.proof.indexSha256 == state.indexSha256 &&
                    decision.proof.regressionCorpusSha256 == state.regressionCorpusSha256) {
                    "schema-6 acceptance decision proof is not bound to the persisted candidate"
                }
                val committedNode = requireNotNull(decision.committedNode)
                require(committedNode.id == decision.intendedHeadId && committedNode.status == ModuleRevisionStatus.ACCEPTED &&
                    committedNode.publicationChanges == decision.promotionChanges &&
                    committedNode.publicationPreimageMetadata == pending.promotionPreimageMetadata.orEmpty()) {
                    "schema-6 decision does not retain the complete accepted node"
                }
                require(decision.stagedFiles.map { it.path } == decision.promotionChanges.map { it.path })
                decision.stagedFiles.zip(decision.promotionChanges).forEach { (staged, change) ->
                    val metadata = requireNotNull(pending.promotionPreimageMetadata?.get(change.path))
                    val parent = metadata.ancestorMetadata.lastOrNull()
                        ?: error("schema-6 source publication is missing its parent-directory witness")
                    require(staged.stagingName == metadata.retainedName && staged.sha256 == change.afterSha256 &&
                        staged.size == change.afterBytes && staged.parentDevice == parent.device &&
                        staged.parentInode == parent.inode && staged.parentMountId == parent.mountId &&
                        staged.device == staged.parentDevice && staged.mountId == staged.parentMountId &&
                        staged.mode == metadata.mode && staged.uid == metadata.uid && staged.gid == metadata.gid) {
                        "schema-6 staged publication is not bound to its source and directory witness: ${change.path}"
                    }
                }
            }
            pending.preimageMetadata.orEmpty().forEach { (path, metadata) ->
                require(metadata.retainedName == sourceTransactionPreimageName(path, pending.id)) {
                    "schema-5 preimage name is not bound to its path and transaction: $path"
                }
            }
            pending.promotionPreimageMetadata.orEmpty().forEach { (path, metadata) ->
                require(metadata.retainedName == sourceTransactionPreimageName(path, pending.id)) {
                    "schema-5 promotion preimage name is not bound to its path and transaction: $path"
                }
            }
            require(pending.parentId == workingHeadId() && pending.ordinal == state.nextOrdinal - 1) {
                "pending repair attempt is not attached to the current graph head"
            }
            require(pending.ordinal == previousOrdinal + 1) { "pending repair ordinal is not contiguous" }
            require(pending.parentSourceRevisionSha256.matches(Regex("[0-9a-f]{64}")))
            val parentSources = sourcesAt(pending.parentId)
            require(pending.parentSourceRevisionSha256 == revisionSha256(parentSources.values)) {
                "pending repair parent digest does not match the accepted head"
            }
            require(
                pending.candidateSourceRevisionSha256 == null ||
                    pending.candidateSourceRevisionSha256.matches(Regex("[0-9a-f]{64}")),
            )
            require(pending.allowedPaths == pending.allowedPaths.distinct().sorted() && pending.allowedPaths.isNotEmpty())
            require(pending.allowedPaths.all { it in index.editablePaths })
            require(pending.preimages.map { it.path } == pending.allowedPaths)
            pending.preimages.forEach { preimage ->
                validateDelta(preimage)
                val accepted = parentSources.getValue(preimage.path)
                require(preimage.beforeSha256 == accepted.sha256 && preimage.beforeBytes == accepted.bytes) {
                    "pending repair preimage is not bound to the accepted head: ${preimage.path}"
                }
            }
            validatePendingPreimageAggregate(pending.allowedPaths, pending.preimages, state.budget,
                pending.preimageMetadata?.takeUnless { pending.detached })
            require(pending.candidateChanges.map { it.path } == pending.candidateChanges.map { it.path }.distinct().sorted())
            require(pending.candidateChanges.all { it.path in pending.allowedPaths })
            val pendingCandidateSources = parentSources.toMutableMap()
            pending.candidateChanges.forEach { change ->
                validateDelta(change)
                val accepted = parentSources.getValue(change.path)
                require(change.beforeSha256 == accepted.sha256 && change.beforeBytes == accepted.bytes) {
                    "pending candidate is not bound to the accepted head: ${change.path}"
                }
                pendingCandidateSources[change.path] = IndexedSource(change.path, change.afterBytes, change.afterSha256)
            }
            if (pending.candidateSourceRevisionSha256 == null) {
                require(pending.candidateChanges.isEmpty()) { "pending repair has changes without a candidate digest" }
            } else {
                require(pending.candidateChanges.isNotEmpty()) { "pending repair has a candidate digest without changes" }
                require(pending.candidateSourceRevisionSha256 == revisionSha256(pendingCandidateSources.values)) {
                    "pending candidate digest does not match its deltas"
                }
            }
            validateRepairMetadata(pending.repairMetadata)
            pending.repairMetadata?.let { metadata ->
                if (state.schemaVersion == 1) {
                    require(metadata.agentInvocation == null) {
                        "legacy pending repair contains schema-v2 ACP invocation evidence"
                    }
                } else {
                    if (state.schemaVersion >= 7) metadata.turnIntent?.let { binding ->
                        validateTurnIntentBinding(binding, pending.id, pending.parentSourceRevisionSha256)
                    }
                    metadata.agentInvocation?.let { invocation ->
                        validateAgentInvocationBinding(
                            invocation,
                            pending.id,
                            metadata.turnIntent,
                            metadata.prompt,
                            RepairAgentAssessmentStatus.PENDING,
                            verifyBlobContents,
                        )
                        if (pending.candidateSourceRevisionSha256 != null) {
                            requireRecordedPendingChanges(invocation, pending.candidateChanges, pending.id)
                        }
                    }
                }
            }
            pending.repairMetadata?.let { metadata ->
                require(metadata.iterationIndex == previousRepairIteration + 1) {
                    "pending repair iteration index is not contiguous"
                }
            }
            pending.rollbackRecord?.let { record ->
                require(state.schemaVersion >= 4)
                val targetId = if (pending.detached) state.headId else pending.parentId
                val targetSources = sourcesAt(targetId)
                validatePendingRollbackRecord(record, pending, targetId, revisionSha256(targetSources.values))
            }
        }
        if (state.pending == null) {
            require(state.nextOrdinal == previousOrdinal + 1) { "revision graph next ordinal is not contiguous" }
        }
        validateRepairRunContract(state)
        val expectedReceipts = buildSet {
            state.nodes.mapNotNull { it.repairMetadata }.forEach { metadata ->
                metadata.turnIntent?.let { add(it.intentPath.substringAfterLast('/')) }
                metadata.agentInvocation?.let { binding ->
                    add(binding.receiptPath.substringAfterLast('/'))
                    binding.assessmentPath?.let { add(it.substringAfterLast('/')) }
                }
            }
            state.pending?.let { pending ->
                val metadata = pending.repairMetadata
                metadata?.turnIntent?.let { add(it.intentPath.substringAfterLast('/')) }
                metadata?.agentInvocation?.let { binding ->
                    add(binding.receiptPath.substringAfterLast('/'))
                    binding.assessmentPath?.let { add(it.substringAfterLast('/')) }
                }
                listOf("${pending.id}.acp-intent.json", "${pending.id}.acp-receipt.json", "${pending.id}.acp-assessment.json")
                    .filter(stateStore::revisionFileExists).forEach(::add)
            }
        }.sorted()
        // Invocation artifacts live beside the graph rather than in the content-blob directory.
        // Bound that traversal by the maximum number of attempts plus the small fixed set of
        // graph/binding/temporary entries; a deliberately tiny blob-entry budget must not make a
        // valid graph impossible to reopen.
        val receiptDirectoryLimit = repairRevisionDirectoryEntryLimit(state.budget)
        val observedReceipts = stateStore.receiptFileNames(receiptDirectoryLimit)
        require(observedReceipts == expectedReceipts) {
            "repair revision state contains missing, extra, or stale ACP invocation receipts"
        }
        val bytes = referencedBlobBytes(state.nodes, state.pending, verifyContents = verifyBlobContents)
        require(bytes == state.storedBlobBytes) { "revision graph stored-blob accounting does not match its content" }
        require(bytes <= state.budget.maximumStoredBlobBytes) { "revision graph exceeds stored blob budget" }
    }

    private fun validateRepairMetadata(metadata: RevisionRepairMetadata?) {
        metadata ?: return
        require(metadata.iterationIndex in 1..state.budget.maximumRevisionNodes)
        require(metadata.prompt.toByteArray(Charsets.UTF_8).size.toLong() <= state.budget.maximumRequestBytes)
        require(metadata.summary == null || metadata.summary.toByteArray(Charsets.UTF_8).size.toLong() <= state.budget.maximumRequestBytes)
        require(metadata.failureKind.toByteArray(Charsets.UTF_8).size.toLong() <= state.budget.maximumRequestBytes)
        require(metadata.retainedRegressionIds == metadata.retainedRegressionIds.distinct().sorted())
        val retained = metadata.retainedRegressionIds.map { id ->
            state.retainedRegressionInputs.singleOrNull { it.id == id }
                ?: error("repair metadata references an unknown retained regression input: $id")
        }
        require(metadata.regressionCorpusSha256 == regressionCorpusSha256(retained)) {
            "repair metadata retained regression digest does not match its input IDs"
        }
        validateEvidence(metadata.before)
        if (metadata.publicationMode == RepairPublicationMode.TEST_ONLY_NON_RELEASE) {
            require(metadata.agentInvocation == null ||
                metadata.agentInvocation.assessmentStatus != RepairAgentAssessmentStatus.ACCEPTED ||
                metadata.agentInvocation.receiptReleaseComplete
            ) { "test-only repair cannot mark incomplete ACP evidence accepted" }
        }
    }

    private fun validateAgentInvocationBinding(
        binding: RepairAgentInvocationBinding,
        attemptId: String,
        intentBinding: RepairAgentTurnIntentBinding?,
        expectedPromptSha256: String,
        expectedAssessment: RepairAgentAssessmentStatus,
        verifyReceiptContents: Boolean,
    ) {
        val expectedName = validateRecordedInvocationBinding(state.schemaVersion, binding, attemptId, expectedAssessment)
        if (verifyReceiptContents) {
            val receipt = stateStore.readRevisionFile(expectedName, MAXIMUM_REPAIR_ACP_RECEIPT_BYTES)
            require(receipt.sha256 == binding.receiptSha256) {
                "repair ACP receipt digest differs from graph binding: $attemptId"
            }
            val verified = verifyAcpExecutionReceiptDocument(
                receipt.bytes,
                TRACE_REPAIR_ACP_RECEIPT_KIND,
                TRACE_REPAIR_ACP_TASK_FIELD,
                attemptId,
            )
            require(verified.requestSha256 == binding.requestSha256 &&
                verified.schemaVersion == binding.receiptSchemaVersion &&
                verified.promptSha256 == expectedPromptSha256 &&
                verified.resultChangesSha256 == binding.resultChangesSha256 &&
                verified.terminalOutcome == binding.terminalOutcome &&
                verified.releaseComplete == binding.receiptReleaseComplete
            ) { "repair ACP receipt content is cross-paired with its graph binding: $attemptId" }
            if (state.schemaVersion >= 7 && binding.intentPath != null) {
                val intentPath = requireNotNull(binding.intentPath) { "schema-7 invocation lacks its turn intent reference" }
                val intentSha = requireNotNull(binding.intentSha256) { "schema-7 invocation lacks its turn intent digest" }
                require(intentPath == "reports/repair-revisions/$attemptId.acp-intent.json") {
                    "repair turn intent path is cross-paired with attempt: $attemptId"
                }
                val metadataIntent = requireNotNull(intentBinding)
                require(metadataIntent.intentPath == intentPath && metadataIntent.intentSha256 == intentSha &&
                    metadataIntent.turnId == binding.turnId) { "repair invocation and graph intent binding disagree: $attemptId" }
                val intent = validateTurnIntentBinding(metadataIntent, attemptId, null)
                require(intent.turnId == binding.turnId &&
                    intent.taskId == attemptId && intent.requestSha256 == verified.requestSha256 &&
                    verified.schemaVersion == 3 &&
                    verified.turnIdentity?.turnId == intent.turnId &&
                    verified.turnIdentity.taskId == intent.taskId &&
                    verified.turnIdentity.requestSha256 == intent.requestSha256) {
                    "repair turn intent is cross-paired with invocation receipt: $attemptId"
                }
                val assessmentPath = binding.assessmentPath
                val assessmentSha = binding.assessmentSha256
                if (assessmentPath != null || assessmentSha != null) {
                    require(assessmentPath == "reports/repair-revisions/$attemptId.acp-assessment.json" && assessmentSha != null) {
                        "repair assessment path is cross-paired with attempt: $attemptId"
                    }
                    val assessmentFile = stateStore.readRevisionFile("$attemptId.acp-assessment.json", MAXIMUM_REPAIR_ASSESSMENT_BYTES.toLong())
                    require(assessmentFile.sha256 == assessmentSha) {
                        "repair assessment digest differs from graph binding: $attemptId"
                    }
                    val assessment = AcpChangeAssessment.parse(assessmentFile.bytes)
                    require(assessment.turnId == intent.turnId && assessment.intentSha256 == intentSha &&
                        assessment.receiptSha256 == binding.receiptSha256 &&
                        assessment.changesSha256 == binding.resultChangesSha256 &&
                        intent.policySha256 == verified.accessPolicySha256 &&
                        assessment.policySha256 == verified.accessPolicySha256 &&
                        assessment.updatesSha256 == verified.updatesSha256 &&
                        assessment.sessionIdSha256 == verified.sessionIdCommitmentSha256?.let {
                            sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
                        } &&
                        assessment.normalizedStopReason == verified.terminalOutcome
                            .takeIf { it.startsWith("returned-") }
                            ?.removePrefix("returned-")
                            ?.let { decompengine.agent.AgentStopReason.valueOf(it.uppercase().replace('-', '_')) }) {
                        "repair assessment is cross-paired with intent or receipt: $attemptId"
                    }
                    if (expectedAssessment == RepairAgentAssessmentStatus.ACCEPTED) require(
                        assessment.eligibility == decompengine.project.AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION,
                    ) { "accepted repair lacks validated-for-publication assessment: $attemptId" }
                    if (expectedAssessment == RepairAgentAssessmentStatus.PROVISIONAL) require(
                        assessment.eligibility == decompengine.project.AcpChangePublicationEligibility.PROVISIONAL,
                    ) { "provisional repair has inconsistent assessment: $attemptId" }
                    if (expectedAssessment == RepairAgentAssessmentStatus.REJECTED) require(
                        assessment.eligibility in setOf(
                            decompengine.project.AcpChangePublicationEligibility.REJECTED,
                            decompengine.project.AcpChangePublicationEligibility.INTERRUPTED,
                        ) || state.nodes.singleOrNull { it.id == attemptId }?.let { rejectedNode ->
                            rejectedNode.rollbackRecord?.state in setOf(
                                RepairRollbackState.RESTORED_AFTER_FAILURE,
                                RepairRollbackState.RESTORED_VERIFIED,
                                RepairRollbackState.NOT_REQUIRED_VERIFIED,
                            ) &&
                                rejectedNode.rollbackRecord?.candidateSourceInstallStarted == false &&
                                assessment.eligibility in setOf(
                                    decompengine.project.AcpChangePublicationEligibility.PROVISIONAL,
                                    decompengine.project.AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION,
                                )
                        } == true,
                    ) { "rejected repair has inconsistent assessment: $attemptId" }
                    if (expectedAssessment in setOf(RepairAgentAssessmentStatus.ACCEPTED, RepairAgentAssessmentStatus.PROVISIONAL)) {
                        val expectedProof = state.nodes.singleOrNull { it.id == attemptId }?.validationProof
                            ?: state.pending?.takeIf { it.id == attemptId }?.acceptanceDecision?.proof
                            ?: error("finalized repair assessment has no independently persisted validation proof: $attemptId")
                        require(assessment.afterSha256 == expectedProof.sourceRevisionSha256 &&
                            assessment.validationProofSha256 == listOf(expectedProof.evidenceSha256) &&
                            assessment.validationStatus == decompengine.project.AcpChangeValidationStatus.PASSED) {
                            "repair assessment validation outcome differs from graph proof: $attemptId"
                        }
                    }
                } else if (expectedAssessment == RepairAgentAssessmentStatus.ACCEPTED) {
                    error("accepted schema-7 repair is missing its durable assessment: $attemptId")
                } else if (expectedAssessment == RepairAgentAssessmentStatus.PROVISIONAL) {
                    error("provisional schema-7 repair is missing its durable assessment: $attemptId")
                }
            } else if (state.schemaVersion >= 7) {
                require(intentBinding == null && binding.intentSha256 == null && binding.turnId == null &&
                    binding.assessmentPath == null && binding.assessmentSha256 == null) {
                    "legacy schema-6 repair invocation has partial schema-7 provenance: $attemptId"
                }
            }
        }
    }

    private fun validateTurnIntentBinding(
        binding: RepairAgentTurnIntentBinding,
        attemptId: String,
        expectedBeforeSha256: String?,
    ): AgentTurnIntent {
        val expectedPath = "reports/repair-revisions/$attemptId.acp-intent.json"
        require(binding.intentPath == expectedPath) { "repair turn intent path is cross-paired: $attemptId" }
        val file = stateStore.readRevisionFile("$attemptId.acp-intent.json", MAXIMUM_REPAIR_INTENT_BYTES.toLong())
        require(file.sha256 == binding.intentSha256) { "repair turn intent digest differs from graph binding: $attemptId" }
        val intent = AgentTurnIntent.parse(file.bytes)
        require(intent.turnId == binding.turnId && intent.attemptId == attemptId &&
            intent.profileSha256 == state.profileSha256 &&
            (expectedBeforeSha256 == null || intent.beforeSha256 == expectedBeforeSha256)) {
            "repair turn intent content is cross-paired with graph state: $attemptId"
        }
        return intent
    }

    /** A crash may occur after the immutable intent write but before its graph exchange. */
    private fun bindPendingOrphanTurnIntentForRecovery() = graphOperation {
        val pending = state.pending ?: return@graphOperation
        val metadata = pending.repairMetadata ?: return@graphOperation
        if (metadata.turnIntent != null) return@graphOperation
        val name = "${pending.id}.acp-intent.json"
        if (!stateStore.revisionFileExists(name)) return@graphOperation
        val file = stateStore.readRevisionFile(name, MAXIMUM_REPAIR_INTENT_BYTES.toLong())
        val intent = AgentTurnIntent.parse(file.bytes)
        require(intent.taskId == pending.id && intent.attemptId == pending.id &&
            intent.profileSha256 == state.profileSha256 &&
            intent.beforeSha256 == pending.parentSourceRevisionSha256) {
            "orphaned repair turn intent does not match its pending attempt"
        }
        val binding = RepairAgentTurnIntentBinding(
            "reports/repair-revisions/$name",
            file.sha256,
            intent.turnId,
        )
        val updated = state.copy(
            schemaVersion = 7,
            pending = pending.copy(repairMetadata = metadata.copy(turnIntent = binding)),
        )
        requireRecoverablePendingState(updated)
        persist(updated)
    }

    private fun validateEvidence(evidence: RepairEvidence?) {
        evidence ?: return
        listOf(evidence.kind, evidence.summary, evidence.artifactPath).filterNotNull().forEach { value ->
            require(value.toByteArray(Charsets.UTF_8).size.toLong() <= state.budget.maximumRequestBytes) {
                "repair evidence field exceeds the request-byte budget"
            }
        }
    }

    private fun validateDelta(delta: RevisionFileDelta) {
        require(delta.path in index.sourcePaths) { "revision graph references an unknown source path: ${delta.path}" }
        require(delta.beforeSha256 == null || delta.beforeSha256.matches(Regex("[0-9a-f]{64}")))
        require(delta.afterSha256.matches(Regex("[0-9a-f]{64}")))
        require(delta.beforeBlobSha256 == null || delta.beforeBlobSha256.matches(Regex("[0-9a-f]{64}")))
        require(delta.afterBlobSha256.matches(Regex("[0-9a-f]{64}")))
        require(delta.beforeBytes == null || delta.beforeBytes in 0..state.budget.maximumSourceFileBytes)
        require(delta.afterBytes in 0..state.budget.maximumSourceFileBytes)
        require((delta.beforeSha256 == null) == (delta.beforeBytes == null)) {
            "repair delta before hash and byte count must both be present or absent"
        }
        require((delta.beforeSha256 == null) == (delta.beforeBlobSha256 == null)) {
            "repair delta before hash and blob must both be present or absent"
        }
        require(delta.beforeBlobSha256 == delta.beforeSha256) { "repair preimage blob digest does not match its content digest" }
        require(delta.afterBlobSha256 == delta.afterSha256) { "repair candidate blob digest does not match its content digest" }
    }

    private fun recoverPendingAttempt() {
        val pending = state.pending ?: return
        if (pending.acceptanceDecision != null) {
            throw RepairAcceptancePendingException(
                "repair acceptance decision is durable; graph is unavailable until roll-forward publication recovery completes",
            )
        }
        val recoverablePending = recoverPersistedInvocationBinding(
            pending, state.schemaVersion, stateStore, state.profileSha256,
        )
        if (recoverablePending != pending) persist(state.copy(
            schemaVersion = if (recoverablePending.repairMetadata?.turnIntent != null) 7 else state.schemaVersion,
            pending = recoverablePending,
        ))
        val rollbackRecord = rollbackPending(recoverablePending)
        val restoredPending = requireNotNull(state.pending)
        val node = finalizeNode(
            restoredPending,
            ModuleRevisionStatus.REJECTED,
            RESTART_RECOVERY_EVIDENCE,
            recovered = true,
            rollbackRecord = rollbackRecord,
        )
        val recoveredState = withFinalizedRollback(state.copy(nodes = state.nodes + node, pending = null), rollbackRecord)
        persist(requireCommitReadyState(recoveredState))
    }

    private fun recoverPersistedInvocationBinding(pending: PendingAttempt): PendingAttempt =
        recoverPersistedInvocationBinding(pending, state.schemaVersion, stateStore, state.profileSha256)

    private fun finalizeNode(
        pending: PendingAttempt,
        status: ModuleRevisionStatus,
        evidence: RepairEvidence?,
        recovered: Boolean,
        rollbackRecord: RepairRollbackRecord? = null,
    ): ModuleRevisionNode {
        require(state.nodes.size < state.budget.maximumRevisionNodes) { "revision graph reached its node budget" }
        val paths = pending.candidateChanges.map { it.path }
        return finalizedRepairNode(pending, status, evidence, recovered, rollbackRecord,
            { index.changedModules(paths) }, { index.downstreamInvalidations(paths) },
            ::portableEvidenceText, ::portableEvidencePath)
    }

    private fun requireRecoverablePendingState(candidate: RevisionGraphState) {
        val pending = requireNotNull(candidate.pending) { "recoverability check requires a pending repair" }
        if (candidate.schemaVersion < 4) {
            val node = finalizeNode(pending, ModuleRevisionStatus.REJECTED, RESTART_RECOVERY_EVIDENCE,
                recovered = true, rollbackRecord = null)
            requireCommitReadyState(candidate.copy(nodes = candidate.nodes + node, pending = null))
            return
        }
        val paths = pending.candidateChanges.map { it.path }
        forEachRecoveryPublicationCandidate(candidate, { index.changedModules(paths) }, { index.downstreamInvalidations(paths) }) { _, next ->
            requireCommitReadyState(next)
        }
    }

    private fun rollbackPending(pending: PendingAttempt): RepairRollbackRecord {
        require(pending.acceptanceDecision == null) {
            "durable acceptance decision forbids rejection or rollback"
        }
        if (state.schemaVersion >= 6 && pending.detached) {
            verifySchema6PendingWitness(projectRoot, state, pending, state.budget)
            discardUndecidedPublicationStages(stateStore, deriveSchema6PromotionChanges(state, pending), pending.id,
                pending.predecisionStageFiles)
        }
        upgradeGraphToRollbackContract(allowPending = true)
        val activePending = requireNotNull(state.pending)
        require(activePending.id == pending.id) { "rollback attempt does not match pending graph state" }
        require(activePending.acceptanceDecision == null) {
            "durable acceptance decision forbids rejection or rollback"
        }
        val priorRecord = activePending.rollbackRecord ?: initialRollbackRecord(
            state,
            activePending,
            activePending.legacyRecoveryRequired,
        )
        // A historical failure stays durable during a retry; a new IN_PROGRESS would erase its witness.
        val inProgress = if (priorRecord.failureCode != null) priorRecord
            else priorRecord.copy(state = RepairRollbackState.RESTORE_IN_PROGRESS)
        persist(state.copy(pending = activePending.copy(rollbackRecord = inProgress)))
        val markedPending = requireNotNull(state.pending)
        var stage = RepairRollbackStage.SOURCE_RESTORE
        try {
            if (markedPending.detached) restoreDetachedPromotion(markedPending)
            else restorePreimages(markedPending)
            stage = RepairRollbackStage.SOURCE_VERIFICATION
            val observed = revisionSha256(index.sourceSnapshot())
            if (observed != inProgress.expectedSourceRevisionSha256) {
                throw RepairRollbackException(
                    stage,
                    RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
                    "restored source tree does not match its authorized rollback target",
                )
            }
            return rollbackOutcomeRecord(inProgress, observed)
        } catch (failure: Exception) {
            val rollbackFailure = failure as? RepairRollbackException
            val observed = currentSourceRevisionOrNull()
            val failedRecord = inProgress.copy(
                state = RepairRollbackState.RESTORE_FAILED_UNRESOLVED,
                failureStage = rollbackFailure?.rollbackStage ?: stage,
                failureCode = rollbackFailure?.failureCode ?: RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
                observedSourceRevisionSha256 = observed,
            )
            try {
                persist(withCommittedRollbackFailure(state, failedRecord))
            } catch (publicationFailure: Exception) {
                failure.addSuppressed(publicationFailure)
            }
            throw failure
        }
    }

    private fun currentSourceRevisionOrNull(): String? = try {
        revisionSha256(index.sourceSnapshot())
    } catch (_: Exception) {
        null
    }

    private fun restorePreimages(pending: PendingAttempt) {
        if (pending.detached) return restoreDetachedPromotion(pending)
        val parents = pending.preimages.associateBy { it.path }
        val replacements = TreeMap<String, ByteArray>()
        val expectedCurrent = TreeMap<String, String>()
        pending.candidateChanges.forEach { candidate ->
            val parent = parents.getValue(candidate.path)
            val observed = readStableRegularFile(
                projectRoot,
                candidate.path,
                state.budget.maximumSourceFileBytes,
            )
            when (observed.sha256) {
                parent.beforeSha256 -> {
                    // A crash can happen after a content-only rollback exchange but before the
                    // retained inode is swapped back into the canonical name. If the durable
                    // transaction link exists, repeat restoration through that inode even though
                    // the bytes already match.
                    val parts = normalizedRelative(candidate.path).split('/')
                    val retained = stateStore.revisionsPath.resolve(
                        sourceTransactionPreimageName(candidate.path, pending.id),
                    )
                    if (Files.exists(retained, LinkOption.NOFOLLOW_LINKS)) {
                        replacements[candidate.path] = readBlob(requireNotNull(parent.beforeBlobSha256))
                        expectedCurrent[candidate.path] = observed.sha256
                    }
                }
                candidate.afterSha256 -> {
                    replacements[candidate.path] = readBlob(requireNotNull(parent.beforeBlobSha256))
                    expectedCurrent[candidate.path] = candidate.afterSha256
                }
                else -> throw RepairRollbackException(
                    RepairRollbackStage.SOURCE_RESTORE,
                    RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE,
                    "refusing to overwrite an unrecognized source replacement during rollback: ${candidate.path}",
                )
            }
        }
        if (replacements.isNotEmpty()) {
        installFiles(
            replacements,
            expectedCurrent,
            transactionId = pending.id,
            phase = "rollback",
            rollbackCandidateSha256 = pending.candidateChanges.associate { it.path to it.afterSha256 },
            preimageMetadata = pending.preimageMetadata.orEmpty(),
        )
        }
        val restored = revisionSha256(index.sourceSnapshot())
        if (restored != pending.parentSourceRevisionSha256) throw RepairRollbackException(
            RepairRollbackStage.SOURCE_VERIFICATION,
            RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
            "could not restore the exact parent source revision",
        )
        pending.preimageMetadata?.forEach { (path, expected) ->
            requireRestoredPreimageMetadata(path, expected, "rollback")
        }
        cleanupRollbackPublicationResidue(pending.candidateChanges, pending.id, "rollback")
    }

    private fun restoreDetachedPromotion(pending: PendingAttempt) {
        if (pending.promotionChanges.isEmpty()) {
            verifyDetachedRollbackTarget()
            return
        }
        val replacements = TreeMap<String, ByteArray>()
        val expected = TreeMap<String, String>()
        pending.promotionChanges.forEach { change ->
            val observed = readStableRegularFile(projectRoot, change.path, state.budget.maximumSourceFileBytes)
            when (observed.sha256) {
                change.beforeSha256 -> Unit
                change.afterSha256 -> {
                    replacements[change.path] = readBlob(requireNotNull(change.beforeBlobSha256))
                    expected[change.path] = change.afterSha256
                }
                else -> throw RepairRollbackException(
                    RepairRollbackStage.SOURCE_RESTORE,
                    RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE,
                    "repair promotion source changed before rollback: ${change.path}",
                )
            }
        }
        if (replacements.isNotEmpty()) installFiles(replacements, expected, pending.id, "promotion-rollback",
            rollbackCandidateSha256 = pending.promotionChanges.associate { it.path to it.afterSha256 },
            preimageMetadata = pending.promotionPreimageMetadata.orEmpty())
        verifyDetachedRollbackTarget()
        pending.promotionPreimageMetadata?.forEach { (path, metadata) ->
            requireRestoredPreimageMetadata(path, metadata, "promotion rollback")
        }
        cleanupRollbackPublicationResidue(pending.promotionChanges, pending.id, "promotion-rollback")
    }

    /**
     * A prior rollback can have restored the canonical bytes and then failed while unlinking
     * its transaction-owned `.restore` entry. On retry, content comparison alone would skip
     * publication and strand that candidate beside the source. Reconcile both the active name
     * and its `.cleanup` quarantine before rollback is allowed to become terminal.
     */
    private fun cleanupRollbackPublicationResidue(
        changes: List<RevisionFileDelta>,
        transactionId: String,
        phase: String,
    ) {
        changes.forEachIndexed { indexInCleanup, change ->
            val parts = normalizedRelative(change.path).split('/')
            val parent = parts.dropLast(1).joinToString("/")
            val temporary = sourceTransactionTemporaryName(parts.last(), transactionId)
            val allowedDigests = setOfNotNull(change.beforeSha256, change.afterSha256)
            cleanupRepairOwnedEntry(
                projectRoot, parent, "$temporary.restore", allowedDigests, null,
                state.budget.maximumSourceFileBytes, phase, change.path, indexInCleanup,
                faultInjector, required = false, expectedLinkCount = -1,
            )
            cleanupRepairOwnedEntry(
                projectRoot, parent, temporary, allowedDigests, null,
                state.budget.maximumSourceFileBytes, phase, change.path, indexInCleanup,
                faultInjector, required = false, expectedLinkCount = -1,
            )
        }
    }

    /** Verify restored content identity and metadata through the same descriptor chain. */
    private fun requireRestoredPreimageMetadata(
        path: String,
        expected: RepairPreimageMetadata,
        operation: String,
    ) {
        val descriptors = mutableListOf<decompengine.acp.LinuxDescriptor>()
        try {
            var parent = openRepairRootDirectory(projectRoot)
            descriptors += parent
            val segments = normalizedRelative(path).split('/')
            segments.dropLast(1).forEach { segment ->
                parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
                descriptors += parent
            }
            val source = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, segments.last())) {
                "$operation source disappeared during metadata verification: $path"
            }
            source.use {
                if (expected.metadataVersion == 2) {
                    if (!expected.matches(LinuxFilesystemSyscalls.fileState(source), includeAtime = false)) throw RepairRollbackException(
                        RepairRollbackStage.SOURCE_VERIFICATION,
                        RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
                        "$operation restored source identity or metadata differs from the committed preimage: $path",
                    )
                    normalizeCommittedPreimageAtime(source, expected)
                }
                if (!expected.matches(LinuxFilesystemSyscalls.fileState(source))) throw RepairRollbackException(
                    RepairRollbackStage.SOURCE_VERIFICATION,
                    RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
                    "$operation restored bytes without the committed preimage metadata: $path",
                )
                if (LinuxFilesystemSyscalls.extendedAttributeNames(source).isNotEmpty()) throw RepairRollbackException(
                    RepairRollbackStage.SOURCE_VERIFICATION,
                    RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
                    "$operation violated the committed no-xattr policy: $path",
                )
            }
        } finally {
            descriptors.asReversed().forEach { it.close() }
        }
    }

    private fun verifyDetachedRollbackTarget() {
        val expected = state.nodes.single { it.id == state.headId }.sourceRevisionSha256
        val observed = revisionSha256(index.sourceSnapshot())
        if (observed != expected) throw RepairRollbackException(
            RepairRollbackStage.SOURCE_VERIFICATION,
            RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
            "restored source tree does not match the pre-promotion published head",
        )
    }

    private fun installFiles(
        replacements: Map<String, ByteArray>,
        expectedCurrentSha256: Map<String, String>,
        transactionId: String,
        phase: String,
        rollbackCandidateSha256: Map<String, String> = emptyMap(),
        preimageMetadata: Map<String, RepairPreimageMetadata> = emptyMap(),
    ) {
        require(replacements.keys.all { it in index.editablePaths })
        publishRepairFiles(
            projectRoot,
            stateStore.revisionsPath,
            replacements,
            expectedCurrentSha256,
            state.budget.maximumSourceFileBytes,
            transactionId,
            phase,
            rollbackCandidateSha256,
            preimageMetadata,
            faultInjector,
        )
    }

    private fun safeSourceTarget(relative: String): Path {
        val normalized = normalizedRelative(relative)
        require(normalized in index.editablePaths) { "revision path is not editable: $relative" }
        val target = projectRoot.resolve(normalized).normalize()
        require(target.startsWith(projectRoot)) { "revision path escapes project: $relative" }
        require(Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(target)) {
            "revision source is not a regular non-symbolic-link file: $relative"
        }
        return target
    }

    private data class BlobPublicationReservation(val digests: Set<String>)

    private fun storeBlob(
        bytes: ByteArray,
        publicationReservation: BlobPublicationReservation? = null,
    ): String {
        // Detach from caller-owned buffers before hashing or writing. A concurrent mutation cannot
        // make the durable filename authenticate bytes other than the bytes referenced by state.
        val frozenBytes = bytes.copyOf()
        val digest = sha256(frozenBytes)
        if (stateStore.blobExists(digest)) {
            require(stateStore.readBlob(digest, index.budget.maximumSourceFileBytes).bytes.contentEquals(frozenBytes)) {
                "repair blob digest collision or corruption: $digest"
            }
            return digest
        }
        require(digest in publicationReservation?.digests.orEmpty()) {
            "repair blob is missing without a budgeted publication reservation: $digest"
        }
        stateStore.writeBlob(digest, frozenBytes)
        val authenticated = stateStore.readBlob(digest, index.budget.maximumSourceFileBytes)
        require(authenticated.sha256 == digest && authenticated.bytes.contentEquals(frozenBytes)) {
            "repair blob write did not persist authenticated content: $digest"
        }
        return digest
    }

    private fun reserveBlobPublications(requiredDigests: Collection<String>): BlobPublicationReservation {
        val required = requiredDigests.toSet()
        require(required.all(REPAIR_BLOB_DIGEST::matches)) { "repair blob publication digest is invalid" }
        val maximumEntries = index.budget.maximumStateDirectoryEntries
        val names = stateStore.blobNames(maximumEntries)
        val stagedDigests = names.mapNotNull { name ->
            BLOB_ATOMIC_TEMPORARY.matchEntire(name)?.groupValues?.get(1)
        }.toSet()
        val additionalEntries = required.count { digest -> digest !in names && digest !in stagedDigests }
        val projectedEntries = Math.addExact(names.size, additionalEntries)
        if (projectedEntries > maximumEntries) {
            throw RepairBudgetExceededException(
                "repair blob publication requires $projectedEntries directory entries; limit=$maximumEntries",
            )
        }
        return BlobPublicationReservation(required)
    }

    private fun readBlob(digest: String): ByteArray {
        require(digest.matches(Regex("[0-9a-f]{64}"))) { "invalid repair blob digest" }
        val observed = stateStore.readBlob(digest, index.budget.maximumSourceFileBytes)
        require(observed.sha256 == digest) { "repair blob is corrupt: $digest" }
        return observed.bytes
    }

    private fun referencedBlobBytes(
        nodes: List<ModuleRevisionNode>,
        pending: PendingAttempt?,
        verifyContents: Boolean = false,
    ): Long {
        val sizes = TreeMap<String, Long>()
        fun record(digest: String?, bytes: Long) {
            if (digest == null) return
            val existing = sizes.putIfAbsent(digest, bytes)
            require(existing == null || existing == bytes) { "repair blob has inconsistent sizes: $digest" }
        }
        nodes.forEach { node ->
            node.changes.forEach { delta ->
                delta.beforeBlobSha256?.let { before ->
                    record(before, delta.beforeBytes ?: error("repair delta is missing before-byte count"))
                }
                record(delta.afterBlobSha256, delta.afterBytes)
            }
        }
        pending?.preimages.orEmpty().forEach {
            record(it.beforeBlobSha256, it.beforeBytes ?: error("repair preimage is missing byte count"))
        }
        pending?.candidateChanges.orEmpty().forEach { delta ->
            delta.beforeBlobSha256?.let { before ->
                record(before, delta.beforeBytes ?: error("repair candidate is missing before-byte count"))
            }
            record(delta.afterBlobSha256, delta.afterBytes)
        }
        return sizes.entries.fold(0L) { total, (digest, bytes) ->
            if (verifyContents) {
                val observed = stateStore.readBlob(digest, index.budget.maximumSourceFileBytes)
                require(observed.sha256 == digest) { "repair blob digest does not match graph: $digest" }
                require(observed.bytes.size.toLong() == bytes) { "repair blob size does not match graph: $digest" }
            }
            Math.addExact(total, bytes)
        }
    }

    private fun deleteUnreferencedCandidateBlobs(changes: List<RevisionFileDelta>) {
        val referenced = referencedBlobDigests()
        changes.map { it.afterBlobSha256 }.filterNot { it in referenced }.distinct().forEachIndexed { cleanupIndex, digest ->
            cleanupRepairOwnedEntry(
                stateStore.blobsPath,
                "",
                digest,
                setOf(digest),
                null,
                index.budget.maximumSourceFileBytes,
                "candidate-blob-cleanup",
                digest,
                cleanupIndex,
                faultInjector,
                required = false,
            )
        }
    }

    private fun cleanupUnreferencedBlobs() {
        val referenced = referencedBlobDigests()
        val names = stateStore.blobNames(state.budget.maximumStateDirectoryEntries)
        names.mapNotNull { name -> BLOB_ATOMIC_TEMPORARY.matchEntire(name)?.groupValues?.get(1) }
            .forEach(stateStore::cleanupBlobTemporary)
        names.asSequence()
            .filterNot(BLOB_ATOMIC_TEMPORARY::matches)
            .forEachIndexed { indexInCleanup, name ->
                val baseName = name.removeSuffix(".cleanup")
                if (baseName !in referenced) {
                    require(baseName.matches(Regex("[0-9a-f]{64}"))) {
                        "repair blob directory contains an unowned entry: $name"
                    }
                    cleanupRepairOwnedEntry(
                        stateStore.blobsPath,
                        "",
                        baseName,
                        setOf(baseName),
                        null,
                        index.budget.maximumSourceFileBytes,
                        "blob-gc",
                        baseName,
                        indexInCleanup,
                        faultInjector,
                        required = false,
                    )
            }
    }
        stateStore.synchronizeBlobs()
    }

    /** Reconcile only normal graph-owned roles, with one shared allowance for both quarantine reads. */
    private fun cleanupUnreferencedValidationArtifacts() {
        val observations = state.runs.flatMap { it.validationObservations.entries }
        val maximumEntries = repairValidationDiffDirectoryEntryLimit(state.budget)
        // Admit both whole directories before any cleanup; fatal root receipts are never swept here.
        val receipts = planRepairValidationReceiptDirectory(stateStore.normalValidationReceiptNames(maximumEntries),
            observations.map { it.primary }, maximumEntries)
        val diffs = planRepairValidationDiffDirectory(stateStore.validationDiffNames(maximumEntries),
            observations.mapNotNull { it.diff }, maximumEntries)
        receipts.temporaryTargets.forEach(stateStore::cleanupNormalValidationReceiptTemporary)
        diffs.temporaryTargets.forEach(stateStore::cleanupValidationDiffTemporary)
        var remaining = minOf(state.budget.maximumIndexEvidenceBytes, 2L * MAXIMUM_REPAIR_PROJECTION_BYTES)
        receipts.orphans.forEachIndexed { cleanupIndex, orphan ->
            val (identity, size) = stateStore.normalValidationReceiptMetadata(orphan.observedName)
            remaining = reserveRepairValidationArtifactCleanupBytes(size, remaining)
            cleanupRepairOwnedEntry(requireNotNull(stateStore.normalValidationReceiptsPath()), "", orphan.targetName,
                setOf(orphan.sha256), identity.key, size, "normal-validation-receipt-gc", orphan.targetName,
                cleanupIndex, faultInjector, required = true)
        }
        diffs.orphans.forEachIndexed { cleanupIndex, orphan ->
            val (identity, size) = stateStore.validationDiffMetadata(orphan.observedName)
            remaining = reserveRepairValidationArtifactCleanupBytes(size, remaining)
            cleanupRepairOwnedEntry(requireNotNull(stateStore.validationDiffsPath()), "", orphan.targetName,
                setOf(orphan.sha256), identity.key, size, "validation-diff-gc", orphan.targetName,
                cleanupIndex, faultInjector, required = true)
        }
    }

    private fun cleanupGraphTemporaries() {
        stateStore.cleanupGraphTemporary()
    }

    private fun cleanupSourceTemporaries(pending: PendingAttempt?) {
        val active = pending ?: return
        val candidateByPath = (if (active.detached) active.promotionChanges else active.candidateChanges).associateBy { it.path }
        val preimages = if (active.detached) active.promotionChanges else active.preimages
        preimages.forEachIndexed { index, preimage ->
            val normalized = normalizedRelative(preimage.path)
            val parts = normalized.split('/')
            cleanupRepairOwnedEntry(
                projectRoot,
                parts.dropLast(1).joinToString("/"),
                sourceTransactionTemporaryName(parts.last(), active.id),
                setOfNotNull(preimage.beforeSha256, candidateByPath[preimage.path]?.afterSha256),
                null,
                state.budget.maximumSourceFileBytes,
                "startup-cleanup",
                normalized,
                index,
                faultInjector,
                required = false,
                expectedLinkCount = -1,
            )
        }
    }

    /** Remove transaction-owned preimage links only after the canonical graph has committed. */
    private fun cleanupCommittedPreimages() {
        if (state.pending != null) return
        state.nodes.forEachIndexed { nodeIndex, node ->
            if (node.status == ModuleRevisionStatus.ROOT) {
                return@forEachIndexed
            }
            // Keep the actual publication plan separate from logical ACP contribution changes:
            // provisional promotion can displace files that are absent from node.changes.
            val physicalChanges = if (state.schemaVersion >= 5) node.publicationChanges else
                if (node.id.matches(Regex("revision_[A-Za-z0-9_]+"))) node.changes else emptyList()
            physicalChanges.forEachIndexed { changeIndex, change ->
                val preimageDigest = requireNotNull(change.beforeSha256) {
                    "committed physical publication is missing its preimage digest"
                }
                val metadata = node.publicationPreimageMetadata[change.path]
                if (state.schemaVersion >= 5) requireNotNull(metadata) {
                    "schema-5 committed publication is missing its preimage identity: ${node.id}:${change.path}"
                }
                if (state.schemaVersion >= 6) {
                    val committed = requireNotNull(metadata)
                    val parentMount = requireNotNull(committed.ancestorMetadata.lastOrNull()).mountId
                    val expectedIdentity = LinuxFileIdentity(
                        LinuxFileKey(committed.device, committed.inode), committed.mode, committed.uid, committed.gid,
                        1, parentMount, true, false, false,
                    )
                    stateStore.removePublicationStage(
                        committed.retainedName, expectedIdentity, preimageDigest, requireNotNull(change.beforeBytes),
                    )
                    return@forEachIndexed
                }
                cleanupRepairOwnedEntry(
                    stateStore.revisionsPath,
                    "",
                    metadata?.retainedName ?: sourceTransactionPreimageName(change.path, node.id),
                    setOf(preimageDigest),
                    metadata?.let { LinuxFileKey(it.device, it.inode) },
                    state.budget.maximumSourceFileBytes,
                    "committed-preimage-cleanup",
                    change.path,
                    nodeIndex + changeIndex,
                    faultInjector,
                    required = false,
                    // A committed candidate leaves the retained preimage as the sole link. A
                    // committed rejection restores the preimage as the canonical source too.
                    // Schema-5 carries a durable inode commitment and therefore has an exact
                    // expected link count. Legacy records are content-only; recovery may have
                    // restored by exchange or by a bounded copy, so accept either owned state
                    // without promoting that observation into metadata provenance.
                    expectedLinkCount = if (metadata == null) -1
                        else if (node.status == ModuleRevisionStatus.REJECTED) 2 else 1,
                    expectedMetadata = metadata,
                )
            }
        }
    }

    private fun referencedBlobDigests(): Set<String> = referencedBlobDigests(state.nodes, state.pending)

    private fun referencedBlobDigests(
        nodes: List<ModuleRevisionNode>,
        pending: PendingAttempt?,
    ): Set<String> = buildSet {
        nodes.forEach { node ->
            node.changes.forEach { delta ->
                delta.beforeBlobSha256?.let(::add)
                add(delta.afterBlobSha256)
            }
        }
        pending?.preimages.orEmpty().forEach { delta ->
            delta.beforeBlobSha256?.let(::add)
            add(delta.afterBlobSha256)
        }
        pending?.candidateChanges.orEmpty().forEach { delta ->
            delta.beforeBlobSha256?.let(::add)
            add(delta.afterBlobSha256)
        }
    }

    private fun requirePending(attempt: ModuleRevisionAttempt): PendingAttempt {
        val pending = state.pending ?: error("revision graph has no pending attempt")
        require(pending.id == attempt.id) { "revision attempt token does not match pending graph state" }
        return pending
    }

    private fun pendingAgentChangeSetSha256(pending: PendingAttempt): String =
        agentChangeSetSha256(pending.candidateChanges)

    private fun agentChangeSetSha256(changes: List<RevisionFileDelta>): String =
        recordedAgentChangeSetSha256(changes)

    private fun requireCurrentHead(): List<IndexedSource> {
        val expected = state.nodes.single { it.id == state.headId }.sourceRevisionSha256
        val snapshot = index.sourceSnapshot()
        val observed = revisionSha256(snapshot)
        require(observed == expected) { "project sources do not match revision graph head: expected=$expected observed=$observed" }
        return snapshot
    }

    private fun portableEvidencePath(value: String): String {
        val portableValue = portableEvidenceText(value)
        return runCatching {
            val path = Path.of(value)
            when {
                path.isAbsolute && path.normalize().startsWith(projectRoot) ->
                    projectRoot.relativize(path.normalize()).pathString.replace('\\', '/')
                path.isAbsolute && path.normalize().startsWith(portableProjectRoot) ->
                    portableProjectRoot.relativize(path.normalize()).pathString.replace('\\', '/')
                path.isAbsolute -> "external/${path.fileName}"
                else -> Path.of(portableValue).normalize().pathString.replace('\\', '/')
            }
        }.getOrDefault(portableValue.replace('\\', '/'))
    }

    private fun portableEvidenceText(value: String): String {
        val replacement = "\${PROJECT_ROOT}"
        val variants = buildSet {
            add(portableProjectRoot.pathString)
            add(portableProjectRoot.pathString.replace('/', '\\'))
            runCatching { add(portableProjectRoot.toUri().toString().removeSuffix("/")) }
            add(projectRoot.pathString)
            add(projectRoot.pathString.replace('/', '\\'))
            runCatching { add(projectRoot.toUri().toString().removeSuffix("/")) }
        }.filter { it.isNotEmpty() }.sortedByDescending { it.length }
        return variants.fold(value) { normalized, root -> normalized.replace(root, replacement) }
    }

    private fun repairPromptCommitment(value: String): String {
        val bytes = receiptCommitmentBytes(value)
        return sha256(bytes)
    }

    private data class PreparedRevisionGraphState(
        val state: RevisionGraphState,
        val payload: ByteArray,
    )

    private fun prepareStateForPersistence(candidate: RevisionGraphState): PreparedRevisionGraphState {
        val frozenCandidate = candidate.deepFrozenCopy()
        val blobBytes = referencedBlobBytes(frozenCandidate.nodes, frozenCandidate.pending)
        require(blobBytes <= frozenCandidate.budget.maximumStoredBlobBytes) { "revision graph exceeds stored blob budget" }
        val normalized = frozenCandidate.copy(storedBlobBytes = blobBytes)
        val prior = state
        state = normalized
        try {
            validateLoadedState(verifyBlobContents = false)
        } finally {
            state = prior
        }
        val payload = renderGraph(normalized).toByteArray(Charsets.UTF_8)
        requireRevisionGraphAdmission(normalized, payload.size.toLong(), purpose = DeclaredOriginPurpose.LOCAL_RECORDED, forEachDeclaredGraph = { consume ->
            stateStore.forEachDeclaredLegacyGraph(normalized.budget, consume) })
        return PreparedRevisionGraphState(normalized, payload)
    }

    private fun persist(candidate: RevisionGraphState) = persist(prepareStateForPersistence(candidate))

    private fun persist(prepared: PreparedRevisionGraphState, beforePublication: (() -> Unit)? = null) {
        stateStore.writeGraph(prepared.payload, beforePublication)
        state = prepared.state
    }

    private fun synchronizeSourceManifest() {
        stateStore.cleanupRootTemporary("source_tree_manifest.json")
        if (!stateStore.rootFileExists("source_tree_manifest.json")) return
        val manifestBytes = readStableRegularFile(
            projectRoot,
            "source_tree_manifest.json",
            state.budget.maximumIndexEvidenceBytes,
        ).bytes
        val acceptedChanges = linkedMapOf<String, ModuleRevisionNode>()
        var canonicalSources = emptyMap<String, IndexedSource>()
        state.nodes.forEach { revision ->
            if (revision.status in setOf(ModuleRevisionStatus.ROOT, ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.LEGACY_UNVERIFIED)) {
                val promotedSources = sourcesAt(revision.id)
                // The accepting node owns the composed publication, including edits inherited
                // from its provisional ancestors. A provisional node alone owns no installed file.
                promotedSources.forEach { (path, source) ->
                    if (canonicalSources[path] != source) acceptedChanges[path] = revision
                }
                canonicalSources = promotedSources
            }
        }
        if (acceptedChanges.isEmpty()) return
        val sourceByPath = index.sourceSnapshot().associateBy { it.path }
        val manifestText = decodeUtf8Strict(manifestBytes, "source_tree_manifest.json")
        UniqueJsonObjectKeyValidator(manifestText).validate()
        val root = Json.parseToJsonElement(manifestText).jsonObject
        val files = root["files"]?.jsonArray ?: return
        val reconstructionProfile = index.profile.reconstructionProfile()
        if (reconstructionProfile != null) {
            require(root["profileId"] == JsonPrimitive(reconstructionProfile.id) &&
                root["profileSha256"] == JsonPrimitive(reconstructionProfile.sha256)) {
                "repair source manifest differs from the selected reconstruction profile"
            }
        }
        // Keep displaced manifest-bound report preimages until both derived reports and the
        // source manifest are durably synchronized. A crash may interrupt that sequence.
        val resolvedImplementationIds = linkedSetOf<String>()
        var changed = false
        val updatedFiles = files.map { element ->
            val item = element.jsonObject
            val relative = item["path"]?.jsonPrimitive?.contentOrNull
            val revision = relative?.let(acceptedChanges::get)
            val source = relative?.let(sourceByPath::get)
            if (revision == null || source == null) {
                element
            } else {
                val updated = LinkedHashMap(item)
                if (item["sha256"]?.jsonPrimitive?.contentOrNull != source.sha256) {
                    changed = true
                    updated["sha256"] = JsonPrimitive(source.sha256)
                    updated["generator"] = JsonPrimitive("repair-revision")
                    updated["promptSha256"] = JsonPrimitive(sha256("revision:${revision.id}".toByteArray(Charsets.UTF_8)))
                    val implementation = item["roles"]?.jsonArray?.any {
                        it == JsonPrimitive(ProjectFileRole.MODULE_IMPLEMENTATION.wireName)
                    } == true
                    if (implementation && item["acceptedImplementation"] != JsonNull) {
                        updated["acceptedImplementation"] = JsonPrimitive(true)
                    }
                }
                if (updated["roles"]?.jsonArray?.any {
                        it == JsonPrimitive(ProjectFileRole.MODULE_IMPLEMENTATION.wireName)
                    } == true && updated["acceptedImplementation"] == JsonPrimitive(true) &&
                    updated["generator"] == JsonPrimitive("repair-revision")) {
                    updated["entityIds"]?.jsonArray?.forEach { resolvedImplementationIds += it.jsonPrimitive.content }
                }
                JsonObject(updated)
            }
        }
        val unresolved = root["unresolvedImplementationIds"]?.jsonArray
        val remaining = unresolved?.filterNot { it.jsonPrimitive.content in resolvedImplementationIds }
        val repairedModules = updatedFiles.mapNotNull { element ->
            val item = element.jsonObject
            val relative = item["path"]?.jsonPrimitive?.contentOrNull ?: return@mapNotNull null
            if (relative !in acceptedChanges || item["generator"] != JsonPrimitive("repair-revision") ||
                item["acceptedImplementation"] != JsonPrimitive(true) ||
                item["roles"]?.jsonArray?.contains(JsonPrimitive(ProjectFileRole.MODULE_IMPLEMENTATION.wireName)) != true
            ) return@mapNotNull null
            reconstructionProfile?.layout?.declaration("module-implementation")?.moduleIdForPath(relative)
        }.toSet()
        if (remaining != null && remaining.size != unresolved.size) changed = true
        if (changed || repairedModules.isNotEmpty()) {
            val updatedRoot = LinkedHashMap(root)
            // Custom index profiles still own accepted source publication, but only a declared
            // reconstruction contract identifies the derived reports and their projection rules.
            val projectedFiles = if (reconstructionProfile != null && remaining != null &&
                (remaining.size != unresolved.size || repairedModules.isNotEmpty())) {
                val confidencePath = reconstructionProfile.layout.declaration("confidence-evidence").materialize()
                val unresolvedPath = reconstructionProfile.layout.declaration("unresolved-evidence").materialize()
                // The confidence report is a derived view of the same unresolved implementation
                // population. Keep its current projection and manifest digest synchronized so an
                // accepted repair does not invalidate unrelated accepted modules at archive audit.
                val confidenceEntry = updatedFiles.single { item ->
                    item.jsonObject["path"]?.jsonPrimitive?.contentOrNull == confidencePath
                }.jsonObject
                val priorSha256 = confidenceEntry.getValue("sha256").jsonPrimitive.content
                val reportBytes = readStableRegularFile(projectRoot, confidencePath,
                    state.budget.maximumIndexEvidenceBytes).bytes
                val currentSha256 = sha256(reportBytes)
                val trustedReportBytes = if (currentSha256 == priorSha256) reportBytes else {
                    requireNotNull(stateStore.readProjectedEvidencePreimage(confidencePath,
                        state.budget.maximumIndexEvidenceBytes)) {
                        "repair confidence projection has no manifest-bound recovery preimage"
                    }.also { preimage ->
                        require(sha256(preimage) == priorSha256) {
                            "repair confidence recovery preimage differs from the source manifest"
                        }
                    }
                }
                val reportText = decodeUtf8Strict(trustedReportBytes, confidencePath)
                UniqueJsonObjectKeyValidator(reportText).validate()
                val report = Json.parseToJsonElement(reportText).jsonObject
                require(report["schemaVersion"] == JsonPrimitive(2)) { "repair confidence projection has an unsupported schema" }
                val projectedImplementations = report.getValue("unresolvedImplementationIds").jsonArray.filterNot {
                    it.jsonPrimitive.content in resolvedImplementationIds
                }
                val recovery = report.getValue("unresolvedRecoveryEntityIds").jsonArray.map { it.jsonPrimitive.content }
                val projectedModules = report.getValue("modules").jsonArray.map { module ->
                    val fields = LinkedHashMap(module.jsonObject)
                    fields["unresolvedImplementationIds"] = JsonArray(
                        module.jsonObject.getValue("unresolvedImplementationIds").jsonArray.filterNot {
                            it.jsonPrimitive.content in resolvedImplementationIds
                        },
                    )
                    JsonObject(fields)
                }
                val projectedReport = LinkedHashMap(report)
                projectedReport["unresolvedImplementationIds"] = JsonArray(projectedImplementations)
                projectedReport["unresolvedEntityIds"] = JsonArray(
                    (recovery + projectedImplementations.map { it.jsonPrimitive.content }).distinct().sorted().map(::JsonPrimitive),
                )
                projectedReport["modules"] = JsonArray(projectedModules)
                val projectedBytes = (JsonObject(projectedReport).toString() + "\n").toByteArray(Charsets.UTF_8)
                require(projectedBytes.size.toLong() <= state.budget.maximumIndexEvidenceBytes) {
                    "repair confidence projection exceeds its byte bound"
                }
                val projectedSha256 = sha256(projectedBytes)
                require(currentSha256 == priorSha256 || currentSha256 == projectedSha256) {
                    "repair confidence projection differs from the checked source manifest"
                }
                val confidenceFiles = updatedFiles.map { item ->
                    if (item.jsonObject["path"]?.jsonPrimitive?.contentOrNull != confidencePath) item else {
                        JsonObject(LinkedHashMap(item.jsonObject).apply { put("sha256", JsonPrimitive(projectedSha256)) })
                    }
                }
                val unresolvedEntry = confidenceFiles.single { item ->
                    item.jsonObject["path"]?.jsonPrimitive?.contentOrNull == unresolvedPath
                }.jsonObject
                val unresolvedBytes = readStableRegularFile(projectRoot, unresolvedPath,
                    state.budget.maximumIndexEvidenceBytes).bytes
                val currentUnresolvedSha256 = sha256(unresolvedBytes)
                val priorUnresolvedSha256 = unresolvedEntry.getValue("sha256").jsonPrimitive.content
                val trustedUnresolvedBytes = if (currentUnresolvedSha256 == priorUnresolvedSha256) unresolvedBytes else {
                    requireNotNull(stateStore.readProjectedEvidencePreimage(unresolvedPath,
                        state.budget.maximumIndexEvidenceBytes)) {
                        "repair unresolved projection has no manifest-bound recovery preimage"
                    }.also { preimage ->
                        require(sha256(preimage) == priorUnresolvedSha256) {
                            "repair unresolved recovery preimage differs from the source manifest"
                        }
                    }
                }
                val unresolvedText = decodeUtf8Strict(trustedUnresolvedBytes, unresolvedPath)
                val marker = "## Implementation generation\n\n"
                require(unresolvedText.indexOf(marker) == unresolvedText.lastIndexOf(marker) && marker in unresolvedText) {
                    "repair unresolved evidence has no unique implementation section"
                }
                val planPath = reconstructionProfile.layout.declaration("module-plan-evidence").materialize()
                val planSnapshot = readStableRegularFile(projectRoot, planPath,
                    state.budget.maximumIndexEvidenceBytes)
                val planEntry = files.single { item ->
                    item.jsonObject["path"]?.jsonPrimitive?.contentOrNull == planPath
                }.jsonObject
                require(planSnapshot.sha256 == planEntry.getValue("sha256").jsonPrimitive.content) {
                    "repair module plan differs from the checked source manifest"
                }
                val planText = decodeUtf8Strict(planSnapshot.bytes, planPath)
                UniqueJsonObjectKeyValidator(planText).validate()
                val plan = Json.parseToJsonElement(planText).jsonObject
                val owners = plan.getValue("modules").jsonArray.flatMap { module ->
                    val fields = module.jsonObject
                    val moduleId = fields.getValue("id").jsonPrimitive.content
                    (fields.getValue("functionIds").jsonArray + fields.getValue("globalIds").jsonArray).map {
                        it.jsonPrimitive.content to moduleId
                    }
                }.toMap()
                val remainingIds = remaining.orEmpty().map { it.jsonPrimitive.content }
                val implementationSection = buildString {
                    append(marker)
                    if (remainingIds.isEmpty()) {
                        append("Every planner-owned implementation passed the acceptance checks.\n")
                    } else {
                        append("These planner-owned entities are not accepted implementations. See the attributable module report for the exact evidence.\n\n")
                        append("| Stable ID | Owning module | Evidence |\n|---|---|---|\n")
                        remainingIds.forEach { id ->
                            val moduleId = requireNotNull(owners[id]) { "repair unresolved owner is absent from the module plan: $id" }
                            val evidencePath = reconstructionProfile.layout.declaration("module-evidence")
                                .materialize(mapOf("module" to moduleId))
                            append("| `$id` | `$moduleId` | `$evidencePath` |\n")
                        }
                    }
                }
                val projectedUnresolvedBytes = (unresolvedText.substringBefore(marker) + implementationSection)
                    .toByteArray(Charsets.UTF_8)
                require(projectedUnresolvedBytes.size.toLong() <= state.budget.maximumIndexEvidenceBytes) {
                    "repair unresolved projection exceeds its byte bound"
                }
                val unresolvedSha256 = sha256(projectedUnresolvedBytes)
                require(currentUnresolvedSha256 == priorUnresolvedSha256 ||
                    currentUnresolvedSha256 == unresolvedSha256) {
                    "repair unresolved projection differs from the checked source manifest"
                }
                if (currentSha256 != projectedSha256) stateStore.writeProjectedEvidence(confidencePath, projectedBytes)
                if (currentUnresolvedSha256 != unresolvedSha256) {
                    stateStore.writeProjectedEvidence(unresolvedPath, projectedUnresolvedBytes)
                }
                confidenceFiles.map { item ->
                    if (item.jsonObject["path"]?.jsonPrimitive?.contentOrNull != unresolvedPath) item else {
                        JsonObject(LinkedHashMap(item.jsonObject).apply {
                            put("sha256", JsonPrimitive(unresolvedSha256))
                            put("entityIds", JsonArray(remainingIds.map(::JsonPrimitive)))
                        })
                    }
                }
            } else updatedFiles
            updatedRoot["files"] = JsonArray(projectedFiles)
            if (remaining != null) updatedRoot["unresolvedImplementationIds"] = JsonArray(remaining)
            stateStore.writeRoot(
                "source_tree_manifest.json",
                (JsonObject(updatedRoot).toString() + "\n").toByteArray(Charsets.UTF_8),
            )
            if (reconstructionProfile != null) {
                stateStore.cleanupProjectEvidenceTemporary(reconstructionProfile.layout.declaration("confidence-evidence").materialize())
                stateStore.cleanupProjectEvidenceTemporary(reconstructionProfile.layout.declaration("unresolved-evidence").materialize())
            }
        }
    }

    private inline fun <T> graphOperation(action: () -> T): T {
        check(Thread.holdsLock(this)) { "revision graph operation monitor is not held" }
        check(lifecycle == Lifecycle.OPEN) { "revision graph is closed" }
        if (state.pending?.acceptanceDecision != null) {
            throw RepairAcceptancePendingException(
                "repair acceptance decision is durable; graph mutations are unavailable pending roll-forward recovery",
            )
        }
        val current = Thread.currentThread()
        if (operationDepth == 0) {
            // A committed graph may still have durable cleanup work after an interrupted unlink.
            // Reconcile it before any later graph mutation or publication can proceed.
            cleanupCommittedPreimages()
            operationThread = current
        } else {
            check(operationThread === current) { "revision graph operation ownership changed" }
        }
        operationDepth = Math.addExact(operationDepth, 1)
        rootCoordination.enterOperation()
        try {
            return action()
        } catch (failure: Throwable) {
            // Non-Exception throwables model a lost process at an arbitrary durability boundary.
            // If a caller catches one in-process, disk may be either side of the last commit while
            // this object's cached state is not. Poison the graph until close/reopen recovery.
            if (failure !is Exception) lifecycle = Lifecycle.POISONED
            throw failure
        } finally {
            try {
                rootCoordination.exitOperation()
            } finally {
                operationDepth--
                if (operationDepth == 0) operationThread = null
            }
        }
    }

    companion object {
        /** JVM bridge owned by [SecureRepairRuntime]; authenticate before all other inputs. */
        fun openAuthorized(
            runtimeIdentity: Any?,
            graphAuthorityCandidate: Any?,
            projectDirCandidate: Path?,
            profileCandidate: RepairIndexProfile?,
            budgetCandidate: RepairResourceBudget?,
            faultInjector: ModuleRevisionFaultInjector?,
        ): ModuleRevisionGraph {
            SecureRepairRuntime.requireRuntimeIdentity(runtimeIdentity)
            SecureRepairRuntime.requireGraphAuthority(graphAuthorityCandidate)
            val graphAuthority = requireNotNull(graphAuthorityCandidate)
            val projectDir = requireNotNull(projectDirCandidate) { "repair project path is required" }
            val profile = requireNotNull(profileCandidate) { "repair profile is required" }
            val budget = requireNotNull(budgetCandidate) { "repair resource budget is required" }
            return openInternal(graphAuthority, projectDir, profile, budget, faultInjector)
        }

        private fun openInternal(
            graphAuthority: Any,
            projectDir: Path,
            profile: RepairIndexProfile,
            budget: RepairResourceBudget,
            faultInjector: ModuleRevisionFaultInjector?,
        ): ModuleRevisionGraph {
            val portableProjectRoot = projectDir.toAbsolutePath().normalize()
            require(Files.isDirectory(portableProjectRoot, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(portableProjectRoot)) {
                "repair project root is not a regular non-symbolic-link directory"
            }
            val rootDescriptor = LinuxFilesystemSyscalls.openRoot(portableProjectRoot)
            val maximumWaitNanos = TimeUnit.MILLISECONDS.toNanos(budget.maximumGraphLockWaitMillis)
            val lockDeadlineNanos = System.nanoTime() + maximumWaitNanos
            val rootCoordination = try {
                RepairRootCoordinator.acquire(
                    rootDescriptor,
                    lockDeadlineNanos,
                    budget.maximumGraphLockWaitMillis,
                )
            } catch (failure: Throwable) {
                rootDescriptor.close()
                throw failure
            }
            var lock: LinuxDescriptor? = null
            try {
                requireLexicalRootBinding(portableProjectRoot, rootDescriptor.identity)
                lock = acquireRepairProjectRootLock(
                    rootDescriptor,
                    lockDeadlineNanos,
                    budget.maximumGraphLockWaitMillis,
                )
                val projectRoot = repairDescriptorPath(rootDescriptor)
                val stateStore = RepairStateStore.open(rootDescriptor, faultInjector)
                return try {
                    stateStore.cleanupGraphTemporary()
                    stateStore.cleanupBindingTemporary()
                    if (!stateStore.graphExists()) {
                        stateStore.cleanupUnboundBlobs(
                            budget.maximumStateDirectoryEntries,
                            budget.maximumSourceFileBytes,
                        )
                    }
                    restorePendingPreimagesBeforeIndex(projectRoot, stateStore, profile, budget, faultInjector, graphAuthority)
                    val currentIndex = SecureRepairRuntime.loadIndex(graphAuthority, projectRoot, profile, budget)
                    require(currentIndex.belongsTo(projectRoot) && currentIndex.budget == budget) {
                        "repair dependency index belongs to a different project or resource budget"
                    }
                    requireRecoveryBinding(stateStore, currentIndex)
                    try {
                        SecureRepairRuntime.authorizeGraphConstruction(graphAuthority)
                        ModuleRevisionGraph(
                            graphAuthority,
                            projectRoot,
                            portableProjectRoot,
                            rootDescriptor,
                            currentIndex,
                            stateStore,
                            requireNotNull(lock),
                            rootCoordination,
                            faultInjector,
                        )
                    } finally {
                        SecureRepairRuntime.clearConstructionAuthorization()
                    }
                } catch (failure: Throwable) {
                    stateStore.close()
                    throw failure
                }
            } catch (failure: Throwable) {
                try {
                    lock?.let { held ->
                        runCatching { LinuxFilesystemSyscalls.unlock(held) }
                        held.close()
                    }
                } finally {
                    try {
                        rootDescriptor.close()
                    } finally {
                        rootCoordination.close()
                    }
                }
                throw failure
            }
        }
    }
}

private fun repairDirectoryEntriesSha256(names: List<String>): String {
    val ordered = names.sorted()
    require(ordered.distinct().size == ordered.size && ordered.none { it.isEmpty() || '/' in it || '\u0000' in it })
    val digest = java.security.MessageDigest.getInstance("SHA-256")
    ordered.forEach { name ->
        val bytes = name.toByteArray(Charsets.UTF_8)
        digest.update(java.nio.ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
        digest.update(bytes)
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

private fun recoveryBinding(index: ModuleRepairIndex): RepairRecoveryBinding = RepairRecoveryBinding(
    profileId = index.profileId,
    profileSha256 = index.profileSha256,
    budgetSha256 = sha256(index.budget.toJson().toByteArray(Charsets.UTF_8)),
    sourcePaths = index.sourcePaths,
    editablePaths = index.editablePaths.sorted(),
    indexSha256 = index.indexSha256,
)

private fun requireLexicalRootBinding(path: Path, expected: LinuxFileIdentity) {
    LinuxFilesystemSyscalls.openRoot(path).use { observed ->
        require(
            observed.identity.key == expected.key && observed.identity.mountId == expected.mountId &&
                observed.identity.isDirectory && !observed.identity.isSymbolicLink,
        ) { "repair project root lexical binding changed during graph open" }
    }
}

private fun requireRecoveryBinding(store: RepairStateStore, index: ModuleRepairIndex) {
    val expected = recoveryBinding(index)
    val expectedBytes = renderRecoveryBinding(expected).toByteArray(Charsets.UTF_8)
    if (expectedBytes.size.toLong() > index.budget.maximumGraphBytes) {
        throw RepairBudgetExceededException(
            "repair recovery authorization exceeds ${index.budget.maximumGraphBytes} bytes",
        )
    }
    if (!store.graphExists()) {
        // A first-open failure may have durably published a large, malformed, or differently bound
        // file before any graph or pending journal existed. Under the held root lock that file is
        // replaceable initialization residue and is never parsed as revision authority.
        store.writeBinding(expectedBytes)
        return
    }
    require(store.bindingExists()) { "repair graph is missing its recovery authorization" }
    val observed = parseCanonicalRecoveryBinding(store.readBinding(index.budget.maximumGraphBytes))
    require(observed == expected) {
        "repair recovery authorization differs from the current profile/index layout"
    }
}

private fun renderRecoveryBinding(binding: RepairRecoveryBinding): String = buildString {
    append("{\n  \"schemaVersion\": 1,")
    append("\n  \"profileId\": \"").append(binding.profileId.jsonEscape()).append("\",")
    append("\n  \"profileSha256\": \"").append(binding.profileSha256).append("\",")
    append("\n  \"budgetSha256\": \"").append(binding.budgetSha256).append("\",")
    append("\n  \"sourcePaths\": ").append(binding.sourcePaths.jsonArray()).append(',')
    append("\n  \"editablePaths\": ").append(binding.editablePaths.jsonArray()).append(',')
    append("\n  \"indexSha256\": \"").append(binding.indexSha256).append("\"\n}\n")
}

private fun parseCanonicalRecoveryBinding(payload: ByteArray): RepairRecoveryBinding {
    val root = Json.parseToJsonElement(
        decodeUtf8Strict(payload, "reports/repair-revisions/recovery-binding.json"),
    ).jsonObject
    require(root["schemaVersion"]?.jsonPrimitive?.intOrNull == 1) {
        "unsupported repair recovery authorization schema"
    }
    val binding = RepairRecoveryBinding(
        profileId = root.requiredString("profileId"),
        profileSha256 = root.requiredString("profileSha256"),
        budgetSha256 = root.requiredString("budgetSha256"),
        sourcePaths = root.stringList("sourcePaths"),
        editablePaths = root.stringList("editablePaths"),
        indexSha256 = root.requiredString("indexSha256"),
    )
    require(renderRecoveryBinding(binding).toByteArray(Charsets.UTF_8).contentEquals(payload)) {
        "repair recovery authorization is not the exact canonical encoding"
    }
    require(
        listOf(binding.profileSha256, binding.budgetSha256, binding.indexSha256)
            .all { it.matches(Regex("[0-9a-f]{64}")) },
    ) { "repair recovery authorization contains an invalid digest" }
    require(binding.sourcePaths == binding.sourcePaths.map(::normalizedRelative).distinct().sorted())
    require(binding.editablePaths == binding.editablePaths.map(::normalizedRelative).distinct().sorted())
    require(binding.editablePaths.all { it in binding.sourcePaths })
    return binding
}

/**
 * Validate every topology, source-delta, profile, pending-parent, and blob invariant before startup
 * recovery is allowed to mutate a project source path. This validation deliberately needs no live
 * dependency index: that index can only be reconstructed after a partially installed candidate is
 * restored to its accepted parent.
 */
private fun validateRepairRunContract(state: RevisionGraphState) {
    if (state.schemaVersion < 3) {
        require(state.provisionalHeadId == null && state.fullyAcceptedHeadId == null && state.acceptedProof == null && state.runs.isEmpty())
        return
    }
    val nodes = state.nodes.associateBy { it.id }
    val runs = state.runs.associateBy { it.id }
    fun requireProofDigests(proof: RepairValidationProof) {
        require(listOf(proof.sourceRevisionSha256, proof.profileSha256, proof.indexSha256,
            proof.regressionCorpusSha256, proof.runtimeSha256, proof.evidenceSha256).all { it.matches(REPAIR_BLOB_DIGEST) })
        require(proof.originalBinarySha256 == null || proof.originalBinarySha256.matches(REPAIR_BLOB_DIGEST))
        require(proof.rebuiltBinarySha256 == null || proof.rebuiltBinarySha256.matches(REPAIR_BLOB_DIGEST))
    }
    state.provisionalHeadId?.let { id ->
        require(nodes[id]?.status == ModuleRevisionStatus.PROVISIONAL)
        require(revisionCanonicalBase(state.nodes, id) == state.headId)
    }
    require((state.fullyAcceptedHeadId == null) == (state.acceptedProof == null))
    state.acceptedProof?.let { proof ->
        requireProofDigests(proof)
        require(state.fullyAcceptedHeadId == state.headId)
        require(proof.sourceRevisionSha256 == nodes.getValue(state.headId).sourceRevisionSha256)
        require(proof.profileSha256 == state.profileSha256 && proof.indexSha256 == state.indexSha256 && proof.cleanupVerified)
        require(proof.originalBinarySha256?.matches(REPAIR_BLOB_DIGEST) == true &&
            proof.rebuiltBinarySha256?.matches(REPAIR_BLOB_DIGEST) == true)
        require(state.runs.any { run -> run.status == RepairRunStatus.FULLY_ACCEPTED &&
            run.acceptedHeadId == state.fullyAcceptedHeadId && run.regressionCorpusSha256 == proof.regressionCorpusSha256 &&
            run.originalBinarySha256 == proof.originalBinarySha256 && run.expectedObservationsSha256 != null }) {
            "accepted source proof is not bound to a fully accepted run"
        }
    }
    state.nodes.forEach { node ->
        if (node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.PROVISIONAL)) {
            val proof = requireNotNull(node.validationProof) { "repair revision lacks source-bound validation proof: ${node.id}" }
            requireProofDigests(proof)
            val metadata = requireNotNull(node.repairMetadata) { "repair revision lacks owning run metadata: ${node.id}" }
            val run = requireNotNull(metadata.runId?.let(runs::get)) { "repair revision names no durable run: ${node.id}" }
            require(proof.sourceRevisionSha256 == node.sourceRevisionSha256 && proof.cleanupVerified)
            require(proof.profileSha256 == state.profileSha256 && proof.indexSha256 == state.indexSha256)
            require(proof.regressionCorpusSha256 == metadata.regressionCorpusSha256 &&
                proof.regressionCorpusSha256 == run.regressionCorpusSha256 && proof.originalBinarySha256 == run.originalBinarySha256)
            if (node.status == ModuleRevisionStatus.ACCEPTED) {
                require(node.evidenceKind == "valid" && proof.originalBinarySha256 != null && proof.rebuiltBinarySha256 != null &&
                    metadata.retainedRegressionIds.isNotEmpty() && run.status == RepairRunStatus.FULLY_ACCEPTED && run.acceptedHeadId == node.id)
            }
        }
    }
    require(state.runs.size <= state.budget.maximumRevisionNodes)
    val validationIds = state.runs.flatMap { run -> run.validationObservations.entries.map { it.invocation.id } +
        listOfNotNull(run.validationDiagnostic?.invocation?.id) }
    require(validationIds.distinct().size == validationIds.size)
    state.runs.forEachIndexed { index, run ->
        require(run.id == "run_${(index + 1).toString().padStart(8, '0')}")
        require(run.baselineId in nodes && (run.acceptedHeadId == null || run.acceptedHeadId in nodes))
        require(run.provisionalHeadId == null || nodes[run.provisionalHeadId]?.status == ModuleRevisionStatus.PROVISIONAL)
        require(index == state.runs.lastIndex || run.terminal)
        val attempts = state.nodes.count { it.repairMetadata?.runId == run.id } +
            if (state.pending?.repairMetadata?.runId == run.id) 1 else 0
        require(run.attemptedCount == attempts) { "repair run attempt count differs from its durable attempts" }
        run.validationDiagnostic?.let { binding ->
            binding.requireRetainedBudget(state.budget.maximumIndexEvidenceBytes)
            val invocation = binding.invocation
            val pending = state.pending?.takeIf { it.id == invocation.candidateRevisionId }
            val node = nodes[invocation.candidateRevisionId]
            require((pending != null) != (node != null))
            require(if (pending != null) pending.repairMetadata?.runId == run.id
                else node?.id == run.baselineId || node?.repairMetadata?.runId == run.id)
            requireRepairValidationDiagnosticAssociation(binding, run.id, state.profileSha256, state.indexSha256,
                run.regressionCorpusSha256, invocation.candidateRevisionId,
                requireNotNull(pending?.candidateSourceRevisionSha256 ?: node?.sourceRevisionSha256))
        }
        run.validationObservations.entries.forEach { observation ->
            observation.requireRetainedBudget(state.budget.maximumIndexEvidenceBytes)
            val invocation = observation.invocation
            val pending = state.pending?.takeIf { it.id == invocation.candidateRevisionId }
            val node = nodes[invocation.candidateRevisionId]
            require((pending != null) != (node != null))
            require(if (pending != null) pending.repairMetadata?.runId == run.id
                else node?.id == run.baselineId || node?.repairMetadata?.runId == run.id)
            requireRepairValidationObservationAssociation(observation, run.id, state.profileSha256, state.indexSha256,
                run.regressionCorpusSha256, invocation.candidateRevisionId,
                requireNotNull(pending?.candidateSourceRevisionSha256 ?: node?.sourceRevisionSha256), run.originalBinarySha256)
            if (node?.repairMetadata?.runId == run.id && node.validationProof != null)
                require(observation.proof == node.validationProof)
        }
        val failedAttempt = run.rollbackFailureAttemptId
        if (failedAttempt != null) {
            val pending = state.pending?.takeIf { it.id == failedAttempt }
            val node = nodes[failedAttempt]
            require((pending != null) != (node != null)) { "rollback failure attempt is missing or duplicated" }
            val record = requireNotNull(pending?.rollbackRecord ?: node?.rollbackRecord)
            require(record.attemptId == failedAttempt && record.runId == run.id &&
                record.failureStage != null && record.failureCode != null &&
                record.state == run.rollbackResolution &&
                record.state == (if (pending != null) RepairRollbackState.RESTORE_FAILED_UNRESOLVED
                    else RepairRollbackState.RESTORED_AFTER_FAILURE)) { "rollback failure run is cross-paired with its record" }
            require((pending?.repairMetadata ?: node?.repairMetadata)?.runId == run.id)
            require(node == null || node.status == ModuleRevisionStatus.REJECTED)
        }
        // Schema one cannot carry a failure link. It must not hide a committed failure record
        // merely by downgrading the owning run; standalone records still name no run here.
        val failedRecords = state.nodes.filter { it.repairMetadata?.runId == run.id }
            .mapNotNull { it.rollbackRecord }.plus(listOfNotNull(state.pending?.takeIf {
                it.repairMetadata?.runId == run.id }?.rollbackRecord)).filter { it.failureCode != null }
        require(failedRecords.all { it.attemptId == failedAttempt }) { "rollback record lacks its run failure link" }
        if (run.status == RepairRunStatus.FULLY_ACCEPTED) {
            require(run.originalBinarySha256 != null && run.expectedObservationsSha256 != null)
            val accepted = nodes.getValue(requireNotNull(run.acceptedHeadId))
            require(if (run.acceptedHeadId == run.baselineId) run.attemptedCount == 0 && run.provisionalHeadId == null
                else accepted.status == ModuleRevisionStatus.ACCEPTED && accepted.repairMetadata?.runId == run.id)
        }
    }
    state.pending?.let { pending ->
        if (pending.legacyRecoveryRequired) {
            require(state.schemaVersion >= 4 && pending.rollbackRecord != null) {
                "legacy pending repair has no durable recovery marker"
            }
            require(pending.rollbackRecord.legacyPendingStateUnknown)
        }
        if (pending.repairMetadata?.runId == null) {
            require(state.schemaVersion >= 4) {
                "pending repair without a run is not a supported legacy or standalone attempt"
            }
            require(state.runs.none { !it.terminal }) {
                "standalone pending repair cannot belong to an active run"
            }
            require(pending.parentId == state.headId || pending.parentId == state.provisionalHeadId) {
                "standalone repair must descend from the canonical or provisional head"
            }
            if (pending.parentId == state.provisionalHeadId) require(pending.detached) {
                "standalone repair from a provisional parent must remain detached"
            }
            require(pending.promotionChanges.isEmpty()) {
                "standalone repair cannot publish an unvalidated provisional tree"
            }
            return@let
        }
        require(pending.detached)
        val metadata = requireNotNull(pending.repairMetadata) { "pending repair lacks owning run metadata" }
        val run = requireNotNull(metadata.runId?.let(runs::get)) { "pending repair names no durable run" }
        require(run.id == state.runs.lastOrNull()?.id &&
            run.status in setOf(RepairRunStatus.RUNNING, RepairRunStatus.VALIDATION_FAILED, RepairRunStatus.ROLLBACK_FAILED) &&
            metadata.regressionCorpusSha256 == run.regressionCorpusSha256)
        val canonical = revisionSourcesAt(state.nodes, state.headId)
        val candidate = revisionSourcesAt(state.nodes, pending.parentId).toMutableMap()
        pending.candidateChanges.forEach { candidate[it.path] = IndexedSource(it.path, it.afterBytes, it.afterSha256) }
        if (pending.promotionChanges.isNotEmpty()) {
            require(pending.candidateSourceRevisionSha256 != null)
            val expected = candidate.toSortedMap().mapNotNull { (path, after) ->
                val before = canonical.getValue(path)
                if (before == after) null else RevisionFileDelta(path, before.sha256, before.bytes,
                    after.sha256, before.sha256, after.sha256, after.bytes)
            }
            require(pending.promotionChanges == expected) { "repair publication delta is not bound to canonical source and candidate lineage" }
            require(expected.all { it.path in state.editablePaths })
        }
    }
}

private fun requireLegacyRollbackInstallMarker(record: RepairRollbackRecord, hasChanges: Boolean) {
    if (record.legacyPendingStateUnknown) {
        if (hasChanges) require(record.candidateSourceInstallStarted == null) {
            "legacy changed attempt has a fabricated source-install marker"
        } else require(record.candidateSourceInstallStarted == false) {
            "legacy unchanged attempt has a fabricated source-install marker"
        }
    }
}

private fun validatePendingRollbackRecord(
    record: RepairRollbackRecord,
    pending: PendingAttempt,
    targetId: String,
    targetSha256: String,
) {
    require(record.attemptId == pending.id && record.runId == pending.repairMetadata?.runId)
    require(record.targetRevisionId == targetId && record.expectedSourceRevisionSha256 == targetSha256) {
        "pending rollback record is not bound to its exact target revision"
    }
    require(record.legacyPendingStateUnknown == pending.legacyRecoveryRequired)
    requireLegacyRollbackInstallMarker(record, pending.candidateChanges.isNotEmpty())
    if (record.state == RepairRollbackState.NOT_REQUIRED_VERIFIED) {
        require(record.candidateSourceInstallStarted == false && record.failureCode == null) {
            "rollback was marked unnecessary after a source exchange may have started"
        }
    }
    if (record.state == RepairRollbackState.RESTORE_FAILED_UNRESOLVED) {
        require(record.failureStage != null && record.failureCode != null)
    }
    if (record.state == RepairRollbackState.RESTORED_AFTER_FAILURE) {
        require(record.failureStage != null && record.failureCode != null)
    }
}

private data class RecordedGraphMetadata(
    val acceptedSources: Map<String, IndexedSource>,
    val referencedBlobSizes: Map<String, Long>,
)

private fun validateRecordedGraphHeader(
    state: RevisionGraphState,
    binding: RepairRecoveryBinding,
): List<String> {
    require(
        binding.profileId == state.profileId &&
            binding.profileSha256 == state.profileSha256 &&
            binding.budgetSha256 == sha256(state.budget.toJson().toByteArray(Charsets.UTF_8)) &&
            binding.editablePaths == state.editablePaths &&
            binding.indexSha256 == state.indexSha256,
    ) { "revision graph differs from its immutable recovery authorization" }
    return validateRecordedGraphShape(state, binding.sourcePaths)
}

/** Pure declared-source shape only; never manufactures a recovery authorization. */
private fun validateRecordedGraphShape(state: RevisionGraphState, authorizedSourcePaths: List<String>? = null): List<String> {
    require(state.profileId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) {
        "revision graph profile ID is invalid"
    }
    require(state.profileSha256.matches(Regex("[0-9a-f]{64}"))) { "revision graph profile digest is invalid" }
    require(state.indexSha256.matches(Regex("[0-9a-f]{64}"))) { "revision graph index digest is invalid" }
    validateRegressionCorpus(state.retainedRegressionInputs, state.budget)
    require(state.regressionCorpusSha256 == regressionCorpusSha256(state.retainedRegressionInputs)) {
        "revision graph retained regression corpus digest does not match its inputs"
    }
    require(state.editablePaths.isNotEmpty() &&
        state.editablePaths == state.editablePaths.map(::normalizedRelative).distinct().sorted()) {
        "revision graph editable paths are not normalized, unique, and sorted"
    }
    require(state.storedBlobBytes >= 0) { "revision graph stored-blob accounting is negative" }
    require(state.nodes.isNotEmpty() && state.nodes.size <= state.budget.maximumRevisionNodes)
    require(state.nodes.map { it.id }.distinct().size == state.nodes.size) { "revision graph node IDs are not unique" }
    val rootPaths = state.nodes.first().changes.map { it.path }
    require(rootPaths == rootPaths.map(::normalizedRelative).distinct().sorted() && rootPaths.isNotEmpty()) {
        "revision graph root source paths are invalid"
    }
    require(rootPaths.size <= state.budget.maximumSourceFiles)
    if (authorizedSourcePaths != null) require(rootPaths == authorizedSourcePaths) {
        "revision graph root source paths differ from its immutable recovery authorization"
    }
    require(rootPaths.none(::isReservedRepairInternalPath)) {
        "revision graph source paths collide with repair-owned state or projections"
    }
    require(state.editablePaths.all { it in rootPaths }) { "revision graph editable path is absent from its root" }
    return immutableList(rootPaths)
}

private fun validateRecordedGraphBody(state: RevisionGraphState, rootPaths: List<String>): RecordedGraphMetadata {
    val referencedSizes = TreeMap<String, Long>()
    fun validatePortableEvidence(kind: String?, summary: String?, artifact: String?) {
        require((kind == null) == (summary == null))
        listOf(kind, summary, artifact).filterNotNull().forEach { value ->
            require(value.toByteArray(Charsets.UTF_8).size.toLong() <= state.budget.maximumRequestBytes) {
                "revision graph evidence field exceeds the request-byte budget"
            }
        }
    }
    fun validatePortableMetadata(metadata: RevisionRepairMetadata?, expectedIteration: Int): Int {
        metadata ?: return expectedIteration - 1
        require(metadata.iterationIndex == expectedIteration &&
            metadata.iterationIndex <= state.budget.maximumRevisionNodes)
        require(metadata.prompt.toByteArray(Charsets.UTF_8).size.toLong() <= state.budget.maximumRequestBytes)
        require(metadata.summary == null ||
            metadata.summary.toByteArray(Charsets.UTF_8).size.toLong() <= state.budget.maximumRequestBytes)
        require(metadata.failureKind.toByteArray(Charsets.UTF_8).size.toLong() <= state.budget.maximumRequestBytes)
        require(metadata.retainedRegressionIds == metadata.retainedRegressionIds.distinct().sorted())
        val retained = metadata.retainedRegressionIds.map { id ->
            state.retainedRegressionInputs.singleOrNull { it.id == id }
                ?: error("repair metadata references an unknown retained regression input: $id")
        }
        require(metadata.regressionCorpusSha256 == regressionCorpusSha256(retained))
        validatePortableEvidence(metadata.before?.kind, metadata.before?.summary, metadata.before?.artifactPath)
        return metadata.iterationIndex
    }
    fun validateDeltaPortable(delta: RevisionFileDelta, allowMissingBefore: Boolean = false) {
        require(delta.path in rootPaths) { "revision graph references an unknown source path: ${delta.path}" }
        require(delta.afterSha256.matches(Regex("[0-9a-f]{64}")) && delta.afterBlobSha256 == delta.afterSha256)
        require(delta.afterBytes in 0..state.budget.maximumSourceFileBytes)
        if (allowMissingBefore) {
            require(delta.beforeSha256 == null && delta.beforeBytes == null && delta.beforeBlobSha256 == null)
        } else {
            require(delta.beforeSha256?.matches(Regex("[0-9a-f]{64}")) == true)
            require(delta.beforeBytes in 0..state.budget.maximumSourceFileBytes)
            require(delta.beforeBlobSha256 == delta.beforeSha256)
        }
        listOfNotNull(
            delta.beforeBlobSha256?.let { it to requireNotNull(delta.beforeBytes) },
            delta.afterBlobSha256 to delta.afterBytes,
        ).forEach { (digest, bytes) ->
            require(digest.matches(Regex("[0-9a-f]{64}"))) { "repair blob digest is invalid" }
            val previous = referencedSizes.putIfAbsent(digest, bytes)
            require(previous == null || previous == bytes) { "repair blob has inconsistent sizes: $digest" }
        }
    }

    var derivedHead: String? = null
    var priorOrdinal = -1
    var priorRepairIteration = 0
    var accepted = sortedMapOf<String, IndexedSource>()
    state.nodes.forEachIndexed { nodeIndex, node ->
        require(node.id.matches(Regex("(?:root|revision)_[A-Za-z0-9_]+"))) { "revision graph node ID is invalid" }
        require(node.ordinal == priorOrdinal + 1) { "revision graph ordinals are not contiguous" }
        priorOrdinal = node.ordinal
        require(node.sourceRevisionSha256.matches(Regex("[0-9a-f]{64}")))
        require(node.changes.map { it.path } == node.changes.map { it.path }.distinct().sorted())
        require(node.changedModules == node.changedModules.distinct().sorted())
        require(node.invalidatedModules == node.invalidatedModules.distinct().sorted())
        require(node.changedModules.intersect(node.invalidatedModules.toSet()).isEmpty())
        validatePortableEvidence(node.evidenceKind, node.evidenceSummary, node.evidenceArtifact)
        node.repairMetadata?.let {
            priorRepairIteration = validatePortableMetadata(it, priorRepairIteration + 1)
        }
        require(node.publicationChanges.map { it.path } ==
            node.publicationChanges.map { it.path }.distinct().sorted()) {
            "revision graph physical publication changes are not unique and sorted: ${node.id}"
        }
        node.publicationChanges.forEach { validateDeltaPortable(it) }
        if (state.schemaVersion >= 5) {
            require(node.publicationPreimageMetadata.keys.sorted() == node.publicationChanges.map { it.path }.sorted()) {
                "schema-5 physical preimage metadata does not exactly cover publication changes: ${node.id}"
            }
            node.publicationChanges.forEach { change ->
                val metadata = node.publicationPreimageMetadata.getValue(change.path)
                require(metadata.size == change.beforeBytes &&
                    metadata.retainedName == sourceTransactionPreimageName(change.path, node.id)) {
                    "schema-5 physical preimage metadata is not bound to its publication: ${node.id}:${change.path}"
                }
            }
        }
        if (nodeIndex == 0) {
            require(node.parentId == null && node.ordinal == 0 && node.status == ModuleRevisionStatus.ROOT)
            require(node.changedModules.isEmpty() && node.invalidatedModules.isEmpty())
            require(node.repairMetadata == null && !node.recoveredAfterCrash)
            require(node.changes.map { it.path } == rootPaths)
            node.changes.forEach { validateDeltaPortable(it, allowMissingBefore = true) }
            val rootSourceBytes = node.changes.fold(0L) { total, change -> Math.addExact(total, change.afterBytes) }
            require(rootSourceBytes <= state.budget.maximumSourceBytes) {
                "revision graph root exceeds the total source-byte budget"
            }
            accepted = node.changes.associateTo(sortedMapOf()) { change ->
                change.path to IndexedSource(change.path, change.afterBytes, change.afterSha256)
            }
            require(node.sourceRevisionSha256 == revisionSha256(accepted.values))
            require(
                node.id == "root_${sha256((state.indexSha256 + "\n" + node.sourceRevisionSha256).toByteArray()).take(24)}",
            ) { "revision graph root ID is not bound to its index and source revision" }
            derivedHead = node.id
        } else {
            require(node.parentId != null &&
                revisionCanonicalBase(state.nodes.take(nodeIndex), node.parentId) == derivedHead &&
                node.status != ModuleRevisionStatus.ROOT) {
                "revision graph node is not attached to the accepted head: ${node.id}"
            }
            require(state.schemaVersion >= 3 || node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.REJECTED))
            require(node.changes.size <= state.budget.maximumPatchFiles) {
                "revision graph node exceeds the patch-file budget: ${node.id}"
            }
            val nodePatchBytes = node.changes.fold(0L) { total, delta ->
                Math.addExact(total, delta.afterBytes)
            }
            require(nodePatchBytes <= state.budget.maximumPatchBytes) {
                "revision graph node exceeds the patch-byte budget: ${node.id}"
            }
            val parentSources = revisionSourcesAt(state.nodes.take(nodeIndex), requireNotNull(node.parentId))
            val candidate = parentSources.toMutableMap()
            node.changes.forEach { delta ->
                validateDeltaPortable(delta)
                val before = parentSources.getValue(delta.path)
                require(delta.beforeSha256 == before.sha256 && delta.beforeBytes == before.bytes) {
                    "revision graph delta is not bound to its accepted parent: ${node.id}:${delta.path}"
                }
                candidate[delta.path] = IndexedSource(delta.path, delta.afterBytes, delta.afterSha256)
            }
            require(node.sourceRevisionSha256 == revisionSha256(candidate.values))
            if (node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.LEGACY_UNVERIFIED)) {
                require(node.changes.isNotEmpty())
                accepted = candidate.toSortedMap()
                derivedHead = node.id
            }
        }
        node.rollbackRecord?.let { record ->
            require(state.schemaVersion >= 4 && node.status == ModuleRevisionStatus.REJECTED)
            require(record.attemptId == node.id && record.runId == node.repairMetadata?.runId)
            require(record.state in setOf(
                RepairRollbackState.RESTORED_VERIFIED,
                RepairRollbackState.RESTORED_AFTER_FAILURE,
                RepairRollbackState.NOT_REQUIRED_VERIFIED,
            ))
            require(record.targetRevisionId == derivedHead) {
                "rollback target differs from the published head: ${node.id}"
            }
            val targetSources = revisionSourcesAt(state.nodes.take(nodeIndex), record.targetRevisionId)
            require(record.expectedSourceRevisionSha256 == revisionSha256(targetSources.values))
            requireLegacyRollbackInstallMarker(record, node.changes.isNotEmpty())
            if (record.state == RepairRollbackState.NOT_REQUIRED_VERIFIED) {
                require(record.candidateSourceInstallStarted == false)
            }
        }
    }
    require(state.headId == derivedHead) { "revision graph head is not derived from its ordered nodes" }
    require(state.nextOrdinal > priorOrdinal)

    state.pending?.let { pending ->
        require(state.nodes.size < state.budget.maximumRevisionNodes)
        require(pending.parentId == (state.provisionalHeadId ?: state.headId) && pending.ordinal == priorOrdinal + 1 &&
            pending.ordinal == state.nextOrdinal - 1)
        require(pending.allowedPaths == pending.allowedPaths.distinct().sorted() && pending.allowedPaths.isNotEmpty())
        require(pending.allowedPaths.all { it in state.editablePaths })
        val expectedIdMaterial = pending.parentId + "\n" + pending.ordinal + "\n" +
            pending.allowedPaths.joinToString("\n")
        require(
            pending.id == "revision_${pending.ordinal.toString().padStart(8, '0')}_${sha256(expectedIdMaterial.toByteArray()).take(16)}",
        ) { "pending repair attempt ID is not bound to its parent and authorization" }
        if (state.schemaVersion >= 5) {
            val metadata = requireNotNull(pending.preimageMetadata) {
                "schema-5 pending repair is missing its preimage metadata commitment"
            }
            if (pending.detached) {
                if (state.schemaVersion < 6) {
                    require(metadata.isEmpty()) { "legacy detached repair cannot invent physical metadata commitments" }
                } else {
                    val published = revisionSourcesAt(state.nodes, revisionCanonicalBase(state.nodes, state.headId))
                    val working = revisionSourcesAt(state.nodes, pending.parentId)
                    val provisionalDeltaPaths = (published.keys + working.keys).filter { path ->
                        published[path]?.let { before -> working[path]?.let { after ->
                            before.sha256 == after.sha256 && before.bytes == after.bytes
                        } } != true
                    }
                    val expectedWitnessPaths = (pending.allowedPaths + provisionalDeltaPaths).distinct().sorted()
                    require(metadata.keys.sorted() == expectedWitnessPaths) {
                        "schema-6 recorded attempt witness does not cover allowed and provisional promotion paths"
                    }
                    metadata.forEach { (path, value) ->
                        require(value.size == published.getValue(path).bytes)
                        require(value.ancestorMetadata.isNotEmpty() && value.ancestorMetadata.first().path == "." &&
                            value.ancestorMetadata.all { it.atimeSeconds != null && it.entryCount != null && it.entriesSha256 != null }) {
                            "schema-6 witness is missing exact ancestor timestamps or entry inventory: $path"
                        }
                        require(value.ancestorMetadata.map { it.path } ==
                            listOf(".") + path.split('/').dropLast(1).mapIndexed { index, _ ->
                                path.split('/').take(index + 1).joinToString("/")
                            }) { "schema-6 ancestor witness does not cover the complete path parent chain: $path" }
                    }
                    require(pending.sourceWitnessSha256?.matches(REPAIR_BLOB_DIGEST) == true) {
                        "schema-6 attempt is missing its complete accepted-source witness commitment"
                    }
                }
            } else {
                validatePendingPreimageAggregate(pending.allowedPaths, pending.preimages, state.budget, metadata)
            }
            if (pending.promotionChanges.isNotEmpty()) require(
                pending.promotionPreimageMetadata?.keys?.sorted() == pending.promotionChanges.map { it.path }.sorted(),
            ) { "schema-5 promotion is missing its physical preimage metadata commitment" }
            pending.promotionChanges.forEach { change ->
                require(pending.promotionPreimageMetadata?.get(change.path)?.size == change.beforeBytes) {
                    "schema-5 promotion preimage metadata size differs from its content commitment: ${change.path}"
                }
                if (state.schemaVersion >= 6) require(
                    pending.promotionPreimageMetadata?.get(change.path) == pending.preimageMetadata?.get(change.path),
                ) { "schema-6 promotion metadata differs from the attempt-time witness: ${change.path}" }
            }
        }
        pending.preimageMetadata.orEmpty().forEach { (path, metadata) ->
            require(metadata.retainedName == sourceTransactionPreimageName(path, pending.id)) {
                "schema-5 preimage name is not bound to its path and transaction: $path"
            }
        }
        pending.promotionPreimageMetadata.orEmpty().forEach { (path, metadata) ->
            require(metadata.retainedName == sourceTransactionPreimageName(path, pending.id)) {
                "schema-5 promotion preimage name is not bound to its path and transaction: $path"
            }
        }
        pending.acceptanceDecision?.let { decision ->
            require(state.schemaVersion >= 6 && pending.detached)
            require(decision.intendedHeadId == pending.id &&
                (pending.repairMetadata?.runId == null || decision.intendedRunId == pending.repairMetadata.runId))
            require(decision.intendedRunStatus == RepairRunStatus.FULLY_ACCEPTED.takeIf { decision.intendedRunId != null })
            validateAcceptanceRunTransition(state, decision)
            validateSchema6DecisionNode(pending, decision)
            require(decision.promotionChanges == pending.promotionChanges)
            require(decision.proof.sourceRevisionSha256 == pending.candidateSourceRevisionSha256 &&
                decision.proof.profileSha256 == state.profileSha256 &&
                decision.proof.indexSha256 == state.indexSha256 &&
                decision.proof.regressionCorpusSha256 == state.regressionCorpusSha256)
            require(decision.stagedFiles.map { it.path } == decision.promotionChanges.map { it.path })
            require(decision.committedNode?.id == decision.intendedHeadId &&
                decision.committedNode?.publicationChanges == decision.promotionChanges &&
                decision.committedNode?.publicationPreimageMetadata == pending.promotionPreimageMetadata.orEmpty())
            decision.stagedFiles.zip(decision.promotionChanges).forEach { (staged, change) ->
                val metadata = requireNotNull(pending.promotionPreimageMetadata?.get(change.path))
                val parent = requireNotNull(metadata.ancestorMetadata.lastOrNull())
                require(staged.stagingName == metadata.retainedName && staged.sha256 == change.afterSha256 &&
                    staged.size == change.afterBytes && staged.device == staged.parentDevice &&
                    staged.mountId == staged.parentMountId && staged.parentDevice == parent.device &&
                    staged.parentInode == parent.inode && staged.parentMountId == parent.mountId &&
                    staged.mode == metadata.mode && staged.uid == metadata.uid && staged.gid == metadata.gid)
            }
            validatePortableEvidence(decision.evidenceKind, decision.evidenceSummary, decision.evidenceArtifact)
        }
        val parentSources = revisionSourcesAt(state.nodes, pending.parentId)
        require(pending.parentSourceRevisionSha256 == revisionSha256(parentSources.values))
        pending.repairMetadata?.let { validatePortableMetadata(it, priorRepairIteration + 1) }
        pending.preimages.forEach { preimage ->
            validateDeltaPortable(preimage)
            val parent = parentSources.getValue(preimage.path)
            require(preimage.beforeSha256 == parent.sha256 && preimage.beforeBytes == parent.bytes)
            require(preimage.afterSha256 == parent.sha256 && preimage.afterBytes == parent.bytes)
        }
        validatePendingPreimageAggregate(pending.allowedPaths, pending.preimages, state.budget,
            pending.preimageMetadata?.takeUnless { pending.detached })
        require(pending.candidateChanges.map { it.path } ==
            pending.candidateChanges.map { it.path }.distinct().sorted())
        require(pending.candidateChanges.size <= state.budget.maximumPatchFiles) {
            "pending repair candidate exceeds the patch-file budget"
        }
        val candidateBytes = pending.candidateChanges.fold(0L) { total, delta ->
            Math.addExact(total, delta.afterBytes)
        }
        require(candidateBytes <= state.budget.maximumPatchBytes) {
            "pending repair candidate exceeds the patch-byte budget"
        }
        require(pending.candidateChanges.all { it.path in pending.allowedPaths })
        val candidate = parentSources.toMutableMap()
        pending.candidateChanges.forEach { delta ->
            validateDeltaPortable(delta)
            val parent = parentSources.getValue(delta.path)
            require(delta.beforeSha256 == parent.sha256 && delta.beforeBytes == parent.bytes)
            candidate[delta.path] = IndexedSource(delta.path, delta.afterBytes, delta.afterSha256)
        }
        if (pending.candidateSourceRevisionSha256 == null) {
            require(pending.candidateChanges.isEmpty())
        } else {
            require(pending.candidateSourceRevisionSha256.matches(Regex("[0-9a-f]{64}")))
            require(pending.candidateChanges.isNotEmpty())
            require(pending.candidateSourceRevisionSha256 == revisionSha256(candidate.values))
        }
        pending.rollbackRecord?.let { record ->
            require(state.schemaVersion >= 4)
            val targetId = if (pending.detached) state.headId else pending.parentId
            val targetSources = revisionSourcesAt(state.nodes, targetId)
            validatePendingRollbackRecord(record, pending, targetId, revisionSha256(targetSources.values))
        }
        // A present pending attempt may legitimately have no rollback record yet.
        Unit
    } ?: require(state.nextOrdinal == priorOrdinal + 1)

    val referencedBytes = referencedSizes.values.fold(0L, Math::addExact)
    require(referencedBytes == state.storedBlobBytes && referencedBytes <= state.budget.maximumStoredBlobBytes)
    return RecordedGraphMetadata(
        Collections.unmodifiableMap(TreeMap(accepted)),
        Collections.unmodifiableMap(TreeMap(referencedSizes)),
    )
}

private fun requireRecordedAcceptedInvocation(
    status: ModuleRevisionStatus,
    metadata: RevisionRepairMetadata,
    attemptId: String,
) {
    if (status == ModuleRevisionStatus.ACCEPTED && metadata.publicationMode == RepairPublicationMode.ACP_RELEASE) {
        requireNotNull(metadata.agentInvocation) {
            "accepted agent-driven repair lacks invocation-bound ACP evidence: $attemptId"
        }
    }
}

private fun validateRecordedInvocationBinding(
    schemaVersion: Int,
    binding: RepairAgentInvocationBinding,
    attemptId: String,
    expectedAssessment: RepairAgentAssessmentStatus,
): String {
    require(schemaVersion >= 2) { "legacy repair graphs cannot contain ACP receipt bindings" }
    val expectedName = "$attemptId.acp-receipt.json"
    require(binding.receiptPath == "reports/repair-revisions/$expectedName") {
        "repair ACP receipt path is cross-paired with a different attempt: $attemptId"
    }
    require(binding.assessmentStatus == expectedAssessment) {
        "repair ACP assessment status disagrees with graph state: $attemptId"
    }
    if (schemaVersion >= 7 && binding.intentPath != null) {
        require(binding.intentPath == "reports/repair-revisions/$attemptId.acp-intent.json" &&
            binding.intentSha256?.matches(REPAIR_BLOB_DIGEST) == true &&
            binding.turnId?.let(::isCanonicalAgentTurnId) == true) {
            "schema-7 repair invocation is missing its pre-dispatch identity: $attemptId"
        }
        if (expectedAssessment in setOf(RepairAgentAssessmentStatus.ACCEPTED, RepairAgentAssessmentStatus.PROVISIONAL)) {
            require(binding.assessmentPath == "reports/repair-revisions/$attemptId.acp-assessment.json" &&
                binding.assessmentSha256?.matches(REPAIR_BLOB_DIGEST) == true) {
                "finalized schema-7 repair is missing its workflow assessment: $attemptId"
            }
        }
    } else if (schemaVersion >= 7) {
        require(binding.intentSha256 == null && binding.turnId == null && binding.assessmentPath == null &&
            binding.assessmentSha256 == null) {
            "legacy schema-6 repair invocation has partial schema-7 provenance: $attemptId"
        }
    }
    if (expectedAssessment == RepairAgentAssessmentStatus.ACCEPTED) {
        require(binding.receiptReleaseComplete && binding.terminalOutcome == "returned-completed") {
            "accepted repair lacks release-complete ACP evidence: $attemptId"
        }
    }
    return expectedName
}

private fun requireRecordedFinalizedChanges(binding: RepairAgentInvocationBinding, changes: List<RevisionFileDelta>, attemptId: String) {
    require(binding.resultChangesSha256 == recordedAgentChangeSetSha256(changes)) {
        "accepted repair changes differ from the bound ACP result: $attemptId"
    }
}

private fun requireRecordedPendingChanges(binding: RepairAgentInvocationBinding, changes: List<RevisionFileDelta>, attemptId: String) {
    require(binding.resultChangesSha256 == recordedAgentChangeSetSha256(changes)) {
        "pending repair changes differ from the bound ACP result: $attemptId"
    }
}

private fun recordedAgentChangeSetSha256(changes: List<RevisionFileDelta>): String =
    agentFileChangeSetSha256(changes.map { change ->
        AgentFileChange(
            AgentWorkspacePath("project", change.path),
            AgentFileChangeKind.MODIFIED,
            change.beforeSha256,
            change.afterSha256,
            change.afterBytes,
        )
    })

private fun validateRecordedAgentAssociations(state: RevisionGraphState) {
    state.nodes.forEach { node ->
        node.repairMetadata?.let { metadata ->
            if (state.schemaVersion == 1) {
                require(metadata.agentInvocation == null) { "legacy repair graph contains schema-v2 ACP invocation evidence" }
            } else {
                val assessment = when (node.status) {
                    ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.LEGACY_UNVERIFIED -> RepairAgentAssessmentStatus.ACCEPTED
                    ModuleRevisionStatus.PROVISIONAL -> RepairAgentAssessmentStatus.PROVISIONAL
                    ModuleRevisionStatus.REJECTED -> RepairAgentAssessmentStatus.REJECTED
                    ModuleRevisionStatus.ROOT -> error("repair graph root cannot contain iteration metadata")
                }
                requireRecordedAcceptedInvocation(node.status, metadata, node.id)
                metadata.agentInvocation?.let { binding ->
                    validateRecordedInvocationBinding(state.schemaVersion, binding, node.id, assessment)
                    if (node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.PROVISIONAL)) {
                        requireRecordedFinalizedChanges(binding, node.changes, node.id)
                    }
                }
            }
        }
    }
    state.pending?.let { pending -> pending.repairMetadata?.let { metadata ->
        if (state.schemaVersion == 1) {
            require(metadata.agentInvocation == null) { "legacy pending repair contains schema-v2 ACP invocation evidence" }
        } else metadata.agentInvocation?.let { binding ->
            validateRecordedInvocationBinding(state.schemaVersion, binding, pending.id, RepairAgentAssessmentStatus.PENDING)
            if (pending.candidateSourceRevisionSha256 != null) {
                requireRecordedPendingChanges(binding, pending.candidateChanges, pending.id)
            }
        }
    } }
}

/**
 * In-memory semantic facade only. Caller admission/descriptor continuity is a separate reader layer.
 * No profile/index/store/recovery/source/blob/receipt operation is reachable from this branch.
 */
internal fun recordedRepairHistorySnapshot(
    graphPayload: ByteArray,
    recoveryBindingPayload: ByteArray,
    requestedBudget: RepairResourceBudget,
    declaredGraphs: List<RepairHistoryDeclaredGraph> = emptyList(),
): RepairHistorySnapshot = recordedRepairHistorySnapshot(graphPayload, recoveryBindingPayload, requestedBudget) { consume ->
    declaredGraphs.forEach { input -> consume(input.name, input.bytes) }
}

/** Fixed-envelope bootstrap only; the returned recorded configuration grants no runtime authority. */
internal fun recordedRepairHistoryReadBudget(graphPayload: ByteArray): RepairResourceBudget = try {
    require(graphPayload.isNotEmpty() && graphPayload.size.toLong() <= Int.MAX_VALUE.toLong() - 1)
    val budget = parseCanonicalGraph(graphPayload, "recorded repair graph bootstrap").state.budget.copy()
    val envelope = minOf(Int.MAX_VALUE.toLong() - 1, Math.addExact(budget.maximumGraphBytes,
        Math.multiplyExact(Math.addExact(budget.maximumRevisionNodes.toLong(), 1L), MAXIMUM_MIGRATION_BYTES_PER_NODE)))
    require(graphPayload.size.toLong() <= envelope)
    budget
} catch (_: Throwable) {
    throw RepairHistorySnapshotRefusal()
}

/** Exact G1/B1 correlation before declaration I/O; no state or authority escapes. */
internal fun requireRecordedRepairHistoryBinding(
    graphPayload: ByteArray,
    recoveryBindingPayload: ByteArray,
    requestedBudget: RepairResourceBudget,
) {
    try {
        require(graphPayload.isNotEmpty() && graphPayload.size.toLong() <= revisionGraphReadLimit(requestedBudget))
        require(recoveryBindingPayload.isNotEmpty() && recoveryBindingPayload.size.toLong() <= requestedBudget.maximumGraphBytes)
        val state = parseCanonicalGraph(graphPayload, "recorded repair binding preflight").state
        require(state.budget == requestedBudget)
        val binding = parseCanonicalRecoveryBinding(recoveryBindingPayload)
        validateRecordedGraphHeader(state, binding)
    } catch (_: Throwable) {
        throw RepairHistorySnapshotRefusal()
    }
}

/** The scanner owns each already-captured body until its synchronous consumer returns. */
internal fun recordedRepairHistorySnapshot(
    graphPayload: ByteArray,
    recoveryBindingPayload: ByteArray,
    requestedBudget: RepairResourceBudget,
    scanDeclaredGraphs: (consume: (String, ByteArray) -> Unit) -> Unit,
): RepairHistorySnapshot = recordedRepairHistoryCapture(graphPayload, recoveryBindingPayload,
    requestedBudget, scanDeclaredGraphs).snapshot

/** Same pure admission; private report hints remain outside the presentation snapshot. */
internal fun recordedRepairHistoryCapture(
    graphPayload: ByteArray,
    recoveryBindingPayload: ByteArray,
    requestedBudget: RepairResourceBudget,
    scanDeclaredGraphs: (consume: (String, ByteArray) -> Unit) -> Unit,
): RepairHistoryArtifactCapture = try {
    require(graphPayload.isNotEmpty() && graphPayload.size.toLong() <= revisionGraphReadLimit(requestedBudget))
    require(recoveryBindingPayload.isNotEmpty() &&
        recoveryBindingPayload.size.toLong() <= requestedBudget.maximumGraphBytes)
    val graphBytes = graphPayload.copyOf()
    val bindingBytes = recoveryBindingPayload.copyOf()
    val canonical = parseCanonicalGraph(graphBytes, "recorded repair graph")
    val state = canonical.state
    require(state.budget == requestedBudget)
    requireRevisionGraphAdmission(state, graphBytes.size.toLong(), canonical.nullNodeWire, purpose = DeclaredOriginPurpose.LOCAL_RECORDED) { consume ->
        var examined = 0
        var remaining = requestedBudget.maximumIndexEvidenceBytes
        val names = HashSet<String>()
        scanDeclaredGraphs { name, bytes ->
            examined = Math.addExact(examined, 1)
            require(examined <= requestedBudget.maximumStateDirectoryEntries)
            require(DECLARED_LEGACY_GRAPH_NAME.matches(name) && names.add(name))
            require(bytes.isNotEmpty() &&
                bytes.size.toLong() <= minOf(requestedBudget.maximumGraphBytes, remaining))
            remaining -= bytes.size.toLong()
            consume(name, bytes.copyOf())
        }
    }
    val binding = parseCanonicalRecoveryBinding(bindingBytes)
    validateRepairRunContract(state)
    val rootPaths = validateRecordedGraphHeader(state, binding)
    validateRecordedGraphBody(state, rootPaths)
    validateRecordedAgentAssociations(state)
    recordedHistoryCapture(state, sha256(graphBytes), canonical.nullNodeWire)
} catch (_: Throwable) {
    // Never retain a private parser message, source path, cause or suppressed exception.
    throw RepairHistorySnapshotRefusal()
}

/** Compare only to these already semantically validated G1 bytes; not a standalone graph validator.
 * The reader must still complete all final declared/G2/B2 checks before publishing this diagnostic.
 */
internal fun compareCapturedRepairHistoryProjection(
    graphPayload: ByteArray,
    historyPayload: ByteArray,
    requestedBudget: RepairResourceBudget,
): RepairHistoryProjectionDiagnostic {
    val state = try {
        require(graphPayload.isNotEmpty() && graphPayload.size.toLong() <= revisionGraphReadLimit(requestedBudget))
        parseCanonicalGraph(graphPayload, "captured projection graph").state.also {
            require(it.budget == requestedBudget)
            requireBoundedIterationProjection(it.nodes, requestedBudget) // Pure feasibility only; never derive/readBlob.
        }
    } catch (_: Throwable) {
        return RepairHistoryProjectionDiagnostic(RepairHistoryProjectionStatus.UNAVAILABLE, RepairHistoryProjectionReason.CANONICAL)
    }
    if (historyPayload.isEmpty() || historyPayload.size.toLong() > requestedBudget.maximumProjectionBytes) {
        return RepairHistoryProjectionDiagnostic(RepairHistoryProjectionStatus.UNAVAILABLE, RepairHistoryProjectionReason.CAPTURE)
    }
    var version: Int? = null
    var digest: String? = null
    var completeEncoding = false
    fun diagnostic(status: RepairHistoryProjectionStatus, reason: RepairHistoryProjectionReason) =
        RepairHistoryProjectionDiagnostic(status, reason, version, historyPayload.size.toLong(), digest)
    return try {
        digest = sha256(historyPayload)
        val text = decodeUtf8Strict(historyPayload, "captured history projection")
        UniqueJsonObjectKeyValidator(text).validate()
        val root = Json.parseToJsonElement(text) as? JsonObject ?: error("history root type")
        version = root["schemaVersion"]?.let { historyInteger(it).also { value -> require(value in 1..4) }.toInt() } ?: 1
        val wireVersion = requireNotNull(version)
        val rootFields = setOf("regressionInputs", "iterations") +
            (if (wireVersion >= 2) setOf("schemaVersion") else emptySet()) +
            (if (wireVersion >= 3) setOf("runs") else emptySet())
        // Explicit schema1 is accepted by old permissive loaders, not an emitted complete wire.
        if (wireVersion == 1 && "schemaVersion" in root) throw HistoryProjectionEncodingRefusal()
        historyFields(root, rootFields, wireVersion)
        val inputsJson = historyArray(root.getValue("regressionInputs"))
        val iterationsJson = historyArray(root.getValue("iterations"))
        require(inputsJson.size <= requestedBudget.maximumRegressionInputs)
        require(iterationsJson.size <= requestedBudget.maximumRevisionNodes)
        val expectedNodes = state.nodes.filter { it.repairMetadata != null }
        historySame(inputsJson.size == state.retainedRegressionInputs.size, RepairHistoryProjectionReason.CORPUS)
        historySame(iterationsJson.size == expectedNodes.size, RepairHistoryProjectionReason.ITERATIONS)
        val work = HistoryProjectionDecodedWork(requestedBudget.maximumProjectionBytes)
        var inputBytes = 0L
        var argumentCount = 0L
        val inputs = inputsJson.mapIndexed { inputIndex, element ->
            val row = historyObject(element)
            historyFields(row, setOf("id", "args", "stdinHex"), wireVersion)
            val id = historyString(row.getValue("id"))
            val arguments = historyArray(row.getValue("args"))
            argumentCount = Math.addExact(argumentCount, arguments.size.toLong())
            require(argumentCount <= requestedBudget.maximumRegressionArguments)
            val args = arguments.map(::historyString)
            val hex = historyString(row.getValue("stdinHex"))
            val size = historyHexSize(hex)
            inputBytes = Math.addExact(inputBytes, id.toByteArray(Charsets.UTF_8).size.toLong())
            args.forEach { inputBytes = Math.addExact(inputBytes, it.toByteArray(Charsets.UTF_8).size.toLong()) }
            inputBytes = Math.addExact(inputBytes, size)
            require(inputBytes <= requestedBudget.maximumRegressionInputBytes)
            val expected = state.retainedRegressionInputs[inputIndex]
            historySame(id == expected.id && args == expected.args && size == expected.stdin.size.toLong(), RepairHistoryProjectionReason.CORPUS)
            ProcessInput(id, args, work.decode(hex))
        }
        val iterations = iterationsJson.mapIndexed { index, element -> historyIteration(element, wireVersion, requestedBudget, work, expectedNodes[index]) }
        val runs = if (wireVersion >= 3) {
            val rows = historyArray(root.getValue("runs"))
            require(rows.size <= requestedBudget.maximumRevisionNodes)
            rows.map { element ->
                val row = historyObject(element)
                val runVersion = historyInteger(row.getValue("schemaVersion")).also { require(it in 1..4) }.toInt()
                val fields = setOf("schemaVersion", "id", "status", "baselineId", "acceptedHeadId", "provisionalHeadId",
                    "regressionCorpusSha256", "maximumAttempts", "attemptedCount", "startedEpochMillis", "deadlineEpochMillis",
                    "expectedObservationsSha256", "originalBinarySha256", "lastEvidence") +
                    (if (runVersion >= 2) setOf("rollbackFailureAttemptId", "rollbackResolution") else emptySet()) +
                    (if (runVersion >= 3) setOf("validationDiagnostic") else emptySet()) +
                    (if (runVersion >= 4) setOf("validationObservations") else emptySet())
                historyFields(row, fields, runVersion)
                val numeric = setOf("schemaVersion", "maximumAttempts", "attemptedCount", "startedEpochMillis", "deadlineEpochMillis")
                numeric.forEach { historyInteger(row.getValue(it)) }
                val nullable = setOf("acceptedHeadId", "provisionalHeadId", "expectedObservationsSha256", "originalBinarySha256",
                    "rollbackFailureAttemptId", "rollbackResolution")
                (fields - numeric - setOf("lastEvidence", "validationDiagnostic", "validationObservations")).forEach { field ->
                    if (field in nullable) historyNullableString(row.getValue(field)) else historyString(row.getValue(field))
                }
                historyEvidence(row.getValue("lastEvidence"), runVersion)
                parseRepairRunState(row.toString())
            }
        } else emptyList()
        val rendered = renderRepairHistoryProjection(iterations, inputs, requestedBudget.maximumProjectionBytes, wireVersion, runs)
        if (!rendered.toByteArray(Charsets.UTF_8).contentEquals(historyPayload)) throw HistoryProjectionEncodingRefusal()
        completeEncoding = true
        historySame(wireVersion == repairHistorySchemaForGraph(state.schemaVersion), RepairHistoryProjectionReason.VERSION)
        historySame(inputs.size == state.retainedRegressionInputs.size, RepairHistoryProjectionReason.CORPUS)
        inputs.zip(state.retainedRegressionInputs).forEach { (actual, expected) ->
            historySame(actual.id == expected.id && actual.args == expected.args && actual.stdin.contentEquals(expected.stdin),
                RepairHistoryProjectionReason.CORPUS)
        }
        val nodes = expectedNodes
        historySame(iterations.size == nodes.size, RepairHistoryProjectionReason.ITERATIONS)
        iterations.zip(nodes).forEach { (actual, node) ->
            val metadata = requireNotNull(node.repairMetadata)
            val summary = metadata.summary ?: if (node.recoveredAfterCrash)
                "repair attempt interrupted before the agent summary was durably recorded" else "repair attempt "+node.id
            val after = node.evidenceKind?.let { RepairEvidence(it, node.evidenceSummary.orEmpty(), node.evidenceArtifact) }
            historySame(actual.index == metadata.iterationIndex && actual.failureKind == metadata.failureKind &&
                actual.prompt == metadata.prompt && actual.summary == summary && actual.retainedRegressionIds == metadata.retainedRegressionIds &&
                actual.before == metadata.before && actual.after == after &&
                actual.succeeded == (node.status == ModuleRevisionStatus.ACCEPTED && node.evidenceKind == "valid"),
                RepairHistoryProjectionReason.METADATA)
            if (wireVersion >= 2) historySame(actual.agentInvocation == metadata.agentInvocation &&
                actual.publicationMode == metadata.publicationMode, RepairHistoryProjectionReason.METADATA)
            if (wireVersion >= 3) {
                val disposition = when (node.status) {
                    ModuleRevisionStatus.ACCEPTED -> RepairAttemptDisposition.FULLY_ACCEPTED
                    ModuleRevisionStatus.PROVISIONAL -> RepairAttemptDisposition.PROVISIONAL
                    ModuleRevisionStatus.REJECTED -> RepairAttemptDisposition.REJECTED
                    else -> RepairAttemptDisposition.LEGACY_UNVERIFIED
                }
                historySame(actual.disposition == disposition && actual.revisionId == node.id &&
                    actual.parentRevisionId == node.parentId && actual.runId == metadata.runId, RepairHistoryProjectionReason.METADATA)
            }
            historySame(actual.patches.size == node.changes.size, RepairHistoryProjectionReason.PATCH)
            actual.patches.zip(node.changes).forEach { (patch, change) ->
                val content = patch.replacementBytes
                historySame(patch.relativePath == change.path && content.size.toLong() == change.afterBytes,
                    RepairHistoryProjectionReason.PATCH)
                val patchDigest = sha256(content)
                historySame(patchDigest == change.afterBlobSha256 && patchDigest == change.afterSha256, RepairHistoryProjectionReason.PATCH)
            }
        }
        historySame(runs.size == state.runs.size, RepairHistoryProjectionReason.RUNS)
        runs.zip(state.runs).forEach { (actual, expected) -> historySame(actual.toJson() == expected.toJson(), RepairHistoryProjectionReason.RUNS) }
        diagnostic(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, RepairHistoryProjectionReason.NONE)
    } catch (difference: HistoryProjectionDifference) {
        if (completeEncoding) diagnostic(RepairHistoryProjectionStatus.DOES_NOT_MATCH_CAPTURED_GRAPH, difference.reason)
        else diagnostic(RepairHistoryProjectionStatus.UNVERIFIABLE_ENCODING, RepairHistoryProjectionReason.ENCODING)
    } catch (_: HistoryProjectionEncodingRefusal) {
        diagnostic(RepairHistoryProjectionStatus.UNVERIFIABLE_ENCODING, RepairHistoryProjectionReason.ENCODING)
    } catch (_: RepairBudgetExceededException) {
        diagnostic(RepairHistoryProjectionStatus.UNVERIFIABLE_ENCODING, RepairHistoryProjectionReason.ENCODING)
    } catch (_: Exception) {
        diagnostic(RepairHistoryProjectionStatus.INVALID, RepairHistoryProjectionReason.ENCODING)
    } catch (_: Throwable) {
        diagnostic(RepairHistoryProjectionStatus.UNAVAILABLE, RepairHistoryProjectionReason.ENCODING)
    }
}

private class HistoryProjectionDifference(val reason: RepairHistoryProjectionReason) : RuntimeException(null, null, false, false)
private class HistoryProjectionEncodingRefusal : RuntimeException(null, null, false, false)
private fun historySame(matches: Boolean, reason: RepairHistoryProjectionReason) { if (!matches) throw HistoryProjectionDifference(reason) }
private fun historyObject(value: JsonElement): JsonObject = value as? JsonObject ?: error("history object type")
private fun historyArray(value: JsonElement): JsonArray = value as? JsonArray ?: error("history array type")
private fun historyString(value: JsonElement): String = (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("history string type")
private fun historyNullableString(value: JsonElement): String? = if (value === JsonNull) null else historyString(value)
private fun historyInteger(value: JsonElement): Long = (value as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull ?: error("history integer type")
private fun historyBoolean(value: JsonElement): Boolean = (value as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull ?: error("history boolean type")
private fun historyFields(value: JsonObject, fields: Set<String>, version: Int) {
    require(value.keys.all { it in fields })
    if (value.keys != fields) {
        if (version < 3) throw HistoryProjectionEncodingRefusal()
        error("incomplete history record")
    }
}
private fun historyHexSize(value: String): Long {
    require(value.length % 2 == 0 && value.all { it in '0'..'9' || it in 'a'..'f' })
    return value.length.toLong() / 2L
}
private class HistoryProjectionDecodedWork(private val limit: Long) {
    private var used = 0L
    fun decode(value: String): ByteArray {
        val next = Math.addExact(used, historyHexSize(value))
        require(next <= limit)
        used = next // BEFORE decoded allocation; no refunds/retries.
        return value.hexToByteArrayStrict()
    }
}
private fun historyEvidence(value: JsonElement, version: Int): RepairEvidence? {
    if (value === JsonNull) return null
    val row = historyObject(value)
    historyFields(row, setOf("kind", "summary", "artifactPath"), version)
    return RepairEvidence(historyString(row.getValue("kind")), historyString(row.getValue("summary")), historyNullableString(row.getValue("artifactPath")))
}
private fun historyIteration(value: JsonElement, version: Int, budget: RepairResourceBudget, work: HistoryProjectionDecodedWork, node: ModuleRevisionNode): RepairIteration {
    val row = historyObject(value)
    val fields = setOf("index", "failureKind", "prompt", "summary", "succeeded", "retainedRegressionIds", "before", "after", "patches") +
        (if (version >= 2) setOf("agentInvocation", "publicationMode") else emptySet()) +
        (if (version >= 3) setOf("disposition", "revisionId", "parentRevisionId", "runId") else emptySet())
    historyFields(row, fields, version)
    val index = historyInteger(row.getValue("index")); require(index in 1..Int.MAX_VALUE.toLong())
    val retained = historyArray(row.getValue("retainedRegressionIds")); require(retained.size <= budget.maximumRegressionInputs)
    val patches = historyArray(row.getValue("patches")); require(patches.size <= budget.maximumSourceFiles)
    historySame(patches.size == node.changes.size, RepairHistoryProjectionReason.PATCH)
    val parsedPatches = patches.mapIndexed { index, element ->
        val patch = historyObject(element)
        if (patch.keys == setOf("relativePath", "replacement")) {
            historyString(patch.getValue("relativePath")); historyString(patch.getValue("replacement"))
            throw HistoryProjectionEncodingRefusal()
        }
        historyFields(patch, setOf("relativePath", "replacementHex"), version)
        val path = historyString(patch.getValue("relativePath"))
        val hex = historyString(patch.getValue("replacementHex"))
        val expected = node.changes[index]
        historySame(path == expected.path && historyHexSize(hex) == expected.afterBytes, RepairHistoryProjectionReason.PATCH)
        RepairPatch(path, work.decode(hex))
    }
    val invocation = if (version >= 2 && row.getValue("agentInvocation") !== JsonNull) {
        val item = historyObject(row.getValue("agentInvocation"))
        historyFields(item, setOf("receiptPath", "receiptSha256", "receiptSchemaVersion", "requestSha256", "resultChangesSha256",
            "terminalOutcome", "receiptReleaseComplete", "assessmentStatus") +
            (if (version >= 4) setOf("intentPath", "intentSha256", "turnId", "assessmentPath", "assessmentSha256") else emptySet()), version)
        val schema = historyInteger(item.getValue("receiptSchemaVersion")); require(schema in 1..Int.MAX_VALUE.toLong())
        RepairAgentInvocationBinding(historyString(item.getValue("receiptPath")), historyString(item.getValue("receiptSha256")), schema.toInt(),
            historyString(item.getValue("requestSha256")), historyString(item.getValue("resultChangesSha256")),
            historyString(item.getValue("terminalOutcome")), historyBoolean(item.getValue("receiptReleaseComplete")),
            RepairAgentAssessmentStatus.valueOf(historyString(item.getValue("assessmentStatus")).uppercase()),
            if (version >= 4) historyNullableString(item.getValue("intentPath")) else null,
            if (version >= 4) historyNullableString(item.getValue("intentSha256")) else null,
            if (version >= 4) historyNullableString(item.getValue("turnId")) else null,
            if (version >= 4) historyNullableString(item.getValue("assessmentPath")) else null,
            if (version >= 4) historyNullableString(item.getValue("assessmentSha256")) else null)
    } else null
    return RepairIteration(index.toInt(), historyString(row.getValue("failureKind")), historyString(row.getValue("prompt")),
        historyString(row.getValue("summary")), parsedPatches, retained.map(::historyString),
        historyEvidence(row.getValue("before"), version), historyEvidence(row.getValue("after"), version),
        historyBoolean(row.getValue("succeeded")), invocation,
        if (version >= 2) RepairPublicationMode.valueOf(historyString(row.getValue("publicationMode")).uppercase()) else RepairPublicationMode.TEST_ONLY_NON_RELEASE,
        if (version >= 3) RepairAttemptDisposition.valueOf(historyString(row.getValue("disposition")).uppercase()) else RepairAttemptDisposition.LEGACY_UNVERIFIED,
        if (version >= 3) historyNullableString(row.getValue("revisionId")) else null,
        if (version >= 3) historyNullableString(row.getValue("parentRevisionId")) else null,
        if (version >= 3) historyNullableString(row.getValue("runId")) else null)
}

private fun recordedHistoryCapture(
    state: RevisionGraphState,
    graphSha256: String,
    wire: NullRollbackNodeWire,
): RepairHistoryArtifactCapture {
    val identities = RepairHistoryIdentityReferences(state.regressionCorpusSha256)
    val artifactPaths = LinkedHashMap<RepairRecordedArtifactReference, String>()
    fun artifact(path: String) = identities.artifact(path).also { artifactPaths[it] = path }
    fun identity(value: String?) = value?.let(identities::revision)
    fun invocation(value: RepairAgentInvocationBinding?) = value?.let {
        RepairRecordedInvocation(it.receiptSha256, it.requestSha256, it.resultChangesSha256, it.assessmentStatus,
            artifact(it.receiptPath), it.receiptSchemaVersion, recordedRepairTerminal(it.terminalOutcome),
            recordedRepairTerminalSha256(it.terminalOutcome), it.receiptReleaseComplete,
            it.turnId, it.intentSha256, it.intentPath?.let(::artifact),
            it.assessmentSha256, it.assessmentPath?.let(::artifact))
    }
    fun evidence(kind: String?, path: String?) = if (kind == null && path == null) null else
        RepairRecordedEvidence(recordedRepairEvidenceKind(kind), path?.let(::artifact))
    val normalObservations = state.runs.flatMap { it.validationObservations.entries }
        .associateBy { it.invocation.runId to it.invocation.candidateRevisionId }
    fun normalObservation(runId: String?, candidateId: String): RepairRecordedValidationObservation? =
        runId?.let { normalObservations[it to candidateId] }?.let { observation ->
            fun observedArtifact(value: RepairValidationObservedArtifact) = RepairRecordedValidationObservedArtifact(
                artifact(value.path), value.sha256, value.bytes)
            RepairRecordedValidationObservation(observation.invocation.commitmentSha256(),
                identities.revision(observation.invocation.candidateRevisionId), observation.proof, observation.outcome,
                observedArtifact(observation.primary), observation.diff?.let(::observedArtifact),
                RepairRecordedValidationContext(state.profileId, state.budget),
                state.runs.single { it.id == runId }.expectedObservationsSha256)
        }
    fun failureKind(value: String?) = when (value) {
        "compile" -> RepairRecordedFailureKind.COMPILE
        "behavior" -> RepairRecordedFailureKind.BEHAVIOR
        else -> RepairRecordedFailureKind.OTHER
    }
    fun rollback(value: RepairRollbackRecord?) = value?.let {
        RepairRecordedRollback(it.schemaVersion, identities.revision(it.attemptId), identity(it.runId),
            identities.revision(it.targetRevisionId), it.expectedSourceRevisionSha256, it.state,
            it.failureStage, it.failureCode, it.observedSourceRevisionSha256, it.legacyPendingStateUnknown,
            it.candidateSourceInstallStarted)
    }
    val attempts = state.nodes.filter { it.status != ModuleRevisionStatus.ROOT }.map { node ->
        val metadata = node.repairMetadata
        RepairRecordedAttempt(RepairRecordedAttemptKind.FINALIZED, identities.revision(node.id),
            identity(node.parentId), node.ordinal,
            if (state.schemaVersion < 3 && node.status == ModuleRevisionStatus.ACCEPTED) ModuleRevisionStatus.LEGACY_UNVERIFIED else node.status,
            node.sourceRevisionSha256,
            identity(node.repairMetadata?.runId), node.repairMetadata?.publicationMode, rollback(node.rollbackRecord),
            invocation(node.repairMetadata?.agentInvocation),
            metadata?.retainedRegressionIds.orEmpty().map { id ->
                identities.case(id, requireNotNull(metadata?.regressionCorpusSha256))
            },
            node.repairMetadata?.iterationIndex, failureKind(node.repairMetadata?.failureKind),
            node.repairMetadata?.before?.let { evidence(it.kind, it.artifactPath) },
            evidence(node.evidenceKind, node.evidenceArtifact), metadata?.regressionCorpusSha256,
            normalObservation(metadata?.runId, node.id))
    }
    val pending = state.pending?.let { pending ->
        val metadata = pending.repairMetadata
        RepairRecordedAttempt(RepairRecordedAttemptKind.PENDING, identities.revision(pending.id), identity(pending.parentId),
            pending.ordinal, null, pending.candidateSourceRevisionSha256, identity(pending.repairMetadata?.runId),
            pending.repairMetadata?.publicationMode, rollback(pending.rollbackRecord), invocation(pending.repairMetadata?.agentInvocation),
            metadata?.retainedRegressionIds.orEmpty().map { id ->
                identities.case(id, requireNotNull(metadata?.regressionCorpusSha256))
            },
            pending.repairMetadata?.iterationIndex, failureKind(pending.repairMetadata?.failureKind),
            pending.repairMetadata?.before?.let { before -> evidence(before.kind, before.artifactPath) }, null,
            metadata?.regressionCorpusSha256, normalObservation(metadata?.runId, pending.id))
    }
    val runs = state.runs.map {
        RepairRecordedRun(it.schemaVersion, identities.revision(it.id), it.status, identities.revision(it.baselineId),
            identity(it.acceptedHeadId), identity(it.provisionalHeadId), it.regressionCorpusSha256, it.maximumAttempts,
            it.attemptedCount, it.startedEpochMillis, it.deadlineEpochMillis, identity(it.rollbackFailureAttemptId),
            it.rollbackResolution, it.validationDiagnostic?.let { binding ->
                RepairRecordedValidationDiagnostic(binding.invocation.commitmentSha256(),
                    identities.revision(binding.invocation.candidateRevisionId), binding.invocation.sourceRevisionSha256,
                    binding.invocation.profileSha256, binding.invocation.indexSha256, binding.invocation.regressionCorpusSha256,
                    binding.runtimeSha256, artifact(binding.receiptPath), binding.receiptSha256, binding.receiptBytes,
                    artifact(binding.diagnosticPath), binding.diagnosticSha256, binding.diagnosticBytes,
                    binding.failureKind, binding.cleanupVerified,
                    RepairRecordedValidationContext(state.profileId, state.budget))
            }, normalObservation(it.id, it.baselineId))
    }
    // An assessed baseline accepts the root itself; expose it only with a proof bound to the root's source.
    val acceptedBaseline = state.nodes.singleOrNull { it.id == state.fullyAcceptedHeadId && it.status == ModuleRevisionStatus.ROOT }
        ?.let { root -> state.acceptedProof?.takeIf { it.sourceRevisionSha256 == root.sourceRevisionSha256 }
            ?.let { proof -> RepairRecordedAcceptedBaseline(identities.revision(root.id), root.sourceRevisionSha256, proof.assurance) } }
    val snapshot = RepairHistorySnapshot(graphSha256, state.schemaVersion, RepairRecordedGraphWire.valueOf(wire.name),
        state.regressionCorpusSha256, identities.revision(state.headId), identity(state.provisionalHeadId),
        identity(state.fullyAcceptedHeadId), runs, attempts, pending,
        state.retainedRegressionInputs.map { identities.case(it.id) }, acceptedBaseline)
    return RepairHistoryArtifactCapture(snapshot, artifactPaths)
}

private fun validateGraphBeforeRecovery(
    state: RevisionGraphState,
    profile: RepairIndexProfile,
    binding: RepairRecoveryBinding,
    blobsDir: Path,
    requestedBudget: RepairResourceBudget,
): Map<String, IndexedSource> {
    validateRepairRunContract(state)
    require(state.budget == requestedBudget) { "revision graph resource budget differs from the requested budget" }
    require(
        state.profileId == profile.profileId() &&
            state.profileSha256 == profile.configurationSha256(requestedBudget),
    ) {
        "revision graph repair profile fingerprint differs from the requested profile"
    }
    val rootPaths = validateRecordedGraphHeader(state, binding)
    if (state.pending?.candidateSourceRevisionSha256 != null) {
        require(profile.authorizesRecoveryLayout(rootPaths, state.editablePaths, state.budget)) {
            "repair profile does not authorize the persisted recovery source paths"
        }
    }

    val (accepted, referencedSizes) = validateRecordedGraphBody(state, rootPaths)
    referencedSizes.forEach { (digest, expectedBytes) ->
        val blob = readStableRegularFile(blobsDir, digest, state.budget.maximumSourceFileBytes)
        require(blob.sha256 == digest && blob.bytes.size.toLong() == expectedBytes) {
            "revision graph blob is corrupt: $digest"
        }
    }
    return accepted
}

/**
 * Reserve with a read-only preimage dependency index, then restore before constructing the
 * canonical index. This deliberately leaves the pending record in place; the fully validated graph instance records the recovered
 * rejection after the source tree is back at its parent revision.
 */
private fun acceptedStateFromDecision(
    source: RevisionGraphState,
    decision: RepairAcceptanceDecision,
): RevisionGraphState {
    val node = requireNotNull(decision.committedNode)
    require(source.schemaVersion >= 6 && source.pending?.acceptanceDecision == decision)
    validateSchema6DecisionNode(requireNotNull(source.pending), decision)
    require(source.nodes.none { it.id == node.id } && node.status == ModuleRevisionStatus.ACCEPTED &&
        node.sourceRevisionSha256 == decision.proof.sourceRevisionSha256)
    validateAcceptanceRunTransition(source, decision)
    val runs = if (decision.intendedRunId == null) source.runs else {
        val runIndex = source.runs.indexOfFirst { it.id == decision.intendedRunId }
        source.runs.mapIndexed { index, run ->
            if (index != runIndex) run else requireNotNull(decision.committedRun)
        }
    }
    val committed = source.copy(
        headId = node.id,
        nodes = source.nodes + node,
        pending = null,
        provisionalHeadId = null,
        fullyAcceptedHeadId = node.id,
        acceptedProof = decision.proof,
        runs = runs,
    )
    return committed.copy(storedBlobBytes = source.storedBlobBytes)
}

/** Verify the complete run transition before any decided source exchange is attempted. */
private fun validateAcceptanceRunTransition(source: RevisionGraphState, decision: RepairAcceptanceDecision) {
    val activeRun = source.runs.lastOrNull()?.takeUnless { it.terminal }
    if (decision.intendedRunId == null) {
        require(decision.committedRun == null && activeRun == null) {
            "schema-6 decision omits the active accepted-run transition"
        }
        return
    }
    val runIndex = source.runs.indexOfFirst { it.id == decision.intendedRunId }
    require(runIndex >= 0 && runIndex == source.runs.lastIndex && !source.runs[runIndex].terminal &&
        activeRun?.id == decision.intendedRunId) {
        "schema-6 accepted run transition is unavailable for deterministic recovery"
    }
    val expected = source.runs[runIndex].copy(
        status = requireNotNull(decision.intendedRunStatus),
        acceptedHeadId = decision.intendedHeadId,
        provisionalHeadId = source.provisionalHeadId,
        lastEvidence = RepairEvidence(decision.evidenceKind, decision.evidenceSummary, decision.evidenceArtifact),
    )
    require(decision.committedRun == expected) {
        "schema-6 decision does not retain the complete accepted run state"
    }
}

/** Authenticate immutable ACP evidence before recovery can publish accepted source bytes. */
private fun validateSchema6DecisionReceipt(
    store: RepairStateStore,
    pending: PendingAttempt,
    decision: RepairAcceptanceDecision,
    preDecisionState: RevisionGraphState,
    budget: RepairResourceBudget,
) {
    val metadata = pending.repairMetadata
    val binding = metadata?.agentInvocation
    if (metadata?.publicationMode == RepairPublicationMode.ACP_RELEASE) {
        requireNotNull(binding) { "schema-6 release decision is missing its ACP receipt binding" }
    }
    val expectedReceiptNames = sortedSetOf<String>()
    binding?.let {
        expectedReceiptNames += validateSchema6ReceiptBinding(
            store = store,
            binding = it,
            attemptId = pending.id,
            promptSha256 = requireNotNull(metadata).prompt,
            expectedAssessment = RepairAgentAssessmentStatus.PENDING,
            expectedChangeSetSha256 = recordedAgentChangeSetSha256(pending.candidateChanges),
            requireReleaseCompletion = metadata.publicationMode == RepairPublicationMode.ACP_RELEASE,
        )
    }
    decision.committedNode?.let { committedNode ->
        committedNode.repairMetadata?.agentInvocation?.let { acceptedBinding ->
            require(binding != null && acceptedBinding == binding.copy(
                assessmentStatus = RepairAgentAssessmentStatus.ACCEPTED,
            )) { "schema-6 accepted node does not retain the authenticated ACP receipt binding" }
        }
    }
    // Authenticate every receipt referenced by retained graph nodes, including provisional
    // ancestors folded into this physical publication. These checks use only immutable graph
    // bindings and receipt bytes; they do not depend on the source index.
    decision.committedNode?.let { committedNode ->
        // The committed node replaces the pending attempt's logical record, so it is covered by
        // the pending receipt above and its finalized binding equality check.
        committedNode.id
    }
    preDecisionState.nodes.forEach { node ->
        val metadataForNode = node.repairMetadata ?: return@forEach
        val nodeBinding = metadataForNode.agentInvocation ?: return@forEach
        val assessment = when (node.status) {
            ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.LEGACY_UNVERIFIED -> RepairAgentAssessmentStatus.ACCEPTED
            ModuleRevisionStatus.PROVISIONAL -> RepairAgentAssessmentStatus.PROVISIONAL
            ModuleRevisionStatus.REJECTED -> RepairAgentAssessmentStatus.REJECTED
            ModuleRevisionStatus.ROOT -> error("root node cannot contain an ACP invocation receipt")
        }
        expectedReceiptNames += validateSchema6ReceiptBinding(
            store = store,
            binding = nodeBinding,
            attemptId = node.id,
            promptSha256 = metadataForNode.prompt,
            expectedAssessment = assessment,
            expectedChangeSetSha256 = recordedAgentChangeSetSha256(node.changes)
                .takeIf { node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.PROVISIONAL) },
            requireReleaseCompletion = node.status == ModuleRevisionStatus.ACCEPTED &&
                metadataForNode.publicationMode == RepairPublicationMode.ACP_RELEASE,
        )
    }
    val diskReceiptNames = store.revisionFileNames(repairRevisionDirectoryEntryLimit(budget))
        .filter { it.matches(Regex("revision_[A-Za-z0-9_]+\\.acp-receipt\\.json")) }
        .toSortedSet()
    require(diskReceiptNames == expectedReceiptNames) {
        "schema-6 ACP receipt inventory differs from retained graph bindings"
    }
}

/** Authenticate schema-7 intent and assessment before a durable decision can exchange source files. */
private fun validateSchema7DecisionEvidence(
    store: RepairStateStore,
    pending: PendingAttempt,
    decision: RepairAcceptanceDecision,
    state: RevisionGraphState,
) {
    if (state.schemaVersion < 7) return
    state.nodes.filter { it.status != ModuleRevisionStatus.ROOT }.forEach { node ->
        validateSchema7RetainedNodeEvidence(store, node, state)
    }

    val pendingMetadata = pending.repairMetadata
    val retainedMetadata = state.nodes.mapNotNull { it.repairMetadata } + listOfNotNull(pendingMetadata)
    val expectedIntentNames = retainedMetadata.flatMap { retained ->
        listOfNotNull(retained.turnIntent?.intentPath, retained.agentInvocation?.intentPath)
    }.map { it.substringAfterLast('/') }.toSortedSet()
    val expectedAssessmentNames = retainedMetadata.mapNotNull { it.agentInvocation?.assessmentPath }
        .map { it.substringAfterLast('/') }.toSortedSet()
    val names = store.revisionFileNames(repairRevisionDirectoryEntryLimit(state.budget))
    val observedIntentNames = names.filter { it.matches(Regex("revision_[A-Za-z0-9_]+\\.acp-intent\\.json")) }
        .toSortedSet()
    val observedAssessmentNames = names.filter {
        it.matches(Regex("revision_[A-Za-z0-9_]+\\.acp-assessment\\.json"))
    }.toSortedSet()
    require(observedIntentNames == expectedIntentNames && observedAssessmentNames == expectedAssessmentNames) {
        "schema-7 recovery turn evidence inventory differs from retained graph bindings"
    }

    val metadata = pendingMetadata ?: return
    val intentBinding = metadata.turnIntent
    val binding = metadata.agentInvocation
    if (intentBinding == null && binding?.intentPath == null) return // historical schema-6 invocation
    val invocation = requireNotNull(binding) {
        "schema-7 recovery turn intent has no invocation receipt binding: ${pending.id}"
    }

    validateRecordedInvocationBinding(7, invocation, pending.id, RepairAgentAssessmentStatus.PENDING)
    val expectedReceiptName = "${pending.id}.acp-receipt.json"
    val receiptFile = store.readRevisionFile(expectedReceiptName, MAXIMUM_REPAIR_ACP_RECEIPT_BYTES)
    require(receiptFile.sha256 == invocation.receiptSha256) {
        "schema-7 recovery receipt digest differs from its graph binding: ${pending.id}"
    }
    val receipt = verifyAcpExecutionReceiptDocument(
        receiptFile.bytes,
        TRACE_REPAIR_ACP_RECEIPT_KIND,
        TRACE_REPAIR_ACP_TASK_FIELD,
        pending.id,
    )
    require(receipt.schemaVersion == invocation.receiptSchemaVersion &&
        receipt.requestSha256 == invocation.requestSha256 &&
        receipt.promptSha256 == metadata.prompt &&
        receipt.resultChangesSha256 == invocation.resultChangesSha256 &&
        receipt.terminalOutcome == invocation.terminalOutcome &&
        receipt.releaseComplete == invocation.receiptReleaseComplete &&
        invocation.resultChangesSha256 == recordedAgentChangeSetSha256(pending.candidateChanges)) {
        "schema-7 recovery receipt is cross-paired with its pending candidate: ${pending.id}"
    }

    val turn = requireNotNull(intentBinding) { "schema-7 recovery is missing its turn intent binding: ${pending.id}" }
    val expectedIntentName = "${pending.id}.acp-intent.json"
    require(turn.intentPath == "reports/repair-revisions/$expectedIntentName" &&
        invocation.intentPath == turn.intentPath && invocation.intentSha256 == turn.intentSha256 &&
        invocation.turnId == turn.turnId) {
        "schema-7 recovery turn intent references disagree: ${pending.id}"
    }
    val intentFile = store.readRevisionFile(expectedIntentName, MAXIMUM_REPAIR_INTENT_BYTES.toLong())
    require(intentFile.sha256 == turn.intentSha256) {
        "schema-7 recovery turn intent digest differs from its graph binding: ${pending.id}"
    }
    val intent = AgentTurnIntent.parse(intentFile.bytes)
    require(intent.turnId == turn.turnId && intent.taskId == pending.id && intent.attemptId == pending.id &&
        intent.profileSha256 == state.profileSha256 && intent.beforeSha256 == pending.parentSourceRevisionSha256 &&
        intent.requestSha256 == receipt.requestSha256 && intent.policySha256 == receipt.accessPolicySha256 &&
        receipt.schemaVersion == 3 && receipt.turnIdentity?.turnId == intent.turnId &&
        receipt.turnIdentity.taskId == intent.taskId && receipt.turnIdentity.requestSha256 == intent.requestSha256) {
        "schema-7 recovery turn intent is cross-paired with its receipt: ${pending.id}"
    }

    val assessmentName = "${pending.id}.acp-assessment.json"
    require(binding.assessmentPath == "reports/repair-revisions/$assessmentName" &&
        invocation.assessmentSha256 != null) {
        "schema-7 recovery is missing its durable assessment reference: ${pending.id}"
    }
    val assessmentFile = store.readRevisionFile(assessmentName, MAXIMUM_REPAIR_ASSESSMENT_BYTES.toLong())
    require(assessmentFile.sha256 == invocation.assessmentSha256) {
        "schema-7 recovery assessment digest differs from its graph binding: ${pending.id}"
    }
    val assessment = AcpChangeAssessment.parse(assessmentFile.bytes)
    val normalizedStop = receipt.terminalOutcome.takeIf { it.startsWith("returned-") }
        ?.removePrefix("returned-")
        ?.let { decompengine.agent.AgentStopReason.valueOf(it.uppercase().replace('-', '_')) }
    require(assessment.turnId == intent.turnId && assessment.intentSha256 == intent.sha256 &&
        assessment.receiptSha256 == invocation.receiptSha256 &&
        assessment.changesSha256 == invocation.resultChangesSha256 &&
        assessment.beforeSha256 == pending.parentSourceRevisionSha256 &&
        assessment.afterSha256 == decision.proof.sourceRevisionSha256 &&
        assessment.policySha256 == receipt.accessPolicySha256 &&
        assessment.policyVerdict == decompengine.project.AcpChangePolicyVerdict.ALLOW &&
        assessment.observation == decompengine.project.AcpChangeObservationStatus.COMPLETE &&
        assessment.sessionIdSha256 == receipt.sessionIdCommitmentSha256?.let {
            sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
        } && assessment.updatesSha256 == receipt.updatesSha256 &&
        assessment.normalizedStopReason == normalizedStop &&
        assessment.normalizedStopReason == decompengine.agent.AgentStopReason.COMPLETED &&
        assessment.eligibility == decompengine.project.AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION &&
        assessment.validationStatus == decompengine.project.AcpChangeValidationStatus.PASSED &&
        assessment.validationProofSha256 == listOf(decision.proof.evidenceSha256)) {
        "schema-7 recovery assessment is cross-paired with its receipt or acceptance proof: ${pending.id}"
    }

}

/** Authenticate every already-retained v7 turn that the decision's lineage will preserve. */
private fun validateSchema7RetainedNodeEvidence(
    store: RepairStateStore,
    node: ModuleRevisionNode,
    state: RevisionGraphState,
) {
    if (state.schemaVersion < 7) return
    val metadata = node.repairMetadata ?: return
    val intentBinding = metadata.turnIntent
    val invocation = metadata.agentInvocation
    if (intentBinding == null && invocation?.intentPath == null) return // historical schema-6 record
    val turn = requireNotNull(intentBinding) {
        "schema-7 retained invocation is missing its turn intent binding: ${node.id}"
    }
    val intentName = "${node.id}.acp-intent.json"
    require(turn.intentPath == "reports/repair-revisions/$intentName") {
        "schema-7 retained turn intent path is cross-paired: ${node.id}"
    }
    val intentFile = store.readRevisionFile(intentName, MAXIMUM_REPAIR_INTENT_BYTES.toLong())
    require(intentFile.sha256 == turn.intentSha256) {
        "schema-7 retained turn intent digest differs from its graph binding: ${node.id}"
    }
    val intent = AgentTurnIntent.parse(intentFile.bytes)
    val parentSourceSha256 = node.parentId?.let { parentId ->
        state.nodes.singleOrNull { it.id == parentId }?.sourceRevisionSha256
    }
    require(intent.turnId == turn.turnId && intent.taskId == node.id && intent.attemptId == node.id &&
        intent.profileSha256 == state.profileSha256 && parentSourceSha256 != null &&
        intent.beforeSha256 == parentSourceSha256) {
        "schema-7 retained turn intent is cross-paired with its revision: ${node.id}"
    }

    if (invocation == null) {
        val rollback = node.rollbackRecord
        val verifiedNoInstallRollback = rollback != null && rollback.state in setOf(
            RepairRollbackState.RESTORED_AFTER_FAILURE,
            RepairRollbackState.RESTORED_VERIFIED,
            RepairRollbackState.NOT_REQUIRED_VERIFIED,
        ) && rollback.candidateSourceInstallStarted == false
        require(node.status == ModuleRevisionStatus.REJECTED && verifiedNoInstallRollback &&
            !store.revisionFileExists("${node.id}.acp-receipt.json") &&
            !store.revisionFileExists("${node.id}.acp-assessment.json")) {
            "schema-7 retained intent-only turn lacks verified rejection or has unexpected invocation evidence: ${node.id}"
        }
        return
    }
    val expectedAssessment = when (node.status) {
        ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.LEGACY_UNVERIFIED -> RepairAgentAssessmentStatus.ACCEPTED
        ModuleRevisionStatus.PROVISIONAL -> RepairAgentAssessmentStatus.PROVISIONAL
        ModuleRevisionStatus.REJECTED -> RepairAgentAssessmentStatus.REJECTED
        ModuleRevisionStatus.ROOT -> error("root revision cannot retain a turn invocation")
    }
    validateRecordedInvocationBinding(7, invocation, node.id, expectedAssessment)
    val receiptName = "${node.id}.acp-receipt.json"
    val receiptFile = store.readRevisionFile(receiptName, MAXIMUM_REPAIR_ACP_RECEIPT_BYTES)
    require(receiptFile.sha256 == invocation.receiptSha256) {
        "schema-7 retained receipt digest differs from its graph binding: ${node.id}"
    }
    val receipt = verifyAcpExecutionReceiptDocument(
        receiptFile.bytes,
        TRACE_REPAIR_ACP_RECEIPT_KIND,
        TRACE_REPAIR_ACP_TASK_FIELD,
        node.id,
    )
    require(receipt.schemaVersion == 3 && receipt.requestSha256 == invocation.requestSha256 &&
        receipt.promptSha256 == metadata.prompt &&
        receipt.resultChangesSha256 == invocation.resultChangesSha256 &&
        receipt.terminalOutcome == invocation.terminalOutcome &&
        receipt.releaseComplete == invocation.receiptReleaseComplete &&
        receipt.turnIdentity?.turnId == intent.turnId && receipt.turnIdentity.taskId == intent.taskId &&
        receipt.turnIdentity.requestSha256 == intent.requestSha256 &&
        intent.requestSha256 == receipt.requestSha256 && intent.policySha256 == receipt.accessPolicySha256) {
        "schema-7 retained receipt is cross-paired with its turn intent: ${node.id}"
    }
    val assessmentName = "${node.id}.acp-assessment.json"
    val assessmentPath = invocation.assessmentPath
    val assessmentSha256 = invocation.assessmentSha256
    if (assessmentPath == null && assessmentSha256 == null) {
        require(node.status == ModuleRevisionStatus.REJECTED) {
            "schema-7 accepted or provisional revision lacks a durable assessment: ${node.id}"
        }
        return
    }
    require(assessmentPath == "reports/repair-revisions/$assessmentName" && assessmentSha256 != null) {
        "schema-7 retained assessment path is cross-paired: ${node.id}"
    }
    val assessmentFile = store.readRevisionFile(assessmentName, MAXIMUM_REPAIR_ASSESSMENT_BYTES.toLong())
    require(assessmentFile.sha256 == assessmentSha256) {
        "schema-7 retained assessment digest differs from its graph binding: ${node.id}"
    }
    val assessment = AcpChangeAssessment.parse(assessmentFile.bytes)
    val normalizedStop = receipt.terminalOutcome.takeIf { it.startsWith("returned-") }
        ?.removePrefix("returned-")
        ?.let { decompengine.agent.AgentStopReason.valueOf(it.uppercase().replace('-', '_')) }
    require(assessment.turnId == intent.turnId && assessment.intentSha256 == intent.sha256 &&
        assessment.receiptSha256 == invocation.receiptSha256 &&
        assessment.changesSha256 == invocation.resultChangesSha256 &&
        assessment.beforeSha256 == parentSourceSha256 &&
        assessment.policySha256 == receipt.accessPolicySha256 &&
        assessment.sessionIdSha256 == receipt.sessionIdCommitmentSha256?.let {
            sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
        } && assessment.updatesSha256 == receipt.updatesSha256 &&
        assessment.normalizedStopReason == normalizedStop) {
        "schema-7 retained assessment is cross-paired with its turn intent or receipt: ${node.id}"
    }
    when (node.status) {
        ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.LEGACY_UNVERIFIED -> {
            val proof = requireNotNull(node.validationProof) {
                "schema-7 accepted revision lacks validation proof: ${node.id}"
            }
            require(assessment.eligibility == decompengine.project.AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION &&
                assessment.policyVerdict == decompengine.project.AcpChangePolicyVerdict.ALLOW &&
                assessment.validationStatus == decompengine.project.AcpChangeValidationStatus.PASSED &&
                assessment.afterSha256 == proof.sourceRevisionSha256 &&
                assessment.validationProofSha256 == listOf(proof.evidenceSha256) &&
                invocation.resultChangesSha256 == recordedAgentChangeSetSha256(node.changes)) {
                "schema-7 accepted assessment differs from its revision proof: ${node.id}"
            }
        }
        ModuleRevisionStatus.PROVISIONAL -> {
            val proof = requireNotNull(node.validationProof) {
                "schema-7 provisional revision lacks validation proof: ${node.id}"
            }
            require(assessment.eligibility == decompengine.project.AcpChangePublicationEligibility.PROVISIONAL &&
                assessment.policyVerdict == decompengine.project.AcpChangePolicyVerdict.ALLOW &&
                assessment.validationStatus == decompengine.project.AcpChangeValidationStatus.PASSED &&
                assessment.afterSha256 == proof.sourceRevisionSha256 &&
                assessment.validationProofSha256 == listOf(proof.evidenceSha256) &&
                invocation.resultChangesSha256 == recordedAgentChangeSetSha256(node.changes)) {
                "schema-7 provisional assessment differs from its revision proof: ${node.id}"
            }
        }
        ModuleRevisionStatus.REJECTED -> {
            // Assessment records candidate policy/validation, not the durable publication
            // decision. Ordinary cancellation may reject after assessment persistence as long
            // as the rollback witness proves that candidate source installation never started.
            val restoredBeforeInstall = node.rollbackRecord?.let { rollback ->
                rollback.state in setOf(
                    RepairRollbackState.RESTORED_AFTER_FAILURE,
                    RepairRollbackState.RESTORED_VERIFIED,
                    RepairRollbackState.NOT_REQUIRED_VERIFIED,
                ) &&
                    rollback.candidateSourceInstallStarted == false
            } == true
            val eligible = assessment.eligibility in setOf(
                decompengine.project.AcpChangePublicationEligibility.REJECTED,
                decompengine.project.AcpChangePublicationEligibility.INTERRUPTED,
            ) || restoredBeforeInstall && assessment.eligibility in setOf(
                decompengine.project.AcpChangePublicationEligibility.PROVISIONAL,
                decompengine.project.AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION,
            )
            require(eligible) { "schema-7 rejected assessment has inconsistent eligibility: ${node.id}" }
        }
        ModuleRevisionStatus.ROOT -> error("root revision cannot retain an assessment")
    }
}

private fun validateSchema6ReceiptBinding(
    store: RepairStateStore,
    binding: RepairAgentInvocationBinding,
    attemptId: String,
    promptSha256: String,
    expectedAssessment: RepairAgentAssessmentStatus,
    expectedChangeSetSha256: String?,
    requireReleaseCompletion: Boolean,
): String {
    val expectedName = validateRecordedInvocationBinding(6, binding, attemptId, expectedAssessment)
    if (expectedChangeSetSha256 != null) {
        require(binding.resultChangesSha256 == expectedChangeSetSha256) {
            "schema-6 ACP receipt does not bind its retained change set: $attemptId"
        }
    }
    val receipt = store.readRevisionFile(expectedName, MAXIMUM_REPAIR_ACP_RECEIPT_BYTES)
    require(receipt.sha256 == binding.receiptSha256) {
        "schema-6 ACP receipt digest differs from its immutable graph binding: $attemptId"
    }
    val verified = verifyAcpExecutionReceiptDocument(
        receipt.bytes,
        TRACE_REPAIR_ACP_RECEIPT_KIND,
        TRACE_REPAIR_ACP_TASK_FIELD,
        attemptId,
    )
    require(verified.requestSha256 == binding.requestSha256 &&
        verified.promptSha256 == promptSha256 &&
        verified.resultChangesSha256 == binding.resultChangesSha256 &&
        verified.terminalOutcome == binding.terminalOutcome &&
        verified.releaseComplete == binding.receiptReleaseComplete) {
        "schema-6 ACP receipt content is cross-paired with its graph binding: $attemptId"
    }
    if (requireReleaseCompletion) {
        require(verified.releaseComplete && verified.terminalOutcome == "returned-completed") {
            "schema-6 release receipt is not release-complete: $attemptId"
        }
    }
    return expectedName
}

/** Derive the decided node's module projections from its committed candidate bytes pre-publication. */
private fun validateSchema6DecisionModuleClassifications(
    graphAuthority: Any,
    projectRoot: Path,
    profile: RepairIndexProfile,
    budget: RepairResourceBudget,
    binding: RepairRecoveryBinding,
    committed: RevisionGraphState,
    decision: RepairAcceptanceDecision,
    store: RepairStateStore,
) {
    val recordedNode = requireNotNull(decision.committedNode)
    val committedSources = revisionSourcesAt(committed.nodes, committed.headId)
    val candidateView = object : RepairRecoverySourceView {
        override val sourcePaths: List<String> = binding.sourcePaths
        override val editablePaths: List<String> = binding.editablePaths

        override fun readSource(relative: String): ByteArray {
            require(relative == normalizedRelative(relative))
            val source = requireNotNull(committedSources[relative]) {
                "schema-6 accepted source view omits a bound path: $relative"
            }
            val blob = store.readBlob(source.sha256, budget.maximumSourceFileBytes)
            require(blob.sha256 == source.sha256 && blob.bytes.size.toLong() == source.bytes) {
                "schema-6 accepted source blob differs from its graph commitment: $relative"
            }
            return blob.bytes
        }
    }
    val candidateIndex = SecureRepairRuntime.loadRecoveryIndex(
        graphAuthority,
        projectRoot,
        profile,
        budget,
        candidateView,
    )
    require(candidateIndex.profileId == committed.profileId &&
        candidateIndex.profileSha256 == committed.profileSha256 &&
        candidateIndex.indexSha256 == committed.indexSha256 &&
        candidateIndex.sourceRevisionSha256 == recordedNode.sourceRevisionSha256 &&
        candidateIndex.sourcePaths == binding.sourcePaths &&
        candidateIndex.editablePaths.sorted() == binding.editablePaths) {
        "schema-6 accepted decision candidate index differs from its immutable recovery binding"
    }
    val changedPaths = recordedNode.changes.map { it.path }
    require(recordedNode.changedModules == candidateIndex.changedModules(changedPaths) &&
        recordedNode.invalidatedModules == candidateIndex.downstreamInvalidations(changedPaths)) {
        "schema-6 accepted node module classifications differ from the authenticated candidate index"
    }
}

/**
 * A schema-6 decision must not be able to promote a hand-edited accepted node. Rebuild every
 * index-independent node field from the pending candidate and durable decision payload. The
 * module classifications are separately derived from the authenticated recovery index before
 * any source exchange.
 */
private fun validateSchema6DecisionNode(pending: PendingAttempt, decision: RepairAcceptanceDecision) {
    val recorded = requireNotNull(decision.committedNode) {
        "schema-6 acceptance decision is missing its committed node"
    }
    val expected = finalizedRepairNode(
        pending = pending,
        status = ModuleRevisionStatus.ACCEPTED,
        evidence = RepairEvidence(decision.evidenceKind, decision.evidenceSummary, decision.evidenceArtifact),
        recovered = false,
        rollbackRecord = null,
        changedModules = { recorded.changedModules },
        invalidatedModules = { recorded.invalidatedModules },
        // Decision evidence has already passed validatePortableEvidence; identity normalization
        // makes the persisted value itself part of the deterministic node commitment.
        normalizeText = { it },
        normalizePath = { it },
    ).copy(validationProof = decision.proof)
    require(recorded == expected) {
        "schema-6 accepted node is not derivable from the pending candidate and decision evidence"
    }
}

private fun restorePendingPreimagesBeforeIndex(
    projectRoot: Path,
    store: RepairStateStore,
    profile: RepairIndexProfile,
    requestedBudget: RepairResourceBudget,
    faultInjector: ModuleRevisionFaultInjector?,
    graphAuthority: Any,
) {
    if (!store.graphExists()) return
    val (graphBytes, loaded) = readBoundedRevisionGraph(store, requestedBudget)
    require(store.bindingExists()) {
        "revision graph is missing its immutable recovery authorization"
    }
    val binding = parseCanonicalRecoveryBinding(
        store.readBinding(requestedBudget.maximumGraphBytes),
    )
    validateGraphBeforeRecovery(
        loaded,
        profile,
        binding,
        store.blobsPath,
        requestedBudget,
    )
    val persistedPending = loaded.pending ?: return
    if (persistedPending.acceptanceDecision != null) {
        require(loaded.schemaVersion >= 6 && persistedPending.detached)
        val decision = persistedPending.acceptanceDecision
        // Validate the complete committed graph, proof, run transition, and candidate blobs
        // before the first source exchange. A malformed decision must never mutate source and
        // only then discover that its intended accepted state cannot be committed.
        val committed = acceptedStateFromDecision(loaded, decision)
        validateGraphBeforeRecovery(committed, profile, binding, store.blobsPath, requestedBudget)
        validateSchema6DecisionReceipt(store, persistedPending, decision, loaded, requestedBudget)
        validateSchema7DecisionEvidence(store, persistedPending, decision, loaded)
        validateSchema6DecisionModuleClassifications(
            graphAuthority = graphAuthority,
            projectRoot = projectRoot,
            profile = profile,
            budget = requestedBudget,
            binding = binding,
            committed = committed,
            decision = decision,
            store = store,
        )
        rollForwardRepairPublication(projectRoot, store, decision, faultInjector)
        val expectedSources = revisionSourcesAt(committed.nodes, committed.headId)
        val observedSources = expectedSources.values.map { expected ->
            val observed = readStableRegularFile(projectRoot, expected.path,
                requestedBudget.maximumSourceFileBytes, requireNoExtendedAttributes = true)
            require(observed.sha256 == expected.sha256 && observed.bytes.size.toLong() == expected.bytes) {
                "schema-6 decided source differs from its accepted graph node: ${expected.path}"
            }
            profile.validateSourceContent(expected.path, observed.bytes)
            expected
        }
        require(revisionSha256(observedSources) == requireNotNull(decision.committedNode).sourceRevisionSha256) {
            "schema-6 roll-forward did not produce the recorded accepted source revision"
        }
        val bytes = renderGraph(committed).toByteArray(Charsets.UTF_8)
        require(bytes.size.toLong() <= requestedBudget.maximumGraphBytes)
        requireRevisionGraphAdmission(committed, bytes.size.toLong(), purpose = DeclaredOriginPurpose.LOCAL_RECORDED,
            forEachDeclaredGraph = { consume -> store.forEachDeclaredLegacyGraph(requestedBudget, consume) })
        faultInjector?.hit(ModuleRevisionFaultPoint.BeforeRecoveredAcceptancePersist)
        store.writeGraph(bytes)
        faultInjector?.hit(ModuleRevisionFaultPoint.AfterRecoveredAcceptancePersist)
        return
    }
    if (loaded.schemaVersion >= 6 && persistedPending.detached) {
        // In schema 6 a detached candidate is staged privately until the durable decision.
        // The install marker is therefore the recovery authority boundary: if it is absent or
        // says installation may have started, this path must not guess or invoke legacy restore.
        val rollback = requireNotNull(persistedPending.rollbackRecord) {
            "schema-6 detached attempt is missing its rollback authority"
        }
        require(rollback.candidateSourceInstallStarted == false) {
            "schema-6 undecided detached attempt has contradictory install authority"
        }
        recoverUndecidedSchema6BeforeIndex(
            projectRoot, store, loaded, persistedPending, profile, binding, requestedBudget, faultInjector, graphAuthority,
        )
        return
    }
    val oldPending = recoverPersistedInvocationBinding(
        persistedPending, loaded.schemaVersion, store, loaded.profileSha256,
    )
    val legacyRunContract = loaded.schemaVersion < 3
    if (loaded.schemaVersion < 5 &&
        !(loaded.schemaVersion == 4 && persistedPending.legacyRecoveryRequired)) {
        // Schema-4 records can classify whether candidate installation began, but they do not
        // carry the schema-5 physical inode/metadata commitment. Keep their exact source bytes
        // available as a historical witness when the recovered graph is later archived. A
        // schema-4 recovery marker for an original schema-1..3 graph is not a new origin: that
        // exact earlier source was retained before the marker was published, and preserving the
        // enlarged marker would duplicate unbounded legacy payload under a second identity.
        store.preserveLegacyState("graph", graphBytes, requestedBudget.maximumGraphBytes)
    }
    if (loaded.schemaVersion < 4) {
        val historyPath = projectRoot.resolve("reports/repair_history.json")
        if (legacyRunContract && Files.exists(historyPath, LinkOption.NOFOLLOW_LINKS)) {
            store.preserveLegacyState(
                "history",
                readStableRegularFile(projectRoot, "reports/repair_history.json", requestedBudget.maximumProjectionBytes).bytes,
                requestedBudget.maximumProjectionBytes,
            )
        }
    }
    val upgradedNodes = if (legacyRunContract) loaded.nodes.map { node ->
        if (node.status == ModuleRevisionStatus.ACCEPTED) node.copy(status = ModuleRevisionStatus.LEGACY_UNVERIFIED)
        else node
    } else loaded.nodes
    val upgradedPending = oldPending.copy(
        // Schema 4 already has a durable install-start marker.  It lacks schema-5 physical
        // metadata, but that is a separate unverified property and must not erase the native
        // rollback classification.  Only schemas 1..3 need the unknown-install legacy marker.
        legacyRecoveryRequired = oldPending.legacyRecoveryRequired || loaded.schemaVersion < 4,
    )
    // Preserve schema-5 recovery authority across every startup marker write. Older pending
    // records stay at v4 because they have no historical metadata commitment and must not be
    // relabeled as metadata-verified merely to use the current wire schema.
    val provenanceSchema = if (oldPending.repairMetadata?.turnIntent != null) 7 else 4
    val upgraded = loaded.copy(schemaVersion = maxOf(loaded.schemaVersion, provenanceSchema), nodes = upgradedNodes, pending = upgradedPending)
    val targetId = if (upgradedPending.detached) upgraded.headId else upgradedPending.parentId
    val targetSources = revisionSourcesAt(upgraded.nodes, targetId)
    require(targetSources.keys.sorted() == binding.sourcePaths)
    val targetBytes = targetSources.values.fold(0L) { total, source -> Math.addExact(total, source.bytes) }
    require(targetBytes <= requestedBudget.maximumSourceBytes) { "recovery source view exceeds source-byte budget" }
    val sourceView = object : RepairRecoverySourceView {
        override val sourcePaths: List<String> get() = binding.sourcePaths
        override val editablePaths: List<String> get() = binding.editablePaths
        override fun readSource(relative: String): ByteArray {
            val source = requireNotNull(targetSources[relative]) { "recovery source view path is absent" }
            require(relative == normalizedRelative(relative)) { "recovery source view read is unnormalized" }
            val blob = readStableRegularFile(store.blobsPath, source.sha256, requestedBudget.maximumSourceFileBytes)
            require(blob.sha256 == source.sha256 && blob.bytes.size.toLong() == source.bytes) {
                "recovery source view preimage digest or size differs"
            }
            profile.validateSourceContent(relative, blob.bytes)
            return blob.bytes
        }
    }
    // Index identity depends on the resolved dependency evidence, not the dirty source digest.
    // The virtual view substitutes authenticated preimages and excludes paths absent from the
    // immutable source set. Profile lookups alone are cached by the loader; both index snapshots
    // still reread authenticated preimages physically. No callback-count limit substitutes for
    // distinct source bounds, and dirty candidate bytes never become recovery index authority.
    val recoveryIndex = SecureRepairRuntime.loadRecoveryIndex(graphAuthority, projectRoot, profile, requestedBudget, sourceView)
    require(recoveryIndex.belongsTo(projectRoot) && recoveryIndex.budget == requestedBudget &&
        recoveryBinding(recoveryIndex) == binding) { "startup recovery dependency index is not bound to persisted authority" }
    val initial = upgradedPending.rollbackRecord ?: initialRollbackRecord(
        upgraded,
        upgradedPending,
        upgradedPending.legacyRecoveryRequired,
    )
    val inProgress = if (initial.failureCode != null) initial
        else initial.copy(state = RepairRollbackState.RESTORE_IN_PROGRESS)
    val pending = upgradedPending.copy(rollbackRecord = inProgress)
    val marked = upgraded.copy(pending = pending)

    fun persistRecoveryState(next: RevisionGraphState) {
        val payload = renderGraph(next).toByteArray(Charsets.UTF_8)
        requireRevisionGraphAdmission(next, payload.size.toLong(), purpose = DeclaredOriginPurpose.LOCAL_RECORDED, forEachDeclaredGraph = { consume ->
            store.forEachDeclaredLegacyGraph(requestedBudget, consume) })
        validateGraphBeforeRecovery(next, profile, binding, store.blobsPath, requestedBudget)
        store.writeGraph(payload)
    }

    // Every actual success/failure/restart publication must fit BEFORE marker or source exchange.
    val recoveryPaths = pending.candidateChanges.map { it.path }
    forEachRecoveryPublicationCandidate(marked, { recoveryIndex.changedModules(recoveryPaths) },
        { recoveryIndex.downstreamInvalidations(recoveryPaths) }) { _, next ->
        val bytes = renderGraph(next).toByteArray(Charsets.UTF_8)
        requireRevisionGraphAdmission(next, bytes.size.toLong(), purpose = DeclaredOriginPurpose.LOCAL_RECORDED, forEachDeclaredGraph = { consume ->
            store.forEachDeclaredLegacyGraph(requestedBudget, consume) })
        validateGraphBeforeRecovery(next, profile, binding, store.blobsPath, requestedBudget)
        val iterations = deriveRepairIterations(next.nodes, next.budget, next.schemaVersion) { digest ->
            val blob = readStableRegularFile(store.blobsPath, digest, requestedBudget.maximumSourceFileBytes)
            require(blob.sha256 == digest)
            blob.bytes
        }
        renderRepairHistoryProjection(iterations, next.retainedRegressionInputs,
            requestedBudget.maximumProjectionBytes, repairHistorySchemaForGraph(next.schemaVersion), next.runs)
        renderCompatibilityProjection(next.nodes, requestedBudget.maximumProjectionBytes)
    }
    // This atomic, synced marker is durable before source preflight can proceed to an exchange.
    persistRecoveryState(marked)
    var stage = RepairRollbackStage.SOURCE_RESTORE
    try {
        val candidateByPath = (if (pending.detached) pending.promotionChanges else pending.candidateChanges)
            .associateBy { it.path }
        val replacements = TreeMap<String, ByteArray>()
        val expectedCurrent = TreeMap<String, String>()
        // Preflight the entire source set. Unknown replacements are never overwritten.
        targetSources.toSortedMap().forEach { (relative, expected) ->
            val observed = readStableRegularFile(projectRoot, relative, requestedBudget.maximumSourceFileBytes)
            val candidate = candidateByPath[relative]
            when {
                observed.sha256 == expected.sha256 && observed.bytes.size.toLong() == expected.bytes -> {
                    val retained = store.revisionsPath.resolve(sourceTransactionPreimageName(relative, pending.id))
                    if (candidate != null && Files.exists(retained, LinkOption.NOFOLLOW_LINKS)) {
                        val beforeDigest = requireNotNull(candidate.beforeBlobSha256)
                        val preimage = readStableRegularFile(store.blobsPath, beforeDigest,
                            requestedBudget.maximumSourceFileBytes)
                        require(preimage.sha256 == beforeDigest) {
                            "pending repair recovery blob changed after graph validation"
                        }
                        replacements[relative] = preimage.bytes
                        expectedCurrent[relative] = observed.sha256
                    } else if (candidate != null) {
                        val committed = (if (pending.detached) pending.promotionPreimageMetadata
                            else pending.preimageMetadata)?.get(relative)
                        if (committed != null) {
                            if (!committed.matches(observed.state, includeAtime = false)) {
                                throw RepairRollbackException(
                                    RepairRollbackStage.SOURCE_RESTORE,
                                    RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE,
                                    "restored repair source metadata lacks its retained preimage witness: $relative",
                                )
                            }
                            // Before the first candidate exchange there is no retained hard link.
                            // A normal source read may have advanced atime, so authenticate the
                            // still-original inode through a descriptor and restore only atime.
                            normalizeCommittedPreimageAtimeAt(
                                projectRoot, relative, committed, expected.sha256, expected.bytes,
                            )
                        }
                    }
                }
                candidate != null && observed.sha256 == candidate.afterSha256 &&
                    observed.bytes.size.toLong() == candidate.afterBytes -> {
                    val beforeDigest = requireNotNull(candidate.beforeBlobSha256)
                    val preimage = readStableRegularFile(
                        store.blobsPath,
                        beforeDigest,
                        requestedBudget.maximumSourceFileBytes,
                    )
                    require(preimage.sha256 == beforeDigest) {
                        "pending repair recovery blob changed after graph validation"
                    }
                    replacements[relative] = preimage.bytes
                    expectedCurrent[relative] = candidate.afterSha256
                }
                else -> throw RepairRollbackException(
                    RepairRollbackStage.SOURCE_RESTORE,
                    RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE,
                    "pending repair recovery found an unrecognized source replacement",
                )
            }
        }
        if (pending.candidateSourceRevisionSha256 == null) {
            require(replacements.isEmpty()) { "pre-candidate recovery unexpectedly requires source writes" }
        }
        require(replacements.keys.all { it in if (pending.detached) upgraded.editablePaths else pending.allowedPaths })
        if (replacements.isNotEmpty()) {
            publishRepairFiles(
                projectRoot,
                store.revisionsPath,
                replacements,
                expectedCurrent,
                requestedBudget.maximumSourceFileBytes,
                pending.id,
                "startup-rollback",
                candidateByPath.mapValues { it.value.afterSha256 },
                (if (pending.detached) pending.promotionPreimageMetadata else pending.preimageMetadata).orEmpty(),
                faultInjector,
            )
        }
        stage = RepairRollbackStage.SOURCE_VERIFICATION
        val observedRevision = measureSourceRevision(
            projectRoot,
            targetSources.keys.toList(),
            requestedBudget.maximumSourceFileBytes,
        )
        if (observedRevision != inProgress.expectedSourceRevisionSha256) {
            throw RepairRollbackException(
                RepairRollbackStage.SOURCE_VERIFICATION,
                RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
                "pending repair rollback did not restore its exact source revision",
            )
        }
    } catch (failure: Exception) {
        val rollbackFailure = failure as? RepairRollbackException
        val observed = try {
            measureSourceRevision(projectRoot, targetSources.keys.toList(), requestedBudget.maximumSourceFileBytes)
        } catch (_: Exception) {
            null
        }
        val failedRecord = inProgress.copy(
            state = RepairRollbackState.RESTORE_FAILED_UNRESOLVED,
            failureStage = rollbackFailure?.rollbackStage ?: stage,
            failureCode = rollbackFailure?.failureCode ?: RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
            observedSourceRevisionSha256 = observed,
        )
        try {
            persistRecoveryState(withCommittedRollbackFailure(marked, failedRecord))
        } catch (publicationFailure: Exception) {
            failure.addSuppressed(publicationFailure)
        }
        throw failure
    }
}

/**
 * Schema-6 candidates are blob-only until an acceptance decision is durable. An undecided
 * recovery therefore never restores or reads the live source through the legacy rollback path:
 * it verifies the exact witness, removes only authenticated private stages, and records a
 * deterministic rejected outcome while the source remains untouched.
 */
private fun recoverUndecidedSchema6BeforeIndex(
    projectRoot: Path,
    store: RepairStateStore,
    source: RevisionGraphState,
    persistedPending: PendingAttempt,
    profile: RepairIndexProfile,
    binding: RepairRecoveryBinding,
    budget: RepairResourceBudget,
    faultInjector: ModuleRevisionFaultInjector?,
    graphAuthority: Any,
) {
    require(source.schemaVersion >= 6 && persistedPending.detached && persistedPending.acceptanceDecision == null)
    val durableRollback = requireNotNull(persistedPending.rollbackRecord) {
        "schema-6 undecided recovery is missing its durable no-install authority"
    }
    require(durableRollback.candidateSourceInstallStarted == false &&
        durableRollback.legacyPendingStateUnknown == persistedPending.legacyRecoveryRequired) {
        "schema-6 undecided recovery has contradictory rollback authority"
    }

    // Authenticate the whole accepted source tree before stage cleanup. A failed check leaves
    // both the pending graph and every stage in place so readers remain unavailable.
    verifySchema6PendingWitness(projectRoot, source, persistedPending, budget)
    val changes = deriveSchema6PromotionChanges(source, persistedPending)
    discardUndecidedPublicationStages(store, changes, persistedPending.id, persistedPending.predecisionStageFiles)

    val pending = recoverPersistedInvocationBinding(
        persistedPending, source.schemaVersion, store, source.profileSha256,
    )
    val targetId = source.headId // Physical source remains the accepted head, even with provisional lineage.
    val targetSources = revisionSourcesAt(source.nodes, targetId)
    require(targetSources.keys.sorted() == binding.sourcePaths) {
        "schema-6 rollback target does not cover its immutable source authorization"
    }
    val targetBytes = targetSources.values.fold(0L) { total, item -> Math.addExact(total, item.bytes) }
    require(targetBytes <= budget.maximumSourceBytes) { "schema-6 rollback source view exceeds its byte budget" }
    val sourceView = object : RepairRecoverySourceView {
        override val sourcePaths: List<String> get() = binding.sourcePaths
        override val editablePaths: List<String> get() = binding.editablePaths
        override fun readSource(relative: String): ByteArray {
            require(relative == normalizedRelative(relative))
            val expected = requireNotNull(targetSources[relative]) {
                "schema-6 rollback source view path is absent: $relative"
            }
            val blob = store.readBlob(expected.sha256, budget.maximumSourceFileBytes)
            require(blob.sha256 == expected.sha256 && blob.bytes.size.toLong() == expected.bytes) {
                "schema-6 rollback source blob differs from its graph commitment: $relative"
            }
            return blob.bytes
        }
    }
    val recoveryIndex = SecureRepairRuntime.loadRecoveryIndex(
        graphAuthority, projectRoot, profile, budget, sourceView,
    )
    require(recoveryIndex.belongsTo(projectRoot) && recoveryIndex.budget == budget &&
        recoveryBinding(recoveryIndex) == binding) {
        "schema-6 rollback recovery index differs from immutable source authorization"
    }

    val expectedRevision = revisionSha256(targetSources.values)
    val rollback = pending.rollbackRecord ?: durableRollback
    validatePendingRollbackRecord(rollback, pending, targetId, expectedRevision)
    require(rollback.candidateSourceInstallStarted == false) {
        "schema-6 undecided recovery cannot prove that source installation was unnecessary"
    }
    val outcome = rollbackOutcomeRecord(rollback, expectedRevision)
    val changedPaths = pending.candidateChanges.map { it.path }
    val rejected = finalizedRepairNode(
        pending,
        ModuleRevisionStatus.REJECTED,
        RESTART_RECOVERY_EVIDENCE,
        recovered = true,
        rollbackRecord = outcome,
        changedModules = { recoveryIndex.changedModules(changedPaths) },
        invalidatedModules = { recoveryIndex.downstreamInvalidations(changedPaths) },
    )
    val finalized = withFinalizedRollback(
        source.copy(nodes = source.nodes + rejected, pending = null),
        outcome,
    )
    val complete = if (finalized.runs.lastOrNull()?.terminal == false) {
        finishedRunCandidate(finalized, RepairRunStatus.INTERRUPTED, RESTART_INTERRUPTION_EVIDENCE)
    } else {
        // Standalone repair attempts intentionally have no synthetic run record.
        finalized
    }
    // Finalizing a rejected node moves the candidate deltas from `pending` into `nodes`; it
    // does not add or remove any referenced blob. Keep the already-admitted accounting exact.
    val storedBytes = source.storedBlobBytes
    require(storedBytes <= budget.maximumStoredBlobBytes) {
        "schema-6 recovered graph exceeds its stored blob budget"
    }
    val ready = complete.copy(
        schemaVersion = if (pending.repairMetadata?.turnIntent != null) 7 else complete.schemaVersion,
        storedBlobBytes = storedBytes,
    )
    val payload = renderGraph(ready).toByteArray(Charsets.UTF_8)
    require(payload.size.toLong() <= budget.maximumGraphBytes) {
        "schema-6 recovered graph exceeds its graph-byte budget"
    }
    requireRevisionGraphAdmission(
        ready,
        payload.size.toLong(),
        purpose = DeclaredOriginPurpose.LOCAL_RECORDED,
        forEachDeclaredGraph = { consume -> store.forEachDeclaredLegacyGraph(budget, consume) },
    )
    validateGraphBeforeRecovery(ready, profile, binding, store.blobsPath, budget)
    val iterations = deriveRepairIterations(ready.nodes, ready.budget, ready.schemaVersion) { digest ->
        val blob = store.readBlob(digest, budget.maximumSourceFileBytes)
        require(blob.sha256 == digest)
        blob.bytes
    }
    renderRepairHistoryProjection(
        iterations, ready.retainedRegressionInputs, budget.maximumProjectionBytes,
        repairHistorySchemaForGraph(ready.schemaVersion), ready.runs,
    )
    renderCompatibilityProjection(ready.nodes, budget.maximumProjectionBytes)

    // Recheck after the recovered graph temp and directory entry have been synced. If anything
    // changed during serialization or staging cleanup, the callback refuses publication and the
    // old pending graph remains authoritative; no legacy source restore is attempted.
    store.writeGraph(payload) {
        verifySchema6PendingWitness(projectRoot, source, persistedPending, budget)
    }
}

private fun measureSourceRevision(projectRoot: Path, sourcePaths: List<String>, maximumSourceFileBytes: Long): String {
    val sources = sourcePaths.sorted().map { relative ->
        val observed = readStableRegularFile(projectRoot, relative, maximumSourceFileBytes)
        IndexedSource(relative, observed.bytes.size.toLong(), observed.sha256)
    }
    return revisionSha256(sources)
}

private data class RepairStagedReplacement(
    val relative: String,
    val temporaryName: String,
    val retainedPreimageName: String,
    val parentRelative: String,
    val preparedSha256: String,
    val preparedIdentity: LinuxFileIdentity,
    val preimageMetadata: RepairPreimageMetadata?,
)

private fun schema6PublicationPreimageMatches(
    file: LinuxDescriptor,
    preimage: RepairPreimageMetadata,
    mountId: Long,
    digest: String?,
): Boolean {
    val expectedDigest = digest ?: return false
    val state = LinuxFilesystemSyscalls.fileState(file)
    return state.identity.key.device == preimage.device && state.identity.key.inode == preimage.inode &&
        state.identity.mountId == mountId && state.identity.linkCount == 1 &&
        state.identity.mode == preimage.mode && state.identity.uid == preimage.uid && state.identity.gid == preimage.gid &&
        state.size == preimage.size && state.modificationTimeSeconds == preimage.mtimeSeconds &&
        state.modificationTimeNanoseconds == preimage.mtimeNanoseconds &&
        LinuxFilesystemSyscalls.sha256WithoutAtime(file, preimage.size) == expectedDigest &&
        LinuxFilesystemSyscalls.extendedAttributeNames(file).isEmpty()
}

private fun schema6PublicationCandidateMatches(file: LinuxDescriptor, staged: RepairStagedFile): Boolean {
    val state = LinuxFilesystemSyscalls.fileState(file)
    return state.identity.key.device == staged.device && state.identity.key.inode == staged.inode &&
        state.identity.mountId == staged.mountId && state.identity.linkCount == 1 &&
        state.identity.mode == staged.mode && state.identity.uid == staged.uid && state.identity.gid == staged.gid &&
        state.size == staged.size && state.accessTimeSeconds == staged.atimeSeconds &&
        state.accessTimeNanoseconds == staged.atimeNanoseconds &&
        state.modificationTimeSeconds == staged.mtimeSeconds &&
        state.modificationTimeNanoseconds == staged.mtimeNanoseconds &&
        LinuxFilesystemSyscalls.sha256WithoutAtime(file, staged.size) == staged.sha256 &&
        LinuxFilesystemSyscalls.extendedAttributeNames(file).isEmpty()
}

/** Idempotently rolls a durable schema-6 decision forward before any source index is built. */
private fun rollForwardRepairPublication(
    projectRoot: Path,
    store: RepairStateStore,
    decision: RepairAcceptanceDecision,
    faultInjector: ModuleRevisionFaultInjector?,
) {
    val stageDirectory = store.openPublicationStagingDirectory()
    val root = openRepairRootDirectory(projectRoot)
    val openedParents = mutableListOf<LinuxDescriptor>()
    try {
        val stageIdentity = LinuxFilesystemSyscalls.identity(stageDirectory.fd)
        require(stageIdentity.key == store.publicationStagingIdentity().key && stageIdentity.mountId == store.publicationStagingIdentity().mountId)
        val node = requireNotNull(decision.committedNode)
        val metadataByPath = node.publicationPreimageMetadata
        require(decision.stagedFiles.map { it.path } == decision.promotionChanges.map { it.path })
        // Preflight every pair before changing any target. If a later staged inode is missing,
        // tampered, or bound to an unexpected target, no earlier path may already have moved.
        decision.stagedFiles.zip(decision.promotionChanges).forEach { (staged, change) ->
            val preimage = requireNotNull(metadataByPath[change.path])
            require(staged.path == change.path && staged.stagingName == preimage.retainedName &&
                staged.sha256 == change.afterSha256 && staged.size == change.afterBytes)
            val parts = normalizedRelative(change.path).split('/')
            val parents = mutableListOf<LinuxDescriptor>()
            try {
                var parent = openRepairRootDirectory(projectRoot)
                parents += parent
                parts.dropLast(1).forEach { segment ->
                    parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
                    parents += parent
                }
                val parentState = LinuxFilesystemSyscalls.fileState(parent)
                require(parentState.identity.key.device == staged.parentDevice &&
                    parentState.identity.key.inode == staged.parentInode &&
                    parentState.identity.mountId == staged.parentMountId &&
                    stageIdentity.key.device == staged.parentDevice && stageIdentity.mountId == staged.parentMountId) {
                    "schema-6 publication target parent or mount changed: ${change.path}"
                }
                val target = requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, parts.last())) {
                    "schema-6 publication target is missing: ${change.path}"
                }
                val stagedFile = requireNotNull(store.openPublicationStage(staged.stagingName)) {
                    "schema-6 publication stage is missing: ${change.path}"
                }
                target.use { targetFile -> stagedFile.use { replacementFile ->
                    val targetPreimage = schema6PublicationPreimageMatches(targetFile, preimage, staged.parentMountId, change.beforeSha256)
                    val stagedCandidate = schema6PublicationCandidateMatches(replacementFile, staged)
                    val targetCandidate = schema6PublicationCandidateMatches(targetFile, staged)
                    val stagedPreimage = schema6PublicationPreimageMatches(replacementFile, preimage, staged.parentMountId, change.beforeSha256)
                    require(targetPreimage && stagedCandidate || targetCandidate && stagedPreimage) {
                        "schema-6 publication pair failed preflight: ${change.path} " +
                            "targetPreimage=$targetPreimage stagedCandidate=$stagedCandidate " +
                            "targetCandidate=$targetCandidate stagedPreimage=$stagedPreimage"
                    }
                } }
            } finally {
                parents.asReversed().forEach { runCatching { it.close() } }
            }
        }
        decision.stagedFiles.zip(decision.promotionChanges).forEach { (staged, change) ->
            val preimage = requireNotNull(metadataByPath[change.path])
            require(staged.path == change.path && staged.stagingName == preimage.retainedName &&
                staged.sha256 == change.afterSha256 && staged.size == change.afterBytes &&
                preimage.device >= 0 && preimage.inode >= 0)
            val parts = normalizedRelative(change.path).split('/')
            var parent = LinuxFilesystemSyscalls.openDirectoryAt(root.fd, ".")
            openedParents += parent
            parts.dropLast(1).forEach { segment ->
                parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
                openedParents += parent
            }
            val parentState = LinuxFilesystemSyscalls.fileState(parent)
            require(parentState.identity.key.device == staged.parentDevice &&
                parentState.identity.key.inode == staged.parentInode && parentState.identity.mountId == staged.parentMountId &&
                stageIdentity.key.device == staged.parentDevice && stageIdentity.mountId == staged.parentMountId) {
                "schema-6 publication target parent or mount changed: ${change.path}"
            }

            fun openTarget(): LinuxDescriptor = requireNotNull(
                LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, parts.last()),
            ) { "schema-6 publication target is missing: ${change.path}" }
            fun openStage(): LinuxDescriptor = requireNotNull(store.openPublicationStage(staged.stagingName)) {
                "schema-6 publication stage is missing: ${change.path}"
            }
            fun isPreimage(file: LinuxDescriptor): Boolean =
                schema6PublicationPreimageMatches(file, preimage, staged.parentMountId, change.beforeSha256)
            fun isCandidate(file: LinuxDescriptor): Boolean = schema6PublicationCandidateMatches(file, staged)
            val target = openTarget()
            val stagedName = openStage()
            val exchanged = try {
                val targetIsPreimage = isPreimage(target)
                val stageIsCandidate = isCandidate(stagedName)
                val targetIsCandidate = isCandidate(target)
                val stageIsPreimage = isPreimage(stagedName)
                val targetState = LinuxFilesystemSyscalls.fileState(target)
                when {
                    targetIsPreimage && stageIsCandidate -> {
                        val publicationIndex = decision.stagedFiles.indexOf(staged)
                        faultInjector?.hit(ModuleRevisionFaultPoint.BeforePublicationExchange(
                            "schema6-roll-forward", change.path, publicationIndex,
                        ))
                        LinuxFilesystemSyscalls.exchange(parent.fd, parts.last(), stageDirectory.fd, staged.stagingName)
                        faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationExchange(
                            "schema6-roll-forward", change.path, publicationIndex,
                        ))
                        LinuxFilesystemSyscalls.synchronize(parent)
                        faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationTargetDirectorySync(
                            "schema6-roll-forward", change.path, publicationIndex,
                        ))
                        LinuxFilesystemSyscalls.synchronize(stageDirectory)
                        faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationMove(
                            "schema6-roll-forward", change.path, publicationIndex,
                        ))
                        true
                    }
                    targetIsCandidate && stageIsPreimage -> false
                    else -> throw RepairAcceptancePendingException(
                        "schema-6 repair publication has an unknown target/stage binding: ${change.path} " +
                            "targetPreimage=$targetIsPreimage stageCandidate=$stageIsCandidate " +
                            "targetCandidate=$targetIsCandidate stagePreimage=$stageIsPreimage " +
                            "targetId=${targetState.identity.key} expectedPreimageId=${LinuxFileKey(preimage.device, preimage.inode)} " +
                            "candidateId=${staged.device}:${staged.inode}",
                    )
                }
            } finally {
                stagedName.close()
                target.close()
            }
            val installed = openTarget()
            val retained = openStage()
            try {
                require(isCandidate(installed) && isPreimage(retained)) {
                    "schema-6 repair publication exchange did not install its recorded inode: ${change.path}"
                }
                // Re-sync an already exchanged pair too; this makes recovery safe across a crash
                // between renameat2 and either directory fsync.
                if (!exchanged) {
                    LinuxFilesystemSyscalls.synchronize(parent)
                    LinuxFilesystemSyscalls.synchronize(stageDirectory)
                }
            } finally {
                retained.close()
                installed.close()
            }
            openedParents.asReversed().forEach(LinuxDescriptor::close)
            openedParents.clear()
        }
        LinuxFilesystemSyscalls.synchronize(stageDirectory)
    } catch (failure: RepairAcceptancePendingException) {
        throw failure
    } catch (failure: Exception) {
        throw RepairAcceptancePendingException("schema-6 repair publication remains unavailable", failure)
    } finally {
        openedParents.asReversed().forEach { runCatching { it.close() } }
        root.close()
        stageDirectory.close()
    }
}

private fun publishRepairFiles(
    projectRoot: Path,
    preimageRoot: Path,
    replacements: Map<String, ByteArray>,
    expectedCurrentSha256: Map<String, String>,
    maximumSourceFileBytes: Long,
    transactionId: String,
    phase: String,
    rollbackCandidateSha256: Map<String, String>,
    preimageMetadata: Map<String, RepairPreimageMetadata>,
    faultInjector: ModuleRevisionFaultInjector?,
) {
    require(replacements.isNotEmpty())
    require(replacements.keys == expectedCurrentSha256.keys)
    val staged = mutableListOf<RepairStagedReplacement>()
    var primaryFailure: Throwable? = null
    try {
        replacements.toSortedMap().entries.forEachIndexed { stageIndex, (relative, bytes) ->
            val normalized = normalizedRelative(relative)
            val target = projectRoot.resolve(normalized).normalize()
            require(target.startsWith(projectRoot) &&
                Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(target)) {
                "repair publication target is not a regular contained source file: $relative"
            }
            staged += stageRepairReplacement(
                projectRoot,
                preimageRoot,
                normalized,
                bytes,
                expectedCurrentSha256.getValue(relative),
                maximumSourceFileBytes,
                transactionId,
                phase,
                stageIndex,
                preimageMetadata[normalized],
                faultInjector,
            )
        }
        staged.forEachIndexed { moveIndex, replacement ->
            exchangeRepairFile(
                projectRoot,
                preimageRoot,
                replacement.relative,
                replacement.temporaryName,
                replacement.retainedPreimageName,
                expectedCurrentSha256.getValue(replacement.relative),
                rollbackCandidateSha256[replacement.relative],
                replacement.preimageMetadata,
                replacements.getValue(replacement.relative),
                replacement.preparedIdentity,
                maximumSourceFileBytes,
                phase,
                moveIndex,
                faultInjector,
            )
        }
    } catch (failure: Throwable) {
        primaryFailure = failure
        throw failure
    } finally {
        var cleanupFailure: Throwable? = null
        staged.forEachIndexed { index, replacement ->
            try {
                cleanupRepairOwnedEntry(
                    projectRoot,
                    replacement.parentRelative,
                    replacement.temporaryName,
                    setOf(replacement.preparedSha256),
                    replacement.preparedIdentity.key,
                    maximumSourceFileBytes,
                    phase,
                    replacement.relative,
                    index,
                    faultInjector,
                    required = false,
                )
            } catch (failure: Throwable) {
                cleanupFailure?.addSuppressed(failure) ?: run { cleanupFailure = failure }
            }
        }
        cleanupFailure?.let { failure ->
            primaryFailure?.addSuppressed(failure) ?: throw failure
        }
    }
}

private fun stageRepairReplacement(
    projectRoot: Path,
    preimageRoot: Path,
    relative: String,
    replacement: ByteArray,
    expectedCurrentSha256: String,
    maximumSourceFileBytes: Long,
    transactionId: String,
    phase: String,
    stageIndex: Int,
    preimageMetadata: RepairPreimageMetadata?,
    faultInjector: ModuleRevisionFaultInjector?,
): RepairStagedReplacement {
    val parts = normalizedRelative(relative).split('/')
    val parentRelative = parts.dropLast(1).joinToString("/")
    val temporaryName = sourceTransactionTemporaryName(parts.last(), transactionId)
    val retainedPreimageName = sourceTransactionPreimageName(relative, transactionId)
    if (preimageMetadata != null) require(preimageMetadata.retainedName == retainedPreimageName) {
        "repair retained-preimage name differs from its durable metadata commitment: $relative"
    }
    cleanupRepairOwnedEntry(
        projectRoot,
        parentRelative,
        temporaryName,
        setOf(expectedCurrentSha256, sha256(replacement)),
        null,
        maximumSourceFileBytes,
        phase,
        relative,
        stageIndex,
        faultInjector,
        required = false,
        expectedLinkCount = if (phase in setOf("rollback", "startup-rollback", "promotion-rollback")) -1 else 1,
    )
    val directories = mutableListOf<decompengine.acp.LinuxDescriptor>()
    var target: decompengine.acp.LinuxDescriptor? = null
    var temporary: decompengine.acp.LinuxDescriptor? = null
    var linked = false
    try {
        var parent = openRepairRootDirectory(projectRoot)
        directories += parent
        parts.dropLast(1).forEach { component ->
            val child = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component)
            require(child.identity.mountId == directories.first().identity.mountId) {
                "repair staging crosses a filesystem mount: $relative"
            }
            directories += child
            parent = child
        }
        val preimageDirectory = openRepairRootDirectory(preimageRoot)
        require(preimageDirectory.identity.mountId == directories.first().identity.mountId) {
            preimageDirectory.close()
            "repair preimage retention crosses a filesystem mount: $relative"
        }
        directories += preimageDirectory
        target = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, parts.last())) {
            "repair publication target disappeared while staging: $relative"
        }
        require(target.identity.isRegularFile && !target.identity.isSymbolicLink &&
            (target.identity.linkCount == 1 ||
                phase in setOf("rollback", "startup-rollback", "promotion-rollback") && target.identity.linkCount == 2)) {
            "repair publication requires a regular source file with a transaction-bounded link count: $relative"
        }
        if (preimageMetadata != null && phase !in setOf("rollback", "startup-rollback", "promotion-rollback")) require(preimageMetadata.matches(
            LinuxFilesystemSyscalls.fileState(target), includeAtime = false,
        )) {
            "repair source metadata changed after its durable preimage commitment: $relative"
        }
        require(LinuxFilesystemSyscalls.extendedAttributeNames(target).isEmpty()) {
            "repair publication refuses to discard extended source metadata: $relative"
        }
        require(sha256(readAuthorizedRepairFile(target, maximumSourceFileBytes)) == expectedCurrentSha256) {
            "source changed while repair replacement was staged: $relative"
        }
        if (preimageMetadata?.metadataVersion == 2 && phase !in setOf("rollback", "startup-rollback", "promotion-rollback")) {
            // Reads performed by the agent are allowed to advance atime. Restore the captured
            // pre-turn timestamp on the retained original inode immediately before publication;
            // after exchange, rollback can then restore the exact atime without trusting a later
            // read or mutable filesystem state as its source of truth.
            normalizeCommittedPreimageAtime(target, preimageMetadata)
        }
        temporary = LinuxFilesystemSyscalls.createTemporaryAt(parent.fd)
        LinuxFilesystemSyscalls.write(temporary, replacement) { }
        LinuxFilesystemSyscalls.chmod(temporary, target.identity.mode.permissions)
        LinuxFilesystemSyscalls.synchronize(temporary)
        val preparedBeforeLink = LinuxFilesystemSyscalls.identity(temporary.fd)
        require(
            preparedBeforeLink.key == temporary.identity.key &&
                preparedBeforeLink.mode.permissions == target.identity.mode.permissions &&
                preparedBeforeLink.uid == target.identity.uid &&
                preparedBeforeLink.gid == target.identity.gid &&
                LinuxFilesystemSyscalls.extendedAttributeNames(temporary).isEmpty(),
        ) { "repair replacement cannot preserve source mode/ownership metadata: $relative" }
        LinuxFilesystemSyscalls.linkTemporaryAt(temporary, parent.fd, temporaryName)
        linked = true
        LinuxFilesystemSyscalls.synchronize(parent)
        val materialized = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, temporaryName)) {
            "repair replacement disappeared after materialization: $relative"
        }
        materialized.use {
            val identity = materialized.identity
            require(
                identity.key == preparedBeforeLink.key && identity.isRegularFile && !identity.isSymbolicLink &&
                    identity.linkCount == 1 && identity.mode.permissions == target.identity.mode.permissions &&
                    identity.uid == target.identity.uid && identity.gid == target.identity.gid &&
                    LinuxFilesystemSyscalls.extendedAttributeNames(materialized).isEmpty() &&
                    readAuthorizedRepairFile(materialized, maximumSourceFileBytes).contentEquals(replacement),
            ) { "materialized repair replacement metadata/content changed: $relative" }
            return RepairStagedReplacement(
                relative,
                temporaryName,
                retainedPreimageName,
                parentRelative,
                sha256(replacement),
                identity,
                preimageMetadata,
            )
        }
    } catch (failure: Throwable) {
        if (linked) {
            runCatching {
                cleanupRepairOwnedEntry(
                    projectRoot,
                    parentRelative,
                    temporaryName,
                    setOf(sha256(replacement)),
                    temporary?.identity?.key,
                    maximumSourceFileBytes,
                    phase,
                    relative,
                    stageIndex,
                    faultInjector,
                    required = true,
                )
            }.onFailure(failure::addSuppressed)
        }
        throw failure
    } finally {
        temporary?.close()
        target?.close()
        directories.asReversed().forEach { it.close() }
    }
}

private fun exchangeRepairFile(
    projectRoot: Path,
    preimageRoot: Path,
    relative: String,
    temporaryName: String,
    retainedPreimageName: String,
    expectedCurrentSha256: String,
    rollbackCandidateSha256: String?,
    preimageMetadata: RepairPreimageMetadata?,
    replacement: ByteArray,
    preparedIdentity: LinuxFileIdentity,
    maximumSourceFileBytes: Long,
    phase: String,
    moveIndex: Int,
    faultInjector: ModuleRevisionFaultInjector?,
) {
    val parts = normalizedRelative(relative).split('/')
    if (preimageMetadata != null) require(preimageMetadata.retainedName == retainedPreimageName) {
        "repair retained-preimage name differs from its durable metadata commitment: $relative"
    }
    val directories = mutableListOf<decompengine.acp.LinuxDescriptor>()
    var authorizedTarget: decompengine.acp.LinuxDescriptor? = null
    var authorizedTemporary: decompengine.acp.LinuxDescriptor? = null
    var exchanged = false
    try {
        var parent = openRepairRootDirectory(projectRoot)
        directories += parent
        parts.dropLast(1).forEach { component ->
            val child = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component)
            require(child.identity.mountId == directories.first().identity.mountId) {
                "repair publication crosses a filesystem mount: $relative"
            }
            directories += child
            parent = child
        }
        val preimageDirectory = openRepairRootDirectory(preimageRoot)
        require(preimageDirectory.identity.mountId == directories.first().identity.mountId) {
            preimageDirectory.close()
            "repair preimage retention crosses a filesystem mount: $relative"
        }
        directories += preimageDirectory
        authorizedTarget = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, parts.last())) {
            "repair publication target disappeared: $relative"
        }
        authorizedTemporary = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, temporaryName)) {
            "repair publication temporary disappeared: $relative"
        }
        require(authorizedTarget.identity.isRegularFile && !authorizedTarget.identity.isSymbolicLink &&
            authorizedTarget.identity.mountId == directories.first().identity.mountId) {
            "repair publication target is not a regular file: $relative"
        }
        if (preimageMetadata != null && phase !in setOf("rollback", "startup-rollback", "promotion-rollback")) require(preimageMetadata.matches(LinuxFilesystemSyscalls.fileState(authorizedTarget))) {
            "repair source metadata changed at the publication boundary: $relative"
        }
        require(authorizedTemporary.identity.isRegularFile && !authorizedTemporary.identity.isSymbolicLink &&
            authorizedTemporary.identity.mountId == directories.first().identity.mountId) {
            "repair publication temporary is not a regular file: $relative"
        }
        require(readAuthorizedRepairFile(authorizedTarget, maximumSourceFileBytes).let {
            sha256(it) == expectedCurrentSha256
        }) { "source changed before atomic repair exchange: $relative" }
        require(readAuthorizedRepairFile(authorizedTemporary, maximumSourceFileBytes).contentEquals(replacement)) {
            "repair publication temporary changed before exchange: $relative"
        }
        require(
            authorizedTemporary.identity.key == preparedIdentity.key &&
                authorizedTarget.identity.linkCount in
                    (if (phase == "candidate" || phase == "promotion") setOf(1)
                    else if (phase in setOf("rollback", "startup-rollback", "promotion-rollback")) setOf(1, 2) else setOf(1)) &&
                authorizedTemporary.identity.linkCount == 1 &&
                authorizedTemporary.identity.mode.permissions == authorizedTarget.identity.mode.permissions &&
                authorizedTemporary.identity.uid == authorizedTarget.identity.uid &&
                authorizedTemporary.identity.gid == authorizedTarget.identity.gid &&
                LinuxFilesystemSyscalls.extendedAttributeNames(authorizedTarget).isEmpty() &&
                LinuxFilesystemSyscalls.extendedAttributeNames(authorizedTemporary).isEmpty(),
        ) { "repair publication cannot preserve source metadata: $relative " +
            "preparedKey=${authorizedTemporary.identity.key == preparedIdentity.key} " +
            "targetLinks=${authorizedTarget.identity.linkCount} tempLinks=${authorizedTemporary.identity.linkCount} " +
            "mode=${authorizedTemporary.identity.mode.permissions}/${authorizedTarget.identity.mode.permissions} " +
            "owner=${authorizedTemporary.identity.uid}:${authorizedTemporary.identity.gid}/" +
            "${authorizedTarget.identity.uid}:${authorizedTarget.identity.gid} " +
            "xattr=${LinuxFilesystemSyscalls.extendedAttributeNames(authorizedTarget).size}/" +
            "${LinuxFilesystemSyscalls.extendedAttributeNames(authorizedTemporary).size}" }
        val portablePath = relative.replace('\\', '/')
        parent.requireNamedRepairIdentity(parts.last(), authorizedTarget.identity)
        parent.requireNamedRepairIdentity(temporaryName, authorizedTemporary.identity)
        if (phase in setOf("rollback", "startup-rollback", "promotion-rollback")) {
            val retainedEntry = LinuxFilesystemSyscalls.openPathAtOrNull(preimageDirectory.fd, retainedPreimageName)
            if (retainedEntry == null && preimageMetadata == null) {
                // Pre-schema-5 pending attempts have no durable inode commitment. Restore their
                // authenticated content blob, but keep the outcome explicitly legacy/unverified;
                // never infer metadata identity from the candidate's current filesystem state.
                faultInjector?.hit(ModuleRevisionFaultPoint.BeforePublicationExchange(phase, portablePath, moveIndex))
                parent.requireNamedRepairIdentity(parts.last(), authorizedTarget.identity)
                LinuxFilesystemSyscalls.exchange(parent.fd, temporaryName, parts.last())
                exchanged = true
                faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationExchange(phase, portablePath, moveIndex))
                val restored = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, parts.last()))
                restored.use {
                    require(sha256(readAuthorizedRepairFile(restored, maximumSourceFileBytes)) == sha256(replacement)) {
                        "legacy repair rollback did not restore its authenticated content preimage: $relative"
                    }
                }
                val displaced = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, temporaryName))
                displaced.use {
                    require(sha256(readAuthorizedRepairFile(displaced, maximumSourceFileBytes)) == expectedCurrentSha256 ||
                        sha256(readAuthorizedRepairFile(displaced, maximumSourceFileBytes)) == rollbackCandidateSha256) {
                        "legacy repair rollback displaced an unrecognized source: $relative"
                    }
                    cleanupRepairOwnedEntryAt(
                        parent.fd, temporaryName,
                        setOfNotNull(expectedCurrentSha256, rollbackCandidateSha256),
                        displaced.identity.key, maximumSourceFileBytes, phase, portablePath, moveIndex,
                        faultInjector, required = true, expectedLinkCount = 1,
                    )
                }
                LinuxFilesystemSyscalls.synchronize(parent)
                exchanged = false
                faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationMove(phase, portablePath, moveIndex))
                return
            }
            val retained = requireNotNull(retainedEntry) {
                "repair retained preimage is missing during rollback: $relative"
            }
            retained.use {
                val targetBytes = readAuthorizedRepairFile(authorizedTarget, maximumSourceFileBytes)
                val retainedBytes = readAuthorizedRepairFile(retained, maximumSourceFileBytes)
                val targetDigest = sha256(targetBytes)
                val retainedDigest = sha256(retainedBytes)
                val targetIsPreimage = targetBytes.contentEquals(replacement)
                val retainedIsPreimage = retainedBytes.contentEquals(replacement)
                val targetIsCandidate = targetDigest == expectedCurrentSha256
                val retainedIsCandidate = retainedDigest == expectedCurrentSha256
                require((targetIsPreimage || targetIsCandidate) &&
                    (retainedIsPreimage || retainedIsCandidate)) {
                    "repair retained preimage is ambiguous or corrupt: $relative"
                }
                if (preimageMetadata?.metadataVersion == 2) {
                    require(preimageMetadata.matches(LinuxFilesystemSyscalls.fileState(retained), includeAtime = false)) {
                        "retained repair preimage identity or metadata differs from its durable commitment: $relative"
                    }
                    normalizeCommittedPreimageAtime(retained, preimageMetadata)
                }
                if (preimageMetadata != null) require(preimageMetadata.matches(LinuxFilesystemSyscalls.fileState(retained))) {
                    "retained repair preimage metadata differs from its durable commitment: $relative"
                }
                require(LinuxFilesystemSyscalls.extendedAttributeNames(retained).isEmpty()) {
                    "retained repair preimage violates the committed no-xattr policy: $relative"
                }
                val alreadyRestored = targetIsPreimage &&
                    (preimageMetadata == null || preimageMetadata.matches(LinuxFilesystemSyscalls.fileState(authorizedTarget))) &&
                    (retainedIsCandidate || retained.identity.key == authorizedTarget.identity.key)
                if (!alreadyRestored) {
                    require((targetIsCandidate || targetIsPreimage) && retainedIsPreimage) {
                        "repair retained preimage cannot safely restore the current source: $relative"
                    }
                    faultInjector?.hit(ModuleRevisionFaultPoint.BeforePublicationExchange(phase, portablePath, moveIndex))
                    parent.requireNamedRepairIdentity(parts.last(), authorizedTarget.identity)
                    val targetAtExchange = sha256(readAuthorizedRepairFile(authorizedTarget, maximumSourceFileBytes))
                    require(targetAtExchange == expectedCurrentSha256 || targetAtExchange == sha256(replacement)) {
                        "repair rollback target changed at the exchange boundary: $relative"
                    }
                    val restoreName = "$temporaryName.restore"
                    val stagedRestore = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, restoreName)
                    if (stagedRestore == null) {
                        LinuxFilesystemSyscalls.linkTemporaryAt(retained, parent.fd, restoreName)
                    } else {
                        stagedRestore.use {
                            require(stagedRestore.identity.key == retained.identity.key &&
                                stagedRestore.identity.linkCount == 2 &&
                                readAuthorizedRepairFile(stagedRestore, maximumSourceFileBytes)
                                    .contentEquals(readAuthorizedRepairFile(retained, maximumSourceFileBytes))) {
                                "staged repair preimage link is ambiguous or corrupt: $relative"
                            }
                        }
                    }
                    LinuxFilesystemSyscalls.exchange(parent.fd, restoreName, parts.last())
                    faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationExchange(phase, portablePath, moveIndex))
                    parent.requireNamedRepairIdentity(parts.last(), retained.identity)
                    cleanupRepairOwnedEntryAt(
                        parent.fd, restoreName, setOf(expectedCurrentSha256, sha256(replacement)), null,
                        maximumSourceFileBytes, phase, portablePath, moveIndex, faultInjector,
                        required = true, expectedLinkCount = 1,
                    )
                    LinuxFilesystemSyscalls.synchronize(parent)
                }
            }
            val restoreName = "$temporaryName.restore"
            // This point is reached only after the target has been verified/restored to the
            // preimage. Reconcile both the active staging name and its deterministic cleanup
            // quarantine: process death can occur after cleanupRepairOwnedEntryAt renames
            // `.restore` to `.restore.cleanup` but before it unlinks the candidate inode.
            // The helper authenticates the surviving name/content before retrying cleanup.
            cleanupRepairOwnedEntryAt(
                parent.fd,
                restoreName,
                setOfNotNull(expectedCurrentSha256, sha256(replacement), rollbackCandidateSha256),
                expectedKey = null,
                maximumBytes = maximumSourceFileBytes,
                phase = phase,
                relative = portablePath,
                index = moveIndex,
                faultInjector = faultInjector,
                required = false,
                expectedLinkCount = -1,
            )
            cleanupRepairOwnedEntryAt(
                parent.fd,
                temporaryName,
                setOf(sha256(replacement)),
                preparedIdentity.key,
                maximumSourceFileBytes,
                phase,
                portablePath,
                moveIndex,
                faultInjector,
                required = false,
            )
            exchanged = false
            faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationMove(phase, portablePath, moveIndex))
            return
        }
        // This hook is intentionally after the last name check and immediately before renameat2;
        // adversarial tests exercise the actual check-to-commit gap.
        faultInjector?.hit(ModuleRevisionFaultPoint.BeforePublicationExchange(phase, portablePath, moveIndex))
        // Keep the accepted inode under a transaction-bound name before exchanging the candidate
        // into place. The link is durable before the exchange, so every partially installed
        // multi-file transaction retains the actual preimage rather than only its content blob.
        if (phase == "candidate" || phase == "promotion") {
            val existing = LinuxFilesystemSyscalls.openPathAtOrNull(preimageDirectory.fd, retainedPreimageName)
            if (existing == null) {
                LinuxFilesystemSyscalls.linkTemporaryAt(authorizedTarget, preimageDirectory.fd, retainedPreimageName)
                requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(preimageDirectory.fd, retainedPreimageName)).use { linked ->
                    require(linked.identity.key == authorizedTarget.identity.key && linked.identity.linkCount == 2 &&
                        linked.identity.mode == authorizedTarget.identity.mode &&
                        linked.identity.uid == authorizedTarget.identity.uid && linked.identity.gid == authorizedTarget.identity.gid &&
                        readAuthorizedRepairFile(linked, maximumSourceFileBytes)
                            .contentEquals(readAuthorizedRepairFile(authorizedTarget, maximumSourceFileBytes))) {
                        "repair retained preimage could not be verified after linking: $relative"
                    }
                }
                LinuxFilesystemSyscalls.synchronize(preimageDirectory)
            } else {
                existing.use {
                    require(existing.identity.key == authorizedTarget.identity.key &&
                        readAuthorizedRepairFile(existing, maximumSourceFileBytes)
                            .contentEquals(readAuthorizedRepairFile(authorizedTarget, maximumSourceFileBytes))) {
                        "repair retained preimage is ambiguous or corrupt: $relative"
                    }
                }
            }
        }
        try {
            LinuxFilesystemSyscalls.exchange(parent.fd, temporaryName, parts.last())
            exchanged = true
            faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationExchange(phase, portablePath, moveIndex))
            val displaced = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, temporaryName))
            val installed = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, parts.last()))
            displaced.use {
                installed.use {
                    val displacedCurrent = LinuxFilesystemSyscalls.identity(displaced.fd)
                    val installedCurrent = LinuxFilesystemSyscalls.identity(installed.fd)
                    require(
                        displacedCurrent.key == authorizedTarget.identity.key &&
                            displacedCurrent.mode.permissions == authorizedTarget.identity.mode.permissions &&
                            displacedCurrent.uid == authorizedTarget.identity.uid &&
                            displacedCurrent.gid == authorizedTarget.identity.gid &&
                            displacedCurrent.linkCount == (if (phase == "candidate" || phase == "promotion") 2 else 1) &&
                            installedCurrent.key == authorizedTemporary.identity.key &&
                            installedCurrent.mode.permissions == authorizedTarget.identity.mode.permissions &&
                            installedCurrent.uid == authorizedTarget.identity.uid &&
                            installedCurrent.gid == authorizedTarget.identity.gid &&
                            installedCurrent.linkCount == 1 &&
                            LinuxFilesystemSyscalls.extendedAttributeNames(displaced).isEmpty() &&
                            LinuxFilesystemSyscalls.extendedAttributeNames(installed).isEmpty(),
                    ) {
                        "repair publication target changed at the atomic exchange: $relative"
                    }
                }
            }
            parent.requireNamedRepairIdentity(parts.last(), authorizedTemporary.identity)
            parent.requireNamedRepairIdentity(temporaryName, authorizedTarget.identity)
            // Persist both the installed candidate name and the displaced accepted inode before
            // the latter is quarantined or unlinked.
            LinuxFilesystemSyscalls.synchronize(parent)
        } catch (failure: Exception) {
            if (exchanged) {
                runCatching {
                    rollbackRepairExchange(
                        parent.fd,
                        temporaryName,
                        parts.last(),
                        authorizedTemporary.identity,
                        phase,
                        portablePath,
                        moveIndex,
                        faultInjector,
                    )
                }.onFailure(failure::addSuppressed)
            }
            throw failure
        }
        // The old inode is now reachable only at the exact journal-owned name. Revalidate its
        // identity at unlink; an unknown name is preserved and makes the transaction fail closed.
        cleanupRepairOwnedEntryAt(
            parent.fd, temporaryName, setOf(expectedCurrentSha256), authorizedTarget.identity.key,
            maximumSourceFileBytes, phase, portablePath, moveIndex, faultInjector, required = true,
            expectedLinkCount = if (phase == "candidate" || phase == "promotion") 2 else 1,
        )
        exchanged = false
        faultInjector?.hit(ModuleRevisionFaultPoint.AfterPublicationMove(phase, portablePath, moveIndex))
    } finally {
        authorizedTemporary?.close()
        authorizedTarget?.close()
        directories.asReversed().forEach { it.close() }
    }
}

private fun decompengine.acp.LinuxDescriptor.requireNamedRepairIdentity(
    name: String,
    expected: LinuxFileIdentity,
) {
    requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(fd, name)) {
        "repair publication name disappeared"
    }.use { current ->
        require(current.identity.isRegularFile && !current.identity.isSymbolicLink &&
            current.identity.key == expected.key && current.identity.mountId == expected.mountId) {
            "repair publication name changed identity"
        }
    }
}

private fun readAuthorizedRepairFile(
    authorized: decompengine.acp.LinuxDescriptor,
    maximumBytes: Long,
): ByteArray {
    require(maximumBytes in 1 until Int.MAX_VALUE.toLong())
    // Rollback retains and restores the original inode. Validation and recovery reads must not
    // change its access time; if O_NOATIME is unavailable, fail closed before accepting the read.
    return LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(authorized).use { readable ->
        val bytes = try {
            LinuxFilesystemSyscalls.read(readable, maximumBytes.toInt()) { }
        } catch (_: LinuxResourceLimitException) {
            throw RepairBudgetExceededException("repair publication file exceeds $maximumBytes bytes")
        }
        require(LinuxFilesystemSyscalls.identity(readable.fd).key == authorized.identity.key) {
            "repair publication descriptor changed while it was read"
        }
        bytes
    }
}

/** Reset only atime on the authenticated original inode before it is retained or restored. */
private fun normalizeCommittedPreimageAtime(authorized: LinuxDescriptor, metadata: RepairPreimageMetadata) {
    if (metadata.metadataVersion < 2) return
    LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(authorized).use { readable ->
        LinuxFilesystemSyscalls.setAccessTime(readable,
            requireNotNull(metadata.atimeSeconds), requireNotNull(metadata.atimeNanoseconds))
        require(metadata.matches(LinuxFilesystemSyscalls.fileState(readable))) {
            "repair preimage could not be normalized to its committed metadata"
        }
    }
}

/** Normalize atime only when the source name still denotes the committed pre-turn inode. */
private fun normalizeCommittedPreimageAtimeAt(
    projectRoot: Path,
    relative: String,
    metadata: RepairPreimageMetadata,
    expectedSha256: String,
    expectedBytes: Long,
) {
    if (metadata.metadataVersion < 2) return
    val parts = normalizedRelative(relative).split('/')
    val directories = mutableListOf<LinuxDescriptor>()
    try {
        var parent = openRepairRootDirectory(projectRoot)
        directories += parent
        parts.dropLast(1).forEach { component ->
            parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component)
            directories += parent
        }
        val source = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, parts.last()) ?: return
        source.use {
            val before = LinuxFilesystemSyscalls.fileState(source)
            if (before.identity.key.device != metadata.device || before.identity.key.inode != metadata.inode) return
            require(metadata.matches(before, includeAtime = false)) {
                "restored repair source changed metadata before atime normalization: $relative"
            }
            require(before.size == expectedBytes &&
                LinuxFilesystemSyscalls.sha256WithoutAtime(source, expectedBytes) == expectedSha256) {
                "restored repair source differs from its committed preimage: $relative"
            }
            normalizeCommittedPreimageAtime(source, metadata)
        }
    } finally {
        directories.asReversed().forEach { it.close() }
    }
}

private fun cleanupRepairOwnedEntry(
    projectRoot: Path,
    parentRelative: String,
    name: String,
    expectedSha256: Set<String>,
    expectedKey: LinuxFileKey?,
    maximumBytes: Long,
    phase: String,
    relative: String,
    index: Int,
    faultInjector: ModuleRevisionFaultInjector?,
    required: Boolean,
    expectedLinkCount: Int = 1,
    expectedMetadata: RepairPreimageMetadata? = null,
) {
    val directories = mutableListOf<decompengine.acp.LinuxDescriptor>()
    try {
        var parent = openRepairRootDirectory(projectRoot)
        directories += parent
        if (parentRelative.isNotEmpty()) {
            parentRelative.split('/').forEach { component ->
                val child = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component)
                require(child.identity.mountId == directories.first().identity.mountId) {
                    "repair cleanup crosses a filesystem mount: $relative"
                }
                directories += child
                parent = child
            }
        }
        cleanupRepairOwnedEntryAt(
            parent.fd,
            name,
            expectedSha256,
            expectedKey,
            maximumBytes,
            phase,
            relative,
            index,
            faultInjector,
            required,
            expectedLinkCount,
            expectedMetadata,
        )
    } finally {
        directories.asReversed().forEach { it.close() }
    }
}

private fun cleanupRepairOwnedEntryAt(
    parentFd: Int,
    name: String,
    expectedSha256: Set<String>,
    expectedKey: LinuxFileKey?,
    maximumBytes: Long,
    phase: String,
    relative: String,
    index: Int,
    faultInjector: ModuleRevisionFaultInjector?,
    required: Boolean,
    expectedLinkCount: Int = 1,
    expectedMetadata: RepairPreimageMetadata? = null,
) {
    require(expectedSha256.isNotEmpty() && expectedSha256.all { it.matches(Regex("[0-9a-f]{64}")) })
    val quarantine = "$name.cleanup"
    var quarantined = false
    try {
        // A crash after quarantine but before unlink leaves one deterministic journal-owned name.
        LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, quarantine).use { stranded ->
            if (stranded != null) {
                LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, name).use { active ->
                    require(active == null) {
                        "repair cleanup found both an active and quarantined journal entry"
                    }
                }
                LinuxFilesystemSyscalls.renameNoReplace(parentFd, quarantine, name)
                synchronizeRepairDirectory(parentFd)
            }
        }
        try {
            LinuxFilesystemSyscalls.renameNoReplace(parentFd, name, quarantine)
            quarantined = true
            synchronizeRepairDirectory(parentFd)
        } catch (failure: decompengine.acp.LinuxSyscallException) {
            if (failure.errno == LinuxFilesystemSyscalls.ENOENT && !required) return
            throw failure
        }
        fun requireOwned() {
            val entry = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, quarantine)) {
                "quarantined repair entry disappeared during cleanup"
            }
            entry.use {
                require(entry.identity.isRegularFile && !entry.identity.isSymbolicLink &&
                    (entry.identity.linkCount == expectedLinkCount ||
                        expectedLinkCount == -1 && entry.identity.linkCount in 1..2)) {
                    "quarantined repair entry has unsupported identity"
                }
                require(expectedKey == null || entry.identity.key == expectedKey) {
                    "quarantined repair entry changed inode identity"
                }
                if (expectedMetadata != null) {
                    require(expectedMetadata.retainedName == name &&
                        expectedMetadata.matches(LinuxFilesystemSyscalls.fileState(entry), includeAtime = false) &&
                        LinuxFilesystemSyscalls.extendedAttributeNames(entry).isEmpty()) {
                        "quarantined repair entry differs from its committed preimage metadata"
                    }
                }
                require(sha256(readAuthorizedRepairFile(entry, maximumBytes)) in expectedSha256) {
                    "quarantined repair entry has unrecognized content"
                }
            }
        }
        requireOwned()
        faultInjector?.hit(ModuleRevisionFaultPoint.BeforeOwnedEntryUnlink(phase, relative, index))
        requireOwned()
        LinuxFilesystemSyscalls.unlink(parentFd, quarantine)
        quarantined = false
        synchronizeRepairDirectory(parentFd)
    } catch (failure: Throwable) {
        if (quarantined) {
            runCatching {
                LinuxFilesystemSyscalls.renameNoReplace(parentFd, quarantine, name)
                synchronizeRepairDirectory(parentFd)
            }
                .onFailure(failure::addSuppressed)
        }
        throw failure
    }
}

private fun rollbackRepairExchange(
    parentFd: Int,
    temporaryName: String,
    targetName: String,
    preparedIdentity: LinuxFileIdentity,
    phase: String,
    relative: String,
    moveIndex: Int,
    faultInjector: ModuleRevisionFaultInjector?,
) {
    val displaced = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, temporaryName)) {
        "repair displaced source disappeared before CAS rollback"
    }
    val installed = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, targetName)) {
        "repair installed source disappeared before CAS rollback"
    }
    try {
        require(installed.identity.key == preparedIdentity.key) {
            "repair CAS rollback refuses to exchange an unrecognized installed source"
        }
        requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, temporaryName)).use { current ->
            require(current.identity.key == displaced.identity.key) {
                "repair displaced source name changed before CAS rollback"
            }
        }
        requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, targetName)).use { current ->
            require(current.identity.key == installed.identity.key) {
                "repair installed source name changed before CAS rollback"
            }
        }
        faultInjector?.hit(ModuleRevisionFaultPoint.BeforeRollbackExchange(phase, relative, moveIndex))
        LinuxFilesystemSyscalls.exchange(parentFd, temporaryName, targetName)
        val restored = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, targetName)) {
            "repair CAS rollback target disappeared"
        }
        val prepared = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, temporaryName)) {
            "repair CAS rollback temporary disappeared"
        }
        restored.use {
            prepared.use {
                if (restored.identity.key != displaced.identity.key || prepared.identity.key != installed.identity.key) {
                    // A non-cooperating writer changed a name in the final rollback gap. Exchange
                    // the just-observed pair back so its target entry is not silently overwritten;
                    // all inodes remain reachable even if compensation itself is raced.
                    LinuxFilesystemSyscalls.exchange(parentFd, temporaryName, targetName)
                    requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, targetName)).use { compensatedTarget ->
                        require(compensatedTarget.identity.key == prepared.identity.key) {
                            "repair CAS rollback compensation target identity mismatch"
                        }
                    }
                    requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, temporaryName)).use { compensatedTemp ->
                        require(compensatedTemp.identity.key == restored.identity.key) {
                            "repair CAS rollback compensation temporary identity mismatch"
                        }
                    }
                    error("repair CAS rollback detected a concurrent replacement at its commit gap")
                }
            }
        }
        synchronizeRepairDirectory(parentFd)
    } finally {
        installed.close()
        displaced.close()
    }
}

private fun synchronizeRepairDirectory(parentFd: Int) {
    LinuxFilesystemSyscalls.openDirectoryAt(parentFd, ".").use(LinuxFilesystemSyscalls::synchronize)
}

// Two exact whole-document encodings are readable. All new publications use compact nodes.
private enum class NullRollbackNodeWire { COMPACT, EXPLICIT_NULL }

private fun renderGraph(
    state: RevisionGraphState,
    nullNodeWire: NullRollbackNodeWire = NullRollbackNodeWire.COMPACT,
): String = buildString {
    append("{\n  \"schemaVersion\": ").append(state.schemaVersion).append(',')
    append("\n  \"budget\": ").append(state.budget.toJson()).append(',')
    append("\n  \"profileId\": \"").append(state.profileId.jsonEscape()).append("\",")
    append("\n  \"profileSha256\": \"").append(state.profileSha256).append("\",")
    append("\n  \"editablePaths\": ").append(state.editablePaths.jsonArray()).append(',')
    append("\n  \"indexSha256\": \"").append(state.indexSha256).append("\",")
    append("\n  \"retainedRegressionInputs\": ").append(state.retainedRegressionInputs.toGraphJson()).append(',')
    append("\n  \"regressionCorpusSha256\": \"").append(state.regressionCorpusSha256).append("\",")
    append("\n  \"headId\": \"").append(state.headId).append("\",")
    if (state.schemaVersion >= 3) {
        append("\n  \"provisionalHeadId\": ").append(state.provisionalHeadId?.let { "\"$it\"" } ?: "null").append(',')
        append("\n  \"fullyAcceptedHeadId\": ").append(state.fullyAcceptedHeadId?.let { "\"$it\"" } ?: "null").append(',')
        append("\n  \"acceptedProof\": ").append(state.acceptedProof?.toStateJson() ?: "null").append(',')
        append("\n  \"runs\": [").append(state.runs.joinToString(",") { it.toJson() }).append("],")
    }
    append("\n  \"nextOrdinal\": ").append(state.nextOrdinal).append(',')
    append("\n  \"storedBlobBytes\": ").append(state.storedBlobBytes).append(',')
    append("\n  \"nodes\": [")
    append(state.nodes.joinToString(",") { "\n" + it.toJson(state.schemaVersion, nullNodeWire).prependIndent("    ") })
    append("\n  ],\n  \"pending\": ")
        .append(state.pending?.toJson(state.schemaVersion) ?: "null").append("\n}\n")
}

/** Stable policy bytes used by external adapters when binding a profile to its repair limits. */
internal fun RepairResourceBudget.canonicalJson(): String = toJson()

private fun RepairResourceBudget.toJson(): String =
    "{\"maximumIndexedModules\":$maximumIndexedModules,\"maximumIndexedEntities\":$maximumIndexedEntities," +
        "\"maximumDependencyEdges\":$maximumDependencyEdges,\"maximumSourceFiles\":$maximumSourceFiles," +
        "\"maximumSourceFileBytes\":$maximumSourceFileBytes,\"maximumSourceBytes\":$maximumSourceBytes," +
        "\"maximumIndexEvidenceBytes\":$maximumIndexEvidenceBytes,\"maximumDiagnosticCharacters\":$maximumDiagnosticCharacters," +
        "\"maximumRegressionInputBytes\":$maximumRegressionInputBytes," +
        "\"maximumRegressionInputs\":$maximumRegressionInputs," +
        "\"maximumRegressionArguments\":$maximumRegressionArguments,\"maximumRequestBytes\":$maximumRequestBytes," +
        "\"maximumResponseBytes\":$maximumResponseBytes," +
        "\"maximumProjectionBytes\":$maximumProjectionBytes," +
        "\"maximumContextModules\":$maximumContextModules,\"maximumContextFiles\":$maximumContextFiles," +
        "\"maximumContextBytes\":$maximumContextBytes,\"maximumStagingDirectories\":$maximumStagingDirectories," +
        "\"maximumStagingBytes\":$maximumStagingBytes,\"maximumPatchFiles\":$maximumPatchFiles," +
        "\"maximumPatchBytes\":$maximumPatchBytes," +
        "\"maximumBehaviorStdoutBytes\":$maximumBehaviorStdoutBytes," +
        "\"maximumBehaviorStderrBytes\":$maximumBehaviorStderrBytes," +
        "\"maximumBehaviorOutputBytes\":$maximumBehaviorOutputBytes," +
        "\"maximumBehaviorExecutionMillis\":$maximumBehaviorExecutionMillis," +
        "\"maximumDiscoveryEntries\":$maximumDiscoveryEntries," +
        "\"maximumDiscoveryDirectories\":$maximumDiscoveryDirectories," +
        "\"maximumDiscoveryDepth\":$maximumDiscoveryDepth," +
        "\"maximumStateDirectoryEntries\":$maximumStateDirectoryEntries," +
        "\"maximumGraphLockWaitMillis\":$maximumGraphLockWaitMillis," +
        "\"maximumRevisionNodes\":$maximumRevisionNodes," +
        "\"maximumGraphBytes\":$maximumGraphBytes," +
        "\"maximumStoredBlobBytes\":$maximumStoredBlobBytes}"

private fun ModuleRevisionNode.toJson(
    schemaVersion: Int,
    nullNodeWire: NullRollbackNodeWire = NullRollbackNodeWire.COMPACT,
): String = buildString {
    append("{\n  \"id\": \"").append(id.jsonEscape()).append("\",")
    append("\n  \"parentId\": ").append(parentId?.let { "\"${it.jsonEscape()}\"" } ?: "null").append(',')
    append("\n  \"ordinal\": ").append(ordinal).append(',')
    append("\n  \"status\": \"").append(status.name.lowercase()).append("\",")
    append("\n  \"sourceRevisionSha256\": \"").append(sourceRevisionSha256).append("\",")
    append("\n  \"changedModules\": ").append(changedModules.jsonArray()).append(',')
    append("\n  \"invalidatedModules\": ").append(invalidatedModules.jsonArray()).append(',')
    append("\n  \"evidenceKind\": ").append(evidenceKind?.let { "\"${it.jsonEscape()}\"" } ?: "null").append(',')
    append("\n  \"evidenceArtifact\": ").append(evidenceArtifact?.let { "\"${it.jsonEscape()}\"" } ?: "null").append(',')
    append("\n  \"evidenceSummary\": ").append(evidenceSummary?.let { "\"${it.jsonEscape()}\"" } ?: "null").append(',')
    append("\n  \"repairMetadata\": ")
        .append(repairMetadata?.toJson(schemaVersion) ?: "null").append(',')
    if (schemaVersion >= 3) append("\n  \"validationProof\": ").append(validationProof?.toStateJson() ?: "null").append(',')
    if (schemaVersion >= 4 && (rollbackRecord != null || nullNodeWire == NullRollbackNodeWire.EXPLICIT_NULL)) {
        append("\n  \"rollbackRecord\": ").append(rollbackRecord?.toJson() ?: "null").append(',')
    }
    append("\n  \"recoveredAfterCrash\": ").append(recoveredAfterCrash).append(',')
    append("\n  \"changes\": [")
    append(changes.joinToString(",") { "\n" + it.toJson().prependIndent("    ") })
    append("\n  ]")
    if (schemaVersion >= 5) {
        append(",\n  \"publicationChanges\": [")
        append(publicationChanges.joinToString(",") { "\n" + it.toJson().prependIndent("    ") })
        append("\n  ],")
        append("\n  \"publicationPreimageMetadata\": ")
            .append(publicationPreimageMetadata.toRepairPreimageMetadataJson())
    }
    append("\n}")
}

private fun RevisionFileDelta.toJson(): String =
    "{\"path\":\"${path.jsonEscape()}\",\"beforeSha256\":" +
        (beforeSha256?.let { "\"$it\"" } ?: "null") +
        ",\"beforeBytes\":" + (beforeBytes?.toString() ?: "null") +
        ",\"afterSha256\":\"$afterSha256\",\"beforeBlobSha256\":" +
        (beforeBlobSha256?.let { "\"$it\"" } ?: "null") +
        ",\"afterBlobSha256\":\"$afterBlobSha256\",\"afterBytes\":$afterBytes}"

private fun PendingAttempt.toJson(schemaVersion: Int): String = buildString {
    append("{\"id\":\"").append(id.jsonEscape()).append("\",\"parentId\":\"").append(parentId.jsonEscape())
    append("\",\"ordinal\":").append(ordinal).append(",\"allowedPaths\":").append(allowedPaths.jsonArray())
    append(",\"parentSourceRevisionSha256\":\"").append(parentSourceRevisionSha256).append("\",")
    append("\"candidateSourceRevisionSha256\":")
        .append(candidateSourceRevisionSha256?.let { "\"$it\"" } ?: "null").append(',')
    append("\"preimages\":[").append(preimages.joinToString(",") { it.toJson() }).append("],")
    append("\"candidateChanges\":[").append(candidateChanges.joinToString(",") { it.toJson() }).append("],")
    if (schemaVersion >= 3) {
        append("\"detached\":").append(detached).append(',')
        append("\"promotionChanges\":[").append(promotionChanges.joinToString(",") { it.toJson() }).append("],")
    }
    append("\"repairMetadata\":").append(repairMetadata?.toJson(schemaVersion) ?: "null")
    if (schemaVersion >= 4) {
        append(",\"legacyRecoveryRequired\":").append(legacyRecoveryRequired)
        append(",\"rollbackRecord\":").append(rollbackRecord?.toJson() ?: "null")
    }
    if (schemaVersion >= 5) {
        append(",\"preimageMetadata\":").append(preimageMetadata.toRepairPreimageMetadataJson())
        append(",\"promotionPreimageMetadata\":").append(promotionPreimageMetadata.toRepairPreimageMetadataJson())
    }
    if (schemaVersion >= 6) {
        append(",\"sourceWitnessSha256\":").append(sourceWitnessSha256?.let { "\"$it\"" } ?: "null")
        append(",\"acceptanceDecision\":").append(acceptanceDecision?.toJson(schemaVersion) ?: "null")
        append(",\"predecisionStageFiles\":").append(predecisionStageFiles.toJson())
    }
    append('}')
}

private fun RepairAcceptanceDecision.toJson(schemaVersion: Int): String = buildString {
    append("{\"proof\":").append(proof.toStateJson())
    append(",\"evidenceKind\":\"").append(evidenceKind.jsonEscape()).append('\"')
    append(",\"evidenceSummary\":\"").append(evidenceSummary.jsonEscape()).append('\"')
    append(",\"evidenceArtifact\":").append(evidenceArtifact?.let { "\"${it.jsonEscape()}\"" } ?: "null")
    append(",\"promotionChanges\":[").append(promotionChanges.joinToString(",") { it.toJson() }).append(']')
    append(",\"intendedHeadId\":\"").append(intendedHeadId.jsonEscape()).append('\"')
    append(",\"intendedRunId\":").append(intendedRunId?.let { "\"${it.jsonEscape()}\"" } ?: "null")
    append(",\"intendedRunStatus\":").append(intendedRunStatus?.name?.let { "\"$it\"" } ?: "null")
    append(",\"stagedFiles\":[").append(stagedFiles.joinToString(",") { it.toJson() }).append(']')
    append(",\"committedNode\":").append(requireNotNull(committedNode).toJson(schemaVersion))
    append(",\"committedRun\":").append(committedRun?.toJson() ?: "null")
    append('}')
}

private fun RepairStagedFile.toJson(): String =
    "{\"path\":\"${path.jsonEscape()}\",\"stagingName\":\"${stagingName.jsonEscape()}\"," +
        "\"device\":$device,\"inode\":$inode,\"mountId\":$mountId,\"mode\":$mode," +
        "\"uid\":$uid,\"gid\":$gid,\"linkCount\":$linkCount,\"sha256\":\"$sha256\"," +
        "\"size\":$size,\"atimeSeconds\":$atimeSeconds,\"atimeNanoseconds\":$atimeNanoseconds," +
        "\"mtimeSeconds\":$mtimeSeconds,\"mtimeNanoseconds\":$mtimeNanoseconds," +
        "\"parentDevice\":$parentDevice,\"parentInode\":$parentInode," +
        "\"parentMountId\":$parentMountId}"

private fun List<RepairPredecisionStage>.toJson(): String = joinToString(prefix = "[", postfix = "]") { staged ->
    "{\"path\":\"${staged.path.jsonEscape()}\",\"stagingName\":\"${staged.stagingName.jsonEscape()}\"," +
        "\"device\":${staged.device},\"inode\":${staged.inode},\"mountId\":${staged.mountId}," +
        "\"mode\":${staged.mode},\"uid\":${staged.uid},\"gid\":${staged.gid}," +
        "\"sha256\":\"${staged.sha256}\",\"size\":${staged.size}}"
}

private fun Map<String, RepairPreimageMetadata>?.toRepairPreimageMetadataJson(): String =
    this?.toSortedMap()?.entries?.joinToString(prefix = "{", postfix = "}", separator = ",") { (path, metadata) ->
        "\"${path.jsonEscape()}\":${metadata.toJson()}"
    } ?: "null"

private fun RepairPreimageMetadata.toJson(): String =
    "{\"metadataVersion\":$metadataVersion,\"device\":$device,\"inode\":$inode," +
        "\"mode\":$mode,\"uid\":$uid,\"gid\":$gid," +
        "\"size\":$size" +
        (if (metadataVersion >= 2) ",\"atimeSeconds\":$atimeSeconds,\"atimeNanoseconds\":$atimeNanoseconds" else "") +
        ",\"mtimeSeconds\":$mtimeSeconds,\"mtimeNanoseconds\":$mtimeNanoseconds," +
        "\"ctimeSeconds\":$ctimeSeconds,\"ctimeNanoseconds\":$ctimeNanoseconds," +
        "\"retainedName\":\"${retainedName.jsonEscape()}\",\"xattrPolicy\":\"$xattrPolicy\"" +
        (if (ancestorMetadata.isEmpty()) "" else ",\"ancestorMetadata\":[" +
            ancestorMetadata.joinToString(",") { it.toJson() } + "]") + "}"

private fun RepairAncestorMetadata.toJson(): String =
    "{\"path\":\"${path.jsonEscape()}\",\"device\":$device,\"inode\":$inode," +
        "\"mode\":$mode,\"uid\":$uid,\"gid\":$gid,\"linkCount\":$linkCount," +
        "\"mountId\":$mountId,\"size\":$size," +
        "\"mtimeSeconds\":$mtimeSeconds,\"mtimeNanoseconds\":$mtimeNanoseconds," +
        "\"ctimeSeconds\":$ctimeSeconds,\"ctimeNanoseconds\":$ctimeNanoseconds" +
        (if (atimeSeconds == null) "" else ",\"atimeSeconds\":$atimeSeconds,\"atimeNanoseconds\":$atimeNanoseconds") +
        (if (entryCount == null) "" else ",\"entryCount\":$entryCount,\"entriesSha256\":\"$entriesSha256\"") + "}"

private fun RepairRollbackRecord.toJson(): String =
    "{\"schemaVersion\":$schemaVersion,\"attemptId\":\"${attemptId.jsonEscape()}\"," +
        "\"runId\":${runId?.let { "\"${it.jsonEscape()}\"" } ?: "null"}," +
        "\"targetRevisionId\":\"${targetRevisionId.jsonEscape()}\"," +
        "\"expectedSourceRevisionSha256\":\"$expectedSourceRevisionSha256\"," +
        "\"state\":\"${state.name.lowercase()}\"," +
        "\"failureStage\":${failureStage?.name?.lowercase()?.let { "\"$it\"" } ?: "null"}," +
        "\"failureCode\":${failureCode?.name?.lowercase()?.let { "\"$it\"" } ?: "null"}," +
        "\"observedSourceRevisionSha256\":" +
        (observedSourceRevisionSha256?.let { "\"$it\"" } ?: "null") + "," +
        "\"legacyPendingStateUnknown\":$legacyPendingStateUnknown," +
        "\"candidateSourceInstallStarted\":" +
        (candidateSourceInstallStarted?.toString() ?: "null") + "}"

private fun RevisionRepairMetadata.toJson(schemaVersion: Int): String = buildString {
    append("{\"iterationIndex\":").append(iterationIndex)
    append(",\"failureKind\":\"").append(failureKind.jsonEscape()).append('"')
    append(",\"prompt\":\"").append(prompt.jsonEscape()).append('"')
    append(",\"summary\":").append(summary?.let { "\"${it.jsonEscape()}\"" } ?: "null")
    append(",\"retainedRegressionIds\":").append(retainedRegressionIds.jsonArray())
    append(",\"before\":").append(before?.toGraphJson() ?: "null")
    append(",\"regressionCorpusSha256\":")
        .append(regressionCorpusSha256?.let { "\"${it.jsonEscape()}\"" } ?: "null")
    if (schemaVersion >= 2) {
        append(",\"agentInvocation\":").append(agentInvocation?.toGraphJson(schemaVersion) ?: "null")
        append(",\"publicationMode\":\"").append(publicationMode.name.lowercase()).append('"')
    }
    if (schemaVersion >= 3) append(",\"runId\":").append(runId?.let { "\"$it\"" } ?: "null")
    if (schemaVersion >= 7) append(",\"turnIntent\":").append(turnIntent?.toGraphJson() ?: "null")
    append('}')
}

private fun RepairAgentTurnIntentBinding.toGraphJson(): String =
    "{\"intentPath\":\"${intentPath.jsonEscape()}\",\"intentSha256\":\"$intentSha256\",\"turnId\":\"$turnId\"}"

private fun RepairAgentInvocationBinding.toGraphJson(schemaVersion: Int): String = buildString {
    append("{\"receiptPath\":\"").append(receiptPath.jsonEscape()).append("\",\"receiptSha256\":\"").append(receiptSha256).append('\"')
    append(",\"receiptSchemaVersion\":").append(receiptSchemaVersion).append(",\"requestSha256\":\"").append(requestSha256).append('\"')
    append(",\"resultChangesSha256\":\"").append(resultChangesSha256).append('\"')
    append(",\"terminalOutcome\":\"").append(terminalOutcome.jsonEscape()).append('\"')
    append(",\"receiptReleaseComplete\":").append(receiptReleaseComplete)
    if (schemaVersion >= 7) {
        append(",\"intentPath\":").append(intentPath?.let { "\"${it.jsonEscape()}\"" } ?: "null")
        append(",\"intentSha256\":").append(intentSha256?.let { "\"$it\"" } ?: "null")
        append(",\"turnId\":").append(turnId?.let { "\"$it\"" } ?: "null")
        append(",\"assessmentPath\":").append(assessmentPath?.let { "\"${it.jsonEscape()}\"" } ?: "null")
        append(",\"assessmentSha256\":").append(assessmentSha256?.let { "\"$it\"" } ?: "null")
    }
    append(",\"assessmentStatus\":\"").append(assessmentStatus.name.lowercase()).append("\"}")
}

private fun List<ProcessInput>.toGraphJson(): String = joinToString(prefix = "[", postfix = "]") { input ->
    "{\"id\":\"${input.id.jsonEscape()}\",\"args\":${input.args.jsonArray()}," +
        "\"stdinHex\":\"${input.stdin.toHexLower()}\"}"
}

private fun RepairEvidence.toGraphJson(): String =
    "{\"kind\":\"${kind.jsonEscape()}\",\"summary\":\"${summary.jsonEscape()}\",\"artifactPath\":" +
        (artifactPath?.let { "\"${it.jsonEscape()}\"" } ?: "null") + "}"

// Migration adds only bounded, allowlisted records and default wire-format fields. Keep the
// authorized budget and profile identity unchanged: ordinary graph content still pays every byte.
private const val MAXIMUM_ROLLBACK_RECORD_BYTES = 1024L
private const val MAXIMUM_MIGRATION_BYTES_PER_NODE = 2048L

private fun revisionGraphReadLimit(budget: RepairResourceBudget): Long = minOf(
    Int.MAX_VALUE.toLong() - 1,
    budget.maximumGraphBytes + (budget.maximumRevisionNodes.toLong() + 1) * MAXIMUM_MIGRATION_BYTES_PER_NODE,
)

private fun readBoundedRevisionGraph(store: RepairStateStore, budget: RepairResourceBudget): Pair<ByteArray, RevisionGraphState> {
    val bytes = store.readGraph(revisionGraphReadLimit(budget))
    val parsed = parseCanonicalGraph(bytes, "reports/repair-revisions/graph.json")
    require(parsed.state.budget == budget) { "revision graph resource budget differs from the requested budget" }
    requireRevisionGraphAdmission(parsed.state, bytes.size.toLong(), parsed.nullNodeWire, purpose = DeclaredOriginPurpose.LOCAL_RECORDED) { consume ->
        store.forEachDeclaredLegacyGraph(budget, consume)
    }
    return bytes to parsed.state
}

/** Focused byte-credit fixture API only; production uses combined semantic admission. */
internal fun requireRepairGraphByteBudget(
    payload: ByteArray,
    budget: RepairResourceBudget,
    forEachDeclaredGraph: ((String, ByteArray) -> Unit) -> Unit = { _ -> },
) {
    if (payload.size.toLong() <= budget.maximumGraphBytes) return
    require(payload.size.toLong() <= revisionGraphReadLimit(budget)) { "repair graph exceeds migration read bound" }
    val parsed = parseCanonicalGraph(payload, "repair release graph")
    require(parsed.state.budget == budget)
    requireRevisionGraphByteBudget(parsed.state, payload.size.toLong(), parsed.nullNodeWire, forEachDeclaredGraph)
}

/** Semantic admission plus credit, never a release permit or external writer-origin proof. */
internal fun requireRepairReleaseGraphAdmission(
    payload: ByteArray,
    budget: RepairResourceBudget,
    forEachDeclaredGraph: ((String, ByteArray) -> Unit) -> Unit,
) {
    try {
        require(payload.isNotEmpty() && payload.size.toLong() <= revisionGraphReadLimit(budget))
        val parsed = if (payload.size.toLong() > budget.maximumGraphBytes)
            parseCanonicalGraph(payload, "repair release graph")
        else CanonicalRevisionGraph(parseGraph(decodeUtf8Strict(payload, "repair release graph")), NullRollbackNodeWire.COMPACT)
        require(parsed.state.budget == budget)
        requireRevisionGraphAdmission(parsed.state, payload.size.toLong(), parsed.nullNodeWire,
            purpose = DeclaredOriginPurpose.ARCHIVE_RELEASE, forEachDeclaredGraph = forEachDeclaredGraph)
    } catch (failure: IllegalArgumentException) {
        // Preserve the release verifier's existing closed marker/pair diagnostics at this earlier gate.
        when (failure.message) {
            "legacy changed attempt has a fabricated source-install marker",
            "legacy unchanged attempt has a fabricated source-install marker",
            "native rollback requires a known source-install marker",
            "failure-free restored rollback has an unstarted source-install marker",
            "not-required rollback requires an unstarted source-install marker",
            "rollback failure stage/code pair is invalid" ->
                throw IllegalArgumentException("repair release ${failure.message}", failure)
            else -> throw failure
        }
    }
}

/** A legacy graph has only one pending attempt, and no rollback records before that migration. */
internal fun requireSingleLegacyRollbackOrigin(legacyFlags: List<Boolean>) {
    require(legacyFlags.count { it } <= 1 && (legacyFlags.none { it } || legacyFlags.first())) {
        "repair graph has multiple or out-of-order legacy rollback origins"
    }
}

private enum class DeclaredLegacyGraphOrigin(val schema: Int) {
    SCHEMA1(1), SCHEMA2(2), SCHEMA3(3), SCHEMA4(4),
}

/** Current declared compatibility input; a self hash is integrity, never chronology/execution. */
private data class DeclaredLegacyGraph(val graph: CanonicalRevisionGraph, val origin: DeclaredLegacyGraphOrigin)

private val DECLARED_LEGACY_GRAPH_NAME = Regex("legacy-graph-([0-9a-f]{64})\\.json")
private val RECOVERY_FAILURE_PAIRS = listOf(
    RepairRollbackStage.SOURCE_RESTORE to RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE,
    RepairRollbackStage.SOURCE_RESTORE to RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
    RepairRollbackStage.SOURCE_VERIFICATION to RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
    RepairRollbackStage.SOURCE_VERIFICATION to RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
)

private fun joinedLegacyPending(source: RevisionGraphState, current: RevisionGraphState): PendingAttempt? {
    val pending = source.pending ?: return null
    if (source.schemaVersion !in 1..3 || source.budget != current.budget ||
        source.profileId != current.profileId || source.profileSha256 != current.profileSha256 ||
        source.indexSha256 != current.indexSha256 || source.editablePaths != current.editablePaths ||
        source.nodes.size > current.nodes.size || source.nodes.size > source.budget.maximumRevisionNodes ||
        source.nodes.map { it.id }.distinct().size != source.nodes.size ||
        source.nodes.any { it.rollbackRecord != null }
    ) return null
    val prefix = source.nodes.map { node ->
        if (source.schemaVersion < 3 && node.status == ModuleRevisionStatus.ACCEPTED)
            node.copy(status = ModuleRevisionStatus.LEGACY_UNVERIFIED) else node
    }
    if (current.nodes.take(prefix.size) != prefix) return null
    if (source.retainedRegressionInputs.any { old -> current.retainedRegressionInputs.none {
            it.id == old.id && it.args == old.args && it.stdin.contentEquals(old.stdin) } }) return null
    val active = current.pending?.takeIf { it.id == pending.id }
    val node = current.nodes.getOrNull(prefix.size)?.takeIf { it.id == pending.id }
    if ((active == null) == (node == null)) return null
    val record = active?.rollbackRecord ?: node?.rollbackRecord ?: return null
    val target = if (pending.detached) source.headId else pending.parentId
    if (!record.legacyPendingStateUnknown || record.attemptId != pending.id ||
        record.runId != pending.repairMetadata?.runId || record.targetRevisionId != target ||
        record.expectedSourceRevisionSha256 != revisionSha256(revisionSourcesAt(source.nodes, target).values)) return null
    if ((pending.candidateChanges.isNotEmpty() && record.candidateSourceInstallStarted != null) ||
        (pending.candidateChanges.isEmpty() && record.candidateSourceInstallStarted != false)) return null
    val metadata = active?.repairMetadata ?: node?.repairMetadata
    val oldMetadata = pending.repairMetadata
    if ((metadata == null) != (oldMetadata == null)) return null
    if (metadata != null && oldMetadata != null) {
        if (metadata.copy(agentInvocation = oldMetadata.agentInvocation) != oldMetadata) return null
        val assessment = if (active != null) RepairAgentAssessmentStatus.PENDING else RepairAgentAssessmentStatus.REJECTED
        if (metadata.agentInvocation?.assessmentStatus?.let { it != assessment } == true) return null
        if (oldMetadata.agentInvocation != null && metadata.agentInvocation !=
            oldMetadata.agentInvocation.copy(assessmentStatus = assessment)) return null
    }
    if (active != null) {
        if (!active.legacyRecoveryRequired || current.nodes.size != prefix.size || active.copy(rollbackRecord = null,
                legacyRecoveryRequired = pending.legacyRecoveryRequired, repairMetadata = oldMetadata) != pending) return null
    } else if (node != null) {
        if (node.parentId != pending.parentId || node.ordinal != pending.ordinal || node.status != ModuleRevisionStatus.REJECTED ||
            node.sourceRevisionSha256 != (pending.candidateSourceRevisionSha256 ?: pending.parentSourceRevisionSha256) ||
            node.changes != pending.candidateChanges || node.validationProof != null) return null
        if (node.recoveredAfterCrash && (node.evidenceKind != RESTART_RECOVERY_EVIDENCE.kind ||
                node.evidenceSummary != RESTART_RECOVERY_EVIDENCE.summary || node.evidenceArtifact != null)) return null
    }
    return pending
}

private enum class DeclaredOriginPurpose { LOCAL_RECORDED, ARCHIVE_RELEASE }

/** One parsed original source per admission. No IO, serialized permit, or global cache. */
private data class DeclaredRollbackOrigins(
    val source: DeclaredLegacyGraph,
    val pending: PendingAttempt?,
    val name: String,
    val sha256: String,
)

private fun normalizedDeclaredNodes(source: RevisionGraphState): List<ModuleRevisionNode> = source.nodes.map { node ->
    if (source.schemaVersion < 3 && node.status == ModuleRevisionStatus.ACCEPTED)
        node.copy(status = ModuleRevisionStatus.LEGACY_UNVERIFIED) else node
}

private fun validateDeclaredGraphSemantics(source: RevisionGraphState) {
    val paths = validateRecordedGraphShape(source)
    validateRepairRunContract(source)
    validateRecordedGraphBody(source, paths)
    validateRecordedAgentAssociations(source)
}

/** Complete immutable prefix/context; later append-only nodes/runs/corpus are separately validated. */
private fun joinedDeclaredPrefix(source: RevisionGraphState, current: RevisionGraphState): Boolean {
    if (source.budget != current.budget || source.profileId != current.profileId ||
        source.profileSha256 != current.profileSha256 || source.indexSha256 != current.indexSha256 ||
        source.editablePaths != current.editablePaths || source.nodes.size > current.nodes.size ||
        current.nodes.take(source.nodes.size) != normalizedDeclaredNodes(source) ||
        source.retainedRegressionInputs.any { old -> current.retainedRegressionInputs.none {
            it.id == old.id && it.args == old.args && it.stdin.contentEquals(old.stdin) } }) return false
    // A source's head/proof/provisional references are already validated against its complete
    // prefix. If no later node exists, those historical boundary associations cannot change.
    val laterAccepted = current.nodes.drop(source.nodes.size).any { it.status == ModuleRevisionStatus.ACCEPTED } ||
        current.runs.drop(source.runs.size).any { it.status == RepairRunStatus.FULLY_ACCEPTED }
    if (!laterAccepted && (current.fullyAcceptedHeadId != source.fullyAcceptedHeadId ||
            current.acceptedProof != source.acceptedProof)) return false
    if (current.nodes.size == source.nodes.size && current.runs.size == source.runs.size &&
        (current.headId != source.headId || current.provisionalHeadId != source.provisionalHeadId ||
            current.fullyAcceptedHeadId != source.fullyAcceptedHeadId || current.acceptedProof != source.acceptedProof)) return false
    return true
}

private fun joinedDeclaredPending(source: RevisionGraphState, current: RevisionGraphState): PendingAttempt? {
    val pending = joinedLegacyPending(source, current) ?: return null
    if (!joinedDeclaredPrefix(source, current) || current.runs.size < source.runs.size) return null
    val active = current.pending?.takeIf { it.id == pending.id }
    val node = current.nodes.getOrNull(source.nodes.size)?.takeIf { it.id == pending.id }
    val record = active?.rollbackRecord ?: node?.rollbackRecord ?: return null
    if (record.failureCode == null) {
        if (record.failureStage != null || (active != null &&
                (record.state != RepairRollbackState.RESTORE_IN_PROGRESS || record.observedSourceRevisionSha256 != null))) return null
        if (node != null && record.state != (if (record.candidateSourceInstallStarted == false)
                RepairRollbackState.NOT_REQUIRED_VERIFIED else RepairRollbackState.RESTORED_VERIFIED)) return null
    } else {
        if (RECOVERY_FAILURE_PAIRS.none { it.first == record.failureStage && it.second == record.failureCode }) return null
        if (record.state != (if (active != null) RepairRollbackState.RESTORE_FAILED_UNRESOLVED
                else RepairRollbackState.RESTORED_AFTER_FAILURE)) return null
    }
    if (node != null && record.observedSourceRevisionSha256 != record.expectedSourceRevisionSha256) return null
    val metadata = active?.repairMetadata ?: node?.repairMetadata
    // An originally absent invocation can be recovered only by the existing physical receipt
    // validation at the live/archive layer; pure admission additionally keeps its candidate join.
    val originalInvocation = pending.repairMetadata?.agentInvocation
    val restoredInvocation = metadata?.agentInvocation?.copy(assessmentStatus = RepairAgentAssessmentStatus.PENDING)
    if (originalInvocation == null && restoredInvocation != null) {
        validateRecordedInvocationBinding(4, restoredInvocation, pending.id, RepairAgentAssessmentStatus.PENDING)
        if (pending.candidateSourceRevisionSha256 != null)
            requireRecordedPendingChanges(restoredInvocation, pending.candidateChanges, pending.id)
    }
    val restoredPending = pending.copy(repairMetadata = pending.repairMetadata?.copy(agentInvocation = restoredInvocation))
    val initial = initialRollbackRecord(source, restoredPending, true)
    val base = source.copy(schemaVersion = 4, nodes = normalizedDeclaredNodes(source),
        pending = restoredPending.copy(legacyRecoveryRequired = true, rollbackRecord = initial))
    val marked = if (record.failureCode != null) withCommittedRollbackFailure(base,
        record.copy(state = RepairRollbackState.RESTORE_FAILED_UNRESOLVED))
        else base.copy(pending = requireNotNull(base.pending).copy(rollbackRecord = record))
    var projected = marked
    if (node != null) {
        val evidence = if (node.recoveredAfterCrash) RESTART_RECOVERY_EVIDENCE else node.evidenceKind?.let {
            RepairEvidence(it, requireNotNull(node.evidenceSummary), node.evidenceArtifact) }
        val expected = finalizedRepairNode(requireNotNull(marked.pending), ModuleRevisionStatus.REJECTED,
            evidence, node.recoveredAfterCrash, record, { node.changedModules }, { node.invalidatedModules })
        if (expected != node) return null
        projected = withFinalizedRollback(marked.copy(nodes = marked.nodes + expected, pending = null), record)
    }
    val runs = current.runs.take(source.runs.size)
    if (runs != projected.runs) {
        // Exact existing producer interruption, not arbitrary terminal status/head/evidence edits.
        if (node?.recoveredAfterCrash != true || projected.runs.lastOrNull()?.terminal != false ||
            runs != finishedRunCandidate(projected, RepairRunStatus.INTERRUPTED, RESTART_INTERRUPTION_EVIDENCE).runs) return null
    }
    return pending
}

private fun selectDeclaredRollbackOrigins(
    state: RevisionGraphState,
    missingFinal: Set<String>,
    flagged: Boolean,
    scan: ((String, ByteArray) -> Unit) -> Unit,
): DeclaredRollbackOrigins? {
    var selected: DeclaredRollbackOrigins? = null
    var examined = 0
    var remaining = state.budget.maximumIndexEvidenceBytes
    val names = HashSet<String>()
    scan { name, bytes ->
        examined = Math.addExact(examined, 1)
        require(examined <= state.budget.maximumStateDirectoryEntries && names.add(name)) {
            "declared legacy graph count or uniqueness exceeds its entry bound" }
        require(bytes.isNotEmpty() && bytes.size.toLong() <= minOf(state.budget.maximumGraphBytes, remaining)) {
            "declared legacy graph exceeds its aggregate payload bound" }
        remaining -= bytes.size.toLong()
        val match = requireNotNull(DECLARED_LEGACY_GRAPH_NAME.matchEntire(name)) { "invalid declared legacy graph name" }
        require(sha256(bytes) == match.groupValues[1]) { "declared legacy graph digest changed" }
        val parsed = parseCanonicalGraph(bytes, "declared legacy graph")
        val origin = requireNotNull(DeclaredLegacyGraphOrigin.entries.singleOrNull { it.schema == parsed.state.schemaVersion }) {
            "declared legacy graph must have schema1,2,3 or4" }
        val source = parsed.state
        require(bytes.size.toLong() <= source.budget.maximumGraphBytes) { "declared legacy graph exceeds its original byte budget" }
        validateDeclaredGraphSemantics(source)
        val pending = if (flagged) joinedDeclaredPending(source, state) else null
        val joins = if (flagged) pending != null else source.pending == null &&
            joinedDeclaredPrefix(source, state) && currentRunPrefixUnchanged(source, state)
        val nullableIds = source.nodes.filter { it.status == ModuleRevisionStatus.REJECTED && it.rollbackRecord == null }
            .map { it.id }.toSet()
        if (joins && missingFinal.all { it in nullableIds }) {
            require(selected == null) { "multiple declared legacy graphs join the same migration origin" }
            selected = DeclaredRollbackOrigins(DeclaredLegacyGraph(parsed, origin), pending, name, match.groupValues[1])
        }
    }
    return selected
}

private fun currentRunPrefixUnchanged(source: RevisionGraphState, current: RevisionGraphState): Boolean =
    current.runs.size >= source.runs.size && current.runs.take(source.runs.size) == source.runs

private fun selectDeclaredLegacyGraph(
    state: RevisionGraphState,
    scan: ((String, ByteArray) -> Unit) -> Unit,
): DeclaredLegacyGraph? {
    var selected: DeclaredLegacyGraph? = null
    var examined = 0
    var remaining = state.budget.maximumIndexEvidenceBytes
    scan { name, bytes ->
        examined++
        require(examined <= state.budget.maximumStateDirectoryEntries) { "declared legacy graph count exceeds its entry bound" }
        require(bytes.isNotEmpty() && bytes.size.toLong() <= minOf(state.budget.maximumGraphBytes, remaining)) {
            "declared legacy graph exceeds its aggregate payload bound"
        }
        remaining -= bytes.size.toLong()
        val match = requireNotNull(DECLARED_LEGACY_GRAPH_NAME.matchEntire(name)) { "invalid declared legacy graph name" }
        require(sha256(bytes) == match.groupValues[1]) { "declared legacy graph digest changed" }
        val parsed = parseCanonicalGraph(bytes, "declared legacy graph")
        val origin = requireNotNull(DeclaredLegacyGraphOrigin.entries.singleOrNull { it.schema == parsed.state.schemaVersion }) {
            "declared legacy graph must have schema1,2,3 or4"
        }
        // Schema-4 snapshots can be preserved as a pre-upgrade byte witness, but they are not
        // eligible as the schema-1..3 authority for legacy run/pending recovery.
        if (origin == DeclaredLegacyGraphOrigin.SCHEMA4) return@scan
        if (joinedLegacyPending(parsed.state, state) != null) {
            require(selected == null) { "multiple declared legacy graphs join the same migration origin" }
            selected = DeclaredLegacyGraph(parsed, origin)
        }
    }
    return selected
}

/** Locate exact value tokens in our existing serializer output; never compact payload whitespace. */
private fun chargedOriginValues(json: String, fields: Set<String>): Long {
    fun stringEnd(start: Int): Int {
        var at = start + 1
        while (at < json.length) {
            when (json[at]) {
                '\\' -> at += 2
                '"' -> return at + 1
                else -> at++
            }
        }
        error("incomplete producer JSON string")
    }
    fun valueEnd(start: Int): Int {
        if (json[start] == '"') return stringEnd(start)
        if (json[start] != '[' && json[start] != '{') {
            var at = start
            while (at < json.length && !json[at].isWhitespace() && json[at] !in ",}]") at++
            return at
        }
        var depth = 0
        var at = start
        while (at < json.length) {
            when (json[at]) {
                '"' -> { at = stringEnd(at); continue }
                '[', '{' -> depth++
                ']', '}' -> { depth--; if (depth == 0) return at + 1 }
            }
            at++
        }
        error("incomplete producer JSON value")
    }
    var at = json.indexOf('{') + 1
    var bytes = 0L
    while (at < json.length) {
        while (at < json.length && (json[at].isWhitespace() || json[at] == ',')) at++
        if (json[at] == '}') return bytes
        require(json[at] == '"')
        val keyEnd = stringEnd(at)
        val key = Json.parseToJsonElement(json.substring(at, keyEnd)).jsonPrimitive.content
        at = keyEnd
        while (json[at].isWhitespace()) at++
        require(json[at++] == ':')
        while (json[at].isWhitespace()) at++
        val end = valueEnd(at)
        if (key in fields) bytes += json.substring(at, end).toByteArray(Charsets.UTF_8).size.toLong()
        at = end
    }
    error("incomplete producer JSON object")
}

private val PENDING_CHARGED_VALUES = setOf("id", "parentId", "ordinal", "allowedPaths", "parentSourceRevisionSha256",
    "candidateSourceRevisionSha256", "preimages", "candidateChanges", "promotionChanges")
private val NODE_CHARGED_VALUES = setOf("id", "parentId", "ordinal", "sourceRevisionSha256", "changes", "changedModules", "invalidatedModules")

private fun declaredMigrationCredit(state: RevisionGraphState, wire: NullRollbackNodeWire, source: DeclaredLegacyGraph): Long {
    val original = source.graph.state
    val pending = joinedLegacyPending(original, state) ?: return 0L
    val active = state.pending?.takeIf { it.id == pending.id }
    val node = state.nodes.getOrNull(original.nodes.size)?.takeIf { it.id == pending.id }
    val record = active?.rollbackRecord ?: node?.rollbackRecord ?: return 0L
    if (active != null && record.state != (if (record.failureCode == null)
            RepairRollbackState.RESTORE_IN_PROGRESS else RepairRollbackState.RESTORE_FAILED_UNRESOLVED)) return 0L
    if (active != null && record.failureCode == null && record.observedSourceRevisionSha256 != null) return 0L
    if (node != null && record.state != (if (record.failureCode != null) RepairRollbackState.RESTORED_AFTER_FAILURE
            else if (record.candidateSourceInstallStarted == false) RepairRollbackState.NOT_REQUIRED_VERIFIED
            else RepairRollbackState.RESTORED_VERIFIED)) return 0L
    if (record.failureCode != null && RECOVERY_FAILURE_PAIRS.none {
            it.first == record.failureStage && it.second == record.failureCode }) return 0L
    var templateRuns = original.runs
    val runId = pending.repairMetadata?.runId
    if (runId != null) {
        val oldRun = original.runs.singleOrNull { it.id == runId } ?: return 0L
        val actual = state.runs.singleOrNull { it.id == runId } ?: return 0L
        var expected = oldRun
        if (record.failureCode != null) {
            expected = oldRun.copy(schemaVersion = maxOf(oldRun.schemaVersion, 2), status = RepairRunStatus.ROLLBACK_FAILED,
                rollbackFailureAttemptId = pending.id, rollbackResolution = record.state)
        } else if (node?.recoveredAfterCrash == true && oldRun.status == RepairRunStatus.RUNNING && actual.status == RepairRunStatus.INTERRUPTED) {
            expected = oldRun.copy(status = RepairRunStatus.INTERRUPTED, lastEvidence = RESTART_INTERRUPTION_EVIDENCE)
        }
        val published = if (expected.status == RepairRunStatus.INTERRUPTED && oldRun.status == RepairRunStatus.RUNNING)
            expected.copy(acceptedHeadId = original.fullyAcceptedHeadId, provisionalHeadId = original.provisionalHeadId) else expected
        if (actual != published) return 0L
        // Head assignments carry their actual cost, not compatibility credit.
        templateRuns = original.runs.map { if (it.id == runId) expected else it }
    } else if (record.runId != null) return 0L
    val prefix = original.nodes.map { n -> if (source.origin.schema < 3 && n.status == ModuleRevisionStatus.ACCEPTED)
        n.copy(status = ModuleRevisionStatus.LEGACY_UNVERIFIED) else n }
    var template = original.copy(schemaVersion = 4, nodes = prefix, runs = templateRuns)
    // The empty promotion list is a newly required default for source1/2, not new data.
    val pendingChargedFields = if (source.origin.schema < 3) PENDING_CHARGED_VALUES - "promotionChanges" else PENDING_CHARGED_VALUES
    val oldCharged = chargedOriginValues(pending.toJson(source.origin.schema), pendingChargedFields)
    val newCharged: Long
    if (active != null) {
        val projected = pending.copy(legacyRecoveryRequired = true, rollbackRecord = record)
        template = template.copy(pending = projected)
        newCharged = chargedOriginValues(projected.toJson(4), pendingChargedFields)
    } else {
        val actual = requireNotNull(node)
        val metadata = pending.repairMetadata?.let { it.copy(agentInvocation = it.agentInvocation?.copy(assessmentStatus = RepairAgentAssessmentStatus.REJECTED)) }
        val projected = actual.copy(repairMetadata = metadata)
        template = template.copy(nodes = prefix + projected, pending = null)
        val charged = if (actual.recoveredAfterCrash) NODE_CHARGED_VALUES else
            NODE_CHARGED_VALUES + setOf("evidenceKind", "evidenceSummary", "evidenceArtifact")
        // Delta values are identical to the joined pending candidate. Charge its real compact
        // payload; the node's mandatory pretty indentation is format, not extra source data.
        newCharged = chargedOriginValues(projected.toJson(4, wire), charged - "changes") +
            chargedOriginValues(pending.toJson(source.origin.schema), setOf("candidateChanges"))
    }
    val encodingDelta = renderGraph(template, wire).toByteArray(Charsets.UTF_8).size.toLong() -
        renderGraph(original, source.graph.nullNodeWire).toByteArray(Charsets.UTF_8).size.toLong()
    val allowance = maxOf(0L, encodingDelta - (newCharged - oldCharged))
    require(allowance <= (original.nodes.size.toLong() + 1) * MAXIMUM_MIGRATION_BYTES_PER_NODE) {
        "declared migration encoding exceeds its fixed original population bound"
    }
    return allowance
}

private fun requireRollbackRecordBounds(state: RevisionGraphState) {
    val records = state.nodes.mapNotNull { it.rollbackRecord } + listOfNotNull(state.pending?.rollbackRecord)
    requireSingleLegacyRollbackOrigin(records.map { it.legacyPendingStateUnknown })
    records.forEach { record ->
        require(record.toJson().toByteArray(Charsets.UTF_8).size.toLong() <= MAXIMUM_ROLLBACK_RECORD_BYTES) {
            "repair rollback record exceeds its fixed byte bound"
        }
    }
    state.nodes.forEach { node -> node.rollbackRecord?.let {
        requireLegacyRollbackInstallMarker(it, node.changes.isNotEmpty()) } }
    state.pending?.let { pending -> pending.rollbackRecord?.let {
        requireLegacyRollbackInstallMarker(it, pending.candidateChanges.isNotEmpty()) } }
}

private fun requireDeclaredGraphBytes(
    state: RevisionGraphState,
    bytes: Long,
    wire: NullRollbackNodeWire,
    source: DeclaredLegacyGraph?,
) {
    if (bytes <= state.budget.maximumGraphBytes) return
    val allowance = source?.let { declaredMigrationCredit(state, wire, it) } ?: 0L
    if (bytes - allowance > state.budget.maximumGraphBytes) {
        throw RepairBudgetExceededException("repair revision graph exceeds ${state.budget.maximumGraphBytes} content bytes")
    }
}

private fun requireRevisionGraphAdmission(
    state: RevisionGraphState,
    bytes: Long,
    nullNodeWire: NullRollbackNodeWire = NullRollbackNodeWire.COMPACT,
    purpose: DeclaredOriginPurpose,
    forEachDeclaredGraph: ((String, ByteArray) -> Unit) -> Unit = { _ -> },
) {
    requireRollbackRecordBounds(state)
    val missing = if (state.schemaVersion >= 4) state.nodes.filter {
        it.status == ModuleRevisionStatus.REJECTED && it.rollbackRecord == null }.map { it.id }.toSet() else emptySet()
    val flagged = state.schemaVersion >= 4 && (state.pending?.rollbackRecord?.legacyPendingStateUnknown == true ||
        state.nodes.any { it.rollbackRecord?.legacyPendingStateUnknown == true })
    val needed = flagged || (purpose == DeclaredOriginPurpose.LOCAL_RECORDED && missing.isNotEmpty())
    val origins = if (needed) selectDeclaredRollbackOrigins(state, missing, flagged, forEachDeclaredGraph) else null
    if (needed && origins == null) {
        if (bytes > state.budget.maximumGraphBytes)
            throw RepairBudgetExceededException("repair revision graph lacks a complete declared rollback origin")
        require(origins != null) { "repair revision graph lacks a complete declared rollback origin" }
    }
    // Only a complete pending origin can supply existing encoding credit. A nullable prefix
    // grants zero bytes, and archive's independent blanket finalized-record refusal remains.
    requireDeclaredGraphBytes(state, bytes, nullNodeWire, origins?.takeIf { it.pending != null }?.source)
}

/** Budget-only authored fixture seam; never a successful production semantic admission. */
private fun requireRevisionGraphByteBudget(
    state: RevisionGraphState,
    bytes: Long,
    nullNodeWire: NullRollbackNodeWire = NullRollbackNodeWire.COMPACT,
    forEachDeclaredGraph: ((String, ByteArray) -> Unit) -> Unit = { _ -> },
) {
    requireRollbackRecordBounds(state)
    if (bytes <= state.budget.maximumGraphBytes) return
    val flagged = state.schemaVersion >= 4 && (state.pending?.rollbackRecord?.legacyPendingStateUnknown == true ||
        state.nodes.any { it.rollbackRecord?.legacyPendingStateUnknown == true })
    val source = if (flagged) selectDeclaredLegacyGraph(state, forEachDeclaredGraph) else null
    requireDeclaredGraphBytes(state, bytes, nullNodeWire, source)
}

private data class CanonicalRevisionGraph(val state: RevisionGraphState, val nullNodeWire: NullRollbackNodeWire)

private fun parseCanonicalGraph(payload: ByteArray, label: String): CanonicalRevisionGraph {
    val state = parseGraph(decodeUtf8Strict(payload, label))
    // Select a complete encoding, never a per-node mixture. Comparing raw canonical bytes also
    // refuses unknown/duplicate fields and whitespace changes without rewriting digest identity.
    val wire = when {
        renderGraph(state).toByteArray(Charsets.UTF_8).contentEquals(payload) -> NullRollbackNodeWire.COMPACT
        renderGraph(state, NullRollbackNodeWire.EXPLICIT_NULL).toByteArray(Charsets.UTF_8)
            .contentEquals(payload) -> NullRollbackNodeWire.EXPLICIT_NULL
        else -> throw IllegalArgumentException("$label is not the exact canonical graph encoding")
    }
    return CanonicalRevisionGraph(state, wire)
}

private fun parseGraph(payload: String): RevisionGraphState {
    val root = Json.parseToJsonElement(payload).jsonObject
    val schemaVersion = root["schemaVersion"]?.jsonPrimitive?.intOrNull
        ?: error("repair revision graph is missing schemaVersion")
    require(schemaVersion in 1..7) { "unsupported repair revision graph schema" }
    val budget = root.getValue("budget").jsonObject.let { value ->
        RepairResourceBudget(
            maximumIndexedModules = value.requiredInt("maximumIndexedModules"),
            maximumIndexedEntities = value.requiredInt("maximumIndexedEntities"),
            maximumDependencyEdges = value.requiredLong("maximumDependencyEdges"),
            maximumSourceFiles = value.requiredInt("maximumSourceFiles"),
            maximumSourceFileBytes = value.requiredLong("maximumSourceFileBytes"),
            maximumSourceBytes = value.requiredLong("maximumSourceBytes"),
            maximumIndexEvidenceBytes = value.requiredLong("maximumIndexEvidenceBytes"),
            maximumDiagnosticCharacters = value.requiredInt("maximumDiagnosticCharacters"),
            maximumRegressionInputBytes = value.requiredLong("maximumRegressionInputBytes"),
            maximumRegressionInputs = value.requiredInt("maximumRegressionInputs"),
            maximumRegressionArguments = value.requiredInt("maximumRegressionArguments"),
            maximumRequestBytes = value.requiredLong("maximumRequestBytes"),
            maximumResponseBytes = value.requiredLong("maximumResponseBytes"),
            maximumProjectionBytes = value.requiredLong("maximumProjectionBytes"),
            maximumContextModules = value.requiredInt("maximumContextModules"),
            maximumContextFiles = value.requiredInt("maximumContextFiles"),
            maximumContextBytes = value.requiredLong("maximumContextBytes"),
            maximumStagingDirectories = value.requiredInt("maximumStagingDirectories"),
            maximumStagingBytes = value.requiredLong("maximumStagingBytes"),
            maximumPatchFiles = value.requiredInt("maximumPatchFiles"),
            maximumPatchBytes = value.requiredLong("maximumPatchBytes"),
            maximumBehaviorStdoutBytes = value.requiredLong("maximumBehaviorStdoutBytes"),
            maximumBehaviorStderrBytes = value.requiredLong("maximumBehaviorStderrBytes"),
            maximumBehaviorOutputBytes = value.requiredLong("maximumBehaviorOutputBytes"),
            maximumBehaviorExecutionMillis = value.requiredLong("maximumBehaviorExecutionMillis"),
            maximumDiscoveryEntries = value.requiredInt("maximumDiscoveryEntries"),
            maximumDiscoveryDirectories = value.requiredInt("maximumDiscoveryDirectories"),
            maximumDiscoveryDepth = value.requiredInt("maximumDiscoveryDepth"),
            maximumStateDirectoryEntries = value.requiredInt("maximumStateDirectoryEntries"),
            maximumGraphLockWaitMillis = value.requiredLong("maximumGraphLockWaitMillis"),
            maximumRevisionNodes = value.requiredInt("maximumRevisionNodes"),
            maximumGraphBytes = value.requiredLong("maximumGraphBytes"),
            maximumStoredBlobBytes = value.requiredLong("maximumStoredBlobBytes"),
        )
    }
    val nodes = root.getValue("nodes").jsonArray.map { parseNode(it, schemaVersion) }
    val pendingElement = root["pending"]
    return RevisionGraphState(
        budget,
        root.requiredString("profileId"),
        root.requiredString("profileSha256"),
        root.stringList("editablePaths"),
        root.requiredString("indexSha256"),
        root.getValue("retainedRegressionInputs").jsonArray.map(::parseRegressionInput),
        root.requiredString("regressionCorpusSha256"),
        root.requiredString("headId"),
        root.requiredInt("nextOrdinal"),
        nodes,
        pendingElement?.takeUnless { it is JsonNull }?.let { parsePending(it, schemaVersion) },
        root.requiredLong("storedBlobBytes"),
        schemaVersion,
        if (schemaVersion >= 3) root.optionalString("provisionalHeadId") else null,
        if (schemaVersion >= 3) root.optionalString("fullyAcceptedHeadId") else null,
        if (schemaVersion >= 3) root["acceptedProof"]?.takeUnless { it is JsonNull }?.jsonObject?.let(::parseRepairValidationProof) else null,
        if (schemaVersion >= 3) root.getValue("runs").jsonArray.map { parseRepairRunState(it.toString()) } else emptyList(),
    )
}

private fun parseNode(element: JsonElement, schemaVersion: Int): ModuleRevisionNode {
    val value = element.jsonObject
    return ModuleRevisionNode(
        value.requiredString("id"),
        value.optionalString("parentId"),
        value.requiredInt("ordinal"),
        ModuleRevisionStatus.valueOf(value.requiredString("status").uppercase()),
        value.requiredString("sourceRevisionSha256"),
        value.getValue("changes").jsonArray.map(::parseDelta),
        value.stringList("changedModules"),
        value.stringList("invalidatedModules"),
        value.optionalString("evidenceKind"),
        value.optionalString("evidenceArtifact"),
        value.getValue("recoveredAfterCrash").jsonPrimitive.content.toBooleanStrict(),
        value.optionalString("evidenceSummary"),
        value["repairMetadata"]?.takeUnless { it is JsonNull }?.let { parseRepairMetadata(it, schemaVersion) },
        if (schemaVersion >= 3) value["validationProof"]?.takeUnless { it is JsonNull }?.jsonObject?.let(::parseRepairValidationProof) else null,
        if (schemaVersion >= 4) value["rollbackRecord"]?.takeUnless { it is JsonNull }?.let(::parseRepairRollbackRecord) else null,
        if (schemaVersion >= 5) value.getValue("publicationChanges").jsonArray.map(::parseDelta) else emptyList(),
        if (schemaVersion >= 5) parsePreimageMetadataMap(value.getValue("publicationPreimageMetadata")).orEmpty()
        else emptyMap(),
    )
}

private fun parsePending(element: JsonElement, schemaVersion: Int): PendingAttempt {
    val value = element.jsonObject
    return PendingAttempt(
        value.requiredString("id"),
        value.requiredString("parentId"),
        value.requiredInt("ordinal"),
        value.stringList("allowedPaths"),
        value.requiredString("parentSourceRevisionSha256"),
        value.getValue("preimages").jsonArray.map(::parseDelta),
        value.optionalString("candidateSourceRevisionSha256"),
        value.getValue("candidateChanges").jsonArray.map(::parseDelta),
        value["repairMetadata"]?.takeUnless { it is JsonNull }?.let { parseRepairMetadata(it, schemaVersion) },
        if (schemaVersion >= 3) value.getValue("detached").jsonPrimitive.content.toBooleanStrict() else false,
        if (schemaVersion >= 3) value.getValue("promotionChanges").jsonArray.map(::parseDelta) else emptyList(),
        if (schemaVersion >= 4) value["rollbackRecord"]?.takeUnless { it is JsonNull }?.let(::parseRepairRollbackRecord) else null,
        if (schemaVersion >= 4) value["legacyRecoveryRequired"]?.jsonPrimitive?.content?.toBooleanStrict() ?: false else false,
        if (schemaVersion >= 5) value["preimageMetadata"]?.let(::parsePreimageMetadataMap) else null,
        if (schemaVersion >= 5) value["promotionPreimageMetadata"]?.let(::parsePreimageMetadataMap) else null,
        if (schemaVersion >= 6) value["acceptanceDecision"]?.takeUnless { it is JsonNull }
            ?.let { parseAcceptanceDecision(it, schemaVersion) } else null,
        if (schemaVersion >= 6) value.optionalString("sourceWitnessSha256") else null,
        if (schemaVersion >= 6) value.getValue("predecisionStageFiles").jsonArray.map(::parseRepairPredecisionStage)
        else emptyList(),
    )
}

private fun parseRepairPredecisionStage(element: JsonElement): RepairPredecisionStage {
    val value = element.jsonObject
    require(value.keys == setOf("path", "stagingName", "device", "inode", "mountId", "mode", "uid", "gid", "sha256", "size")) {
        "schema-6 predecision stage has an unknown or missing field"
    }
    return RepairPredecisionStage(
        path = value.strictString("path"), stagingName = value.strictString("stagingName"),
        device = value.requiredLong("device"), inode = value.requiredLong("inode"),
        mountId = value.requiredLong("mountId"), mode = value.requiredInt("mode"),
        uid = value.requiredInt("uid"), gid = value.requiredInt("gid"),
        sha256 = value.strictString("sha256"), size = value.requiredLong("size"),
    )
}

private fun parseAcceptanceDecision(element: JsonElement, schemaVersion: Int): RepairAcceptanceDecision {
    val value = element.jsonObject
    require(value.keys == setOf("proof", "evidenceKind", "evidenceSummary", "evidenceArtifact", "promotionChanges",
        "intendedHeadId", "intendedRunId", "intendedRunStatus", "stagedFiles", "committedNode", "committedRun")) {
        "schema-6 acceptance decision has an unknown or missing field"
    }
    return RepairAcceptanceDecision(
        proof = parseRepairValidationProof(value.getValue("proof").jsonObject),
        evidenceKind = value.requiredString("evidenceKind"),
        evidenceSummary = value.requiredString("evidenceSummary"),
        evidenceArtifact = value.optionalString("evidenceArtifact"),
        promotionChanges = value.getValue("promotionChanges").jsonArray.map(::parseDelta),
        intendedHeadId = value.requiredString("intendedHeadId"),
        intendedRunId = value.optionalString("intendedRunId"),
        intendedRunStatus = value.optionalString("intendedRunStatus")?.let { RepairRunStatus.valueOf(it) },
        stagedFiles = value.getValue("stagedFiles").jsonArray.map(::parseRepairStagedFile),
        committedNode = parseNode(value.getValue("committedNode"), schemaVersion),
        committedRun = value["committedRun"]?.takeUnless { it is JsonNull }?.let { parseRepairRunState(it.toString()) },
    )
}

private fun parseRepairStagedFile(element: JsonElement): RepairStagedFile {
    val value = element.jsonObject
    require(value.keys == setOf("path", "stagingName", "device", "inode", "mountId", "mode", "uid", "gid",
        "linkCount", "sha256", "size", "atimeSeconds", "atimeNanoseconds", "mtimeSeconds", "mtimeNanoseconds",
        "parentDevice", "parentInode", "parentMountId"))
    return RepairStagedFile(
        path = value.strictString("path"), stagingName = value.strictString("stagingName"),
        device = value.strictLong("device"), inode = value.strictLong("inode"), mountId = value.strictLong("mountId"),
        mode = value.strictInt("mode"), uid = value.strictInt("uid"), gid = value.strictInt("gid"),
        linkCount = value.strictInt("linkCount"), sha256 = value.strictString("sha256"), size = value.strictLong("size"),
        atimeSeconds = value.strictLong("atimeSeconds"), atimeNanoseconds = value.strictInt("atimeNanoseconds"),
        mtimeSeconds = value.strictLong("mtimeSeconds"), mtimeNanoseconds = value.strictInt("mtimeNanoseconds"),
        parentDevice = value.strictLong("parentDevice"), parentInode = value.strictLong("parentInode"),
        parentMountId = value.strictLong("parentMountId"),
    )
}

private fun parsePreimageMetadataMap(element: JsonElement): Map<String, RepairPreimageMetadata>? {
    if (element is JsonNull) return null
    return element.jsonObject.mapValues { (_, raw) ->
        val value = raw.jsonObject
        val metadataVersion = value.strictInt("metadataVersion")
        val expectedKeys = setOf(
            "metadataVersion", "device", "inode", "mode", "uid", "gid", "size",
            "mtimeSeconds", "mtimeNanoseconds", "ctimeSeconds", "ctimeNanoseconds", "retainedName", "xattrPolicy",
        ) + if (metadataVersion >= 2) setOf("atimeSeconds", "atimeNanoseconds") else emptySet()
        require(metadataVersion in 1..2 &&
            (value.keys == expectedKeys || value.keys == expectedKeys + "ancestorMetadata")) {
            "repair preimage metadata contains unknown or missing fields"
        }
        RepairPreimageMetadata(
            metadataVersion = metadataVersion,
            device = value.strictLong("device"),
            inode = value.strictLong("inode"),
            mode = value.strictInt("mode"),
            uid = value.strictInt("uid"),
            gid = value.strictInt("gid"),
            size = value.strictLong("size"),
            atimeSeconds = if (metadataVersion >= 2) value.strictLong("atimeSeconds") else null,
            atimeNanoseconds = if (metadataVersion >= 2) value.strictInt("atimeNanoseconds") else null,
            mtimeSeconds = value.strictLong("mtimeSeconds"),
            mtimeNanoseconds = value.strictInt("mtimeNanoseconds"),
            ctimeSeconds = value.strictLong("ctimeSeconds"),
            ctimeNanoseconds = value.strictInt("ctimeNanoseconds"),
            retainedName = value.strictString("retainedName"),
            xattrPolicy = value.strictString("xattrPolicy"),
            ancestorMetadata = value["ancestorMetadata"]?.jsonArray?.map(::parseRepairAncestorMetadata).orEmpty(),
        )
    }
}

private fun parseRepairAncestorMetadata(element: JsonElement): RepairAncestorMetadata {
    val value = element.jsonObject
    val legacyKeys = setOf("path", "device", "inode", "mode", "uid", "gid", "linkCount", "mountId",
        "size", "mtimeSeconds", "mtimeNanoseconds", "ctimeSeconds", "ctimeNanoseconds")
    val extendedKeys = legacyKeys + setOf("atimeSeconds", "atimeNanoseconds", "entryCount", "entriesSha256")
    require(value.keys == legacyKeys || value.keys == extendedKeys) {
        "repair ancestor metadata contains unknown or missing fields"
    }
    return RepairAncestorMetadata(
        path = value.strictString("path"),
        device = value.strictLong("device"),
        inode = value.strictLong("inode"),
        mode = value.strictInt("mode"),
        uid = value.strictInt("uid"),
        gid = value.strictInt("gid"),
        linkCount = value.strictInt("linkCount"),
        mountId = value.strictLong("mountId"),
        size = value.strictLong("size"),
        mtimeSeconds = value.strictLong("mtimeSeconds"),
        mtimeNanoseconds = value.strictInt("mtimeNanoseconds"),
        ctimeSeconds = value.strictLong("ctimeSeconds"),
        ctimeNanoseconds = value.strictInt("ctimeNanoseconds"),
        atimeSeconds = value["atimeSeconds"]?.let { value.strictLong("atimeSeconds") },
        atimeNanoseconds = value["atimeNanoseconds"]?.let { value.strictInt("atimeNanoseconds") },
        entryCount = value["entryCount"]?.let { value.strictInt("entryCount") },
        entriesSha256 = value["entriesSha256"]?.let { value.strictString("entriesSha256") },
    )
}

private fun JsonObject.strictString(name: String): String {
    val primitive = get(name)?.jsonPrimitive ?: error("repair preimage metadata is missing $name")
    require(primitive.isString) { "repair preimage metadata $name must be a string" }
    return primitive.content
}

private fun JsonObject.strictInt(name: String): Int {
    val primitive = get(name)?.jsonPrimitive ?: error("repair preimage metadata is missing $name")
    require(!primitive.isString) { "repair preimage metadata $name must be an integer" }
    return primitive.intOrNull ?: error("repair preimage metadata $name must be an integer")
}

private fun JsonObject.strictLong(name: String): Long {
    val primitive = get(name)?.jsonPrimitive ?: error("repair preimage metadata is missing $name")
    require(!primitive.isString) { "repair preimage metadata $name must be an integer" }
    return primitive.longOrNull ?: error("repair preimage metadata $name must be an integer")
}

private fun parseRepairRollbackRecord(element: JsonElement): RepairRollbackRecord {
    val value = element.jsonObject
    return RepairRollbackRecord(
        schemaVersion = value.requiredInt("schemaVersion"),
        attemptId = value.requiredString("attemptId"),
        runId = value.optionalString("runId"),
        targetRevisionId = value.requiredString("targetRevisionId"),
        expectedSourceRevisionSha256 = value.requiredString("expectedSourceRevisionSha256"),
        state = RepairRollbackState.valueOf(value.requiredString("state").uppercase()),
        failureStage = value.optionalString("failureStage")?.let { RepairRollbackStage.valueOf(it.uppercase()) },
        failureCode = value.optionalString("failureCode")?.let { RepairRollbackFailureCode.valueOf(it.uppercase()) },
        observedSourceRevisionSha256 = value.optionalString("observedSourceRevisionSha256"),
        legacyPendingStateUnknown = value["legacyPendingStateUnknown"]?.jsonPrimitive?.content?.toBooleanStrict() ?: false,
        candidateSourceInstallStarted = run {
            require("candidateSourceInstallStarted" in value) {
                "rollback record is missing candidateSourceInstallStarted"
            }
            value.getValue("candidateSourceInstallStarted").let {
                if (it is JsonNull) null else it.jsonPrimitive.booleanOrNull
                    ?: error("candidateSourceInstallStarted must be a boolean or null")
            }
        },
    )
}

private fun parseRepairMetadata(element: JsonElement, schemaVersion: Int): RevisionRepairMetadata {
    val value = element.jsonObject
    return RevisionRepairMetadata(
        iterationIndex = value.requiredInt("iterationIndex"),
        failureKind = value.requiredString("failureKind"),
        prompt = value.requiredString("prompt"),
        summary = value.optionalString("summary"),
        retainedRegressionIds = value.stringList("retainedRegressionIds"),
        before = value["before"]?.takeUnless { it is JsonNull }?.let(::parseGraphEvidence),
        regressionCorpusSha256 = value.optionalString("regressionCorpusSha256"),
        agentInvocation = if (schemaVersion >= 2) {
            value["agentInvocation"]?.takeUnless { it is JsonNull }?.let(::parseAgentInvocationBinding)
        } else {
            null
        },
        turnIntent = if (schemaVersion >= 7) {
            value["turnIntent"]?.takeUnless { it is JsonNull }?.let(::parseTurnIntentBinding)
        } else null,
        publicationMode = if (schemaVersion >= 2) {
            RepairPublicationMode.valueOf(value.requiredString("publicationMode").uppercase())
        } else {
            RepairPublicationMode.TEST_ONLY_NON_RELEASE
        },
        runId = if (schemaVersion >= 3) value.optionalString("runId") else null,
    )
}

private fun parseTurnIntentBinding(element: JsonElement): RepairAgentTurnIntentBinding {
    val value = element.jsonObject
    require(value.keys == setOf("intentPath", "intentSha256", "turnId")) {
        "repair ACP turn intent binding has missing or extra fields"
    }
    return RepairAgentTurnIntentBinding(
        intentPath = value.requiredString("intentPath"),
        intentSha256 = value.requiredString("intentSha256"),
        turnId = value.requiredString("turnId"),
    )
}

private fun parseAgentInvocationBinding(element: JsonElement): RepairAgentInvocationBinding {
    val value = element.jsonObject
    return RepairAgentInvocationBinding(
        receiptPath = value.requiredString("receiptPath"),
        receiptSha256 = value.requiredString("receiptSha256"),
        receiptSchemaVersion = value.requiredInt("receiptSchemaVersion"),
        requestSha256 = value.requiredString("requestSha256"),
        resultChangesSha256 = value.requiredString("resultChangesSha256"),
        terminalOutcome = value.requiredString("terminalOutcome"),
        receiptReleaseComplete = value.getValue("receiptReleaseComplete").jsonPrimitive.content.toBooleanStrict(),
        intentPath = value.optionalString("intentPath"),
        intentSha256 = value.optionalString("intentSha256"),
        turnId = value.optionalString("turnId"),
        assessmentPath = value.optionalString("assessmentPath"),
        assessmentSha256 = value.optionalString("assessmentSha256"),
        assessmentStatus = RepairAgentAssessmentStatus.valueOf(
            value.requiredString("assessmentStatus").uppercase(),
        ),
    )
}

private fun parseRegressionInput(element: JsonElement): ProcessInput {
    val value = element.jsonObject
    return ProcessInput(
        id = value.requiredString("id"),
        args = value.stringList("args"),
        stdin = value.requiredString("stdinHex").hexToByteArrayStrict(),
    )
}

private fun parseGraphEvidence(element: JsonElement): RepairEvidence {
    val value = element.jsonObject
    return RepairEvidence(
        kind = value.requiredString("kind"),
        summary = value.requiredString("summary"),
        artifactPath = value.optionalString("artifactPath"),
    )
}

private fun parseDelta(element: JsonElement): RevisionFileDelta {
    val value = element.jsonObject
    return RevisionFileDelta(
        value.requiredString("path"),
        value.optionalString("beforeSha256"),
        value.optionalLong("beforeBytes"),
        value.requiredString("afterSha256"),
        value.optionalString("beforeBlobSha256"),
        value.requiredString("afterBlobSha256"),
        value.requiredLong("afterBytes"),
    )
}

private fun captureSourceSnapshot(
    root: Path,
    paths: Collection<String>,
    budget: RepairResourceBudget,
    profile: RepairIndexProfile,
    sourceView: RepairRecoverySourceView? = null,
): List<IndexedSource> {
    var total = 0L
    val snapshot = paths.distinct().sorted().map { relative ->
        val normalized = normalizedRelative(relative)
        val bytes = sourceView?.readSource(normalized)
            ?: readStableRegularFile(root, normalized, budget.maximumSourceFileBytes).bytes
        require(bytes.size.toLong() <= budget.maximumSourceFileBytes)
        total = Math.addExact(total, bytes.size.toLong())
        if (total > budget.maximumSourceBytes) {
            throw RepairBudgetExceededException("repair source inputs exceed ${budget.maximumSourceBytes} bytes")
        }
        profile.validateSourceContent(normalized, bytes)
        IndexedSource(normalized, bytes.size.toLong(), sha256(bytes))
    }
    if (snapshot.size > budget.maximumSourceFiles) {
        throw RepairBudgetExceededException("repair source inputs exceed ${budget.maximumSourceFiles} files")
    }
    return snapshot
}

private val PROCESS_SELF_FD: Path = Path.of("/proc/self/fd")

internal fun isPinnedRepairRootPath(path: Path): Boolean {
    val normalized = path.toAbsolutePath().normalize()
    return normalized.parent == PROCESS_SELF_FD && normalized.fileName.toString().toIntOrNull()?.let { it >= 0 } == true
}

/** Duplicate a directory handle without resolving a retained `/proc/self/fd/N` anchor lexically. */
internal fun openRepairRootDirectory(path: Path): LinuxDescriptor {
    val normalized = path.toAbsolutePath().normalize()
    val descriptorNumber = if (isPinnedRepairRootPath(normalized)) normalized.fileName.toString().toInt() else null
    return if (descriptorNumber == null) {
        LinuxFilesystemSyscalls.openRoot(normalized)
    } else {
        LinuxFilesystemSyscalls.openDirectoryAt(descriptorNumber, ".")
    }
}

internal data class StableRegularFile(
    val bytes: ByteArray,
    val sha256: String,
    val identity: LinuxFileIdentity,
    val state: decompengine.acp.LinuxFileState = decompengine.acp.LinuxFileState(
        identity, bytes.size.toLong(), 0, 0, 0, 0, 0, 0,
    ),
)

internal data class StableFileDigest(val sha256: String, val size: Long, val identity: LinuxFileIdentity, val validUtf8: Boolean)

/** Stream a pinned regular file, then revalidate its metadata and every directory binding. */
internal fun hashStableRegularFile(
    root: Path,
    relative: String,
    declaredSize: (Long) -> Unit,
    readBytes: (Int, Long) -> Unit,
    cancellationCheck: () -> Unit,
    validateMetadata: (LinuxDescriptor) -> Unit = {},
): StableFileDigest {
    cancellationCheck()
    // Snapshot paths use Linux filename semantics, independently of repair manifest grammar.
    require(relative.isNotEmpty() && !relative.startsWith('/') && '\u0000' !in relative) {
        "stable hash path is not a contained relative path"
    }
    val normalized = relative
    require(normalized.split('/').none { it.isEmpty() || it == "." || it == ".." }) {
        "stable hash path contains an invalid segment"
    }
    val base = root.toAbsolutePath().normalize()
    RepairDescriptorReadSupport.requireSupported(base)
    val parts = normalized.split('/')
    val directories = mutableListOf<decompengine.acp.LinuxDescriptor>()
    var authorized: decompengine.acp.LinuxDescriptor? = null
    var readable: decompengine.acp.LinuxDescriptor? = null
    try {
        var parent = openRepairRootDirectory(base)
        directories += parent
        parts.dropLast(1).forEach { segment ->
            cancellationCheck()
            parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
            directories += parent
        }
        authorized = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, parts.last())
            ?: throw StableFileUnavailableException("stable hash target is unavailable")
        readable = LinuxFilesystemSyscalls.openReadableFrom(authorized)
        requireUnchanged(readable.identity == authorized.identity) { "stable hash descriptor identity changed" }
        validateMetadata(readable)
        val descriptorPath = Path.of("/proc/self/fd/${readable.fd}")
        val before = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
        requireUnchanged(before.isRegularFile) { "stable hash descriptor is not regular" }
        declaredSize(before.size())
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val utf8 = StrictUtf8ByteValidator()
        val buffer = ByteArray(64 * 1024)
        var size = 0L
        // This kernel-owned proc entry references our still-owned descriptor, not the workspace name.
        Files.newInputStream(descriptorPath).use { input ->
            while (true) {
                cancellationCheck()
                val count = input.read(buffer)
                if (count < 0) break
                size = Math.addExact(size, count.toLong())
                readBytes(count, size)
                digest.update(buffer, 0, count)
                utf8.accept(buffer, count)
            }
        }
        cancellationCheck()
        val after = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
        validateMetadata(readable)
        requireUnchanged(after.isRegularFile && before.fileKey() == after.fileKey() &&
            before.size() == after.size() && after.size() == size &&
            before.lastModifiedTime() == after.lastModifiedTime() &&
            LinuxFilesystemSyscalls.identity(readable.fd) == readable.identity) {
            "stable hash file changed during reading"
        }
        revalidateDescriptorPath(base, parts, directories.map { it.identity }, authorized.identity)
        cancellationCheck()
        return StableFileDigest(digest.digest().joinToString("") { "%02x".format(it) }, size, authorized.identity, utf8.finish())
    } finally {
        readable?.close()
        authorized?.close()
        directories.asReversed().forEach { it.close() }
    }
}

/** Incremental UTF-8 validation performed on the exact descriptor-bound bytes being hashed. */
private class StrictUtf8ByteValidator {
    private var remaining = 0
    private var codePoint = 0
    private var minimum = 0
    private var valid = true

    fun accept(bytes: ByteArray, count: Int) {
        if (!valid) return
        for (index in 0 until count) {
            val value = bytes[index].toInt() and 0xff
            if (remaining == 0) {
                when {
                    value <= 0x7f -> Unit
                    value in 0xc2..0xdf -> { remaining = 1; codePoint = value and 0x1f; minimum = 0x80 }
                    value in 0xe0..0xef -> { remaining = 2; codePoint = value and 0x0f; minimum = 0x800 }
                    value in 0xf0..0xf4 -> { remaining = 3; codePoint = value and 0x07; minimum = 0x10000 }
                    else -> valid = false
                }
            } else if (value !in 0x80..0xbf) {
                valid = false
            } else {
                codePoint = (codePoint shl 6) or (value and 0x3f)
                remaining--
                if (remaining == 0 && (codePoint < minimum || codePoint > 0x10ffff || codePoint in 0xd800..0xdfff)) {
                    valid = false
                }
            }
            if (!valid) return
        }
    }

    fun finish(): Boolean = valid && remaining == 0
}

internal fun readStableRegularFile(
    root: Path,
    relative: String,
    maximumBytes: Long,
    afterAuthorization: (() -> Unit)? = null,
    afterRead: (() -> Unit)? = null,
    cancellationCheck: () -> Unit = {},
    requireNoExtendedAttributes: Boolean = false,
): StableRegularFile = readStableRegularFileInternal(
    root, relative, maximumBytes, afterAuthorization, afterRead, cancellationCheck, requireNoExtendedAttributes,
    allowFinalDirectoryLinkCountChange = false,
)

/** Job metadata alone tolerates job-directory link-count changes while every other binding remains pinned. */
internal fun readStableJobMetadataFile(
    root: Path,
    jobId: String,
    maximumBytes: Long,
    afterAuthorization: (() -> Unit)? = null,
): StableRegularFile {
    val relative = "$jobId/job.json"
    val parts = normalizedRelative(relative).split('/')
    require(parts.size == 2 && parts[0] == jobId && parts[1] == "job.json") {
        "stable job-metadata path is invalid"
    }
    return readStableRegularFileInternal(
        root, relative, maximumBytes, afterAuthorization, null, {}, false,
        allowFinalDirectoryLinkCountChange = true,
    )
}

private fun readStableRegularFileInternal(
    root: Path,
    relative: String,
    maximumBytes: Long,
    afterAuthorization: (() -> Unit)?,
    afterRead: (() -> Unit)?,
    cancellationCheck: () -> Unit,
    requireNoExtendedAttributes: Boolean,
    allowFinalDirectoryLinkCountChange: Boolean,
): StableRegularFile {
    cancellationCheck()
    require(maximumBytes in 1 until Int.MAX_VALUE.toLong()) { "stable file-read limit is invalid" }
    val normalized = normalizedRelative(relative)
    val base = root.toAbsolutePath().normalize()
    RepairDescriptorReadSupport.requireSupported(base)
    val parts = normalized.split('/')
    val pinnedDirectories = mutableListOf<decompengine.acp.LinuxDescriptor>()
    var authorized: decompengine.acp.LinuxDescriptor? = null
    var readable: decompengine.acp.LinuxDescriptor? = null
    try {
        var parent = openRepairRootDirectory(base)
        pinnedDirectories += parent
        parts.dropLast(1).forEach { segment ->
            cancellationCheck()
            parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
            pinnedDirectories += parent
            cancellationCheck()
        }
        authorized = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, parts.last())
            ?: throw StableFileUnavailableException("stable file-read target disappeared: $relative")
        if (!authorized.identity.isRegularFile || authorized.identity.isSymbolicLink) {
            throw StableFileUnavailableException("stable file-read target is not a regular non-symbolic-link file: $relative")
        }
        afterAuthorization?.invoke()
        readable = try {
            LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(authorized)
        } catch (failure: decompengine.acp.LinuxSyscallException) {
            // Ordinary evidence reads may run under a mapped UID that does not own the source
            // inode. Preserve the historical readable path there; metadata commitments use
            // requireNoExtendedAttributes and must fail closed instead of changing atime.
            if (requireNoExtendedAttributes || failure.errno != 1) throw failure
            LinuxFilesystemSyscalls.openReadableFrom(authorized)
        }
        requireUnchanged(readable.identity == authorized.identity) {
            "stable file-read descriptor identity differs from its authorized path: $relative"
        }
        val descriptorPath = Path.of("/proc/self/fd/${readable.fd}")
        val before = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
        val stateBefore = LinuxFilesystemSyscalls.fileState(readable)
        val xattrsBefore = if (requireNoExtendedAttributes) {
            LinuxFilesystemSyscalls.extendedAttributeNames(readable, cancellationCheck)
        } else emptyList()
        requireUnchanged(!requireNoExtendedAttributes || xattrsBefore.isEmpty()) {
            "stable file-read target violates the no-extended-attributes policy: $relative"
        }
        requireUnchanged(before.isRegularFile) { "stable file-read descriptor is not regular: $relative" }
        if (before.size() > maximumBytes) {
            throw RepairBudgetExceededException(
                "stable file-read target $relative has ${before.size()} bytes; limit=$maximumBytes",
            )
        }
        val bytes = try {
            LinuxFilesystemSyscalls.read(readable, maximumBytes.toInt(), cancellationCheck)
        } catch (_: LinuxResourceLimitException) {
            throw RepairBudgetExceededException("stable file-read target $relative grew beyond $maximumBytes bytes")
        }
        afterRead?.invoke()
        cancellationCheck()
        val after = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
        requireUnchanged(
            after.isRegularFile && before.fileKey() == after.fileKey() &&
                before.size() == after.size() && after.size() == bytes.size.toLong() &&
                before.lastModifiedTime() == after.lastModifiedTime() &&
            LinuxFilesystemSyscalls.identity(readable.fd) == readable.identity,
        ) { "stable file-read descriptor changed while it was read: $relative" }
        val stateAfter = LinuxFilesystemSyscalls.fileState(readable)
        val xattrsAfter = if (requireNoExtendedAttributes) {
            LinuxFilesystemSyscalls.extendedAttributeNames(readable, cancellationCheck)
        } else emptyList()
        requireUnchanged(xattrsAfter == xattrsBefore &&
            (!requireNoExtendedAttributes || xattrsAfter.isEmpty())) {
            "stable file-read extended attributes changed while it was read: $relative"
        }
        requireUnchanged(
            stateBefore.copy(
                accessTimeSeconds = stateAfter.accessTimeSeconds,
                accessTimeNanoseconds = stateAfter.accessTimeNanoseconds,
                changeTimeSeconds = stateAfter.changeTimeSeconds,
                changeTimeNanoseconds = stateAfter.changeTimeNanoseconds,
            ) == stateAfter,
        ) {
            "stable file-read metadata changed while it was read: $relative"
        }
        revalidateDescriptorPath(
            base, parts, pinnedDirectories.map { it.identity }, authorized.identity,
            allowFinalDirectoryLinkCountChange,
        )
        cancellationCheck()
        return StableRegularFile(bytes, sha256(bytes), authorized.identity, stateAfter)
    } finally {
        readable?.close()
        authorized?.close()
        pinnedDirectories.asReversed().forEach { it.close() }
    }
}

private fun revalidateDescriptorPath(
    base: Path,
    parts: List<String>,
    expectedDirectories: List<LinuxFileIdentity>,
    expectedFile: LinuxFileIdentity,
    allowFinalDirectoryLinkCountChange: Boolean = false,
) {
    val opened = mutableListOf<decompengine.acp.LinuxDescriptor>()
    var target: decompengine.acp.LinuxDescriptor? = null
    try {
        var parent = openRepairRootDirectory(base)
        opened += parent
        requireUnchanged(parent.identity == expectedDirectories.first()) { "stable file-read root binding changed" }
        parts.dropLast(1).forEachIndexed { index, segment ->
            parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
            opened += parent
            val expected = expectedDirectories[index + 1]
            val allowLinkCountChange = allowFinalDirectoryLinkCountChange && index + 1 == expectedDirectories.lastIndex
            val sameBinding = if (allowLinkCountChange) {
                expected.copy(linkCount = parent.identity.linkCount) == parent.identity
            } else expected == parent.identity
            requireUnchanged(sameBinding) { "stable file-read directory binding changed" }
        }
        target = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, parts.last())
            ?: throw StableFileChangedException("stable file-read target disappeared during revalidation")
        requireUnchanged(target.identity == expectedFile) { "stable file-read target binding changed" }
    } catch (failure: java.io.IOException) {
        // The path was admitted at open; failing to reopen it now is a concurrent change, not absence.
        throw StableFileChangedException("stable file-read path binding changed").apply { initCause(failure) }
    } finally {
        target?.close()
        opened.asReversed().forEach { it.close() }
    }
}

private object RepairDescriptorReadSupport {
    @Volatile
    private var initialized = false

    fun requireSupported(path: Path) {
        require(path.fileSystem == FileSystems.getDefault()) {
            "stable repair reads require the default filesystem provider"
        }
        if (initialized) return
        synchronized(this) {
            if (!initialized) {
                LinuxFilesystemSyscalls.requireSupported(path)
                initialized = true
            }
        }
    }
}

internal fun readStableRepairFile(root: Path, relative: String, maximumBytes: Long): ByteArray =
    readStableRegularFile(root, relative, maximumBytes).bytes

private fun revisionSha256(sources: Collection<IndexedSource>): String {
    val canonical = sources.sortedBy { it.path }.joinToString("") { source ->
        "${source.path.length}:${source.path}:${source.bytes}:${source.sha256}\n"
    }
    return sha256(canonical.toByteArray(Charsets.UTF_8))
}

private fun <T> immutableList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))

private fun immutableStringListMap(values: Map<String, List<String>>): Map<String, List<String>> {
    val copied = TreeMap<String, List<String>>()
    values.forEach { (key, entries) -> copied[key] = immutableList(entries) }
    return Collections.unmodifiableMap(copied)
}

private fun ProcessInput.deepCopy(): ProcessInput = ProcessInput(id, immutableList(args), stdin.copyOf())

private fun validateRegressionInput(input: ProcessInput) {
    require(input.id.isNotBlank() && '\u0000' !in input.id) { "regression input ID must be non-blank and contain no NUL" }
    require(input.args.none { '\u0000' in it }) { "regression input arguments must contain no NUL" }
}

private fun validateRegressionCorpus(inputs: List<ProcessInput>, budget: RepairResourceBudget) {
    if (inputs.size > budget.maximumRegressionInputs) {
        throw RepairBudgetExceededException(
            "retained regression corpus contains ${inputs.size} inputs; limit=${budget.maximumRegressionInputs}",
        )
    }
    var previousId: String? = null
    var argumentCount = 0L
    val bytes = inputs.fold(0L) { total, input ->
        validateRegressionInput(input)
        previousId?.let { prior ->
            require(prior < input.id) { "retained regression inputs must have unique sorted IDs" }
        }
        previousId = input.id
        argumentCount = Math.addExact(argumentCount, input.args.size.toLong())
        if (argumentCount > budget.maximumRegressionArguments) {
            throw RepairBudgetExceededException(
                "retained regression corpus contains $argumentCount arguments; " +
                    "limit=${budget.maximumRegressionArguments}",
            )
        }
        val inputBytes = Math.addExact(
            input.id.toByteArray(Charsets.UTF_8).size.toLong(),
            input.stdin.size.toLong(),
        )
        val withArgs = input.args.fold(inputBytes) { subtotal, argument ->
            Math.addExact(subtotal, argument.toByteArray(Charsets.UTF_8).size.toLong())
        }
        Math.addExact(total, withArgs)
    }
    if (bytes > budget.maximumRegressionInputBytes) {
        throw RepairBudgetExceededException(
            "retained regression inputs contain $bytes bytes; limit=${budget.maximumRegressionInputBytes}",
        )
    }
}

private fun regressionCorpusSha256(inputs: List<ProcessInput>): String = sha256(
    buildString {
        inputs.forEach { input ->
            val idBytes = input.id.toByteArray(Charsets.UTF_8)
            append(idBytes.size).append(':').append(input.id).append('|').append(input.args.size).append('|')
            input.args.forEach { argument ->
                append(argument.toByteArray(Charsets.UTF_8).size).append(':').append(argument).append('|')
            }
            append(input.stdin.size).append(':').append(input.stdin.toHexLower()).append('\n')
        }
    }.toByteArray(Charsets.UTF_8),
)

private fun ByteArray.toHexLower(): String = joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

private fun String.hexToByteArrayStrict(): ByteArray {
    require(length % 2 == 0 && all { it in '0'..'9' || it in 'a'..'f' }) {
        "regression input stdin must use lowercase hexadecimal"
    }
    return ByteArray(length / 2) { offset -> substring(offset * 2, offset * 2 + 2).toInt(16).toByte() }
}

private fun decodeUtf8Strict(bytes: ByteArray, path: String): String = try {
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (failure: java.nio.charset.CharacterCodingException) {
    throw IllegalArgumentException("repair history patch is not UTF-8 text: $path", failure)
}

private fun normalizedRelative(value: String): String {
    require(
        value.isNotBlank() && '\\' !in value && !value.startsWith('/') &&
            value.none { it.code < 0x20 || it.code == 0x7f },
    ) { "repair path is not normalized: $value" }
    val parts = value.split('/')
    require(parts.none { it.isEmpty() || it == "." || it == ".." }) { "repair path is not normalized: $value" }
    return value
}

private fun isReservedRepairInternalPath(value: String): Boolean =
    value == "source_tree_manifest.json" ||
        value == "reports/source_revisions.jsonl" ||
        value == "reports/repair_history.json" ||
        value == "reports/repair-revisions" ||
        value.startsWith("reports/repair-revisions/")

private fun sourceTransactionTemporaryName(targetName: String, transactionId: String): String {
    require(transactionId.matches(Regex("revision_[A-Za-z0-9_]+"))) { "invalid repair transaction ID" }
    require(targetName.isNotBlank() && '/' !in targetName && '\u0000' !in targetName)
    return ".$targetName.$transactionId.repair"
}

private fun sourceTransactionPreimageName(relativePath: String, transactionId: String): String {
    require(transactionId.matches(Regex("revision_[A-Za-z0-9_]+"))) { "invalid repair transaction ID" }
    val normalized = normalizedRelative(relativePath)
    return ".$transactionId-${sha256(normalized.toByteArray(Charsets.UTF_8))}.preimage"
}

private fun atomicWrite(path: Path, bytes: ByteArray) {
    path.parent.createDirectories()
    require(!Files.isSymbolicLink(path)) { "atomic repair evidence target must not be a symbolic link: $path" }
    val temporary = atomicRepairTemporary(path)
    if (Files.exists(temporary, LinkOption.NOFOLLOW_LINKS)) {
        require(!Files.isDirectory(temporary, LinkOption.NOFOLLOW_LINKS)) {
            "atomic repair evidence temporary must not be a directory: $temporary"
        }
        Files.delete(temporary)
    }
    Files.createFile(temporary)
    try {
        FileChannel.open(
            temporary,
            StandardOpenOption.WRITE,
            StandardOpenOption.TRUNCATE_EXISTING,
            LinkOption.NOFOLLOW_LINKS,
        ).use { channel ->
            val buffer = java.nio.ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
        moveAtomically(temporary, path)
        forceDirectory(path.parent)
    } finally {
        Files.deleteIfExists(temporary)
    }
}

internal fun writeRepairEvidenceAtomically(path: Path, content: String) =
    atomicWrite(path, content.toByteArray(Charsets.UTF_8))

internal fun cleanupExactRepairEvidenceTemporary(path: Path) {
    val temporary = atomicRepairTemporary(path)
    if (!Files.exists(temporary, LinkOption.NOFOLLOW_LINKS)) return
    require(Files.isRegularFile(temporary, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(temporary)) {
        "repair evidence temporary is not a regular file: $temporary"
    }
    Files.delete(temporary)
    forceDirectory(path.parent)
}

private fun atomicRepairTemporary(path: Path): Path = path.parent.resolve(".${path.fileName}.repair-atomic.tmp")

private fun moveAtomically(source: Path, target: Path) {
    Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
}

private fun forceDirectory(path: Path) {
    FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
}

private fun JsonObject.requiredString(name: String): String =
    get(name)?.jsonPrimitive?.contentOrNull ?: error("repair revision evidence is missing $name")

private fun JsonObject.optionalString(name: String): String? =
    get(name)?.takeUnless { it is JsonNull }?.jsonPrimitive?.contentOrNull

private fun JsonObject.requiredInt(name: String): Int =
    get(name)?.jsonPrimitive?.intOrNull ?: error("repair revision evidence is missing integer $name")

private fun JsonObject.requiredLong(name: String): Long =
    get(name)?.jsonPrimitive?.longOrNull ?: error("repair revision evidence is missing integer $name")

private fun JsonObject.optionalLong(name: String): Long? =
    get(name)?.takeUnless { it is JsonNull }?.jsonPrimitive?.longOrNull

private fun JsonObject.stringList(name: String): List<String> =
    getValue(name).jsonArray.map { it.jsonPrimitive.content }

private fun List<String>.jsonArray(): String = joinToString(prefix = "[", postfix = "]") { "\"${it.jsonEscape()}\"" }

private fun String.jsonEscape(): String = buildString {
    for (character in this@jsonEscape) {
        when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
        }
    }
}
