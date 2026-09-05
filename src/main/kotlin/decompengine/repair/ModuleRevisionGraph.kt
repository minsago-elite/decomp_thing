package decompengine.repair

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxResourceLimitException
import decompengine.acp.permissions
import decompengine.project.AcpExecutionReceiptDocument
import decompengine.project.RepairAgentInvocationDocument
import decompengine.project.verifyRepairAgentInvocationDocument
import decompengine.builtin.BuiltinInvocationArchiveReference
import decompengine.builtin.parseBuiltinInvocationArchiveReference
import decompengine.project.agentFileChangeSetSha256
import decompengine.project.sha256
import decompengine.agent.receiptCommitmentBytes
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkflow
import decompengine.agent.AgentWorkflowIdentity
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
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
private const val MAXIMUM_REPAIR_STATE_NON_RECEIPT_ENTRIES = 16
private val REPAIR_BLOB_DIGEST = Regex("[0-9a-f]{64}")
private val BLOB_ATOMIC_TEMPORARY = Regex("\\.([0-9a-f]{64})\\.repair-atomic\\.tmp")
private val REPAIR_RECEIPT_PATH =
    Regex("reports/repair-revisions/revision_[A-Za-z0-9_]+\\.(?:acp|builtin)-receipt\\.json")
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
        return captureSourceSnapshot(projectRoot, observedPaths, budget)
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
            val layout = profile.resolve(root, budget).deepFrozenCopy()
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
            val snapshot = captureSourceSnapshot(root, sourcePaths, budget)
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
            val verifiedSnapshot = captureSourceSnapshot(root, sourcePaths, budget)
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
)

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

class ModuleRevisionAttempt internal constructor(val id: String)

internal sealed interface ModuleRevisionFaultPoint {
    data class BeforePreimageRead(val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class BeforeDescriptorBoundRead(val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class AfterDescriptorBoundRead(val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class BeforePublicationExchange(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class AfterPublicationExchange(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class AfterPublicationMove(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class BeforeOwnedEntryUnlink(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data class BeforeRollbackExchange(val phase: String, val path: String, val index: Int) : ModuleRevisionFaultPoint
    data object BeforeHeadIndexValidation : ModuleRevisionFaultPoint
    data object AfterHeadIndexValidation : ModuleRevisionFaultPoint
    data object AfterHeadPersist : ModuleRevisionFaultPoint
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

/**
 * Content-addressed link from a repair assessment to its immutable provider invocation.
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
    val builtinArchive: BuiltinInvocationArchiveReference? = null,
) {
    val receiptSuffix: String get() = if (builtinArchive == null) "acp-receipt.json" else "builtin-receipt.json"
    init {
        require(receiptPath.matches(REPAIR_RECEIPT_PATH)) { "repair ACP receipt path is invalid" }
        require(receiptPath.endsWith(".$receiptSuffix")) { "repair receipt format differs from its reference" }
        require(receiptSha256.matches(REPAIR_BLOB_DIGEST)) { "repair ACP receipt digest is invalid" }
        require(receiptSchemaVersion == if (builtinArchive == null) 2 else 1) { "repair receipt schema is unsupported" }
        builtinArchive?.let {
            require(!receiptReleaseComplete) { "built-in invocation does not yet qualify for release acceptance" }
            require(it.identity.binding.requestSha256 == requestSha256) { "built-in request reference differs from graph binding" }
        }
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
)

private fun validatePendingPreimageAggregate(
    allowedPaths: List<String>,
    preimages: List<RevisionFileDelta>,
    budget: RepairResourceBudget,
) {
    require(allowedPaths == allowedPaths.distinct().sorted() && allowedPaths.isNotEmpty())
    require(preimages.map { it.path } == allowedPaths) {
        "pending repair preimages do not exactly cover authorized paths"
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

private fun RevisionRepairMetadata.deepFrozenCopy(): RevisionRepairMetadata = copy(
    retainedRegressionIds = immutableList(retainedRegressionIds),
    before = before?.copy(),
)

private fun ModuleRevisionNode.deepFrozenCopy(): ModuleRevisionNode = copy(
    changes = immutableList(changes.map(RevisionFileDelta::copy)),
    changedModules = immutableList(changedModules),
    invalidatedModules = immutableList(invalidatedModules),
    repairMetadata = repairMetadata?.deepFrozenCopy(),
)

private fun PendingAttempt.deepFrozenCopy(): PendingAttempt = copy(
    allowedPaths = immutableList(allowedPaths),
    preimages = immutableList(preimages.map(RevisionFileDelta::copy)),
    candidateChanges = immutableList(candidateChanges.map(RevisionFileDelta::copy)),
    promotionChanges = immutableList(promotionChanges.map(RevisionFileDelta::copy)),
    repairMetadata = repairMetadata?.deepFrozenCopy(),
)

private fun RevisionGraphState.deepFrozenCopy(): RevisionGraphState = copy(
    editablePaths = immutableList(editablePaths),
    retainedRegressionInputs = immutableList(retainedRegressionInputs.map(ProcessInput::deepCopy)),
    nodes = immutableList(nodes.map(ModuleRevisionNode::deepFrozenCopy)),
    pending = pending?.deepFrozenCopy(),
    runs = immutableList(runs.map { it.copy(lastEvidence = it.lastEvidence?.copy()) }),
)

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
        cleanupSourceTemporaries(state.pending)
        recoverPendingAttempt()
        state.runs.lastOrNull()?.takeUnless { it.terminal }?.let {
            finishRun(RepairRunStatus.INTERRUPTED, RepairEvidence("interrupted", "repair run reopened without a completed terminal publication"))
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

    /** Preserve the original bytes before assigning honest authority to legacy head records. */
    @Synchronized
    fun enableRunContract() = graphOperation {
        if (state.schemaVersion == 3) return@graphOperation
        require(state.pending == null)
        stateStore.preserveLegacyState("graph", stateStore.readGraph(state.budget.maximumGraphBytes), state.budget.maximumGraphBytes)
        val historyPath = projectRoot.resolve("reports/repair_history.json")
        if (Files.exists(historyPath, LinkOption.NOFOLLOW_LINKS)) {
            stateStore.preserveLegacyState("history", readStableRegularFile(projectRoot,
                "reports/repair_history.json", state.budget.maximumProjectionBytes).bytes, state.budget.maximumProjectionBytes)
        }
        persist(state.copy(schemaVersion = 3, nodes = state.nodes.map { node ->
            if (node.status == ModuleRevisionStatus.ACCEPTED) node.copy(status = ModuleRevisionStatus.LEGACY_UNVERIFIED)
            else node
        }))
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
        require(state.pending == null || status == RepairRunStatus.VALIDATION_FAILED)
        val run = requireNotNull(state.runs.lastOrNull())
        if (run.terminal) return@graphOperation run
        val finished = run.copy(status = status, acceptedHeadId = state.fullyAcceptedHeadId,
            provisionalHeadId = state.provisionalHeadId, lastEvidence = portableEvidence(evidence))
        persist(state.copy(runs = state.runs.dropLast(1) + finished))
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

    private fun workingHeadId(): String = state.provisionalHeadId ?: state.headId

    private fun sourcesAt(nodeId: String): Map<String, IndexedSource> = revisionSourcesAt(state.nodes, nodeId)

    @Synchronized
    fun candidateSources(attempt: ModuleRevisionAttempt? = null): Map<String, ByteArray> = graphOperation {
        requireCurrentHead()
        val pending = attempt?.let(::requirePending)
        val sources = sourcesAt(pending?.parentId ?: workingHeadId()).toMutableMap()
        pending?.candidateChanges?.forEach { sources[it.path] = IndexedSource(it.path, it.afterBytes, it.afterSha256) }
        Collections.unmodifiableMap(sources.toSortedMap().mapValues { (_, source) -> readBlob(source.sha256) })
    }

    @Synchronized
    fun recordProvisional(attempt: ModuleRevisionAttempt, evidence: RepairEvidence, proof: RepairValidationProof): ModuleRevisionNode = graphOperation {
        val pending = requirePending(attempt)
        require(state.schemaVersion == 3 && pending.detached && pending.promotionChanges.isEmpty())
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
            require(state.schemaVersion >= 2) {
                "legacy repair revision graphs are non-release and cannot begin a new agent repair"
            }
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
        val currentHeadSnapshot = sourcesAt(workingHeadId()).values.toList()
        val parent = state.nodes.single { it.id == workingHeadId() }
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
        val capturedPreimages = if (state.schemaVersion >= 3) emptyList() else allowed.mapIndexed { preimageIndex, path ->
            faultInjector?.hit(ModuleRevisionFaultPoint.BeforePreimageRead(path, preimageIndex))
            val source = readStableRegularFile(
                projectRoot,
                path,
                state.budget.maximumSourceFileBytes,
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
        val ordinal = state.nextOrdinal
        val idMaterial = parent.id + "\n" + ordinal + "\n" + allowed.joinToString("\n")
        val attemptId = "revision_${ordinal.toString().padStart(8, '0')}_${sha256(idMaterial.toByteArray()).take(16)}"
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
            detached = state.schemaVersion >= 3,
        )
        val run = state.runs.lastOrNull()?.takeUnless { it.terminal }
        run?.let {
            if (it.remainingAttempts <= 0) throw RepairBudgetExceededException("repair run attempt budget exhausted")
            if (System.currentTimeMillis() >= it.deadlineEpochMillis) throw RepairBudgetExceededException("repair run wall budget exhausted")
        }
        val pendingState = state.copy(nextOrdinal = ordinal + 1, pending = pending,
            runs = if (run == null) state.runs else state.runs.dropLast(1) + run.copy(attemptedCount = run.attemptedCount + 1))
        requireRecoverablePendingState(pendingState)
        persist(pendingState)
        return ModuleRevisionAttempt(attemptId)
    }

    /** Read lineage from the durable pending attempt, never from provider context or a staged subset. */
    @Synchronized
    internal fun invocationIdentity(attempt: ModuleRevisionAttempt): AgentWorkflowIdentity = graphOperation {
        val pending = requirePending(attempt)
        val metadata = requireNotNull(pending.repairMetadata) { "repair attempt has no iteration metadata" }
        require(metadata.agentInvocation == null) { "repair attempt already has invocation evidence" }
        requireCurrentHead()
        require(revisionSha256(sourcesAt(pending.parentId).values) == pending.parentSourceRevisionSha256) {
            "input sources changed before repair invocation"
        }
        invocationWorkflowIdentity(pending.id, pending.parentId, metadata.prompt, state.schemaVersion >= 3)
    }

    private fun invocationWorkflowIdentity(attemptId: String, parentId: String, prompt: String,
        bindInput: Boolean): AgentWorkflowIdentity {
        val parent = state.nodes.single { it.id == parentId }
        var baseline = parent
        if (bindInput) {
            while (baseline.status == ModuleRevisionStatus.PROVISIONAL) {
                baseline = state.nodes.single { it.id == baseline.parentId }
            }
            require(baseline.status in setOf(ModuleRevisionStatus.ROOT, ModuleRevisionStatus.ACCEPTED))
        }
        return AgentWorkflowIdentity(AgentWorkflow.REPAIR, attemptId, baseline.sourceRevisionSha256, prompt,
            if (bindInput) parent.sourceRevisionSha256 else null)
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
     * Durably publishes the immutable invocation before the graph assessment refers to it. If the
     * second (graph) publication fails, the raw receipt intentionally remains available for audit;
     * callers must propagate [RepairAgentEvidencePersistenceException] without fallback/retry.
     */
    @Synchronized
    internal fun persistAndBindAgentInvocation(
        attempt: ModuleRevisionAttempt,
        document: AcpExecutionReceiptDocument,
    ): RepairAgentInvocationBinding = persistAndBindAgentInvocation(attempt, RepairAgentInvocationDocument.fromAcp(document))

    @Synchronized
    internal fun persistAndBindAgentInvocation(
        attempt: ModuleRevisionAttempt,
        document: RepairAgentInvocationDocument,
    ): RepairAgentInvocationBinding = graphOperation {
        require(state.schemaVersion >= 2) {
            "legacy repair revision graphs are read-only and cannot record ACP invocations"
        }
        val pending = requirePending(attempt)
        val metadata = requireNotNull(pending.repairMetadata) { "repair attempt has no iteration metadata" }
        require(metadata.agentInvocation == null) { "repair attempt already has invocation evidence" }
        val fileName = "${pending.id}.${document.suffix}"
        val receiptPath = "reports/repair-revisions/$fileName"
        val bytes = document.bytes
        require(bytes.size.toLong() <= MAXIMUM_REPAIR_ACP_RECEIPT_BYTES) {
            "repair ACP receipt exceeds its $MAXIMUM_REPAIR_ACP_RECEIPT_BYTES-byte limit"
        }
        require(sha256(bytes) == document.sha256) { "repair ACP receipt changed after rendering" }
        val verifiedDocument = verifyRepairAgentInvocationDocument(
            bytes,
            invocationWorkflowIdentity(pending.id, pending.parentId, metadata.prompt, state.schemaVersion >= 3),
            document.builtinArchive,
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
            builtinArchive = document.builtinArchive,
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
        val candidateState = state.copy(pending = candidatePending)
        try {
            requireRecoverablePendingState(candidateState)
        } catch (failure: Exception) {
            deleteUnreferencedCandidateBlobs(changes)
            throw failure
        }
        persist(candidateState)
        if (pending.detached) return@graphOperation immutableList(changes.map(RevisionFileDelta::copy))
        try {
            installFiles(
                changes.associate { it.path to readBlob(it.afterBlobSha256) },
                changes.associate { it.path to requireNotNull(it.beforeSha256) },
                transactionId = pending.id,
                phase = "candidate",
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
            runCatching { restorePreimages(candidatePending) }.onFailure(failure::addSuppressed)
            throw failure
        }
        immutableList(changes.map(RevisionFileDelta::copy))
    }

    @Synchronized
    fun accept(attempt: ModuleRevisionAttempt, evidence: RepairEvidence?, proof: RepairValidationProof? = null,
        cancellationCheck: () -> Unit = {}): ModuleRevisionNode = graphOperation {
        cancellationCheck()
        var pending = requirePending(attempt)
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
                metadata.prompt,
                pending.parentId,
                RepairAgentAssessmentStatus.PENDING,
                verifyReceiptContents = true,
            )
        }
        val candidate = requireNotNull(pending.candidateSourceRevisionSha256) { "repair candidate has not been installed" }
        if (pending.detached) {
            require(evidence?.kind == "valid") { "only full retained behavior validation may promote source" }
            requireValidationProof(candidate, requireNotNull(proof), full = true)
            if (pending.repairMetadata?.publicationMode == RepairPublicationMode.ACP_RELEASE) {
                require(proof.assurance == RepairValidationAssurance.STRICT_CONTAINED)
            }
            val baseSources = requireCurrentHead().associateBy { it.path }
            val finalSources = sourcesAt(pending.parentId).toMutableMap()
            pending.candidateChanges.forEach { finalSources[it.path] = IndexedSource(it.path, it.afterBytes, it.afterSha256) }
            val promotion = finalSources.toSortedMap().mapNotNull { (path, after) ->
                val before = baseSources.getValue(path)
                if (before == after) null else RevisionFileDelta(path, before.sha256, before.bytes,
                    after.sha256, before.sha256, after.sha256, after.bytes)
            }
            require(promotion.isNotEmpty())
            pending = pending.copy(promotionChanges = promotion)
            cancellationCheck()
            persist(state.copy(pending = pending))
            installFiles(promotion.associate { it.path to readBlob(it.afterBlobSha256) },
                promotion.associate { it.path to requireNotNull(it.beforeSha256) }, pending.id, "promotion")
        }
        fun requireAcceptingIndex() {
            val acceptingIndex = SecureRepairRuntime.loadIndex(graphAuthority, projectRoot, index.profile, state.budget)
            require(acceptingIndex.sourceRevisionSha256 == candidate) {
                "accepted source tree changed after candidate installation"
            }
            require(
                acceptingIndex.profileId == state.profileId &&
                    acceptingIndex.profileSha256 == state.profileSha256 &&
                    acceptingIndex.sourcePaths == index.sourcePaths &&
                    acceptingIndex.editablePaths.sorted() == state.editablePaths &&
                    acceptingIndex.indexSha256 == state.indexSha256,
            ) { "repair dependency/profile evidence changed after candidate installation" }
        }
        faultInjector?.hit(ModuleRevisionFaultPoint.BeforeHeadIndexValidation)
        requireAcceptingIndex()
        faultInjector?.hit(ModuleRevisionFaultPoint.AfterHeadIndexValidation)
        // Repeat the complete source/evidence rebuild after the deterministic commit-gap hook. This
        // is the final fallible check before the canonical head write; cooperating writers are
        // excluded by the graph lock and non-cooperating changes observed here fail closed.
        requireAcceptingIndex()
        cancellationCheck()
        val node = finalizeNode(pending, ModuleRevisionStatus.ACCEPTED, evidence, recovered = false).copy(validationProof = proof)
        val run = state.runs.lastOrNull()?.takeUnless { it.terminal }
        val acceptedState = state.copy(headId = node.id, nodes = state.nodes + node, pending = null,
            provisionalHeadId = null, fullyAcceptedHeadId = if (pending.detached) node.id else state.fullyAcceptedHeadId,
            acceptedProof = proof ?: state.acceptedProof,
            runs = if (run == null) state.runs else state.runs.dropLast(1) + run.copy(status = RepairRunStatus.FULLY_ACCEPTED,
                acceptedHeadId = node.id, provisionalHeadId = state.provisionalHeadId, lastEvidence = portableEvidence(evidence)))
        val preparedAcceptance = requireCommitReadyState(acceptedState)
        cancellationCheck()
        persist(preparedAcceptance)
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
        require(state.schemaVersion == 3 && state.pending == null && state.provisionalHeadId == null)
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
        val node = finalizeNode(pending, ModuleRevisionStatus.REJECTED, evidence, recovered = false)
        val rejectedState = state.copy(nodes = state.nodes + node, pending = null)
        val preparedRejection = requireCommitReadyState(rejectedState)
        if (pending.detached) {
            restoreDetachedPromotion(pending)
        } else if (pending.candidateSourceRevisionSha256 == null) {
            require(revisionSha256(index.sourceSnapshot()) == pending.parentSourceRevisionSha256) {
                "source tree changed while a pre-candidate repair attempt was pending"
            }
        } else {
            restorePreimages(pending)
        }
        persist(preparedRejection)
        try {
            synchronizeCompatibilityLog()
        } catch (_: Exception) {
            // Derived projection; retried on a later open.
        }
        node.deepFrozenCopy()
    }

    @Synchronized
    fun derivedRepairIterations(): List<RepairIteration> = graphOperation {
        derivedRepairIterations(state.nodes, state.budget)
    }

    private fun derivedRepairIterations(
        nodes: List<ModuleRevisionNode>,
        budget: RepairResourceBudget,
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
                    ModuleRevisionStatus.ACCEPTED -> if (state.schemaVersion >= 3) RepairAttemptDisposition.FULLY_ACCEPTED else RepairAttemptDisposition.LEGACY_UNVERIFIED
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

    @Synchronized
    fun synchronizeCompatibilityLog() = graphOperation {
        stateStore.writeReport(
            "source_revisions.jsonl",
            renderCompatibilityProjection(state.nodes, state.budget.maximumProjectionBytes),
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

    @Synchronized
    internal fun synchronizeRepairHistory() = graphOperation {
        stateStore.writeReport(
            "repair_history.json",
            renderRepairHistoryProjection(
                derivedRepairIterations(),
                retainedRegressionCorpus().inputs,
                state.budget.maximumProjectionBytes,
                state.schemaVersion,
                state.runs,
            ).toByteArray(Charsets.UTF_8),
        )
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

    private fun requireProjectableState(candidate: RevisionGraphState) {
        renderRepairHistoryProjection(
            derivedRepairIterations(candidate.nodes, candidate.budget),
            candidate.retainedRegressionInputs,
            candidate.budget.maximumProjectionBytes,
            candidate.schemaVersion,
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
            val payload = stateStore.readGraph(index.budget.maximumGraphBytes)
            return parseCanonicalGraph(payload, "reports/repair-revisions/graph.json")
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
        require(state.schemaVersion in 1..3) { "unsupported repair revision graph schema" }
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
                    if (node.status == ModuleRevisionStatus.ACCEPTED &&
                        metadata.publicationMode == RepairPublicationMode.ACP_RELEASE
                    ) {
                        requireNotNull(metadata.agentInvocation) {
                            "accepted agent-driven repair lacks invocation-bound ACP evidence: ${node.id}"
                        }
                    }
                    metadata.agentInvocation?.let { invocation ->
                        validateAgentInvocationBinding(
                            invocation,
                            node.id,
                            metadata.prompt,
                            requireNotNull(node.parentId),
                            expectedAssessment,
                            verifyBlobContents,
                        )
                        if (node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.PROVISIONAL)) {
                            require(invocation.resultChangesSha256 == agentChangeSetSha256(node.changes)) {
                                "accepted repair changes differ from the bound ACP result: ${node.id}"
                            }
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
            ids += node.id
        }
        require(state.headId in ids) { "revision graph head does not exist" }
        require(state.headId == derivedHeadId) { "revision graph head is not derived from its ordered nodes" }
        require(state.nodes.single { it.id == state.headId }.status != ModuleRevisionStatus.REJECTED) {
            "revision graph head cannot be rejected"
        }
        require(state.nextOrdinal > previousOrdinal) { "revision graph next ordinal is not ahead of completed nodes" }
        state.pending?.let { pending ->
            require(pending.id.matches(Regex("revision_[A-Za-z0-9_]+"))) { "pending repair attempt ID is invalid" }
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
            validatePendingPreimageAggregate(pending.allowedPaths, pending.preimages, state.budget)
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
                    metadata.agentInvocation?.let { invocation ->
                        validateAgentInvocationBinding(
                            invocation,
                            pending.id,
                            metadata.prompt,
                            pending.parentId,
                            RepairAgentAssessmentStatus.PENDING,
                            verifyBlobContents,
                        )
                        if (pending.candidateSourceRevisionSha256 != null) {
                            require(invocation.resultChangesSha256 == agentChangeSetSha256(pending.candidateChanges)) {
                                "pending repair changes differ from the bound ACP result: ${pending.id}"
                            }
                        }
                    }
                }
            }
            pending.repairMetadata?.let { metadata ->
                require(metadata.iterationIndex == previousRepairIteration + 1) {
                    "pending repair iteration index is not contiguous"
                }
            }
        }
        if (state.pending == null) {
            require(state.nextOrdinal == previousOrdinal + 1) { "revision graph next ordinal is not contiguous" }
        }
        validateRepairRunContract(state)
        val expectedReceipts = buildSet {
            state.nodes.mapNotNull { it.repairMetadata?.agentInvocation }.forEach { binding ->
                add(binding.receiptPath.substringAfterLast('/'))
            }
            state.pending?.let { pending ->
                pending.repairMetadata?.agentInvocation?.let { binding ->
                    add(binding.receiptPath.substringAfterLast('/'))
                } ?: run {
                    val recoveryNames = listOf("acp", "builtin").map { "${pending.id}.$it-receipt.json" }
                        .filter(stateStore::revisionFileExists)
                    require(recoveryNames.size <= 1) { "pending repair has ambiguous invocation receipts" }
                    addAll(recoveryNames)
                }
            }
        }.sorted()
        // Invocation artifacts live beside the graph rather than in the content-blob directory.
        // Bound that traversal by the maximum number of attempts plus the small fixed set of
        // graph/binding/temporary entries; a deliberately tiny blob-entry budget must not make a
        // valid graph impossible to reopen.
        val receiptDirectoryLimit = Math.addExact(
            state.budget.maximumRevisionNodes,
            MAXIMUM_REPAIR_STATE_NON_RECEIPT_ENTRIES,
        )
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
        expectedPromptSha256: String,
        expectedParentId: String,
        expectedAssessment: RepairAgentAssessmentStatus,
        verifyReceiptContents: Boolean,
    ) {
        require(state.schemaVersion >= 2) { "legacy repair graphs cannot contain ACP receipt bindings" }
        val expectedName = "$attemptId.${binding.receiptSuffix}"
        val expected = invocationWorkflowIdentity(attemptId, expectedParentId, expectedPromptSha256,
            binding.builtinArchive?.identity?.journal?.inputRevisionSha256 != null)
        binding.builtinArchive?.requireWorkflow(expected)
        require(binding.receiptPath == "reports/repair-revisions/$expectedName") {
            "repair ACP receipt path is cross-paired with a different attempt: $attemptId"
        }
        require(binding.assessmentStatus == expectedAssessment) {
            "repair ACP assessment status disagrees with graph state: $attemptId"
        }
        if (expectedAssessment == RepairAgentAssessmentStatus.ACCEPTED) {
            require(binding.receiptReleaseComplete && binding.terminalOutcome == "returned-completed") {
                "accepted repair lacks release-complete ACP evidence: $attemptId"
            }
        }
        if (verifyReceiptContents) {
            val receipt = stateStore.readRevisionFile(expectedName, MAXIMUM_REPAIR_ACP_RECEIPT_BYTES)
            require(receipt.sha256 == binding.receiptSha256) {
                "repair ACP receipt digest differs from graph binding: $attemptId"
            }
            val verified = verifyRepairAgentInvocationDocument(receipt.bytes, expected, binding.builtinArchive)
            require(verified.requestSha256 == binding.requestSha256 &&
                verified.promptSha256 == expectedPromptSha256 &&
                verified.resultChangesSha256 == binding.resultChangesSha256 &&
                verified.terminalOutcome == binding.terminalOutcome &&
                verified.releaseComplete == binding.receiptReleaseComplete
            ) { "repair ACP receipt content is cross-paired with its graph binding: $attemptId" }
        }
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
        val recoverablePending = recoverPersistedInvocationBinding(pending)
        val node = finalizeNode(
            recoverablePending,
            ModuleRevisionStatus.REJECTED,
            RepairEvidence("crash-recovery", "restored pending repair preimages after restart"),
            recovered = true,
        )
        val recoveredState = state.copy(nodes = state.nodes + node, pending = null)
        val preparedRecovery = requireCommitReadyState(recoveredState)
        if (recoverablePending.detached) {
            restoreDetachedPromotion(recoverablePending)
        } else if (recoverablePending.candidateSourceRevisionSha256 == null) {
            require(revisionSha256(index.sourceSnapshot()) == recoverablePending.parentSourceRevisionSha256) {
                "source tree changed while a pre-candidate repair attempt was pending"
            }
        } else {
            restorePreimages(recoverablePending)
        }
        persist(preparedRecovery)
    }

    private fun recoverPersistedInvocationBinding(pending: PendingAttempt): PendingAttempt {
        if (state.schemaVersion < 2 || pending.repairMetadata?.agentInvocation != null) return pending
        val metadata = pending.repairMetadata ?: return pending
        val files = listOf("acp", "builtin").map { "${pending.id}.$it-receipt.json" }.filter(stateStore::revisionFileExists)
        require(files.size <= 1) { "pending repair has ambiguous invocation receipts" }
        val fileName = files.singleOrNull() ?: return pending
        val receipt = stateStore.readRevisionFile(fileName, MAXIMUM_REPAIR_ACP_RECEIPT_BYTES)
        val verified = RepairAgentInvocationDocument.recover(receipt.bytes,
            invocationWorkflowIdentity(pending.id, pending.parentId, metadata.prompt, state.schemaVersion >= 3),
            fileName.endsWith(".builtin-receipt.json"))
        val binding = RepairAgentInvocationBinding(
            receiptPath = "reports/repair-revisions/$fileName",
            receiptSha256 = receipt.sha256,
            receiptSchemaVersion = verified.schemaVersion,
            requestSha256 = verified.requestSha256,
            resultChangesSha256 = verified.resultChangesSha256,
            terminalOutcome = verified.terminalOutcome,
            receiptReleaseComplete = verified.releaseComplete,
            assessmentStatus = RepairAgentAssessmentStatus.PENDING,
            builtinArchive = verified.builtinArchive,
        )
        return pending.copy(repairMetadata = metadata.copy(agentInvocation = binding))
    }

    private fun finalizeNode(
        pending: PendingAttempt,
        status: ModuleRevisionStatus,
        evidence: RepairEvidence?,
        recovered: Boolean,
    ): ModuleRevisionNode {
        require(state.nodes.size < state.budget.maximumRevisionNodes) { "revision graph reached its node budget" }
        val paths = pending.candidateChanges.map { it.path }
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
        return ModuleRevisionNode(
            id = pending.id,
            parentId = pending.parentId,
            ordinal = pending.ordinal,
            status = status,
            sourceRevisionSha256 = pending.candidateSourceRevisionSha256 ?: pending.parentSourceRevisionSha256,
            changes = pending.candidateChanges,
            changedModules = index.changedModules(paths),
            invalidatedModules = index.downstreamInvalidations(paths),
            evidenceKind = evidence?.kind?.let(::portableEvidenceText),
            evidenceArtifact = evidence?.artifactPath?.let(::portableEvidencePath),
            recoveredAfterCrash = recovered,
            evidenceSummary = evidence?.summary?.let(::portableEvidenceText),
            repairMetadata = finalizedMetadata,
        )
    }

    private fun requireRecoverablePendingState(candidate: RevisionGraphState) {
        val pending = requireNotNull(candidate.pending) { "recoverability check requires a pending repair" }
        val recoveredNode = finalizeNode(
            pending,
            ModuleRevisionStatus.REJECTED,
            RepairEvidence("crash-recovery", "restored pending repair preimages after restart"),
            recovered = true,
        )
        requireCommitReadyState(candidate.copy(nodes = candidate.nodes + recoveredNode, pending = null))
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
                parent.beforeSha256 -> Unit
                candidate.afterSha256 -> {
                    replacements[candidate.path] = readBlob(requireNotNull(parent.beforeBlobSha256))
                    expectedCurrent[candidate.path] = candidate.afterSha256
                }
                else -> error("refusing to overwrite an unrecognized source replacement during rollback: ${candidate.path}")
            }
        }
        if (replacements.isNotEmpty()) {
        installFiles(
            replacements,
            expectedCurrent,
            transactionId = pending.id,
            phase = "rollback",
        )
        }
        val restored = revisionSha256(index.sourceSnapshot())
        require(restored == pending.parentSourceRevisionSha256) {
            "could not restore the exact parent source revision: expected=${pending.parentSourceRevisionSha256} observed=$restored"
        }
    }

    private fun restoreDetachedPromotion(pending: PendingAttempt) {
        if (pending.promotionChanges.isEmpty()) {
            requireCurrentHead()
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
                else -> error("repair promotion source changed before rollback: ${change.path}")
            }
        }
        if (replacements.isNotEmpty()) installFiles(replacements, expected, pending.id, "promotion-rollback")
        requireCurrentHead()
    }

    private fun installFiles(
        replacements: Map<String, ByteArray>,
        expectedCurrentSha256: Map<String, String>,
        transactionId: String,
        phase: String,
    ) {
        require(replacements.keys.all { it in index.editablePaths })
        publishRepairFiles(
            projectRoot,
            replacements,
            expectedCurrentSha256,
            state.budget.maximumSourceFileBytes,
            transactionId,
            phase,
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
            )
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
        agentFileChangeSetSha256(changes.map { change ->
            AgentFileChange(
                AgentWorkspacePath("project", change.path),
                AgentFileChangeKind.MODIFIED,
                change.beforeSha256,
                change.afterSha256,
                change.afterBytes,
            )
        })

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
        if (payload.size.toLong() > frozenCandidate.budget.maximumGraphBytes) {
            throw RepairBudgetExceededException("repair revision graph exceeds ${frozenCandidate.budget.maximumGraphBytes} bytes")
        }
        return PreparedRevisionGraphState(normalized, payload)
    }

    private fun persist(candidate: RevisionGraphState) = persist(prepareStateForPersistence(candidate))

    private fun persist(prepared: PreparedRevisionGraphState) {
        stateStore.writeGraph(prepared.payload)
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
        val root = Json.parseToJsonElement(decodeUtf8Strict(manifestBytes, "source_tree_manifest.json")).jsonObject
        val files = root["files"]?.jsonArray ?: return
        var changed = false
        val updatedFiles = files.map { element ->
            val item = element.jsonObject
            val relative = item["path"]?.jsonPrimitive?.contentOrNull
            val revision = relative?.let(acceptedChanges::get)
            val source = relative?.let(sourceByPath::get)
            if (revision == null || source == null || item["sha256"]?.jsonPrimitive?.contentOrNull == source.sha256) {
                element
            } else {
                changed = true
                val updated = LinkedHashMap(item)
                updated["sha256"] = JsonPrimitive(source.sha256)
                updated["generator"] = JsonPrimitive("repair-revision")
                updated["promptSha256"] = JsonPrimitive(sha256("revision:${revision.id}".toByteArray(Charsets.UTF_8)))
                if (item["acceptedImplementation"] !is JsonNull) {
                    updated["acceptedImplementation"] = JsonPrimitive(true)
                }
                JsonObject(updated)
            }
        }
        if (changed) {
            val updatedRoot = LinkedHashMap(root)
            updatedRoot["files"] = kotlinx.serialization.json.JsonArray(updatedFiles)
            stateStore.writeRoot(
                "source_tree_manifest.json",
                (JsonObject(updatedRoot).toString() + "\n").toByteArray(Charsets.UTF_8),
            )
        }
    }

    private inline fun <T> graphOperation(action: () -> T): T {
        check(Thread.holdsLock(this)) { "revision graph operation monitor is not held" }
        check(lifecycle == Lifecycle.OPEN) { "revision graph is closed" }
        val current = Thread.currentThread()
        if (operationDepth == 0) {
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
                    restorePendingPreimagesBeforeIndex(projectRoot, stateStore, profile, budget)
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
    state.runs.forEachIndexed { index, run ->
        require(run.id == "run_${(index + 1).toString().padStart(8, '0')}")
        require(run.baselineId in nodes && (run.acceptedHeadId == null || run.acceptedHeadId in nodes))
        require(run.provisionalHeadId == null || nodes[run.provisionalHeadId]?.status == ModuleRevisionStatus.PROVISIONAL)
        require(index == state.runs.lastIndex || run.terminal)
        val attempts = state.nodes.count { it.repairMetadata?.runId == run.id } +
            if (state.pending?.repairMetadata?.runId == run.id) 1 else 0
        require(run.attemptedCount == attempts) { "repair run attempt count differs from its durable attempts" }
        if (run.status == RepairRunStatus.FULLY_ACCEPTED) {
            require(run.originalBinarySha256 != null && run.expectedObservationsSha256 != null)
            val accepted = nodes.getValue(requireNotNull(run.acceptedHeadId))
            require(if (run.acceptedHeadId == run.baselineId) run.attemptedCount == 0 && run.provisionalHeadId == null
                else accepted.status == ModuleRevisionStatus.ACCEPTED && accepted.repairMetadata?.runId == run.id)
        }
    }
    state.pending?.let { pending ->
        require(pending.detached)
        val metadata = requireNotNull(pending.repairMetadata) { "pending repair lacks owning run metadata" }
        val run = requireNotNull(metadata.runId?.let(runs::get)) { "pending repair names no durable run" }
        require(run.id == state.runs.lastOrNull()?.id &&
            run.status in setOf(RepairRunStatus.RUNNING, RepairRunStatus.VALIDATION_FAILED) &&
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
    require(
        binding.profileId == state.profileId &&
            binding.profileSha256 == state.profileSha256 &&
            binding.budgetSha256 == sha256(state.budget.toJson().toByteArray(Charsets.UTF_8)) &&
            binding.editablePaths == state.editablePaths &&
            binding.indexSha256 == state.indexSha256,
    ) { "revision graph differs from its immutable recovery authorization" }
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
    require(rootPaths == binding.sourcePaths) {
        "revision graph root source paths differ from its immutable recovery authorization"
    }
    require(rootPaths.none(::isReservedRepairInternalPath)) {
        "revision graph source paths collide with repair-owned state or projections"
    }
    require(state.editablePaths.all { it in rootPaths }) { "revision graph editable path is absent from its root" }
    if (state.pending?.candidateSourceRevisionSha256 != null) {
        require(profile.authorizesRecoveryLayout(rootPaths, state.editablePaths, state.budget)) {
            "repair profile does not authorize the persisted recovery source paths"
        }
    }

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
        val parentSources = revisionSourcesAt(state.nodes, pending.parentId)
        require(pending.parentSourceRevisionSha256 == revisionSha256(parentSources.values))
        pending.repairMetadata?.let { validatePortableMetadata(it, priorRepairIteration + 1) }
        pending.preimages.forEach { preimage ->
            validateDeltaPortable(preimage)
            val parent = parentSources.getValue(preimage.path)
            require(preimage.beforeSha256 == parent.sha256 && preimage.beforeBytes == parent.bytes)
            require(preimage.afterSha256 == parent.sha256 && preimage.afterBytes == parent.bytes)
        }
        validatePendingPreimageAggregate(pending.allowedPaths, pending.preimages, state.budget)
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
    } ?: require(state.nextOrdinal == priorOrdinal + 1)

    val referencedBytes = referencedSizes.values.fold(0L, Math::addExact)
    require(referencedBytes == state.storedBlobBytes && referencedBytes <= state.budget.maximumStoredBlobBytes)
    referencedSizes.forEach { (digest, expectedBytes) ->
        val blob = readStableRegularFile(blobsDir, digest, state.budget.maximumSourceFileBytes)
        require(blob.sha256 == digest && blob.bytes.size.toLong() == expectedBytes) {
            "revision graph blob is corrupt: $digest"
        }
    }
    return accepted
}

/**
 * Restore a journaled source preimage before constructing any dependency index. This deliberately
 * leaves the pending record in place; the fully validated graph instance records the recovered
 * rejection after the source tree is back at its parent revision.
 */
private fun restorePendingPreimagesBeforeIndex(
    projectRoot: Path,
    store: RepairStateStore,
    profile: RepairIndexProfile,
    requestedBudget: RepairResourceBudget,
) {
    if (!store.graphExists()) return
    val graphBytes = store.readGraph(requestedBudget.maximumGraphBytes)
    val loaded = parseCanonicalGraph(graphBytes, "reports/repair-revisions/graph.json")
    require(store.bindingExists()) {
        "revision graph is missing its immutable recovery authorization"
    }
    val binding = parseCanonicalRecoveryBinding(
        store.readBinding(requestedBudget.maximumGraphBytes),
    )
    val acceptedSources = validateGraphBeforeRecovery(
        loaded,
        profile,
        binding,
        store.blobsPath,
        requestedBudget,
    )
    val pending = loaded.pending ?: return
    val candidateByPath = (if (pending.detached) pending.promotionChanges else pending.candidateChanges).associateBy { it.path }
    val replacements = TreeMap<String, ByteArray>()
    // Preflight the complete accepted source set before the first write. A pending candidate may be
    // partially installed, but an unrecognized out-of-band replacement is never overwritten.
    acceptedSources.forEach { (relative, accepted) ->
        val observed = readStableRegularFile(projectRoot, relative, requestedBudget.maximumSourceFileBytes)
        val candidate = candidateByPath[relative]
        when {
            observed.sha256 == accepted.sha256 && observed.bytes.size.toLong() == accepted.bytes -> Unit
            candidate != null && observed.sha256 == candidate.afterSha256 &&
                observed.bytes.size.toLong() == candidate.afterBytes -> {
                val beforeDigest = requireNotNull(candidate.beforeBlobSha256)
                val preimage = readStableRegularFile(
                    store.blobsPath,
                    beforeDigest,
                    requestedBudget.maximumSourceFileBytes,
                )
                require(preimage.sha256 == beforeDigest) {
                    "pending repair recovery blob changed after graph validation: $beforeDigest"
                }
                replacements[relative] = preimage.bytes
            }
            else -> error("pending repair recovery found an unrecognized source replacement: $relative")
        }
    }
    if (pending.candidateSourceRevisionSha256 == null) {
        require(replacements.isEmpty()) { "pre-candidate recovery unexpectedly requires source writes" }
        return
    }
    require(replacements.keys.all { it in if (pending.detached) loaded.editablePaths else pending.allowedPaths })
    if (replacements.isEmpty()) return
    publishRepairFiles(
        projectRoot,
        replacements,
        replacements.keys.associateWith { candidateByPath.getValue(it).afterSha256 },
        requestedBudget.maximumSourceFileBytes,
        pending.id,
        "startup-rollback",
        null,
    )
    replacements.forEach { (relative, expected) ->
        val observed = readStableRegularFile(projectRoot, relative, requestedBudget.maximumSourceFileBytes)
        require(observed.bytes.contentEquals(expected)) { "pending repair preimage restoration failed: $relative" }
    }
}

private data class RepairStagedReplacement(
    val relative: String,
    val temporaryName: String,
    val parentRelative: String,
    val preparedSha256: String,
    val preparedIdentity: LinuxFileIdentity,
)

private fun publishRepairFiles(
    projectRoot: Path,
    replacements: Map<String, ByteArray>,
    expectedCurrentSha256: Map<String, String>,
    maximumSourceFileBytes: Long,
    transactionId: String,
    phase: String,
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
                normalized,
                bytes,
                expectedCurrentSha256.getValue(relative),
                maximumSourceFileBytes,
                transactionId,
                phase,
                stageIndex,
                faultInjector,
            )
        }
        staged.forEachIndexed { moveIndex, replacement ->
            exchangeRepairFile(
                projectRoot,
                replacement.relative,
                replacement.temporaryName,
                expectedCurrentSha256.getValue(replacement.relative),
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
    relative: String,
    replacement: ByteArray,
    expectedCurrentSha256: String,
    maximumSourceFileBytes: Long,
    transactionId: String,
    phase: String,
    stageIndex: Int,
    faultInjector: ModuleRevisionFaultInjector?,
): RepairStagedReplacement {
    val parts = normalizedRelative(relative).split('/')
    val parentRelative = parts.dropLast(1).joinToString("/")
    val temporaryName = sourceTransactionTemporaryName(parts.last(), transactionId)
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
        target = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, parts.last())) {
            "repair publication target disappeared while staging: $relative"
        }
        require(target.identity.isRegularFile && !target.identity.isSymbolicLink && target.identity.linkCount == 1) {
            "repair publication requires a single-link regular source file: $relative"
        }
        require(LinuxFilesystemSyscalls.extendedAttributeNames(target).isEmpty()) {
            "repair publication refuses to discard extended source metadata: $relative"
        }
        require(sha256(readAuthorizedRepairFile(target, maximumSourceFileBytes)) == expectedCurrentSha256) {
            "source changed while repair replacement was staged: $relative"
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
                parentRelative,
                sha256(replacement),
                identity,
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
    relative: String,
    temporaryName: String,
    expectedCurrentSha256: String,
    replacement: ByteArray,
    preparedIdentity: LinuxFileIdentity,
    maximumSourceFileBytes: Long,
    phase: String,
    moveIndex: Int,
    faultInjector: ModuleRevisionFaultInjector?,
) {
    val parts = normalizedRelative(relative).split('/')
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
                authorizedTarget.identity.linkCount == 1 && authorizedTemporary.identity.linkCount == 1 &&
                authorizedTemporary.identity.mode.permissions == authorizedTarget.identity.mode.permissions &&
                authorizedTemporary.identity.uid == authorizedTarget.identity.uid &&
                authorizedTemporary.identity.gid == authorizedTarget.identity.gid &&
                LinuxFilesystemSyscalls.extendedAttributeNames(authorizedTarget).isEmpty() &&
                LinuxFilesystemSyscalls.extendedAttributeNames(authorizedTemporary).isEmpty(),
        ) { "repair publication cannot preserve source metadata: $relative" }
        val portablePath = relative.replace('\\', '/')
        parent.requireNamedRepairIdentity(parts.last(), authorizedTarget.identity)
        parent.requireNamedRepairIdentity(temporaryName, authorizedTemporary.identity)
        // This hook is intentionally after the last name check and immediately before renameat2;
        // adversarial tests exercise the actual check-to-commit gap.
        faultInjector?.hit(ModuleRevisionFaultPoint.BeforePublicationExchange(phase, portablePath, moveIndex))
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
                            displacedCurrent.linkCount == 1 &&
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
            parent.fd,
            temporaryName,
            setOf(expectedCurrentSha256),
            authorizedTarget.identity.key,
            maximumSourceFileBytes,
            phase,
            portablePath,
            moveIndex,
            faultInjector,
            required = true,
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
    return LinuxFilesystemSyscalls.openReadableFrom(authorized).use { readable ->
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
                require(entry.identity.isRegularFile && !entry.identity.isSymbolicLink && entry.identity.linkCount == 1) {
                    "quarantined repair entry has unsupported identity"
                }
                require(expectedKey == null || entry.identity.key == expectedKey) {
                    "quarantined repair entry changed inode identity"
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

private fun renderGraph(state: RevisionGraphState): String = buildString {
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
    append(state.nodes.joinToString(",") { "\n" + it.toJson(state.schemaVersion).prependIndent("    ") })
    append("\n  ],\n  \"pending\": ")
        .append(state.pending?.toJson(state.schemaVersion) ?: "null").append("\n}\n")
}

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

private fun ModuleRevisionNode.toJson(schemaVersion: Int): String = buildString {
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
    append("\n  \"recoveredAfterCrash\": ").append(recoveredAfterCrash).append(',')
    append("\n  \"changes\": [")
    append(changes.joinToString(",") { "\n" + it.toJson().prependIndent("    ") })
    append("\n  ]\n}")
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
    append("\"repairMetadata\":").append(repairMetadata?.toJson(schemaVersion) ?: "null").append('}')
}

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
        append(",\"agentInvocation\":").append(agentInvocation?.toGraphJson() ?: "null")
        append(",\"publicationMode\":\"").append(publicationMode.name.lowercase()).append('"')
    }
    if (schemaVersion >= 3) append(",\"runId\":").append(runId?.let { "\"$it\"" } ?: "null")
    append('}')
}

private fun RepairAgentInvocationBinding.toGraphJson(): String =
    "{\"receiptPath\":\"${receiptPath.jsonEscape()}\",\"receiptSha256\":\"$receiptSha256\"," +
        "\"receiptSchemaVersion\":$receiptSchemaVersion,\"requestSha256\":\"$requestSha256\"," +
        "\"resultChangesSha256\":\"$resultChangesSha256\"," +
        "\"terminalOutcome\":\"${terminalOutcome.jsonEscape()}\"," +
        "\"receiptReleaseComplete\":$receiptReleaseComplete," +
        "\"assessmentStatus\":\"${assessmentStatus.name.lowercase()}\"" +
        (builtinArchive?.let { ",\"builtinArchive\":${it.json()}" } ?: "") + "}"

private fun List<ProcessInput>.toGraphJson(): String = joinToString(prefix = "[", postfix = "]") { input ->
    "{\"id\":\"${input.id.jsonEscape()}\",\"args\":${input.args.jsonArray()}," +
        "\"stdinHex\":\"${input.stdin.toHexLower()}\"}"
}

private fun RepairEvidence.toGraphJson(): String =
    "{\"kind\":\"${kind.jsonEscape()}\",\"summary\":\"${summary.jsonEscape()}\",\"artifactPath\":" +
        (artifactPath?.let { "\"${it.jsonEscape()}\"" } ?: "null") + "}"

private fun parseCanonicalGraph(payload: ByteArray, label: String): RevisionGraphState {
    val state = parseGraph(decodeUtf8Strict(payload, label))
    require(renderGraph(state).toByteArray(Charsets.UTF_8).contentEquals(payload)) {
        "$label is not the exact canonical graph encoding"
    }
    return state
}

private fun parseGraph(payload: String): RevisionGraphState {
    val root = Json.parseToJsonElement(payload).jsonObject
    val schemaVersion = root["schemaVersion"]?.jsonPrimitive?.intOrNull
        ?: error("repair revision graph is missing schemaVersion")
    require(schemaVersion in 1..3) { "unsupported repair revision graph schema" }
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
        publicationMode = if (schemaVersion >= 2) {
            RepairPublicationMode.valueOf(value.requiredString("publicationMode").uppercase())
        } else {
            RepairPublicationMode.TEST_ONLY_NON_RELEASE
        },
        runId = if (schemaVersion >= 3) value.optionalString("runId") else null,
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
        assessmentStatus = RepairAgentAssessmentStatus.valueOf(
            value.requiredString("assessmentStatus").uppercase(),
        ),
        builtinArchive = value["builtinArchive"]?.let(::parseBuiltinInvocationArchiveReference),
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

private fun captureSourceSnapshot(root: Path, paths: Collection<String>, budget: RepairResourceBudget): List<IndexedSource> {
    var total = 0L
    val snapshot = paths.distinct().sorted().map { relative ->
        val normalized = normalizedRelative(relative)
        val source = readStableRegularFile(root, normalized, budget.maximumSourceFileBytes)
        total = Math.addExact(total, source.bytes.size.toLong())
        if (total > budget.maximumSourceBytes) {
            throw RepairBudgetExceededException("repair source inputs exceed ${budget.maximumSourceBytes} bytes")
        }
        IndexedSource(normalized, source.bytes.size.toLong(), source.sha256)
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
)

internal fun readStableRegularFile(
    root: Path,
    relative: String,
    maximumBytes: Long,
    afterAuthorization: (() -> Unit)? = null,
    afterRead: (() -> Unit)? = null,
    cancellationCheck: () -> Unit = {},
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
        authorized = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, parts.last())) {
            "stable file-read target disappeared: $relative"
        }
        require(authorized.identity.isRegularFile && !authorized.identity.isSymbolicLink) {
            "stable file-read target is not a regular non-symbolic-link file: $relative"
        }
        afterAuthorization?.invoke()
        readable = LinuxFilesystemSyscalls.openReadableFrom(authorized)
        require(readable.identity == authorized.identity) {
            "stable file-read descriptor identity differs from its authorized path: $relative"
        }
        val descriptorPath = Path.of("/proc/self/fd/${readable.fd}")
        val before = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
        require(before.isRegularFile) { "stable file-read descriptor is not regular: $relative" }
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
        require(
            after.isRegularFile && before.fileKey() == after.fileKey() &&
                before.size() == after.size() && after.size() == bytes.size.toLong() &&
                before.lastModifiedTime() == after.lastModifiedTime() &&
                LinuxFilesystemSyscalls.identity(readable.fd) == readable.identity,
        ) { "stable file-read descriptor changed while it was read: $relative" }
        revalidateDescriptorPath(base, parts, pinnedDirectories.map { it.identity }, authorized.identity)
        cancellationCheck()
        return StableRegularFile(bytes, sha256(bytes), authorized.identity)
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
) {
    val opened = mutableListOf<decompengine.acp.LinuxDescriptor>()
    var target: decompengine.acp.LinuxDescriptor? = null
    try {
        var parent = openRepairRootDirectory(base)
        opened += parent
        require(parent.identity == expectedDirectories.first()) { "stable file-read root binding changed" }
        parts.dropLast(1).forEachIndexed { index, segment ->
            parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
            opened += parent
            require(parent.identity == expectedDirectories[index + 1]) {
                "stable file-read directory binding changed"
            }
        }
        target = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, parts.last())) {
            "stable file-read target disappeared during revalidation"
        }
        require(target.identity == expectedFile) { "stable file-read target binding changed" }
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
