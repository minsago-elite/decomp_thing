package decompengine.repair

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxResourceLimitException
import decompengine.acp.permissions
import decompengine.project.sha256
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
import java.nio.channels.FileLock
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
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.math.min

internal const val MAXIMUM_REPAIR_PROJECTION_BYTES: Long = 64L * 1024 * 1024

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
        require(maximumRevisionNodes in 2..1_000_000)
        require(maximumGraphBytes in 1 until Int.MAX_VALUE.toLong())
        require(maximumStoredBlobBytes >= maximumSourceBytes)
    }
}

class RepairBudgetExceededException(message: String) : IllegalArgumentException(message)

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

enum class ModuleRevisionStatus { ROOT, ACCEPTED, REJECTED }

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
) {
    init {
        require(iterationIndex > 0)
        require(failureKind in setOf("compile", "behavior"))
        require(retainedRegressionIds == retainedRegressionIds.distinct())
        require(regressionCorpusSha256 == null || regressionCorpusSha256.matches(Regex("[0-9a-f]{64}")))
    }
}

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
    repairMetadata = repairMetadata?.deepFrozenCopy(),
)

private fun RevisionGraphState.deepFrozenCopy(): RevisionGraphState = copy(
    editablePaths = immutableList(editablePaths),
    retainedRegressionInputs = immutableList(retainedRegressionInputs.map(ProcessInput::deepCopy)),
    nodes = immutableList(nodes.map(ModuleRevisionNode::deepFrozenCopy)),
    pending = pending?.deepFrozenCopy(),
)

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

    fun acquire(rootDescriptor: LinuxDescriptor): RepairRootCoordination {
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
                entry.permit.acquire()
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
    graphPathCandidate: Path?,
    blobsDirCandidate: Path?,
    lockChannelCandidate: FileChannel?,
    lockCandidate: FileLock?,
    rootCoordinationCandidate: RepairRootCoordination?,
    faultInjectorCandidate: ModuleRevisionFaultInjector?,
) : AutoCloseable {
    private enum class Lifecycle { OPEN, CLOSING, CLOSED }

    private var lifecycle: Lifecycle
    private var operationDepth: Int
    private var operationThread: Thread?
    private val graphAuthority: Any
    private val rootDescriptor: LinuxDescriptor
    private val projectRoot: Path
    private val portableProjectRoot: Path
    private val index: ModuleRepairIndex
    private val graphPath: Path
    private val blobsDir: Path
    private val lockChannel: FileChannel
    private val lock: FileLock
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
        graphPath = requireNotNull(graphPathCandidate)
        blobsDir = requireNotNull(blobsDirCandidate)
        lockChannel = requireNotNull(lockChannelCandidate)
        lock = requireNotNull(lockCandidate)
        rootCoordination = requireNotNull(rootCoordinationCandidate)
        faultInjector = faultInjectorCandidate
        state = loadOrInitialize().deepFrozenCopy()
    }

    init {
        validateLoadedState()
        cleanupSourceTemporaries(state.pending)
        recoverPendingAttempt()
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
            )
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
            persist(state.copy(retainedRegressionInputs = canonical, regressionCorpusSha256 = digest))
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
        index.select(failureKind, diagnosticHint).deepFrozenCopy()
    }

    @Synchronized
    internal fun requireContextBinding(context: RepairContextSelection) = graphOperation {
        require(state.pending == null) { "cannot bind repair context while an attempt is pending" }
        require(context.indexSha256 == index.indexSha256) {
            "repair dependency evidence changed after context selection"
        }
        val observedRevision = revisionSha256(requireCurrentHead())
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
            val bytes = readStableRegularFile(
                projectRoot,
                relative,
                state.budget.maximumSourceFileBytes,
            ).bytes
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
        require(revisionSha256(requireCurrentHead()) == context.sourceRevisionSha256) {
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
        require(state.nodes.size < state.budget.maximumRevisionNodes) { "revision graph reached its node budget" }
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
        val currentHeadSnapshot = requireCurrentHead()
        val parent = state.nodes.single { it.id == state.headId }
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
        val capturedPreimages = allowed.mapIndexed { preimageIndex, path ->
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
        val verifiedSnapshot = index.sourceSnapshot().associateBy { it.path }
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
                prompt = portableEvidenceText(metadata.prompt),
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
        )
        persist(state.copy(nextOrdinal = ordinal + 1, pending = pending))
        return ModuleRevisionAttempt(attemptId)
    }

    @Synchronized
    fun annotateAttempt(attempt: ModuleRevisionAttempt, summary: String) = graphOperation {
        val pending = requirePending(attempt)
        val metadata = requireNotNull(pending.repairMetadata) { "repair attempt has no iteration metadata" }
        require(metadata.summary == null) { "repair attempt summary is already recorded" }
        persist(
            state.copy(
                pending = pending.copy(
                    repairMetadata = metadata.copy(summary = portableEvidenceText(summary)),
                ),
            ),
        )
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
        val changes = normalized.entries.sortedBy { it.key }.mapNotNull { (path, replacement) ->
            val before = preimages.getValue(path)
            val afterSha = sha256(replacement)
            if (afterSha == before.beforeSha256 && replacement.contentEquals(readBlob(before.beforeBlobSha256!!))) return@mapNotNull null
            val blob = storeBlob(replacement)
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
        val expectedSources = index.sourceSnapshot().associateBy { it.path }.toMutableMap()
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
        persist(state.copy(pending = candidatePending))
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
    fun accept(attempt: ModuleRevisionAttempt, evidence: RepairEvidence?): ModuleRevisionNode = graphOperation {
        val pending = requirePending(attempt)
        val candidate = requireNotNull(pending.candidateSourceRevisionSha256) { "repair candidate has not been installed" }
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
        val node = finalizeNode(pending, ModuleRevisionStatus.ACCEPTED, evidence, recovered = false)
        persist(state.copy(headId = node.id, nodes = state.nodes + node, pending = null))
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
    fun reject(attempt: ModuleRevisionAttempt, evidence: RepairEvidence? = null): ModuleRevisionNode = graphOperation {
        val pending = requirePending(attempt)
        if (pending.candidateSourceRevisionSha256 == null) {
            require(revisionSha256(index.sourceSnapshot()) == pending.parentSourceRevisionSha256) {
                "source tree changed while a pre-candidate repair attempt was pending"
            }
        } else {
            restorePreimages(pending)
        }
        val node = finalizeNode(pending, ModuleRevisionStatus.REJECTED, evidence, recovered = false)
        persist(state.copy(nodes = state.nodes + node, pending = null))
        try {
            synchronizeCompatibilityLog()
        } catch (_: Exception) {
            // Derived projection; retried on a later open.
        }
        node.deepFrozenCopy()
    }

    @Synchronized
    fun derivedRepairIterations(): List<RepairIteration> = graphOperation {
        requireBoundedIterationProjection()
        immutableList(state.nodes.mapNotNull { node ->
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
            )
        }.also { iterations ->
            require(iterations.map { it.index } == iterations.map { it.index }.distinct().sorted()) {
                "repair graph iteration indexes are not unique and ordered"
            }
        }.map(RepairIteration::deepFrozenCopy))
    }

    @Synchronized
    fun synchronizeCompatibilityLog() = graphOperation {
        val path = projectRoot.resolve("reports/source_revisions.jsonl")
        val nodes = state.nodes.filter { it.status != ModuleRevisionStatus.ROOT && it.changes.isNotEmpty() }
        var projectedBytes = 0L
        nodes.forEach { node ->
            projectedBytes = Math.addExact(
                projectedBytes,
                compatibilityRevisionRecord(node).toByteArray(Charsets.UTF_8).size.toLong(),
            )
            if (projectedBytes > state.budget.maximumProjectionBytes) {
                throw RepairBudgetExceededException(
                    "source revision compatibility projection exceeds ${state.budget.maximumProjectionBytes} bytes",
                )
            }
        }
        val payload = buildString(projectedBytes.toInt()) {
            nodes.forEach { append(compatibilityRevisionRecord(it)) }
        }.toByteArray(Charsets.UTF_8)
        if (payload.size.toLong() > state.budget.maximumProjectionBytes) {
            throw RepairBudgetExceededException(
                "source revision compatibility projection exceeds ${state.budget.maximumProjectionBytes} bytes",
            )
        }
        atomicWrite(path, payload)
    }

    @Synchronized
    internal fun synchronizeRepairHistory() = graphOperation {
        RepairHistory(
            projectRoot.resolve("reports/repair_history.json"),
            state.budget.maximumProjectionBytes,
        ).reconcile(derivedRepairIterations(), retainedRegressionCorpus().inputs)
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

    private fun requireBoundedIterationProjection() {
        var projectedBytes = 128L
        fun addText(value: String?) {
            if (value == null) return
            projectedBytes = Math.addExact(
                projectedBytes,
                Math.multiplyExact(value.toByteArray(Charsets.UTF_8).size.toLong(), 6L),
            )
        }
        state.nodes.forEach { node ->
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
            if (projectedBytes > state.budget.maximumProjectionBytes) {
                throw RepairBudgetExceededException(
                    "repair history projection exceeds ${state.budget.maximumProjectionBytes} bytes",
                )
            }
        }
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
            runCatching { lock.release() }
            lockChannel.close()
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
        if (Files.exists(graphPath, LinkOption.NOFOLLOW_LINKS)) {
            val payload = readStableRegularFile(
                graphPath.parent,
                graphPath.fileName.toString(),
                index.budget.maximumGraphBytes,
            ).bytes
            return parseCanonicalGraph(payload, "reports/repair-revisions/graph.json")
        }
        val snapshot = index.sourceSnapshot()
        val rootChanges = snapshot.map { source ->
            val observed = readStableRegularFile(projectRoot, source.path, index.budget.maximumSourceFileBytes)
            require(observed.sha256 == source.sha256 && observed.bytes.size.toLong() == source.bytes) {
                "repair root source changed while its content blob was captured: ${source.path}"
            }
            val blob = storeBlob(observed.bytes)
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
            "source_tree_manifest.json".takeIf { projectRoot.resolve(it).exists() },
            false,
            "initial accepted source tree",
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
        val payload = renderGraph(initial).toByteArray(Charsets.UTF_8)
        if (payload.size.toLong() > index.budget.maximumGraphBytes) {
            throw RepairBudgetExceededException("initial repair graph exceeds ${index.budget.maximumGraphBytes} bytes")
        }
        atomicWrite(graphPath, payload)
        return initial
    }

    private fun validateLoadedState(verifyBlobContents: Boolean = true) {
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
                require(node.parentId == derivedHeadId && node.status != ModuleRevisionStatus.ROOT) {
                    "revision graph node is not attached to the accepted head: ${node.id}"
                }
                if (node.status == ModuleRevisionStatus.ACCEPTED) derivedHeadId = node.id
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
                require(node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.REJECTED))
                val candidateSources = acceptedSources.toMutableMap()
                node.changes.forEach { change ->
                    val before = acceptedSources.getValue(change.path)
                    require(change.beforeSha256 == before.sha256 && change.beforeBytes == before.bytes) {
                        "revision graph delta is not bound to its accepted parent: ${node.id}:${change.path}"
                    }
                    candidateSources[change.path] = IndexedSource(change.path, change.afterBytes, change.afterSha256)
                }
                require(node.sourceRevisionSha256 == revisionSha256(candidateSources.values)) {
                    "revision graph node source digest does not match its deltas: ${node.id}"
                }
                if (node.status == ModuleRevisionStatus.ACCEPTED) {
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
            require(pending.parentId == state.headId && pending.ordinal == state.nextOrdinal - 1) {
                "pending repair attempt is not attached to the current graph head"
            }
            require(pending.ordinal == previousOrdinal + 1) { "pending repair ordinal is not contiguous" }
            require(pending.parentSourceRevisionSha256.matches(Regex("[0-9a-f]{64}")))
            require(pending.parentSourceRevisionSha256 == revisionSha256(acceptedSources.values)) {
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
                val accepted = acceptedSources.getValue(preimage.path)
                require(preimage.beforeSha256 == accepted.sha256 && preimage.beforeBytes == accepted.bytes) {
                    "pending repair preimage is not bound to the accepted head: ${preimage.path}"
                }
            }
            validatePendingPreimageAggregate(pending.allowedPaths, pending.preimages, state.budget)
            require(pending.candidateChanges.map { it.path } == pending.candidateChanges.map { it.path }.distinct().sorted())
            require(pending.candidateChanges.all { it.path in pending.allowedPaths })
            val pendingCandidateSources = acceptedSources.toMutableMap()
            pending.candidateChanges.forEach { change ->
                validateDelta(change)
                val accepted = acceptedSources.getValue(change.path)
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
                require(metadata.iterationIndex == previousRepairIteration + 1) {
                    "pending repair iteration index is not contiguous"
                }
            }
        }
        if (state.pending == null) {
            require(state.nextOrdinal == previousOrdinal + 1) { "revision graph next ordinal is not contiguous" }
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
        if (pending.candidateSourceRevisionSha256 == null) {
            require(revisionSha256(index.sourceSnapshot()) == pending.parentSourceRevisionSha256) {
                "source tree changed while a pre-candidate repair attempt was pending"
            }
        } else {
            restorePreimages(pending)
        }
        val node = finalizeNode(
            pending,
            ModuleRevisionStatus.REJECTED,
            RepairEvidence("crash-recovery", "restored pending repair preimages after restart"),
            recovered = true,
        )
        persist(state.copy(nodes = state.nodes + node, pending = null))
    }

    private fun finalizeNode(
        pending: PendingAttempt,
        status: ModuleRevisionStatus,
        evidence: RepairEvidence?,
        recovered: Boolean,
    ): ModuleRevisionNode {
        require(state.nodes.size < state.budget.maximumRevisionNodes) { "revision graph reached its node budget" }
        val paths = pending.candidateChanges.map { it.path }
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
            repairMetadata = pending.repairMetadata,
        )
    }

    private fun restorePreimages(pending: PendingAttempt) {
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

    private fun storeBlob(bytes: ByteArray): String {
        // Detach from caller-owned buffers before hashing or writing. A concurrent mutation cannot
        // make the durable filename authenticate bytes other than the bytes referenced by state.
        val frozenBytes = bytes.copyOf()
        val digest = sha256(frozenBytes)
        val target = blobsDir.resolve(digest)
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            require(Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(target)) {
                "repair blob is not a regular file: $digest"
            }
            require(readStableRegularFile(blobsDir, digest, index.budget.maximumSourceFileBytes).bytes.contentEquals(frozenBytes)) {
                "repair blob digest collision or corruption: $digest"
            }
            return digest
        }
        atomicWrite(target, frozenBytes)
        val authenticated = readStableRegularFile(blobsDir, digest, index.budget.maximumSourceFileBytes)
        require(authenticated.sha256 == digest && authenticated.bytes.contentEquals(frozenBytes)) {
            "repair blob write did not persist authenticated content: $digest"
        }
        return digest
    }

    private fun readBlob(digest: String): ByteArray {
        require(digest.matches(Regex("[0-9a-f]{64}"))) { "invalid repair blob digest" }
        val observed = readStableRegularFile(blobsDir, digest, index.budget.maximumSourceFileBytes)
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
        nodes.flatMap { it.changes }.forEach { delta ->
            delta.beforeBlobSha256?.let { before ->
                record(before, delta.beforeBytes ?: error("repair delta is missing before-byte count"))
            }
            record(delta.afterBlobSha256, delta.afterBytes)
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
                val observed = readStableRegularFile(blobsDir, digest, index.budget.maximumSourceFileBytes)
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
                graphPath.parent,
                "blobs",
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
        Files.list(blobsDir).use { entries ->
            entries.toList().sortedBy { it.fileName.toString() }.forEachIndexed { indexInCleanup, path ->
                val name = path.fileName.toString()
                val baseName = name.removeSuffix(".cleanup")
                if (baseName !in referenced) {
                    require(!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                        "repair blob directory contains an unexpected directory: $name"
                    }
                    require(baseName.matches(Regex("[0-9a-f]{64}"))) {
                        "repair blob directory contains an unowned entry: $name"
                    }
                    cleanupRepairOwnedEntry(
                        graphPath.parent,
                        "blobs",
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
        }
        forceDirectory(blobsDir)
    }

    private fun cleanupGraphTemporaries() {
        cleanupAtomicSiblingTemporaries(graphPath)
    }

    private fun cleanupAtomicSiblingTemporaries(target: Path) {
        val temporary = atomicRepairTemporary(target)
        if (Files.exists(temporary, LinkOption.NOFOLLOW_LINKS)) {
            require(!Files.isDirectory(temporary, LinkOption.NOFOLLOW_LINKS)) {
                "repair graph state contains an unexpected journal-owned temporary directory"
            }
            Files.delete(temporary)
        }
        forceDirectory(target.parent)
    }

    private fun cleanupSourceTemporaries(pending: PendingAttempt?) {
        val active = pending ?: return
        val candidateByPath = active.candidateChanges.associateBy { it.path }
        active.preimages.forEachIndexed { index, preimage ->
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
        nodes.flatMap { it.changes }.forEach { delta ->
            delta.beforeBlobSha256?.let(::add)
            add(delta.afterBlobSha256)
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

    private fun persist(candidate: RevisionGraphState) {
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
        atomicWrite(graphPath, payload)
        state = normalized
    }

    private fun synchronizeSourceManifest() {
        val manifestPath = projectRoot.resolve("source_tree_manifest.json")
        cleanupAtomicSiblingTemporaries(manifestPath)
        if (!Files.exists(manifestPath, LinkOption.NOFOLLOW_LINKS)) return
        val manifestBytes = readStableRegularFile(
            projectRoot,
            "source_tree_manifest.json",
            state.budget.maximumIndexEvidenceBytes,
        ).bytes
        val acceptedChanges = linkedMapOf<String, ModuleRevisionNode>()
        val nodesById = state.nodes.associateBy { it.id }
        var cursor: ModuleRevisionNode? = nodesById.getValue(state.headId)
        while (cursor != null) {
            if (cursor.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.ROOT)) {
                val revision = cursor
                revision.changes.forEach { change -> acceptedChanges.putIfAbsent(change.path, revision) }
            }
            cursor = cursor.parentId?.let(nodesById::get)
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
            atomicWrite(manifestPath, (JsonObject(updatedRoot).toString() + "\n").toByteArray(Charsets.UTF_8))
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
            val rootCoordination = try {
                RepairRootCoordinator.acquire(rootDescriptor)
            } catch (failure: Throwable) {
                rootDescriptor.close()
                throw failure
            }
            try {
                requireLexicalRootBinding(portableProjectRoot, rootDescriptor.identity)
                val projectRoot = repairDescriptorPath(rootDescriptor)
                val stateDir = projectRoot.resolve("reports/repair-revisions")
                require(!Files.isSymbolicLink(projectRoot.resolve("reports"))) {
                    "repair reports directory must not be a symbolic link"
                }
                stateDir.createDirectories()
                require(Files.isDirectory(stateDir, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(stateDir)) {
                    "repair revision state is not a regular directory"
                }
                val blobs = stateDir.resolve("blobs").createDirectories()
                require(Files.isDirectory(blobs, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(blobs)) {
                    "repair blob state is not a regular directory"
                }
                val lockPath = stateDir.resolve("graph.lock")
                require(!Files.isSymbolicLink(lockPath)) { "repair graph lock must not be a symbolic link" }
                val channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)
                val lock = try {
                    channel.lock()
                } catch (failure: Exception) {
                    channel.close()
                    throw IllegalStateException("could not acquire repair revision graph lock", failure)
                }
                return try {
                    val graphPath = stateDir.resolve("graph.json")
                    val bindingPath = stateDir.resolve("recovery-binding.json")
                    cleanupAtomicTemporaryBeforeOpen(graphPath)
                    cleanupAtomicTemporaryBeforeOpen(bindingPath)
                    restorePendingPreimagesBeforeIndex(projectRoot, graphPath, bindingPath, blobs, profile, budget)
                    val currentIndex = SecureRepairRuntime.loadIndex(graphAuthority, projectRoot, profile, budget)
                    require(currentIndex.belongsTo(projectRoot) && currentIndex.budget == budget) {
                        "repair dependency index belongs to a different project or resource budget"
                    }
                    requireRecoveryBinding(bindingPath, currentIndex)
                    try {
                        SecureRepairRuntime.authorizeGraphConstruction(graphAuthority)
                        ModuleRevisionGraph(
                            graphAuthority,
                            projectRoot,
                            portableProjectRoot,
                            rootDescriptor,
                            currentIndex,
                            graphPath,
                            blobs,
                            channel,
                            lock,
                            rootCoordination,
                            faultInjector,
                        )
                    } finally {
                        SecureRepairRuntime.clearConstructionAuthorization()
                    }
                } catch (failure: Throwable) {
                    runCatching { lock.release() }
                    channel.close()
                    throw failure
                }
            } catch (failure: Throwable) {
                try {
                    rootDescriptor.close()
                } finally {
                    rootCoordination.close()
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

private fun requireRecoveryBinding(path: Path, index: ModuleRepairIndex) {
    val expected = recoveryBinding(index)
    if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)) {
            "repair recovery authorization is not a regular file"
        }
        val observed = parseCanonicalRecoveryBinding(
            readStableRegularFile(path.parent, path.fileName.toString(), index.budget.maximumGraphBytes).bytes,
        )
        require(observed == expected) {
            "repair recovery authorization differs from the current profile/index layout"
        }
    } else {
        atomicWrite(path, renderRecoveryBinding(expected).toByteArray(Charsets.UTF_8))
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

private fun cleanupAtomicTemporaryBeforeOpen(target: Path) {
    val temporary = atomicRepairTemporary(target)
    if (!Files.exists(temporary, LinkOption.NOFOLLOW_LINKS)) return
    require(Files.isRegularFile(temporary, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(temporary)) {
        "repair graph temporary is not a regular file"
    }
    Files.delete(temporary)
    forceDirectory(target.parent)
}

/**
 * Validate every topology, source-delta, profile, pending-parent, and blob invariant before startup
 * recovery is allowed to mutate a project source path. This validation deliberately needs no live
 * dependency index: that index can only be reconstructed after a partially installed candidate is
 * restored to its accepted parent.
 */
private fun validateGraphBeforeRecovery(
    state: RevisionGraphState,
    profile: RepairIndexProfile,
    binding: RepairRecoveryBinding,
    blobsDir: Path,
    requestedBudget: RepairResourceBudget,
): Map<String, IndexedSource> {
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
            require(node.parentId == derivedHead &&
                node.status in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.REJECTED)) {
                "revision graph node is not attached to the accepted head: ${node.id}"
            }
            require(node.changes.size <= state.budget.maximumPatchFiles) {
                "revision graph node exceeds the patch-file budget: ${node.id}"
            }
            val nodePatchBytes = node.changes.fold(0L) { total, delta ->
                Math.addExact(total, delta.afterBytes)
            }
            require(nodePatchBytes <= state.budget.maximumPatchBytes) {
                "revision graph node exceeds the patch-byte budget: ${node.id}"
            }
            val candidate = accepted.toMutableMap()
            node.changes.forEach { delta ->
                validateDeltaPortable(delta)
                val before = accepted.getValue(delta.path)
                require(delta.beforeSha256 == before.sha256 && delta.beforeBytes == before.bytes) {
                    "revision graph delta is not bound to its accepted parent: ${node.id}:${delta.path}"
                }
                candidate[delta.path] = IndexedSource(delta.path, delta.afterBytes, delta.afterSha256)
            }
            require(node.sourceRevisionSha256 == revisionSha256(candidate.values))
            if (node.status == ModuleRevisionStatus.ACCEPTED) {
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
        require(pending.parentId == state.headId && pending.ordinal == priorOrdinal + 1 &&
            pending.ordinal == state.nextOrdinal - 1)
        require(pending.allowedPaths == pending.allowedPaths.distinct().sorted() && pending.allowedPaths.isNotEmpty())
        require(pending.allowedPaths.all { it in state.editablePaths })
        val expectedIdMaterial = pending.parentId + "\n" + pending.ordinal + "\n" +
            pending.allowedPaths.joinToString("\n")
        require(
            pending.id == "revision_${pending.ordinal.toString().padStart(8, '0')}_${sha256(expectedIdMaterial.toByteArray()).take(16)}",
        ) { "pending repair attempt ID is not bound to its parent and authorization" }
        require(pending.parentSourceRevisionSha256 == revisionSha256(accepted.values))
        pending.repairMetadata?.let { validatePortableMetadata(it, priorRepairIteration + 1) }
        pending.preimages.forEach { preimage ->
            validateDeltaPortable(preimage)
            val parent = accepted.getValue(preimage.path)
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
        val candidate = accepted.toMutableMap()
        pending.candidateChanges.forEach { delta ->
            validateDeltaPortable(delta)
            val parent = accepted.getValue(delta.path)
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
    graphPath: Path,
    bindingPath: Path,
    blobsDir: Path,
    profile: RepairIndexProfile,
    requestedBudget: RepairResourceBudget,
) {
    if (!Files.exists(graphPath, LinkOption.NOFOLLOW_LINKS)) return
    require(Files.isRegularFile(graphPath, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(graphPath)) {
        "revision graph is not a regular file: $graphPath"
    }
    val graphBytes = readStableRegularFile(graphPath.parent, graphPath.fileName.toString(), requestedBudget.maximumGraphBytes).bytes
    val loaded = parseCanonicalGraph(graphBytes, "reports/repair-revisions/graph.json")
    require(Files.isRegularFile(bindingPath, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(bindingPath)) {
        "revision graph is missing its immutable recovery authorization"
    }
    val binding = parseCanonicalRecoveryBinding(
        readStableRegularFile(
            bindingPath.parent,
            bindingPath.fileName.toString(),
            requestedBudget.maximumGraphBytes,
        ).bytes,
    )
    val acceptedSources = validateGraphBeforeRecovery(
        loaded,
        profile,
        binding,
        blobsDir,
        requestedBudget,
    )
    val pending = loaded.pending ?: return
    val candidateByPath = pending.candidateChanges.associateBy { it.path }
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
                    blobsDir,
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
    require(replacements.keys.all { it in pending.allowedPaths })
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
        staged.map { replacement ->
            if (replacement.parentRelative.isEmpty()) projectRoot else projectRoot.resolve(replacement.parentRelative)
        }.distinct().forEach(::forceDirectory)
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
            }
        }
        try {
            LinuxFilesystemSyscalls.renameNoReplace(parentFd, name, quarantine)
            quarantined = true
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
        // There is deliberately no fallible work after the irreversible unlink.
    } catch (failure: Throwable) {
        if (quarantined) {
            runCatching { LinuxFilesystemSyscalls.renameNoReplace(parentFd, quarantine, name) }
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
    } finally {
        installed.close()
        displaced.close()
    }
}

private fun renderGraph(state: RevisionGraphState): String = buildString {
    append("{\n  \"schemaVersion\": 1,")
    append("\n  \"budget\": ").append(state.budget.toJson()).append(',')
    append("\n  \"profileId\": \"").append(state.profileId.jsonEscape()).append("\",")
    append("\n  \"profileSha256\": \"").append(state.profileSha256).append("\",")
    append("\n  \"editablePaths\": ").append(state.editablePaths.jsonArray()).append(',')
    append("\n  \"indexSha256\": \"").append(state.indexSha256).append("\",")
    append("\n  \"retainedRegressionInputs\": ").append(state.retainedRegressionInputs.toGraphJson()).append(',')
    append("\n  \"regressionCorpusSha256\": \"").append(state.regressionCorpusSha256).append("\",")
    append("\n  \"headId\": \"").append(state.headId).append("\",")
    append("\n  \"nextOrdinal\": ").append(state.nextOrdinal).append(',')
    append("\n  \"storedBlobBytes\": ").append(state.storedBlobBytes).append(',')
    append("\n  \"nodes\": [")
    append(state.nodes.joinToString(",") { "\n" + it.toJson().prependIndent("    ") })
    append("\n  ],\n  \"pending\": ").append(state.pending?.toJson() ?: "null").append("\n}\n")
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
        "\"maximumRevisionNodes\":$maximumRevisionNodes," +
        "\"maximumGraphBytes\":$maximumGraphBytes," +
        "\"maximumStoredBlobBytes\":$maximumStoredBlobBytes}"

private fun ModuleRevisionNode.toJson(): String = buildString {
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
    append("\n  \"repairMetadata\": ").append(repairMetadata?.toJson() ?: "null").append(',')
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

private fun PendingAttempt.toJson(): String = buildString {
    append("{\"id\":\"").append(id.jsonEscape()).append("\",\"parentId\":\"").append(parentId.jsonEscape())
    append("\",\"ordinal\":").append(ordinal).append(",\"allowedPaths\":").append(allowedPaths.jsonArray())
    append(",\"parentSourceRevisionSha256\":\"").append(parentSourceRevisionSha256).append("\",")
    append("\"candidateSourceRevisionSha256\":")
        .append(candidateSourceRevisionSha256?.let { "\"$it\"" } ?: "null").append(',')
    append("\"preimages\":[").append(preimages.joinToString(",") { it.toJson() }).append("],")
    append("\"candidateChanges\":[").append(candidateChanges.joinToString(",") { it.toJson() }).append("],")
    append("\"repairMetadata\":").append(repairMetadata?.toJson() ?: "null").append('}')
}

private fun RevisionRepairMetadata.toJson(): String = buildString {
    append("{\"iterationIndex\":").append(iterationIndex)
    append(",\"failureKind\":\"").append(failureKind.jsonEscape()).append('"')
    append(",\"prompt\":\"").append(prompt.jsonEscape()).append('"')
    append(",\"summary\":").append(summary?.let { "\"${it.jsonEscape()}\"" } ?: "null")
    append(",\"retainedRegressionIds\":").append(retainedRegressionIds.jsonArray())
    append(",\"before\":").append(before?.toGraphJson() ?: "null")
    append(",\"regressionCorpusSha256\":")
        .append(regressionCorpusSha256?.let { "\"${it.jsonEscape()}\"" } ?: "null").append('}')
}

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
    require(root["schemaVersion"]?.jsonPrimitive?.intOrNull == 1) { "unsupported repair revision graph schema" }
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
            maximumRevisionNodes = value.requiredInt("maximumRevisionNodes"),
            maximumGraphBytes = value.requiredLong("maximumGraphBytes"),
            maximumStoredBlobBytes = value.requiredLong("maximumStoredBlobBytes"),
        )
    }
    val nodes = root.getValue("nodes").jsonArray.map(::parseNode)
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
        pendingElement?.takeUnless { it is JsonNull }?.let(::parsePending),
        root.requiredLong("storedBlobBytes"),
    )
}

private fun parseNode(element: JsonElement): ModuleRevisionNode {
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
        value["repairMetadata"]?.takeUnless { it is JsonNull }?.let(::parseRepairMetadata),
    )
}

private fun parsePending(element: JsonElement): PendingAttempt {
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
        value["repairMetadata"]?.takeUnless { it is JsonNull }?.let(::parseRepairMetadata),
    )
}

private fun parseRepairMetadata(element: JsonElement): RevisionRepairMetadata {
    val value = element.jsonObject
    return RevisionRepairMetadata(
        iterationIndex = value.requiredInt("iterationIndex"),
        failureKind = value.requiredString("failureKind"),
        prompt = value.requiredString("prompt"),
        summary = value.optionalString("summary"),
        retainedRegressionIds = value.stringList("retainedRegressionIds"),
        before = value["before"]?.takeUnless { it is JsonNull }?.let(::parseGraphEvidence),
        regressionCorpusSha256 = value.optionalString("regressionCorpusSha256"),
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
): StableRegularFile {
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
            parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
            pinnedDirectories += parent
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
            LinuxFilesystemSyscalls.read(readable, maximumBytes.toInt()) { }
        } catch (_: LinuxResourceLimitException) {
            throw RepairBudgetExceededException("stable file-read target $relative grew beyond $maximumBytes bytes")
        }
        afterRead?.invoke()
        val after = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
        require(
            after.isRegularFile && before.fileKey() == after.fileKey() &&
                before.size() == after.size() && after.size() == bytes.size.toLong() &&
                before.lastModifiedTime() == after.lastModifiedTime() &&
                LinuxFilesystemSyscalls.identity(readable.fd) == readable.identity,
        ) { "stable file-read descriptor changed while it was read: $relative" }
        revalidateDescriptorPath(base, parts, pinnedDirectories.map { it.identity }, authorized.identity)
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
