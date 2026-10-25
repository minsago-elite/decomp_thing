package decompengine.oracle.reference

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateSnapshot
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** One retained, single-use reference operation; incomplete journals are never resumed implicitly. */
internal class ReferenceCorpusOperationJournal private constructor(
    val path: Path,
    val operationId: String,
    val intentSha256: String,
    private val rootPath: Path,
    private val parent: LinuxDescriptor,
    private val root: LinuxDescriptor,
    private val directory: LinuxDescriptor,
    intent: DescriptorBoundStateSnapshot,
    batches: List<String>,
) : AutoCloseable {
    private val snapshots = linkedMapOf("intent.json" to intent)
    private val batchIds = batches.toList()
    private var batchIndex = 0
    private var phase = Phase.INTENT
    private var prior = "intent.json"
    private var closed = false
    private var poisoned = false

    @Synchronized
    fun verify(label: String = "reference journal") = guarded(label) { }

    @Synchronized
    fun recordLease(evidence: FullTreeDiskScratchEvidence) = guarded("lease") {
        check(phase == Phase.INTENT)
        require(evidence.operationId == operationId && evidence.requestSha256 == intentSha256) {
            "reference lease differs from the retained intent"
        }
        val bytes = evidence.canonicalBytes()
        require(FullTreeDiskScratchEvidence.parseCanonical(bytes).evidenceSha256 == evidence.evidenceSha256)
        publish("lease.json", bytes)
        prior = "lease.json"
        phase = Phase.LEASED
    }

    @Synchronized
    fun prepareBatch(batchId: String, request: ByteArray, configurationSha256: String): Path = guarded("batch preparation") {
        check(phase == Phase.LEASED || phase == Phase.OBSERVED)
        require(batchIndex < batchIds.size && batchId == batchIds[batchIndex]) { "reference batches are out of order" }
        require(configurationSha256.matches(SHA256))
        require(OracleJson.parseCanonical(request, JSON_LIMITS) is JsonObject)
        val requestName = "request-$batchId.json"
        publish(requestName, request)
        link("prepared-$batchId.json", "reference-batch-prepared-v1", JsonObject(mapOf(
            "batchId" to JsonPrimitive(batchId),
            "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(request)),
            "configurationSha256" to JsonPrimitive(configurationSha256),
        )))
        phase = Phase.PREPARED
        path.resolve(requestName)
    }

    @Synchronized
    fun recordAttachment(batchId: String, attachment: ByteArray) = guarded("attachment") {
        requireBatch(batchId, Phase.PREPARED)
        link("attached-$batchId.json", "reference-batch-attached-v1", parseObject(attachment))
        phase = Phase.ATTACHED
    }

    @Synchronized
    fun authorizeStart(batchId: String) = guarded("START authorization") {
        requireBatch(batchId, Phase.ATTACHED)
        link("started-$batchId.json", "reference-batch-start-authorized-v1", JsonObject(emptyMap()))
        phase = Phase.STARTED
    }

    @Synchronized
    fun recordExecution(batchId: String, execution: ByteArray) = guarded("execution") {
        requireBatch(batchId, Phase.STARTED)
        link("execution-$batchId.json", "reference-batch-executed-v1", parseObject(execution))
        phase = Phase.EXECUTED
    }

    @Synchronized
    fun recordObservations(batchId: String, observations: ByteArray) = guarded("observation capture") {
        requireBatch(batchId, Phase.EXECUTED)
        require(OracleJson.parseCanonical(observations, OBSERVATION_LIMITS) is JsonObject)
        publish("observations-$batchId.json", observations, manifest = true)
        link("captured-$batchId.json", "reference-batch-captured-v1", JsonObject(mapOf(
            "batchId" to JsonPrimitive(batchId),
            "observationsSha256" to JsonPrimitive(OracleArtifacts.sha256(observations)),
            "observationsBytes" to JsonPrimitive(observations.size),
        )))
        batchIndex++
        phase = Phase.OBSERVED
    }

    @Synchronized
    fun complete(reference: ByteArray): Path = guarded("complete reference publication") {
        check(phase == Phase.OBSERVED && batchIndex == batchIds.size) { "reference capture lacks completed batches" }
        require(OracleJson.parseCanonical(reference, OBSERVATION_LIMITS) is JsonObject)
        publish("reference-observations.json", reference, manifest = true)
        link("complete.json", "reference-corpus-captured-v1", JsonObject(mapOf(
            "referenceSha256" to JsonPrimitive(OracleArtifacts.sha256(reference)),
            "referenceBytes" to JsonPrimitive(reference.size),
            "batches" to JsonArray(batchIds.map(::JsonPrimitive)),
            "scratchDisposition" to JsonPrimitive("retained-for-trusted-reset"),
            "candidateQualified" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
        )))
        phase = Phase.COMPLETE
        path.resolve("reference-observations.json")
    }

    private fun requireBatch(batchId: String, expected: Phase) {
        check(phase == expected && batchIndex < batchIds.size && batchIds[batchIndex] == batchId) {
            "reference batch does not follow its retained lifecycle"
        }
    }

    private fun link(name: String, provider: String, payload: JsonObject) {
        val unsigned = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive(provider),
            "operationId" to JsonPrimitive(operationId), "intentSha256" to JsonPrimitive(intentSha256),
            "previousSha256" to JsonPrimitive(OracleArtifacts.sha256(snapshots.getValue(prior).bytes)),
            "payload" to payload,
        ))
        val record = JsonObject(unsigned + ("recordSha256" to JsonPrimitive(OracleArtifacts.sha256(
            OracleJson.canonicalBytes(unsigned, JSON_LIMITS)))))
        publish(name, OracleJson.canonicalBytes(record, JSON_LIMITS))
        prior = name
    }

    private fun publish(name: String, bytes: ByteArray, manifest: Boolean = false) {
        require(name.matches(Regex("[a-z][a-z0-9-]{0,95}\\.json")) && name !in snapshots)
        requireDirectoryBindings()
        snapshots[name] = if (manifest) DescriptorBoundAtomicStateFile.publishManifestNoReplace(
            directory, name, bytes, MAXIMUM_OBSERVATION_BYTES,
        ) else DescriptorBoundAtomicStateFile.publishNoReplace(directory, name, bytes, MAXIMUM_RECORD_BYTES)
        requireDirectoryBindings()
    }

    private fun requireCurrent(label: String) {
        requireDirectoryBindings()
        require(LinuxFilesystemSyscalls.directoryEntryNames(directory, MAXIMUM_ENTRIES + 1).toSet() == snapshots.keys) {
            "reference journal has unexpected residue $label"
        }
        snapshots.forEach { (name, expected) ->
            val manifest = name.startsWith("observations-") || name == "reference-observations.json"
            val actual = if (manifest) DescriptorBoundAtomicStateFile.readManifestOrNull(directory, name, MAXIMUM_OBSERVATION_BYTES)
                else DescriptorBoundAtomicStateFile.readOrNull(directory, name, MAXIMUM_RECORD_BYTES)
            require(actual != null && actual.identity == expected.identity && MessageDigest.isEqual(actual.bytes, expected.bytes)) {
                "reference journal identity or bytes changed $label: $name"
            }
        }
        requireDirectoryBindings()
    }

    private fun requireDirectoryBindings() {
        requireRootBinding(rootPath, parent, root)
        val current = LinuxFilesystemSyscalls.identity(directory.fd)
        requireManagedDirectory(current, root.identity, "reference operation journal")
        require(sameDirectory(current, directory.identity))
        LinuxFilesystemSyscalls.openDirectoryAt(root.fd, path.fileName.toString()).use {
            require(sameDirectory(LinuxFilesystemSyscalls.identity(it.fd), current))
        }
        require(path.toRealPath() == path && Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(directory)))
    }

    private inline fun <T> guarded(label: String, action: () -> T): T {
        check(!closed && !poisoned) { "reference journal is closed or poisoned" }
        return try {
            requireCurrent("before $label")
            action().also { requireCurrent("after $label") }
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        closeJournalDescriptors(directory, root, parent, true, true)?.let { throw it }
    }

    companion object {
        fun create(root: Path, operationId: String, intentBytes: ByteArray, batches: List<String>): ReferenceCorpusOperationJournal {
            require(operationId.matches(SHA256))
            require(batches.size in 1..16 && batches.distinct().size == batches.size &&
                batches.all { it.matches(Regex("[a-z][a-z0-9-]{0,63}")) })
            require(intentBytes.size in 1..MAXIMUM_RECORD_BYTES && OracleJson.parseCanonical(intentBytes, JSON_LIMITS) is JsonObject)
            require(root.isAbsolute && root.normalize() == root && root.parent != null &&
                Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) && root.toRealPath() == root)
            LinuxFilesystemSyscalls.requireSupported(root)
            val parent = LinuxFilesystemSyscalls.openRoot(root.parent)
            var openedRoot: LinuxDescriptor? = null
            var directory: LinuxDescriptor? = null
            var rootLocked = false
            var directoryLocked = false
            try {
                openedRoot = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, root.fileName.toString())
                requireRootBinding(root, parent, openedRoot)
                check(LinuxFilesystemSyscalls.tryExclusiveLock(openedRoot)) { "reference journal root is already owned" }
                rootLocked = true
                val name = ".reference-corpus-$operationId"
                LinuxFilesystemSyscalls.openPathAtOrNull(openedRoot.fd, name)?.use {
                    error("reference operation already exists; explicit recovery is required")
                }
                LinuxFilesystemSyscalls.createDirectory(openedRoot.fd, name, OWNER_DIRECTORY_MODE)
                directory = LinuxFilesystemSyscalls.openDirectoryAt(openedRoot.fd, name)
                LinuxFilesystemSyscalls.chmod(directory, OWNER_DIRECTORY_MODE)
                requireManagedDirectory(LinuxFilesystemSyscalls.identity(directory.fd), openedRoot.identity, "reference journal")
                check(LinuxFilesystemSyscalls.tryExclusiveLock(directory))
                directoryLocked = true
                LinuxFilesystemSyscalls.synchronize(directory)
                LinuxFilesystemSyscalls.synchronize(openedRoot)
                LinuxFilesystemSyscalls.synchronize(parent)
                require(LinuxFilesystemSyscalls.directoryEntryNames(directory, 1).isEmpty())
                val intent = DescriptorBoundAtomicStateFile.publishNoReplace(directory, "intent.json", intentBytes, MAXIMUM_RECORD_BYTES)
                return ReferenceCorpusOperationJournal(root.resolve(name), operationId, OracleArtifacts.sha256(intentBytes),
                    root, parent, openedRoot, directory, intent, batches).also { it.verify("creation") }
            } catch (failure: Throwable) {
                closeJournalDescriptors(directory, openedRoot, parent, directoryLocked, rootLocked)?.let(failure::addSuppressed)
                throw failure
            }
        }
    }

    private enum class Phase { INTENT, LEASED, PREPARED, ATTACHED, STARTED, EXECUTED, OBSERVED, COMPLETE }
}

private fun parseObject(bytes: ByteArray): JsonObject = OracleJson.parseCanonical(bytes, JSON_LIMITS) as? JsonObject
    ?: throw IllegalArgumentException("reference lifecycle payload must be a canonical object")

private fun requireRootBinding(path: Path, parent: LinuxDescriptor, root: LinuxDescriptor) {
    val currentParent = LinuxFilesystemSyscalls.identity(parent.fd)
    val uid = currentUid()
    if (
        !sameDirectory(currentParent, parent.identity) || currentParent.uid !in setOf(0, uid) ||
        currentParent.mode.permissions and GROUP_OR_OTHER_WRITE_MODE != 0 ||
        path.parent.toRealPath() != path.parent ||
        !Files.isSameFile(path.parent, LinuxFilesystemSyscalls.descriptorPath(parent))
    ) referenceJournalFail("reference corpus journal root has an untrusted or changed parent")
    val currentRoot = LinuxFilesystemSyscalls.identity(root.fd)
    requireManagedDirectory(currentRoot, root.identity, "reference corpus journal root")
    if (!sameDirectory(currentRoot, root.identity)) referenceJournalFail("reference corpus journal root changed identity")
    LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, path.fileName.toString()).use { selected ->
        if (!sameDirectory(LinuxFilesystemSyscalls.identity(selected.fd), currentRoot)) {
            referenceJournalFail("reference corpus journal root name changed identity")
        }
    }
    if (path.toRealPath() != path || !Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(root))) {
        referenceJournalFail("reference corpus journal root pathname changed")
    }
}

private fun requireManagedDirectory(actual: LinuxFileIdentity, parent: LinuxFileIdentity, label: String) {
    val uid = currentUid()
    if (
        !actual.isDirectory || actual.isRegularFile || actual.isSymbolicLink ||
        actual.mountId != parent.mountId || actual.uid != uid || parent.uid != uid ||
        actual.mode.permissions != OWNER_DIRECTORY_MODE
    ) referenceJournalFail("$label is not an owner-only directory on its authorized filesystem")
}

private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId && first.uid == second.uid && first.gid == second.gid &&
        first.isDirectory && second.isDirectory && !first.isRegularFile && !second.isRegularFile &&
        !first.isSymbolicLink && !second.isSymbolicLink

private fun currentUid(): Int = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private fun closeJournalDescriptors(
    directory: LinuxDescriptor?,
    root: LinuxDescriptor?,
    parent: LinuxDescriptor,
    directoryLocked: Boolean = true,
    rootLocked: Boolean = true,
): Throwable? {
    var failure: Throwable? = null
    fun attempt(action: () -> Unit) {
        runCatching(action).exceptionOrNull()?.let { next ->
            val first = failure
            if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
        }
    }
    if (directory != null) {
        if (directoryLocked) attempt { LinuxFilesystemSyscalls.unlock(directory) }
        attempt { directory.close() }
    }
    if (root != null) {
        if (rootLocked) attempt { LinuxFilesystemSyscalls.unlock(root) }
        attempt { root.close() }
    }
    attempt { parent.close() }
    return failure
}


private fun referenceJournalFail(message: String): Nothing = throw IllegalArgumentException(message)
private val SHA256 = Regex("[a-f0-9]{64}")
private const val OWNER_DIRECTORY_MODE = 448
private const val GROUP_OR_OTHER_WRITE_MODE = 18
private const val MAXIMUM_RECORD_BYTES = 1024 * 1024
private const val MAXIMUM_OBSERVATION_BYTES = 16 * 1024 * 1024
private const val MAXIMUM_ENTRIES = 128
private val JSON_LIMITS = StrictJsonLimits(maximumInputBytes = MAXIMUM_RECORD_BYTES, maximumCanonicalBytes = MAXIMUM_RECORD_BYTES, maximumDepth = 48, maximumNodes = 100_000)
private val OBSERVATION_LIMITS = StrictJsonLimits(maximumInputBytes = MAXIMUM_OBSERVATION_BYTES, maximumCanonicalBytes = MAXIMUM_OBSERVATION_BYTES, maximumDepth = 64, maximumNodes = 500_000, maximumStringBytes = MAXIMUM_OBSERVATION_BYTES, maximumTotalStringBytes = MAXIMUM_OBSERVATION_BYTES)
