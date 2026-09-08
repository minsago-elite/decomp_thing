package decompengine.oracle.gcc

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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonElement

internal class GccBundledOperationJournal private constructor(
    val path: Path,
    private val operationId: String,
    private val intentSha256: String,
    private val rootPath: Path,
    private val parent: LinuxDescriptor,
    private val root: LinuxDescriptor,
    private val directory: LinuxDescriptor,
    intentSnapshot: DescriptorBoundStateSnapshot,
) : AutoCloseable {
    private val snapshots = linkedMapOf(INTENT_FILE to intentSnapshot)
    private var stage = JournalStage.INTENT
    private var diskEvidenceSha256: String? = null
    private var poisoned = false
    private var closed = false

    val preparedBytes: ByteArray
        @Synchronized get() {
            checkOpen()
            check(stage >= JournalStage.PREPARED) { "GCC bundled operation is not prepared" }
            return snapshots.getValue(PREPARED_FILE).bytes
        }

    @Synchronized
    fun recordLease(evidence: FullTreeDiskScratchEvidence) = boundOperation("recording GCC disk lease") {
        check(stage == JournalStage.INTENT) { "GCC bundled disk lease requires the intent-only stage" }
        if (evidence.operationId != operationId || evidence.requestSha256 != intentSha256) {
            journalFail("GCC bundled disk evidence belongs to a different operation intent")
        }
        val bytes = evidence.canonicalBytes()
        val parsed = FullTreeDiskScratchEvidence.parseCanonical(bytes)
        if (parsed.evidenceSha256 != evidence.evidenceSha256) {
            journalFail("GCC bundled disk evidence identity changed")
        }
        publish(LEASE_FILE, bytes)
        diskEvidenceSha256 = evidence.evidenceSha256
        stage = JournalStage.LEASED
    }

    @Synchronized
    fun recordPrepared(definitionBytes: ByteArray, deploymentClosureSha256: String) = boundOperation("recording prepared GCC operation") {
        check(stage == JournalStage.LEASED) { "GCC bundled preparation requires one recorded disk lease" }
        require(deploymentClosureSha256.matches(Regex("[a-f0-9]{64}"))) {
            "GCC bundled deployment closure digest is invalid"
        }
        val bytes = boundedCopy(definitionBytes, MAXIMUM_DEFINITION_BYTES, "GCC bundled containment definition")
        val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(bytes)
        if (definition.bundledRuntime == null) {
            journalFail("GCC bundled operation requires a v2 bundled containment definition")
        }
        if (path.startsWith(definition.outputLease.path) || definition.outputLease.path.startsWith(path)) {
            journalFail("GCC bundled journal must remain outside its writable output")
        }
        val unsigned = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-prepared-operation-v1"),
            "schemaVersion" to JsonPrimitive(1),
            "operationId" to JsonPrimitive(operationId),
            "intentSha256" to JsonPrimitive(intentSha256),
            "diskEvidenceSha256" to JsonPrimitive(checkNotNull(diskEvidenceSha256)),
            "definitionSha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
            "definitionBindingSha256" to JsonPrimitive(definition.bindingSha256),
            "deploymentClosureSha256" to JsonPrimitive(deploymentClosureSha256),
        ))
        val prepared = OracleJson.canonicalBytes(
            JsonObject(unsigned + ("preparedSha256" to JsonPrimitive(
                OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned, JOURNAL_JSON_LIMITS)),
            ))),
            JOURNAL_JSON_LIMITS,
        )
        publish(DEFINITION_FILE, bytes)
        stage = JournalStage.DEFINITION_STAGED
        requireCurrent("after GCC definition publication")
        publish(PREPARED_FILE, prepared)
        stage = JournalStage.PREPARED
    }

    @Synchronized
    fun verify(label: String) = boundOperation(label) { }

    @Synchronized
    fun recordAttachment(attachmentBytes: ByteArray) = boundOperation("recording GCC command attachment") {
        check(stage == JournalStage.PREPARED) { "GCC command attachment requires a prepared operation" }
        publishLinkedRecord(ATTACHMENT_FILE, "gcc-bundled-command-attached-v1", PREPARED_FILE, "attachment", attachmentBytes)
        stage = JournalStage.ATTACHED
    }

    @Synchronized
    fun recordStartAuthorization() = boundOperation("authorizing GCC command START") {
        check(stage == JournalStage.ATTACHED) { "GCC command START requires a retained attachment" }
        publishLinkedRecord(START_FILE, "gcc-bundled-command-start-authorized-v1", ATTACHMENT_FILE, null, null)
        stage = JournalStage.START_AUTHORIZED
    }

    @Synchronized
    fun recordExecution(executionBytes: ByteArray): ByteArray = boundOperation("recording GCC command execution") {
        check(stage == JournalStage.START_AUTHORIZED) { "GCC command execution requires durable START authorization" }
        publishLinkedRecord(EXECUTION_FILE, "gcc-bundled-command-executed-v1", START_FILE, "execution", executionBytes)
        stage = JournalStage.EXECUTED
        snapshots.getValue(EXECUTION_FILE).bytes
    }

    @Synchronized
    fun recordExportAssessment(assessmentBytes: ByteArray): ByteArray = boundOperation("recording GCC export assessment") {
        check(stage == JournalStage.EXECUTED) { "GCC export assessment requires recorded contained execution" }
        publishLinkedRecord(EXPORT_FILE, "gcc-bundled-command-export-assessed-v1", EXECUTION_FILE, "assessment", assessmentBytes)
        stage = JournalStage.EXPORT_ASSESSED
        snapshots.getValue(EXPORT_FILE).bytes
    }

    @Synchronized
    fun recordInterruptionAuthorization(authorizationBytes: ByteArray) = boundOperation("authorizing GCC command interruption") {
        check(stage == JournalStage.START_AUTHORIZED) { "GCC interruption requires durable START authorization" }
        publishLinkedRecord(INTERRUPT_FILE, "gcc-bundled-command-interrupt-authorized-v1", START_FILE, "authorization", authorizationBytes)
        stage = JournalStage.INTERRUPT_AUTHORIZED
    }

    @Synchronized
    fun recordInterruptedExecution(executionBytes: ByteArray): ByteArray = boundOperation("recording interrupted GCC command") {
        check(stage == JournalStage.INTERRUPT_AUTHORIZED) { "GCC interrupted execution requires durable interruption authorization" }
        publishLinkedRecord(INTERRUPTED_FILE, "gcc-bundled-command-interrupted-v1", INTERRUPT_FILE, "execution", executionBytes)
        stage = JournalStage.INTERRUPTED
        snapshots.getValue(INTERRUPTED_FILE).bytes
    }

    @Synchronized
    fun recordInterruptedPrefixAssessment(assessmentBytes: ByteArray): ByteArray = boundOperation("recording interrupted GCC prefix") {
        check(stage == JournalStage.INTERRUPTED) { "GCC interrupted prefix requires recorded interrupted execution" }
        publishLinkedRecord(PREFIX_FILE, "gcc-bundled-command-prefix-assessed-v1", INTERRUPTED_FILE, "assessment", assessmentBytes)
        stage = JournalStage.PREFIX_ASSESSED
        snapshots.getValue(PREFIX_FILE).bytes
    }

    @Synchronized
    fun recordInterruptedAnalysisState(snapshot: GccBundledAnalysisStateSnapshot): ByteArray = boundOperation("recording stopped GCC analysis state") {
        check(stage == JournalStage.PREFIX_ASSESSED) { "GCC stopped analysis state requires a validated interrupted prefix" }
        val manifest = snapshot.canonicalBytes
        publish(STATE_MANIFEST_FILE, manifest)
        stage = JournalStage.STATE_MANIFEST_STAGED
        requireCurrent("after GCC state manifest publication")
        val summary = OracleJson.canonicalBytes(JsonObject(mapOf(
            "manifestSha256" to JsonPrimitive(snapshot.sha256),
            "manifestBytes" to JsonPrimitive(manifest.size),
            "entryCount" to JsonPrimitive(snapshot.entryCount),
            "totalBytes" to JsonPrimitive(snapshot.totalBytes),
        )))
        publishLinkedRecord(STATE_CAPTURED_FILE, "gcc-bundled-interrupted-state-captured-v1", PREFIX_FILE, "analysisState", summary)
        stage = JournalStage.STATE_CAPTURED
        snapshots.getValue(STATE_CAPTURED_FILE).bytes
    }

    private fun publishLinkedRecord(name: String, provider: String, previous: String, payloadName: String?, payloadBytes: ByteArray?) {
        val fields = linkedMapOf<String, JsonElement>(
            "provider" to JsonPrimitive(provider),
            "schemaVersion" to JsonPrimitive(1),
            "operationId" to JsonPrimitive(operationId),
            "intentSha256" to JsonPrimitive(intentSha256),
            "previousSha256" to JsonPrimitive(OracleArtifacts.sha256(snapshots.getValue(previous).bytes)),
            "complete" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
        )
        if (payloadName != null) {
            val bytes = boundedCopy(requireNotNull(payloadBytes), MAXIMUM_INTENT_BYTES, "GCC command record")
            val payload = OracleJson.parseCanonical(bytes, JOURNAL_JSON_LIMITS)
            require(payload is JsonObject) { "GCC command payload must be a canonical object" }
            fields[payloadName] = payload
            fields["${payloadName}Sha256"] = JsonPrimitive(OracleArtifacts.sha256(bytes))
        }
        fields["recordSha256"] = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields), JOURNAL_JSON_LIMITS)))
        publish(name, OracleJson.canonicalBytes(JsonObject(fields), JOURNAL_JSON_LIMITS))
    }

    private fun publish(name: String, bytes: ByteArray) {
        requireDirectoryBindings()
        snapshots[name] = if (name == STATE_MANIFEST_FILE) {
            DescriptorBoundAtomicStateFile.publishManifestNoReplace(directory, name, bytes, maximumFileBytes(name))
        } else {
            DescriptorBoundAtomicStateFile.publishNoReplace(directory, name, bytes, maximumFileBytes(name))
        }
        requireDirectoryBindings()
    }

    private fun requireCurrent(label: String) {
        requireDirectoryBindings()
        val expectedNames = when (stage) {
            JournalStage.INTENT -> setOf(INTENT_FILE)
            JournalStage.LEASED -> setOf(INTENT_FILE, LEASE_FILE)
            JournalStage.DEFINITION_STAGED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE)
            JournalStage.PREPARED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE)
            JournalStage.ATTACHED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE)
            JournalStage.START_AUTHORIZED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE)
            JournalStage.EXECUTED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, EXECUTION_FILE)
            JournalStage.EXPORT_ASSESSED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, EXECUTION_FILE, EXPORT_FILE)
            JournalStage.INTERRUPT_AUTHORIZED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, INTERRUPT_FILE)
            JournalStage.INTERRUPTED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, INTERRUPT_FILE, INTERRUPTED_FILE)
            JournalStage.PREFIX_ASSESSED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, INTERRUPT_FILE, INTERRUPTED_FILE, PREFIX_FILE)
            JournalStage.STATE_MANIFEST_STAGED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, INTERRUPT_FILE, INTERRUPTED_FILE, PREFIX_FILE, STATE_MANIFEST_FILE)
            JournalStage.STATE_CAPTURED -> setOf(INTENT_FILE, LEASE_FILE, DEFINITION_FILE, PREPARED_FILE, ATTACHMENT_FILE, START_FILE, INTERRUPT_FILE, INTERRUPTED_FILE, PREFIX_FILE, STATE_MANIFEST_FILE, STATE_CAPTURED_FILE)
        }
        if (snapshots.keys != expectedNames) journalFail("GCC bundled journal has inconsistent retained state")
        requireExactNames(expectedNames, label)
        snapshots.forEach { (name, expected) ->
            val actual = (if (name == STATE_MANIFEST_FILE) {
                DescriptorBoundAtomicStateFile.readManifestOrNull(directory, name, maximumFileBytes(name))
            } else DescriptorBoundAtomicStateFile.readOrNull(directory, name, maximumFileBytes(name)))
                ?: journalFail("GCC bundled journal file disappeared $label: $name")
            if (actual.identity != expected.identity || !MessageDigest.isEqual(actual.bytes, expected.bytes)) {
                journalFail("GCC bundled journal file changed $label: $name")
            }
        }
        requireExactNames(expectedNames, label)
        requireDirectoryBindings()
    }

    private fun requireExactNames(expected: Set<String>, label: String) {
        val names = LinuxFilesystemSyscalls.directoryEntryNames(directory, MAXIMUM_JOURNAL_ENTRIES + 1)
        if (names.size != expected.size || names.toSet() != expected) {
            journalFail("GCC bundled journal contains unexpected residue $label")
        }
    }

    private fun requireDirectoryBindings() {
        requireRootBinding(rootPath, parent, root)
        val current = LinuxFilesystemSyscalls.identity(directory.fd)
        requireManagedDirectory(current, root.identity, "GCC bundled operation journal")
        if (!sameDirectory(current, directory.identity)) journalFail("GCC bundled operation journal changed identity")
        LinuxFilesystemSyscalls.openDirectoryAt(root.fd, path.fileName.toString()).use { selected ->
            if (!sameDirectory(LinuxFilesystemSyscalls.identity(selected.fd), current)) {
                journalFail("GCC bundled operation journal name changed identity")
            }
        }
        if (path.toRealPath() != path || !Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(directory))) {
            journalFail("GCC bundled operation journal pathname changed")
        }
    }

    private inline fun <T> boundOperation(label: String, action: () -> T): T {
        checkOpen()
        return try {
            requireCurrent("before $label")
            action().also { requireCurrent("after $label") }
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun checkOpen() {
        check(!closed) { "GCC bundled operation journal is closed" }
        check(!poisoned) { "GCC bundled operation journal is poisoned" }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        closeJournalDescriptors(directory, root, parent)?.let { throw it }
    }

    companion object {
        fun create(root: Path, operationId: String, intentBytes: ByteArray): GccBundledOperationJournal {
            require(operationId.matches(Regex("[a-f0-9]{64}"))) { "GCC bundled operation ID is invalid" }
            val bytes = boundedCopy(intentBytes, MAXIMUM_INTENT_BYTES, "GCC bundled operation intent")
            require(OracleJson.parseCanonical(bytes, JOURNAL_JSON_LIMITS) is JsonObject) {
                "GCC bundled operation intent must be a canonical JSON object"
            }
            if (
                !root.isAbsolute || root.normalize() != root || root.parent == null ||
                !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) || root.toRealPath() != root
            ) journalFail("GCC bundled journal root must be a canonical non-root directory")
            LinuxFilesystemSyscalls.requireSupported(root)
            val parent = LinuxFilesystemSyscalls.openRoot(root.parent)
            var rootDescriptor: LinuxDescriptor? = null
            var directory: LinuxDescriptor? = null
            var rootLocked = false
            var directoryLocked = false
            try {
                val openedRoot = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, root.fileName.toString())
                rootDescriptor = openedRoot
                requireRootBinding(root, parent, openedRoot)
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(openedRoot)) {
                    journalFail("GCC bundled journal root is already locked")
                }
                rootLocked = true
                LinuxFilesystemSyscalls.synchronize(openedRoot)
                LinuxFilesystemSyscalls.synchronize(parent)
                requireRootBinding(root, parent, openedRoot)
                val name = ".gcc-bundled-operation-$operationId"
                LinuxFilesystemSyscalls.openPathAtOrNull(openedRoot.fd, name)?.use {
                    journalFail("GCC bundled operation journal already exists")
                }
                LinuxFilesystemSyscalls.createDirectory(openedRoot.fd, name, OWNER_DIRECTORY_MODE)
                val openedDirectory = LinuxFilesystemSyscalls.openDirectoryAt(openedRoot.fd, name)
                directory = openedDirectory
                LinuxFilesystemSyscalls.chmod(openedDirectory, OWNER_DIRECTORY_MODE)
                requireManagedDirectory(
                    LinuxFilesystemSyscalls.identity(openedDirectory.fd),
                    openedRoot.identity,
                    "GCC bundled operation journal",
                )
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(openedDirectory)) {
                    journalFail("GCC bundled operation journal is already locked")
                }
                directoryLocked = true
                LinuxFilesystemSyscalls.synchronize(openedDirectory)
                LinuxFilesystemSyscalls.synchronize(openedRoot)
                requireRootBinding(root, parent, openedRoot)
                if (LinuxFilesystemSyscalls.directoryEntryNames(openedDirectory, 1).isNotEmpty()) {
                    journalFail("new GCC bundled operation journal contains residue")
                }
                val snapshot = DescriptorBoundAtomicStateFile.publishNoReplace(
                    openedDirectory,
                    INTENT_FILE,
                    bytes,
                    MAXIMUM_INTENT_BYTES,
                )
                return GccBundledOperationJournal(
                    root.resolve(name), operationId, OracleArtifacts.sha256(bytes), root,
                    parent, openedRoot, openedDirectory, snapshot,
                ).also { it.verify("after journal creation") }
            } catch (failure: Throwable) {
                closeJournalDescriptors(
                    directory, rootDescriptor, parent, directoryLocked, rootLocked,
                )?.let { if (it !== failure) failure.addSuppressed(it) }
                throw failure
            }
        }
    }
}

private fun requireRootBinding(path: Path, parent: LinuxDescriptor, root: LinuxDescriptor) {
    val currentParent = LinuxFilesystemSyscalls.identity(parent.fd)
    val uid = currentUid()
    if (
        !sameDirectory(currentParent, parent.identity) || currentParent.uid !in setOf(0, uid) ||
        currentParent.mode.permissions and GROUP_OR_OTHER_WRITE_MODE != 0 ||
        path.parent.toRealPath() != path.parent ||
        !Files.isSameFile(path.parent, LinuxFilesystemSyscalls.descriptorPath(parent))
    ) journalFail("GCC bundled journal root has an untrusted or changed parent")
    val currentRoot = LinuxFilesystemSyscalls.identity(root.fd)
    requireManagedDirectory(currentRoot, root.identity, "GCC bundled journal root")
    if (!sameDirectory(currentRoot, root.identity)) journalFail("GCC bundled journal root changed identity")
    LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, path.fileName.toString()).use { selected ->
        if (!sameDirectory(LinuxFilesystemSyscalls.identity(selected.fd), currentRoot)) {
            journalFail("GCC bundled journal root name changed identity")
        }
    }
    if (path.toRealPath() != path || !Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(root))) {
        journalFail("GCC bundled journal root pathname changed")
    }
}

private fun requireManagedDirectory(actual: LinuxFileIdentity, parent: LinuxFileIdentity, label: String) {
    val uid = currentUid()
    if (
        !actual.isDirectory || actual.isRegularFile || actual.isSymbolicLink ||
        actual.mountId != parent.mountId || actual.uid != uid || parent.uid != uid ||
        actual.mode.permissions != OWNER_DIRECTORY_MODE
    ) journalFail("$label is not an owner-only directory on its authorized filesystem")
}

private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId && first.uid == second.uid && first.gid == second.gid &&
        first.isDirectory && second.isDirectory && !first.isRegularFile && !second.isRegularFile &&
        !first.isSymbolicLink && !second.isSymbolicLink

private fun currentUid(): Int = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private fun boundedCopy(bytes: ByteArray, maximumBytes: Int, label: String): ByteArray {
    require(bytes.isNotEmpty() && bytes.size <= maximumBytes) { "$label exceeds its byte bound" }
    return bytes.copyOf()
}

private fun maximumFileBytes(name: String): Int =
    when (name) {
        DEFINITION_FILE -> MAXIMUM_DEFINITION_BYTES
        STATE_MANIFEST_FILE -> GccBundledAnalysisStateCapture.JSON_LIMITS.maximumCanonicalBytes
        else -> MAXIMUM_INTENT_BYTES
    }

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

private fun journalFail(message: String): Nothing = throw IllegalArgumentException(message)

private enum class JournalStage { INTENT, LEASED, DEFINITION_STAGED, PREPARED, ATTACHED, START_AUTHORIZED, EXECUTED, EXPORT_ASSESSED, INTERRUPT_AUTHORIZED, INTERRUPTED, PREFIX_ASSESSED, STATE_MANIFEST_STAGED, STATE_CAPTURED }
private const val INTENT_FILE = "intent.json"
private const val LEASE_FILE = "lease-evidence.json"
private const val DEFINITION_FILE = "definition.json"
private const val PREPARED_FILE = "prepared.json"
private const val ATTACHMENT_FILE = "attachment.json"
private const val START_FILE = "start-authorized.json"
private const val EXECUTION_FILE = "execution.json"
private const val EXPORT_FILE = "export-assessment.json"
private const val INTERRUPT_FILE = "interrupt-authorized.json"
private const val INTERRUPTED_FILE = "interrupted-execution.json"
private const val PREFIX_FILE = "interrupted-prefix-assessment.json"
private const val STATE_MANIFEST_FILE = "analysis-state-manifest.json"
private const val STATE_CAPTURED_FILE = "analysis-state-captured.json"
private const val OWNER_DIRECTORY_MODE = 0x1c0
private const val GROUP_OR_OTHER_WRITE_MODE = 0x12
private const val MAXIMUM_JOURNAL_ENTRIES = 11
private const val MAXIMUM_INTENT_BYTES = 256 * 1024
private const val MAXIMUM_DEFINITION_BYTES = 1024 * 1024
private val JOURNAL_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_INTENT_BYTES,
    maximumCanonicalBytes = MAXIMUM_INTENT_BYTES,
    maximumDepth = 24,
    maximumNodes = 10_000,
    maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = MAXIMUM_INTENT_BYTES,
)
