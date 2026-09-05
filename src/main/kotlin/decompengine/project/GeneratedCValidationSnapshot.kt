package decompengine.project

import decompengine.acp.AcpCleanupProofFailure
import decompengine.acp.AcpStagingQuotaLimits
import decompengine.acp.AcpWorkflowStagingRoot
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.calculateAcpRuntimeManifestSha256
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.RepairCandidateValidationRequest
import decompengine.repair.RepairResourceBudget
import decompengine.repair.readStableRegularFile
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Owns both finite mounts for one validation; directory flock leases also serialize other JVMs. */
internal class GeneratedCValidationSnapshot private constructor(
    private val configuration: GeneratedCRepairRuntimeConfiguration,
    val budget: RepairResourceBudget,
    private val check: () -> Unit,
    private val leases: List<LinuxDescriptor>,
    val source: AcpWorkflowStagingRoot,
) : AutoCloseable {
    private var output: AcpWorkflowStagingRoot? = null
    private var sourceBytes = 0L
    private var entries = 0
    private var sourceMetadataBytes = 0L
    private var processCleanupUnverified = false
    private val sourceManifest = ArrayList<JsonObject>()
    var sourceManifestSha256: String? = null
        private set
    val sourceFiles: List<JsonObject> get() = Collections.unmodifiableList(sourceManifest)

    fun populate(request: RepairCandidateValidationRequest) {
        require(request.profileId == GeneratedCRepairIndexProfile.profileId())
        val paths = ArrayList<String>()
        val revision = MessageDigest.getInstance("SHA-256")
        request.forEachCandidateSource { relative, bytes ->
            check()
            require(relative == "Makefile" || relative.startsWith("src/") || relative.startsWith("include/")) {
                "candidate input is outside the registered generated-C source layout"
            }
            require(Path.of(relative).nameCount <= budget.maximumDiscoveryDepth)
            require(relative.toByteArray(Charsets.UTF_8).size <= 4096)
            // Charge escaped path/record capacity before retaining JSON nodes or allocating the
            // file tree; empty files still consume bounded manifest and directory authority.
            sourceMetadataBytes = Math.addExact(sourceMetadataBytes,
                Math.addExact(Math.multiplyExact(relative.toByteArray(Charsets.UTF_8).size.toLong(), 6), 512))
            if (sourceMetadataBytes > minOf(budget.maximumIndexEvidenceBytes, 64L * 1024 * 1024)) {
                throw RepairBudgetExceededException("validation source manifest exceeds its metadata bound")
            }
            paths += relative
            revision.update("${relative.length}:$relative:${bytes.size}:${sha256(bytes)}\n".toByteArray(Charsets.UTF_8))
            writeSource(relative, bytes, executable = false)
            sourceManifest += JsonObject(mapOf(
                "path" to JsonPrimitive(relative), "role" to JsonPrimitive(if (relative == "Makefile") "build-file" else "source"),
                "mode" to JsonPrimitive(0x124), "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(sha256(bytes)),
            ))
        }
        require("Makefile" in paths && GeneratedCRepairIndexProfile.authorizesRecoveryLayout(
            paths, paths.filter { it == "Makefile" || it.endsWith(".c") || it.endsWith(".h") }, budget,
        )) { "candidate source layout is not authorized by the generated-C profile" }
        require(revision.digest().joinToString("") { "%02x".format(it) } == request.sourceRevisionSha256) {
            "candidate revision changed during snapshot population"
        }
        sourceManifestSha256 = sha256(JsonArray(sourceManifest).toString().toByteArray(Charsets.UTF_8))
    }

    /** Only this application-owned link connects immutable sources to the independent writable mount. */
    fun beginBuild(): AcpWorkflowStagingRoot {
        val stage = newOutput()
        require(!Files.exists(source.path.resolve("build"), LinkOption.NOFOLLOW_LINKS))
        accountEntry()
        Files.createSymbolicLink(source.path.resolve("build"), stage.path)
        return stage
    }

    fun newOutput(): AcpWorkflowStagingRoot {
        check()
        kotlin.check(output == null) { "previous contained output has not been cleaned" }
        val root = AcpWorkflowStagingRoot.createQuotaBacked(
            "generated-c-output", configuration.outputTmpfs,
            AcpStagingQuotaLimits(budget.maximumStagingBytes, budget.maximumStagingDirectories.toLong()),
            ".generated-c-output-",
        )
        output = root
        check()
        return root
    }

    fun finishOutput() {
        output?.let { root ->
            deleteOwnedTree(root, budget.maximumStagingDirectories.toLong())
            output = null
        }
    }

    fun captureOriginal(path: Path): CapturedGeneratedExecutable = capture(path, "reference")
    fun captureRebuilt(): CapturedGeneratedExecutable = capture(
        requireNotNull(output).path.resolve("reconstructed"), "candidate",
    )

    private fun capture(path: Path, role: String): CapturedGeneratedExecutable {
        check()
        require(path.isAbsolute && path == path.normalize()) { "validation executable path must be absolute and normalized" }
        val limit = minOf(budget.maximumSourceFileBytes, configuration.sandbox.agentResourceLimits.maximumFileBytes)
        val file = readStableRegularFile(requireNotNull(path.parent), path.fileName.toString(), limit,
            afterAuthorization = check, afterRead = check, cancellationCheck = check)
        require(file.bytes.size >= 4 && file.bytes[0] == 0x7f.toByte() && file.bytes[1] == 'E'.code.toByte() &&
            file.bytes[2] == 'L'.code.toByte() && file.bytes[3] == 'F'.code.toByte()) {
            "generated-C validation requires a captured ELF executable"
        }
        val target = writeSource(".validation/$role.elf", file.bytes, executable = true)
        return CapturedGeneratedExecutable(target, file.sha256, file.bytes.size.toLong(), role,
            calculateAcpRuntimeManifestSha256(target, configuration.sandbox.runtimeClosureLimits, check))
    }

    private fun writeSource(relative: String, bytes: ByteArray, executable: Boolean): Path {
        check()
        sourceBytes = Math.addExact(sourceBytes, bytes.size.toLong())
        if (sourceBytes > budget.maximumSourceBytes) throw RepairBudgetExceededException("validation source and executable snapshot exceeds aggregate bytes")
        val target = source.path.resolve(relative)
        require(target.normalize() == target && target.startsWith(source.path))
        var directory = source.path
        Path.of(relative).parent?.forEach { component ->
            check()
            directory = directory.resolve(component)
            if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
                accountEntry()
                Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            }
            require(Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(directory))
        }
        accountEntry()
        Files.newOutputStream(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { stream ->
            var offset = 0
            while (offset < bytes.size) {
                check()
                val count = minOf(64 * 1024, bytes.size - offset)
                stream.write(bytes, offset, count)
                offset += count
            }
        }
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString(if (executable) "r-x------" else "r--r--r--"))
        check()
        return target
    }

    private fun accountEntry() {
        entries = Math.addExact(entries, 1)
        if (entries > budget.maximumDiscoveryEntries) throw RepairBudgetExceededException("validation snapshot exceeds entry count")
    }

    fun retainAfterUnverifiedProcessCleanup() { processCleanupUnverified = true }

    override fun close() {
        // Never release either mount lease after an unverified cleanup. The retained lease and
        // nonempty mount prevent another JVM from treating abandoned authority as a fresh workspace.
        try {
            require(!processCleanupUnverified) { "process cleanup is unverified; snapshot authority must be retained" }
            finishOutput()
            deleteOwnedTree(source, budget.maximumDiscoveryEntries.toLong())
        } catch (failure: Throwable) {
            synchronized(retainedLeases) { retainedLeases.addAll(leases) }
            throw AcpCleanupProofFailure("generated-C validation snapshot cleanup was not proven", failure)
        }
        leases.asReversed().forEach { it.close() }
    }

    companion object {
        private val retainedLeases = ArrayList<LinuxDescriptor>()

        fun create(configuration: GeneratedCRepairRuntimeConfiguration, budget: RepairResourceBudget, check: () -> Unit): GeneratedCValidationSnapshot {
            val leases = ArrayList<LinuxDescriptor>()
            try {
                listOf(configuration.sourceTmpfs, configuration.outputTmpfs).sorted().forEach { mount ->
                    check()
                    val lease = LinuxFilesystemSyscalls.openRoot(mount)
                    leases += lease
                    while (!LinuxFilesystemSyscalls.tryExclusiveLock(lease)) {
                        check()
                        Thread.sleep(10)
                    }
                    LinuxFilesystemSyscalls.openRoot(mount).use { current ->
                        require(current.identity == lease.identity) { "validation quota mount changed while leasing" }
                    }
                }
                check()
                val source = AcpWorkflowStagingRoot.createQuotaBacked(
                    "generated-c-source", configuration.sourceTmpfs,
                    AcpStagingQuotaLimits(budget.maximumSourceBytes, budget.maximumDiscoveryEntries.toLong()),
                    ".generated-c-source-",
                )
                return GeneratedCValidationSnapshot(configuration, budget, check, leases, source)
            } catch (failure: Throwable) {
                if (failure is AcpCleanupProofFailure) synchronized(retainedLeases) { retainedLeases.addAll(leases) }
                else leases.asReversed().forEach { it.close() }
                throw failure
            }
        }
    }
}

internal data class CapturedGeneratedExecutable(val path: Path, val sha256: String, val bytes: Long, val role: String,
    val runtimeManifestSha256: String)

/** Called only after the boundary has proved the complete process tree stopped; never follows links. */
private fun deleteOwnedTree(root: AcpWorkflowStagingRoot, maximumEntries: Long) {
    root.requireCurrentIdentity()
    var count = 0L
    Files.walkFileTree(root.path, object : SimpleFileVisitor<Path>() {
        private fun count() {
            count = Math.addExact(count, 1)
            require(count <= maximumEntries) { "validation cleanup exceeds its finite inode bound" }
        }
        override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
            count()
            require(!attrs.isSymbolicLink)
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"))
            return FileVisitResult.CONTINUE
        }
        override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
            count()
            Files.delete(file)
            return FileVisitResult.CONTINUE
        }
        override fun postVisitDirectory(dir: Path, exc: java.io.IOException?): FileVisitResult {
            if (exc != null) throw exc
            Files.delete(dir)
            return FileVisitResult.CONTINUE
        }
    })
    require(!Files.exists(root.path, LinkOption.NOFOLLOW_LINKS)) { "validation snapshot cleanup did not remove its root" }
}
