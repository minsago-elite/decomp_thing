package decompengine.project

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.*
import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Exact module-object compilation only. Linking and program behavior retain separate authority. */
internal object ContainedModuleCompilationPolicy : ModuleCompilationPolicy {
    const val POLICY_ID = "generated-c-contained-module-compilation-v1"
    override val id = POLICY_ID
    override val legacyFingerprintIdentity = GeneratedCModuleValidation.POLICY_ID
    override fun requireAvailable(profile: ReconstructionProfile) {
        requireContainedModuleCompilerProfile(profile)
        val configuration = ContainedModuleCompilationRuntimeConfiguration.loadFromEnvironment(profile.id)
        require(configuration.profileId == profile.id) {
            "contained module compiler runtime does not match the registered profile"
        }
    }
    override fun historicalCommand(profile: ReconstructionProfile, sourcePath: String) = GeneratedCModuleValidation.command(profile, sourcePath)
    override fun command(profile: ReconstructionProfile, sourcePath: String): List<String> {
        profile.layout.declaration("module-implementation").moduleIdForPath(sourcePath)
        return listOf("authenticated-profile-compiler") + profile.adapterConfiguration.getValue("compiler-flags") +
            listOf("-c", sourcePath, "-o", "<owned-module-object>")
    }
    override fun validate(projectDir: Path, sourcePath: String, profile: ReconstructionProfile): ModuleCompilationEvidence =
        VerifiedContainedModuleCompilation.compile(projectDir, sourcePath, profile)
}

/** A same-process result issued only after real execution, result capture, and owned cleanup. */
internal class VerifiedContainedModuleCompilation private constructor(private val proofSha256: String, private val snapshot: ContainedModuleCompilationSnapshot) {
    fun matches(evidence: ModuleCompilationEvidence, expectedSourceSha256: String, expectedProfileSha256: String,
        expectedPolicyId: String): Boolean {
        if (!ModuleCompilerLiveAdmissions.contains(this, proofSha256)) return false
        val proof = evidence.containedProof ?: return false
        val matches = evidence.passed && evidence.sourceSha256 == expectedSourceSha256 &&
            proof["sourceSha256"] == JsonPrimitive(expectedSourceSha256) &&
            proof["profileSha256"] == JsonPrimitive(expectedProfileSha256) &&
            proof["policyId"] == JsonPrimitive(expectedPolicyId) && sha256(OracleJson.canonicalBytes(proof)) == proofSha256
        if (!matches) return false
        return try { checkCancellation(); snapshot.requireCurrent(); true }
        catch (failure: Exception) {
            if (failure is InterruptedException || Thread.currentThread().isInterrupted) {
                throw moduleCompilationFailurePreservingCancellation(failure, interrupted = true)
            }
            false
        }
    }

    companion object {
        fun compile(projectDir: Path, sourcePath: String, profile: ReconstructionProfile): ModuleCompilationEvidence {
            checkCancellation()
            val deadline = ContainedCommandOperationDeadline(moduleCompilerOperationWallMillis(profile))
            requireContainedModuleCompilerProfile(profile)
            val canonicalProject = projectDir.toAbsolutePath().normalize()
            require(canonicalProject.toRealPath() == canonicalProject) { "module compiler project must not contain a symbolic path alias" }
            val configuration = ContainedModuleCompilationRuntimeConfiguration.loadFromEnvironment(profile.id)
            require(configuration.profileId == profile.id) { "contained compiler runtime belongs to a different profile" }
            deadline.requireCurrent()
            val snapshot = ContainedModuleCompilationSnapshot.capture(canonicalProject, sourcePath, profile) { deadline.requireCurrent() }
            val nonce = ByteArray(32).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }
            val snapshotSha = moduleCompilationSnapshotDigest(snapshot.inputs)
            val intent = JsonObject(mapOf("provider" to JsonPrimitive("module-compilation-intent-v1"),
                "nonce" to JsonPrimitive(nonce), "profileId" to JsonPrimitive(profile.id), "profileSha256" to JsonPrimitive(profile.sha256),
                "sourcePath" to JsonPrimitive(sourcePath), "sourceSha256" to JsonPrimitive(snapshot.sourceSha256),
                "snapshotSha256" to JsonPrimitive(snapshotSha), "runtimeConfigurationSha256" to JsonPrimitive(configuration.configurationSha256)))
            val intentSha = sha256(OracleJson.canonicalBytes(intent))
            deadline.requireCurrent()
            val temporary = Files.createTempDirectory(canonicalProject, ".module-compilation-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val requestPath = temporary.resolve("request.json")
            var launched = false
            var absenceProved = true
            var lease: FullTreeDiskScratchLease? = null
            var runRoot: FullTreeDiskScratchRunRoot? = null
            var released = false
            var rootRemoved = false
            var releaseAttempted = false
            var primaryFailure: Throwable? = null
            try {
                val acquired = FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(configuration.scratchMount,
                    FullTreeDiskScratchOperation(nonce, intentSha, "module-compile", configuration.configurationSha256), configuration.scratchPolicy)
                lease = acquired
                val diskBytes = acquired.evidence.canonicalBytes()
                val rootToken = acquired.createEmptyOperationRunRoot()
                runRoot = rootToken
                var stateIdentity: decompengine.acp.LinuxFileIdentity? = null
                val request = acquired.withCurrentOperationRunRootBeforeLaunch(rootToken) { borrowed ->
                    borrowed.withPinnedDescriptor { directory ->
                        for (name in listOf("state", "reports", "tmp")) LinuxFilesystemSyscalls.createDirectory(directory.fd, name, 448)
                        LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, "state").use { state ->
                            LinuxFilesystemSyscalls.createDirectory(state.fd, "snapshot", 448)
                            LinuxFilesystemSyscalls.openDirectoryAt(state.fd, "snapshot").use { snapshot.populate(it) { deadline.requireCurrent() } }
                            LinuxFilesystemSyscalls.synchronize(state)
                            stateIdentity = LinuxFilesystemSyscalls.identity(state.fd)
                        }
                        LinuxFilesystemSyscalls.synchronize(directory)
                    }
                    ContainedModuleCompilerRequest(nonce, profile.id, profile.sha256, borrowed.path.resolve("state/snapshot"),
                        sourcePath, snapshot.inputs, configuration.compilerExecutable, configuration.compilerSha256,
                        borrowed.path.resolve("reports"), minOf(profile.budgets.buildWallClockMillis, ContainedModuleCompilerRequest.MAXIMUM_WALL_MILLIS),
                        minOf(profile.budgets.buildMaximumOutputBytes, ContainedModuleCompilerRequest.MAXIMUM_OUTPUT_BYTES),
                        profileRecord = OracleJson.parse(profile.canonicalJson().toByteArray()) as JsonObject)
                }
                require(request.snapshotSha256 == snapshotSha)
                LinuxFilesystemSyscalls.openRoot(temporary).use { directory ->
                    LinuxFilesystemSyscalls.createRegularFile(directory.fd, "request.json", 384).use { file ->
                        LinuxFilesystemSyscalls.write(file, request.canonicalBytes) { checkCancellation(); deadline.requireCurrent() }
                        LinuxFilesystemSyscalls.chmod(file, 256)
                        LinuxFilesystemSyscalls.synchronize(file)
                    }
                    LinuxFilesystemSyscalls.synchronize(directory)
                }
                val unit = "decomp-module-compile-${nonce.take(32)}.scope"
                var attachment: ByteArray? = null
                var commandRequest: ByteArray? = null
                var workerResult: ContainedModuleCompilerResult? = null
                val execution = acquired.withCurrentOperationRunRootForContainedExecution(rootToken) { borrowed ->
                    val compilerInput = configuration.verifyCompilerInput()
                    snapshot.requireCurrent { deadline.requireCurrent() }
                    deadline.requireCurrent()
                    checkCancellation()
                    launched = true
                    absenceProved = false
                    val result = try {
                        KotlinSystemdCgroupCommandLauncher.execute(borrowed, configuration.isolation, unit,
                            "${configuration.managerControlGroup.trimEnd('/')}/app.slice/$unit", nonce,
                            containedModuleCompilerCommand(configuration.isolation, requestPath, request),
                            mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"),
                            listOf(KotlinSystemdCgroupCommandInput(requestPath, request.canonicalBytes.size.toLong(), request.sha256), compilerInput),
                            configuration.compilerRuntimeMounts,
                            KotlinSystemdCgroupCommandResources(deadline.remainingWholeSecondsMillis(60_000), 512L * 1024 * 1024,
                                128, ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES), configuration.configurationSha256,
                            beforeStart = { receipt ->
                                acquired.requireCurrentOperationRunRootAfterScopeAttachment(rootToken)
                                snapshot.requireCurrent { deadline.requireCurrent() }
                                configuration.verifyCompilerInput()
                                checkCancellation()
                                deadline.requireCurrent()
                                attachment = receipt.canonicalBytes
                            }, controlDirectoryName = moduleCompileControl(request.nonce),
                            readOnlyStateDirectory = checkNotNull(stateIdentity), operationDeadline = deadline,
                            requireTerminalResourceEventProof = true)
                    } catch (failure: KotlinSystemdCgroupCommandExecutionException) {
                        // Polling sleeps clear interruption before the launcher wraps it. Keep that
                        // cancellation visible while allowing owned cleanup to run without a set flag.
                        var interrupted = Thread.interrupted()
                        try {
                            failure.cleanup.closeAndProveAbsent()
                        } catch (cleanupFailure: Throwable) {
                            interrupted = Thread.interrupted() || interrupted ||
                                moduleCompilationFailurePreservingCancellation(cleanupFailure) is InterruptedException
                            if (cleanupFailure !== failure) failure.addSuppressed(cleanupFailure)
                        } finally {
                            absenceProved = failure.cleanup.absenceProved
                        }
                        throw moduleCompilationFailurePreservingCancellation(failure, interrupted)
                    }
                    absenceProved = true
                    acquired.requireCurrentOperationRunRootAfterCgroupAbsence(rootToken)
                    ContainedCommandTerminalResourceEvidence.verifyExecution(result.canonicalBytes, checkNotNull(attachment))
                    snapshot.requireCurrent { deadline.requireCurrent() }
                    borrowed.withPinnedDescriptor { directory ->
                        val controlIdentity = checkNotNull(result.controlDirectoryIdentity)
                        LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, moduleCompileControl(request.nonce)).use { control ->
                            require(control.identity == controlIdentity) { "module compiler control identity changed" }
                            commandRequest = readOwnedFile(control, "runtime/contained-command-request.json", 256 * 1024)
                            val output = readOwnedFile(control, "reports/${KotlinContainedCommandProtocol.STDOUT_FILE}",
                                ContainedModuleCompilerResult.MAXIMUM_RESULT_BYTES)
                            val stderr = readOwnedFile(control, "reports/${KotlinContainedCommandProtocol.STDERR_FILE}", 64 * 1024)
                            require(stderr.isEmpty()) { "module compiler worker produced unexpected stderr" }
                            workerResult = ContainedModuleCompilerResult.parse(output).also { it.requireBinding(request) }
                        }
                        val worker = checkNotNull(workerResult)
                        val stdout = readOwnedFile(directory, "reports/${ContainedModuleCompilerRequest.STDOUT_FILE}", request.maximumOutputBytes.toInt())
                        val stderr = readOwnedFile(directory, "reports/${ContainedModuleCompilerRequest.STDERR_FILE}", request.maximumOutputBytes.toInt())
                        require(stdout.size.toLong() == worker.stdoutBytes && sha256(stdout) == worker.stdoutSha256 &&
                            stderr.size.toLong() == worker.stderrBytes && sha256(stderr) == worker.stderrSha256) {
                            "module compiler diagnostic capture differs from its result"
                        }
                        worker.objectSha256?.let { expected ->
                            val objectBytes = readOwnedFile(directory, "reports/${ContainedModuleCompilerRequest.OBJECT_FILE}",
                                ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES.toInt())
                            require(objectBytes.size.toLong() == worker.objectBytes && sha256(objectBytes) == expected) {
                                "module compiler object capture differs from its result"
                            }
                        }
                    }
                    deadline.requireCurrent()
                    result
                }
                acquired.removeOperationRunRootAfterCgroupAbsence(rootToken, configuration.scratchPolicy.maximumFilesystemInodes.toInt(),
                    configuration.scratchPolicy.maximumFilesystemBytes)
                rootRemoved = true
                releaseAttempted = true
                acquired.requireCleanAndRelease()
                released = true
                Files.delete(requestPath)
                Files.delete(temporary)
                val worker = checkNotNull(workerResult)
                val proof = JsonObject(mapOf(
                    "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("contained-module-compilation-v1"),
                    "scope" to JsonPrimitive("module-object"), "policyId" to JsonPrimitive(ContainedModuleCompilationPolicy.POLICY_ID),
                    "profileId" to JsonPrimitive(profile.id), "profileSha256" to JsonPrimitive(profile.sha256),
                    "sourceSha256" to JsonPrimitive(request.sourceSha256), "snapshotSha256" to JsonPrimitive(request.snapshotSha256),
                    "runtimeConfigurationSha256" to JsonPrimitive(configuration.configurationSha256),
                    "runtimeConfiguration" to configuration.configurationRecord, "intent" to intent,
                    "request" to OracleJson.parseCanonical(request.canonicalBytes), "result" to OracleJson.parseCanonical(worker.canonicalBytes),
                    "commandRequest" to OracleJson.parseCanonical(checkNotNull(commandRequest)),
                    "attachment" to OracleJson.parseCanonical(checkNotNull(attachment)), "execution" to OracleJson.parseCanonical(execution.canonicalBytes),
                    "diskLease" to OracleJson.parseCanonical(diskBytes), "cleanup" to JsonObject(listOf("processesAbsent", "unitAbsent", "cgroupAbsent",
                        "scratchRemoved", "leaseReleased").associateWith { JsonPrimitive(true) })))
                val evidence = ModuleCompilationEvidence(request.sourceSha256, ContainedModuleCompilationPolicy.command(profile, sourcePath),
                    if (worker.outcome == "compiled-object") "passed" else "failed", worker.exitCode,
                    ContainedModuleCompilationProof.diagnosticsSha256(worker), worker.stdoutBytes + worker.stderrBytes, proof,
                    if (worker.outcome == "compiled-object") VerifiedContainedModuleCompilation(sha256(OracleJson.canonicalBytes(proof)), snapshot) else null)
                ContainedModuleCompilationProof.verify(evidence)
                snapshot.requireCurrent { deadline.requireCurrent() }
                deadline.requireCurrent()
                checkCancellation()
                evidence.liveAuthority?.let { token ->
                    ModuleCompilerLiveAdmissions.register(token, sha256(OracleJson.canonicalBytes(proof)))
                }
                return evidence
            } catch (failure: Throwable) {
                val propagated = moduleCompilationFailurePreservingCancellation(failure, Thread.interrupted())
                primaryFailure = propagated
                throw propagated
            } finally {
                val failedBeforeCleanup = primaryFailure != null
                fun cleanup(action: () -> Unit) {
                    try { action() } catch (failure: Throwable) {
                        val original = primaryFailure
                        if (original == null) primaryFailure = failure
                        else if (original !== failure) original.addSuppressed(failure)
                    }
                }
                if (!released && lease != null) {
                    // Failed cleanup preserves finite lease residue. A consumed token or a release
                    // attempt is never retried, and cleanup errors cannot replace the original fault.
                    if (absenceProved && runRoot != null && !rootRemoved && !releaseAttempted) cleanup {
                        lease.removeOperationRunRootAfterCgroupAbsence(runRoot, configuration.scratchPolicy.maximumFilesystemInodes.toInt(),
                            configuration.scratchPolicy.maximumFilesystemBytes)
                        rootRemoved = true
                    }
                    if (rootRemoved && !releaseAttempted) cleanup {
                        releaseAttempted = true
                        lease.requireCleanAndRelease()
                    }
                    cleanup { lease.close() }
                }
                if (!launched || absenceProved) {
                    cleanup { Files.deleteIfExists(requestPath) }
                    cleanup { Files.deleteIfExists(temporary) }
                }
                if (!failedBeforeCleanup) primaryFailure?.let { throw it }

            }
        }
    }
}

/** Exception classification only; this helper grants no execution or cleanup authority. */
internal fun moduleCompilationFailurePreservingCancellation(failure: Throwable, interrupted: Boolean = false): Throwable {
    val seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Throwable, Boolean>())
    var cause: Throwable? = failure
    var containsInterruption = interrupted
    while (cause != null && seen.add(cause)) {
        if (cause is InterruptedException) containsInterruption = true
        cause = cause.cause
    }
    return if (containsInterruption && failure !is InterruptedException) {
        InterruptedException("contained module compilation cancelled").also { it.initCause(failure) }
    } else failure
}

internal fun moduleCompileControl(nonce: String): String = "control-$nonce"
internal fun containedModuleCompilerCommand(configuration: FullTreeFunctionObservationIsolationConfiguration,
    requestPath: Path, request: ContainedModuleCompilerRequest): List<String> {
    val control = request.outputDirectory.parent.resolve(moduleCompileControl(request.nonce))
    return listOf(configuration.javaExecutable.toString(), "-Xms16m", "-Xmx128m", "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1",
        "-XX:-UsePerfData", "-XX:+DisableAttachMechanism", "-XX:MaxMetaspaceSize=96m", "-XX:ReservedCodeCacheSize=32m") +
        isolatedObservationJvmTemporaryArguments(control, configuration.javaRuntime.destination.resolve(OracleNativeLibraries.relativeDirectory)) +
        listOf("-Duser.home=${control.resolve("tmp")}", "-classpath", configuration.workerClassPath.indices.joinToString(java.io.File.pathSeparator) {
            control.resolve("runtime/classpath-$it.jar").toString()
        }, ContainedModuleCompilerWorker::class.java.name, requestPath.toString(), request.sha256)
}

internal fun moduleCompilationSnapshotDigest(inputs: List<ContainedModuleCompilerInput>): String = sha256(OracleJson.canonicalBytes(
    JsonObject(mapOf("provider" to JsonPrimitive("module-compiler-snapshot-v1"),
        "files" to kotlinx.serialization.json.JsonArray(inputs.sortedBy { it.path }.map { it.json() })))))

private fun readOwnedFile(root: LinuxDescriptor, relative: String, limit: Int): ByteArray {
    val parts = relative.split('/')
    if (parts.size > 1) return LinuxFilesystemSyscalls.openDirectoryAt(root.fd, parts.first()).use { child ->
        require(child.identity.uid == root.identity.uid && child.identity.mountId == root.identity.mountId)
        readOwnedFile(child, parts.drop(1).joinToString("/"), limit)
    }
    val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(root.fd, parts.single())
        ?: error("module compilation result is absent: $relative")
    return selected.use { file ->
        val identity = file.identity
        require(identity.isRegularFile && !identity.isSymbolicLink && identity.linkCount == 1 &&
            identity.uid == root.identity.uid && identity.mountId == root.identity.mountId) { "module compilation output is not owned" }
        LinuxFilesystemSyscalls.openReadableFrom(file).use { readable ->
            LinuxFilesystemSyscalls.read(readable, limit) { checkCancellation() }.also {
                require(LinuxFilesystemSyscalls.identity(file.fd) == identity) { "module compilation output identity changed" }
            }
        }
    }
}
private fun checkCancellation() {
    if (Thread.currentThread().isInterrupted) throw InterruptedException("contained module compilation cancelled")
}

/** Constructor bridges and replayed bytes cannot populate this application-owned identity set. */
private object ModuleCompilerLiveAdmissions {
    private val issued = java.util.WeakHashMap<VerifiedContainedModuleCompilation, String>()
    @Synchronized fun register(token: VerifiedContainedModuleCompilation, proofSha256: String) {
        check(!issued.containsKey(token)) { "module compiler authority was already issued" }
        issued[token] = proofSha256
    }
    @Synchronized fun contains(token: VerifiedContainedModuleCompilation, proofSha256: String): Boolean =
        issued[token] == proofSha256
}
