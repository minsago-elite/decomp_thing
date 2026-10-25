package decompengine.oracle.reference

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.ContainedCommandOperationDeadline
import decompengine.oracle.fulltree.FullTreeDiskScratchAuthority
import decompengine.oracle.fulltree.FullTreeDiskScratchBorrowedRunRoot
import decompengine.oracle.fulltree.FullTreeDiskScratchLease
import decompengine.oracle.fulltree.FullTreeDiskScratchOperation
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import decompengine.oracle.fulltree.FullTreeFunctionObservationIsolationConfiguration
import decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeMount
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandExecutionException
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandInput
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandLauncher
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandResources
import decompengine.oracle.fulltree.OracleNativeLibraries
import decompengine.oracle.fulltree.isolatedObservationJvmTemporaryArguments
import java.nio.file.Files
import java.nio.file.Path
import java.security.SecureRandom
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Reference-only execution owner. Authentication requires the registered profile and admitted
 * native runtime; no caller-selected program, expected result, command, or execution callback is
 * accepted. Every batch uses the existing retained BOOT/START/cgroup-absence lifecycle.
 */
internal object ReferenceCorpusCoordinator {
    private const val WALL_MILLIS = 600_000L
    private const val RESIDENT_BYTES = 1024L * 1024 * 1024
    private val DISK_POLICY = FullTreeDiskScratchPolicy(128L * 1024 * 1024, 512L * 1024 * 1024, 4096, 32768)

    fun capture(
        profile: AuthenticatedReferenceCorpusProfile,
        nativeRuntime: AdmittedReferenceNativeRuntime,
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        journalRoot: Path,
        provisionedScratch: Path,
        expectedCgroupParent: String,
    ): Path {
        requireRoot(journalRoot)
        requireRoot(provisionedScratch)
        require(!overlap(journalRoot, provisionedScratch)) { "reference journal and scratch must be disjoint" }
        val cgroupParent = canonicalControlGroupParent(expectedCgroupParent)
        profile.requireCurrent("before reference operation")
        nativeRuntime.requireCurrent("before reference operation")
        val batches = profile.definition.batches.keys.toList()
        val configurations = batches.associateWith { batch ->
            withNativeRuntime(configuration, nativeRuntime.mounts(batch))
        }
        val operationId = randomDigest()
        val intent = OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("reference-corpus-intent-v1"), "schemaVersion" to JsonPrimitive(1),
            "operationId" to JsonPrimitive(operationId), "profileSha256" to JsonPrimitive(profile.profileSha256),
            "registrationId" to JsonPrimitive(profile.registrationId),
            "nativeRuntimeSha256" to JsonPrimitive(nativeRuntime.identitySha256),
            "configurationSha256ByBatch" to JsonObject(configurations.mapValues { JsonPrimitive(it.value.canonicalSha256) }),
            "journalRoot" to JsonPrimitive(journalRoot.toString()), "scratchMount" to JsonPrimitive(provisionedScratch.toString()),
            "expectedCgroupParent" to JsonPrimitive(cgroupParent),
            "wallClockMillis" to JsonPrimitive(WALL_MILLIS), "maximumResidentBytes" to JsonPrimitive(RESIDENT_BYTES),
            "pidsMax" to JsonPrimitive(64), "maximumFilesystemBytes" to JsonPrimitive(DISK_POLICY.maximumFilesystemBytes),
            "maximumFilesystemInodes" to JsonPrimitive(DISK_POLICY.maximumFilesystemInodes),
            "maximumAggregateOutputBytes" to JsonPrimitive(profile.definition.limits.maximumAggregateOutputBytes),
            "batches" to JsonArray(batches.map(::JsonPrimitive)),
            "candidateQualified" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        )))
        val intentSha = OracleArtifacts.sha256(intent)
        val deadline = ContainedCommandOperationDeadline(WALL_MILLIS)
        val journal = ReferenceCorpusOperationJournal.create(journalRoot, operationId, intent, batches)
        var lease: FullTreeDiskScratchLease? = null
        var retainedFailure: KotlinSystemdCgroupCommandExecutionException? = null
        try {
            val openedLease = FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(provisionedScratch,
                FullTreeDiskScratchOperation(operationId, intentSha, "reference-corpus", profile.profileSha256), DISK_POLICY)
            lease = openedLease
            journal.recordLease(openedLease.evidence)
            val runRoot = openedLease.createEmptyOperationRunRoot()
            val rootDirectories = openedLease.withCurrentOperationRunRootBeforeLaunch(runRoot, ::prepareRoot)
            val completedControls = linkedMapOf<String, LinuxFileIdentity>()
            val observed = linkedMapOf<String, JsonObject>()
            val executionHashes = linkedMapOf<String, String>()
            val reportHashes = linkedMapOf<String, String>()
            var capturedOutputBytes = 0L
            for (batch in batches) {
                deadline.requireCurrent()
                profile.requireCurrent("before reference batch $batch")
                nativeRuntime.requireCurrent("before reference batch $batch")
                journal.verify("before reference batch $batch")
                val selected = configurations.getValue(batch)
                openedLease.withCurrentOperationRunRootForContainedExecution(runRoot) { borrowed ->
                    val controlName = "control-${OracleArtifacts.sha256("$operationId:$batch".toByteArray())}"
                    val control = borrowed.path.resolve(controlName)
                    val request = ReferenceCorpusWorkerRequest(profile.profilePath, profile.canonicalBytes.size,
                        profile.profileSha256, batch, control, intentSha)
                    val requestPath = journal.prepareBatch(batch, request.canonicalBytes, selected.canonicalSha256)
                    val unitName = "decomp-reference-${randomDigest().take(32)}.scope"
                    val execution = KotlinSystemdCgroupCommandLauncher.execute(
                        borrowed = borrowed, configuration = selected, unitName = unitName,
                        expectedControlGroup = "$cgroupParent/$unitName", nonce = randomDigest(),
                        command = workerCommand(selected, request, requestPath),
                        environment = mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"),
                        readOnlyInputs = listOf(
                            KotlinSystemdCgroupCommandInput(profile.profilePath, profile.canonicalBytes.size.toLong(), profile.profileSha256),
                            KotlinSystemdCgroupCommandInput(requestPath, request.canonicalBytes.size.toLong(), OracleArtifacts.sha256(request.canonicalBytes))),
                        runtimeMounts = nativeRuntime.mounts(batch),
                        resources = KotlinSystemdCgroupCommandResources(deadline.remainingWholeSecondsMillis(WALL_MILLIS),
                            RESIDENT_BYTES, 64, 64L * 1024 * 1024),
                        deploymentClosureSha256 = deploymentDigest(profile, nativeRuntime, selected),
                        controlDirectoryName = controlName, readOnlyControlDirectories = completedControls,
                        readOnlyStateDirectory = rootDirectories.getValue("state"),
                        readOnlyReportsDirectory = rootDirectories.getValue("reports"), operationDeadline = deadline,
                        beforeStart = { attachment ->
                            profile.requireCurrent("before reference START")
                            nativeRuntime.requireCurrent("before reference START")
                            openedLease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                            journal.recordAttachment(batch, attachment.canonicalBytes)
                            journal.authorizeStart(batch)
                            profile.requireCurrent("after durable reference START")
                            nativeRuntime.requireCurrent("after durable reference START")
                            journal.verify("before reference START delivery")
                            openedLease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                        },
                    )
                    openedLease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                    profile.requireCurrent("after reference cgroup absence")
                    nativeRuntime.requireCurrent("after reference cgroup absence")
                    val identity = checkNotNull(execution.controlDirectoryIdentity)
                    completedControls[controlName] = identity
                    journal.recordExecution(batch, execution.canonicalBytes)
                    val report = readReport(borrowed, controlName, identity)
                    val verified = ReferenceCorpusWorkerObservations.verify(profile.definition, request, report)
                    capturedOutputBytes = Math.addExact(capturedOutputBytes, verified.capturedOutputBytes)
                    require(capturedOutputBytes <= profile.definition.limits.maximumAggregateOutputBytes) {
                        "reference operation output exceeds its aggregate profile budget"
                    }
                    journal.recordObservations(batch, verified.canonicalReportBytes)
                    verified.cases.forEach { case ->
                        require(observed.put(case.getValue("id").jsonPrimitive.content, case) == null)
                    }
                    reportHashes[batch] = OracleArtifacts.sha256(verified.canonicalReportBytes)
                    executionHashes[batch] = OracleArtifacts.sha256(execution.canonicalBytes)
                    deadline.requireCurrent()
                }
            }
            require(observed.keys == profile.definition.cases.map { it.id }.toSet())
            val cases = JsonArray(profile.definition.cases.map { observed.getValue(it.id) })
            val reference = OracleJson.canonicalBytes(JsonObject(mapOf(
                "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("authenticated-reference-corpus-v1"),
                "registrationId" to JsonPrimitive(profile.registrationId), "profileSha256" to JsonPrimitive(profile.profileSha256),
                "nativeRuntimeSha256" to JsonPrimitive(nativeRuntime.identitySha256), "operationId" to JsonPrimitive(operationId),
                "intentSha256" to JsonPrimitive(intentSha), "casesSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(cases, REFERENCE_LIMITS))),
                "cases" to cases, "executionSha256ByBatch" to JsonObject(executionHashes.mapValues { JsonPrimitive(it.value) }),
                "capturedOutputBytes" to JsonPrimitive(capturedOutputBytes),
                "workerObservationsSha256ByBatch" to JsonObject(reportHashes.mapValues { JsonPrimitive(it.value) }),
                "executionAuthenticated" to JsonPrimitive(true), "referenceAuthority" to JsonPrimitive(true),
                "candidateQualified" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                "scratchDisposition" to JsonPrimitive("retained-for-trusted-reset"), "operationWallTime" to deadline.snapshot(),
            )), REFERENCE_LIMITS)
            openedLease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            profile.requireCurrent("before completed reference publication")
            nativeRuntime.requireCurrent("before completed reference publication")
            deadline.requireCurrent()
            return journal.complete(reference)
        } catch (failure: Throwable) {
            if (failure is KotlinSystemdCgroupCommandExecutionException && !failure.cleanup.absenceProved) {
                retainedFailure = failure
                throw ReferenceCorpusRetainedFailure(failure, checkNotNull(lease), journal)
            }
            throw failure
        } finally {
            if (retainedFailure == null) {
                try { lease?.abandonForRecovery() } finally { journal.close() }
            }
        }
    }

    internal fun workerCommand(configuration: FullTreeFunctionObservationIsolationConfiguration,
        request: ReferenceCorpusWorkerRequest, requestPath: Path): List<String> = buildList {
        add(configuration.javaExecutable.toString())
        addAll(listOf("-Xms32m", "-Xmx256m", "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1", "-XX:-UsePerfData", "-XX:+DisableAttachMechanism"))
        addAll(isolatedObservationJvmTemporaryArguments(request.controlRoot,
            configuration.javaRuntime.source.resolve(OracleNativeLibraries.relativeDirectory)))
        add("-Duser.home=${request.controlRoot.resolve("tmp")}")
        add("-classpath")
        // The admitted launcher privately snapshots these exact configured jars before BOOT.
        add(configuration.workerClassPath.indices.joinToString(":") { request.controlRoot.resolve("runtime/classpath-$it.jar").toString() })
        add(ReferenceCorpusWorker::class.java.name)
        add(requestPath.toString())
        add(OracleArtifacts.sha256(request.canonicalBytes))
    }

    internal fun canonicalControlGroupParent(value: String): String {
        val path = Path.of(value)
        require(value.startsWith('/') && !value.endsWith('/') && path.normalize() == path && path.toString() == value &&
            path.nameCount in 1..32 && path.all { it.toString().matches(Regex("[A-Za-z0-9_.:@-]{1,128}")) }) {
            "reference cgroup parent is not an exact canonical path"
        }
        return value
    }
}

/** Retains the lease/journal until the same launcher can prove whole-cgroup absence. */
internal class ReferenceCorpusRetainedFailure internal constructor(
    cause: KotlinSystemdCgroupCommandExecutionException,
    private val lease: FullTreeDiskScratchLease,
    private val journal: ReferenceCorpusOperationJournal,
) : IllegalStateException("reference launch failed; retained ownership requires explicit absence cleanup", cause), AutoCloseable {
    private val cleanup = cause.cleanup
    private var closed = false
    @Synchronized override fun close() {
        if (closed) return
        cleanup.closeAndProveAbsent()
        check(cleanup.absenceProved)
        try { lease.abandonForRecovery() } finally { journal.close() }
        closed = true
    }
}

private fun prepareRoot(borrowed: FullTreeDiskScratchBorrowedRunRoot): Map<String, LinuxFileIdentity> =
    borrowed.withPinnedDescriptor { root ->
        require(LinuxFilesystemSyscalls.directoryEntryNames(root, 1).isEmpty())
        listOf("state", "reports", "tmp").associateWith { name ->
            LinuxFilesystemSyscalls.createDirectory(root.fd, name, 448)
            LinuxFilesystemSyscalls.openDirectoryAt(root.fd, name).use { child ->
                LinuxFilesystemSyscalls.chmod(child, 448)
                LinuxFilesystemSyscalls.identity(child.fd).also {
                    require(it.isDirectory && !it.isSymbolicLink && it.mode.permissions == 448 &&
                        it.uid == root.identity.uid && it.mountId == root.identity.mountId)
                    LinuxFilesystemSyscalls.synchronize(child)
                }
            }
        }.also { LinuxFilesystemSyscalls.synchronize(root) }
    }

private fun readReport(borrowed: FullTreeDiskScratchBorrowedRunRoot, control: String, expected: LinuxFileIdentity): ByteArray =
    borrowed.withPinnedDescriptor { root ->
        LinuxFilesystemSyscalls.openDirectoryAt(root.fd, control).use { selected ->
            require(LinuxFilesystemSyscalls.identity(selected.fd) == expected)
            LinuxFilesystemSyscalls.openDirectoryAt(selected.fd, "reports").use { reports ->
                require(reports.identity.isDirectory && reports.identity.mode.permissions == 448 &&
                    reports.identity.uid == root.identity.uid && reports.identity.mountId == root.identity.mountId)
                require(LinuxFilesystemSyscalls.directoryEntryNames(reports, 2) == listOf(ReferenceCorpusWorker.OBSERVATIONS_FILE))
                checkNotNull(DescriptorBoundAtomicStateFile.readManifestOrNull(reports, ReferenceCorpusWorker.OBSERVATIONS_FILE,
                    ReferenceCorpusWorker.MAXIMUM_OBSERVATION_BYTES)).bytes
            }
        }
    }

private fun withNativeRuntime(base: FullTreeFunctionObservationIsolationConfiguration,
    mounts: List<FullTreeFunctionObservationRuntimeMount>) = FullTreeFunctionObservationIsolationConfiguration(
    base.javaExecutable, base.javaRuntime, mounts, base.bubblewrapExecutable, base.resourceLimiterExecutable,
    base.scopeSupervisorExecutable, base.scopeInspectorExecutable, base.systemdBusControllerExecutable,
    base.systemdUserRuntimeDirectory, base.workerClassPath, base.expectedJavaSha256, base.expectedBubblewrapSha256,
    base.expectedResourceLimiterSha256, base.expectedScopeSupervisorSha256, base.expectedScopeInspectorSha256,
    base.expectedSystemdBusControllerSha256,
)

private fun deploymentDigest(profile: AuthenticatedReferenceCorpusProfile, runtime: AdmittedReferenceNativeRuntime,
    configuration: FullTreeFunctionObservationIsolationConfiguration): String = OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(mapOf(
    "provider" to JsonPrimitive("reference-corpus-deployment-v1"), "profileSha256" to JsonPrimitive(profile.profileSha256),
    "nativeRuntimeSha256" to JsonPrimitive(runtime.identitySha256), "configurationSha256" to JsonPrimitive(configuration.canonicalSha256),
    "workerEntryPoint" to JsonPrimitive(ReferenceCorpusWorker::class.java.name),
))))

private fun randomDigest(): String = ByteArray(32).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it.toInt() and 255) }
private fun requireRoot(path: Path) { require(path.isAbsolute && path.normalize() == path && Files.isDirectory(path) && path.toRealPath() == path) }
private fun overlap(first: Path, second: Path) = first.startsWith(second) || second.startsWith(first)
private val REFERENCE_LIMITS = StrictJsonLimits(maximumInputBytes = 16 * 1024 * 1024, maximumCanonicalBytes = 16 * 1024 * 1024,
    maximumNodes = 500_000, maximumStringBytes = 16 * 1024 * 1024, maximumTotalStringBytes = 16 * 1024 * 1024)
