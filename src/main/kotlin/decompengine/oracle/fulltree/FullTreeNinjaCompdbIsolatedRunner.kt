package decompengine.oracle.fulltree

import decompengine.acp.AcpLinuxSandboxConfiguration
import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.AcpSandboxEvidence
import decompengine.acp.AcpSandboxLaunch
import decompengine.acp.AcpSandboxLaunchEvidence
import decompengine.acp.AcpSandboxLaunchPurpose
import decompengine.acp.AcpSandboxReadOnlyMount
import decompengine.acp.AcpSandboxResourceLimits
import decompengine.acp.AcpSandboxStdinDisposition
import decompengine.acp.LinuxBubblewrapBoundary
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.acpSandboxCanonicalStringDigest
import decompengine.acp.acpSandboxCleanupTimeoutMicros
import decompengine.acp.acpSandboxEmptyStagingRootsDigest
import decompengine.acp.acpSandboxEnvironmentFileMode
import decompengine.acp.acpSandboxEnvironmentPathSha256
import decompengine.acp.acpSandboxGateHelperPathSha256
import decompengine.acp.acpSandboxGateProtocolSha256
import decompengine.acp.calculateAcpRuntimeManifestSha256
import decompengine.acp.deletePrivateTreeContents
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.time.Duration
import java.util.Collections
import java.util.LinkedHashMap
import java.util.TreeMap
import java.util.TreeSet
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** One exact regular-file member of the operator-provisioned Ninja ELF runtime profile. */
internal class FullTreeNinjaCompdbRuntimeFile(
    val source: Path,
    val destination: Path,
    val expectedBytes: Long,
    val expectedSha256: String,
    val expectedRuntimeManifestSha256: String,
) {
    init {
        requireNinjaRunnerAbsolutePath(source, "Ninja runtime source")
        requireNinjaRunnerAbsolutePath(destination, "Ninja runtime destination")
        require(expectedBytes in 1L..NINJA_RUN_MAXIMUM_RUNTIME_FILE_BYTES)
        requireNinjaRunnerSha256(expectedSha256, "Ninja runtime file")
        requireNinjaRunnerSha256(expectedRuntimeManifestSha256, "Ninja runtime manifest")
    }

    internal fun mount(): AcpSandboxReadOnlyMount = AcpSandboxReadOnlyMount(
        source,
        destination,
        expectedRuntimeManifestSha256,
    )
}

/**
 * Trusted operator provisioning. Run requests cannot supply argv, environment, mounts, staging
 * roots, callbacks, or a process seam; all of those are fixed by the Kotlin runner and prestart.
 */
class FullTreeNinjaCompdbIsolationDeployment private constructor(
    @get:JvmSynthetic
    internal val sandbox: AcpLinuxSandboxConfiguration,
    @get:JvmSynthetic
    internal val ninjaExecutableSource: Path,
    @get:JvmSynthetic
    internal val expectedNinjaRuntimeManifestSha256: String,
    runtimeFiles: Collection<FullTreeNinjaCompdbRuntimeFile>,
    @get:JvmSynthetic
    internal val scratchParent: Path,
) {
    @get:JvmSynthetic
    internal val runtimeFiles: List<FullTreeNinjaCompdbRuntimeFile> = Collections.unmodifiableList(
        ArrayList(runtimeFiles),
    )

    @get:JvmSynthetic
    internal val configurationSha256: String

    init {
        requireNinjaRunnerAbsolutePath(ninjaExecutableSource, "Ninja executable source")
        requireNinjaRunnerSha256(expectedNinjaRuntimeManifestSha256, "Ninja executable runtime manifest")
        requireNinjaRunnerAbsolutePath(scratchParent, "Ninja materialization scratch parent")
        require(this.runtimeFiles.size <= NINJA_RUN_MAXIMUM_RUNTIME_FILES)
        var aggregateRuntimeBytes = 0L
        require(sandbox.launcherRuntimeMounts.isEmpty()) {
            "Ninja compdb isolation cannot inherit launcher runtime mounts"
        }
        require(sandbox.agentRuntimeMounts.isEmpty()) {
            "Ninja compdb isolation cannot inherit outer-agent runtime mounts"
        }
        val destinations = HashSet<Path>()
        val sources = HashSet<Path>()
        this.runtimeFiles.forEach { runtime ->
            aggregateRuntimeBytes = Math.addExact(aggregateRuntimeBytes, runtime.expectedBytes)
            require(aggregateRuntimeBytes <= NINJA_RUN_MAXIMUM_RUNTIME_PROFILE_BYTES) {
                "Ninja runtime-file profile exceeds its aggregate byte bound"
            }
            require(destinations.add(runtime.destination)) { "Ninja runtime destinations must be unique" }
            require(sources.add(runtime.source)) { "Ninja runtime sources must be unique" }
            require(runtime.source != ninjaExecutableSource) {
                "Ninja executable must not be repeated in its runtime-file profile"
            }
        }
        val configured = sandbox.ninjaCompdbRuntimeMounts.sortedBy { it.destination.toString() }
        val expected = this.runtimeFiles.map { it.mount() }.sortedBy { it.destination.toString() }
        require(configured.size == expected.size && configured.zip(expected).all { (left, right) ->
            left.source == right.source && left.destination == right.destination &&
                left.expectedManifestSha256 == right.expectedManifestSha256
        }) { "sandbox Ninja runtime mounts differ from the authenticated deployment profile" }
        require(sandbox.runtimeClosureLimits.maximumEntries <= NINJA_RUN_MAXIMUM_RUNTIME_ENTRIES)
        require(
            sandbox.runtimeClosureLimits.maximumUserOwnedFileBytes <=
                NINJA_RUN_MAXIMUM_RUNTIME_PROFILE_BYTES,
        )
        require(sandbox.runtimeClosureLimits.maximumDepth <= NINJA_RUN_MAXIMUM_RUNTIME_DEPTH)
        configurationSha256 = ninjaRunnerDeploymentSha256(this)
    }

    internal companion object {
        /** Trusted-host provisioning; this is intentionally not a public run-request factory. */
        @JvmSynthetic
        fun provision(
            sandbox: AcpLinuxSandboxConfiguration,
            ninjaExecutableSource: Path,
            expectedNinjaRuntimeManifestSha256: String,
            runtimeFiles: Collection<FullTreeNinjaCompdbRuntimeFile>,
            scratchParent: Path,
        ): FullTreeNinjaCompdbIsolationDeployment = FullTreeNinjaCompdbIsolationDeployment(
            sandbox,
            ninjaExecutableSource,
            expectedNinjaRuntimeManifestSha256,
            runtimeFiles,
            scratchParent,
        )
    }
}

/** Caller-lowerable ceilings beneath the immutable isolated-query v1 policy. */
data class FullTreeNinjaCompdbExecutionLimits(
    val prestart: FullTreeNinjaCompdbPrestartLimits = FullTreeNinjaCompdbPrestartLimits(),
    val maximumCanonicalBytes: Int = NINJA_RUN_MAXIMUM_CANONICAL_BYTES,
    val maximumWallMillis: Long = NINJA_RUN_MAXIMUM_WALL_MILLIS,
    val maximumStderrBytes: Int = NINJA_RUN_MAXIMUM_STDERR_BYTES,
    val cleanupMillis: Long = NINJA_RUN_MAXIMUM_CLEANUP_MILLIS,
    val resourceLimits: AcpSandboxResourceLimits = NINJA_RUN_RESOURCE_LIMITS,
) {
    init {
        require(maximumCanonicalBytes in 1..NINJA_RUN_MAXIMUM_CANONICAL_BYTES)
        require(maximumWallMillis in 1L..NINJA_RUN_MAXIMUM_WALL_MILLIS)
        require(maximumStderrBytes in 1..NINJA_RUN_MAXIMUM_STDERR_BYTES)
        require(cleanupMillis in 1L..NINJA_RUN_MAXIMUM_CLEANUP_MILLIS)
        require(resourceLimits.maximumProcesses <= NINJA_RUN_RESOURCE_LIMITS.maximumProcesses)
        require(resourceLimits.maximumOpenFiles <= NINJA_RUN_RESOURCE_LIMITS.maximumOpenFiles)
        require(resourceLimits.maximumFileBytes <= NINJA_RUN_RESOURCE_LIMITS.maximumFileBytes)
        require(
            resourceLimits.maximumAddressSpaceBytes <=
                NINJA_RUN_RESOURCE_LIMITS.maximumAddressSpaceBytes,
        )
        require(resourceLimits.maximumCpuSeconds <= NINJA_RUN_RESOURCE_LIMITS.maximumCpuSeconds)
    }
}

/** Same-process authenticated result; its persisted canonical bytes are explicitly non-bearer. */
sealed interface FullTreeNinjaCompdbExecutionRegistry {
    val artifactBytes: Long
    val artifactSha256: String
    val reportSha256: String
    val configurationSha256: String
    val prestartArtifactSha256: String
    val prestartContextSha256: String
    val executedNinjaSha256: String
    val containmentReceiptSha256: String
    val stdoutBytes: Long
    val stdoutSha256: String
    val stderrBytes: Long
    val stderrSha256: String
    val exitCode: Int
    val blockerCodes: List<String>
    val canonicalBytes: ByteArray
    val executionAuthenticated: Boolean
    val artifactBearerAuthority: Boolean
    val processAuthority: Boolean
    val releaseEligible: Boolean
}

/** Kotlin-owned, direct-exec, cgroup-contained Ninja `-t compdb` transaction. */
object FullTreeNinjaCompdbIsolatedRunner {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(NINJA_RUN_SCHEMA, NINJA_RUN_CONFIGURATION_POLICY)
    }

    @Suppress("LongParameterList")
    fun generateAndPublish(
        prestartPath: Path,
        manifestArchivePath: Path,
        reconciliationPath: Path,
        compdbPath: Path,
        captureInputPath: Path,
        headerPlanReadinessPath: Path,
        generatedFileInventoryPath: Path,
        sourceArchivePath: Path,
        generatedTreeArchivePath: Path,
        generatedProvenancePath: Path,
        scopePath: Path,
        sourceLockPath: Path,
        artifactManifestPath: Path,
        buildRecordPath: Path,
        inventoryPath: Path,
        sourceInventoryPath: Path,
        planningInventoryPath: Path,
        outputPath: Path,
        deployment: FullTreeNinjaCompdbIsolationDeployment,
        limits: FullTreeNinjaCompdbExecutionLimits = FullTreeNinjaCompdbExecutionLimits(),
    ): FullTreeNinjaCompdbExecutionRegistry {
        requireNinjaReceiptOutputPath(outputPath)
        val paths = NinjaPrestartPaths(
            prestartPath,
            manifestArchivePath,
            reconciliationPath,
            compdbPath,
            captureInputPath,
            headerPlanReadinessPath,
            generatedFileInventoryPath,
            sourceArchivePath,
            generatedTreeArchivePath,
            generatedProvenancePath,
            scopePath,
            sourceLockPath,
            artifactManifestPath,
            buildRecordPath,
            inventoryPath,
            sourceInventoryPath,
            planningInventoryPath,
        )
        requireNinjaDeploymentDisjointFromControls(paths, deployment)
        requireDistinctControlOutput(
            outputPath,
            *(paths.all().mapIndexed { index, path -> "Ninja execution predecessor $index" to path } +
                listOf("Ninja executable" to deployment.ninjaExecutableSource) +
                deployment.runtimeFiles.mapIndexed { index, runtime ->
                    "Ninja runtime file $index" to runtime.source
                }).toTypedArray(),
        )
        return executeNinjaCompdb(paths, outputPath, deployment, limits)
    }
}

private fun executeNinjaCompdb(
    paths: NinjaPrestartPaths,
    outputPath: Path,
    deployment: FullTreeNinjaCompdbIsolationDeployment,
    limits: FullTreeNinjaCompdbExecutionLimits,
): FullTreeNinjaCompdbExecutionRegistry = StableControlFile.open(
    paths.artifact,
    limits.prestart.maximumCanonicalBytes.toLong(),
    "full-tree Ninja compdb prestart retained execution input",
).use { prestartArtifact ->
    prestartArtifact.requireSingleLink("full-tree Ninja compdb prestart retained execution input")
    NinjaPrestartInputGuards.open(paths, limits.prestart).use { retainedInputs ->
        val prestart = loadPrestartForExecution(paths, limits)
        require(
            prestartArtifact.size == prestart.artifactBytes &&
                prestartArtifact.authenticatedSha256 == prestart.artifactSha256 &&
                prestartArtifact.readExactly(
                    0L,
                    prestartArtifact.size.toInt(),
                    "full-tree Ninja compdb prestart retained execution input",
                ).contentEquals(prestart.canonicalBytes),
        ) { "retained Ninja prestart differs from the validated prestart" }
        require(prestart.expectedStdoutBytes <= limits.prestart.maximumStdoutBytes.toLong()) {
            "expected Ninja stdout exceeds the effective execution bound"
        }
        requireSafeNinjaEnvironment(prestart.environment)
        StableControlFile.open(
            paths.compdb,
            limits.prestart.maximumStdoutBytes.toLong(),
            "retained expected Ninja stdout",
        ).use { expectedStdout ->
            expectedStdout.requireSingleLink("retained expected Ninja stdout")
            if (expectedStdout.size != prestart.expectedStdoutBytes ||
                expectedStdout.authenticatedSha256 != prestart.expectedStdoutSha256
            ) throw FullTreeControlException("retained expected Ninja stdout identity changed")
            val expectedBytes = expectedStdout.readExactly(
                0L,
                expectedStdout.size.toInt(),
                "retained expected Ninja stdout",
            )
            PinnedNinjaReceiptTarget.open(outputPath, limits.maximumCanonicalBytes).use { output ->
                output.requireAbsent()
                PinnedNinjaRuntimeProfile.open(deployment, prestart).use { runtime ->
                    val materialization = loadFullTreeNinjaManifestMaterialization(
                        paths.manifestArchive,
                        prestart.manifestRootBytes,
                        prestart.manifestRootSha256,
                        requireNotNull(prestart.environment["SOURCE_DATE_EPOCH"]?.toLongOrNull()) {
                            "validated Ninja prestart lacks a numeric SOURCE_DATE_EPOCH"
                        },
                        limits.prestart.manifestArchive,
                    )
                    requireMaterializationMatchesPrestart(materialization, prestart)
                    val tree = PrivateNinjaManifestTree.create(
                        deployment.scratchParent,
                        materialization,
                        deployment.sandbox.runtimeClosureLimits,
                    )
                    var treeClosed = false
                    var treeTransactionFailure: Throwable? = null
                    try {
                        val terminal = runContainedNinjaQuery(
                            paths,
                            prestartArtifact,
                            retainedInputs,
                            expectedStdout,
                            expectedBytes,
                            prestart,
                            runtime,
                            tree,
                            output,
                            deployment,
                            limits,
                        )
                        val identities = retainedInputs.identities()
                        requireExecutionInputsUnchanged(
                            paths,
                            prestartArtifact,
                            retainedInputs,
                            expectedStdout,
                            prestart,
                            runtime,
                            tree,
                            output,
                            limits,
                        )
                        tree.close()
                        treeClosed = true
                        prestartArtifact.verifyUnchanged("retained Ninja prestart")
                        retainedInputs.verifyUnchanged()
                        expectedStdout.verifyUnchanged("retained expected Ninja stdout")
                        runtime.verifyUnchanged()
                        output.requireAbsent()
                        val document = expectedNinjaExecutionReceipt(
                            prestart,
                            identities,
                            runtime,
                            tree,
                            terminal,
                            deployment,
                            limits,
                        )
                        val (_, canonicalBytes) = snapshotControlObject(
                            document,
                            limits.maximumCanonicalBytes,
                            "full-tree Ninja compdb execution receipt",
                            NINJA_RUN_SCHEMA,
                        )
                        prestartArtifact.verifyUnchanged("retained Ninja prestart")
                        retainedInputs.verifyUnchanged()
                        expectedStdout.verifyUnchanged("retained expected Ninja stdout")
                        runtime.verifyUnchanged()
                        output.requireAbsent()
                        val published = output.publish(canonicalBytes)
                        if (!published.contentEquals(canonicalBytes)) {
                            throw FullTreeControlException(
                                "published Ninja execution receipt differs from its canonical bytes",
                            )
                        }
                        output.requirePresent(OracleArtifacts.sha256(canonicalBytes))
                        validatedNinjaExecutionRegistry(document, canonicalBytes)
                    } catch (failure: Throwable) {
                        treeTransactionFailure = failure
                        throw failure
                    } finally {
                        if (!treeClosed) {
                            try {
                                tree.close()
                            } catch (cleanupFailure: Throwable) {
                                val transactionFailure = treeTransactionFailure
                                if (transactionFailure != null && transactionFailure !== cleanupFailure) {
                                    cleanupFailure.addSuppressed(transactionFailure)
                                }
                                throw cleanupFailure
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun loadPrestartForExecution(
    paths: NinjaPrestartPaths,
    limits: FullTreeNinjaCompdbExecutionLimits,
): FullTreeNinjaCompdbPrestartRegistry = FullTreeNinjaCompdbPrestartControl.loadAndValidate(
    paths.artifact,
    paths.manifestArchive,
    paths.reconciliation,
    paths.compdb,
    paths.captureInput,
    paths.readiness,
    paths.generatedInventory,
    paths.sourceArchive,
    paths.generatedArchive,
    paths.generatedProvenance,
    paths.scope,
    paths.sourceLock,
    paths.artifactManifest,
    paths.buildRecord,
    paths.inventory,
    paths.sourceInventory,
    paths.planningInventory,
    limits.prestart,
)

private class PinnedNinjaRuntimeProfile private constructor(
    val deployment: FullTreeNinjaCompdbIsolationDeployment,
    private val ninja: StableControlFile,
    private val files: List<Pair<FullTreeNinjaCompdbRuntimeFile, StableControlFile>>,
    val ninjaRuntimeManifestSha256: String,
    val runtimeProfileSha256: String,
) : AutoCloseable {
    val ninjaBytes: Long get() = ninja.size
    val ninjaSha256: String get() = ninja.authenticatedSha256

    fun mounts(): List<AcpSandboxReadOnlyMount> = deployment.sandbox.ninjaCompdbRuntimeMounts

    fun ninjaMount(destination: Path): AcpSandboxReadOnlyMount = AcpSandboxReadOnlyMount(
        deployment.ninjaExecutableSource,
        destination,
        deployment.expectedNinjaRuntimeManifestSha256,
    )

    fun verifyUnchanged() {
        ninja.requireSingleLink("live Ninja executable")
        ninja.verifyUnchanged("live Ninja executable")
        if (calculateAcpRuntimeManifestSha256(
                deployment.ninjaExecutableSource,
                deployment.sandbox.runtimeClosureLimits,
            ) != ninjaRuntimeManifestSha256
        ) throw FullTreeControlException("live Ninja runtime manifest changed")
        files.forEach { (profile, guard) ->
            guard.requireSingleLink("Ninja runtime file ${profile.destination}")
            guard.verifyUnchanged("Ninja runtime file ${profile.destination}")
            if (calculateAcpRuntimeManifestSha256(
                    profile.source,
                    deployment.sandbox.runtimeClosureLimits,
                ) != profile.expectedRuntimeManifestSha256
            ) throw FullTreeControlException("Ninja runtime manifest changed: ${profile.destination}")
        }
    }

    override fun close() {
        var failure: Throwable? = null
        files.asReversed().forEach { (_, guard) ->
            try {
                guard.close()
            } catch (closeFailure: Throwable) {
                val existing = failure
                if (existing == null) failure = closeFailure else existing.addSuppressed(closeFailure)
            }
        }
        try {
            ninja.close()
        } catch (closeFailure: Throwable) {
            val existing = failure
            if (existing == null) failure = closeFailure else existing.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(
            deployment: FullTreeNinjaCompdbIsolationDeployment,
            prestart: FullTreeNinjaCompdbPrestartRegistry,
        ): PinnedNinjaRuntimeProfile {
            val ninja = StableControlFile.open(
                deployment.ninjaExecutableSource,
                prestart.ninjaExecutableBytes,
                "live Ninja executable",
            )
            val opened = ArrayList<Pair<FullTreeNinjaCompdbRuntimeFile, StableControlFile>>()
            try {
                ninja.requireSingleLink("live Ninja executable")
                if (ninja.size != prestart.ninjaExecutableBytes ||
                    ninja.authenticatedSha256 != prestart.ninjaExecutableSha256
                ) throw FullTreeControlException("live Ninja executable differs from the build record")
                val ninjaManifest = calculateAcpRuntimeManifestSha256(
                    deployment.ninjaExecutableSource,
                    deployment.sandbox.runtimeClosureLimits,
                )
                if (ninjaManifest != deployment.expectedNinjaRuntimeManifestSha256) {
                    throw FullTreeControlException("live Ninja executable runtime manifest is untrusted")
                }
                deployment.runtimeFiles.forEach { profile ->
                    val guard = StableControlFile.open(
                        profile.source,
                        profile.expectedBytes,
                        "Ninja runtime file ${profile.destination}",
                    )
                    opened += profile to guard
                    guard.requireSingleLink("Ninja runtime file ${profile.destination}")
                    if (guard.size != profile.expectedBytes ||
                        guard.authenticatedSha256 != profile.expectedSha256
                    ) throw FullTreeControlException(
                        "Ninja runtime file differs from its deployment identity: ${profile.destination}",
                    )
                    if (calculateAcpRuntimeManifestSha256(
                            profile.source,
                            deployment.sandbox.runtimeClosureLimits,
                        ) != profile.expectedRuntimeManifestSha256
                    ) throw FullTreeControlException(
                        "Ninja runtime file manifest is untrusted: ${profile.destination}",
                    )
                }
                val profileSha = NinjaRunnerCommitment(NINJA_RUN_RUNTIME_PROFILE_DOMAIN).apply {
                    token(deployment.configurationSha256)
                    token(prestart.ninjaToolIdentitySha256)
                    long(ninja.size)
                    token(ninja.authenticatedSha256)
                    token(ninjaManifest)
                    long(opened.size.toLong())
                    opened.sortedBy { it.first.destination.toString() }.forEach { (profile, guard) ->
                        token(profile.source.toString())
                        token(profile.destination.toString())
                        long(guard.size)
                        token(guard.authenticatedSha256)
                        token(profile.expectedRuntimeManifestSha256)
                    }
                }.finish()
                return PinnedNinjaRuntimeProfile(
                    deployment,
                    ninja,
                    Collections.unmodifiableList(opened),
                    ninjaManifest,
                    profileSha,
                )
            } catch (failure: Throwable) {
                opened.asReversed().forEach { (_, guard) ->
                    try {
                        guard.close()
                    } catch (closeFailure: Throwable) {
                        failure.addSuppressed(closeFailure)
                    }
                }
                try {
                    ninja.close()
                } catch (closeFailure: Throwable) {
                    failure.addSuppressed(closeFailure)
                }
                throw failure
            }
        }
    }
}

private class PinnedNinjaReceiptTarget private constructor(
    private val parent: LinuxDescriptor,
    private val name: String,
    private val maximumBytes: Int,
) : AutoCloseable {
    private var publishedSha256: String? = null

    fun requireAbsent() {
        if (publishedSha256 != null) throw FullTreeControlException("Ninja execution receipt is already published")
        LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name).use { existing ->
            if (existing != null) {
                throw FullTreeControlException("Ninja execution receipt output already exists")
            }
        }
        val temporaryName = DescriptorBoundAtomicStateFile.temporaryName(name)
        LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, temporaryName).use { existing ->
            if (existing != null) {
                throw FullTreeControlException("Ninja execution receipt temporary output already exists")
            }
        }
    }

    fun publish(bytes: ByteArray): ByteArray {
        require(publishedSha256 == null) { "Ninja execution receipt may be published only once" }
        val snapshot = DescriptorBoundAtomicStateFile.publishNoReplace(
            parent,
            name,
            bytes,
            maximumBytes,
        )
        val published = snapshot.bytes
        publishedSha256 = OracleArtifacts.sha256(published)
        return published
    }

    fun requirePresent(expectedSha256: String) {
        val expected = publishedSha256
            ?: throw FullTreeControlException("Ninja execution receipt has not been published")
        if (expected != expectedSha256) {
            throw FullTreeControlException("published Ninja receipt expectation differs")
        }
        val current = DescriptorBoundAtomicStateFile.readOrNull(parent, name, maximumBytes)
            ?: throw FullTreeControlException("published Ninja execution receipt disappeared")
        if (OracleArtifacts.sha256(current.bytes) != expectedSha256) {
            throw FullTreeControlException("published Ninja execution receipt changed")
        }
    }

    override fun close() = parent.close()

    companion object {
        fun open(path: Path, maximumBytes: Int): PinnedNinjaReceiptTarget {
            val normalized = requireNinjaReceiptOutputPath(path)
            val name = checkNotNull(normalized.fileName).toString()
            val parentPath = normalized.parent
                ?: throw IllegalArgumentException("Ninja execution receipt output has no parent")
            val parent = LinuxFilesystemSyscalls.openRoot(parentPath)
            try {
                DescriptorBoundAtomicStateFile.requireOwnerOnlyParent(parent)
                return PinnedNinjaReceiptTarget(parent, name, maximumBytes)
            } catch (failure: Throwable) {
                runCatching { parent.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private fun requireNinjaReceiptOutputPath(path: Path): Path {
    val normalized = path.toAbsolutePath().normalize()
    require(path.isAbsolute && path == normalized) {
        "Ninja execution receipt output must be absolute and normalized"
    }
    val name = normalized.fileName?.toString()
        ?: throw IllegalArgumentException("Ninja execution receipt output has no file name")
    require(name.matches(NINJA_RUN_RECEIPT_NAME)) {
        "Ninja execution receipt output name is invalid"
    }
    return normalized
}

internal enum class NinjaManifestTreeCleanupStage { AFTER_QUARANTINE }

internal fun interface NinjaManifestTreeCleanupFaultInjector {
    fun at(stage: NinjaManifestTreeCleanupStage)
}

internal class PrivateNinjaManifestTree private constructor(
    private val parent: LinuxDescriptor,
    private val root: LinuxDescriptor,
    private val name: String,
    val path: Path,
    private val expectedKey: decompengine.acp.LinuxFileKey,
    private val expectedMountId: Long,
    private val cleanupLimits: AcpRuntimeClosureLimits,
    val runtimeManifestSha256: String,
    val materializationSha256: String,
    private val cleanupFaultInjector: NinjaManifestTreeCleanupFaultInjector?,
) : AutoCloseable {
    private var closed = false
    private var currentName = name
    private var firstCleanupFailure: IOException? = null

    fun mount(destination: Path): AcpSandboxReadOnlyMount = AcpSandboxReadOnlyMount(
        path,
        destination,
        runtimeManifestSha256,
    )

    fun verifyUnchanged() {
        check(!closed) { "Ninja manifest materialization is already closed" }
        requireNamedRootIdentity()
        if (calculateAcpRuntimeManifestSha256(path, cleanupLimits) != runtimeManifestSha256) {
            throw FullTreeControlException("Ninja manifest materialization changed")
        }
    }

    private fun requireNamedRootIdentity() {
        val current = LinuxFilesystemSyscalls.identity(root.fd)
        if (current.key != expectedKey || current.mountId != expectedMountId ||
            !current.isDirectory || current.isSymbolicLink
        ) throw FullTreeControlException("Ninja manifest materialization descriptor changed")
        LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, currentName).use { byName ->
            if (byName.identity.key != expectedKey || byName.identity.mountId != expectedMountId) {
                throw FullTreeControlException("Ninja manifest materialization pathname changed")
            }
        }
        if (currentName != name) {
            LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name).use { original ->
                if (original != null) {
                    throw FullTreeControlException("Ninja manifest materialization original name reappeared")
                }
            }
        }
    }

    @Synchronized
    override fun close() {
        if (closed) {
            firstCleanupFailure?.let { throw it }
            return
        }
        val priorFailure = firstCleanupFailure
        try {
            if (LinuxFilesystemSyscalls.identity(root.fd).linkCount == 0) {
                root.close()
                parent.close()
                closed = true
            } else {
                requireNamedRootIdentity()
                deletePrivateTreeContents(root, cleanupLimits)
                if (currentName == name) {
                    val quarantine = ".decomp-ninja-manifest-delete-${UUID.randomUUID()}"
                    LinuxFilesystemSyscalls.renameNoReplace(parent.fd, name, quarantine)
                    currentName = quarantine
                    cleanupFaultInjector?.at(NinjaManifestTreeCleanupStage.AFTER_QUARANTINE)
                }
                LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, currentName).use { selected ->
                    if (selected.identity.key != expectedKey || selected.identity.mountId != expectedMountId) {
                        throw IOException("Ninja manifest cleanup selected a replacement")
                    }
                }
                LinuxFilesystemSyscalls.removeDirectory(parent.fd, currentName)
                if (LinuxFilesystemSyscalls.identity(root.fd).linkCount != 0) {
                    throw IOException("Ninja manifest materialization remains linked after cleanup")
                }
                root.close()
                parent.close()
                closed = true
            }
        } catch (failure: Throwable) {
            val attempt = IOException("Ninja manifest materialization cleanup was not proven", failure)
            val original = firstCleanupFailure
            if (original == null) {
                firstCleanupFailure = attempt
                throw attempt
            }
            if (attempt !== original) original.addSuppressed(attempt)
            throw original
        }
        priorFailure?.let { throw it }
    }

    companion object {
        fun create(
            scratchParent: Path,
            materialization: FullTreeNinjaManifestMaterialization,
            runtimeLimits: AcpRuntimeClosureLimits,
            cleanupFaultInjector: NinjaManifestTreeCleanupFaultInjector? = null,
        ): PrivateNinjaManifestTree {
            requireNinjaRunnerAbsolutePath(scratchParent, "Ninja materialization scratch parent")
            val attributes = Files.readAttributes(
                scratchParent,
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            require(attributes.isDirectory && !attributes.isSymbolicLink) {
                "Ninja materialization scratch parent must be a real directory"
            }
            require(scratchParent.toRealPath(LinkOption.NOFOLLOW_LINKS) == scratchParent) {
                "Ninja materialization scratch parent must be canonical"
            }
            val parent = LinuxFilesystemSyscalls.openRoot(scratchParent)
            val name = ".decomp-ninja-manifest-${UUID.randomUUID()}"
            var root: LinuxDescriptor? = null
            var directoryCreated = false
            try {
                DescriptorBoundAtomicStateFile.requireOwnerOnlyParent(parent)
                LinuxFilesystemSyscalls.createDirectory(parent.fd, name, NINJA_RUN_OWNER_DIRECTORY_MODE)
                directoryCreated = true
                root = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
                val actualRoot = requireNotNull(root)
                val treePath = scratchParent.resolve(name)
                populateNinjaManifestTree(actualRoot, materialization)
                val runtimeManifest = calculateAcpRuntimeManifestSha256(treePath, runtimeLimits)
                val materializationSha = NinjaRunnerCommitment(NINJA_RUN_MATERIALIZATION_DOMAIN).apply {
                    token(materialization.snapshot.configurationSha256)
                    token(materialization.snapshot.reportSha256)
                    token(materialization.snapshot.fileManifestSha256)
                    token(runtimeManifest)
                    long(materialization.paths.size.toLong())
                    materialization.paths.forEach { path ->
                        val bytes = materialization.bytes(path)
                        token(path)
                        long(bytes.size.toLong())
                        token(OracleArtifacts.sha256(bytes))
                    }
                }.finish()
                return PrivateNinjaManifestTree(
                    parent,
                    actualRoot,
                    name,
                    treePath,
                    actualRoot.identity.key,
                    actualRoot.identity.mountId,
                    runtimeLimits,
                    runtimeManifest,
                    materializationSha,
                    cleanupFaultInjector,
                )
            } catch (failure: Throwable) {
                val cleanupFailures = ArrayList<Throwable>()
                val opened = root
                if (opened != null) {
                    val contentsRemoved = runCatching {
                        deletePrivateTreeContents(opened, runtimeLimits)
                    }.exceptionOrNull()?.also(cleanupFailures::add) == null
                    if (contentsRemoved) {
                        runCatching { LinuxFilesystemSyscalls.removeDirectory(parent.fd, name) }
                            .exceptionOrNull()?.let(cleanupFailures::add)
                    }
                } else if (directoryCreated) {
                    runCatching { LinuxFilesystemSyscalls.removeDirectory(parent.fd, name) }
                        .exceptionOrNull()?.let(cleanupFailures::add)
                }
                runCatching { opened?.close() }.exceptionOrNull()?.let(cleanupFailures::add)
                runCatching { parent.close() }.exceptionOrNull()?.let(cleanupFailures::add)
                if (cleanupFailures.isNotEmpty()) {
                    val cleanup = IOException(
                        "Ninja manifest initialization failed and cleanup was not proven",
                        cleanupFailures.first(),
                    )
                    cleanupFailures.drop(1).forEach(cleanup::addSuppressed)
                    cleanup.addSuppressed(failure)
                    throw cleanup
                }
                throw failure
            }
        }
    }
}

private fun populateNinjaManifestTree(
    root: LinuxDescriptor,
    materialization: FullTreeNinjaManifestMaterialization,
) {
    val directories = TreeSet<String>(compareBy<String>({ it.count { character -> character == '/' } }, { it }))
    materialization.paths.forEach { path ->
        val components = path.split('/')
        for (end in 1 until components.size) directories += components.take(end).joinToString("/")
    }
    directories.forEach { relative ->
        withNinjaManifestDirectory(root, relative.substringBeforeLast('/', "")) { parent ->
            val name = relative.substringAfterLast('/')
            LinuxFilesystemSyscalls.createDirectory(parent.fd, name, NINJA_RUN_OWNER_DIRECTORY_MODE)
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name).use(LinuxFilesystemSyscalls::synchronize)
        }
    }
    materialization.paths.forEach { relative ->
        val content = materialization.bytes(relative)
        withNinjaManifestDirectory(root, relative.substringBeforeLast('/', "")) { parent ->
            val fileName = relative.substringAfterLast('/')
            LinuxFilesystemSyscalls.createRegularFile(
                parent.fd,
                fileName,
                NINJA_RUN_OWNER_FILE_WRITE_MODE,
            ).use { file ->
                LinuxFilesystemSyscalls.write(file, content) {}
                LinuxFilesystemSyscalls.chmod(file, NINJA_RUN_OWNER_FILE_READ_MODE)
                LinuxFilesystemSyscalls.synchronize(file)
            }
            LinuxFilesystemSyscalls.synchronize(parent)
        }
    }
    directories.sortedWith(
        compareByDescending<String> { it.count { character -> character == '/' } }.thenByDescending { it },
    ).forEach { relative ->
        withNinjaManifestDirectory(root, relative) { directory ->
            LinuxFilesystemSyscalls.chmod(directory, NINJA_RUN_OWNER_DIRECTORY_READ_MODE)
            LinuxFilesystemSyscalls.synchronize(directory)
        }
    }
    LinuxFilesystemSyscalls.chmod(root, NINJA_RUN_OWNER_DIRECTORY_READ_MODE)
    LinuxFilesystemSyscalls.synchronize(root)
}

private inline fun <T> withNinjaManifestDirectory(
    root: LinuxDescriptor,
    relative: String,
    action: (LinuxDescriptor) -> T,
): T {
    if (relative.isEmpty()) return action(root)
    val opened = ArrayList<LinuxDescriptor>()
    try {
        var current = root
        relative.split('/').forEach { component ->
            val child = LinuxFilesystemSyscalls.openDirectoryAt(current.fd, component)
            opened += child
            current = child
        }
        return action(current)
    } finally {
        opened.asReversed().forEach(LinuxDescriptor::close)
    }
}

internal data class NinjaPipeObservation(
    val bytes: ByteArray,
    val sha256: String,
)

private data class NinjaPipeSources(
    val stdout: InputStream,
    val stderr: InputStream,
)

internal class PrestartedNinjaPipeCapture(
    expectedStdout: ByteArray,
    maximumStderrBytes: Int,
) {
    private val sources = AtomicReference<NinjaPipeSources?>()
    private val released = CountDownLatch(1)
    private val aborted = AtomicBoolean(false)
    private val failure = AtomicReference<Throwable?>()
    private val stdout = AtomicReference<NinjaPipeObservation?>()
    private val stderr = AtomicReference<NinjaPipeObservation?>()
    private val expected = expectedStdout.copyOf()
    private val stdoutBuffer = ByteArray(Math.addExact(expectedStdout.size, 1))
    private val stderrBuffer = ByteArray(Math.addExact(maximumStderrBytes, 1))
    private val stdoutThread = pipeThread("decomp-ninja-compdb-stdout") {
        val launched = awaitSources() ?: return@pipeThread
        stdout.set(drain(launched.stdout, stdoutBuffer, expected))
    }
    private val stderrThread = pipeThread("decomp-ninja-compdb-stderr") {
        val launched = awaitSources() ?: return@pipeThread
        stderr.set(drain(launched.stderr, stderrBuffer, null))
    }

    init {
        stdoutThread.start()
        try {
            stderrThread.start()
        } catch (startFailure: Throwable) {
            aborted.set(true)
            released.countDown()
            stdoutThread.join()
            throw startFailure
        }
    }

    @Synchronized
    fun handoff(launched: Process) {
        check(!aborted.get()) { "Ninja capture was aborted before process handoff" }
        check(sources.get() == null) { "Ninja capture process was already handed off" }
        val stdout = launched.inputStream
        val stderr = try {
            launched.errorStream
        } catch (failure: Throwable) {
            runCatching { stdout.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
        if (!sources.compareAndSet(null, NinjaPipeSources(stdout, stderr))) {
            val handoffFailure = IllegalStateException("Ninja capture process was already handed off")
            runCatching { stdout.close() }.exceptionOrNull()?.let(handoffFailure::addSuppressed)
            runCatching { stderr.close() }.exceptionOrNull()?.let(handoffFailure::addSuppressed)
            throw handoffFailure
        }
        released.countDown()
    }

    fun firstFailure(): Throwable? = failure.get()

    fun requireReadyForStart() {
        failure.get()?.let { throw IOException("Ninja output capture failed before START", it) }
        if (!stdoutThread.isAlive || !stderrThread.isAlive || released.count != 1L) {
            throw IOException("Ninja output capture is not waiting for the authenticated process handoff")
        }
    }

    @Synchronized
    fun abortAndAwait(timeout: Duration) {
        aborted.set(true)
        released.countDown()
        val cleanupFailures = ArrayList<Throwable>()
        sources.get()?.let { retained ->
            runCatching { retained.stdout.close() }.exceptionOrNull()?.let(cleanupFailures::add)
            runCatching { retained.stderr.close() }.exceptionOrNull()?.let(cleanupFailures::add)
        }
        stdoutThread.interrupt()
        stderrThread.interrupt()
        val deadline = saturatedDeadline(timeout.toNanos())
        try {
            joinUntil(stdoutThread, deadline)
            joinUntil(stderrThread, deadline)
        } catch (failure: Throwable) {
            cleanupFailures += failure
        }
        if (stdoutThread.isAlive || stderrThread.isAlive) {
            cleanupFailures += IOException("Ninja output-capture workers did not terminate after terminal abort")
        }
        if (cleanupFailures.isNotEmpty()) {
            val cleanup = IOException("Ninja output-capture terminal abort was not proven", cleanupFailures.first())
            cleanupFailures.drop(1).forEach(cleanup::addSuppressed)
            throw cleanup
        }
    }

    fun await(timeout: Duration): Pair<NinjaPipeObservation, NinjaPipeObservation> {
        val deadline = saturatedDeadline(timeout.toNanos())
        joinUntil(stdoutThread, deadline)
        joinUntil(stderrThread, deadline)
        if (stdoutThread.isAlive || stderrThread.isAlive) {
            throw IOException("Ninja output capture did not reach terminal EOF")
        }
        failure.get()?.let { throw IOException("Ninja output capture failed", it) }
        return requireNotNull(stdout.get()) { "Ninja stdout was not captured" } to
            requireNotNull(stderr.get()) { "Ninja stderr was not captured" }
    }

    private fun awaitSources(): NinjaPipeSources? {
        try {
            released.await()
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            failure.compareAndSet(null, interrupted)
            return null
        }
        return if (aborted.get()) null else sources.get()
            ?: IOException("Ninja capture was released without a process").also {
                failure.compareAndSet(null, it)
            }.let { null }
    }

    private fun drain(
        input: InputStream,
        buffer: ByteArray,
        exactExpected: ByteArray?,
    ): NinjaPipeObservation = input.use { stream ->
        var offset = 0
        val chunk = ByteArray(NINJA_RUN_PIPE_CHUNK_BYTES)
        while (true) {
            val amount = try {
                stream.read(chunk)
            } catch (readFailure: Throwable) {
                failure.compareAndSet(null, readFailure)
                throw readFailure
            }
            if (amount < 0) break
            if (amount == 0) continue
            val remaining = buffer.size - offset
            if (amount > remaining) {
                System.arraycopy(chunk, 0, buffer, offset, remaining)
                val overflow = IOException("Ninja output exceeded its nontruncating byte bound")
                failure.compareAndSet(null, overflow)
                throw overflow
            }
            System.arraycopy(chunk, 0, buffer, offset, amount)
            if (exactExpected != null) {
                for (index in 0 until amount) {
                    val absolute = offset + index
                    if (absolute >= exactExpected.size || chunk[index] != exactExpected[absolute]) {
                        val mismatch = IOException("Ninja stdout differs from the retained expected bytes")
                        failure.compareAndSet(null, mismatch)
                        throw mismatch
                    }
                }
            }
            offset += amount
            if (offset == buffer.size) {
                val overflow = IOException("Ninja output reached its limit-plus-one sentinel")
                failure.compareAndSet(null, overflow)
                throw overflow
            }
        }
        if (exactExpected != null && offset != exactExpected.size) {
            val mismatch = IOException("Ninja stdout ended before its retained expected bytes")
            failure.compareAndSet(null, mismatch)
            throw mismatch
        }
        val observed = buffer.copyOf(offset)
        NinjaPipeObservation(observed, OracleArtifacts.sha256(observed))
    }

    private fun pipeThread(name: String, action: () -> Unit): Thread = Thread({
        try {
            action()
        } catch (captureFailure: Throwable) {
            failure.compareAndSet(null, captureFailure)
        }
    }, name).apply { isDaemon = false }
}

private data class NinjaRunTerminal(
    val sandboxEvidence: AcpSandboxEvidence,
    val launchEvidence: AcpSandboxLaunchEvidence,
    val stdout: NinjaPipeObservation,
    val stderr: NinjaPipeObservation,
    val exitCode: Int,
    val elapsedMillis: Long,
)

private fun runContainedNinjaQuery(
    paths: NinjaPrestartPaths,
    prestartArtifact: StableControlFile,
    retainedInputs: NinjaPrestartInputGuards,
    expectedStdout: StableControlFile,
    expectedBytes: ByteArray,
    prestart: FullTreeNinjaCompdbPrestartRegistry,
    runtime: PinnedNinjaRuntimeProfile,
    tree: PrivateNinjaManifestTree,
    output: PinnedNinjaReceiptTarget,
    deployment: FullTreeNinjaCompdbIsolationDeployment,
    limits: FullTreeNinjaCompdbExecutionLimits,
): NinjaRunTerminal {
    val capture = PrestartedNinjaPipeCapture(expectedBytes, limits.maximumStderrBytes)
    val startedAt = System.nanoTime()
    val deadline = saturatedDeadline(Duration.ofMillis(limits.maximumWallMillis).toNanos())
    var boundary: LinuxBubblewrapBoundary? = null
    var contained: decompengine.acp.AcpSandboxedProcess? = null
    var boundaryClosed = false
    try {
        capture.requireReadyForStart()
        val preparedBoundary = LinuxBubblewrapBoundary.prepare(deployment.sandbox)
        boundary = preparedBoundary
        val remainingBeforeLaunch = remainingDuration(deadline)
        val launch = AcpSandboxLaunch(
            command = prestart.argv,
            environment = prestart.environment,
            workingDirectory = Path.of(prestart.workingDirectory),
            resourceLimits = limits.resourceLimits,
            maximumWallDuration = remainingBeforeLaunch,
            readOnlyMounts = buildList {
                addAll(runtime.mounts())
                add(runtime.ninjaMount(Path.of(prestart.ninjaExecutablePath)))
                add(tree.mount(Path.of(prestart.workingDirectory)))
            },
            stagingRoots = emptyList(),
            purpose = AcpSandboxLaunchPurpose.NINJA_COMPDB_QUERY,
            emptyDirectories = emptyList(),
            stdinDisposition = AcpSandboxStdinDisposition.CLOSED_BEFORE_EXEC,
        )
        val launched = preparedBoundary.launch(
            launch,
            mergeError = false,
            cancellationCheck = { requireBeforeDeadline(deadline, "Ninja containment provisioning") },
            beforeAuthorizationCommit = {
                capture.requireReadyForStart()
                requireExecutionInputsUnchanged(
                    paths,
                    prestartArtifact,
                    retainedInputs,
                    expectedStdout,
                    prestart,
                    runtime,
                    tree,
                    output,
                    limits,
                )
                requireBeforeDeadline(deadline, "Ninja final START authorization")
            },
        )
        contained = launched
        capture.handoff(launched.process)
        runCatching { launched.process.outputStream.close() }
            .getOrElse { closeFailure ->
                runCatching { launched.destroyForcibly() }
                throw IOException("could not close the host side of Ninja's gated stdin", closeFailure)
            }

        var timedOut = false
        while (true) {
            capture.firstFailure()?.let {
                runCatching { launched.destroyForcibly() }
                throw IOException("Ninja output failed before process completion", it)
            }
            val remainingNanos = deadline - System.nanoTime()
            if (remainingNanos <= 0L) {
                timedOut = true
                runCatching { launched.destroyForcibly() }
                break
            }
            val waitMillis = minOf(
                NINJA_RUN_PROCESS_POLL_MILLIS,
                maxOf(1L, TimeUnit.NANOSECONDS.toMillis(remainingNanos)),
            )
            if (launched.process.waitFor(waitMillis, TimeUnit.MILLISECONDS)) break
        }
        if (timedOut) throw IOException("Ninja compdb query exceeded its wall deadline")
        val exitCode = launched.process.exitValue()
        launched.awaitCleanup(Duration.ofMillis(limits.cleanupMillis))
        val observations = capture.await(Duration.ofMillis(limits.cleanupMillis))
        if (exitCode != 0) throw IOException("Ninja compdb query exited with status $exitCode")
        if (!observations.first.bytes.contentEquals(expectedBytes) ||
            observations.first.sha256 != prestart.expectedStdoutSha256
        ) throw IOException("Ninja stdout did not authenticate the retained compilation database")
        val evidence = preparedBoundary.evidence(policy = null)
        val launchEvidence = requireExactNinjaLaunchEvidence(
            evidence,
            prestart,
            runtime,
            tree,
            deployment,
            limits,
        )
        preparedBoundary.close()
        boundaryClosed = true
        return NinjaRunTerminal(
            evidence,
            launchEvidence,
            observations.first,
            observations.second,
            exitCode,
            TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt),
        )
    } catch (failure: Throwable) {
        val cleanupFailures = ArrayList<Throwable>()
        contained?.let { launched ->
            runCatching { launched.destroyForcibly() }.exceptionOrNull()?.let(cleanupFailures::add)
        }
        runCatching { capture.abortAndAwait(Duration.ofMillis(limits.cleanupMillis)) }
            .exceptionOrNull()?.let(cleanupFailures::add)
        contained?.let { launched ->
            runCatching { launched.awaitCleanup(Duration.ofMillis(limits.cleanupMillis)) }
                .exceptionOrNull()?.let(cleanupFailures::add)
        }
        if (!boundaryClosed) {
            runCatching { boundary?.close() }.exceptionOrNull()?.let(cleanupFailures::add)
        }
        if (cleanupFailures.isNotEmpty()) {
            val cleanup = IOException("Ninja execution failed and terminal cleanup was not proven", cleanupFailures.first())
            cleanupFailures.drop(1).forEach(cleanup::addSuppressed)
            cleanup.addSuppressed(failure)
            throw cleanup
        }
        throw failure
    }
}

private fun requireExecutionInputsUnchanged(
    paths: NinjaPrestartPaths,
    prestartArtifact: StableControlFile,
    retainedInputs: NinjaPrestartInputGuards,
    expectedStdout: StableControlFile,
    prestart: FullTreeNinjaCompdbPrestartRegistry,
    runtime: PinnedNinjaRuntimeProfile,
    tree: PrivateNinjaManifestTree,
    output: PinnedNinjaReceiptTarget,
    limits: FullTreeNinjaCompdbExecutionLimits,
) {
    prestartArtifact.requireSingleLink("retained Ninja prestart")
    prestartArtifact.verifyUnchanged("retained Ninja prestart")
    retainedInputs.verifyUnchanged()
    expectedStdout.requireSingleLink("retained expected Ninja stdout")
    expectedStdout.verifyUnchanged("retained expected Ninja stdout")
    runtime.verifyUnchanged()
    tree.verifyUnchanged()
    val terminal = loadPrestartForExecution(paths, limits)
    if (!terminal.canonicalBytes.contentEquals(prestart.canonicalBytes) ||
        terminal.prestartContextSha256 != prestart.prestartContextSha256
    ) throw FullTreeControlException("Ninja prestart changed across execution authorization")
    output.requireAbsent()
}

private fun requireMaterializationMatchesPrestart(
    materialization: FullTreeNinjaManifestMaterialization,
    prestart: FullTreeNinjaCompdbPrestartRegistry,
) {
    val snapshot = materialization.snapshot
    if (snapshot.archiveSha256 != prestart.manifestArchiveSha256 ||
        snapshot.configurationSha256 != prestart.manifestConfigurationSha256 ||
        snapshot.reportSha256 != prestart.manifestReportSha256 ||
        snapshot.fileManifestSha256 != prestart.manifestFileManifestSha256 ||
        snapshot.includeGraphSha256 != prestart.manifestIncludeGraphSha256 ||
        snapshot.ruleManifestSha256 != prestart.manifestRuleManifestSha256 ||
        snapshot.archiveRoot != prestart.manifestArchiveRoot ||
        snapshot.rootManifest != prestart.manifestRootFile ||
        snapshot.files.size != materialization.paths.size
    ) throw FullTreeControlException("Ninja manifest materialization differs from the prestart closure")
    val root = snapshot.files.singleOrNull { it.path == snapshot.rootManifest }
        ?: throw FullTreeControlException("Ninja materialization has no unique root manifest")
    if (root.bytes != prestart.manifestRootBytes || root.sha256 != prestart.manifestRootSha256) {
        throw FullTreeControlException("Ninja materialization root differs from the prestart")
    }
}

private fun requireExactNinjaLaunchEvidence(
    evidence: AcpSandboxEvidence,
    prestart: FullTreeNinjaCompdbPrestartRegistry,
    runtime: PinnedNinjaRuntimeProfile,
    tree: PrivateNinjaManifestTree,
    deployment: FullTreeNinjaCompdbIsolationDeployment,
    limits: FullTreeNinjaCompdbExecutionLimits,
): AcpSandboxLaunchEvidence {
    val sandbox = deployment.sandbox
    if (!evidence.cgroupV2PidsLimited || !evidence.cgroupV2MemoryLimited ||
        !evidence.cgroupV2CpuLimited || !evidence.networkIsolated ||
        !evidence.outerAgentContained || !evidence.nestedUserNamespacesDisabled ||
        !evidence.newSession || !evidence.dieWithParent
    ) throw FullTreeControlException("Ninja sandbox lacks a required containment proof")
    if (evidence.authorities.isNotEmpty() || evidence.terminalAudit.isNotEmpty() ||
        evidence.launches.size != 1 || evidence.policySha256 != null ||
        evidence.terminalLimits != null || evidence.outerProcessOutput != null ||
        evidence.outerAgentLimits != sandbox.agentResourceLimits ||
        evidence.runtimeClosureLimits != sandbox.runtimeClosureLimits ||
        evidence.provider != "bubblewrap+systemd-cgroup-v2" || evidence.providerVersion.isBlank() ||
        evidence.providerExecutableSha256 != sandbox.expectedBubblewrapSha256 ||
        evidence.resourceLimiterSha256 != sandbox.expectedResourceLimiterSha256 ||
        evidence.scopeSupervisorSha256 != sandbox.expectedScopeSupervisorSha256 ||
        evidence.scopeInspectorSha256 != sandbox.expectedScopeInspectorSha256 ||
        evidence.environmentFdOpenerSha256 != sandbox.expectedEnvironmentFdOpenerSha256
    ) throw FullTreeControlException("Ninja sandbox evidence contains extraneous authority")
    val expectedSecurityExecutables = mapOf(
        "bubblewrap" to (sandbox.bubblewrapExecutable to sandbox.expectedBubblewrapSha256),
        "resource-limiter" to Pair(
            sandbox.resourceLimiterExecutable,
            sandbox.expectedResourceLimiterSha256,
        ),
        "scope-supervisor" to Pair(
            sandbox.scopeSupervisorExecutable,
            sandbox.expectedScopeSupervisorSha256,
        ),
        "scope-inspector" to Pair(
            sandbox.scopeInspectorExecutable,
            sandbox.expectedScopeInspectorSha256,
        ),
        "environment-fd-opener" to Pair(
            sandbox.environmentFdOpenerExecutable,
            sandbox.expectedEnvironmentFdOpenerSha256,
        ),
        "sandbox-gate-helper" to Pair(
            sandbox.sandboxGateHelperExecutable,
            sandbox.expectedSandboxGateHelperSha256,
        ),
    )
    val securityExecutables = evidence.securityExecutables.associateBy { it.role }
    if (securityExecutables.size != expectedSecurityExecutables.size ||
        evidence.securityExecutables.size != expectedSecurityExecutables.size ||
        expectedSecurityExecutables.any { (role, expected) ->
            val observed = securityExecutables[role]
            observed == null ||
                observed.canonicalPathSha256 != rawNinjaRunnerSha256(expected.first.toString()) ||
                observed.contentSha256 != expected.second || observed.mode and 0x92 != 0 ||
                !observed.metadataSha256.matches(Regex("[0-9a-f]{64}"))
        } || securityExecutables.getValue("bubblewrap").mode != evidence.providerExecutableMode
    ) throw FullTreeControlException("Ninja sandbox security-tool evidence differs from deployment")
    val launch = evidence.launches.single()
    if (launch.purpose != AcpSandboxLaunchPurpose.NINJA_COMPDB_QUERY || launch.mergeError ||
        launch.stagingRootCount != 0 || launch.emptyDirectoryCount != 0 ||
        launch.commandSha256 != acpSandboxCanonicalStringDigest(prestart.argv) ||
        launch.workingDirectorySha256 != rawNinjaRunnerSha256(prestart.workingDirectory) ||
        launch.stagingRootsSha256 != acpSandboxEmptyStagingRootsDigest() ||
        launch.emptyDirectoriesSha256 != acpSandboxCanonicalStringDigest(emptyList()) ||
        launch.stdinDisposition != AcpSandboxStdinDisposition.CLOSED_BEFORE_EXEC.protocolArgument ||
        launch.resourceLimits != limits.resourceLimits
    ) throw FullTreeControlException("Ninja sandbox launch evidence differs from the fixed query")
    val environmentBytes = canonicalNinjaRunnerEnvironment(prestart.environment)
    if (launch.environment.sandboxPathSha256 != acpSandboxEnvironmentPathSha256() ||
        launch.environment.bindingNamesSha256 != acpSandboxCanonicalStringDigest(
            prestart.environment.keys.sorted(),
        ) ||
        launch.environment.bindingCount != prestart.environment.size ||
        launch.environment.encodedBytes != environmentBytes.size.toLong() ||
        launch.environment.contentSha256 != OracleArtifacts.sha256(environmentBytes) ||
        launch.environment.mode != acpSandboxEnvironmentFileMode() ||
        launch.environment.linkCount != 0
    ) throw FullTreeControlException("Ninja sandbox environment evidence differs from the prestart")
    val rlimits = launch.effectiveRlimits
    if (rlimits.processesSoft != limits.resourceLimits.maximumProcesses.toLong() ||
        rlimits.processesHard != limits.resourceLimits.maximumProcesses.toLong() ||
        rlimits.openFilesSoft != limits.resourceLimits.maximumOpenFiles.toLong() ||
        rlimits.openFilesHard != limits.resourceLimits.maximumOpenFiles.toLong() ||
        rlimits.fileBytesSoft != limits.resourceLimits.maximumFileBytes ||
        rlimits.fileBytesHard != limits.resourceLimits.maximumFileBytes ||
        rlimits.coreBytesSoft != 0L || rlimits.coreBytesHard != 0L ||
        rlimits.addressSpaceSoft != limits.resourceLimits.maximumAddressSpaceBytes ||
        rlimits.addressSpaceHard != limits.resourceLimits.maximumAddressSpaceBytes ||
        rlimits.cpuSecondsSoft != limits.resourceLimits.maximumCpuSeconds.toLong() ||
        rlimits.cpuSecondsHard != limits.resourceLimits.maximumCpuSeconds.toLong()
    ) throw FullTreeControlException("Ninja sandbox effective rlimits differ from policy")
    val controllers = launch.controllers
    val boundaryCleanupMicros = acpSandboxCleanupTimeoutMicros()
    if (controllers.pidsMax != limits.resourceLimits.maximumProcesses.toLong() ||
        controllers.memoryMaxBytes != limits.resourceLimits.maximumAddressSpaceBytes ||
        controllers.memorySwapMaxBytes != 0L || !controllers.memoryOomGroup ||
        controllers.cpuQuotaMicros <= 0L || controllers.cpuQuotaMicros != controllers.cpuPeriodMicros ||
        controllers.runtimeMaxMicros <= controllers.timeoutStopMicros ||
        controllers.runtimeMaxMicros >
        limits.maximumWallMillis * 1_000L + boundaryCleanupMicros ||
        controllers.timeoutStopMicros != boundaryCleanupMicros
    ) throw FullTreeControlException("Ninja sandbox cgroup controllers differ from policy")
    if (launch.startGate.descriptor != 0 || !launch.startGate.positiveByteRequired ||
        launch.startGate.waiterExecutableSha256 != deployment.sandbox.expectedSandboxGateHelperSha256 ||
        launch.startGate.helperProtocolSha256 != acpSandboxGateProtocolSha256()
    ) {
        throw FullTreeControlException("Ninja sandbox lacks the authenticated positive-byte gate")
    }

    data class ExpectedMount(
        val sourcePathSha256: String,
        val configuredManifestSha256: String,
        val directory: Boolean,
    )

    val expectedMounts = LinkedHashMap<String, ExpectedMount>()
    fun expectedMount(
        source: Path,
        destination: Path,
        manifest: String,
        directory: Boolean,
        destinationPathSha256: String = rawNinjaRunnerSha256(destination.toString()),
    ) {
        if (expectedMounts.put(
                destinationPathSha256,
                ExpectedMount(rawNinjaRunnerSha256(source.toString()), manifest, directory),
            ) != null
        ) throw FullTreeControlException("Ninja expected mount destinations are ambiguous")
    }
    expectedMount(
        deployment.sandbox.sandboxGateHelperExecutable,
        Path.of("/decomp-acp-internal/gate-helper"),
        deployment.sandbox.expectedSandboxGateHelperManifestSha256,
        false,
        acpSandboxGateHelperPathSha256(),
    )
    deployment.runtimeFiles.forEach { profile ->
        expectedMount(
            profile.source,
            profile.destination,
            profile.expectedRuntimeManifestSha256,
            false,
        )
    }
    expectedMount(
        deployment.ninjaExecutableSource,
        Path.of(prestart.ninjaExecutablePath),
        deployment.expectedNinjaRuntimeManifestSha256,
        false,
    )
    expectedMount(
        tree.path,
        Path.of(prestart.workingDirectory),
        tree.runtimeManifestSha256,
        true,
    )
    if (launch.runtimeMounts.size != expectedMounts.size) {
        throw FullTreeControlException("Ninja sandbox contains an unexpected runtime mount population")
    }
    val executableDestinationSha256 = rawNinjaRunnerSha256(prestart.ninjaExecutablePath)
    val executableRuntimeMount = launch.runtimeMounts.singleOrNull {
        it.destinationPathSha256 == executableDestinationSha256
    }
    launch.runtimeMounts.forEach { observed ->
        val expected = expectedMounts.remove(observed.destinationPathSha256)
            ?: throw FullTreeControlException("Ninja sandbox contains an unexpected runtime mount")
        if (observed.sourcePathSha256 != expected.sourcePathSha256 ||
            observed.configuredManifestSha256 != expected.configuredManifestSha256 ||
            !observed.manifestSha256.matches(Regex("[0-9a-f]{64}")) ||
            observed.directory != expected.directory
        ) throw FullTreeControlException("Ninja sandbox runtime mount identity differs from deployment")
    }
    val executable = launch.executableMount
    if (expectedMounts.isNotEmpty() ||
        executable.sourcePathSha256 != rawNinjaRunnerSha256(deployment.ninjaExecutableSource.toString()) ||
        executable.destinationPathSha256 != executableDestinationSha256 ||
        executable.configuredManifestSha256 != runtime.ninjaRuntimeManifestSha256 ||
        !executable.manifestSha256.matches(Regex("[0-9a-f]{64}")) || executable.directory ||
        executableRuntimeMount == null || executableRuntimeMount != executable
    ) throw FullTreeControlException("Ninja executable mount evidence is incomplete")
    return launch
}

private fun expectedNinjaExecutionReceipt(
    prestart: FullTreeNinjaCompdbPrestartRegistry,
    retainedInputs: List<NinjaPrestartRetainedInputIdentity>,
    runtime: PinnedNinjaRuntimeProfile,
    tree: PrivateNinjaManifestTree,
    terminal: NinjaRunTerminal,
    deployment: FullTreeNinjaCompdbIsolationDeployment,
    limits: FullTreeNinjaCompdbExecutionLimits,
): JsonObject {
    if (prestart.blockerCodes != NINJA_RUN_BLOCKER_CODES) {
        throw FullTreeControlException("Ninja execution must carry the exact eight prestart blockers")
    }
    val executionPredecessorManifestSha256 = NinjaRunnerCommitment(
        NINJA_RUN_PREDECESSOR_DOMAIN,
    ).apply {
        long(prestart.artifactBytes)
        token(prestart.artifactSha256)
        token(prestart.reportSha256)
        token(prestart.configurationSha256)
        token(prestart.prestartContextSha256)
        token(prestart.predecessorManifestSha256)
        long(retainedInputs.size.toLong())
        retainedInputs.forEach { identity ->
            token(identity.label)
            long(identity.bytes)
            token(identity.sha256)
        }
    }.finish()
    val executedNinjaSha256 = NinjaRunnerCommitment(NINJA_RUN_EXECUTED_NINJA_DOMAIN).apply {
        token(prestart.ninjaToolIdentitySha256)
        long(runtime.ninjaBytes)
        token(runtime.ninjaSha256)
        token(runtime.ninjaRuntimeManifestSha256)
        token(runtime.runtimeProfileSha256)
    }.finish()
    val containmentReceiptSha256 = NinjaRunnerCommitment(NINJA_RUN_CONTAINMENT_DOMAIN).apply {
        token(terminal.sandboxEvidence.evidenceSha256)
        token(terminal.launchEvidence.commandSha256)
        token(terminal.launchEvidence.environment.contentSha256)
        token(terminal.launchEvidence.workingDirectorySha256)
        token(terminal.launchEvidence.stagingRootsSha256)
        token(terminal.launchEvidence.emptyDirectoriesSha256)
        token(terminal.launchEvidence.stdinDisposition)
        long(terminal.launchEvidence.runtimeMounts.size.toLong())
        terminal.launchEvidence.runtimeMounts.sortedBy { it.destinationPathSha256 }.forEach { mount ->
            token(mount.sourcePathSha256)
            token(mount.destinationPathSha256)
            token(mount.manifestSha256)
            token(mount.configuredManifestSha256)
            long(mount.device)
            long(mount.inode)
            long(mount.mode.toLong())
            token(mount.directory.toString())
        }
    }.finish()
    val stdoutObservationSha256 = NinjaRunnerCommitment(NINJA_RUN_STDOUT_DOMAIN).apply {
        long(terminal.stdout.bytes.size.toLong())
        token(terminal.stdout.sha256)
        long(prestart.expectedStdoutBytes)
        token(prestart.expectedStdoutSha256)
        token(prestart.expectedStdoutCanonicalSha256)
        token("exact-match")
    }.finish()
    val stderrObservationSha256 = NinjaRunnerCommitment(NINJA_RUN_STDERR_DOMAIN).apply {
        long(terminal.stderr.bytes.size.toLong())
        token(terminal.stderr.sha256)
        long(limits.maximumStderrBytes.toLong())
        token("complete-nontruncated")
    }.finish()
    val cleanupReceiptSha256 = NinjaRunnerCommitment(NINJA_RUN_CLEANUP_DOMAIN).apply {
        token(terminal.sandboxEvidence.evidenceSha256)
        token(tree.materializationSha256)
        token("whole-cgroup-absent")
        token("boundary-runtime-snapshots-removed")
        token("boundary-control-tree-removed")
        token("source-materialization-removed")
    }.finish()
    val receiptContextSha256 = NinjaRunnerCommitment(NINJA_RUN_CONTEXT_DOMAIN).apply {
        token(FullTreeNinjaCompdbIsolatedRunner.configurationSha256)
        token(deployment.configurationSha256)
        token(executionPredecessorManifestSha256)
        token(executedNinjaSha256)
        token(runtime.runtimeProfileSha256)
        token(tree.materializationSha256)
        token(prestart.compilerRulesSha256)
        token(prestart.invocationSha256)
        token(prestart.containmentPolicySha256)
        token(containmentReceiptSha256)
        token(stdoutObservationSha256)
        token(stderrObservationSha256)
        token(cleanupReceiptSha256)
    }.finish()

    val blockers = JsonArray(prestart.blockerCodes.map { code ->
        JsonObject(
            mapOf(
                "code" to JsonPrimitive(code),
                "disposition" to JsonPrimitive("carried"),
                "source" to JsonPrimitive("full-tree-ninja-compdb-prestart-v1"),
            ),
        )
    })
    val launch = terminal.launchEvidence
    val withoutHash = JsonObject(
        mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "kind" to JsonPrimitive("full-tree-ninja-compdb-execution-receipt-v1"),
            "configurationSha256" to JsonPrimitive(
                FullTreeNinjaCompdbIsolatedRunner.configurationSha256,
            ),
            "receiptTrust" to NINJA_RUN_RECEIPT_TRUST,
            "authority" to NINJA_RUN_AUTHORITY,
            "acpBoundary" to NINJA_RUN_ACP_BOUNDARY,
            "receiptPolicy" to NINJA_RUN_RECEIPT_POLICY,
            "bounds" to JsonObject(
                mapOf(
                    "maximumCanonicalBytes" to JsonPrimitive(limits.maximumCanonicalBytes),
                    "maximumWallMillis" to JsonPrimitive(limits.maximumWallMillis),
                    "maximumStderrBytes" to JsonPrimitive(limits.maximumStderrBytes),
                    "cleanupMillis" to JsonPrimitive(limits.cleanupMillis),
                    "maximumProcesses" to JsonPrimitive(limits.resourceLimits.maximumProcesses),
                    "maximumOpenFiles" to JsonPrimitive(limits.resourceLimits.maximumOpenFiles),
                    "maximumFileBytes" to JsonPrimitive(limits.resourceLimits.maximumFileBytes),
                    "maximumAddressSpaceBytes" to JsonPrimitive(
                        limits.resourceLimits.maximumAddressSpaceBytes,
                    ),
                    "maximumCpuSeconds" to JsonPrimitive(limits.resourceLimits.maximumCpuSeconds),
                    "maximumStdoutBytes" to JsonPrimitive(limits.prestart.maximumStdoutBytes),
                ),
            ),
            "prestart" to JsonObject(
                mapOf(
                    "artifactBytes" to JsonPrimitive(prestart.artifactBytes),
                    "artifactSha256" to JsonPrimitive(prestart.artifactSha256),
                    "reportSha256" to JsonPrimitive(prestart.reportSha256),
                    "configurationSha256" to JsonPrimitive(prestart.configurationSha256),
                    "prestartContextSha256" to JsonPrimitive(prestart.prestartContextSha256),
                    "predecessorManifestSha256" to JsonPrimitive(prestart.predecessorManifestSha256),
                    "retainedInputs" to JsonArray(retainedInputs.map { identity ->
                        JsonObject(
                            mapOf(
                                "label" to JsonPrimitive(identity.label),
                                "bytes" to JsonPrimitive(identity.bytes),
                                "sha256" to JsonPrimitive(identity.sha256),
                            ),
                        )
                    }),
                ),
            ),
            "ninja" to JsonObject(
                mapOf(
                    "recordedPath" to JsonPrimitive(prestart.ninjaExecutablePath),
                    "bytes" to JsonPrimitive(runtime.ninjaBytes),
                    "sha256" to JsonPrimitive(runtime.ninjaSha256),
                    "toolIdentitySha256" to JsonPrimitive(prestart.ninjaToolIdentitySha256),
                    "runtimeManifestSha256" to JsonPrimitive(runtime.ninjaRuntimeManifestSha256),
                    "runtimeProfileSha256" to JsonPrimitive(runtime.runtimeProfileSha256),
                    "executedNinjaSha256" to JsonPrimitive(executedNinjaSha256),
                    "runtimeFiles" to JsonArray(deployment.runtimeFiles.sortedBy {
                        it.destination.toString()
                    }.map { profile ->
                        JsonObject(
                            mapOf(
                                "sourcePathSha256" to JsonPrimitive(
                                    rawNinjaRunnerSha256(profile.source.toString()),
                                ),
                                "destination" to JsonPrimitive(profile.destination.toString()),
                                "bytes" to JsonPrimitive(profile.expectedBytes),
                                "sha256" to JsonPrimitive(profile.expectedSha256),
                                "runtimeManifestSha256" to JsonPrimitive(
                                    profile.expectedRuntimeManifestSha256,
                                ),
                            ),
                        )
                    }),
                ),
            ),
            "manifestClosure" to JsonObject(
                mapOf(
                    "archiveSha256" to JsonPrimitive(prestart.manifestArchiveSha256),
                    "closureSha256" to JsonPrimitive(prestart.manifestClosureSha256),
                    "fileManifestSha256" to JsonPrimitive(prestart.manifestFileManifestSha256),
                    "includeGraphSha256" to JsonPrimitive(prestart.manifestIncludeGraphSha256),
                    "ruleManifestSha256" to JsonPrimitive(prestart.manifestRuleManifestSha256),
                    "materializationSha256" to JsonPrimitive(tree.materializationSha256),
                    "runtimeManifestSha256" to JsonPrimitive(tree.runtimeManifestSha256),
                    "mountedReadOnly" to JsonPrimitive(true),
                    "sourceMaterializationRemoved" to JsonPrimitive(true),
                ),
            ),
            "compilerRules" to JsonObject(
                mapOf(
                    "names" to JsonArray(prestart.compilerRuleNames.map(::JsonPrimitive)),
                    "rulesSha256" to JsonPrimitive(prestart.compilerRulesSha256),
                    "selectedBy" to JsonPrimitive("kotlin-jvm-host"),
                ),
            ),
            "invocation" to JsonObject(
                mapOf(
                    "workingDirectory" to JsonPrimitive(prestart.workingDirectory),
                    "argv" to JsonArray(prestart.argv.map(::JsonPrimitive)),
                    "argvSha256" to JsonPrimitive(prestart.argvSha256),
                    "environment" to JsonArray(prestart.environment.entries.map { (name, value) ->
                        JsonObject(mapOf("name" to JsonPrimitive(name), "value" to JsonPrimitive(value)))
                    }),
                    "environmentSha256" to JsonPrimitive(prestart.environmentSha256),
                    "invocationSha256" to JsonPrimitive(prestart.invocationSha256),
                    "shell" to JsonPrimitive(false),
                    "inheritedEnvironment" to JsonPrimitive("cleared"),
                    "stdin" to JsonPrimitive("closed-before-exec"),
                    "stderrMerged" to JsonPrimitive(false),
                ),
            ),
            "containment" to JsonObject(
                mapOf(
                    "provider" to JsonPrimitive(terminal.sandboxEvidence.provider),
                    "providerVersion" to JsonPrimitive(terminal.sandboxEvidence.providerVersion),
                    "boundaryEvidenceSha256" to JsonPrimitive(terminal.sandboxEvidence.evidenceSha256),
                    "containmentReceiptSha256" to JsonPrimitive(containmentReceiptSha256),
                    "launchPurpose" to JsonPrimitive("ninja-compdb-query"),
                    "commandSha256" to JsonPrimitive(launch.commandSha256),
                    "environmentContentSha256" to JsonPrimitive(launch.environment.contentSha256),
                    "workingDirectorySha256" to JsonPrimitive(launch.workingDirectorySha256),
                    "stagingRootsSha256" to JsonPrimitive(launch.stagingRootsSha256),
                    "stagingRootCount" to JsonPrimitive(launch.stagingRootCount),
                    "emptyDirectoriesSha256" to JsonPrimitive(launch.emptyDirectoriesSha256),
                    "emptyDirectoryCount" to JsonPrimitive(launch.emptyDirectoryCount),
                    "runtimeMountCount" to JsonPrimitive(launch.runtimeMounts.size),
                    "networkIsolated" to JsonPrimitive(true),
                    "inheritedFilesystemAbsent" to JsonPrimitive(true),
                    "cgroupV2PidsMemoryCpu" to JsonPrimitive(true),
                    "startGatePositiveByte" to JsonPrimitive(true),
                    "stdinClosedBeforeExec" to JsonPrimitive(true),
                ),
            ),
            "execution" to JsonObject(
                mapOf(
                    "phase" to JsonPrimitive("terminal"),
                    "startCommittedDuringExecution" to JsonPrimitive(true),
                    "exitCode" to JsonPrimitive(terminal.exitCode),
                    "signal" to JsonNull,
                    "timedOut" to JsonPrimitive(false),
                    "outputLimitExceeded" to JsonPrimitive(false),
                    "elapsedMillis" to JsonPrimitive(terminal.elapsedMillis),
                    "stdout" to JsonObject(
                        mapOf(
                            "bytes" to JsonPrimitive(terminal.stdout.bytes.size),
                            "sha256" to JsonPrimitive(terminal.stdout.sha256),
                            "canonicalSha256" to JsonPrimitive(prestart.expectedStdoutCanonicalSha256),
                            "expectedBytes" to JsonPrimitive(prestart.expectedStdoutBytes),
                            "expectedSha256" to JsonPrimitive(prestart.expectedStdoutSha256),
                            "exactMatch" to JsonPrimitive(true),
                            "complete" to JsonPrimitive(true),
                            "truncated" to JsonPrimitive(false),
                        ),
                    ),
                    "stderr" to JsonObject(
                        mapOf(
                            "bytes" to JsonPrimitive(terminal.stderr.bytes.size),
                            "sha256" to JsonPrimitive(terminal.stderr.sha256),
                            "maximumBytes" to JsonPrimitive(limits.maximumStderrBytes),
                            "complete" to JsonPrimitive(true),
                            "truncated" to JsonPrimitive(false),
                        ),
                    ),
                ),
            ),
            "cleanup" to JsonObject(
                mapOf(
                    "wholeCgroupCleanupVerified" to JsonPrimitive(true),
                    "terminalAbsenceProven" to JsonPrimitive(true),
                    "boundaryRuntimeSnapshotsRemoved" to JsonPrimitive(true),
                    "boundaryControlTreeRemoved" to JsonPrimitive(true),
                    "sourceMaterializationRemoved" to JsonPrimitive(true),
                    "cleanupReceiptSha256" to JsonPrimitive(cleanupReceiptSha256),
                ),
            ),
            "commitments" to JsonObject(
                mapOf(
                    "executionPredecessorManifestSha256" to JsonPrimitive(
                        executionPredecessorManifestSha256,
                    ),
                    "deploymentConfigurationSha256" to JsonPrimitive(deployment.configurationSha256),
                    "runtimeProfileSha256" to JsonPrimitive(runtime.runtimeProfileSha256),
                    "executedNinjaSha256" to JsonPrimitive(executedNinjaSha256),
                    "manifestMaterializationSha256" to JsonPrimitive(tree.materializationSha256),
                    "compilerRulesSha256" to JsonPrimitive(prestart.compilerRulesSha256),
                    "invocationSha256" to JsonPrimitive(prestart.invocationSha256),
                    "containmentPolicySha256" to JsonPrimitive(prestart.containmentPolicySha256),
                    "expectedStdoutSha256" to JsonPrimitive(
                        prestart.expectedStdoutCommitmentSha256,
                    ),
                    "containmentReceiptSha256" to JsonPrimitive(containmentReceiptSha256),
                    "stdoutObservationSha256" to JsonPrimitive(stdoutObservationSha256),
                    "stderrObservationSha256" to JsonPrimitive(stderrObservationSha256),
                    "cleanupReceiptSha256" to JsonPrimitive(cleanupReceiptSha256),
                    "receiptContextSha256" to JsonPrimitive(receiptContextSha256),
                ),
            ),
            "blockerDispositions" to JsonArray(prestart.blockerCodes.map { code ->
                JsonObject(mapOf("code" to JsonPrimitive(code), "disposition" to JsonPrimitive("carried")))
            }),
            "blockers" to blockers,
        ),
    )
    val reportSha256 = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, controlJsonLimits(NINJA_RUN_MAXIMUM_CANONICAL_BYTES)),
    )
    return JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
}

private data class ValidatedNinjaExecutionState(
    val artifactBytes: Long,
    val artifactSha256: String,
    val reportSha256: String,
    val configurationSha256: String,
    val prestartArtifactSha256: String,
    val prestartContextSha256: String,
    val executedNinjaSha256: String,
    val containmentReceiptSha256: String,
    val stdoutBytes: Long,
    val stdoutSha256: String,
    val stderrBytes: Long,
    val stderrSha256: String,
    val exitCode: Int,
    val blockerCodes: List<String>,
    val canonicalBytes: ByteArray,
)

private class ValidatedNinjaExecutionRegistry(
    state: ValidatedNinjaExecutionState,
) : FullTreeNinjaCompdbExecutionRegistry {
    override val artifactBytes: Long = state.artifactBytes
    override val artifactSha256: String = state.artifactSha256
    override val reportSha256: String = state.reportSha256
    override val configurationSha256: String = state.configurationSha256
    override val prestartArtifactSha256: String = state.prestartArtifactSha256
    override val prestartContextSha256: String = state.prestartContextSha256
    override val executedNinjaSha256: String = state.executedNinjaSha256
    override val containmentReceiptSha256: String = state.containmentReceiptSha256
    override val stdoutBytes: Long = state.stdoutBytes
    override val stdoutSha256: String = state.stdoutSha256
    override val stderrBytes: Long = state.stderrBytes
    override val stderrSha256: String = state.stderrSha256
    override val exitCode: Int = state.exitCode
    override val blockerCodes: List<String> = Collections.unmodifiableList(ArrayList(state.blockerCodes))
    private val storedCanonicalBytes = state.canonicalBytes.copyOf()
    override val canonicalBytes: ByteArray get() = storedCanonicalBytes.copyOf()
    override val executionAuthenticated: Boolean = true
    override val artifactBearerAuthority: Boolean = false
    override val processAuthority: Boolean = false
    override val releaseEligible: Boolean = false
}

private fun validatedNinjaExecutionRegistry(
    document: JsonObject,
    bytes: ByteArray,
): FullTreeNinjaCompdbExecutionRegistry {
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    val expectedReportSha256 = OracleArtifacts.sha256(
        OracleJson.canonicalBytes(withoutHash, controlJsonLimits(NINJA_RUN_MAXIMUM_CANONICAL_BYTES)),
    )
    if (document.runnerString("reportSha256") != expectedReportSha256) {
        throw FullTreeControlException("Ninja execution receipt report hash does not reconcile")
    }
    val prestart = document.runnerObject("prestart")
    val ninja = document.runnerObject("ninja")
    val containment = document.runnerObject("containment")
    val execution = document.runnerObject("execution")
    val stdout = execution.runnerObject("stdout")
    val stderr = execution.runnerObject("stderr")
    val blockers = document.runnerArray("blockers").map { element ->
        (element as? JsonObject)?.runnerString("code")
            ?: throw FullTreeControlException("Ninja execution receipt blocker is invalid")
    }
    return ValidatedNinjaExecutionRegistry(
        ValidatedNinjaExecutionState(
            bytes.size.toLong(),
            OracleArtifacts.sha256(bytes),
            document.runnerString("reportSha256"),
            document.runnerString("configurationSha256").also { configuration ->
                if (configuration != FullTreeNinjaCompdbIsolatedRunner.configurationSha256) {
                    throw FullTreeControlException("Ninja execution receipt configuration changed")
                }
            },
            prestart.runnerString("artifactSha256"),
            prestart.runnerString("prestartContextSha256"),
            ninja.runnerString("executedNinjaSha256"),
            containment.runnerString("containmentReceiptSha256"),
            stdout.runnerLong("bytes"),
            stdout.runnerString("sha256"),
            stderr.runnerLong("bytes"),
            stderr.runnerString("sha256"),
            execution.runnerLong("exitCode").toInt(),
            blockers,
            bytes.copyOf(),
        ),
    )
}

private fun requireSafeNinjaEnvironment(environment: Map<String, String>) {
    environment.forEach { (name, value) ->
        require(name.matches(Regex("[A-Za-z_][A-Za-z0-9_]*"))) {
            "Ninja environment name is not portable: $name"
        }
        require('\u0000' !in value) { "Ninja environment value contains NUL" }
        require(name !in NINJA_RUN_RESERVED_ENVIRONMENT_NAMES &&
            !name.startsWith("LD_") && !name.startsWith("BASH_")) {
            "Ninja environment contains a static-gate control name: $name"
        }
    }
}

private fun requireNinjaDeploymentDisjointFromControls(
    paths: NinjaPrestartPaths,
    deployment: FullTreeNinjaCompdbIsolationDeployment,
) {
    val controls = paths.all().map(Path::toAbsolutePath).map(Path::normalize)
    val runtimeSources = listOf(deployment.ninjaExecutableSource) +
        deployment.runtimeFiles.map(FullTreeNinjaCompdbRuntimeFile::source)
    require(runtimeSources.distinct().size == runtimeSources.size) {
        "Ninja deployment runtime sources must be distinct"
    }
    runtimeSources.forEach { runtime ->
        require(runtime !in controls) {
            "Ninja deployment runtime sources cannot also be oracle control inputs"
        }
    }
    val scratch = deployment.scratchParent.toAbsolutePath().normalize()
    require(controls.none { control -> control == scratch || control.startsWith(scratch) }) {
        "Ninja materialization scratch parent cannot contain oracle control inputs"
    }
}

private fun canonicalNinjaRunnerEnvironment(environment: Map<String, String>): ByteArray {
    requireSafeNinjaEnvironment(environment)
    val output = java.io.ByteArrayOutputStream()
    environment.entries.sortedBy { it.key }.forEach { (name, value) ->
        output.write(name.toByteArray(StandardCharsets.UTF_8))
        output.write('='.code)
        output.write(value.toByteArray(StandardCharsets.UTF_8))
        output.write(0)
    }
    return output.toByteArray()
}

private fun ninjaRunnerDeploymentSha256(
    deployment: FullTreeNinjaCompdbIsolationDeployment,
): String = NinjaRunnerCommitment(NINJA_RUN_DEPLOYMENT_DOMAIN).apply {
    val sandbox = deployment.sandbox
    token(AcpSandboxLaunchPurpose.NINJA_COMPDB_QUERY.name)
    token(sandbox.bubblewrapExecutable.toString())
    token(sandbox.expectedBubblewrapSha256)
    token(sandbox.resourceLimiterExecutable.toString())
    token(sandbox.expectedResourceLimiterSha256)
    token(sandbox.scopeSupervisorExecutable.toString())
    token(sandbox.expectedScopeSupervisorSha256)
    token(sandbox.scopeInspectorExecutable.toString())
    token(sandbox.expectedScopeInspectorSha256)
    token(sandbox.environmentFdOpenerExecutable.toString())
    token(sandbox.expectedEnvironmentFdOpenerSha256)
    token(sandbox.sandboxGateHelperExecutable.toString())
    token(sandbox.expectedSandboxGateHelperSha256)
    token(sandbox.expectedSandboxGateHelperManifestSha256)
    token(sandbox.systemdUserRuntimeDirectory.toString())
    long(sandbox.runtimeClosureLimits.maximumEntries.toLong())
    long(sandbox.runtimeClosureLimits.maximumUserOwnedFileBytes)
    long(sandbox.runtimeClosureLimits.maximumDepth.toLong())
    token(deployment.ninjaExecutableSource.toString())
    token(deployment.expectedNinjaRuntimeManifestSha256)
    token(deployment.scratchParent.toString())
    long(deployment.runtimeFiles.size.toLong())
    deployment.runtimeFiles.sortedBy { it.destination.toString() }.forEach { runtime ->
        token(runtime.source.toString())
        token(runtime.destination.toString())
        long(runtime.expectedBytes)
        token(runtime.expectedSha256)
        token(runtime.expectedRuntimeManifestSha256)
    }
}.finish()

private class NinjaRunnerCommitment(domain: String) {
    private val digest = MessageDigest.getInstance("SHA-256")

    init {
        token(domain)
    }

    fun token(value: String) = bytes(value.toByteArray(StandardCharsets.UTF_8))

    fun long(value: Long) {
        require(value >= 0L) { "Ninja runner commitment values must be nonnegative" }
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(value).array())
    }

    private fun bytes(value: ByteArray) {
        long(value.size.toLong())
        digest.update(value)
    }

    fun finish(): String = digest.digest().joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}

private fun ninjaRunnerCanonicalCommitment(domain: String, value: JsonObject): String {
    val bytes = OracleJson.canonicalBytes(value, controlJsonLimits(NINJA_RUN_MAXIMUM_CANONICAL_BYTES))
    return NinjaRunnerCommitment(domain).apply {
        long(bytes.size.toLong())
        token(OracleArtifacts.sha256(bytes))
    }.finish()
}

private fun rawNinjaRunnerSha256(value: String): String = OracleArtifacts.sha256(
    value.toByteArray(StandardCharsets.UTF_8),
)

private fun requireNinjaRunnerAbsolutePath(path: Path, label: String) {
    require(path.isAbsolute && path == path.normalize()) { "$label must be absolute and normalized" }
}

private fun requireNinjaRunnerSha256(value: String, label: String) {
    require(value.matches(Regex("[0-9a-f]{64}"))) { "$label SHA-256 is invalid" }
}

private fun saturatedDeadline(durationNanos: Long): Long {
    require(durationNanos > 0L)
    val now = System.nanoTime()
    return if (Long.MAX_VALUE - now < durationNanos) Long.MAX_VALUE else now + durationNanos
}

private fun remainingDuration(deadline: Long): Duration {
    val remaining = deadline - System.nanoTime()
    if (remaining <= 0L) throw IOException("Ninja execution deadline expired before launch")
    return Duration.ofNanos(remaining)
}

private fun requireBeforeDeadline(deadline: Long, label: String) {
    if (System.nanoTime() >= deadline) throw IOException("$label exceeded the execution deadline")
}

private fun joinUntil(thread: Thread, deadline: Long) {
    while (thread.isAlive) {
        val remaining = deadline - System.nanoTime()
        if (remaining <= 0L) return
        try {
            thread.join(maxOf(1L, minOf(100L, TimeUnit.NANOSECONDS.toMillis(remaining))))
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("interrupted while awaiting Ninja output capture", interrupted)
        }
    }
}

private fun JsonObject.runnerObject(name: String): JsonObject = this[name] as? JsonObject
    ?: throw FullTreeControlException("Ninja execution receipt $name must be an object")

private fun JsonObject.runnerArray(name: String): JsonArray = this[name] as? JsonArray
    ?: throw FullTreeControlException("Ninja execution receipt $name must be an array")

private fun JsonObject.runnerString(name: String): String {
    val primitive = this[name] as? JsonPrimitive
        ?: throw FullTreeControlException("Ninja execution receipt $name must be a string")
    if (!primitive.isString) throw FullTreeControlException("Ninja execution receipt $name must be a string")
    return primitive.content
}

private fun JsonObject.runnerLong(name: String): Long {
    val primitive = this[name] as? JsonPrimitive
        ?: throw FullTreeControlException("Ninja execution receipt $name must be an integer")
    return primitive.content.toLongOrNull()
        ?: throw FullTreeControlException("Ninja execution receipt $name must be an integer")
}

private fun ninjaRunnerConstantObject(source: String): JsonObject =
    OracleJson.parse(
        source.toByteArray(StandardCharsets.UTF_8),
        controlJsonLimits(NINJA_RUN_MAXIMUM_CANONICAL_BYTES),
    ) as? JsonObject ?: error("Ninja runner policy constant must be an object")

private val NINJA_RUN_RESOURCE_LIMITS = AcpSandboxResourceLimits(
    maximumProcesses = 16,
    maximumOpenFiles = 128,
    maximumFileBytes = 64L * 1024L * 1024L,
    maximumAddressSpaceBytes = 1024L * 1024L * 1024L,
    maximumCpuSeconds = 120,
)

private val NINJA_RUN_CONFIGURATION_POLICY: JsonObject by lazy {
    JsonObject(
        mapOf(
            "id" to JsonPrimitive(NINJA_RUN_SCHEMA),
            "version" to JsonPrimitive(1),
            "owner" to JsonPrimitive("kotlin-jvm-host"),
            "receiptTrust" to NINJA_RUN_RECEIPT_TRUST,
            "authority" to NINJA_RUN_AUTHORITY,
            "acpBoundary" to NINJA_RUN_ACP_BOUNDARY,
            "receiptPolicy" to NINJA_RUN_RECEIPT_POLICY,
            "blockerCodes" to JsonArray(NINJA_RUN_BLOCKER_CODES.map(::JsonPrimitive)),
            "compiledCeilings" to JsonObject(
                mapOf(
                    "maximumCanonicalBytes" to JsonPrimitive(NINJA_RUN_MAXIMUM_CANONICAL_BYTES),
                    "maximumWallMillis" to JsonPrimitive(NINJA_RUN_MAXIMUM_WALL_MILLIS),
                    "maximumCleanupMillis" to JsonPrimitive(NINJA_RUN_MAXIMUM_CLEANUP_MILLIS),
                    "maximumStderrBytes" to JsonPrimitive(NINJA_RUN_MAXIMUM_STDERR_BYTES),
                    "maximumRuntimeFiles" to JsonPrimitive(NINJA_RUN_MAXIMUM_RUNTIME_FILES),
                    "maximumRuntimeEntries" to JsonPrimitive(NINJA_RUN_MAXIMUM_RUNTIME_ENTRIES),
                    "maximumRuntimeFileBytes" to JsonPrimitive(
                        NINJA_RUN_MAXIMUM_RUNTIME_FILE_BYTES,
                    ),
                    "maximumRuntimeProfileBytes" to JsonPrimitive(
                        NINJA_RUN_MAXIMUM_RUNTIME_PROFILE_BYTES,
                    ),
                    "maximumRuntimeDepth" to JsonPrimitive(NINJA_RUN_MAXIMUM_RUNTIME_DEPTH),
                    "maximumProcesses" to JsonPrimitive(NINJA_RUN_RESOURCE_LIMITS.maximumProcesses),
                    "maximumOpenFiles" to JsonPrimitive(NINJA_RUN_RESOURCE_LIMITS.maximumOpenFiles),
                    "maximumFileBytes" to JsonPrimitive(NINJA_RUN_RESOURCE_LIMITS.maximumFileBytes),
                    "maximumAddressSpaceBytes" to JsonPrimitive(
                        NINJA_RUN_RESOURCE_LIMITS.maximumAddressSpaceBytes,
                    ),
                    "maximumCpuSeconds" to JsonPrimitive(NINJA_RUN_RESOURCE_LIMITS.maximumCpuSeconds),
                ),
            ),
            "commitmentDomains" to JsonObject(
                mapOf(
                    "deployment" to JsonPrimitive(NINJA_RUN_DEPLOYMENT_DOMAIN),
                    "predecessor" to JsonPrimitive(NINJA_RUN_PREDECESSOR_DOMAIN),
                    "runtimeProfile" to JsonPrimitive(NINJA_RUN_RUNTIME_PROFILE_DOMAIN),
                    "executedNinja" to JsonPrimitive(NINJA_RUN_EXECUTED_NINJA_DOMAIN),
                    "materialization" to JsonPrimitive(NINJA_RUN_MATERIALIZATION_DOMAIN),
                    "containment" to JsonPrimitive(NINJA_RUN_CONTAINMENT_DOMAIN),
                    "stdout" to JsonPrimitive(NINJA_RUN_STDOUT_DOMAIN),
                    "stderr" to JsonPrimitive(NINJA_RUN_STDERR_DOMAIN),
                    "cleanup" to JsonPrimitive(NINJA_RUN_CLEANUP_DOMAIN),
                    "context" to JsonPrimitive(NINJA_RUN_CONTEXT_DOMAIN),
                    "report" to JsonPrimitive("raw-sha256-of-canonical-document-without-reportSha256"),
                ),
            ),
            "prestartConfigurationSha256" to JsonPrimitive(
                FullTreeNinjaCompdbPrestartControl.configurationSha256,
            ),
            "manifestArchiveConfigurationSha256" to JsonPrimitive(
                FullTreeNinjaManifestArchive.configurationSha256,
            ),
            "launchPurpose" to JsonPrimitive("ninja-compdb-query"),
            "invocation" to JsonPrimitive("fixed-direct-exec-no-shell"),
            "stdin" to JsonPrimitive("closed-by-attested-gate-before-exec"),
            "output" to JsonPrimitive("separate-bounded-nontruncating-byte-exact"),
            "cleanup" to JsonPrimitive("whole-cgroup-and-private-snapshots-terminal-absence"),
            "persistence" to JsonPrimitive("non-bearer-audit-receipt-no-cold-execution-authority"),
        ),
    )
}

private val NINJA_RUN_RECEIPT_TRUST = ninjaRunnerConstantObject(
    """{"artifactBearerAuthority":false,"authoritativeConstruction":"same-process-kotlin-owned-execution-and-terminal-cleanup-only","coldLoadExecutionAuthenticated":false,"persistedBytes":"non-bearer-audit-evidence","reexecutionRequiredForColdAuthority":true}""",
)

private val NINJA_RUN_AUTHORITY = ninjaRunnerConstantObject(
    """
    {
      "status":"kotlin-executed-contained-terminal-ninja-compdb-receipt",
      "predecessorBindingsReconciled":true,
      "rawInputIntegrityVerified":true,
      "buildRecordOracleManifestBindingVerified":true,
      "recordedNinjaExecutableIdentityBound":true,
      "liveNinjaExecutableAuthenticated":true,
      "manifestClosureIntegrityBound":true,
      "manifestClosureOriginAuthenticated":false,
      "manifestIncludeGraphValidated":true,
      "manifestClosureMaterializedExactly":true,
      "compilerRulesSelectedByKotlinHost":true,
      "compilerRuleDeclarationsOriginAuthenticated":false,
      "invocationFixedByKotlinHost":true,
      "expectedStdoutBound":true,
      "containmentRequirementsBound":true,
      "ninjaRuntimeClosureAuthenticated":true,
      "runtimeProvisionedDuringExecution":true,
      "startCommittedDuringExecution":true,
      "executionStarted":true,
      "ninjaExecuted":true,
      "stdoutObserved":true,
      "stderrObserved":true,
      "exitStatusObserved":true,
      "stdoutByteExactExpectedMatch":true,
      "stdoutCanonicalReconciled":true,
      "compdbExecutionAuthenticated":true,
      "containmentVerified":true,
      "networkIsolationVerified":true,
      "readOnlyMountContainmentVerified":true,
      "inheritedFilesystemAbsentVerified":true,
      "inheritedEnvironmentClearedVerified":true,
      "stdinClosedVerified":true,
      "cgroupV2ResourceContainmentVerified":true,
      "boundedNontruncatingOutputCaptureVerified":true,
      "wholeCgroupCleanupVerified":true,
      "cleanupComplete":true,
      "terminalAbsenceProven":true,
      "executionReceiptBound":true,
      "artifactBearerAuthority":false,
      "coldLoadExecutionAuthenticated":false,
      "retainedRuntimeHandlesPresent":false,
      "startAuthorized":false,
      "processAuthority":false,
      "buildGraphOriginAuthenticated":false,
      "compilerActionGraphOriginAuthenticated":false,
      "compilerExecuted":false,
      "captureStarted":false,
      "captureOutputsPresent":false,
      "exitStatusesPresent":false,
      "compilerCaptureAuthenticated":false,
      "compilerWriteSetContained":false,
      "generatedSnapshotAuthenticated":false,
      "headerPopulationComplete":false,
      "headerPlanReady":false,
      "cleanCompilationProven":false,
      "scoringAuthority":false,
      "certificationAuthority":false,
      "releaseEligible":false
    }
    """.trimIndent(),
)

private val NINJA_RUN_ACP_BOUNDARY = ninjaRunnerConstantObject(
    """
    {
      "role":"first-class-candidate-producer-operator",
      "candidateContribution":"authenticated-session-change-build-artifact-provenance",
      "candidateProvenanceAccess":"read-only-oracle-input",
      "candidateAdmissionOwner":"kotlin-jvm-host",
      "candidateLiveExecutionOwner":"kotlin-jvm-host",
      "candidateEvidenceDisposition":"non-authoritative-input-to-later-host-validation",
      "candidateLineageAdmission":"not-an-input-to-ninja-compdb-execution-receipt-v1",
      "referenceSubjectAdmission":"kotlin-jvm-host-only",
      "runtimeProfileAuthority":false,
      "referenceManifestAuthority":false,
      "compilerRuleSelectionAuthority":false,
      "invocationAuthority":false,
      "expectedOutputAuthority":false,
      "startAuthority":false,
      "processAuthority":false,
      "containmentAuthority":false,
      "cleanupAuthority":false,
      "receiptAuthoringAuthority":false,
      "graphEvidenceAuthoringAuthority":false,
      "compdbEvidenceAuthoringAuthority":false,
      "compilerActionAuthoringAuthority":false,
      "captureAuthority":false,
      "executionAuthority":false,
      "oracleAuthority":false,
      "referenceAuthoringAuthority":false,
      "policyAuthoringAuthority":false,
      "validationAuthority":false,
      "observationAuthoringAuthority":false,
      "scoringAuthority":false,
      "certificationAuthority":false,
      "releaseAuthority":false
    }
    """.trimIndent(),
)

private val NINJA_RUN_RECEIPT_POLICY = ninjaRunnerConstantObject(
    """
    {
      "owner":"kotlin-jvm-host",
      "operation":"authenticated-read-only-ninja-compdb-graph-query",
      "publicRequestSurface":"raw-predecessor-paths-plus-immutable-operator-deployment-only",
      "callerCommandEnvironmentMountStagingCallback":"forbidden",
      "execution":"direct-exec-no-shell-fixed-prestart-argv-environment-cwd",
      "runtime":"authenticated-exact-mounted-elf-profile-no-inherited-filesystem",
      "manifest":"authenticated-private-exact-materialization-read-only-mount",
      "stdin":"closed-by-attested-static-gate-before-exec",
      "output":"preallocated-concurrent-separate-bounded-nontruncating-capture",
      "success":"exit-zero-byte-exact-stdout-complete-stderr-cleanup-terminal-absence",
      "persistence":"descriptor-bound-no-replace-non-bearer-canonical-json",
      "semanticLimit":"compdb-query-authentication-is-not-build-graph-origin-or-live-edge-replay",
      "blockers":"all-eight-prestart-blockers-carried-unchanged"
    }
    """.trimIndent(),
)

private val NINJA_RUN_RESERVED_ENVIRONMENT_NAMES = setOf(
    "BASH_ENV", "BASHOPTS", "SHELLOPTS", "BASH_XTRACEFD", "ENV", "SHLVL",
    "PWD", "OLDPWD", "_", "IFS", "CDPATH", "GLOBIGNORE", "FIGNORE",
    "POSIXLY_CORRECT", "PROMPT_COMMAND", "PS0", "PS1", "PS2", "PS3", "PS4",
    "TIMEFORMAT", "TMOUT", "GCONV_PATH", "LOCPATH", "NLSPATH", "GLIBC_TUNABLES",
    "MALLOC_TRACE", "MALLOC_CHECK_", "TZDIR", "HOSTALIASES", "RES_OPTIONS", "LOCALDOMAIN",
)

/** Exact public-entry grammar consumed by DescriptorBoundAtomicStateFile. */
private val NINJA_RUN_RECEIPT_NAME = Regex("[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]")

private val NINJA_RUN_BLOCKER_CODES = listOf(
    "complete-project-header-inventory-missing",
    "compiler-capture-provenance-missing",
    "compiler-option-arity-unvalidated",
    "generated-generation-receipt-missing",
    "generated-snapshot-completeness-unproven",
    "ninja-live-edge-replay-missing",
    "physical-build-root-unverified",
    "physical-project-roots-unverified",
)

private const val NINJA_RUN_SCHEMA = "full-tree-ninja-compdb-execution-receipt"
private const val NINJA_RUN_MAXIMUM_CANONICAL_BYTES = 1024 * 1024
private const val NINJA_RUN_MAXIMUM_WALL_MILLIS = 120_000L
private const val NINJA_RUN_MAXIMUM_CLEANUP_MILLIS = 30_000L
private const val NINJA_RUN_MAXIMUM_STDERR_BYTES = 8 * 1024 * 1024
private const val NINJA_RUN_MAXIMUM_RUNTIME_FILES = 64
private const val NINJA_RUN_MAXIMUM_RUNTIME_ENTRIES = 10_000
private const val NINJA_RUN_MAXIMUM_RUNTIME_FILE_BYTES = 512L * 1024L * 1024L
private const val NINJA_RUN_MAXIMUM_RUNTIME_PROFILE_BYTES = 512L * 1024L * 1024L
private const val NINJA_RUN_MAXIMUM_RUNTIME_DEPTH = 64
private const val NINJA_RUN_PIPE_CHUNK_BYTES = 64 * 1024
private const val NINJA_RUN_PROCESS_POLL_MILLIS = 10L
private const val NINJA_RUN_OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val NINJA_RUN_OWNER_DIRECTORY_READ_MODE = 0x140 // 0500
private const val NINJA_RUN_OWNER_FILE_WRITE_MODE = 0x180 // 0600
private const val NINJA_RUN_OWNER_FILE_READ_MODE = 0x100 // 0400
private const val NINJA_RUN_DEPLOYMENT_DOMAIN = "decomp.full-tree.ninja-compdb.deployment.v1"
private const val NINJA_RUN_PREDECESSOR_DOMAIN = "decomp.full-tree.ninja-compdb.predecessors.v1"
private const val NINJA_RUN_RUNTIME_PROFILE_DOMAIN = "decomp.full-tree.ninja-compdb.runtime-profile.v1"
private const val NINJA_RUN_EXECUTED_NINJA_DOMAIN = "decomp.full-tree.ninja-compdb.executed-ninja.v1"
private const val NINJA_RUN_MATERIALIZATION_DOMAIN = "decomp.full-tree.ninja-compdb.materialization.v1"
private const val NINJA_RUN_CONTAINMENT_DOMAIN = "decomp.full-tree.ninja-compdb.containment.v1"
private const val NINJA_RUN_STDOUT_DOMAIN = "decomp.full-tree.ninja-compdb.stdout.v1"
private const val NINJA_RUN_STDERR_DOMAIN = "decomp.full-tree.ninja-compdb.stderr.v1"
private const val NINJA_RUN_CLEANUP_DOMAIN = "decomp.full-tree.ninja-compdb.cleanup.v1"
private const val NINJA_RUN_CONTEXT_DOMAIN = "decomp.full-tree.ninja-compdb.context.v1"
