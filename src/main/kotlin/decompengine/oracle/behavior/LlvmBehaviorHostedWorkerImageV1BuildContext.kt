package decompengine.oracle.behavior

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FULL_TREE_CODE_POINT_ORDER
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.requireStableDirectory
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.FileTime
import java.security.MessageDigest
import java.util.Collections
import java.util.jar.Attributes
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.Manifest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal class LlvmBehaviorHostedWorkerImageV1BuildContextException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/**
 * Retained Kotlin/JVM authority for the exact private inputs of the derived worker-image build.
 *
 * The commitments describe only the fixed Dockerfile and the copied JDK/application closure. They
 * authenticate no Docker executable, endpoint, build invocation, image ID, CREATE eligibility,
 * candidate execution, observation, score, publication, or release fact.
 * ACP remains the required first-class candidate producer/operator, is not an input to this
 * image-runtime closure, and gains no authority from it.
 */
internal sealed interface LlvmBehaviorHostedWorkerImageV1BuildContextOwner : AutoCloseable {
    val workerDockerfileSha256: String
    val jdkClosureSha256: String
    val applicationClosureSha256: String
    val contextManifestSha256: String
    val contextRootPathSha256: String
    val deterministicTarBytes: Long
    val deterministicTarSha256: String

    fun requireCurrent()

    /** Emits only the retained, canonicalized context; no host path or descriptor escapes. */
    fun writeDeterministicTarTo(output: OutputStream)

    override fun close()
}

/** Stages the closed worker-image context from exactly three raw paths. */
internal object LlvmBehaviorHostedWorkerImageV1BuildContext {
    fun stage(
        workerDockerfilePath: Path,
        jdkRootPath: Path,
        emptyContextRootPath: Path,
    ): LlvmBehaviorHostedWorkerImageV1BuildContextOwner = BoundOwner(
        workerDockerfilePath,
        jdkRootPath,
        emptyContextRootPath,
    )

    private class BoundOwner(
        workerDockerfilePath: Path,
        jdkRootPath: Path,
        emptyContextRootPath: Path,
    ) : LlvmBehaviorHostedWorkerImageV1BuildContextOwner {
        private val state = translateBuildContextFailure(
            "stage LLVM hosted-worker image build context",
        ) {
            stageBoundContext(
                workerDockerfilePath = workerDockerfilePath,
                jdkRootPath = jdkRootPath,
                emptyContextRootPath = emptyContextRootPath,
                applicationSelection = discoverApplicationSelection(),
                requiredJdkUid = ROOT_UID,
                requireProductionJdkAncestors = true,
            )
        }
        private var closed = false
        private var poisoned = false

        override val workerDockerfileSha256: String
            get() = state.workerDockerfileSha256
        override val jdkClosureSha256: String
            get() = state.jdkClosureSha256
        override val applicationClosureSha256: String
            get() = state.applicationClosureSha256
        override val contextManifestSha256: String
            get() = state.contextManifestSha256
        override val contextRootPathSha256: String
            get() = state.contextRootPathSha256
        override val deterministicTarBytes: Long
            get() = state.deterministicTarBytes
        override val deterministicTarSha256: String
            get() = state.deterministicTarSha256

        @Synchronized
        override fun requireCurrent() {
            check(!closed) { "LLVM hosted-worker image build-context owner is closed" }
            if (poisoned) buildContextFail("LLVM hosted-worker image build-context owner is poisoned")
            try {
                state.requireCurrent()
            } catch (failure: Throwable) {
                poisoned = true
                if (failure is LlvmBehaviorHostedWorkerImageV1BuildContextException) throw failure
                throw LlvmBehaviorHostedWorkerImageV1BuildContextException(
                    "LLVM hosted-worker image build context changed",
                    failure,
                )
            }
        }

        @Synchronized
        override fun writeDeterministicTarTo(output: OutputStream) {
            check(!closed) { "LLVM hosted-worker image build-context owner is closed" }
            if (poisoned) buildContextFail("LLVM hosted-worker image build-context owner is poisoned")
            try {
                state.writeDeterministicTarTo(output)
            } catch (failure: Throwable) {
                poisoned = true
                if (failure is LlvmBehaviorHostedWorkerImageV1BuildContextException) throw failure
                throw LlvmBehaviorHostedWorkerImageV1BuildContextException(
                    "cannot emit the deterministic LLVM hosted-worker build context",
                    failure,
                )
            }
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            state.close()
        }
    }
}

/** Clearly non-authoritative test seam; it cannot construct or return the production owner. */
internal object LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport {
    fun projectJdk(jdkRootPath: Path, requiredUid: Int): NonAuthoritativeWorkerJdkProjection =
        translateBuildContextFailure("project non-authoritative hosted-worker JDK test fixture") {
            openBoundDirectory(jdkRootPath, "test JDK root").use { opened ->
                val projection = observeTree(
                    root = opened.directory,
                    namedRoot = opened.path,
                    requiredUid = requiredUid,
                    label = "test JDK closure",
                )
                requireJdkRuntime(projection, opened.directory)
                NonAuthoritativeWorkerJdkProjection(
                    projection.manifestSha256,
                    projection.entries.size,
                    projection.totalRegularBytes,
                )
            }
        }

    fun projectApplication(
        referencePath: Path,
        applicationRootPath: Path,
    ): NonAuthoritativeWorkerApplicationProjection = translateBuildContextFailure(
        "project non-authoritative hosted-worker application test fixture",
    ) {
        BoundApplicationClosure.open(
            ApplicationSelection(
                referencePath.toAbsolutePath().normalize(),
                applicationRootPath.toAbsolutePath().normalize(),
                requireLoadedApplication = false,
            ),
        ).use { closure ->
            NonAuthoritativeWorkerApplicationProjection(
                closure.closureSha256,
                closure.entries.size,
                closure.workerArgumentsSha256,
            )
        }
    }

    fun projectConfiguredApplication(): NonAuthoritativeWorkerApplicationProjection = translateBuildContextFailure(
        "project configured non-authoritative hosted-worker application",
    ) {
        BoundApplicationClosure.open(discoverApplicationSelection()).use { closure ->
            NonAuthoritativeWorkerApplicationProjection(
                closure.closureSha256,
                closure.entries.size,
                closure.workerArgumentsSha256,
            )
        }
    }

    fun stage(
        workerDockerfilePath: Path,
        jdkRootPath: Path,
        emptyContextRootPath: Path,
        referencePath: Path,
        applicationRootPath: Path,
        requiredJdkUid: Int,
        tarOutput: OutputStream? = null,
    ): NonAuthoritativeWorkerBuildContextProjection = translateBuildContextFailure(
        "stage non-authoritative hosted-worker build-context test fixture",
    ) {
        stageBoundContext(
            workerDockerfilePath,
            jdkRootPath,
            emptyContextRootPath,
            ApplicationSelection(
                referencePath.toAbsolutePath().normalize(),
                applicationRootPath.toAbsolutePath().normalize(),
                requireLoadedApplication = false,
            ),
            requiredJdkUid,
            requireProductionJdkAncestors = false,
        ).use { state ->
            if (tarOutput != null) state.writeDeterministicTarTo(tarOutput)
            NonAuthoritativeWorkerBuildContextProjection(
                state.workerDockerfileSha256,
                state.jdkClosureSha256,
                state.applicationClosureSha256,
                state.workerArgumentsSha256,
                state.contextManifestSha256,
                state.deterministicTarBytes,
                state.deterministicTarSha256,
            )
        }
    }
}

internal data class NonAuthoritativeWorkerJdkProjection(
    val manifestSha256: String,
    val entryCount: Int,
    val regularBytes: Long,
)

internal data class NonAuthoritativeWorkerApplicationProjection(
    val closureSha256: String,
    val entryCount: Int,
    val workerArgumentsSha256: String,
)

internal data class NonAuthoritativeWorkerBuildContextProjection(
    val workerDockerfileSha256: String,
    val jdkClosureSha256: String,
    val applicationClosureSha256: String,
    val workerArgumentsSha256: String,
    val contextManifestSha256: String,
    val deterministicTarBytes: Long,
    val deterministicTarSha256: String,
)

private class BoundBuildContext(
    val workerDockerfileSha256: String,
    val jdkClosureSha256: String,
    val applicationClosureSha256: String,
    val workerArgumentsSha256: String,
    val contextManifestSha256: String,
    val contextRootPathSha256: String,
    val deterministicTarBytes: Long,
    val deterministicTarSha256: String,
    private val dockerfileGuard: StableControlFile,
    private val application: BoundApplicationClosure,
    private val jdk: BoundDirectory,
    private val context: BoundDirectory,
    private val contextProjection: TreeProjection,
    private val requiredJdkUid: Int,
) : AutoCloseable {
    private var closed = false

    fun requireCurrent() {
        if (dockerfileGuard.sha256(label = "hosted-worker Dockerfile terminal authentication") !=
            workerDockerfileSha256
        ) buildContextFail("hosted-worker Dockerfile bytes changed")
        dockerfileGuard.verifyUnchanged("hosted-worker Dockerfile")
        application.requireCurrent("during build-context recheck")
        jdk.requireNamedCurrent("hosted-worker JDK root")
        val currentJdk = observeTree(
            jdk.directory,
            jdk.path,
            requiredJdkUid,
            "hosted-worker JDK closure",
        )
        requireJdkRuntime(currentJdk, jdk.directory)
        if (currentJdk.manifestSha256 != jdkClosureSha256) {
            buildContextFail("hosted-worker JDK closure changed")
        }
        context.requireNamedCurrent("hosted-worker private build-context root")
        val currentContext = observeTree(
            context.directory,
            context.path,
            currentUid(),
            "hosted-worker staged build context",
        )
        requireExactContextShape(
            currentContext,
            workerArgumentsSha256,
            application.entries.map { it.value },
        )
        if (currentContext.manifestSha256 != contextManifestSha256) {
            buildContextFail("hosted-worker staged build context changed")
        }
    }

    fun writeDeterministicTarTo(output: OutputStream) {
        requireCurrent()
        val emitted = emitDeterministicTar(
            dockerfileGuard,
            workerDockerfileSha256,
            context.directory,
            contextProjection,
            output,
        )
        if (emitted.bytes != deterministicTarBytes || emitted.sha256 != deterministicTarSha256) {
            buildContextFail("hosted-worker deterministic build-context tar changed")
        }
        requireCurrent()
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var first: Throwable? = null
        fun closeOne(close: () -> Unit) {
            try {
                close()
            } catch (failure: Throwable) {
                val primary = first
                if (primary == null) first = failure else if (failure !== primary) primary.addSuppressed(failure)
            }
        }
        closeOne { cleanupPrivateContext(context) }
        closeOne(context::close)
        closeOne(jdk::close)
        closeOne(application::close)
        closeOne(dockerfileGuard::close)
        first?.let { throw it }
    }
}

private fun stageBoundContext(
    workerDockerfilePath: Path,
    jdkRootPath: Path,
    emptyContextRootPath: Path,
    applicationSelection: ApplicationSelection,
    requiredJdkUid: Int,
    requireProductionJdkAncestors: Boolean,
): BoundBuildContext {
    if (requiredJdkUid < 0) buildContextFail("required JDK owner is invalid")
    val dockerfile = StableControlFile.open(
        workerDockerfilePath,
        MAXIMUM_WORKER_DOCKERFILE_BYTES,
        "hosted-worker Dockerfile",
    )
    var application: BoundApplicationClosure? = null
    var jdk: BoundDirectory? = null
    var context: BoundDirectory? = null
    var cleanupArmed = false
    try {
        val dockerfileSha256 = dockerfile.sha256(label = "hosted-worker Dockerfile")
        if (dockerfileSha256 != EXPECTED_WORKER_DOCKERFILE_SHA256) {
            buildContextFail("hosted-worker Dockerfile differs from the reviewed bytes")
        }
        val openedApplication = BoundApplicationClosure.open(applicationSelection)
        application = openedApplication
        val openedJdk = openBoundDirectory(jdkRootPath, "hosted-worker JDK root")
        jdk = openedJdk
        if (requireProductionJdkAncestors) requireRootOwnedJdkAncestors(openedJdk.path)
        val initialJdk = observeTree(
            openedJdk.directory,
            openedJdk.path,
            requiredJdkUid,
            "hosted-worker JDK closure",
        )
        requireJdkRuntime(initialJdk, openedJdk.directory)

        val openedContext = openBoundDirectory(emptyContextRootPath, "hosted-worker private build-context root")
        context = openedContext
        requireEmptyPrivateContext(openedContext)
        requireDistinctRoots(
            dockerfile.path,
            openedApplication.rootPath,
            openedJdk.path,
            openedContext.path,
        )
        cleanupArmed = true

        copyTree(
            sourceRoot = openedJdk.directory,
            targetParent = openedContext.directory,
            targetName = JDK_DIRECTORY_NAME,
            expected = initialJdk,
        )
        openedApplication.stage(openedContext.directory)
        setNormalizedTimestamp(openedContext.directory)
        LinuxFilesystemSyscalls.synchronize(openedContext.directory)

        openedApplication.requireCurrent("after build-context staging")
        openedJdk.requireNamedCurrent("hosted-worker JDK root after staging")
        val terminalJdk = observeTree(
            openedJdk.directory,
            openedJdk.path,
            requiredJdkUid,
            "hosted-worker JDK closure after staging",
        )
        requireJdkRuntime(terminalJdk, openedJdk.directory)
        if (terminalJdk != initialJdk) buildContextFail("hosted-worker JDK changed during staging")

        openedContext.requireNamedCurrent("hosted-worker private build-context root after staging")
        val staged = observeTree(
            openedContext.directory,
            openedContext.path,
            currentUid(),
            "hosted-worker staged build context",
        )
        requireExactContextShape(
            staged,
            openedApplication.workerArgumentsSha256,
            openedApplication.entries.map { it.value },
        )
        dockerfile.verifyUnchanged("hosted-worker Dockerfile after staging")
        if (dockerfile.sha256(label = "hosted-worker Dockerfile after staging") != dockerfileSha256) {
            buildContextFail("hosted-worker Dockerfile changed during staging")
        }
        val deterministicTar = emitDeterministicTar(
            dockerfile,
            dockerfileSha256,
            openedContext.directory,
            staged,
            OutputStream.nullOutputStream(),
        )

        return BoundBuildContext(
            workerDockerfileSha256 = dockerfileSha256,
            jdkClosureSha256 = initialJdk.manifestSha256,
            applicationClosureSha256 = openedApplication.closureSha256,
            workerArgumentsSha256 = openedApplication.workerArgumentsSha256,
            contextManifestSha256 = staged.manifestSha256,
            contextRootPathSha256 = framedSha256(
                CONTEXT_PATH_DOMAIN,
                listOf(openedContext.path.toString()),
            ),
            deterministicTarBytes = deterministicTar.bytes,
            deterministicTarSha256 = deterministicTar.sha256,
            dockerfileGuard = dockerfile,
            application = openedApplication,
            jdk = openedJdk,
            context = openedContext,
            contextProjection = staged,
            requiredJdkUid = requiredJdkUid,
        ).also {
            application = null
            jdk = null
            context = null
        }
    } catch (failure: Throwable) {
        context?.takeIf { cleanupArmed }?.let { opened ->
            try {
                cleanupPrivateContext(opened)
            } catch (cleanupFailure: Throwable) {
                if (cleanupFailure !== failure) failure.addSuppressed(cleanupFailure)
            }
        }
        context?.closeSuppressing(failure)
        jdk?.closeSuppressing(failure)
        application?.closeSuppressing(failure)
        dockerfile.closeSuppressing(failure)
        throw failure
    }
}

private data class ApplicationSelection(
    val referencePath: Path,
    val rootPath: Path,
    val requireLoadedApplication: Boolean,
)

private data class ApplicationEntry(
    val logicalName: String,
    val bytes: Long,
    val sha256: String,
)

private class BoundApplicationEntry(
    val value: ApplicationEntry,
    val path: Path,
    val guard: StableControlFile,
    val descriptor: LinuxDescriptor,
) : AutoCloseable {
    private var closed = false

    fun requireCurrent(label: String) {
        val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
        requireApplicationFileIdentity(identity, "application JAR ${value.logicalName}")
        if (!sameIdentity(identity, descriptor.identity) ||
            !Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(descriptor))
        ) buildContextFail("application JAR ${value.logicalName} changed identity $label")
        if (guard.size != value.bytes || guard.sha256(label = "application JAR ${value.logicalName} $label") !=
            value.sha256
        ) buildContextFail("application JAR ${value.logicalName} changed bytes $label")
        guard.verifyUnchanged("application JAR ${value.logicalName} $label")
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        descriptor.close()
        guard.close()
    }
}

private class BoundApplicationClosure private constructor(
    val closureSha256: String,
    val rootPath: Path,
    val entries: List<BoundApplicationEntry>,
    val workerArgumentsBytes: ByteArray,
    val workerArgumentsSha256: String,
    private val referencePath: Path,
    private val referenceBytes: ByteArray,
    private val referenceGuard: StableControlFile,
    private val referenceDescriptor: LinuxDescriptor,
    private val root: BoundDirectory,
) : AutoCloseable {
    private var closed = false

    fun stage(contextRoot: LinuxDescriptor) {
        LinuxFilesystemSyscalls.createDirectory(contextRoot.fd, APP_DIRECTORY_NAME, READ_EXECUTE_DIRECTORY_MODE)
        LinuxFilesystemSyscalls.openDirectoryAt(contextRoot.fd, APP_DIRECTORY_NAME).use { app ->
            LinuxFilesystemSyscalls.chmodPinned(app, READ_EXECUTE_DIRECTORY_MODE)
            LinuxFilesystemSyscalls.createDirectory(app.fd, APP_LIB_DIRECTORY_NAME, READ_EXECUTE_DIRECTORY_MODE)
            LinuxFilesystemSyscalls.openDirectoryAt(app.fd, APP_LIB_DIRECTORY_NAME).use { lib ->
                LinuxFilesystemSyscalls.chmodPinned(lib, READ_EXECUTE_DIRECTORY_MODE)
                entries.forEach { entry ->
                    val target = LinuxFilesystemSyscalls.createRegularFile(
                        lib.fd,
                        entry.value.logicalName,
                        READ_ONLY_FILE_MODE,
                    )
                    target.use {
                        val copied = LinuxFilesystemSyscalls.copyReadableTo(
                            entry.descriptor,
                            target,
                            entry.value.bytes,
                        )
                        if (copied != entry.value.bytes) {
                            buildContextFail("application JAR ${entry.value.logicalName} changed while copied")
                        }
                        LinuxFilesystemSyscalls.chmod(target, READ_ONLY_FILE_MODE)
                        setNormalizedTimestamp(target)
                        LinuxFilesystemSyscalls.synchronize(target)
                    }
                }
                setNormalizedTimestamp(lib)
                LinuxFilesystemSyscalls.synchronize(lib)
            }
            val arguments = LinuxFilesystemSyscalls.createRegularFile(
                app.fd,
                WORKER_ARGUMENTS_FILE_NAME,
                READ_ONLY_FILE_MODE,
            )
            arguments.use {
                LinuxFilesystemSyscalls.write(arguments, workerArgumentsBytes) {}
                LinuxFilesystemSyscalls.chmod(arguments, READ_ONLY_FILE_MODE)
                setNormalizedTimestamp(arguments)
                LinuxFilesystemSyscalls.synchronize(arguments)
            }
            setNormalizedTimestamp(app)
            LinuxFilesystemSyscalls.synchronize(app)
        }
    }

    fun requireCurrent(label: String) {
        root.requireNamedCurrent("LLVM hosted-worker application closure $label")
        val referenceIdentity = LinuxFilesystemSyscalls.identity(referenceDescriptor.fd)
        requireApplicationFileIdentity(referenceIdentity, "LLVM hosted-worker class-path reference")
        if (!sameIdentity(referenceIdentity, referenceDescriptor.identity) ||
            !Files.isSameFile(referencePath, LinuxFilesystemSyscalls.descriptorPath(referenceDescriptor)) ||
            referenceGuard.size != referenceBytes.size.toLong() ||
            !MessageDigest.isEqual(
                referenceGuard.readExactly(0L, referenceBytes.size, "LLVM hosted-worker class-path reference $label"),
                referenceBytes,
            )
        ) buildContextFail("LLVM hosted-worker class-path reference changed $label")
        referenceGuard.verifyUnchanged("LLVM hosted-worker class-path reference $label")
        entries.forEach { it.requireCurrent(label) }
        val currentWorkerArguments = renderWorkerArguments(entries.map { it.value })
        if (!MessageDigest.isEqual(currentWorkerArguments, workerArgumentsBytes) ||
            OracleArtifacts.sha256(currentWorkerArguments) != workerArgumentsSha256
        ) buildContextFail("LLVM hosted-worker launcher arguments changed $label")
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var first: Throwable? = null
        fun closeOne(close: () -> Unit) {
            try {
                close()
            } catch (failure: Throwable) {
                val primary = first
                if (primary == null) first = failure else if (failure !== primary) primary.addSuppressed(failure)
            }
        }
        entries.asReversed().forEach { closeOne(it::close) }
        closeOne(root::close)
        closeOne(referenceDescriptor::close)
        closeOne(referenceGuard::close)
        first?.let { throw it }
    }

    companion object {
        fun open(selection: ApplicationSelection): BoundApplicationClosure {
            val referencePath = canonicalFile(selection.referencePath, "LLVM hosted-worker class-path reference")
            val rootPath = canonicalDirectory(selection.rootPath, "LLVM hosted-worker application root")
            val referenceGuard = StableControlFile.open(
                referencePath,
                MAXIMUM_APPLICATION_REFERENCE_BYTES,
                "LLVM hosted-worker class-path reference",
            )
            var referenceDescriptor: LinuxDescriptor? = null
            var root: BoundDirectory? = null
            val opened = ArrayDeque<BoundApplicationEntry>()
            try {
                val referenceBytes = referenceGuard.readExactly(
                    0L,
                    referenceGuard.size.toBoundedInt("LLVM hosted-worker class-path reference"),
                    "LLVM hosted-worker class-path reference",
                )
                val parsed = parseApplicationReference(referenceBytes)
                val openedReference = LinuxFilesystemSyscalls.openAbsolutePathOrNull(referencePath)
                    ?: buildContextFail("LLVM hosted-worker class-path reference disappeared")
                referenceDescriptor = openedReference
                requireApplicationFileIdentity(
                    LinuxFilesystemSyscalls.identity(openedReference.fd),
                    "LLVM hosted-worker class-path reference",
                )
                val openedRoot = openBoundDirectory(rootPath, "LLVM hosted-worker application root")
                root = openedRoot
                if (selection.requireLoadedApplication) {
                    val loaded = deploymentCodeSource()
                    val selected = rootPath.resolve(parsed.entries.first().logicalName)
                    if (!Files.isSameFile(loaded, selected)) {
                        buildContextFail("loaded hosted-worker application differs from its deployment reference")
                    }
                }

                var workerMainClasses = 0
                var aggregateJarEntries = 0
                var workerMainJarIndex = -1
                parsed.entries.forEachIndexed { index, entry ->
                    val path = rootPath.resolve(entry.logicalName).normalize()
                    if (path.parent != rootPath) buildContextFail("application JAR $index escaped its root")
                    val guard = StableControlFile.open(
                        path,
                        MAXIMUM_APPLICATION_ENTRY_BYTES,
                        "LLVM hosted-worker application JAR $index",
                    )
                    var descriptor: LinuxDescriptor? = null
                    try {
                        val openedDescriptor = LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)
                            ?: buildContextFail("LLVM hosted-worker application JAR $index disappeared")
                        descriptor = openedDescriptor
                        requireApplicationFileIdentity(
                            LinuxFilesystemSyscalls.identity(openedDescriptor.fd),
                            "LLVM hosted-worker application JAR $index",
                        )
                        if (guard.size != entry.bytes ||
                            guard.sha256(label = "LLVM hosted-worker application JAR $index") != entry.sha256
                        ) buildContextFail("LLVM hosted-worker application JAR $index differs from its reference")
                        guard.verifyUnchanged("LLVM hosted-worker application JAR $index before ZIP inspection")
                        if (!Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(openedDescriptor))) {
                            buildContextFail("LLVM hosted-worker application JAR $index changed identity")
                        }
                        val inspected = inspectApplicationJar(
                            openedDescriptor,
                            index,
                            MAXIMUM_APPLICATION_JAR_AGGREGATE_ENTRIES - aggregateJarEntries,
                            guard,
                        )
                        workerMainClasses += inspected.workerMainClasses
                        if (inspected.workerMainClasses > 0) workerMainJarIndex = index
                        aggregateJarEntries = Math.addExact(aggregateJarEntries, inspected.entryCount)
                        guard.verifyUnchanged("LLVM hosted-worker application JAR $index")
                        opened.addFirst(BoundApplicationEntry(entry, path, guard, openedDescriptor))
                        descriptor = null
                    } catch (failure: Throwable) {
                        descriptor?.closeSuppressing(failure)
                        guard.closeSuppressing(failure)
                        throw failure
                    }
                }
                if (workerMainClasses != 1) {
                    buildContextFail("hosted-worker main class does not occur exactly once in its deployment closure")
                }
                if (workerMainJarIndex != 0 ||
                    parsed.entries.drop(1).map(ApplicationEntry::logicalName) !=
                    parsed.entries.drop(1).map(ApplicationEntry::logicalName).sorted()
                ) buildContextFail("hosted-worker deployment closure order is not canonical")
                referenceGuard.verifyUnchanged("LLVM hosted-worker class-path reference after authorization")
                val orderedEntries = Collections.unmodifiableList(opened.toList().asReversed())
                val workerArgumentsBytes = renderWorkerArguments(orderedEntries.map { it.value })
                val result = BoundApplicationClosure(
                    parsed.closureSha256,
                    rootPath,
                    orderedEntries,
                    workerArgumentsBytes,
                    OracleArtifacts.sha256(workerArgumentsBytes),
                    referencePath,
                    referenceBytes.copyOf(),
                    referenceGuard,
                    openedReference,
                    openedRoot,
                )
                referenceDescriptor = null
                root = null
                opened.clear()
                return result
            } catch (failure: Throwable) {
                opened.forEach { it.closeSuppressing(failure) }
                root?.closeSuppressing(failure)
                referenceDescriptor?.closeSuppressing(failure)
                referenceGuard.closeSuppressing(failure)
                throw failure
            }
        }
    }
}

private data class ParsedApplicationReference(
    val closureSha256: String,
    val entries: List<ApplicationEntry>,
)

private fun parseApplicationReference(bytes: ByteArray): ParsedApplicationReference {
    val root = try {
        OracleJson.parseCanonical(bytes, APPLICATION_REFERENCE_JSON_LIMITS) as? JsonObject
            ?: buildContextFail("LLVM hosted-worker class-path reference must be an object")
    } catch (failure: LlvmBehaviorHostedWorkerImageV1BuildContextException) {
        throw failure
    } catch (failure: Throwable) {
        buildContextFail("LLVM hosted-worker class-path reference is not strict canonical JSON", failure)
    }
    if (root.keys != APPLICATION_REFERENCE_FIELDS) {
        buildContextFail("LLVM hosted-worker class-path reference has an unexpected shape")
    }
    requireReferenceInteger(root, "schemaVersion", 1L)
    requireReferenceString(root, "provider", APPLICATION_REFERENCE_PROVIDER)
    val closure = referenceString(root, "closureSha256")
    if (!closure.matches(SHA256)) buildContextFail("LLVM hosted-worker class-path reference digest is invalid")
    val rawEntries = root["entries"] as? JsonArray
        ?: buildContextFail("LLVM hosted-worker class-path reference entries must be an array")
    if (rawEntries.isEmpty() || rawEntries.size > MAXIMUM_APPLICATION_ENTRIES) {
        buildContextFail("LLVM hosted-worker class-path reference exceeds its entry bound")
    }
    var aggregate = 0L
    val names = hashSetOf<String>()
    val entries = rawEntries.mapIndexed { index, value ->
        val entry = value as? JsonObject
            ?: buildContextFail("LLVM hosted-worker class-path reference entry $index must be an object")
        if (entry.keys != APPLICATION_ENTRY_FIELDS) {
            buildContextFail("LLVM hosted-worker class-path reference entry $index has an unexpected shape")
        }
        val name = referenceString(entry, "logicalName")
        if (!name.matches(LOGICAL_JAR_NAME) || !names.add(name)) {
            buildContextFail("LLVM hosted-worker class-path reference entry $index name is invalid")
        }
        val size = referenceLong(entry, "bytes")
        if (size !in 1L..MAXIMUM_APPLICATION_ENTRY_BYTES) {
            buildContextFail("LLVM hosted-worker class-path reference entry $index size is invalid")
        }
        aggregate = try {
            Math.addExact(aggregate, size)
        } catch (failure: ArithmeticException) {
            buildContextFail("LLVM hosted-worker class-path reference byte count overflowed", failure)
        }
        if (aggregate > MAXIMUM_APPLICATION_AGGREGATE_BYTES) {
            buildContextFail("LLVM hosted-worker class-path reference exceeds its aggregate bound")
        }
        val sha256 = referenceString(entry, "sha256")
        if (!sha256.matches(SHA256)) {
            buildContextFail("LLVM hosted-worker class-path reference entry $index digest is invalid")
        }
        ApplicationEntry(name, size, sha256)
    }
    val unsigned = JsonObject(root - "closureSha256")
    val calculated = OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned, APPLICATION_REFERENCE_JSON_LIMITS))
    if (calculated != closure) buildContextFail("LLVM hosted-worker class-path reference self-hash differs")
    return ParsedApplicationReference(closure, Collections.unmodifiableList(entries))
}

private data class ApplicationJarInspection(
    val workerMainClasses: Int,
    val entryCount: Int,
)

private fun inspectApplicationJar(
    descriptor: LinuxDescriptor,
    index: Int,
    remainingAggregateEntries: Int,
    guard: StableControlFile,
): ApplicationJarInspection = try {
    val preflight = preflightClassicZip(guard, index, remainingAggregateEntries)
    // The sidecar SHA authenticates bytes. Disabling JAR signatures prevents implicit, unbounded
    // verifier reads of signature metadata before our bounded manual manifest read.
    JarFile(LinuxFilesystemSyscalls.descriptorPath(descriptor).toFile(), false).use { jar ->
        if (jar.size() != preflight.entryCount) {
            buildContextFail("LLVM hosted-worker application JAR $index central directory changed")
        }
        var visited = 0
        var workerMainClasses = 0
        var manifestEntry: JarEntry? = null
        val entries = jar.entries()
        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            visited += 1
            if (visited > MAXIMUM_APPLICATION_JAR_ENTRIES) {
                buildContextFail("LLVM hosted-worker application JAR $index exceeds its entry bound")
            }
            if (!entry.isDirectory && entry.name.equals(JarFile.MANIFEST_NAME, ignoreCase = true)) {
                if (manifestEntry != null) {
                    buildContextFail("LLVM hosted-worker application JAR $index contains duplicate manifests")
                }
                manifestEntry = entry
            }
            if (!entry.isDirectory && entry.name.equals("META-INF/INDEX.LIST", ignoreCase = true)) {
                buildContextFail("LLVM hosted-worker application JAR $index contains an index")
            }
            if (!entry.isDirectory && entry.name == WORKER_MAIN_CLASS) workerMainClasses += 1
            if (!entry.isDirectory && VERSIONED_WORKER_MAIN_CLASS.matches(entry.name)) {
                buildContextFail("LLVM hosted-worker application JAR $index contains a versioned worker main class")
            }
        }
        if (visited != preflight.entryCount) {
            buildContextFail("LLVM hosted-worker application JAR $index central directory changed")
        }
        manifestEntry?.let { entry ->
            val manifestBytes = readBoundedJarEntry(jar, entry, MAXIMUM_APPLICATION_MANIFEST_BYTES, index)
            val manifest = try {
                Manifest(manifestBytes.inputStream())
            } catch (failure: Throwable) {
                buildContextFail("LLVM hosted-worker application JAR $index contains an invalid manifest", failure)
            }
            if (manifest.mainAttributes.getValue(Attributes.Name.CLASS_PATH) != null) {
                buildContextFail("LLVM hosted-worker application JAR $index contains Class-Path")
            }
        }
        ApplicationJarInspection(workerMainClasses, visited)
    }
} catch (failure: LlvmBehaviorHostedWorkerImageV1BuildContextException) {
    throw failure
} catch (failure: Throwable) {
    buildContextFail("LLVM hosted-worker application JAR $index is invalid", failure)
}

private data class ClassicZipPreflight(
    val entryCount: Int,
)

/** Rejects ZIP64 and bounds the classic ZIP central directory before JarFile allocates from it. */
private fun preflightClassicZip(
    guard: StableControlFile,
    index: Int,
    remainingAggregateEntries: Int,
): ClassicZipPreflight {
    if (guard.size < ZIP_END_MINIMUM_BYTES || remainingAggregateEntries <= 0) {
        buildContextFail("LLVM hosted-worker application JAR $index lacks a bounded classic ZIP directory")
    }
    val tailBytes = minOf(guard.size, ZIP_END_MAXIMUM_SEARCH_BYTES.toLong()).toInt()
    val tailOffset = guard.size - tailBytes
    val tail = readStableRange(guard, tailOffset, tailBytes, "LLVM hosted-worker application JAR $index ZIP end")
    var endOffset = -1
    for (candidate in tail.size - ZIP_END_MINIMUM_BYTES downTo 0) {
        if (littleEndianInt(tail, candidate) != ZIP_END_SIGNATURE) continue
        val commentBytes = littleEndianUnsignedShort(tail, candidate + 20)
        if (candidate + ZIP_END_MINIMUM_BYTES + commentBytes == tail.size) {
            endOffset = candidate
            break
        }
    }
    if (endOffset < 0) {
        buildContextFail("LLVM hosted-worker application JAR $index lacks a bounded classic ZIP end")
    }
    val absoluteEndOffset = Math.addExact(tailOffset, endOffset.toLong())
    if (absoluteEndOffset >= ZIP64_END_LOCATOR_BYTES) {
        val locator = readStableRange(
            guard,
            absoluteEndOffset - ZIP64_END_LOCATOR_BYTES,
            ZIP64_END_LOCATOR_BYTES,
            "LLVM hosted-worker application JAR $index ZIP64 locator",
        )
        if (littleEndianInt(locator, 0) == ZIP64_END_LOCATOR_SIGNATURE) {
            buildContextFail("LLVM hosted-worker application JAR $index contains a ZIP64 end locator")
        }
    }
    val disk = littleEndianUnsignedShort(tail, endOffset + 4)
    val centralDisk = littleEndianUnsignedShort(tail, endOffset + 6)
    val diskEntries = littleEndianUnsignedShort(tail, endOffset + 8)
    val totalEntries = littleEndianUnsignedShort(tail, endOffset + 10)
    val centralBytes = littleEndianUnsignedInt(tail, endOffset + 12)
    val centralOffset = littleEndianUnsignedInt(tail, endOffset + 16)
    if (disk != 0 || centralDisk != 0 || diskEntries != totalEntries || totalEntries == ZIP16_SENTINEL ||
        centralBytes == ZIP32_SENTINEL || centralOffset == ZIP32_SENTINEL
    ) buildContextFail("LLVM hosted-worker application JAR $index requires unsupported ZIP64 or split ZIP")
    if (totalEntries !in 1..minOf(MAXIMUM_APPLICATION_JAR_ENTRIES, remainingAggregateEntries) ||
        centralBytes !in 1L..MAXIMUM_APPLICATION_CENTRAL_DIRECTORY_BYTES
    ) buildContextFail("LLVM hosted-worker application JAR $index exceeds its central-directory bound")
    if (Math.addExact(centralOffset, centralBytes) != absoluteEndOffset) {
        buildContextFail("LLVM hosted-worker application JAR $index has a non-canonical central-directory extent")
    }
    val scannedEntries = scanClassicCentralDirectory(
        guard,
        index,
        centralOffset,
        centralBytes,
        remainingAggregateEntries,
    )
    if (scannedEntries != diskEntries || scannedEntries != totalEntries) {
        buildContextFail("LLVM hosted-worker application JAR $index central-directory count differs from its ZIP end")
    }
    return ClassicZipPreflight(scannedEntries)
}

private fun scanClassicCentralDirectory(
    guard: StableControlFile,
    index: Int,
    centralOffset: Long,
    centralBytes: Long,
    remainingAggregateEntries: Int,
): Int {
    val centralEnd = Math.addExact(centralOffset, centralBytes)
    var cursor = centralOffset
    var count = 0
    while (cursor < centralEnd) {
        if (centralEnd - cursor < ZIP_CENTRAL_FIXED_BYTES) {
            buildContextFail("LLVM hosted-worker application JAR $index has a truncated central-directory record")
        }
        val header = readStableRange(
            guard,
            cursor,
            ZIP_CENTRAL_FIXED_BYTES,
            "LLVM hosted-worker application JAR $index central-directory header",
        )
        if (littleEndianInt(header, 0) != ZIP_CENTRAL_SIGNATURE) {
            buildContextFail("LLVM hosted-worker application JAR $index has an invalid central-directory signature")
        }
        val compressedBytes = littleEndianUnsignedInt(header, 20)
        val uncompressedBytes = littleEndianUnsignedInt(header, 24)
        val nameBytes = littleEndianUnsignedShort(header, 28)
        val extraBytes = littleEndianUnsignedShort(header, 30)
        val commentBytes = littleEndianUnsignedShort(header, 32)
        val startDisk = littleEndianUnsignedShort(header, 34)
        val localHeaderOffset = littleEndianUnsignedInt(header, 42)
        if (nameBytes == 0 || startDisk != 0 || compressedBytes == ZIP32_SENTINEL ||
            uncompressedBytes == ZIP32_SENTINEL || localHeaderOffset == ZIP32_SENTINEL ||
            localHeaderOffset >= centralOffset
        ) buildContextFail("LLVM hosted-worker application JAR $index contains a non-classic central-directory record")
        val recordBytes = try {
            Math.addExact(
                ZIP_CENTRAL_FIXED_BYTES.toLong(),
                Math.addExact(nameBytes.toLong(), Math.addExact(extraBytes.toLong(), commentBytes.toLong())),
            )
        } catch (failure: ArithmeticException) {
            buildContextFail("LLVM hosted-worker application JAR $index central-directory length overflowed", failure)
        }
        val next = try {
            Math.addExact(cursor, recordBytes)
        } catch (failure: ArithmeticException) {
            buildContextFail("LLVM hosted-worker application JAR $index central-directory extent overflowed", failure)
        }
        if (next > centralEnd) {
            buildContextFail("LLVM hosted-worker application JAR $index has a truncated central-directory record")
        }
        if (extraBytes > 0) {
            val extra = readStableRange(
                guard,
                cursor + ZIP_CENTRAL_FIXED_BYTES + nameBytes,
                extraBytes,
                "LLVM hosted-worker application JAR $index central-directory extra fields",
            )
            requireClassicZipExtraFields(extra, index)
        }
        if (count >= MAXIMUM_APPLICATION_JAR_ENTRIES || count >= remainingAggregateEntries) {
            buildContextFail("LLVM hosted-worker application JAR $index exceeds its central-directory entry bound")
        }
        count += 1
        cursor = next
    }
    if (cursor != centralEnd || count == 0) {
        buildContextFail("LLVM hosted-worker application JAR $index has an invalid central-directory extent")
    }
    return count
}

private fun requireClassicZipExtraFields(extra: ByteArray, index: Int) {
    var cursor = 0
    while (cursor < extra.size) {
        if (extra.size - cursor < ZIP_EXTRA_FIXED_BYTES) {
            buildContextFail("LLVM hosted-worker application JAR $index has a truncated ZIP extra field")
        }
        val identifier = littleEndianUnsignedShort(extra, cursor)
        val valueBytes = littleEndianUnsignedShort(extra, cursor + 2)
        val next = try {
            Math.addExact(cursor, Math.addExact(ZIP_EXTRA_FIXED_BYTES, valueBytes))
        } catch (failure: ArithmeticException) {
            buildContextFail("LLVM hosted-worker application JAR $index ZIP extra-field length overflowed", failure)
        }
        if (next > extra.size) {
            buildContextFail("LLVM hosted-worker application JAR $index has a truncated ZIP extra field")
        }
        if (identifier == ZIP64_EXTRA_IDENTIFIER) {
            buildContextFail("LLVM hosted-worker application JAR $index contains ZIP64 metadata")
        }
        cursor = next
    }
}

private fun readStableRange(
    guard: StableControlFile,
    position: Long,
    length: Int,
    label: String,
): ByteArray {
    val bytes = ByteArray(length)
    var offset = 0
    while (offset < length) {
        val read = guard.readAt(position + offset, bytes, offset, length - offset)
        if (read <= 0) buildContextFail("$label ended during bounded reading")
        offset += read
    }
    return bytes
}

private fun readBoundedJarEntry(
    jar: JarFile,
    entry: JarEntry,
    maximumBytes: Int,
    index: Int,
): ByteArray {
    if (entry.size !in 0L..maximumBytes.toLong() ||
        entry.compressedSize !in 0L..MAXIMUM_APPLICATION_MANIFEST_COMPRESSED_BYTES
    ) buildContextFail("LLVM hosted-worker application JAR $index manifest exceeds its byte bound")
    val output = ByteArrayOutputStream(minOf(entry.size.toInt(), maximumBytes))
    jar.getInputStream(entry).use { input ->
        val buffer = ByteArray(8192)
        var total = 0
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total = Math.addExact(total, read)
            if (total > maximumBytes) {
                buildContextFail("LLVM hosted-worker application JAR $index manifest exceeds its byte bound")
            }
            output.write(buffer, 0, read)
        }
    }
    val bytes = output.toByteArray()
    if (bytes.size.toLong() != entry.size) {
        buildContextFail("LLVM hosted-worker application JAR $index manifest changed length")
    }
    return bytes
}

private fun littleEndianUnsignedShort(bytes: ByteArray, offset: Int): Int =
    (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

private fun littleEndianInt(bytes: ByteArray, offset: Int): Int =
    littleEndianUnsignedInt(bytes, offset).toInt()

private fun littleEndianUnsignedInt(bytes: ByteArray, offset: Int): Long =
    (bytes[offset].toLong() and 0xffL) or
        ((bytes[offset + 1].toLong() and 0xffL) shl 8) or
        ((bytes[offset + 2].toLong() and 0xffL) shl 16) or
        ((bytes[offset + 3].toLong() and 0xffL) shl 24)

private fun renderWorkerArguments(entries: List<ApplicationEntry>): ByteArray {
    if (entries.isEmpty() || entries.size > MAXIMUM_APPLICATION_ENTRIES) {
        buildContextFail("LLVM hosted-worker launcher arguments lack a bounded class path")
    }
    val classPath = entries.joinToString(UNIX_CLASS_PATH_SEPARATOR) { entry ->
        if (!entry.logicalName.matches(LOGICAL_JAR_NAME)) {
            buildContextFail("LLVM hosted-worker launcher arguments contain an invalid JAR name")
        }
        "$CONTAINER_APPLICATION_LIB_DIRECTORY/${entry.logicalName}"
    }
    val text = listOf(
        "-Djna.nosys=true",
        "-Djna.tmpdir=/decomp-jna",
        "-cp",
        classPath,
        WORKER_MAIN_CLASS_NAME,
    ).joinToString(separator = "\n", postfix = "\n")
    if (text.any { it.code !in 0x20..0x7e && it != '\n' }) {
        buildContextFail("LLVM hosted-worker launcher arguments are not ASCII-safe")
    }
    val bytes = text.toByteArray(Charsets.US_ASCII)
    if (bytes.size > MAXIMUM_WORKER_ARGUMENT_BYTES) {
        buildContextFail("LLVM hosted-worker launcher arguments exceed their byte bound")
    }
    return bytes
}

/**
 * Emits an always-PAX, USTAR-backed archive in code-point path order. Host uid/gid/mtime/mode are
 * never serialized: archive ownership is root, timestamps are fixed, directories/executables are
 * 0555, and other regular files are 0444. Every file is reread from a retained descriptor and
 * checked against its staged digest while its exact bytes flow to the caller-owned sink.
 */
private fun emitDeterministicTar(
    dockerfile: StableControlFile,
    expectedDockerfileSha256: String,
    contextRoot: LinuxDescriptor,
    projection: TreeProjection,
    output: OutputStream,
): DeterministicTarEmission {
    val tar = DeterministicTarOutput(output)
    tar.writeRegularFile(
        path = TAR_DOCKERFILE_NAME,
        mode = TAR_READ_ONLY_MODE,
        size = dockerfile.size,
    ) { destination ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(TAR_COPY_BUFFER_BYTES)
        var position = 0L
        while (position < dockerfile.size) {
            val amount = minOf(buffer.size.toLong(), dockerfile.size - position).toInt()
            val read = dockerfile.readAt(position, buffer, 0, amount)
            if (read <= 0) buildContextFail("hosted-worker Dockerfile ended during tar emission")
            digest.update(buffer, 0, read)
            destination.write(buffer, 0, read)
            position = Math.addExact(position, read.toLong())
        }
        if (digest.digest().toHex() != expectedDockerfileSha256) {
            buildContextFail("hosted-worker Dockerfile changed during tar emission")
        }
        position
    }

    fun emitChildren(directory: LinuxDescriptor, parent: String) {
        projection.childrenByParent[parent].orEmpty().forEach { entry ->
            val name = Path.of(entry.relativePath).fileName.toString()
            val child = LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)
                ?: buildContextFail("staged hosted-worker entry ${entry.relativePath} disappeared during tar emission")
            child.use {
                val identity = LinuxFilesystemSyscalls.identity(child.fd)
                requireEntryMatches(entry, identity, "staged hosted-worker entry ${entry.relativePath}")
                when (entry.kind) {
                    "directory" -> {
                        tar.writeDirectory(entry.relativePath, TAR_READ_EXECUTE_MODE)
                        LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name).use { opened ->
                            if (!sameIdentity(identity, LinuxFilesystemSyscalls.identity(opened.fd))) {
                                buildContextFail(
                                    "staged hosted-worker directory ${entry.relativePath} changed during tar emission",
                                )
                            }
                            emitChildren(opened, entry.relativePath)
                        }
                    }
                    "file" -> {
                        val canonicalMode = if (entry.mode and ANY_EXECUTE_MODE != 0) {
                            TAR_READ_EXECUTE_MODE
                        } else {
                            TAR_READ_ONLY_MODE
                        }
                        tar.writeRegularFile(entry.relativePath, canonicalMode, entry.bytes) { destination ->
                            val digest = MessageDigest.getInstance("SHA-256")
                            val validating = object : OutputStream() {
                                override fun write(value: Int) {
                                    digest.update(value.toByte())
                                    destination.write(value)
                                }

                                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                                    digest.update(bytes, offset, length)
                                    destination.write(bytes, offset, length)
                                }
                            }
                            val copied = LinuxFilesystemSyscalls.copyReadableTo(
                                child,
                                validating,
                                entry.bytes,
                            )
                            if (copied != entry.bytes || digest.digest().toHex() != entry.sha256) {
                                buildContextFail(
                                    "staged hosted-worker file ${entry.relativePath} changed during tar emission",
                                )
                            }
                            copied
                        }
                    }
                    "symlink" -> {
                        val target = readStableSymbolicLink(
                            directory,
                            name,
                            child,
                            "staged hosted-worker tar input",
                        )
                        if (target != entry.linkTarget) {
                            buildContextFail(
                                "staged hosted-worker symlink ${entry.relativePath} changed during tar emission",
                            )
                        }
                        tar.writeSymbolicLink(entry.relativePath, target)
                    }
                    else -> buildContextFail("staged hosted-worker tar input contains an unsupported type")
                }
            }
        }
    }

    emitChildren(contextRoot, ROOT_RELATIVE_PATH)
    tar.finish()
    return DeterministicTarEmission(tar.bytes(), tar.sha256())
}

private data class DeterministicTarEmission(
    val bytes: Long,
    val sha256: String,
)

/** Minimal deterministic POSIX pax/ustar writer; it deliberately has no pathname lookup logic. */
private class DeterministicTarOutput(
    private val destination: OutputStream,
) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var entryIndex = 0
    private var bytesWritten = 0L
    private var finished = false

    fun writeDirectory(path: String, mode: Int) {
        val archivePath = "$path/"
        writePaxHeader(archivePath, null)
        writeHeader(dummyPath(directory = true), mode, 0L, TAR_DIRECTORY_TYPE, "")
        entryIndex += 1
    }

    fun writeSymbolicLink(path: String, target: String) {
        writePaxHeader(path, target)
        writeHeader(dummyPath(directory = false), TAR_SYMBOLIC_LINK_MODE, 0L, TAR_SYMBOLIC_LINK_TYPE, "target")
        entryIndex += 1
    }

    fun writeRegularFile(
        path: String,
        mode: Int,
        size: Long,
        content: (OutputStream) -> Long,
    ) {
        if (size < 0L || size > MAXIMUM_TAR_ENTRY_BYTES) {
            buildContextFail("deterministic hosted-worker tar entry $path exceeds its byte bound")
        }
        writePaxHeader(path, null)
        writeHeader(dummyPath(directory = false), mode, size, TAR_REGULAR_FILE_TYPE, "")
        val written = content(hashUpdatingOutput)
        if (written != size) buildContextFail("deterministic hosted-worker tar entry $path changed length")
        writeZeros(tarPadding(size))
        entryIndex += 1
    }

    fun finish() {
        check(!finished) { "deterministic hosted-worker tar is already finished" }
        finished = true
        writeZeros(TAR_BLOCK_BYTES * 2)
    }

    fun sha256(): String {
        check(finished) { "deterministic hosted-worker tar is incomplete" }
        return digest.digest().toHex()
    }

    fun bytes(): Long {
        check(finished) { "deterministic hosted-worker tar is incomplete" }
        return bytesWritten
    }

    private fun writePaxHeader(path: String, linkTarget: String?) {
        if ('\u0000' in path || '\n' in path || linkTarget?.let { '\u0000' in it || '\n' in it } == true) {
            buildContextFail("deterministic hosted-worker tar contains an invalid PAX value")
        }
        val content = ByteArrayOutputStream().apply {
            write(paxRecord("path", path))
            if (linkTarget != null) write(paxRecord("linkpath", linkTarget))
        }.toByteArray()
        writeHeader(
            "PaxHeaders/${entryIndex.toString().padStart(8, '0')}",
            TAR_READ_ONLY_MODE,
            content.size.toLong(),
            TAR_PAX_TYPE,
            "",
        )
        writeBytes(content)
        writeZeros(tarPadding(content.size.toLong()))
    }

    private fun writeHeader(name: String, mode: Int, size: Long, type: Byte, linkName: String) {
        val header = ByteArray(TAR_BLOCK_BYTES)
        putTarAscii(header, 0, 100, name)
        putTarOctal(header, 100, 8, mode.toLong())
        putTarOctal(header, 108, 8, TAR_OWNER_ID)
        putTarOctal(header, 116, 8, TAR_OWNER_ID)
        putTarOctal(header, 124, 12, size)
        putTarOctal(header, 136, 12, NORMALIZED_TIMESTAMP_SECONDS)
        for (index in 148 until 156) header[index] = ' '.code.toByte()
        header[156] = type
        putTarAscii(header, 157, 100, linkName)
        putTarAscii(header, 257, 6, "ustar\u0000")
        putTarAscii(header, 263, 2, "00")
        putTarOctal(header, 329, 8, 0L)
        putTarOctal(header, 337, 8, 0L)
        val checksum = header.sumOf { byte -> byte.toInt() and 0xff }
        val checksumBytes = checksum.toString(8).padStart(6, '0').toByteArray(Charsets.US_ASCII)
        if (checksumBytes.size != 6) buildContextFail("deterministic hosted-worker tar checksum overflowed")
        checksumBytes.copyInto(header, 148)
        header[154] = 0
        header[155] = ' '.code.toByte()
        writeBytes(header)
    }

    private fun dummyPath(directory: Boolean): String =
        "Entries/${entryIndex.toString().padStart(8, '0')}" + if (directory) "/" else ""

    private fun writeZeros(count: Int) {
        if (count > 0) writeBytes(ByteArray(count))
    }

    private fun writeBytes(bytes: ByteArray) {
        destination.write(bytes)
        digest.update(bytes)
        bytesWritten = Math.addExact(bytesWritten, bytes.size.toLong())
    }

    private val hashUpdatingOutput = object : OutputStream() {
        override fun write(value: Int) {
            destination.write(value)
            digest.update(value.toByte())
            bytesWritten = Math.addExact(bytesWritten, 1L)
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            destination.write(bytes, offset, length)
            digest.update(bytes, offset, length)
            bytesWritten = Math.addExact(bytesWritten, length.toLong())
        }
    }
}

private fun paxRecord(key: String, value: String): ByteArray {
    val body = "$key=$value\n".toByteArray(Charsets.UTF_8)
    var digitCount = 1
    while (true) {
        val size = Math.addExact(Math.addExact(digitCount, 1), body.size)
        val requiredDigits = size.toString().length
        if (requiredDigits == digitCount) {
            return "$size ".toByteArray(Charsets.US_ASCII) + body
        }
        digitCount = requiredDigits
    }
}

private fun putTarAscii(target: ByteArray, offset: Int, length: Int, value: String) {
    val bytes = value.toByteArray(Charsets.US_ASCII)
    if (bytes.size > length) buildContextFail("deterministic hosted-worker tar header field overflowed")
    bytes.copyInto(target, offset)
}

private fun putTarOctal(target: ByteArray, offset: Int, length: Int, value: Long) {
    if (value < 0L) buildContextFail("deterministic hosted-worker tar contains a negative numeric field")
    val bytes = value.toString(8).padStart(length - 1, '0').toByteArray(Charsets.US_ASCII)
    if (bytes.size != length - 1) buildContextFail("deterministic hosted-worker tar numeric field overflowed")
    bytes.copyInto(target, offset)
    target[offset + length - 1] = 0
}

private fun tarPadding(size: Long): Int =
    ((TAR_BLOCK_BYTES - (size % TAR_BLOCK_BYTES).toInt()) % TAR_BLOCK_BYTES)

private data class TreeEntry(
    val relativePath: String,
    val kind: String,
    val mode: Int,
    val uid: Int,
    val gid: Int,
    val bytes: Long,
    val sha256: String,
    val linkTarget: String,
)

private data class TreeProjection(
    val entries: List<TreeEntry>,
    val manifestSha256: String,
    val totalRegularBytes: Long,
) {
    val byPath: Map<String, TreeEntry> = entries.associateBy(TreeEntry::relativePath)
    val childrenByParent: Map<String, List<TreeEntry>> = entries
        .asSequence()
        .filter { it.relativePath != ROOT_RELATIVE_PATH }
        .groupBy { entry ->
            Path.of(entry.relativePath).parent?.toString()?.takeIf(String::isNotEmpty) ?: ROOT_RELATIVE_PATH
        }
}

private fun observeTree(
    root: LinuxDescriptor,
    namedRoot: Path,
    requiredUid: Int,
    label: String,
): TreeProjection {
    val entries = ArrayList<TreeEntry>()
    var totalBytes = 0L
    val rootMountId = LinuxFilesystemSyscalls.identity(root.fd).mountId

    fun add(entry: TreeEntry) {
        if (entries.size >= MAXIMUM_JDK_ENTRIES) buildContextFail("$label exceeds its entry bound")
        entries += entry
    }

    fun scan(directory: LinuxDescriptor, relative: Path, depth: Int) {
        if (depth > MAXIMUM_JDK_DEPTH) buildContextFail("$label exceeds its depth bound")
        val directoryIdentity = LinuxFilesystemSyscalls.identity(directory.fd)
        if (directoryIdentity.mountId != rootMountId) buildContextFail("$label crosses a mount boundary")
        requireTreeIdentity(directoryIdentity, requiredUid, "directory", "$label directory ${display(relative)}")
        add(treeEntry(relative, "directory", directoryIdentity))
        val names = try {
            LinuxFilesystemSyscalls.directoryEntryNames(directory, MAXIMUM_JDK_ENTRIES + 1)
        } catch (failure: Throwable) {
            buildContextFail("cannot enumerate $label directory ${display(relative)}", failure)
        }.sortedWith(FULL_TREE_CODE_POINT_ORDER)
        names.forEach { name ->
            requireTreeName(name, label)
            val childRelative = if (relative.toString().isEmpty()) Path.of(name) else relative.resolve(name)
            requireTreePath(childRelative, label)
            val child = LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)
                ?: buildContextFail("$label entry ${display(childRelative)} disappeared")
            child.use {
                val identity = LinuxFilesystemSyscalls.identity(child.fd)
                if (identity.mountId != rootMountId) buildContextFail("$label crosses a mount boundary")
                when {
                    identity.isDirectory && !identity.isSymbolicLink -> {
                        requireTreeIdentity(identity, requiredUid, "directory", "$label directory ${display(childRelative)}")
                        LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name).use { opened ->
                            if (!sameIdentity(identity, LinuxFilesystemSyscalls.identity(opened.fd))) {
                                buildContextFail("$label directory ${display(childRelative)} changed identity")
                            }
                            scan(opened, childRelative, depth + 1)
                        }
                    }
                    identity.isRegularFile && !identity.isSymbolicLink -> {
                        requireTreeIdentity(identity, requiredUid, "file", "$label file ${display(childRelative)}")
                        val size = Files.size(LinuxFilesystemSyscalls.descriptorPath(child))
                        if (size !in 0L..MAXIMUM_JDK_ENTRY_BYTES) {
                            buildContextFail("$label file ${display(childRelative)} exceeds its byte bound")
                        }
                        totalBytes = try {
                            Math.addExact(totalBytes, size)
                        } catch (failure: ArithmeticException) {
                            buildContextFail("$label aggregate byte count overflowed", failure)
                        }
                        if (totalBytes > MAXIMUM_JDK_AGGREGATE_BYTES) {
                            buildContextFail("$label exceeds its aggregate byte bound")
                        }
                        val digest = hashDescriptor(child, size, "$label file ${display(childRelative)}")
                        add(treeEntry(childRelative, "file", identity, size, digest))
                    }
                    identity.isSymbolicLink && !identity.isDirectory && !identity.isRegularFile -> {
                        requireTreeIdentity(identity, requiredUid, "symlink", "$label symlink ${display(childRelative)}")
                        val target = readStableSymbolicLink(directory, name, child, label)
                        add(treeEntry(childRelative, "symlink", identity, linkTarget = target))
                    }
                    else -> buildContextFail("$label entry ${display(childRelative)} has an unsupported type")
                }
            }
        }
    }

    scan(root, Path.of(""), 0)
    val ordered = entries.sortedWith { left, right ->
        FULL_TREE_CODE_POINT_ORDER.compare(left.relativePath, right.relativePath)
    }
    requireSafeSymlinks(ordered, namedRoot, label)
    return TreeProjection(
        Collections.unmodifiableList(ordered),
        treeManifestSha256(ordered),
        totalBytes,
    )
}

private fun requireSafeSymlinks(entries: List<TreeEntry>, namedRoot: Path, label: String) {
    entries.filter { it.kind == "symlink" }.forEach { entry ->
        val rawTarget = entry.linkTarget
        val parsed = try {
            Path.of(rawTarget)
        } catch (failure: Throwable) {
            buildContextFail("$label symlink ${entry.relativePath} has an invalid target", failure)
        }
        if (rawTarget.isEmpty() || rawTarget.toByteArray(Charsets.UTF_8).size > MAXIMUM_SYMLINK_TARGET_BYTES ||
            rawTarget.any { it.code < 0x20 || it.code == 0x7f } ||
            parsed.isAbsolute || parsed.fileSystem != FileSystems.getDefault()
        ) buildContextFail("$label symlink ${entry.relativePath} target is not a bounded relative path")
        val relative = Path.of(entry.relativePath)
        val parent = relative.parent ?: Path.of("")
        val lexical = parent.resolve(parsed).normalize()
        if (lexical.isAbsolute || lexical.startsWith(Path.of(".."))) {
            buildContextFail("$label symlink ${entry.relativePath} escapes its root")
        }
        val linkPath = namedRoot.resolve(relative)
        val resolved = try {
            linkPath.toRealPath()
        } catch (failure: Throwable) {
            buildContextFail("$label symlink ${entry.relativePath} is dangling or cyclic", failure)
        }
        if (!resolved.startsWith(namedRoot)) {
            buildContextFail("$label symlink ${entry.relativePath} resolves outside its root")
        }
    }
}

private fun copyTree(
    sourceRoot: LinuxDescriptor,
    targetParent: LinuxDescriptor,
    targetName: String,
    expected: TreeProjection,
) {
    val rootEntry = expected.byPath[ROOT_RELATIVE_PATH]
        ?: buildContextFail("hosted-worker JDK projection lacks its root")
    LinuxFilesystemSyscalls.createDirectory(targetParent.fd, targetName, OWNER_DIRECTORY_MODE)
    LinuxFilesystemSyscalls.openDirectoryAt(targetParent.fd, targetName).use { targetRoot ->
        LinuxFilesystemSyscalls.chmodPinned(targetRoot, OWNER_DIRECTORY_MODE)
        copyTreeDirectory(sourceRoot, targetRoot, Path.of(""), expected)
        setNormalizedTimestamp(targetRoot)
        LinuxFilesystemSyscalls.chmodPinned(targetRoot, rootEntry.mode)
        LinuxFilesystemSyscalls.synchronize(targetRoot)
    }
}

private fun copyTreeDirectory(
    source: LinuxDescriptor,
    target: LinuxDescriptor,
    relative: Path,
    expected: TreeProjection,
) {
    val parentKey = relative.toString().takeIf(String::isNotEmpty) ?: ROOT_RELATIVE_PATH
    val children = expected.childrenByParent[parentKey].orEmpty()
    children.forEach { entry ->
        val sourceEntry = LinuxFilesystemSyscalls.openPathAtOrNull(source.fd, Path.of(entry.relativePath).fileName.toString())
            ?: buildContextFail("hosted-worker JDK entry ${entry.relativePath} disappeared while copied")
        sourceEntry.use {
            val identity = LinuxFilesystemSyscalls.identity(sourceEntry.fd)
            requireEntryMatches(entry, identity, "hosted-worker JDK entry ${entry.relativePath}")
            val name = Path.of(entry.relativePath).fileName.toString()
            when (entry.kind) {
                "directory" -> {
                    LinuxFilesystemSyscalls.createDirectory(target.fd, name, OWNER_DIRECTORY_MODE)
                    LinuxFilesystemSyscalls.openDirectoryAt(source.fd, name).use { sourceDirectory ->
                        LinuxFilesystemSyscalls.openDirectoryAt(target.fd, name).use { targetDirectory ->
                            LinuxFilesystemSyscalls.chmodPinned(targetDirectory, OWNER_DIRECTORY_MODE)
                            copyTreeDirectory(sourceDirectory, targetDirectory, Path.of(entry.relativePath), expected)
                            setNormalizedTimestamp(targetDirectory)
                            LinuxFilesystemSyscalls.chmodPinned(targetDirectory, entry.mode)
                            LinuxFilesystemSyscalls.synchronize(targetDirectory)
                        }
                    }
                }
                "file" -> {
                    val destination = LinuxFilesystemSyscalls.createRegularFile(target.fd, name, entry.mode)
                    destination.use {
                        val copied = LinuxFilesystemSyscalls.copyReadableTo(sourceEntry, destination, entry.bytes)
                        if (copied != entry.bytes) {
                            buildContextFail("hosted-worker JDK entry ${entry.relativePath} changed while copied")
                        }
                        LinuxFilesystemSyscalls.chmod(destination, entry.mode)
                        setNormalizedTimestamp(destination)
                        LinuxFilesystemSyscalls.synchronize(destination)
                    }
                }
                "symlink" -> createSymbolicLink(target, name, entry.linkTarget)
                else -> buildContextFail("hosted-worker JDK projection contains an unsupported type")
            }
        }
    }
}

private fun createSymbolicLink(parent: LinuxDescriptor, name: String, target: String) {
    val path = LinuxFilesystemSyscalls.descriptorPath(parent).resolve(name)
    try {
        Files.createSymbolicLink(path, Path.of(target))
    } catch (failure: Throwable) {
        buildContextFail("cannot create hosted-worker JDK symbolic link $name", failure)
    }
    val created = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)
        ?: buildContextFail("created hosted-worker JDK symbolic link $name disappeared")
    created.use {
        val identity = LinuxFilesystemSyscalls.identity(created.fd)
        if (!identity.isSymbolicLink || identity.isDirectory || identity.isRegularFile ||
            identity.uid != currentUid() || identity.linkCount != 1
        ) buildContextFail("created hosted-worker JDK symbolic link $name has an invalid identity")
        val observedTarget = readStableSymbolicLink(parent, name, created, "staged hosted-worker JDK")
        if (observedTarget != target) buildContextFail("created hosted-worker JDK symbolic link $name changed target")
        setNormalizedSymlinkTimestamp(path)
    }
    LinuxFilesystemSyscalls.synchronize(parent)
}

private fun requireJdkRuntime(projection: TreeProjection, root: LinuxDescriptor) {
    val release = projection.byPath[JDK_RELEASE_FILE]
        ?: buildContextFail("hosted-worker JDK lacks release metadata")
    if (release.kind != "file" || release.bytes !in 1L..MAXIMUM_JDK_RELEASE_BYTES) {
        buildContextFail("hosted-worker JDK release metadata is invalid")
    }
    val java = projection.byPath[JDK_JAVA_FILE]
        ?: buildContextFail("hosted-worker JDK lacks bin/java")
    if (java.kind != "file" || java.mode and ANY_EXECUTE_MODE == 0) {
        buildContextFail("hosted-worker JDK bin/java is not executable")
    }
    LinuxFilesystemSyscalls.openDirectoryAt(root.fd, "bin").use { bin ->
        val releaseBytes = openTreeRegular(root, "release").use { descriptor ->
            val output = ByteArrayOutputStream(release.bytes.toInt())
            val copied = LinuxFilesystemSyscalls.copyReadableTo(descriptor, output, release.bytes)
            if (copied != release.bytes) buildContextFail("hosted-worker JDK release metadata changed length")
            output.toByteArray()
        }
        val fields = parseJdkRelease(releaseBytes)
        if (fields["OS_NAME"] != "Linux" || fields["OS_ARCH"] !in setOf("amd64", "x86_64") ||
            fields["IMAGE_TYPE"] != "JDK" || !fields.getValue("JAVA_VERSION").matches(JAVA_21_VERSION)
        ) buildContextFail("hosted-worker JDK release is not a Linux/amd64 Java 21 JDK")
        openTreeRegular(bin, "java").use { descriptor ->
            val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
            if (identity.mode.permissions and ANY_EXECUTE_MODE == 0) {
                buildContextFail("hosted-worker JDK bin/java is not executable")
            }
        }
    }
}

private fun parseJdkRelease(bytes: ByteArray): Map<String, String> {
    val text = decodeStrictUtf8(bytes, "hosted-worker JDK release metadata")
    if (!text.endsWith('\n') || '\r' in text || '\u0000' in text) {
        buildContextFail("hosted-worker JDK release metadata is not canonical LF-terminated text")
    }
    val fields = linkedMapOf<String, String>()
    text.dropLast(1).split('\n').forEachIndexed { index, line ->
        val match = JDK_RELEASE_LINE.matchEntire(line)
            ?: buildContextFail("hosted-worker JDK release line ${index + 1} is malformed")
        if (fields.put(match.groupValues[1], match.groupValues[2]) != null) {
            buildContextFail("hosted-worker JDK release contains duplicate fields")
        }
    }
    REQUIRED_JDK_RELEASE_FIELDS.forEach { field ->
        if (field !in fields) buildContextFail("hosted-worker JDK release lacks $field")
    }
    return Collections.unmodifiableMap(fields)
}

private fun requireExactContextShape(
    projection: TreeProjection,
    workerArgumentsSha256: String,
    applicationEntries: List<ApplicationEntry>,
) {
    val paths = projection.entries.map(TreeEntry::relativePath).toSet()
    if (ROOT_RELATIVE_PATH !in paths || JDK_DIRECTORY_NAME !in paths || APP_DIRECTORY_NAME !in paths ||
        APP_LIB_PATH !in paths || WORKER_ARGUMENTS_PATH !in paths ||
        projection.byPath[JDK_DIRECTORY_NAME]?.kind != "directory" ||
        projection.byPath[APP_DIRECTORY_NAME]?.kind != "directory" ||
        projection.byPath[APP_LIB_PATH]?.kind != "directory" ||
        projection.byPath[WORKER_ARGUMENTS_PATH]?.let { entry ->
            entry.kind == "file" && entry.mode == READ_ONLY_FILE_MODE && entry.sha256 == workerArgumentsSha256 &&
                entry.bytes in 1L..MAXIMUM_WORKER_ARGUMENT_BYTES.toLong()
        } != true
    ) buildContextFail("hosted-worker staged build context lacks its fixed roots")
    val rootChildren = paths.filter { path ->
        path != ROOT_RELATIVE_PATH && Path.of(path).parent == null
    }.toSet()
    if (rootChildren != setOf(JDK_DIRECTORY_NAME, APP_DIRECTORY_NAME)) {
        buildContextFail("hosted-worker staged build context contains an unrelated root")
    }
    val appChildren = paths.filter { path -> Path.of(path).parent == Path.of(APP_DIRECTORY_NAME) }.toSet()
    if (appChildren != setOf(APP_LIB_PATH, WORKER_ARGUMENTS_PATH)) {
        buildContextFail("hosted-worker staged application context contains an unrelated root")
    }
    val expectedLibPaths = applicationEntries.associateBy { "$APP_LIB_PATH/${it.logicalName}" }
    val actualLibChildren = paths.filter { path -> Path.of(path).parent == Path.of(APP_LIB_PATH) }.toSet()
    if (actualLibChildren != expectedLibPaths.keys) {
        buildContextFail("hosted-worker staged application library differs from its deployment closure")
    }
    expectedLibPaths.forEach { (path, expected) ->
        val actual = projection.byPath[path]
        if (actual?.kind != "file" || actual.mode != READ_ONLY_FILE_MODE ||
            actual.bytes != expected.bytes || actual.sha256 != expected.sha256
        ) buildContextFail("hosted-worker staged application JAR $path differs from its deployment closure")
    }
}

private class BoundDirectory(
    val path: Path,
    val parentPath: Path,
    val parent: LinuxDescriptor,
    val directory: LinuxDescriptor,
) : AutoCloseable {
    fun requireNamedCurrent(label: String) {
        val parentIdentity = LinuxFilesystemSyscalls.identity(parent.fd)
        val directoryIdentity = LinuxFilesystemSyscalls.identity(directory.fd)
        if (!sameDirectoryIdentity(parentIdentity, parent.identity) ||
            !sameDirectoryIdentity(directoryIdentity, directory.identity)
        ) {
            buildContextFail("$label descriptor identity changed")
        }
        val namedParent = LinuxFilesystemSyscalls.openRoot(parentPath)
        namedParent.use {
            if (!sameDirectoryIdentity(LinuxFilesystemSyscalls.identity(namedParent.fd), parent.identity) ||
                !Files.isSameFile(parentPath, LinuxFilesystemSyscalls.descriptorPath(parent))
            ) buildContextFail("$label parent path changed identity")
        }
        val named = LinuxFilesystemSyscalls.openRoot(path)
        named.use {
            if (!sameDirectoryIdentity(LinuxFilesystemSyscalls.identity(named.fd), directory.identity) ||
                !Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(directory))
            ) buildContextFail("$label path changed identity")
        }
    }

    override fun close() {
        directory.close()
        parent.close()
    }
}

private fun openBoundDirectory(rawPath: Path, label: String): BoundDirectory {
    val path = canonicalDirectory(rawPath, label)
    val parentPath = path.parent ?: buildContextFail("$label must have a parent")
    val parent = LinuxFilesystemSyscalls.openRoot(parentPath)
    var directory: LinuxDescriptor? = null
    try {
        val opened = LinuxFilesystemSyscalls.openRoot(path)
        directory = opened
        if (!Files.isSameFile(parentPath, LinuxFilesystemSyscalls.descriptorPath(parent)) ||
            !Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(opened))
        ) buildContextFail("$label differs from its retained descriptor")
        return BoundDirectory(path, parentPath, parent, opened).also { directory = null }
    } catch (failure: Throwable) {
        directory?.closeSuppressing(failure)
        parent.closeSuppressing(failure)
        throw failure
    }
}

private fun requireEmptyPrivateContext(context: BoundDirectory) {
    requirePrivateContextRoot(context)
    val entries = LinuxFilesystemSyscalls.directoryEntryNames(context.directory, 1)
    if (entries.isNotEmpty()) buildContextFail("hosted-worker build-context root must already be empty")
}

private fun requirePrivateContextRoot(context: BoundDirectory) {
    context.requireNamedCurrent("hosted-worker private build-context root")
    val parent = LinuxFilesystemSyscalls.identity(context.parent.fd)
    val root = LinuxFilesystemSyscalls.identity(context.directory.fd)
    if (!parent.isDirectory || parent.isSymbolicLink || parent.uid != currentUid() ||
        parent.mode.permissions != OWNER_DIRECTORY_MODE
    ) buildContextFail("hosted-worker build-context parent must be an owner-owned mode-0700 directory")
    if (!root.isDirectory || root.isSymbolicLink || root.uid != currentUid() || root.gid != parent.gid ||
        root.mode.permissions != OWNER_DIRECTORY_MODE
    ) buildContextFail("hosted-worker build-context root must be an owner-owned mode-0700 directory")
}

/** Removes only bounded children reached below the still-pinned private context descriptor. */
private fun cleanupPrivateContext(context: BoundDirectory) {
    requirePrivateContextRoot(context)
    val rootMountId = LinuxFilesystemSyscalls.identity(context.directory.fd).mountId
    var removed = 0

    fun removeChildren(directory: LinuxDescriptor, depth: Int) {
        if (depth > MAXIMUM_CONTEXT_CLEANUP_DEPTH) {
            buildContextFail("hosted-worker build-context cleanup exceeds its depth bound")
        }
        val remaining = MAXIMUM_CONTEXT_CLEANUP_ENTRIES - removed
        if (remaining <= 0) buildContextFail("hosted-worker build-context cleanup exceeds its entry bound")
        val names = try {
            LinuxFilesystemSyscalls.directoryEntryNames(directory, remaining + 1)
        } catch (failure: Throwable) {
            buildContextFail("cannot enumerate hosted-worker build-context residue", failure)
        }.sortedWith(FULL_TREE_CODE_POINT_ORDER)
        if (names.size > remaining) {
            buildContextFail("hosted-worker build-context cleanup exceeds its entry bound")
        }
        names.forEach { name ->
            if (removed >= MAXIMUM_CONTEXT_CLEANUP_ENTRIES) {
                buildContextFail("hosted-worker build-context cleanup exceeds its entry bound")
            }
            requireTreeName(name, "hosted-worker build-context cleanup")
            val child = LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)
                ?: buildContextFail("hosted-worker build-context residue disappeared during cleanup")
            child.use {
                val identity = LinuxFilesystemSyscalls.identity(child.fd)
                if (identity.mountId != rootMountId) {
                    buildContextFail("hosted-worker build-context cleanup refuses a mount boundary")
                }
                if (identity.isDirectory && !identity.isSymbolicLink) {
                    if (identity.uid != currentUid() || identity.isRegularFile) {
                        buildContextFail("hosted-worker build-context cleanup refuses an unowned directory")
                    }
                    LinuxFilesystemSyscalls.chmodPinned(child, OWNER_DIRECTORY_MODE)
                    val mutableIdentity = LinuxFilesystemSyscalls.identity(child.fd)
                    if (mutableIdentity.key != identity.key || mutableIdentity.mountId != identity.mountId ||
                        mutableIdentity.uid != identity.uid || mutableIdentity.gid != identity.gid ||
                        mutableIdentity.mode.permissions != OWNER_DIRECTORY_MODE ||
                        !mutableIdentity.isDirectory || mutableIdentity.isRegularFile ||
                        mutableIdentity.isSymbolicLink
                    ) buildContextFail("hosted-worker build-context directory changed while armed for cleanup")
                    LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name).use { opened ->
                        if (!sameIdentity(mutableIdentity, LinuxFilesystemSyscalls.identity(opened.fd))) {
                            buildContextFail("hosted-worker build-context directory changed during cleanup")
                        }
                        removeChildren(opened, depth + 1)
                    }
                    if (removed >= MAXIMUM_CONTEXT_CLEANUP_ENTRIES) {
                        buildContextFail("hosted-worker build-context cleanup exceeds its entry bound")
                    }
                    val terminal = LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)
                        ?: buildContextFail("hosted-worker build-context directory disappeared during cleanup")
                    terminal.use {
                        val terminalIdentity = LinuxFilesystemSyscalls.identity(terminal.fd)
                        if (terminalIdentity.key != identity.key || terminalIdentity.mountId != identity.mountId ||
                            terminalIdentity.uid != identity.uid || terminalIdentity.gid != identity.gid ||
                            terminalIdentity.mode.permissions != OWNER_DIRECTORY_MODE ||
                            !terminalIdentity.isDirectory || terminalIdentity.isRegularFile ||
                            terminalIdentity.isSymbolicLink
                        ) {
                            buildContextFail("hosted-worker build-context directory changed during cleanup")
                        }
                    }
                    LinuxFilesystemSyscalls.removeDirectory(directory.fd, name)
                } else {
                    val terminal = LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)
                        ?: buildContextFail("hosted-worker build-context entry disappeared during cleanup")
                    terminal.use {
                        if (!sameIdentity(identity, LinuxFilesystemSyscalls.identity(terminal.fd))) {
                            buildContextFail("hosted-worker build-context entry changed during cleanup")
                        }
                    }
                    LinuxFilesystemSyscalls.unlink(directory.fd, name)
                }
                removed += 1
            }
        }
        LinuxFilesystemSyscalls.synchronize(directory)
    }

    removeChildren(context.directory, 0)
    if (LinuxFilesystemSyscalls.directoryEntryNames(context.directory, 1).isNotEmpty()) {
        buildContextFail("hosted-worker build-context cleanup left residue")
    }
}

private fun requireRootOwnedJdkAncestors(path: Path) {
    var cursor = path.root ?: buildContextFail("hosted-worker JDK path has no root")
    val segments = listOf(cursor) + path.map { component ->
        cursor = cursor.resolve(component)
        cursor
    }
    segments.forEach { ancestor ->
        val basic = Files.readAttributes(
            ancestor,
            java.nio.file.attribute.BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        val unix = Files.readAttributes(ancestor, "unix:uid,mode", LinkOption.NOFOLLOW_LINKS)
        val uid = (unix.getValue("uid") as Number).toInt()
        val mode = (unix.getValue("mode") as Number).toInt().permissions
        if (!basic.isDirectory || basic.isSymbolicLink || uid != ROOT_UID || mode and UNTRUSTED_WRITE_MODE != 0) {
            buildContextFail("hosted-worker JDK path has an untrusted ancestor: $ancestor")
        }
    }
}

private fun requireDistinctRoots(
    dockerfile: Path,
    applicationRoot: Path,
    jdkRoot: Path,
    contextRoot: Path,
) {
    val directories = listOf(applicationRoot, jdkRoot, contextRoot)
    directories.indices.forEach { left ->
        for (right in left + 1 until directories.size) {
            if (directories[left] == directories[right] || Files.isSameFile(directories[left], directories[right]) ||
                directories[left].startsWith(directories[right]) || directories[right].startsWith(directories[left])
            ) buildContextFail("hosted-worker build-context roots alias or contain one another")
        }
    }
    if (dockerfile.startsWith(contextRoot) || dockerfile.startsWith(jdkRoot) ||
        Files.isSameFile(dockerfile, contextRoot) || Files.isSameFile(dockerfile, jdkRoot)
    ) buildContextFail("hosted-worker Dockerfile aliases a build-context root")
}

private fun discoverApplicationSelection(): ApplicationSelection {
    val codeSource = deploymentCodeSource()
    val configuredReference = System.getProperty(APPLICATION_REFERENCE_PROPERTY)?.takeIf(String::isNotBlank)
    val configuredRoot = System.getProperty(APPLICATION_ROOT_PROPERTY)?.takeIf(String::isNotBlank)
    val development = Files.isDirectory(codeSource, LinkOption.NOFOLLOW_LINKS)
    if (!development && (configuredReference != null || configuredRoot != null)) {
        buildContextFail("installed hosted-worker authority rejects class-path reference overrides")
    }
    if (development && (configuredReference == null || configuredRoot == null)) {
        buildContextFail("development hosted-worker authority lacks its Gradle-pinned class-path reference")
    }
    return if (development) {
        ApplicationSelection(
            canonicalFile(Path.of(checkNotNull(configuredReference)), "configured hosted-worker class-path reference"),
            canonicalDirectory(Path.of(checkNotNull(configuredRoot)), "configured hosted-worker application root"),
            requireLoadedApplication = false,
        )
    } else {
        ApplicationSelection(
            codeSource.parent.resolve(APPLICATION_REFERENCE_FILE),
            codeSource.parent,
            requireLoadedApplication = true,
        )
    }
}

private fun deploymentCodeSource(): Path = try {
    val location = LlvmBehaviorHostedCleanBuildV2InnerWorkerMain::class.java.protectionDomain
        ?.codeSource?.location
        ?: buildContextFail("hosted-worker application has no deployment code source")
    Path.of(location.toURI()).toAbsolutePath().normalize().toRealPath()
} catch (failure: LlvmBehaviorHostedWorkerImageV1BuildContextException) {
    throw failure
} catch (failure: Throwable) {
    buildContextFail("hosted-worker application deployment code source is invalid", failure)
}

private fun canonicalFile(raw: Path, label: String): Path {
    val path = raw.toAbsolutePath().normalize()
    if (path.fileSystem != FileSystems.getDefault() || path.fileName == null || path.parent == null) {
        buildContextFail("$label must be an absolute default-filesystem file")
    }
    val real = try {
        path.toRealPath()
    } catch (failure: Throwable) {
        buildContextFail("$label is unavailable", failure)
    }
    if (real != path || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
        buildContextFail("$label must be a canonical regular file")
    }
    return path
}

private fun canonicalDirectory(raw: Path, label: String): Path {
    val path = raw.toAbsolutePath().normalize()
    if (path.fileSystem != FileSystems.getDefault() || path == Path.of("/") || path.parent == null) {
        buildContextFail("$label must be an absolute non-root default-filesystem directory")
    }
    try {
        requireStableDirectory(path, label)
    } catch (failure: Throwable) {
        buildContextFail("$label is not a stable directory", failure)
    }
    return path
}

private fun requireApplicationFileIdentity(identity: LinuxFileIdentity, label: String) {
    if (!identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink || identity.linkCount != 1 ||
        identity.mode.permissions and UNTRUSTED_WRITE_MODE != 0 ||
        identity.mode.permissions and SPECIAL_PERMISSION_MODE != 0
    ) buildContextFail("$label must be a single-link regular file without untrusted writes")
}

private fun requireTreeIdentity(
    identity: LinuxFileIdentity,
    requiredUid: Int,
    kind: String,
    label: String,
) {
    if (identity.uid != requiredUid) buildContextFail("$label is not owned by uid $requiredUid")
    when (kind) {
        "directory" -> if (!identity.isDirectory || identity.isRegularFile || identity.isSymbolicLink ||
            identity.mode.permissions and (UNTRUSTED_WRITE_MODE or SPECIAL_PERMISSION_MODE) != 0 ||
            identity.mode.permissions and OWNER_READ_EXECUTE_MODE != OWNER_READ_EXECUTE_MODE
        ) buildContextFail("$label is not a trusted directory")
        "file" -> if (!identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink ||
            identity.linkCount != 1 ||
            identity.mode.permissions and (UNTRUSTED_WRITE_MODE or SPECIAL_PERMISSION_MODE) != 0 ||
            identity.mode.permissions and OWNER_READ_MODE == 0
        ) buildContextFail("$label is not a trusted single-link regular file")
        "symlink" -> if (!identity.isSymbolicLink || identity.isDirectory || identity.isRegularFile ||
            identity.linkCount != 1
        ) buildContextFail("$label is not a trusted symbolic link")
        else -> buildContextFail("$label has an unsupported type")
    }
}

private fun requireEntryMatches(entry: TreeEntry, identity: LinuxFileIdentity, label: String) {
    val actualKind = when {
        identity.isDirectory && !identity.isSymbolicLink -> "directory"
        identity.isRegularFile && !identity.isSymbolicLink -> "file"
        identity.isSymbolicLink && !identity.isDirectory && !identity.isRegularFile -> "symlink"
        else -> "special"
    }
    if (actualKind != entry.kind || identity.mode.permissions != entry.mode || identity.uid != entry.uid ||
        identity.gid != entry.gid
    ) buildContextFail("$label changed metadata")
}

private fun treeEntry(
    relative: Path,
    kind: String,
    identity: LinuxFileIdentity,
    bytes: Long = 0L,
    sha256: String = "",
    linkTarget: String = "",
): TreeEntry = TreeEntry(
    relativePath = if (relative.toString().isEmpty()) ROOT_RELATIVE_PATH else relative.toString(),
    kind = kind,
    mode = identity.mode.permissions,
    uid = identity.uid,
    gid = identity.gid,
    bytes = bytes,
    sha256 = sha256,
    linkTarget = linkTarget,
)

private fun treeManifestSha256(entries: List<TreeEntry>): String {
    val digest = MessageDigest.getInstance("SHA-256")
    updateFramed(digest, TREE_MANIFEST_DOMAIN)
    updateFramed(digest, entries.size.toString())
    entries.forEach { entry ->
        updateFramed(digest, entry.relativePath)
        updateFramed(digest, entry.kind)
        updateFramed(digest, entry.mode.toString())
        updateFramed(digest, entry.uid.toString())
        updateFramed(digest, entry.gid.toString())
        updateFramed(digest, entry.bytes.toString())
        updateFramed(digest, entry.sha256)
        updateFramed(digest, entry.linkTarget)
    }
    return digest.digest().toHex()
}

private fun framedSha256(domain: String, values: List<String>): String {
    val digest = MessageDigest.getInstance("SHA-256")
    updateFramed(digest, domain)
    values.forEach { updateFramed(digest, it) }
    return digest.digest().toHex()
}

private fun updateFramed(digest: MessageDigest, value: String) {
    val bytes = value.toByteArray(Charsets.UTF_8)
    digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putLong(bytes.size.toLong()).array())
    digest.update(bytes)
}

private fun hashDescriptor(descriptor: LinuxDescriptor, expectedBytes: Long, label: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val sink = object : OutputStream() {
        override fun write(value: Int) {
            digest.update(value.toByte())
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            digest.update(bytes, offset, length)
        }
    }
    val copied = try {
        LinuxFilesystemSyscalls.copyReadableTo(descriptor, sink, expectedBytes)
    } catch (failure: Throwable) {
        buildContextFail("cannot hash $label", failure)
    }
    if (copied != expectedBytes) buildContextFail("$label changed length while hashed")
    return digest.digest().toHex()
}

private fun readStableSymbolicLink(
    parent: LinuxDescriptor,
    name: String,
    descriptor: LinuxDescriptor,
    label: String,
): String {
    val before = LinuxFilesystemSyscalls.identity(descriptor.fd)
    val path = LinuxFilesystemSyscalls.descriptorPath(parent).resolve(name)
    val target = try {
        Files.readSymbolicLink(path).toString()
    } catch (failure: Throwable) {
        buildContextFail("cannot read $label symbolic link $name", failure)
    }
    val named = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)
        ?: buildContextFail("$label symbolic link $name disappeared")
    named.use {
        val after = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!sameIdentity(before, after) || !sameIdentity(after, LinuxFilesystemSyscalls.identity(named.fd))) {
            buildContextFail("$label symbolic link $name changed identity")
        }
    }
    return target
}

private fun openTreeRegular(parent: LinuxDescriptor, name: String): LinuxDescriptor {
    val opened = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
        ?: buildContextFail("hosted-worker JDK entry $name is unavailable")
    val identity = LinuxFilesystemSyscalls.identity(opened.fd)
    if (!identity.isRegularFile || identity.isSymbolicLink) {
        opened.close()
        buildContextFail("hosted-worker JDK entry $name is not a regular file")
    }
    return opened
}

private fun requireTreeName(name: String, label: String) {
    val bytes = name.toByteArray(Charsets.UTF_8)
    if (name.isEmpty() || name == "." || name == ".." || '/' in name || '\u0000' in name ||
        bytes.size !in 1..MAXIMUM_TREE_COMPONENT_BYTES || name.any { it.code < 0x20 || it.code == 0x7f }
    ) buildContextFail("$label contains an invalid entry name")
}

private fun requireTreePath(path: Path, label: String) {
    if (path.isAbsolute || path.nameCount > MAXIMUM_JDK_DEPTH ||
        path.toString().toByteArray(Charsets.UTF_8).size > MAXIMUM_TREE_PATH_BYTES
    ) buildContextFail("$label contains an excessive relative path")
}

private fun setNormalizedTimestamp(descriptor: LinuxDescriptor) {
    try {
        Files.setLastModifiedTime(
            LinuxFilesystemSyscalls.descriptorPath(descriptor),
            NORMALIZED_TIMESTAMP,
        )
    } catch (failure: Throwable) {
        buildContextFail("cannot normalize hosted-worker build-context timestamp", failure)
    }
}

private fun setNormalizedSymlinkTimestamp(path: Path) {
    try {
        val view = Files.getFileAttributeView(
            path,
            BasicFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        ) ?: buildContextFail("hosted-worker JDK symlink lacks basic attributes")
        view.setTimes(NORMALIZED_TIMESTAMP, NORMALIZED_TIMESTAMP, null)
    } catch (failure: LlvmBehaviorHostedWorkerImageV1BuildContextException) {
        throw failure
    } catch (failure: Throwable) {
        buildContextFail("cannot normalize hosted-worker JDK symlink timestamp", failure)
    }
}

private fun sameIdentity(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    left.key == right.key && left.mountId == right.mountId && left.mode == right.mode &&
        left.uid == right.uid && left.gid == right.gid && left.linkCount == right.linkCount &&
        left.isRegularFile == right.isRegularFile && left.isDirectory == right.isDirectory &&
        left.isSymbolicLink == right.isSymbolicLink

private fun sameDirectoryIdentity(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    left.key == right.key && left.mountId == right.mountId && left.mode == right.mode &&
        left.uid == right.uid && left.gid == right.gid && left.isDirectory && right.isDirectory &&
        !left.isRegularFile && !right.isRegularFile && !left.isSymbolicLink && !right.isSymbolicLink

private fun parseReferencePrimitive(root: JsonObject, name: String): JsonPrimitive =
    root[name] as? JsonPrimitive
        ?: buildContextFail("LLVM hosted-worker class-path reference field $name is invalid")

private fun referenceString(root: JsonObject, name: String): String {
    val primitive = parseReferencePrimitive(root, name)
    if (!primitive.isString) buildContextFail("LLVM hosted-worker class-path reference field $name is not a string")
    return primitive.content
}

private fun referenceLong(root: JsonObject, name: String): Long {
    val primitive = parseReferencePrimitive(root, name)
    if (primitive.isString || primitive.content.any { it in ".eE" }) {
        buildContextFail("LLVM hosted-worker class-path reference field $name is not an integer")
    }
    return primitive.longOrNull
        ?: buildContextFail("LLVM hosted-worker class-path reference field $name is invalid")
}

private fun requireReferenceString(root: JsonObject, name: String, expected: String) {
    if (referenceString(root, name) != expected) {
        buildContextFail("LLVM hosted-worker class-path reference field $name differs")
    }
}

private fun requireReferenceInteger(root: JsonObject, name: String, expected: Long) {
    if (referenceLong(root, name) != expected) {
        buildContextFail("LLVM hosted-worker class-path reference field $name differs")
    }
}

private fun decodeStrictUtf8(bytes: ByteArray, label: String): String = try {
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (failure: Throwable) {
    buildContextFail("$label is not valid UTF-8", failure)
}

private fun Int.toBoundedInt(label: String): Int = this

private fun Long.toBoundedInt(label: String): Int {
    if (this !in 0L..Int.MAX_VALUE.toLong()) buildContextFail("$label exceeds the JVM byte bound")
    return toInt()
}

private fun display(relative: Path): String = if (relative.toString().isEmpty()) ROOT_RELATIVE_PATH else relative.toString()

private fun ByteArray.toHex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private fun currentUid(): Int =
    (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private fun AutoCloseable.closeSuppressing(failure: Throwable) {
    try {
        close()
    } catch (closeFailure: Throwable) {
        if (closeFailure !== failure) failure.addSuppressed(closeFailure)
    }
}

private inline fun <T> translateBuildContextFailure(label: String, action: () -> T): T = try {
    action()
} catch (failure: LlvmBehaviorHostedWorkerImageV1BuildContextException) {
    throw failure
} catch (failure: Throwable) {
    throw LlvmBehaviorHostedWorkerImageV1BuildContextException(
        "$label failed: ${failure.message ?: failure.javaClass.simpleName}",
        failure,
    )
}

private fun buildContextFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorHostedWorkerImageV1BuildContextException(message, cause)

private const val EXPECTED_WORKER_DOCKERFILE_SHA256 =
    "fee734ad2acdf083e1cc71a286255af76a14b3175016a888a1761060acb143cf"
private const val APPLICATION_REFERENCE_FILE = "llvm-behavior-hosted-worker-classpath-reference-v1.json"
private const val APPLICATION_REFERENCE_PROVIDER =
    "llvm-behavior-hosted-worker-deployment-classpath-reference-v1"
private const val APPLICATION_REFERENCE_PROPERTY =
    "decompengine.oracle.behavior.hostedWorkerClasspathReference"
private const val APPLICATION_ROOT_PROPERTY = "decompengine.oracle.behavior.hostedWorkerClasspathRoot"
private const val WORKER_MAIN_CLASS =
    "decompengine/oracle/behavior/LlvmBehaviorHostedCleanBuildV2InnerWorkerMain.class"
private const val WORKER_MAIN_CLASS_NAME =
    "decompengine.oracle.behavior.LlvmBehaviorHostedCleanBuildV2InnerWorkerMain"
private const val JDK_DIRECTORY_NAME = "jdk"
private const val APP_DIRECTORY_NAME = "app"
private const val APP_LIB_DIRECTORY_NAME = "lib"
private const val APP_LIB_PATH = "app/lib"
private const val WORKER_ARGUMENTS_FILE_NAME = "worker.args"
private const val WORKER_ARGUMENTS_PATH = "app/worker.args"
private const val CONTAINER_APPLICATION_LIB_DIRECTORY = "/decomp-app/lib"
private const val UNIX_CLASS_PATH_SEPARATOR = ":"
private const val TAR_DOCKERFILE_NAME = "Dockerfile"
private const val ROOT_RELATIVE_PATH = "."
private const val JDK_RELEASE_FILE = "release"
private const val JDK_JAVA_FILE = "bin/java"
private const val ROOT_UID = 0
private const val OWNER_DIRECTORY_MODE = 448
private const val OWNER_READ_MODE = 256
private const val OWNER_READ_EXECUTE_MODE = 320
private const val READ_EXECUTE_DIRECTORY_MODE = 493
private const val READ_ONLY_FILE_MODE = 292
private const val UNTRUSTED_WRITE_MODE = 18
private const val SPECIAL_PERMISSION_MODE = 3584
private const val ANY_EXECUTE_MODE = 73
private const val MAXIMUM_WORKER_DOCKERFILE_BYTES = 16L * 1024L
private const val MAXIMUM_APPLICATION_REFERENCE_BYTES = 1024L * 1024L
private const val MAXIMUM_APPLICATION_ENTRIES = 512
private const val MAXIMUM_APPLICATION_JAR_ENTRIES = 100_000
private const val MAXIMUM_APPLICATION_JAR_AGGREGATE_ENTRIES = 500_000
private const val MAXIMUM_APPLICATION_CENTRAL_DIRECTORY_BYTES = 64L * 1024L * 1024L
private const val MAXIMUM_APPLICATION_MANIFEST_BYTES = 2 * 1024 * 1024
private const val MAXIMUM_APPLICATION_MANIFEST_COMPRESSED_BYTES = 2L * 1024L * 1024L
private const val MAXIMUM_APPLICATION_ENTRY_BYTES = 1024L * 1024L * 1024L
private const val MAXIMUM_APPLICATION_AGGREGATE_BYTES = 2L * 1024L * 1024L * 1024L
private const val MAXIMUM_WORKER_ARGUMENT_BYTES = 256 * 1024
private const val MAXIMUM_JDK_DEPTH = 32
private const val MAXIMUM_JDK_ENTRIES = 20_000
private const val MAXIMUM_JDK_ENTRY_BYTES = 512L * 1024L * 1024L
private const val MAXIMUM_JDK_AGGREGATE_BYTES = 2L * 1024L * 1024L * 1024L
private const val MAXIMUM_JDK_RELEASE_BYTES = 64L * 1024L
private const val MAXIMUM_TREE_COMPONENT_BYTES = 255
private const val MAXIMUM_TREE_PATH_BYTES = 4096
private const val MAXIMUM_SYMLINK_TARGET_BYTES = 4096
private const val MAXIMUM_CONTEXT_CLEANUP_DEPTH = MAXIMUM_JDK_DEPTH + 2
private const val MAXIMUM_CONTEXT_CLEANUP_ENTRIES =
    MAXIMUM_JDK_ENTRIES + MAXIMUM_APPLICATION_ENTRIES + 8
private const val MAXIMUM_TAR_ENTRY_BYTES = MAXIMUM_APPLICATION_ENTRY_BYTES
private const val TAR_BLOCK_BYTES = 512
private const val TAR_COPY_BUFFER_BYTES = 1024 * 1024
private const val TAR_READ_ONLY_MODE = 292
private const val TAR_READ_EXECUTE_MODE = 365
private const val TAR_SYMBOLIC_LINK_MODE = 511
private const val TAR_OWNER_ID = 0L
private const val TAR_REGULAR_FILE_TYPE: Byte = 48
private const val TAR_SYMBOLIC_LINK_TYPE: Byte = 50
private const val TAR_DIRECTORY_TYPE: Byte = 53
private const val TAR_PAX_TYPE: Byte = 120
private const val ZIP_END_MINIMUM_BYTES = 22
private const val ZIP_END_MAXIMUM_SEARCH_BYTES = ZIP_END_MINIMUM_BYTES + 65_535
private const val ZIP_END_SIGNATURE = 0x06054b50
private const val ZIP_CENTRAL_FIXED_BYTES = 46
private const val ZIP_CENTRAL_SIGNATURE = 0x02014b50
private const val ZIP_EXTRA_FIXED_BYTES = 4
private const val ZIP64_EXTRA_IDENTIFIER = 0x0001
private const val ZIP64_END_LOCATOR_BYTES = 20
private const val ZIP64_END_LOCATOR_SIGNATURE = 0x07064b50
private const val ZIP16_SENTINEL = 0xffff
private const val ZIP32_SENTINEL = 0xffff_ffffL
private const val NORMALIZED_TIMESTAMP_SECONDS = 1_779_182_222L
private const val TREE_MANIFEST_DOMAIN = "llvm-behavior-hosted-worker-tree-manifest-v1"
private const val CONTEXT_PATH_DOMAIN = "llvm-behavior-hosted-worker-context-path-v1"

private val NORMALIZED_TIMESTAMP = FileTime.fromMillis(NORMALIZED_TIMESTAMP_SECONDS * 1000L)
private val SHA256 = Regex("[0-9a-f]{64}")
private val LOGICAL_JAR_NAME = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,250}\\.jar")
private val VERSIONED_WORKER_MAIN_CLASS = Regex(
    "META-INF/versions/[1-9][0-9]*/${Regex.escape(WORKER_MAIN_CLASS)}",
)
private val JDK_RELEASE_LINE = Regex("([A-Z][A-Z0-9_]*)=\\\"([^\\\"\\r\\n]*)\\\"")
private val JAVA_21_VERSION = Regex("21(?:\\.[0-9]+)*(?:[-+][A-Za-z0-9._+-]+)?")
private val REQUIRED_JDK_RELEASE_FIELDS = setOf("JAVA_VERSION", "OS_NAME", "OS_ARCH", "IMAGE_TYPE")
private val APPLICATION_REFERENCE_FIELDS = setOf("closureSha256", "entries", "provider", "schemaVersion")
private val APPLICATION_ENTRY_FIELDS = setOf("bytes", "logicalName", "sha256")
private val APPLICATION_REFERENCE_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_APPLICATION_REFERENCE_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_APPLICATION_REFERENCE_BYTES.toInt(),
    maximumDepth = 8,
    maximumNodes = 4096,
    maximumStringBytes = 512,
    maximumTotalStringBytes = 512 * 1024,
)
