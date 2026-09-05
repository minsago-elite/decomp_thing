package decompengine.oracle.fulltree

import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxResourceLimitException
import decompengine.acp.LinuxSyscallException
import decompengine.acp.PinnedSecurityExecutable
import decompengine.acp.PinnedSystemdBusEndpoint
import decompengine.acp.deletePrivateTreeContents
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Duration
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.system.exitProcess
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class FullTreeFunctionObservationIsolationException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/**
 * A failed generic BOOT launch with an explicit cleanup outcome for its host controller.
 *
 * [preAttachmentRollbackSafe] is true only when no process launch was attempted and all private
 * resources closed, or the retained boundary completed its exact-name/cgroup absence proof and
 * all private resources closed. A missing returned owner alone never implies this outcome.
 */
internal class KotlinSystemdCgroupBootLaunchException(
    message: String,
    cause: Throwable,
    val preAttachmentRollbackSafe: Boolean,
) : IllegalArgumentException(message, cause)

internal enum class FullTreeFunctionObservationLaunchFaultPoint {
    BEFORE_INITIAL_UNIT_ABSENCE,
    BEFORE_FINAL_UNIT_ABSENCE,
    AFTER_FINAL_UNIT_ABSENCE,
    AFTER_PROCESS_START_RETURNED,
    AFTER_SCOPE_ATTACHED,
    BEFORE_DESTRUCTIVE_CLEANUP,
    BEFORE_FINAL_CLEANUP_ABSENCE,
}

internal fun interface FullTreeFunctionObservationLaunchFaultInjector {
    fun at(point: FullTreeFunctionObservationLaunchFaultPoint, unitName: String)
}

/** Observes only pinned systemctl invocations; it does not observe launch or process signals. */
internal fun interface FullTreeFunctionObservationSystemctlCommandObserver {
    fun beforeCommand(unitName: String, arguments: List<String>)
}

/** Observes only pinned busctl invocations; it does not observe launch or process signals. */
internal fun interface FullTreeFunctionObservationBusctlCommandObserver {
    fun beforeCommand(unitName: String, arguments: List<String>)
}

/** Explicit fail-only test seam; the production entry point never accepts or constructs one. */
internal class FullTreeFunctionObservationLaunchTestHooks(
    val faultInjector: FullTreeFunctionObservationLaunchFaultInjector? = null,
    val systemctlCommandObserver: FullTreeFunctionObservationSystemctlCommandObserver? = null,
    val forceProcessStartFailure: Boolean = false,
) {
    init {
        require(faultInjector != null || systemctlCommandObserver != null || forceProcessStartFailure) {
            "function-observation launch test hooks cannot be empty"
        }
    }
}

/** Exact authenticated files reloaded by the isolated Kotlin worker. */
internal data class FullTreeFunctionObservationScopeFiles(
    val scope: Path,
    val sourceLock: Path,
    val artifactManifest: Path,
)

/** One provisioned root-owned runtime tree mounted read-only at an exact synthetic-root path. */
internal data class FullTreeFunctionObservationRuntimeMount(
    val source: Path,
    val destination: Path = source,
    val expectedManifestSha256: String,
) {
    init {
        require(source.isAbsolute && source.normalize() == source)
        require(destination.isAbsolute && destination.normalize() == destination && destination != Path.of("/"))
        require(expectedManifestSha256.matches(Regex("[0-9a-f]{64}")))
    }
}

/** One regular-file JVM class-path artifact authenticated before it is privately snapshotted. */
internal data class FullTreeFunctionObservationClassPathEntry(
    val path: Path,
    val expectedSha256: String,
) {
    init {
        require(path.isAbsolute && path.normalize() == path)
        require(expectedSha256.matches(Regex("[0-9a-f]{64}")))
    }
}

/**
 * Trusted host executables used to put one Kotlin derivation in a cgroup and read-only mount view.
 *
 * Digests are deliberately caller supplied: selecting whatever happens to occupy one of these
 * paths at runtime would make executable pinning circular. Each deployment-owned JVM class-path
 * file is separately authenticated, privately snapshotted, and mounted read-only.
 *
 * [canonicalSha256] commits to this declared configuration; it is not proof that the paths contain
 * those bytes and does not cover derived resource limits. Runtime descriptor pinning supplies the
 * former, and a later operation resource contract must supply the latter. Any semantic change to
 * this encoding, its ordering, an entry point, or a protocol requires a schema/provider bump.
 */
internal class FullTreeFunctionObservationIsolationConfiguration(
    val javaExecutable: Path,
    val javaRuntime: FullTreeFunctionObservationRuntimeMount,
    systemLibraryMounts: List<FullTreeFunctionObservationRuntimeMount>,
    val bubblewrapExecutable: Path,
    val resourceLimiterExecutable: Path,
    val scopeSupervisorExecutable: Path,
    val scopeInspectorExecutable: Path,
    val systemdBusControllerExecutable: Path,
    val systemdUserRuntimeDirectory: Path,
    workerClassPath: List<FullTreeFunctionObservationClassPathEntry>,
    val expectedJavaSha256: String,
    val expectedBubblewrapSha256: String,
    val expectedResourceLimiterSha256: String,
    val expectedScopeSupervisorSha256: String,
    val expectedScopeInspectorSha256: String,
    val expectedSystemdBusControllerSha256: String,
) {
    val systemLibraryMounts: List<FullTreeFunctionObservationRuntimeMount> =
        java.util.List.copyOf(systemLibraryMounts)
    val workerClassPath: List<FullTreeFunctionObservationClassPathEntry> =
        java.util.List.copyOf(workerClassPath)

    /** Canonical identity consumed by the durable operation binding; never caller supplied. */
    val canonicalSha256: String by lazy {
        OracleArtifacts.sha256(canonicalBytes())
    }

    init {
        listOf(
            javaExecutable,
            bubblewrapExecutable,
            resourceLimiterExecutable,
            scopeSupervisorExecutable,
            scopeInspectorExecutable,
            systemdBusControllerExecutable,
            systemdUserRuntimeDirectory,
        ).forEach { path ->
            require(path.isAbsolute && path.normalize() == path) {
                "function-observation isolation paths must be absolute and normalized"
            }
        }
        require(javaExecutable.startsWith(javaRuntime.source)) {
            "function-observation Java executable must belong to its authenticated runtime"
        }
        require(systemLibraryMounts.isNotEmpty() && systemLibraryMounts.size <= MAXIMUM_RUNTIME_MOUNTS)
        require(workerClassPath.isNotEmpty() && workerClassPath.size <= MAXIMUM_CLASSPATH_ENTRIES)
        val runtimeMounts = listOf(javaRuntime) + systemLibraryMounts
        require(runtimeMounts.none { mount ->
            pathsOverlap(mount.source, systemdUserRuntimeDirectory) ||
                pathsOverlap(mount.destination, systemdUserRuntimeDirectory)
        }) { "function-observation runtime must not expose the systemd session runtime" }
        runtimeMounts.forEachIndexed { index, mount ->
            require(runtimeMounts.drop(index + 1).none { other ->
                pathsOverlap(mount.destination, other.destination)
            }) { "function-observation runtime mount destinations must not overlap" }
        }
        listOf(
            expectedJavaSha256,
            expectedBubblewrapSha256,
            expectedResourceLimiterSha256,
            expectedScopeSupervisorSha256,
            expectedScopeInspectorSha256,
            expectedSystemdBusControllerSha256,
        ).forEach { digest -> require(digest.matches(SHA256)) }
    }

    internal fun canonicalBytesForTest(): ByteArray = canonicalBytes()

    private fun canonicalBytes(): ByteArray = OracleJson.canonicalBytes(
        JsonObject(
            mapOf(
                "bubblewrapExecutable" to JsonPrimitive(bubblewrapExecutable.toString()),
                "expectedBubblewrapSha256" to JsonPrimitive(expectedBubblewrapSha256),
                "expectedJavaSha256" to JsonPrimitive(expectedJavaSha256),
                "expectedResourceLimiterSha256" to JsonPrimitive(expectedResourceLimiterSha256),
                "expectedScopeInspectorSha256" to JsonPrimitive(expectedScopeInspectorSha256),
                "expectedScopeSupervisorSha256" to JsonPrimitive(expectedScopeSupervisorSha256),
                "expectedSystemdBusControllerSha256" to
                    JsonPrimitive(expectedSystemdBusControllerSha256),
                "javaExecutable" to JsonPrimitive(javaExecutable.toString()),
                "javaRuntime" to javaRuntime.canonicalIdentity(),
                "nativeLibraryProfileSha256" to JsonPrimitive(OracleNativeLibraries.policySha256),
                "producerConfigurationSha256" to
                    JsonPrimitive(FullTreeFunctionObservations.configurationSha256),
                "provider" to JsonPrimitive(ISOLATION_CONFIGURATION_PROVIDER),
                "resourceLimiterExecutable" to JsonPrimitive(resourceLimiterExecutable.toString()),
                "schemaVersion" to JsonPrimitive(ISOLATION_CONFIGURATION_SCHEMA_VERSION),
                "scopeInspectorExecutable" to JsonPrimitive(scopeInspectorExecutable.toString()),
                "scopeSupervisorExecutable" to JsonPrimitive(scopeSupervisorExecutable.toString()),
                "supervisorEntryPoint" to
                    JsonPrimitive(FullTreeFunctionObservationIsolatedSupervisor::class.java.name),
                "supervisorProtocolVersion" to JsonPrimitive(SUPERVISOR_PROTOCOL_VERSION),
                "systemLibraryMounts" to JsonArray(systemLibraryMounts.map { it.canonicalIdentity() }),
                "systemdUserRuntimeDirectory" to JsonPrimitive(systemdUserRuntimeDirectory.toString()),
                "systemdBusControllerExecutable" to
                    JsonPrimitive(systemdBusControllerExecutable.toString()),
                "workerClassPath" to JsonArray(
                    workerClassPath.map { entry ->
                        JsonObject(
                            mapOf(
                                "expectedSha256" to JsonPrimitive(entry.expectedSha256),
                                "path" to JsonPrimitive(entry.path.toString()),
                            ),
                        )
                    },
                ),
                "workerEntryPoint" to
                    JsonPrimitive(FullTreeFunctionObservationIsolatedWorker::class.java.name),
                "workerProtocolVersion" to JsonPrimitive(WORKER_PROTOCOL_VERSION),
            ),
        ),
        ISOLATION_CONFIGURATION_JSON_LIMITS,
    )
}

private fun FullTreeFunctionObservationRuntimeMount.canonicalIdentity(): JsonObject = JsonObject(
    mapOf(
        "destination" to JsonPrimitive(destination.toString()),
        "expectedManifestSha256" to JsonPrimitive(expectedManifestSha256),
        "source" to JsonPrimitive(source.toString()),
    ),
)

/**
 * Provisioning helper for a root-owned runtime directory.
 *
 * Root ownership is the content trust root, as it is for the ACP launcher closure. The manifest is
 * nevertheless caller-pinned and binds every entry's relative name, type, mode, owner, size,
 * timestamp, and symlink target. Regular-file contents are not re-hashed because an unprivileged
 * caller cannot replace bytes anywhere in the recursively non-group/world-writable closure.
 */
internal fun calculateFullTreeObservationRuntimeManifestSha256(source: Path): String {
    val normalized = source.toAbsolutePath().normalize()
    if (normalized == Path.of("/") || normalized.toRealPath() != normalized) {
        isolationFail("isolated runtime root must be a canonical non-root directory")
    }
    requireRootOwnedRuntimeAncestors(normalized)
    val rootAttributes = Files.readAttributes(
        normalized,
        java.nio.file.attribute.BasicFileAttributes::class.java,
        LinkOption.NOFOLLOW_LINKS,
    )
    if (!rootAttributes.isDirectory || rootAttributes.isSymbolicLink) {
        isolationFail("isolated runtime root must be a real directory")
    }
    val entries = Files.walk(normalized, MAXIMUM_RUNTIME_TREE_DEPTH).use { stream ->
        stream.limit(MAXIMUM_RUNTIME_TREE_ENTRIES.toLong() + 1L).toList()
    }
    if (entries.size > MAXIMUM_RUNTIME_TREE_ENTRIES) {
        isolationFail("isolated runtime root exceeds its entry bound")
    }
    entries.filter { path ->
        normalized.relativize(path).nameCount == MAXIMUM_RUNTIME_TREE_DEPTH &&
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
    }.forEach { boundary ->
        Files.newDirectoryStream(boundary).use { children ->
            if (children.iterator().hasNext()) isolationFail("isolated runtime root exceeds its depth bound")
        }
    }
    val digest = MessageDigest.getInstance("SHA-256")
    entries.sortedBy { normalized.relativize(it).toString() }.forEach { path ->
        val attributes = Files.readAttributes(
            path,
            java.nio.file.attribute.BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        val type = when {
            attributes.isRegularFile -> "file"
            attributes.isDirectory -> "directory"
            attributes.isSymbolicLink -> "symlink"
            else -> isolationFail("isolated runtime root contains a special file")
        }
        val uid = (Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
        val mode = (Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt() and 0x1ff
        if (uid != 0 || (!attributes.isSymbolicLink && mode and UNTRUSTED_RUNTIME_WRITE_MODE != 0)) {
            isolationFail("isolated runtime root contains an untrusted writable entry")
        }
        val relative = if (path == normalized) "." else normalized.relativize(path).toString()
        val target = if (attributes.isSymbolicLink) Files.readSymbolicLink(path).toString() else ""
        digest.update(
            (
                "$relative\u0000$type\u0000$mode\u0000$uid\u0000${attributes.size()}\u0000" +
                    "${attributes.lastModifiedTime().toMillis()}\u0000$target\u0000"
                ).toByteArray(Charsets.UTF_8),
        )
    }
    return digest.digest().hex()
}

private fun requireRootOwnedRuntimeAncestors(source: Path) {
    var current = source.parent
    while (current != null) {
        val attributes = Files.readAttributes(
            current,
            java.nio.file.attribute.BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        val uid = (Files.getAttribute(current, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
        val mode = (Files.getAttribute(current, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt() and 0x1ff
        if (
            !attributes.isDirectory || attributes.isSymbolicLink || uid != 0 ||
            mode and UNTRUSTED_RUNTIME_WRITE_MODE != 0
        ) isolationFail("isolated runtime root has an untrusted ancestor")
        current = current.parent
    }
}

private fun pathsOverlap(first: Path, second: Path): Boolean =
    first == second || first.startsWith(second) || second.startsWith(first)

private class AuthenticatedObservationRuntime private constructor(
    private val runtimeMounts: List<Pair<FullTreeFunctionObservationRuntimeMount, String>>,
    private val classPath: List<Pair<FullTreeFunctionObservationClassPathEntry, StableControlFile>>,
    private val nativeDirectory: Path,
) : AutoCloseable {
    val classPathBytes: Long = classPath.fold(0L) { total, (_, guard) ->
        addExact(total, guard.size, "authenticated class-path byte count")
    }

    fun materializeClassPath(runTree: ObservationRunTreeAccess): MaterializedObservationClassPath =
        runTree.withPinnedDescriptor { descriptor ->
            materializeObservationClassPath(runTree.path, descriptor, classPath)
        }

    /** Reauthenticates, but never rewrites, the class-path snapshot in a cold BOOT run tree. */
    fun authenticateExistingClassPathAtBoot(
        runTree: ObservationRunTreeAccess,
    ): MaterializedObservationClassPath {
        verify("before cold materialized class-path authentication")
        val paths = classPath.indices.map { index ->
            runTree.path.resolve(RUNTIME_DIRECTORY).resolve("classpath-$index.jar")
        }
        val expected = classPath.map { (entry, guard) -> guard.size to entry.expectedSha256 }
        return MaterializedObservationClassPath(paths, expected).also { materialized ->
            materialized.authenticatePreparedLayout(runTree, listOf(BOOT_FILE))
            materialized.verify("after cold materialized class-path authentication")
        }
    }

    fun mounts(): List<FullTreeFunctionObservationRuntimeMount> = runtimeMounts.map { it.first }

    fun verify(label: String) {
        OracleNativeLibraries.requireCurrent(nativeDirectory, classPath.map { it.second.authenticatedSha256 })
        runtimeMounts.forEach { (mount, expected) ->
            if (calculateFullTreeObservationRuntimeManifestSha256(mount.source) != expected) {
                isolationFail("isolated runtime mount changed $label: ${mount.source}")
            }
        }
        classPath.forEachIndexed { index, (entry, guard) ->
            if (guard.sha256(label = "isolated class-path entry $index $label") != entry.expectedSha256) {
                isolationFail("isolated class-path entry digest changed $label")
            }
            guard.verifyUnchanged("isolated class-path entry $index $label")
        }
    }

    override fun close() {
        var failure: Throwable? = null
        classPath.asReversed().forEach { (_, guard) ->
            runCatching { guard.close() }.exceptionOrNull()?.let { closeFailure ->
                if (failure == null) failure = closeFailure else if (closeFailure !== failure) {
                    failure.addSuppressed(closeFailure)
                }
            }
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(configuration: FullTreeFunctionObservationIsolationConfiguration): AuthenticatedObservationRuntime {
            val mounts = listOf(configuration.javaRuntime) + configuration.systemLibraryMounts
            mounts.forEachIndexed { index, mount ->
                mounts.drop(index + 1).forEach { other ->
                    if (pathsOverlap(mount.destination, other.destination)) {
                        isolationFail("isolated runtime mount destinations overlap")
                    }
                }
            }
            val verifiedMounts = mounts.map { mount ->
                val actual = calculateFullTreeObservationRuntimeManifestSha256(mount.source)
                if (actual != mount.expectedManifestSha256) {
                    isolationFail("isolated runtime manifest differs from its provisioned digest")
                }
                mount to actual
            }
            val opened = ArrayDeque<StableControlFile>()
            try {
                var total = 0L
                val classPath = configuration.workerClassPath.mapIndexed { index, entry ->
                    val remaining = MAXIMUM_AUTHENTICATED_CLASSPATH_BYTES - total
                    if (remaining <= 0L) isolationFail("authenticated class path exceeds its aggregate byte bound")
                    val guard = StableControlFile.open(
                        entry.path,
                        minOf(remaining, MAXIMUM_CLASSPATH_ENTRY_BYTES),
                        "isolated class-path entry $index",
                    ).also(opened::addFirst)
                    val digest = guard.sha256(label = "isolated class-path entry $index at authorization")
                    if (digest != entry.expectedSha256) {
                        isolationFail("isolated class-path entry differs from its provisioned digest")
                    }
                    total = addExact(total, guard.size, "authenticated class-path byte count")
                    entry to guard
                }
                val nativeDirectory = configuration.javaRuntime.source.resolve(OracleNativeLibraries.relativeDirectory)
                OracleNativeLibraries.requireCurrent(nativeDirectory, classPath.map { it.second.authenticatedSha256 })
                opened.clear()
                return AuthenticatedObservationRuntime(verifiedMounts, classPath, nativeDirectory)
            } catch (failure: Throwable) {
                opened.forEach { guard -> runCatching { guard.close() }.exceptionOrNull()?.let(failure::addSuppressed) }
                throw failure
            }
        }
    }
}

private data class PreparedObservationRunLayout(
    val root: LinuxFileIdentity,
    val scratch: LinuxFileIdentity,
    val temporary: LinuxFileIdentity,
    val runtime: LinuxFileIdentity,
    val classPath: List<LinuxFileIdentity>,
)

private class MaterializedObservationClassPath(
    val paths: List<Path>,
    private val expected: List<Pair<Long, String>>,
) {
    val encoded: String = validatedClassPath(paths)
    private var preparedLayout: PreparedObservationRunLayout? = null

    fun verify(label: String) {
        paths.zip(expected).forEachIndexed { index, (path, sizeAndDigest) ->
            val (size, digest) = sizeAndDigest
            StableControlFile.open(path, size, "materialized class-path entry $index").use { guard ->
                if (guard.size != size || guard.sha256(label = "materialized class path $label") != digest) {
                    isolationFail("materialized class-path entry changed $label")
                }
                guard.verifyUnchanged("materialized class-path entry $index $label")
            }
        }
    }

    @Synchronized
    fun authenticatePreparedLayout(
        runTree: ObservationRunTreeAccess,
        rootFiles: List<String> = emptyList(),
    ) {
        check(preparedLayout == null) { "prepared class-path layout was already authenticated" }
        preparedLayout = runTree.withPinnedDescriptor { root ->
            authenticatePreparedObservationRunLayout(
                runTree.path,
                root,
                paths,
                expected,
                rootFiles = rootFiles,
                retained = null,
            )
        }
    }

    @Synchronized
    fun requirePreparedLayout(
        runTree: ObservationRunTreeAccess,
        rootFiles: List<String> = emptyList(),
    ) {
        val retained = preparedLayout
            ?: isolationFail("prepared class-path layout has no authenticated inode snapshot")
        val current = runTree.withPinnedDescriptor { root ->
            authenticatePreparedObservationRunLayout(
                runTree.path,
                root,
                paths,
                expected,
                rootFiles,
                retained,
            )
        }
        if (current != retained) {
            isolationFail("prepared class-path inode layout changed")
        }
    }
}

/**
 * Authenticates one point-in-time ext4 production layout through pinned descriptors and records
 * inode identities for comparison by later point-in-time validation. Logical size and content are
 * rechecked separately because LinuxFileIdentity intentionally contains neither size nor
 * timestamps. This does not exclude a cooperating same-UID writer; deployment-level separation of
 * the oracle and ACP principals remains mandatory for that stronger property.
 */
private fun authenticatePreparedObservationRunLayout(
    runPath: Path,
    root: LinuxDescriptor,
    classPathPaths: List<Path>,
    classPathExpected: List<Pair<Long, String>>,
    rootFiles: List<String>,
    retained: PreparedObservationRunLayout?,
): PreparedObservationRunLayout {
    if (!runPath.isAbsolute || runPath.normalize() != runPath || runPath.parent == null) {
        isolationFail("prepared function-observation run path is not canonical")
    }
    if (classPathPaths.size != classPathExpected.size) {
        isolationFail("prepared function-observation class-path identity count differs")
    }
    if (rootFiles.isNotEmpty() && rootFiles != listOf(BOOT_FILE)) {
        isolationFail("prepared function-observation root-file allowance is invalid")
    }
    val classPathNames = classPathExpected.indices.map { index -> "classpath-$index.jar" }
    val expectedPaths = classPathNames.map { name ->
        runPath.resolve(RUNTIME_DIRECTORY).resolve(name)
    }
    if (classPathPaths != expectedPaths) {
        isolationFail("prepared function-observation class path is not in exact numeric order")
    }
    root.whileOpen { fd ->
        if (!Files.isSameFile(runPath, LinuxFilesystemSyscalls.stableDescriptorPath(fd))) {
            isolationFail("prepared function-observation run path differs from its pinned root")
        }
    }
    val rootBefore = LinuxFilesystemSyscalls.identity(root.fd)
    requirePreparedRootIdentity(rootBefore)
    if (!sameDirectory(rootBefore, root.identity)) {
        isolationFail("prepared function-observation root differs from its borrowed descriptor")
    }
    retained?.let { expected ->
        if (rootBefore != expected.root) {
            isolationFail("prepared function-observation root identity changed")
        }
    }
    requireExactPreparedNames(
        root,
        listOf(RUNTIME_DIRECTORY, SCRATCH_DIRECTORY, TEMP_DIRECTORY) + rootFiles,
        "run root",
    )

    val scratch = root.whileOpen { fd ->
        LinuxFilesystemSyscalls.openDirectoryAt(fd, SCRATCH_DIRECTORY)
    }
    scratch.use { scratchDirectory ->
        val temporary = root.whileOpen { fd ->
            LinuxFilesystemSyscalls.openDirectoryAt(fd, TEMP_DIRECTORY)
        }
        temporary.use { temporaryDirectory ->
            val runtime = root.whileOpen { fd ->
                LinuxFilesystemSyscalls.openDirectoryAt(fd, RUNTIME_DIRECTORY)
            }
            runtime.use { runtimeDirectory ->
                val scratchIdentity = LinuxFilesystemSyscalls.identity(scratchDirectory.fd)
                val temporaryIdentity = LinuxFilesystemSyscalls.identity(temporaryDirectory.fd)
                val runtimeIdentity = LinuxFilesystemSyscalls.identity(runtimeDirectory.fd)
                requirePreparedChildDirectory(scratchIdentity, rootBefore, "scratch")
                requirePreparedChildDirectory(temporaryIdentity, rootBefore, "temporary")
                requirePreparedChildDirectory(runtimeIdentity, rootBefore, "runtime")
                retained?.let { expected ->
                    if (
                        scratchIdentity != expected.scratch ||
                        temporaryIdentity != expected.temporary ||
                        runtimeIdentity != expected.runtime
                    ) isolationFail("prepared function-observation directory identity changed")
                }
                requireExactPreparedNames(scratchDirectory, emptyList(), "scratch directory")
                requireExactPreparedNames(temporaryDirectory, emptyList(), "temporary directory")
                requireExactPreparedNames(runtimeDirectory, classPathNames, "runtime directory")

                val classPathIdentities = classPathNames.mapIndexed { index, name ->
                    val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(runtimeDirectory.fd, name)
                        ?: isolationFail("prepared class-path entry is absent: $name")
                    selected.use { classPathEntry ->
                        val before = LinuxFilesystemSyscalls.identity(classPathEntry.fd)
                        requirePreparedClassPathIdentity(before, rootBefore, name)
                        retained?.let { expected ->
                            if (before != expected.classPath[index]) {
                                isolationFail("prepared class-path inode changed: $name")
                            }
                        }
                        val (expectedBytes, expectedSha256) = classPathExpected[index]
                        if (digestDescriptor(classPathEntry, expectedBytes) != expectedSha256) {
                            isolationFail("prepared class-path bytes changed: $name")
                        }
                        val after = LinuxFilesystemSyscalls.identity(classPathEntry.fd)
                        if (after != before) {
                            isolationFail("prepared class-path identity changed while hashing: $name")
                        }
                        before
                    }
                }

                requireExactPreparedNames(runtimeDirectory, classPathNames, "runtime directory after hashing")
                classPathNames.forEachIndexed { index, name ->
                    val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(runtimeDirectory.fd, name)
                        ?: isolationFail("prepared class-path entry disappeared: $name")
                    selected.use { classPathEntry ->
                        if (LinuxFilesystemSyscalls.identity(classPathEntry.fd) != classPathIdentities[index]) {
                            isolationFail("prepared class-path name selected a replacement inode: $name")
                        }
                    }
                }
                requireExactPreparedNames(scratchDirectory, emptyList(), "scratch directory after hashing")
                requireExactPreparedNames(temporaryDirectory, emptyList(), "temporary directory after hashing")
                if (
                    LinuxFilesystemSyscalls.identity(scratchDirectory.fd) != scratchIdentity ||
                    LinuxFilesystemSyscalls.identity(temporaryDirectory.fd) != temporaryIdentity ||
                    LinuxFilesystemSyscalls.identity(runtimeDirectory.fd) != runtimeIdentity
                ) isolationFail("prepared function-observation directory changed during validation")
                listOf(
                    SCRATCH_DIRECTORY to scratchIdentity,
                    TEMP_DIRECTORY to temporaryIdentity,
                    RUNTIME_DIRECTORY to runtimeIdentity,
                ).forEach { (name, expectedIdentity) ->
                    val selected = root.whileOpen { fd -> LinuxFilesystemSyscalls.openDirectoryAt(fd, name) }
                    selected.use { directory ->
                        if (LinuxFilesystemSyscalls.identity(directory.fd) != expectedIdentity) {
                            isolationFail("prepared function-observation name selected a replacement directory")
                        }
                    }
                }
                requireExactPreparedNames(
                    root,
                    listOf(RUNTIME_DIRECTORY, SCRATCH_DIRECTORY, TEMP_DIRECTORY) + rootFiles,
                    "run root after validation",
                )
                val rootAfter = LinuxFilesystemSyscalls.identity(root.fd)
                if (rootAfter != rootBefore) {
                    isolationFail("prepared function-observation root changed during validation")
                }
                return PreparedObservationRunLayout(
                    rootBefore,
                    scratchIdentity,
                    temporaryIdentity,
                    runtimeIdentity,
                    classPathIdentities.toList(),
                )
            }
        }
    }
}

private fun requireExactPreparedNames(
    directory: LinuxDescriptor,
    expected: List<String>,
    label: String,
) {
    val actual = LinuxFilesystemSyscalls.directoryEntryNames(directory, expected.size + 1).sorted()
    if (actual != expected.sorted()) {
        isolationFail("prepared function-observation $label has unexpected membership")
    }
}

private fun requirePreparedRootIdentity(identity: LinuxFileIdentity) {
    if (
        !identity.isDirectory || identity.isRegularFile || identity.isSymbolicLink ||
        identity.mode.permissions != OWNER_DIRECTORY_MODE || identity.linkCount != PREPARED_ROOT_LINK_COUNT
    ) isolationFail(
        "prepared function-observation root is not the exact private ext4 layout " +
            "(mode=${identity.mode.permissions}, links=${identity.linkCount})",
    )
}

private fun requirePreparedChildDirectory(
    identity: LinuxFileIdentity,
    root: LinuxFileIdentity,
    label: String,
) {
    if (
        !identity.isDirectory || identity.isRegularFile || identity.isSymbolicLink ||
        identity.mode.permissions != OWNER_DIRECTORY_MODE || identity.linkCount != PREPARED_CHILD_LINK_COUNT ||
        identity.uid != root.uid || identity.gid != root.gid || identity.mountId != root.mountId ||
        identity.key.device != root.key.device
    ) isolationFail("prepared function-observation $label directory is outside the exact private layout")
}

private fun requirePreparedClassPathIdentity(
    identity: LinuxFileIdentity,
    root: LinuxFileIdentity,
    name: String,
) {
    if (
        !identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink ||
        identity.mode.permissions != OWNER_READ_ONLY_MODE || identity.linkCount != 1 ||
        identity.uid != root.uid || identity.gid != root.gid || identity.mountId != root.mountId ||
        identity.key.device != root.key.device
    ) isolationFail("prepared class-path entry is outside the exact private layout: $name")
}

private fun requireObservationBootLayout(
    materializedClassPath: MaterializedObservationClassPath,
    runTree: ObservationRunTreeAccess,
    nonce: String,
) {
    materializedClassPath.requirePreparedLayout(runTree, listOf(BOOT_FILE))
    val boot = runTree.withPinnedDescriptor { root -> protocolFileOrNull(root, BOOT_FILE) }
        ?: isolationFail("isolated BOOT record is absent")
    if (boot != protocol("BOOT", nonce)) isolationFail("isolated BOOT record is invalid")
    materializedClassPath.requirePreparedLayout(runTree, listOf(BOOT_FILE))
}

internal data class FullTreeFunctionObservationCgroupReceipt(
    val peakResidentBytes: Long,
    val cpuNanos: Long,
    val derivationWallNanos: Long,
    val memoryMaxEvents: Long,
    val memoryOomEvents: Long,
    val memoryOomKillEvents: Long,
)

internal data class FullTreeFunctionObservationIsolatedFixturePublication(
    val fixtureShard: FullTreeFunctionObservationPublishedShard,
    val cgroup: FullTreeFunctionObservationCgroupReceipt,
)

/**
 * Fixed-policy resource inputs for the shared Kotlin BOOT-only scope primitive.
 *
 * This is deliberately smaller than the function-observation resource model: it can establish
 * and retain a live systemd/cgroup-v2 boundary, but it cannot authorize the gated command.  The
 * caller may lower these limits, but cannot raise the process controller's fixed ceilings.
 */
internal data class KotlinSystemdCgroupBootResources(
    val wallClockMillis: Long,
    val maximumResidentBytes: Long,
    val pidsMax: Long,
) {
    /** Per-file bootstrap ceiling passed to prlimit; protocol records remain separately capped. */
    val maximumRuntimeFileBytes: Long
        get() = PROTOCOL_CLEANUP_ALLOWANCE_BYTES

    init {
        require(wallClockMillis in 1L..KOTLIN_BOOT_MAXIMUM_WALL_MILLIS)
        require(maximumResidentBytes in KOTLIN_BOOT_MINIMUM_MEMORY_BYTES..KOTLIN_BOOT_MAXIMUM_MEMORY_BYTES)
        require(pidsMax in KOTLIN_BOOT_MINIMUM_PIDS..KOTLIN_BOOT_MAXIMUM_PIDS)
    }
}

internal data class KotlinSystemdCgroupBootProcessReceipt(
    val role: String,
    val pid: Long,
    val startTimeTicks: Long,
    val parentRole: String?,
    val namespacePids: List<Long>,
    val executableSha256: String,
) {
    init {
        require(role in KOTLIN_BOOT_PROCESS_ROLES)
        require(pid in 1L..Int.MAX_VALUE && startTimeTicks > 0L)
        require(parentRole == KOTLIN_BOOT_PROCESS_PARENTS.getValue(role))
        require(namespacePids.isNotEmpty() && namespacePids.size <= 2 && namespacePids.first() == pid)
        require(namespacePids.all { it in 1L..Int.MAX_VALUE })
        require(executableSha256.matches(SHA256))
    }
}

/** Historical bytes copied from a still-live descriptor/pidfd-backed BOOT owner. */
internal class KotlinSystemdCgroupBootReceipt(
    val unitName: String,
    val nonce: String,
    val bootId: String,
    val invocationId: String,
    val controlGroup: String,
    val cgroupDevice: Long,
    val cgroupInode: Long,
    val cgroupMountId: Long,
    val runtimeClosureSha256: String,
    val deploymentClosureSha256: String,
    val resources: KotlinSystemdCgroupBootResources,
    processes: List<KotlinSystemdCgroupBootProcessReceipt>,
) {
    val processes: List<KotlinSystemdCgroupBootProcessReceipt> = java.util.List.copyOf(processes)

    init {
        require(unitName.matches(PRODUCTION_KOTLIN_BOOT_UNIT_NAME))
        require(nonce.matches(SHA256))
        require(bootId.matches(KERNEL_BOOT_UUID))
        require(invocationId.matches(SYSTEMD_ID128) && invocationId !in RESERVED_SYSTEMD_ID128S)
        require(controlGroup.startsWith('/') && controlGroup.substringAfterLast('/') == unitName)
        require(cgroupDevice > 0L && cgroupInode > 0L && cgroupMountId > 0L)
        require(runtimeClosureSha256.matches(SHA256))
        require(deploymentClosureSha256.matches(SHA256))
        require(this.processes.map(KotlinSystemdCgroupBootProcessReceipt::role) == KOTLIN_BOOT_PROCESS_ROLES)
    }
}

private object KOTLIN_SYSTEMD_CGROUP_BOOT_OWNER_PERMIT

/**
 * Linear owner of one exact Kotlin keeper blocked before START.
 *
 * The receipt is historical match data.  Current authority stays in the retained systemd
 * invocation identity, cgroup descriptor, and pidfds and is reobserved on every operation.  This
 * type intentionally has no START/release/publication method. [closeAndProveAbsent] conditionally
 * applies whole-cgroup SIGKILL only to the exact retained target when present, uses retained
 * pidfds as a backstop, and completes two exact-name absence sweeps before returning.
 */
internal class KotlinSystemdCgroupBootOwner internal constructor(
    private val opaqueOwnership: Any,
    constructionPermit: Any,
) : AutoCloseable {
    private val ownership: KotlinSystemdCgroupBootOwnership
    val receipt: KotlinSystemdCgroupBootReceipt
    private var terminal = false
    private var operationActive = false

    init {
        check(constructionPermit === KOTLIN_SYSTEMD_CGROUP_BOOT_OWNER_PERMIT) {
            "Kotlin systemd/cgroup BOOT ownership requires a live verified launch"
        }
        ownership = opaqueOwnership as? KotlinSystemdCgroupBootOwnership
            ?: error("Kotlin systemd/cgroup BOOT ownership is invalid")
        receipt = ownership.receipt
        requireCurrentAtBoot()
    }

    @Synchronized
    fun requireCurrentAtBoot() {
        check(!terminal) { "Kotlin systemd/cgroup BOOT owner is terminal" }
        check(!operationActive) { "Kotlin systemd/cgroup BOOT operation is already active" }
        operationActive = true
        try {
            ownership.requireCurrentAtBoot()
        } finally {
            operationActive = false
        }
    }

    @Synchronized
    fun closeAndProveAbsent() {
        if (terminal) return
        check(!operationActive) { "Kotlin systemd/cgroup BOOT operation is already active" }
        operationActive = true
        try {
            ownership.closeAndProveAbsent()
            terminal = true
        } finally {
            operationActive = false
        }
    }

    override fun close() = closeAndProveAbsent()
}

private class KotlinSystemdCgroupBootOwnership(
    val receipt: KotlinSystemdCgroupBootReceipt,
    private val expectedControlGroup: String,
    private val nonce: String,
    private val resources: IsolatedObservationResources,
    private val runtime: AuthenticatedObservationRuntime,
    private val runTree: PrivateObservationRunTree,
    private val materializedClassPath: MaterializedObservationClassPath,
    private val boundary: TrustedObservationBoundary,
    private val unit: ManagedObservationUnit,
) {
    private var resourcesClosed = false

    fun requireCurrentAtBoot() {
        if (resourcesClosed) isolationFail("Kotlin systemd/cgroup BOOT resources are closed")
        boundary.verifyLiveOperation()
        runtime.verify("while generic Kotlin keeper is at BOOT")
        runTree.withPinnedDescriptor { descriptor ->
            requireObservationBootLayout(materializedClassPath, runTree, nonce)
            requirePrivateDirectory(descriptor, "generic Kotlin BOOT run tree")
        }
        unit.awaitBoot(nonce, runTree)
        val current = unit.captureKotlinBootAttachment(
            expected = resources,
            runtimeConfigurationSha256 = receipt.runtimeClosureSha256,
            requestedResources = receipt.resources,
            deploymentClosureSha256 = receipt.deploymentClosureSha256,
        )
        if (!sameKotlinBootReceipt(current, receipt) || current.controlGroup != expectedControlGroup) {
            isolationFail("generic Kotlin BOOT attachment differs from its retained receipt")
        }
        boundary.verifyLiveOperation()
        runtime.verify("after generic Kotlin BOOT revalidation")
    }

    fun closeAndProveAbsent() {
        if (resourcesClosed) return
        // Boundary close performs a guarded whole-cgroup kill only when the exact retained target
        // remains present, plus one full absence proof; retained-name cleanup then performs an
        // independent exact-name unit/cgroup sweep.
        boundary.close()
        var failure: Throwable? = null
        fun record(next: Throwable) {
            val primary = failure
            if (primary == null) failure = next else if (next !== primary) primary.addSuppressed(next)
        }
        runCatching { runTree.close() }.exceptionOrNull()?.let(::record)
        runCatching { runtime.close() }.exceptionOrNull()?.let(::record)
        // The boundary has already proved whole-cgroup absence and both descriptors have already
        // received their one terminal close attempt. Never re-enter descriptor cleanup on retry.
        resourcesClosed = true
        failure?.let { throw it }
    }
}

private fun sameKotlinBootReceipt(
    left: KotlinSystemdCgroupBootReceipt,
    right: KotlinSystemdCgroupBootReceipt,
): Boolean =
    left.unitName == right.unitName && left.nonce == right.nonce && left.bootId == right.bootId &&
        left.invocationId == right.invocationId && left.controlGroup == right.controlGroup &&
        left.cgroupDevice == right.cgroupDevice && left.cgroupInode == right.cgroupInode &&
        left.cgroupMountId == right.cgroupMountId &&
        left.runtimeClosureSha256 == right.runtimeClosureSha256 &&
        left.deploymentClosureSha256 == right.deploymentClosureSha256 &&
        left.resources == right.resources && left.processes == right.processes

/**
 * Shared production BOOT primitive extracted from the full-tree controller's proven boundary.
 * Callers supply a fully authenticated runtime configuration; this method never accepts a
 * launcher, process observer, receipt, or callback from an untrusted caller and exposes no START.
 */
internal object KotlinSystemdCgroupBootLauncher {
    fun launch(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        scratchParent: Path,
        unitName: String,
        expectedControlGroup: String,
        nonce: String,
        requestedResources: KotlinSystemdCgroupBootResources,
        deploymentClosureSha256: String,
    ): KotlinSystemdCgroupBootOwner = translateIsolationFailures(label = "Kotlin BOOT launch") {
        var runtime: AuthenticatedObservationRuntime? = null
        var runTree: PrivateObservationRunTree? = null
        var boundary: TrustedObservationBoundary? = null
        var launchAttempted = false
        try {
            if (!unitName.matches(PRODUCTION_KOTLIN_BOOT_UNIT_NAME)) {
                isolationFail("Kotlin BOOT unit name is not a safe bounded scope name")
            }
            if (!nonce.matches(SHA256)) isolationFail("Kotlin BOOT nonce is invalid")
            if (
                !expectedControlGroup.startsWith('/') ||
                expectedControlGroup.substringAfterLast('/') != unitName ||
                expectedControlGroup.contains("..") || '\u0000' in expectedControlGroup
            ) isolationFail("Kotlin BOOT expected cgroup is invalid")
            if (!deploymentClosureSha256.matches(SHA256)) {
                isolationFail("Kotlin BOOT deployment-closure digest is invalid")
            }
            val resources = IsolatedObservationResources.forKotlinBoot(requestedResources)
            val openedRuntime = AuthenticatedObservationRuntime.open(configuration)
            runtime = openedRuntime
            val requiredCleanupBytes = addExact(
                openedRuntime.classPathBytes,
                PROTOCOL_CLEANUP_ALLOWANCE_BYTES,
                "Kotlin BOOT private cleanup closure",
            )
            if (requiredCleanupBytes > KOTLIN_BOOT_MAXIMUM_PRIVATE_BYTES) {
                isolationFail("Kotlin BOOT class path exceeds its bounded cleanup closure")
            }
            val openedTree = PrivateObservationRunTree.create(scratchParent, resources)
            runTree = openedTree
            val classPath = openedRuntime.materializeClassPath(openedTree)
            classPath.authenticatePreparedLayout(openedTree)
            val openedBoundary = TrustedObservationBoundary(configuration, openedRuntime, classPath)
            boundary = openedBoundary
            launchAttempted = true
            val unit = openedBoundary.launchKotlinBootKeeper(
                unitName = unitName,
                nonce = nonce,
                runTree = openedTree,
                resources = resources,
            )
            unit.awaitBoot(nonce, openedTree)
            val receipt = unit.captureKotlinBootAttachment(
                resources,
                kotlinSystemdCgroupBootRuntimeClosureSha256(configuration, deploymentClosureSha256),
                requestedResources,
                deploymentClosureSha256,
            )
            if (receipt.controlGroup != expectedControlGroup) {
                isolationFail("Kotlin BOOT scope is outside the exact derived cgroup")
            }
            val ownership = KotlinSystemdCgroupBootOwnership(
                receipt,
                expectedControlGroup,
                nonce,
                resources,
                openedRuntime,
                openedTree,
                classPath,
                openedBoundary,
                unit,
            )
            val result = KotlinSystemdCgroupBootOwner(
                ownership,
                KOTLIN_SYSTEMD_CGROUP_BOOT_OWNER_PERMIT,
            )
            boundary = null
            runTree = null
            runtime = null
            result
        } catch (failure: Throwable) {
            fun suppress(next: Throwable) {
                if (next !== failure) failure.addSuppressed(next)
            }
            val boundaryFailure = runCatching { boundary?.close() }.exceptionOrNull()
            boundaryFailure?.let(::suppress)
            var privateCleanupFailed = false
            if (boundaryFailure == null) {
                runCatching { runTree?.close() }.exceptionOrNull()?.let {
                    privateCleanupFailed = true
                    suppress(it)
                }
                runCatching { runtime?.close() }.exceptionOrNull()?.let {
                    privateCleanupFailed = true
                    suppress(it)
                }
            }
            val rollbackSafe = boundaryFailure == null && !privateCleanupFailed &&
                (!launchAttempted || boundary != null)
            throw KotlinSystemdCgroupBootLaunchException(
                "generic Kotlin BOOT launch failed before ownership transfer",
                failure,
                rollbackSafe,
            )
        }
    }
}

private fun kotlinSystemdCgroupBootRuntimeClosureSha256(
    configuration: FullTreeFunctionObservationIsolationConfiguration,
    deploymentClosureSha256: String,
): String = OracleArtifacts.sha256(
    OracleJson.canonicalBytes(
        JsonObject(
            mapOf(
                "bubblewrapExecutable" to JsonPrimitive(configuration.bubblewrapExecutable.toString()),
                "expectedBubblewrapSha256" to JsonPrimitive(configuration.expectedBubblewrapSha256),
                "expectedJavaSha256" to JsonPrimitive(configuration.expectedJavaSha256),
                "expectedResourceLimiterSha256" to
                    JsonPrimitive(configuration.expectedResourceLimiterSha256),
                "expectedScopeInspectorSha256" to
                    JsonPrimitive(configuration.expectedScopeInspectorSha256),
                "expectedScopeSupervisorSha256" to
                    JsonPrimitive(configuration.expectedScopeSupervisorSha256),
                "expectedSystemdBusControllerSha256" to
                    JsonPrimitive(configuration.expectedSystemdBusControllerSha256),
                "javaExecutable" to JsonPrimitive(configuration.javaExecutable.toString()),
                "javaRuntime" to configuration.javaRuntime.canonicalIdentity(),
                "nativeLibraryProfileSha256" to JsonPrimitive(OracleNativeLibraries.policySha256),
                "keeperEntryPoint" to JsonPrimitive(KotlinSystemdCgroupBootKeeper::class.java.name),
                "deploymentClosureSha256" to
                    JsonPrimitive(deploymentClosureSha256),
                "provider" to JsonPrimitive(KOTLIN_BOOT_RUNTIME_PROVIDER),
                "resourceLimiterExecutable" to
                    JsonPrimitive(configuration.resourceLimiterExecutable.toString()),
                "schemaVersion" to JsonPrimitive(2),
                "scopeInspectorExecutable" to
                    JsonPrimitive(configuration.scopeInspectorExecutable.toString()),
                "scopeSupervisorExecutable" to
                    JsonPrimitive(configuration.scopeSupervisorExecutable.toString()),
                "systemLibraryMounts" to
                    JsonArray(configuration.systemLibraryMounts.map { it.canonicalIdentity() }),
                "systemdBusControllerExecutable" to
                    JsonPrimitive(configuration.systemdBusControllerExecutable.toString()),
                "systemdUserRuntimeDirectory" to
                    JsonPrimitive(configuration.systemdUserRuntimeDirectory.toString()),
                "workerClassPath" to JsonArray(
                    configuration.workerClassPath.map { entry ->
                        JsonObject(
                            mapOf(
                                "expectedSha256" to JsonPrimitive(entry.expectedSha256),
                                "path" to JsonPrimitive(entry.path.toString()),
                            ),
                        )
                    },
                ),
            ),
        ),
        ISOLATION_CONFIGURATION_JSON_LIMITS,
    ),
)

/**
 * Production pre-launch composition for one durable LEASED operation.
 *
 * [prepareBeforeLaunch] authenticates the journal-bound inputs and runtime, transfers the linear
 * journal/disk authority before this layer's first run-tree mutation, initializes the deterministic
 * pinned run root, and snapshots the worker class path. [launchToBoot] may then pin the launch
 * boundary and create the deterministic live scope only through BOOT. [recordUnitAttached] then
 * durably binds that exact still-blocked invocation and returns a distinct UNIT_ATTACHED BOOT
 * typestate. None of these operations starts the worker, publishes output, removes residue, or
 * authorizes lease release.
 */
internal object FullTreeFunctionObservationIsolatedOperationRunner {
    fun prepareBeforeLaunch(
        preparedRun: FullTreeFunctionObservationPreparedRun,
        richArtifact: Path,
        inventoryPath: Path,
        scopeFiles: FullTreeFunctionObservationScopeFiles,
        output: Path,
        configuration: FullTreeFunctionObservationIsolationConfiguration,
    ): FullTreeFunctionObservationPreparedIsolation =
        FullTreeFunctionObservationPreparedIsolation.prepareBeforeLaunch(
            preparedRun,
            richArtifact,
            inventoryPath,
            scopeFiles,
            output,
            configuration,
        )

    fun launchToBoot(
        preparedIsolation: FullTreeFunctionObservationPreparedIsolation,
    ): FullTreeFunctionObservationBootedIsolation = preparedIsolation.launchToBoot()

    fun recordUnitAttached(
        bootedIsolation: FullTreeFunctionObservationBootedIsolation,
    ): FullTreeFunctionObservationUnitAttachedBootIsolation = bootedIsolation.recordUnitAttached()

    fun recoverUnitAttachedAtBootReadOnly(
        coldAttached: FullTreeFunctionObservationColdUnitAttachedOperation,
        richArtifact: Path,
        inventoryPath: Path,
        scopeFiles: FullTreeFunctionObservationScopeFiles,
        output: Path,
        configuration: FullTreeFunctionObservationIsolationConfiguration,
    ): FullTreeFunctionObservationRecoveredUnitAttachedBootObservation =
        FullTreeFunctionObservationRecoveredUnitAttachedBootObservation.recover(
            coldAttached,
            richArtifact,
            inventoryPath,
            scopeFiles,
            output,
            configuration,
        )

    internal fun launchToBootWithTestHooks(
        preparedIsolation: FullTreeFunctionObservationPreparedIsolation,
        testHooks: FullTreeFunctionObservationLaunchTestHooks,
    ): Nothing = preparedIsolation.launchToBootWithTestHooks(testHooks)
}

/**
 * Typed LEASED state whose deterministic run layout and class path passed exact point-in-time
 * validation, but which carries no worker/cgroup or same-UID-writer-exclusion claim. Closing
 * preserves all run, lease, and journal residue.
 */
internal class FullTreeFunctionObservationPreparedIsolation private constructor(
    private val paths: IsolatedObservationPaths,
    private val runDirectory: Path,
    private val configuration: FullTreeFunctionObservationIsolationConfiguration,
    private val authenticatedScope: AuthenticatedFullTreeScope,
    private val authenticatedInputs: FullTreeFunctionObservationAuthenticatedInputs,
    private val resources: IsolatedObservationResources,
    private val runtime: AuthenticatedObservationRuntime,
    private val inputGuards: ParentObservationInputGuards,
    private val materializedClassPath: MaterializedObservationClassPath,
    private val authority: FullTreeFunctionObservationPreparedIsolationAuthority,
) : AutoCloseable {
    val operationId: String = authority.leasedHistory.binding.operationId
    val shardId: String = authority.leasedHistory.binding.shardId
    private var closed = false
    private var operationActive = false
    private var cleanupBoundary: TrustedObservationBoundary? = null

    init {
        requireCurrentBeforeLaunch()
    }

    /** Reauthenticates H, D, input/class-path bytes, runtime closure metadata, and the run layout. */
    @Synchronized
    fun requireCurrentBeforeLaunch() {
        check(!closed) { "function-observation prepared isolation is closed" }
        if (operationActive) {
            isolationFail("function-observation prepared isolation operation is already active")
        }
        operationActive = true
        try {
            requireCurrentBeforeLaunchInternal()
        } finally {
            operationActive = false
        }
    }

    private fun requireCurrentBeforeLaunchInternal() {
        if (cleanupBoundary != null) {
            isolationFail("function-observation launch cleanup remains unresolved")
        }
        val binding = authority.leasedHistory.binding
        FullTreeScopeControl.validate(authenticatedScope)
        requireFullTreeObservationDiskClosureCompatibility(binding, resources.cleanupLimits)
        requirePreparedIsolationBinding(
            binding,
            paths,
            runDirectory,
            configuration,
            authenticatedScope,
            inputGuards,
            authenticatedInputs,
        )
        runtime.verify("while prepared before launch")
        inputGuards.verifyCurrent("while prepared before launch")
        authority.withCurrentRunRootBeforeLaunch { borrowed ->
            if (borrowed.path != runDirectory) {
                isolationFail("prepared function-observation run-root locator changed")
            }
            BorrowedObservationRunTree.access(borrowed).use { runTree ->
                materializedClassPath.requirePreparedLayout(runTree)
            }
        }
        requirePreparedIsolationOutputAbsent(paths.output)
        runtime.verify("after prepared run-tree revalidation")
        inputGuards.verifyCurrent("after prepared run-tree revalidation")
        authority.requireCurrentBeforeLaunch()
    }

    @Synchronized
    override fun close() {
        if (closed) return
        if (operationActive) {
            isolationFail("function-observation prepared isolation cannot close during an active operation")
        }
        cleanupBoundary?.closeAndProveUnitAbsent(authority.leasedHistory.binding.unitName)
        authority.requireCurrentAfterProvedLaunchBoundaryAbsence()
        cleanupBoundary = null
        closed = true
        closePreparedIsolationResources(
            inputGuards = inputGuards,
            runtime = runtime,
            authority = authority,
            untransferred = null,
            priorFailure = null,
        )?.let { throw it }
    }

    @Synchronized
    internal fun launchToBoot(): FullTreeFunctionObservationBootedIsolation =
        launchToBootInternal(testHooks = null)

    /** A hooked launch can fault or fail, but it can never return a production BOOT owner. */
    @Synchronized
    internal fun launchToBootWithTestHooks(
        testHooks: FullTreeFunctionObservationLaunchTestHooks,
    ): Nothing {
        launchToBootInternal(testHooks)
        error("fault-injected function-observation launch escaped its fail-only transaction")
    }

    private fun launchToBootInternal(
        testHooks: FullTreeFunctionObservationLaunchTestHooks?,
    ): FullTreeFunctionObservationBootedIsolation {
        check(!closed) { "function-observation prepared isolation is closed" }
        if (operationActive) {
            isolationFail("function-observation prepared isolation operation is already active")
        }
        if (cleanupBoundary != null) {
            isolationFail("function-observation launch cleanup must complete before another operation")
        }
        operationActive = true
        var boundary: TrustedObservationBoundary? = null
        try {
            requireCurrentBeforeLaunchInternal()
            val binding = authority.leasedHistory.binding
            val openedBoundary = TrustedObservationBoundary(
                configuration,
                runtime,
                materializedClassPath,
                testHooks,
            )
            boundary = openedBoundary
            cleanupBoundary = openedBoundary
            val request = IsolatedWorkerRequest(
                nonce = binding.bindingSha256,
                paths = paths,
                shardId = binding.shardId,
                runDirectory = runDirectory,
            )
            val managed = authority.withCurrentRunRootForScopeAttachment { borrowed ->
                if (borrowed.path != runDirectory) {
                    isolationFail("attached function-observation run-root locator changed")
                }
                BorrowedObservationRunTree.access(borrowed).use { runTree ->
                    fun requireFinalPreparedState(label: String) {
                        FullTreeScopeControl.validate(authenticatedScope)
                        requirePreparedIsolationBinding(
                            binding,
                            paths,
                            runDirectory,
                            configuration,
                            authenticatedScope,
                            inputGuards,
                            authenticatedInputs,
                        )
                        runtime.verify(label)
                        inputGuards.verifyCurrent(label)
                        materializedClassPath.requirePreparedLayout(runTree)
                        requirePreparedIsolationOutputAbsent(paths.output)
                    }
                    requireFinalPreparedState("before isolated scope attachment")
                    val unit = openedBoundary.launch(
                        unitName = binding.unitName,
                        request = request,
                        resources = resources,
                        immediatelyBeforeStart = {
                            requireFinalPreparedState("immediately before isolated process start")
                        },
                    )
                    unit.awaitBoot(binding.bindingSha256, runTree)
                    unit.verifyLiveContainment(resources)
                    requireObservationBootLayout(
                        materializedClassPath,
                        runTree,
                        binding.bindingSha256,
                    )
                    runtime.verify("at isolated BOOT")
                    inputGuards.verifyCurrent("at isolated BOOT")
                    requirePreparedIsolationOutputAbsent(paths.output)
                    unit
                }
            }
            authority.requireCurrentAfterScopeAttachment()
            openedBoundary.verifyLiveOperation()
            runtime.verify("after isolated BOOT attachment")
            inputGuards.verifyCurrent("after isolated BOOT attachment")
            if (testHooks != null) {
                throw AssertionError("fault-injected function-observation launch unexpectedly reached BOOT")
            }
            val booted = createBootedObservationIsolation(
                paths,
                runDirectory,
                configuration,
                authenticatedScope,
                authenticatedInputs,
                resources,
                runtime,
                inputGuards,
                materializedClassPath,
                authority,
                openedBoundary,
                managed,
            )
            cleanupBoundary = null
            boundary = null
            closed = true
            return booted
        } catch (failure: Throwable) {
            val openedBoundary = boundary
            val cleanupFailure = runCatching {
                openedBoundary?.closeAndProveUnitAbsent(authority.leasedHistory.binding.unitName)
                authority.requireCurrentAfterProvedLaunchBoundaryAbsence()
            }.exceptionOrNull()
            if (cleanupFailure != null) {
                if (cleanupFailure !== failure) failure.addSuppressed(cleanupFailure)
                cleanupBoundary = openedBoundary
                throw failure
            }
            cleanupBoundary = null
            closed = true
            closePreparedIsolationResources(
                inputGuards = inputGuards,
                runtime = runtime,
                authority = authority,
                untransferred = null,
                priorFailure = failure,
            )
            throw failure
        } finally {
            operationActive = false
        }
    }

    companion object {
        internal fun prepareBeforeLaunch(
            preparedRun: FullTreeFunctionObservationPreparedRun,
            richArtifact: Path,
            inventoryPath: Path,
            scopeFiles: FullTreeFunctionObservationScopeFiles,
            output: Path,
            configuration: FullTreeFunctionObservationIsolationConfiguration,
        ): FullTreeFunctionObservationPreparedIsolation = translateIsolationFailures(
            label = "pre-launch preparation",
        ) {
            var runtime: AuthenticatedObservationRuntime? = null
            var guards: ParentObservationInputGuards? = null
            var authority: FullTreeFunctionObservationPreparedIsolationAuthority? = null
            try {
                preparedRun.requireCurrentBeforeLaunch()
                val binding = preparedRun.leasedHistory.binding
                val runDirectory = preparedRun.withCurrentRunRootBeforeLaunch { borrowed -> borrowed.path }
                val runParent = runDirectory.parent
                    ?: isolationFail("prepared function-observation run root has no lease parent")
                val paths = IsolatedObservationPaths.normalize(
                    richArtifact,
                    inventoryPath,
                    scopeFiles,
                    runParent,
                    output,
                )
                requirePreparedIsolationPathTopology(binding, paths, runDirectory)

                val authenticated = FullTreeScopeControl.load(
                    paths.scopeFiles.scope,
                    paths.scopeFiles.sourceLock,
                    paths.scopeFiles.artifactManifest,
                )
                FullTreeScopeControl.validate(authenticated)
                val openedRuntime = AuthenticatedObservationRuntime.open(configuration)
                runtime = openedRuntime
                val resources = IsolatedObservationResources.derive(
                    authenticated,
                    openedRuntime.classPathBytes,
                )
                requireFullTreeObservationDiskClosureCompatibility(binding, resources.cleanupLimits)
                val openedGuards = ParentObservationInputGuards.open(paths, authenticated)
                guards = openedGuards
                val inputs = FullTreeFunctionObservationProducer.authenticateShardInputs(
                    inventoryPath = paths.inventory,
                    scope = authenticated,
                    shardId = binding.shardId,
                )
                requirePreparedIsolationBinding(
                    binding,
                    paths,
                    runDirectory,
                    configuration,
                    authenticated,
                    openedGuards,
                    inputs,
                )
                openedGuards.verifyCurrent("immediately before run-tree initialization")
                openedRuntime.verify("immediately before prepared run-tree initialization")
                preparedRun.requireCurrentBeforeLaunch()

                val transferred = preparedRun.transferToPreparedIsolationAuthority()
                authority = transferred
                val materializedClassPath = transferred.withCurrentRunRootBeforeLaunch { borrowed ->
                    if (borrowed.path != runDirectory) {
                        isolationFail("prepared function-observation run-root locator changed")
                    }
                    requirePreparedIsolationPathTopology(binding, paths, runDirectory)
                    openedGuards.verifyCurrent("at run-tree initialization")
                    openedRuntime.verify("at prepared run-tree initialization")
                    BorrowedObservationRunTree.initialize(borrowed).use { runTree ->
                        val classPath = openedRuntime.materializeClassPath(runTree)
                        classPath.authenticatePreparedLayout(runTree)
                        openedRuntime.verify("after prepared class-path snapshotting")
                        openedGuards.verifyCurrent("after prepared class-path snapshotting")
                        requirePreparedIsolationOutputAbsent(paths.output)
                        classPath
                    }
                }
                transferred.requireCurrentBeforeLaunch()

                val result = FullTreeFunctionObservationPreparedIsolation(
                    paths,
                    runDirectory,
                    configuration,
                    authenticated,
                    inputs,
                    resources,
                    openedRuntime,
                    openedGuards,
                    materializedClassPath,
                    transferred,
                )
                runtime = null
                guards = null
                authority = null
                result
            } catch (failure: Throwable) {
                closePreparedIsolationResources(
                    inputGuards = guards,
                    runtime = runtime,
                    authority = authority,
                    untransferred = if (authority == null) preparedRun else null,
                    priorFailure = failure,
                )
                throw failure
            }
        }
    }
}

private class BootedObservationIsolationOwnership(
    val paths: IsolatedObservationPaths,
    val runDirectory: Path,
    val configuration: FullTreeFunctionObservationIsolationConfiguration,
    val authenticatedScope: AuthenticatedFullTreeScope,
    val authenticatedInputs: FullTreeFunctionObservationAuthenticatedInputs,
    val resources: IsolatedObservationResources,
    val runtime: AuthenticatedObservationRuntime,
    val inputGuards: ParentObservationInputGuards,
    val materializedClassPath: MaterializedObservationClassPath,
    var preparedAuthority: FullTreeFunctionObservationPreparedIsolationAuthority?,
    val boundary: TrustedObservationBoundary,
    val unit: ManagedObservationUnit,
) {
    var unitAttachedAuthority: FullTreeFunctionObservationUnitAttachedIsolationAuthority? = null
    var attachmentPublicationAttempted: Boolean = false
}

private object BOOTED_OBSERVATION_ISOLATION_CONSTRUCTION_PERMIT

/**
 * Ephemeral Kotlin-owned point-in-time BOOT containment observation for one deterministic live
 * scope. The worker is blocked before START, the journal deliberately remains LEASED, and this type
 * grants no truth, publication, recovery-adoption, release, or same-UID-writer-exclusion authority.
 * Close proves exact unit/cgroup/pidfd absence before it releases the journal and disk locks; an
 * unproved cleanup retains this owner and its authorities for cleanup retry.
 */
internal class FullTreeFunctionObservationBootedIsolation : AutoCloseable {
    private val ownership: BootedObservationIsolationOwnership
    val operationId: String
    val shardId: String
    val unitName: String
    private val bindingSha256: String
    private var closed = false
    private var operationActive = false

    internal constructor(opaqueOwnership: Any, constructionPermit: Any) {
        check(constructionPermit === BOOTED_OBSERVATION_ISOLATION_CONSTRUCTION_PERMIT) {
            "booted function-observation isolation can only follow proved live attachment"
        }
        ownership = opaqueOwnership as? BootedObservationIsolationOwnership
            ?: error("booted function-observation isolation ownership is invalid")
        val binding = checkNotNull(ownership.preparedAuthority) {
            "booted function-observation isolation lacks its LEASED authority"
        }.leasedHistory.binding
        operationId = binding.operationId
        shardId = binding.shardId
        unitName = binding.unitName
        bindingSha256 = binding.bindingSha256
        requireCurrentAtBoot()
    }

    @Synchronized
    fun requireCurrentAtBoot() {
        check(!closed) { "function-observation BOOT isolation is closed" }
        if (operationActive) {
            isolationFail("function-observation BOOT isolation operation is already active")
        }
        if (ownership.attachmentPublicationAttempted || ownership.unitAttachedAuthority != null) {
            isolationFail("function-observation BOOT isolation is cleanup-only after attachment publication")
        }
        operationActive = true
        try {
            requireCurrentAtBootInternal()
        } finally {
            operationActive = false
        }
    }

    private fun requireCurrentAtBootInternal() {
        val authority = ownership.preparedAuthority
            ?: isolationFail("function-observation BOOT isolation lost its LEASED authority")
        val binding = authority.leasedHistory.binding
        if (
            binding.operationId != operationId || binding.shardId != shardId ||
            binding.unitName != unitName || binding.bindingSha256 != bindingSha256
        ) isolationFail("function-observation BOOT identity changed")
        FullTreeScopeControl.validate(ownership.authenticatedScope)
        requireFullTreeObservationDiskClosureCompatibility(binding, ownership.resources.cleanupLimits)
        requirePreparedIsolationBinding(
            binding,
            ownership.paths,
            ownership.runDirectory,
            ownership.configuration,
            ownership.authenticatedScope,
            ownership.inputGuards,
            ownership.authenticatedInputs,
        )
        ownership.runtime.verify("while isolated worker is at BOOT")
        ownership.inputGuards.verifyCurrent("while isolated worker is at BOOT")
        authority.requireCurrentAfterScopeAttachment()
        ownership.boundary.verifyLiveOperation()
        authority.withCurrentRunRootAfterScopeAttachment { borrowed ->
            if (borrowed.path != ownership.runDirectory) {
                isolationFail("BOOT function-observation run-root locator changed")
            }
            BorrowedObservationRunTree.access(borrowed).use { runTree ->
                requireObservationBootLayout(
                    ownership.materializedClassPath,
                    runTree,
                    binding.bindingSha256,
                )
                ownership.unit.awaitBoot(binding.bindingSha256, runTree)
                ownership.unit.verifyLiveContainment(ownership.resources)
                requireObservationBootLayout(
                    ownership.materializedClassPath,
                    runTree,
                    binding.bindingSha256,
                )
            }
        }
        requirePreparedIsolationOutputAbsent(ownership.paths.output)
        ownership.boundary.verifyLiveOperation()
        ownership.runtime.verify("after isolated BOOT revalidation")
        ownership.inputGuards.verifyCurrent("after isolated BOOT revalidation")
        authority.requireCurrentAfterScopeAttachment()
    }

    /**
     * Durably records the exact still-blocked invocation and linearly consumes this LEASED BOOT
     * wrapper. A failure during the live precheck before transaction handoff leaves it reusable;
     * once transaction validation begins, failure leaves it cleanup-only so cold recovery can
     * inspect or complete the exact staged bytes after lock release.
     */
    @Synchronized
    internal fun recordUnitAttached(): FullTreeFunctionObservationUnitAttachedBootIsolation {
        check(!closed) { "function-observation BOOT isolation is closed" }
        if (operationActive) {
            isolationFail("function-observation BOOT isolation operation is already active")
        }
        if (ownership.attachmentPublicationAttempted || ownership.unitAttachedAuthority != null) {
            isolationFail("function-observation attachment publication was already attempted")
        }
        operationActive = true
        try {
            requireCurrentAtBootInternal()
            val prepared = ownership.preparedAuthority
                ?: isolationFail("function-observation BOOT isolation lost its LEASED authority")
            val binding = prepared.leasedHistory.binding
            val leasedTransition = prepared.leasedHistory.latest
                ?: isolationFail("function-observation BOOT isolation lacks its LEASED transition")
            val receipt = prepared.withCurrentRunRootAfterScopeAttachment { borrowed ->
                borrowed.withPinnedDescriptor { descriptor ->
                    ownership.unit.captureUnitAttachmentReceipt(
                        binding,
                        leasedTransition,
                        descriptor.whileOpen(LinuxFilesystemSyscalls::identity),
                    )
                }
            }
            ownership.unit.requireCurrentUnitAttachmentReceipt(receipt)
            val attached = try {
                prepared.transferToUnitAttachedIsolationAuthority(
                    receipt = receipt,
                    requireLiveReceipt = {
                        ownership.unit.requireCurrentUnitAttachmentReceipt(receipt)
                    },
                )
            } catch (failure: Throwable) {
                ownership.attachmentPublicationAttempted = prepared.attachmentPublicationWasAttempted()
                throw failure
            }
            ownership.preparedAuthority = null
            ownership.unitAttachedAuthority = attached
            ownership.attachmentPublicationAttempted = true
            val transferred = createUnitAttachedBootIsolation(ownership)
            closed = true
            return transferred
        } finally {
            operationActive = false
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        if (operationActive) {
            isolationFail("function-observation BOOT isolation cannot close during an active operation")
        }
        operationActive = true
        try {
            ownership.boundary.close()
            val attached = ownership.unitAttachedAuthority
            val prepared = ownership.preparedAuthority
            when {
                attached != null -> {
                    closed = true
                    closeUnitAttachedIsolationResources(
                        ownership.inputGuards,
                        ownership.runtime,
                        attached,
                        priorFailure = null,
                    )?.let { throw it }
                }

                ownership.attachmentPublicationAttempted && prepared != null -> {
                    closed = true
                    closeFailedAttachmentIsolationResources(
                        ownership.inputGuards,
                        ownership.runtime,
                        prepared,
                        priorFailure = null,
                    )?.let { throw it }
                }

                prepared != null -> {
                    prepared.requireCurrentAfterCgroupAbsence()
                    closed = true
                    closePreparedIsolationResources(
                        inputGuards = ownership.inputGuards,
                        runtime = ownership.runtime,
                        authority = prepared,
                        untransferred = null,
                        priorFailure = null,
                    )?.let { throw it }
                }

                else -> isolationFail("function-observation BOOT isolation lost its operation authority")
            }
        } finally {
            operationActive = false
        }
    }
}

private object UNIT_ATTACHED_BOOT_ISOLATION_CONSTRUCTION_PERMIT

/**
 * Kotlin-owned UNIT_ATTACHED typestate for one exact invocation still blocked before START. The
 * durable receipt is historical match data, not current liveness or mutation authority; every use
 * reobserves the same systemd invocation, descriptor-pinned cgroup, pidfds, process start times,
 * BOOT layout, inputs, runtime, journal, and disk lease. This type grants no START, truth,
 * publication, recovery-adoption, release, or same-UID-writer-exclusion authority.
 */
internal class FullTreeFunctionObservationUnitAttachedBootIsolation : AutoCloseable {
    private val ownership: BootedObservationIsolationOwnership
    val operationId: String
    val shardId: String
    val unitName: String
    val receiptSha256: String
    private val bindingSha256: String
    private var closed = false
    private var operationActive = false

    internal constructor(opaqueOwnership: Any, constructionPermit: Any) {
        check(constructionPermit === UNIT_ATTACHED_BOOT_ISOLATION_CONSTRUCTION_PERMIT) {
            "UNIT_ATTACHED BOOT isolation can only follow durable live attachment"
        }
        ownership = opaqueOwnership as? BootedObservationIsolationOwnership
            ?: error("UNIT_ATTACHED BOOT isolation ownership is invalid")
        check(ownership.preparedAuthority == null) {
            "UNIT_ATTACHED BOOT isolation retained its LEASED authority"
        }
        val authority = ownership.unitAttachedAuthority
            ?: error("UNIT_ATTACHED BOOT isolation lacks its attached authority")
        val binding = authority.attachedHistory.binding
        operationId = binding.operationId
        shardId = binding.shardId
        unitName = binding.unitName
        bindingSha256 = binding.bindingSha256
        receiptSha256 = authority.unitAttachmentReceipt.receiptSha256
        requireCurrentAtBoot()
    }

    @Synchronized
    fun requireCurrentAtBoot() {
        check(!closed) { "UNIT_ATTACHED BOOT isolation is closed" }
        if (operationActive) {
            isolationFail("UNIT_ATTACHED BOOT isolation operation is already active")
        }
        operationActive = true
        try {
            val authority = ownership.unitAttachedAuthority
                ?: isolationFail("UNIT_ATTACHED BOOT isolation lost its attached authority")
            val binding = authority.attachedHistory.binding
            if (
                binding.operationId != operationId || binding.shardId != shardId ||
                binding.unitName != unitName || binding.bindingSha256 != bindingSha256 ||
                authority.unitAttachmentReceipt.receiptSha256 != receiptSha256
            ) isolationFail("UNIT_ATTACHED BOOT identity changed")
            FullTreeScopeControl.validate(ownership.authenticatedScope)
            requireFullTreeObservationDiskClosureCompatibility(binding, ownership.resources.cleanupLimits)
            requirePreparedIsolationBinding(
                binding,
                ownership.paths,
                ownership.runDirectory,
                ownership.configuration,
                ownership.authenticatedScope,
                ownership.inputGuards,
                ownership.authenticatedInputs,
            )
            ownership.runtime.verify("while isolated worker is durably UNIT_ATTACHED at BOOT")
            ownership.inputGuards.verifyCurrent("while isolated worker is durably UNIT_ATTACHED at BOOT")
            authority.requireCurrentAtBoot()
            ownership.boundary.verifyLiveOperation()
            authority.withCurrentRunRootAtBoot { borrowed ->
                if (borrowed.path != ownership.runDirectory) {
                    isolationFail("UNIT_ATTACHED BOOT run-root locator changed")
                }
                BorrowedObservationRunTree.access(borrowed).use { runTree ->
                    requireObservationBootLayout(
                        ownership.materializedClassPath,
                        runTree,
                        binding.bindingSha256,
                    )
                    ownership.unit.awaitBoot(binding.bindingSha256, runTree)
                    ownership.unit.verifyLiveContainment(ownership.resources)
                    ownership.unit.requireCurrentUnitAttachmentReceipt(authority.unitAttachmentReceipt)
                    requireObservationBootLayout(
                        ownership.materializedClassPath,
                        runTree,
                        binding.bindingSha256,
                    )
                }
            }
            requirePreparedIsolationOutputAbsent(ownership.paths.output)
            ownership.boundary.verifyLiveOperation()
            ownership.runtime.verify("after durable UNIT_ATTACHED BOOT revalidation")
            ownership.inputGuards.verifyCurrent("after durable UNIT_ATTACHED BOOT revalidation")
            authority.requireCurrentAtBoot()
        } finally {
            operationActive = false
        }
    }

    /** Immutable history only; callers must still reobserve every live receipt field. */
    @Synchronized
    internal fun historicalAttachmentReceiptForRecovery():
        FullTreeFunctionObservationUnitAttachmentReceipt {
        check(!closed) { "UNIT_ATTACHED BOOT isolation is closed" }
        if (operationActive) {
            isolationFail("UNIT_ATTACHED BOOT isolation operation is already active")
        }
        return ownership.unitAttachedAuthority?.unitAttachmentReceipt
            ?: isolationFail("UNIT_ATTACHED BOOT isolation lost its attached receipt")
    }

    /**
     * Deliberately releases only this JVM's descriptors and H/D locks so another Kotlin
     * coordinator can reopen the exact UNIT_ATTACHED residue. The worker remains blocked at BOOT;
     * this method never signals it or issues a mutating systemd command.
     */
    @Synchronized
    internal fun abandonForColdRecoveryReadOnly() {
        check(!closed) { "UNIT_ATTACHED BOOT isolation is closed" }
        if (operationActive) {
            isolationFail("UNIT_ATTACHED BOOT isolation operation is already active")
        }
        requireCurrentAtBoot()
        operationActive = true
        var failure: Throwable? = null
        fun record(next: Throwable) {
            val primary = failure
            if (primary == null) failure = next else if (next !== primary) primary.addSuppressed(next)
        }
        try {
            val authority = ownership.unitAttachedAuthority
                ?: isolationFail("UNIT_ATTACHED BOOT isolation lost its attached authority")
            closed = true
            runCatching { ownership.boundary.abandonObservationForColdRecovery(ownership.unit) }
                .exceptionOrNull()?.let(::record)
            runCatching { ownership.inputGuards.close() }.exceptionOrNull()?.let(::record)
            runCatching { ownership.runtime.close() }.exceptionOrNull()?.let(::record)
            runCatching { authority.abandonForColdRecovery() }.exceptionOrNull()?.let(::record)
            ownership.unitAttachedAuthority = null
            failure?.let { throw it }
        } finally {
            operationActive = false
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        if (operationActive) {
            isolationFail("UNIT_ATTACHED BOOT isolation cannot close during an active operation")
        }
        operationActive = true
        try {
            ownership.boundary.close()
            val authority = ownership.unitAttachedAuthority
                ?: isolationFail("UNIT_ATTACHED BOOT isolation lost its attached authority")
            closed = true
            closeUnitAttachedIsolationResources(
                ownership.inputGuards,
                ownership.runtime,
                authority,
                priorFailure = null,
            )?.let { throw it }
        } finally {
            operationActive = false
        }
    }
}

private fun createUnitAttachedBootIsolation(
    ownership: BootedObservationIsolationOwnership,
): FullTreeFunctionObservationUnitAttachedBootIsolation =
    FullTreeFunctionObservationUnitAttachedBootIsolation(
        ownership,
        UNIT_ATTACHED_BOOT_ISOLATION_CONSTRUCTION_PERMIT,
    )

/**
 * Query/open-only recovery view of one same-boot, receipt-matched scope still blocked at BOOT.
 *
 * This is intentionally distinct from the fresh UNIT_ATTACHED owner: its disk handle is cold and
 * observation-only by trusted Kotlin composition, and close drops descriptors without signaling a
 * PID or issuing a systemd command. It grants no START, cleanup, recovered-abort, truth,
 * publication, release, or same-UID-writer-exclusion authority and never crosses into ACP.
 */
internal class FullTreeFunctionObservationRecoveredUnitAttachedBootObservation private constructor(
    private val paths: IsolatedObservationPaths,
    private val runDirectory: Path,
    private val configuration: FullTreeFunctionObservationIsolationConfiguration,
    private val authenticatedScope: AuthenticatedFullTreeScope,
    private val authenticatedInputs: FullTreeFunctionObservationAuthenticatedInputs,
    private val resources: IsolatedObservationResources,
    private val runtime: AuthenticatedObservationRuntime,
    private val inputGuards: ParentObservationInputGuards,
    private val materializedClassPath: MaterializedObservationClassPath,
    private val authority: FullTreeFunctionObservationColdUnitAttachedBootAuthority,
    private val boundary: TrustedObservationBoundary,
    private val unit: ManagedObservationUnit,
) : AutoCloseable {
    val operationId: String = authority.attachedHistory.binding.operationId
    val shardId: String = authority.attachedHistory.binding.shardId
    val unitName: String = authority.attachedHistory.binding.unitName
    val receiptSha256: String = authority.unitAttachmentReceipt.receiptSha256
    private val bindingSha256: String = authority.attachedHistory.binding.bindingSha256
    private var closed = false
    private var operationActive = false

    init {
        requireCurrentAtBoot()
    }

    /** Repeats H/D, boot, input/runtime/layout, unit/cgroup, and pidfd receipt matching. */
    @Synchronized
    fun requireCurrentAtBoot() {
        check(!closed) { "recovered UNIT_ATTACHED BOOT observation is closed" }
        if (operationActive) {
            isolationFail("recovered UNIT_ATTACHED BOOT observation is already active")
        }
        operationActive = true
        try {
            val binding = authority.attachedHistory.binding
            val receipt = authority.unitAttachmentReceipt
            if (
                binding.operationId != operationId || binding.shardId != shardId ||
                binding.unitName != unitName || binding.bindingSha256 != bindingSha256 ||
                receipt.receiptSha256 != receiptSha256 ||
                configuration.canonicalSha256 != binding.isolationConfigurationSha256
            ) isolationFail("recovered UNIT_ATTACHED BOOT identity changed")
            authority.requireCurrentReadOnly()
            if (readFullTreeFunctionObservationKernelBootId() != receipt.bootId) {
                isolationFail("recovered UNIT_ATTACHED receipt belongs to a previous kernel boot")
            }
            FullTreeScopeControl.validate(authenticatedScope)
            requireFullTreeObservationDiskClosureCompatibility(binding, resources.cleanupLimits)
            requirePreparedIsolationBinding(
                binding,
                paths,
                runDirectory,
                configuration,
                authenticatedScope,
                inputGuards,
                authenticatedInputs,
            )
            runtime.verify("while cold-adopted worker is at BOOT")
            inputGuards.verifyCurrent("while cold-adopted worker is at BOOT")
            boundary.verifyLiveOperation()
            authority.withCurrentRunRootAtBoot { borrowed ->
                if (borrowed.path != runDirectory) {
                    isolationFail("recovered UNIT_ATTACHED BOOT run-root locator changed")
                }
                BorrowedObservationRunTree.access(borrowed).use { runTree ->
                    requireObservationBootLayout(materializedClassPath, runTree, binding.bindingSha256)
                    unit.awaitBoot(binding.bindingSha256, runTree)
                    unit.verifyLiveContainment(resources)
                    unit.requireCurrentUnitAttachmentReceipt(receipt)
                    requireObservationBootLayout(materializedClassPath, runTree, binding.bindingSha256)
                }
            }
            requirePreparedIsolationOutputAbsent(paths.output)
            boundary.verifyLiveOperation()
            runtime.verify("after cold-adopted BOOT revalidation")
            inputGuards.verifyCurrent("after cold-adopted BOOT revalidation")
            if (readFullTreeFunctionObservationKernelBootId() != receipt.bootId) {
                isolationFail("kernel boot identity changed during recovered BOOT observation")
            }
            authority.requireCurrentReadOnly()
        } finally {
            operationActive = false
        }
    }

    /** Descriptor-only close; the observed systemd unit and receipt PIDs are never mutated. */
    @Synchronized
    override fun close() {
        if (closed) return
        if (operationActive) {
            isolationFail("recovered UNIT_ATTACHED BOOT observation cannot close while active")
        }
        closed = true
        closeRecoveredUnitAttachedBootResources(
            unit,
            boundary,
            inputGuards,
            runtime,
            authority,
            priorFailure = null,
        )?.let { throw it }
    }

    companion object {
        internal fun recover(
            coldAttached: FullTreeFunctionObservationColdUnitAttachedOperation,
            richArtifact: Path,
            inventoryPath: Path,
            scopeFiles: FullTreeFunctionObservationScopeFiles,
            output: Path,
            configuration: FullTreeFunctionObservationIsolationConfiguration,
        ): FullTreeFunctionObservationRecoveredUnitAttachedBootObservation = translateIsolationFailures(
            label = "cold UNIT_ATTACHED BOOT recovery",
        ) {
            var runtime: AuthenticatedObservationRuntime? = null
            var guards: ParentObservationInputGuards? = null
            var boundary: TrustedObservationBoundary? = null
            var unit: ManagedObservationUnit? = null
            var bootAuthority: FullTreeFunctionObservationColdUnitAttachedBootAuthority? = null
            try {
                coldAttached.requireCurrentReadOnly()
                val binding = coldAttached.attachedHistory.binding
                val receipt = coldAttached.unitAttachmentReceipt
                if (readFullTreeFunctionObservationKernelBootId() != receipt.bootId) {
                    isolationFail("cold UNIT_ATTACHED receipt belongs to a previous kernel boot")
                }
                val runDirectory = coldAttached.withCurrentRunRootAtBoot { borrowed -> borrowed.path }
                val runParent = runDirectory.parent
                    ?: isolationFail("cold UNIT_ATTACHED run root has no lease parent")
                val paths = IsolatedObservationPaths.normalize(
                    richArtifact,
                    inventoryPath,
                    scopeFiles,
                    runParent,
                    output,
                )
                requirePreparedIsolationPathTopology(binding, paths, runDirectory)

                val authenticated = FullTreeScopeControl.load(
                    paths.scopeFiles.scope,
                    paths.scopeFiles.sourceLock,
                    paths.scopeFiles.artifactManifest,
                )
                FullTreeScopeControl.validate(authenticated)
                val openedRuntime = AuthenticatedObservationRuntime.open(configuration)
                runtime = openedRuntime
                val resources = IsolatedObservationResources.derive(authenticated, openedRuntime.classPathBytes)
                requireFullTreeObservationDiskClosureCompatibility(binding, resources.cleanupLimits)
                val openedGuards = ParentObservationInputGuards.open(paths, authenticated)
                guards = openedGuards
                val inputs = FullTreeFunctionObservationProducer.authenticateShardInputs(
                    inventoryPath = paths.inventory,
                    scope = authenticated,
                    shardId = binding.shardId,
                )
                requirePreparedIsolationBinding(
                    binding,
                    paths,
                    runDirectory,
                    configuration,
                    authenticated,
                    openedGuards,
                    inputs,
                )
                openedRuntime.verify("before recovered BOOT run-tree authentication")
                openedGuards.verifyCurrent("before recovered BOOT run-tree authentication")
                requirePreparedIsolationOutputAbsent(paths.output)

                var recoveredClassPath: MaterializedObservationClassPath? = null
                coldAttached.withCurrentRunRootAtBoot { borrowed ->
                    if (borrowed.path != runDirectory) {
                        isolationFail("cold UNIT_ATTACHED run-root locator changed")
                    }
                    BorrowedObservationRunTree.access(borrowed).use { runTree ->
                        val materialized = openedRuntime.authenticateExistingClassPathAtBoot(runTree)
                        recoveredClassPath = materialized
                        requireObservationBootLayout(materialized, runTree, binding.bindingSha256)
                        openedRuntime.verify("at cold UNIT_ATTACHED BOOT adoption")
                        openedGuards.verifyCurrent("at cold UNIT_ATTACHED BOOT adoption")
                        requirePreparedIsolationOutputAbsent(paths.output)
                        if (readFullTreeFunctionObservationKernelBootId() != receipt.bootId) {
                            isolationFail("kernel boot identity changed before cold unit adoption")
                        }
                        val openedBoundary = TrustedObservationBoundary(
                            configuration,
                            openedRuntime,
                            materialized,
                        )
                        boundary = openedBoundary
                        val adopted = openedBoundary.adoptUnitAttached(
                            binding,
                            receipt,
                            runDirectory,
                            resources,
                        )
                        unit = adopted
                        adopted.awaitBoot(binding.bindingSha256, runTree)
                        adopted.verifyLiveContainment(resources)
                        adopted.requireCurrentUnitAttachmentReceipt(receipt)
                        requireObservationBootLayout(materialized, runTree, binding.bindingSha256)
                    }
                }
                val materialized = recoveredClassPath
                    ?: isolationFail("cold UNIT_ATTACHED class-path observation was not retained")
                requirePreparedIsolationOutputAbsent(paths.output)
                boundary?.verifyLiveOperation()
                    ?: isolationFail("cold UNIT_ATTACHED boundary observation was not retained")
                unit?.requireCurrentUnitAttachmentReceipt(receipt)
                    ?: isolationFail("cold UNIT_ATTACHED unit observation was not retained")
                coldAttached.requireCurrentReadOnly()

                val transferred = coldAttached.transferToBootAuthority()
                bootAuthority = transferred
                val result = FullTreeFunctionObservationRecoveredUnitAttachedBootObservation(
                    paths,
                    runDirectory,
                    configuration,
                    authenticated,
                    inputs,
                    resources,
                    openedRuntime,
                    openedGuards,
                    materialized,
                    transferred,
                    checkNotNull(boundary),
                    checkNotNull(unit),
                )
                runtime = null
                guards = null
                boundary = null
                unit = null
                bootAuthority = null
                result
            } catch (failure: Throwable) {
                closeRecoveredUnitAttachedBootResources(
                    unit,
                    boundary,
                    guards,
                    runtime,
                    bootAuthority,
                    priorFailure = failure,
                )
                throw failure
            }
        }
    }
}

private fun closeRecoveredUnitAttachedBootResources(
    unit: ManagedObservationUnit?,
    boundary: TrustedObservationBoundary?,
    inputGuards: ParentObservationInputGuards?,
    runtime: AuthenticatedObservationRuntime?,
    authority: FullTreeFunctionObservationColdUnitAttachedBootAuthority?,
    priorFailure: Throwable?,
): Throwable? {
    var failure = priorFailure
    fun record(closeFailure: Throwable) {
        val primary = failure
        if (primary == null) failure = closeFailure else if (closeFailure !== primary) {
            primary.addSuppressed(closeFailure)
        }
    }
    unit?.let { observed ->
        val abandoned = boundary?.let { owner ->
            runCatching { owner.abandonColdAdoption(observed) }.exceptionOrNull()
        }
        abandoned?.let(::record)
        if (!observed.cleaned) {
            runCatching { observed.abandonWithoutMutation() }.exceptionOrNull()?.let(::record)
        }
    }
    inputGuards?.let { opened -> runCatching { opened.close() }.exceptionOrNull()?.let(::record) }
    runtime?.let { opened -> runCatching { opened.close() }.exceptionOrNull()?.let(::record) }
    authority?.let { opened -> runCatching { opened.close() }.exceptionOrNull()?.let(::record) }
    return failure
}

private fun createBootedObservationIsolation(
    paths: IsolatedObservationPaths,
    runDirectory: Path,
    configuration: FullTreeFunctionObservationIsolationConfiguration,
    authenticatedScope: AuthenticatedFullTreeScope,
    authenticatedInputs: FullTreeFunctionObservationAuthenticatedInputs,
    resources: IsolatedObservationResources,
    runtime: AuthenticatedObservationRuntime,
    inputGuards: ParentObservationInputGuards,
    materializedClassPath: MaterializedObservationClassPath,
    authority: FullTreeFunctionObservationPreparedIsolationAuthority,
    boundary: TrustedObservationBoundary,
    unit: ManagedObservationUnit,
): FullTreeFunctionObservationBootedIsolation = FullTreeFunctionObservationBootedIsolation(
    BootedObservationIsolationOwnership(
        paths,
        runDirectory,
        configuration,
        authenticatedScope,
        authenticatedInputs,
        resources,
        runtime,
        inputGuards,
        materializedClassPath,
        authority,
        boundary,
        unit,
    ),
    BOOTED_OBSERVATION_ISOLATION_CONSTRUCTION_PERMIT,
)

/**
 * Parent-owned, non-authoritative containment fixture for one function-observation shard.
 *
 * The worker sees a synthetic mount root containing only its authenticated JVM/runtime/class path
 * and explicit read-only input binds. Its only host write authority is a fresh mode-0700
 * disk-backed run directory. It derives and independently validates
 * a private candidate there, then becomes quiescent at a READY/ACK barrier. A small Kotlin keeper
 * launches that worker in the same boundary and remains blocked after proving the worker exited
 * successfully. The parent then freezes the cgroup, verifies its complete process inventory, and
 * samples the immutable live cgroup files before intentionally killing the frozen keeper. Only
 * after the locally owned scope process has the exact expected SIGKILL status and both its unit and
 * cgroup are absent does the parent copy the unlinked inode into a no-replace 0400 fixture output.
 *
 * The summed cleanup-byte ceiling is a fail-closed recoverability bound, not a live aggregate disk
 * quota. RLIMIT_FSIZE independently limits each writable inode. Consequently this API and its
 * receipt must never enter release evidence: an authoritative runner still requires an independently
 * proven aggregate disk-quota authority plus durable operation identity and crash recovery.
 */
internal object FullTreeFunctionObservationIsolatedFixtureRunner {
    fun generateFixtureNoReplace(
        richArtifact: Path,
        inventoryPath: Path,
        scopeFiles: FullTreeFunctionObservationScopeFiles,
        shardId: String,
        scratchParent: Path,
        output: Path,
        configuration: FullTreeFunctionObservationIsolationConfiguration,
    ): FullTreeFunctionObservationIsolatedFixturePublication = translateIsolationFailures {
        val paths = IsolatedObservationPaths.normalize(
            richArtifact,
            inventoryPath,
            scopeFiles,
            scratchParent,
            output,
        )
        val authenticated = FullTreeScopeControl.load(
            paths.scopeFiles.scope,
            paths.scopeFiles.sourceLock,
            paths.scopeFiles.artifactManifest,
        )
        FullTreeScopeControl.validate(authenticated)
        requireDistinctControlOutput(
            paths.output,
            "rich artifact" to paths.richArtifact,
            "inventory" to paths.inventory,
            "scope" to paths.scopeFiles.scope,
            "source lock" to paths.scopeFiles.sourceLock,
            "artifact manifest" to paths.scopeFiles.artifactManifest,
        )
        if (Files.exists(paths.output, LinkOption.NOFOLLOW_LINKS)) {
            isolationFail("isolated function-observation publication target already exists")
        }

        AuthenticatedObservationRuntime.open(configuration).use { runtime ->
            val resources = IsolatedObservationResources.derive(authenticated, runtime.classPathBytes)
            ParentObservationInputGuards.open(paths, authenticated).use { guards ->
                val parentInputs = FullTreeFunctionObservationProducer.authenticateShardInputs(
                    inventoryPath = paths.inventory,
                    scope = authenticated,
                    shardId = shardId,
                )
                if (parentInputs.inventoryArtifactSha256 != guards.inventorySha256) {
                    isolationFail("parent shard authentication differs from its pinned inventory")
                }
                PrivateObservationRunTree.create(paths.scratchParent, resources).use { runTree ->
                    val classPath = runtime.materializeClassPath(runTree)
                    runtime.verify("immediately before isolated launch")
                    TrustedObservationBoundary(configuration, runtime, classPath).use { boundary ->
                    val request = IsolatedWorkerRequest(
                        nonce = randomHex(PROTOCOL_NONCE_BYTES),
                        paths = paths,
                        shardId = shardId,
                        runDirectory = runTree.path,
                    )
                    boundary.launch(request, resources).use { unit ->
                        unit.awaitBoot(request.nonce)
                        unit.verifyLiveContainment(resources)
                        val derivationStarted = System.nanoTime()
                        writeProtocolFile(runTree.descriptor, START_FILE, protocol("START", request.nonce))
                        val workerReceipt = unit.awaitReady(request.nonce, resources.wallSeconds)
                        val derivationWallNanos = monotonicElapsed(
                            derivationStarted,
                            System.nanoTime(),
                            "isolated function-observation derivation",
                        )
                        if (derivationWallNanos > secondsToNanos(resources.wallSeconds, "wall-clock")) {
                            isolationFail("isolated function-observation derivation exceeded its wall bound")
                        }
                        requireWorkerReceipt(
                            workerReceipt,
                            authenticated,
                            guards,
                            parentInputs,
                            shardId,
                            resources,
                        )

                        PinnedObservationCandidate.open(
                            runTree.descriptor,
                            workerReceipt.outputBytes,
                            workerReceipt.outputSha256,
                            resources.maximumOutputBytes,
                        ).use { candidate ->
                            candidate.unlinkFrom(runTree.descriptor)
                            writeProtocolFile(runTree.descriptor, ACK_FILE, protocol("ACK", request.nonce))
                            unit.awaitDone(request.nonce)
                            writeProtocolFile(
                                runTree.descriptor,
                                WORKER_RELEASE_FILE,
                                protocol("RELEASE", request.nonce),
                            )
                            unit.awaitWorkerExited(request.nonce)
                            val live = unit.freezeAndSampleRawCgroup(resources)
                            unit.killFrozenKeeperAndProveRemoved(resources, live)
                            if (live.peakResidentBytes < workerReceipt.peakResidentBytes) {
                                isolationFail(
                                    "post-exit cgroup peak is below the worker's resident-peak receipt",
                                )
                            }
                            unit.stopAndProveRemoved()
                            runTree.cleanAndRemove()

                            val published = ParentObservationPublisher.publish(
                                candidate = candidate,
                                target = paths.output,
                                expectedBytes = workerReceipt.outputBytes,
                                expectedSha256 = workerReceipt.outputSha256,
                                maximumBytes = resources.maximumOutputBytes,
                                beforeCommit = {
                                    boundary.verifyExecutablesForPublication()
                                    guards.verifyDigests(workerReceipt)
                                },
                                afterCommit = {
                                    boundary.verifyExecutablesForPublication()
                                    guards.verifyDigests(workerReceipt)
                                },
                            )
                            check(published.bytes == workerReceipt.outputBytes)
                            check(published.sha256 == workerReceipt.outputSha256)
                            FullTreeFunctionObservationIsolatedFixturePublication(
                                fixtureShard = workerReceipt.copy(peakResidentBytes = live.peakResidentBytes),
                                cgroup = FullTreeFunctionObservationCgroupReceipt(
                                    peakResidentBytes = live.peakResidentBytes,
                                    cpuNanos = live.cpuNanos,
                                    derivationWallNanos = derivationWallNanos,
                                    memoryMaxEvents = live.memoryMaxEvents,
                                    memoryOomEvents = live.memoryOomEvents,
                                    memoryOomKillEvents = live.memoryOomKillEvents,
                                ),
                            )
                        }
                    }
                    }
                }
            }
        }
    }
}

/** Process entry point used only inside the Kotlin-owned fixture or production isolation boundary. */
internal object FullTreeFunctionObservationIsolatedWorker {
    @JvmStatic
    fun main(arguments: Array<String>) {
        var root: LinuxDescriptor? = null
        var nonce: String? = null
        try {
            val request = IsolatedWorkerRequest.parse(arguments)
            nonce = request.nonce
            val (_, identity) = requireStableDirectory(request.runDirectory, "isolated worker run directory")
            root = LinuxFilesystemSyscalls.openRoot(request.runDirectory)
            if (!Files.isSameFile(
                    request.runDirectory,
                    LinuxFilesystemSyscalls.stableDescriptorPath(root.fd),
                ) || identity != Files.readAttributes(
                    request.runDirectory,
                    java.nio.file.attribute.BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                ).fileKey()
            ) {
                isolationFail("isolated worker run directory changed during startup")
            }
            requirePrivateDirectory(root, "isolated worker run directory")
            writeProtocolFile(root, BOOT_FILE, protocol("BOOT", request.nonce))
            awaitWorkerProtocol(root, START_FILE, protocol("START", request.nonce), WORKER_START_TIMEOUT)

            val scope = FullTreeScopeControl.load(
                request.paths.scopeFiles.scope,
                request.paths.scopeFiles.sourceLock,
                request.paths.scopeFiles.artifactManifest,
            )
            val receipt = FullTreeFunctionObservationShardPublisher.generateAndPublish(
                richArtifact = request.paths.richArtifact,
                inventoryPath = request.paths.inventory,
                scope = scope,
                shardId = request.shardId,
                scratchParent = request.runDirectory.resolve(SCRATCH_DIRECTORY),
                output = request.runDirectory.resolve(CANDIDATE_FILE),
                limits = ISOLATED_PUBLISHER_LIMITS,
            )
            writeProtocolFile(root, READY_FILE, encodeReady(request.nonce, receipt))
            awaitWorkerProtocol(root, ACK_FILE, protocol("ACK", request.nonce), WORKER_ACK_TIMEOUT)
            writeProtocolFile(root, DONE_FILE, protocol("DONE", request.nonce))
            awaitWorkerProtocol(
                root,
                WORKER_RELEASE_FILE,
                protocol("RELEASE", request.nonce),
                WORKER_EXIT_TIMEOUT,
            )
            root.close()
            Runtime.getRuntime().halt(0)
        } catch (failure: Throwable) {
            val descriptor = root
            val token = nonce
            if (descriptor != null && token != null) {
                runCatching {
                    writeProtocolFile(descriptor, FAILURE_FILE, encodeFailure(token, failure))
                }
                runCatching { Thread.sleep(WORKER_FAILURE_OBSERVATION_MILLIS) }
            }
            if (descriptor != null) {
                runCatching { deletePrivateTreeContents(descriptor, WORKER_FAILURE_CLEANUP_LIMITS) }
            }
            runCatching { descriptor?.close() }
            System.err.println("isolated function-observation worker failed safely")
            exitProcess(WORKER_FAILURE_EXIT)
        }
    }
}

/**
 * Tiny same-cgroup keeper which turns worker exit into a parent-observable, freezable barrier.
 *
 * It never receives an output path outside the private run tree. Once the child has exited zero it
 * writes a durable proof containing its PID-namespace identity and blocks without further work.
 * The trusted parent verifies that this JVM and bubblewrap are the only remaining processes before
 * freezing and intentionally killing the cgroup.
 */
internal object FullTreeFunctionObservationIsolatedSupervisor {
    @JvmStatic
    fun main(arguments: Array<String>) {
        var root: LinuxDescriptor? = null
        var child: Process? = null
        var nonce: String? = null
        try {
            val request = IsolatedSupervisorRequest.parse(arguments)
            nonce = request.worker.nonce
            val (_, identity) = requireStableDirectory(
                request.worker.runDirectory,
                "isolated supervisor run directory",
            )
            root = LinuxFilesystemSyscalls.openRoot(request.worker.runDirectory)
            if (!Files.isSameFile(
                    request.worker.runDirectory,
                    LinuxFilesystemSyscalls.stableDescriptorPath(root.fd),
                ) || identity != Files.readAttributes(
                    request.worker.runDirectory,
                    java.nio.file.attribute.BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                ).fileKey()
            ) {
                isolationFail("isolated supervisor run directory changed during startup")
            }
            requirePrivateDirectory(root, "isolated supervisor run directory")

            val workerProcess = ProcessBuilder(request.workerCommand())
                .directory(request.worker.runDirectory.toFile())
                .redirectInput(ProcessBuilder.Redirect.PIPE)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .also { builder ->
                    builder.environment().clear()
                    builder.environment()["HOME"] = request.worker.runDirectory.toString()
                    builder.environment()["TMPDIR"] =
                        request.worker.runDirectory.resolve(TEMP_DIRECTORY).toString()
                }
                .start()
            child = workerProcess
            workerProcess.outputStream.close()
            val status = workerProcess.waitFor()
            if (status != 0) isolationFail("isolated worker exited unsuccessfully")
            writeProtocolFile(
                root,
                WORKER_EXITED_FILE,
                keeperProtocol(request.worker.nonce, ProcessHandle.current().pid()),
            )

            // A successful run ends only when the parent SIGKILLs this frozen keeper. Sleeping
            // forever makes the post-proof state allocation-free and CPU-quiescent.
            while (true) Thread.sleep(Long.MAX_VALUE)
        } catch (failure: Throwable) {
            val process = child
            if (process != null && process.isAlive) {
                runCatching { process.destroyForcibly() }
                runCatching {
                    process.waitFor(WORKER_EXIT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
                }
            }
            val descriptor = root
            val token = nonce
            if (descriptor != null && token != null) {
                runCatching {
                    writeProtocolFile(descriptor, SUPERVISOR_FAILURE_FILE, encodeFailure(token, failure))
                }
                runCatching { Thread.sleep(WORKER_FAILURE_OBSERVATION_MILLIS) }
            }
            runCatching { descriptor?.close() }
            System.err.println("isolated function-observation supervisor failed safely")
            Runtime.getRuntime().halt(SUPERVISOR_FAILURE_EXIT)
        }
    }
}

/** Fixed BOOT-only entry point. It has no accepted START byte or export code path. */
internal object KotlinSystemdCgroupBootKeeper {
    @JvmStatic
    fun main(arguments: Array<String>) {
        var root: LinuxDescriptor? = null
        var nonce: String? = null
        try {
            if (arguments.size != KOTLIN_BOOT_ARGUMENTS || arguments[0] != KOTLIN_BOOT_PROTOCOL_VERSION) {
                isolationFail("generic Kotlin BOOT keeper arguments are invalid")
            }
            val runDirectory = Path.of(arguments[1])
            if (!runDirectory.isAbsolute || runDirectory.normalize() != runDirectory) {
                isolationFail("generic Kotlin BOOT run directory is invalid")
            }
            val parsedNonce = arguments[2]
            if (!parsedNonce.matches(SHA256)) isolationFail("generic Kotlin BOOT nonce is invalid")
            nonce = parsedNonce
            val (_, identity) = requireStableDirectory(runDirectory, "generic Kotlin BOOT run directory")
            val opened = LinuxFilesystemSyscalls.openRoot(runDirectory)
            root = opened
            if (
                !Files.isSameFile(runDirectory, LinuxFilesystemSyscalls.stableDescriptorPath(opened.fd)) ||
                identity != Files.readAttributes(
                    runDirectory,
                    java.nio.file.attribute.BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                ).fileKey()
            ) isolationFail("generic Kotlin BOOT run directory changed during startup")
            requirePrivateDirectory(opened, "generic Kotlin BOOT run directory")
            writeProtocolFile(opened, BOOT_FILE, protocol("BOOT", parsedNonce))

            // This entry point has no input/token transition at all. The launcher intentionally
            // closes its stdin after exec, so treating EOF as a terminal event would let the
            // supposedly retained UNIT_ATTACHED scope disappear immediately after BOOT. Remain
            // allocation-free and CPU-quiescent until PDEATHSIG or whole-cgroup SIGKILL instead.
            while (true) Thread.sleep(Long.MAX_VALUE)
        } catch (failure: Throwable) {
            val descriptor = root
            val token = nonce
            if (descriptor != null && token != null) {
                runCatching { writeProtocolFile(descriptor, FAILURE_FILE, encodeFailure(token, failure)) }
                runCatching { Thread.sleep(WORKER_FAILURE_OBSERVATION_MILLIS) }
            }
            runCatching { descriptor?.close() }
            System.err.println("generic Kotlin BOOT keeper failed safely")
            Runtime.getRuntime().halt(KOTLIN_BOOT_FAILURE_EXIT)
        }
    }
}

private data class IsolatedObservationPaths(
    val richArtifact: Path,
    val inventory: Path,
    val scopeFiles: FullTreeFunctionObservationScopeFiles,
    val scratchParent: Path,
    val output: Path,
) {
    companion object {
        fun normalize(
            richArtifact: Path,
            inventory: Path,
            scopeFiles: FullTreeFunctionObservationScopeFiles,
            scratchParent: Path,
            output: Path,
        ): IsolatedObservationPaths = IsolatedObservationPaths(
            richArtifact.toAbsolutePath().normalize(),
            inventory.toAbsolutePath().normalize(),
            FullTreeFunctionObservationScopeFiles(
                scopeFiles.scope.toAbsolutePath().normalize(),
                scopeFiles.sourceLock.toAbsolutePath().normalize(),
                scopeFiles.artifactManifest.toAbsolutePath().normalize(),
            ),
            scratchParent.toAbsolutePath().normalize(),
            output.toAbsolutePath().normalize(),
        )
    }
}

private fun requirePreparedIsolationBinding(
    binding: FullTreeFunctionObservationOperationBinding,
    paths: IsolatedObservationPaths,
    runDirectory: Path,
    configuration: FullTreeFunctionObservationIsolationConfiguration,
    authenticated: AuthenticatedFullTreeScope,
    guards: ParentObservationInputGuards,
    inputs: FullTreeFunctionObservationAuthenticatedInputs,
) {
    FullTreeScopeControl.validate(authenticated)
    requirePreparedIsolationPathTopology(binding, paths, runDirectory)
    if (configuration.canonicalSha256 != binding.isolationConfigurationSha256) {
        isolationFail("prepared isolation configuration differs from its operation binding")
    }
    if (authenticated.sha256 != binding.scopeSha256) {
        isolationFail("prepared isolation scope differs from its operation binding")
    }
    if (
        guards.inventorySha256 != binding.inventoryArtifactSha256 ||
        guards.richSha256 != binding.richArtifactSha256
    ) isolationFail("prepared isolation artifacts differ from their operation binding")
    if (
        inputs.inventoryArtifactSha256 != guards.inventorySha256 ||
        inputs.inventoryArtifactSha256 != binding.inventoryArtifactSha256 ||
        inputs.shard.identifier != binding.shardId ||
        inputs.shard.inputSha256 != binding.shardInputSha256
    ) isolationFail("prepared isolation shard input differs from its operation binding")
    val outputPathSha256 = OracleArtifacts.sha256(paths.output.toString().toByteArray(Charsets.UTF_8))
    if (outputPathSha256 != binding.outputPathSha256) {
        isolationFail("prepared isolation output path differs from its operation binding")
    }
    requirePreparedIsolationOutputAbsent(paths.output)
}

private fun requirePreparedIsolationPathTopology(
    binding: FullTreeFunctionObservationOperationBinding,
    paths: IsolatedObservationPaths,
    runDirectory: Path,
) {
    if (
        !runDirectory.isAbsolute || runDirectory.normalize() != runDirectory ||
        runDirectory.fileName?.toString() != binding.runDirectoryName ||
        runDirectory.parent?.fileName?.toString() != binding.leaseDirectoryName ||
        paths.scratchParent != runDirectory.parent
    ) isolationFail("prepared isolation run path differs from its deterministic operation names")
    val inputs = listOf(
        paths.richArtifact,
        paths.inventory,
        paths.scopeFiles.scope,
        paths.scopeFiles.sourceLock,
        paths.scopeFiles.artifactManifest,
    )
    requireDistinctControlOutput(
        paths.output,
        "rich artifact" to paths.richArtifact,
        "inventory" to paths.inventory,
        "scope" to paths.scopeFiles.scope,
        "source lock" to paths.scopeFiles.sourceLock,
        "artifact manifest" to paths.scopeFiles.artifactManifest,
    )
    val leaseRoot = runDirectory.parent
        ?: isolationFail("prepared isolation run path has no lease root")
    val outputParent = paths.output.parent
        ?: isolationFail("prepared isolation output path has no parent")
    val (canonicalOutputParent, _) = requireStableDirectory(
        outputParent,
        "prepared function-observation output parent",
    )
    val canonicalLeaseRoot = try {
        leaseRoot.toRealPath()
    } catch (failure: Exception) {
        throw FullTreeFunctionObservationIsolationException(
            "prepared isolation lease root is unavailable",
            failure,
        )
    }
    if (
        canonicalOutputParent != outputParent || canonicalLeaseRoot != leaseRoot ||
        inputs.any { pathsOverlap(it, runDirectory) } ||
        pathsOverlap(canonicalOutputParent, canonicalLeaseRoot)
    ) {
        isolationFail("prepared isolation input or output overlaps its private disk authority")
    }
}

private fun requirePreparedIsolationOutputAbsent(output: Path) {
    val parent = output.parent
        ?: isolationFail("prepared function-observation publication target has no parent")
    val name = output.fileName?.toString()
        ?: isolationFail("prepared function-observation publication target has no name")
    val (canonicalParent, parentKeyBefore) = requireStableDirectory(
        parent,
        "prepared function-observation output parent",
    )
    if (canonicalParent != parent) {
        isolationFail("prepared function-observation output parent is not canonical")
    }
    LinuxFilesystemSyscalls.openRoot(canonicalParent).use { descriptor ->
        descriptor.whileOpen { fd ->
            if (!Files.isSameFile(canonicalParent, LinuxFilesystemSyscalls.stableDescriptorPath(fd))) {
                isolationFail("prepared function-observation output parent changed during absence proof")
            }
            val before = LinuxFilesystemSyscalls.identity(fd)
            LinuxFilesystemSyscalls.openPathAtOrNull(fd, name)?.use {
                isolationFail("prepared function-observation publication target already exists")
            }
            val after = LinuxFilesystemSyscalls.identity(fd)
            if (after != before) {
                isolationFail("prepared function-observation output parent changed during absence proof")
            }
        }
    }
    val (parentAfter, parentKeyAfter) = requireStableDirectory(
        parent,
        "prepared function-observation output parent after absence proof",
    )
    if (parentAfter != canonicalParent || parentKeyAfter != parentKeyBefore) {
        isolationFail("prepared function-observation output parent changed during absence proof")
    }
}

/**
 * Proves only that the committed hard physical/inode aggregate caps fit the isolation closure
 * ceilings. Sparse logical size and excessive depth remain fail-closed recovery/reset concerns and
 * require separate whole-run accounting before release certification.
 */
internal fun requireFullTreeObservationDiskClosureCompatibility(
    binding: FullTreeFunctionObservationOperationBinding,
    limits: AcpRuntimeClosureLimits,
) {
    if (
        binding.maximumFilesystemBytes > limits.maximumUserOwnedFileBytes ||
        binding.maximumFilesystemInodes > limits.maximumEntries.toLong()
    ) isolationFail("prepared disk authority exceeds the bounded isolation closure")
}

private fun closePreparedIsolationResources(
    inputGuards: ParentObservationInputGuards?,
    runtime: AuthenticatedObservationRuntime?,
    authority: FullTreeFunctionObservationPreparedIsolationAuthority?,
    untransferred: FullTreeFunctionObservationPreparedRun?,
    priorFailure: Throwable?,
): Throwable? {
    var failure = priorFailure
    fun record(closeFailure: Throwable) {
        val primary = failure
        if (primary == null) failure = closeFailure else if (closeFailure !== primary) {
            primary.addSuppressed(closeFailure)
        }
    }
    if (authority != null && untransferred != null) {
        record(IllegalStateException("prepared isolation retained two linear operation wrappers"))
    }
    inputGuards?.let { guards -> runCatching { guards.close() }.exceptionOrNull()?.let(::record) }
    runtime?.let { opened -> runCatching { opened.close() }.exceptionOrNull()?.let(::record) }
    authority?.let { owner -> runCatching { owner.close() }.exceptionOrNull()?.let(::record) }
    untransferred?.let { owner -> runCatching { owner.close() }.exceptionOrNull()?.let(::record) }
    return failure
}

private fun closeUnitAttachedIsolationResources(
    inputGuards: ParentObservationInputGuards?,
    runtime: AuthenticatedObservationRuntime?,
    authority: FullTreeFunctionObservationUnitAttachedIsolationAuthority,
    priorFailure: Throwable?,
): Throwable? = closeTransferredIsolationResources(
    inputGuards,
    runtime,
    priorFailure,
    authority::closeAfterProvedCgroupAbsence,
)

private fun closeFailedAttachmentIsolationResources(
    inputGuards: ParentObservationInputGuards?,
    runtime: AuthenticatedObservationRuntime?,
    authority: FullTreeFunctionObservationPreparedIsolationAuthority,
    priorFailure: Throwable?,
): Throwable? = closeTransferredIsolationResources(
    inputGuards,
    runtime,
    priorFailure,
    authority::closeAfterFailedAttachmentPublication,
)

private fun closeTransferredIsolationResources(
    inputGuards: ParentObservationInputGuards?,
    runtime: AuthenticatedObservationRuntime?,
    priorFailure: Throwable?,
    closeAuthority: () -> Unit,
): Throwable? {
    var failure = priorFailure
    fun record(closeFailure: Throwable) {
        val primary = failure
        if (primary == null) failure = closeFailure else if (closeFailure !== primary) {
            primary.addSuppressed(closeFailure)
        }
    }
    inputGuards?.let { guards -> runCatching { guards.close() }.exceptionOrNull()?.let(::record) }
    runtime?.let { opened -> runCatching { opened.close() }.exceptionOrNull()?.let(::record) }
    runCatching(closeAuthority).exceptionOrNull()?.let(::record)
    return failure
}

private data class IsolatedObservationResources(
    val maximumResidentBytes: Long,
    val maximumAddressSpaceBytes: Long,
    val maximumOutputBytes: Long,
    val maximumDatabaseBytes: Long,
    val maximumFileBytes: Long,
    val maximumEntities: Long,
    val cpuSeconds: Long,
    val wallSeconds: Long,
    val serviceRuntimeSeconds: Long,
    val tasksMax: Long,
    val timeoutStopMillis: Long,
    val cleanupLimits: AcpRuntimeClosureLimits,
) {
    companion object {
        fun derive(
            scope: AuthenticatedFullTreeScope,
            classPathBytes: Long,
        ): IsolatedObservationResources {
            val perShard = scope.document.controlObject("bounds").controlObject("perShard")
            val authenticatedOutput = perShard.controlLong("serializedBytes")
            val maximumOutput = minOf(authenticatedOutput, ISOLATED_PUBLISHER_LIMITS.maximumOutputBytes)
            if (maximumOutput <= 0L) isolationFail("authenticated isolated output bound is empty")
            val expanded = multiplyExact(authenticatedOutput, SQLITE_EXPANSION, "SQLite scratch bound")
            val maximumDatabase = minOf(expanded, ISOLATED_PUBLISHER_LIMITS.maximumDatabaseBytes)
            val resident = perShard.controlLong("maximumResidentBytes")
            val entities = perShard.controlLong("entities")
            val cpu = perShard.controlLong("cpuSeconds")
            val wall = perShard.controlLong("wallClockSeconds")
            if (resident < MINIMUM_WORKER_MEMORY_BYTES || entities <= 0L || cpu <= 0L || wall <= 0L) {
                isolationFail("authenticated isolated runtime bounds are not usable")
            }
            val runtimeOverhead = listOf(
                WORKER_START_TIMEOUT,
                WORKER_ACK_TIMEOUT,
                WORKER_EXIT_TIMEOUT,
                WORKER_EXIT_TIMEOUT,
                CGROUP_FREEZE_TIMEOUT,
                SERVICE_CLEANUP_TIMEOUT,
            ).fold(0L) { total, timeout ->
                addExact(total, timeout.seconds, "systemd runtime overhead")
            }
            val runtime = addExact(wall, runtimeOverhead, "systemd runtime bound")
            val cleanupBytes = isolatedObservationCleanupBytes(
                maximumOutput,
                maximumDatabase,
                DEFAULT_CONTROL_LIMITS.maximumDwarfScratchBytes,
                addExact(
                    PROTOCOL_CLEANUP_ALLOWANCE_BYTES,
                    classPathBytes,
                    "private cleanup runtime allowance",
                ),
            )
            val maximumFile = maxOf(
                maximumOutput,
                maximumDatabase,
                DEFAULT_CONTROL_LIMITS.maximumDwarfSectionBytes,
            )
            val modeledAddressSpace = multiplyExact(resident, ADDRESS_SPACE_FACTOR, "address-space backstop")
            val addressSpace = minOf(
                maxOf(MINIMUM_WORKER_ADDRESS_SPACE_BYTES, modeledAddressSpace),
                MAXIMUM_WORKER_ADDRESS_SPACE_BYTES,
            )
            if (addressSpace < resident) isolationFail("isolated address-space backstop is below resident memory")
            return IsolatedObservationResources(
                resident,
                addressSpace,
                maximumOutput,
                maximumDatabase,
                maximumFile,
                entities,
                cpu,
                wall,
                runtime,
                CGROUP_TASKS_MAX.toLong(),
                SERVICE_CLEANUP_TIMEOUT.toMillis(),
                AcpRuntimeClosureLimits(
                    maximumEntries = MAXIMUM_PRIVATE_ENTRIES,
                    maximumUserOwnedFileBytes = cleanupBytes,
                    maximumDepth = MAXIMUM_PRIVATE_DEPTH,
                ),
            )
        }

        fun forKotlinBoot(requested: KotlinSystemdCgroupBootResources): IsolatedObservationResources {
            if (requested.wallClockMillis % 1_000L != 0L) {
                isolationFail("Kotlin BOOT wall-clock policy must use whole seconds")
            }
            val wallSeconds = requested.wallClockMillis / 1_000L
            val addressSpace = minOf(
                maxOf(MINIMUM_WORKER_ADDRESS_SPACE_BYTES, requested.maximumResidentBytes),
                MAXIMUM_WORKER_ADDRESS_SPACE_BYTES,
            )
            if (addressSpace < requested.maximumResidentBytes) {
                isolationFail("Kotlin BOOT address-space backstop is below its memory cgroup")
            }
            return IsolatedObservationResources(
                maximumResidentBytes = requested.maximumResidentBytes,
                maximumAddressSpaceBytes = addressSpace,
                maximumOutputBytes = MAXIMUM_PROTOCOL_BYTES.toLong(),
                maximumDatabaseBytes = MAXIMUM_PROTOCOL_BYTES.toLong(),
                // A fresh JVM must extract its authenticated JNA dispatch library before the
                // descriptor-backed BOOT protocol can run. Keep that bootstrap bounded by the
                // existing fixed cleanup allowance; writeProtocolFile independently retains the
                // 16-KiB canonical protocol-record bound.
                maximumFileBytes = requested.maximumRuntimeFileBytes,
                maximumEntities = 1L,
                cpuSeconds = wallSeconds,
                wallSeconds = wallSeconds,
                serviceRuntimeSeconds = wallSeconds,
                tasksMax = requested.pidsMax,
                timeoutStopMillis = KOTLIN_BOOT_TIMEOUT_STOP_MILLIS,
                cleanupLimits = AcpRuntimeClosureLimits(
                    maximumEntries = KOTLIN_BOOT_MAXIMUM_PRIVATE_ENTRIES,
                    maximumUserOwnedFileBytes = KOTLIN_BOOT_MAXIMUM_PRIVATE_BYTES,
                    maximumDepth = KOTLIN_BOOT_MAXIMUM_PRIVATE_DEPTH,
                ),
            )
        }
    }
}

private data class IsolatedWorkerRequest(
    val nonce: String,
    val paths: IsolatedObservationPaths,
    val shardId: String,
    val runDirectory: Path,
) {
    fun arguments(): List<String> = listOf(
        WORKER_PROTOCOL_VERSION,
        nonce,
        paths.richArtifact.toString(),
        paths.inventory.toString(),
        paths.scopeFiles.scope.toString(),
        paths.scopeFiles.sourceLock.toString(),
        paths.scopeFiles.artifactManifest.toString(),
        shardId,
        runDirectory.toString(),
    )

    companion object {
        fun parse(arguments: Array<String>): IsolatedWorkerRequest {
            if (arguments.size != WORKER_ARGUMENTS || arguments[0] != WORKER_PROTOCOL_VERSION) {
                isolationFail("isolated worker request has an unsupported shape")
            }
            val nonce = arguments[1]
            if (!nonce.matches(PROTOCOL_NONCE)) isolationFail("isolated worker nonce is invalid")
            val absolute = arguments.slice(2..6).map { value ->
                Path.of(value).also { path ->
                    if (!path.isAbsolute || path.normalize() != path) {
                        isolationFail("isolated worker input path is not absolute and normalized")
                    }
                }
            }
            val shardId = arguments[7]
            if (!shardId.matches(SHARD_IDENTIFIER)) isolationFail("isolated worker shard identifier is invalid")
            val run = Path.of(arguments[8])
            if (!run.isAbsolute || run.normalize() != run) {
                isolationFail("isolated worker run path is not absolute and normalized")
            }
            return IsolatedWorkerRequest(
                nonce,
                IsolatedObservationPaths(
                    absolute[0],
                    absolute[1],
                    FullTreeFunctionObservationScopeFiles(absolute[2], absolute[3], absolute[4]),
                    run.parent ?: isolationFail("isolated worker run path has no parent"),
                    run.resolve(CANDIDATE_FILE),
                ),
                shardId,
                run,
            )
        }
    }
}

internal fun isolatedObservationJvmTemporaryArguments(runDirectory: Path, nativeDirectory: Path): List<String> {
    require(!pathsOverlap(runDirectory, nativeDirectory)) { "Oracle native libraries must not come from writable scratch" }
    return OracleNativeLibraries.jvmArguments(nativeDirectory) + listOf(
        "-Djna.tmpdir=${runDirectory.resolve(TEMP_DIRECTORY)}",
        "-Djava.io.tmpdir=${runDirectory.resolve(TEMP_DIRECTORY)}",
    )
}

private data class IsolatedSupervisorRequest(
    val javaExecutable: Path,
    val classPath: String,
    val nativeDirectory: Path,
    val worker: IsolatedWorkerRequest,
) {
    fun workerCommand(): List<String> = buildList {
        add(javaExecutable.toString())
        add("-XX:+UseSerialGC")
        add("-XX:ActiveProcessorCount=1")
        add("-XX:-UsePerfData")
        add("-XX:MaxRAMPercentage=50")
        addAll(isolatedObservationJvmTemporaryArguments(worker.runDirectory, nativeDirectory))
        add("-classpath")
        add(classPath)
        add(FullTreeFunctionObservationIsolatedWorker::class.java.name)
        addAll(worker.arguments())
    }

    companion object {
        fun parse(arguments: Array<String>): IsolatedSupervisorRequest {
            if (
                arguments.size != SUPERVISOR_ARGUMENTS ||
                arguments[0] != SUPERVISOR_PROTOCOL_VERSION
            ) isolationFail("isolated supervisor request has an unsupported shape")
            val javaExecutable = Path.of(arguments[1])
            if (
                !javaExecutable.isAbsolute || javaExecutable.normalize() != javaExecutable ||
                !Files.isRegularFile(javaExecutable, LinkOption.NOFOLLOW_LINKS) ||
                !Files.isExecutable(javaExecutable)
            ) isolationFail("isolated supervisor Java executable is unavailable")
            val classPath = arguments[2]
            if (
                classPath.toByteArray(Charsets.UTF_8).size > MAXIMUM_CLASSPATH_BYTES ||
                classPath != System.getProperty("java.class.path")
            ) isolationFail("isolated supervisor class path differs from its launch boundary")
            val entries = classPath.split(java.io.File.pathSeparator)
                .filter(String::isNotEmpty)
                .map { Path.of(it) }
            if (validatedClassPath(entries) != classPath) {
                isolationFail("isolated supervisor class path is not canonical")
            }
            return IsolatedSupervisorRequest(
                javaExecutable = javaExecutable,
                classPath = classPath,
                nativeDirectory = Path.of(arguments[3]).also { native ->
                    if (!native.isAbsolute || native.normalize() != native) {
                        isolationFail("isolated supervisor native directory is not canonical")
                    }
                },
                worker = IsolatedWorkerRequest.parse(arguments.copyOfRange(4, arguments.size)),
            )
        }
    }
}

private class ParentObservationInputGuards private constructor(
    private val scope: StableControlFile,
    private val sourceLock: StableControlFile,
    private val manifest: StableControlFile,
    private val inventory: StableControlFile,
    private val rich: StableControlFile,
    private val initialScopeSha256: String,
    private val initialSourceLockSha256: String,
    private val initialManifestSha256: String,
    val inventorySha256: String,
    val richSha256: String,
) : AutoCloseable {
    fun verifyCurrent(label: String) {
        if (
            scope.sha256(label = "isolated scope $label") != initialScopeSha256 ||
            sourceLock.sha256(label = "isolated source lock $label") != initialSourceLockSha256 ||
            manifest.sha256(label = "isolated manifest $label") != initialManifestSha256 ||
            inventory.sha256(label = "isolated inventory $label") != inventorySha256 ||
            rich.sha256(label = "isolated rich artifact $label") != richSha256
        ) isolationFail("authenticated isolated inputs changed $label")
        verifyMetadata()
    }

    fun verifyDigests(receipt: FullTreeFunctionObservationPublishedShard) {
        verifyCurrent("before parent publication")
        if (
            receipt.scopeSha256 != initialScopeSha256 ||
            receipt.inventoryArtifactSha256 != inventorySha256 ||
            receipt.richArtifactSha256 != richSha256
        ) isolationFail("isolated worker receipt is not bound to the parent's pinned inputs")
    }

    fun verifyMetadata() {
        scope.verifyUnchanged("isolated scope during publication")
        sourceLock.verifyUnchanged("isolated source lock during publication")
        manifest.verifyUnchanged("isolated manifest during publication")
        inventory.verifyUnchanged("isolated inventory during publication")
        rich.verifyUnchanged("isolated rich artifact during publication")
    }

    override fun close() {
        var failure: Throwable? = null
        listOf(rich, inventory, manifest, sourceLock, scope).forEach { guard ->
            try {
                guard.close()
            } catch (closeFailure: Throwable) {
                if (failure == null) failure = closeFailure else if (closeFailure !== failure) {
                    failure.addSuppressed(closeFailure)
                }
            }
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(
            paths: IsolatedObservationPaths,
            authenticated: AuthenticatedFullTreeScope,
        ): ParentObservationInputGuards {
            val opened = ArrayDeque<StableControlFile>()
            try {
                fun guard(path: Path, maximum: Long, label: String): StableControlFile =
                    StableControlFile.open(path, maximum, label).also(opened::addFirst)
                val scope = guard(paths.scopeFiles.scope, DEFAULT_CONTROL_LIMITS.maximumScopeBytes.toLong(), "scope")
                val lock = guard(
                    paths.scopeFiles.sourceLock,
                    DEFAULT_CONTROL_LIMITS.maximumSourceLockBytes.toLong(),
                    "source lock",
                )
                val manifest = guard(
                    paths.scopeFiles.artifactManifest,
                    DEFAULT_CONTROL_LIMITS.maximumArtifactManifestBytes.toLong(),
                    "artifact manifest",
                )
                val inventory = guard(
                    paths.inventory,
                    DEFAULT_CONTROL_LIMITS.maximumInventoryBytes.toLong(),
                    "function-observation inventory",
                )
                val rich = guard(
                    paths.richArtifact,
                    DEFAULT_CONTROL_LIMITS.maximumRichArtifactBytes,
                    "function-observation rich artifact",
                )
                val scopeSha = scope.sha256(label = "isolated scope at authorization")
                val lockSha = lock.sha256(label = "isolated source lock at authorization")
                val manifestSha = manifest.sha256(label = "isolated manifest at authorization")
                val inventorySha = inventory.sha256(label = "isolated inventory at authorization")
                val richSha = rich.sha256(label = "isolated rich artifact at authorization")
                if (
                    scopeSha != authenticated.sha256 || lockSha != authenticated.sourceLockSha256 ||
                    manifestSha != authenticated.artifactManifestSha256
                ) isolationFail("parent control snapshots differ from the authenticated isolated scope")
                if (
                    richSha != authenticated.document.controlObject("oracle")
                        .controlString("richArtifactSha256")
                ) isolationFail("parent rich artifact differs from the authenticated isolated scope")
                opened.clear()
                return ParentObservationInputGuards(
                    scope,
                    lock,
                    manifest,
                    inventory,
                    rich,
                    scopeSha,
                    lockSha,
                    manifestSha,
                    inventorySha,
                    richSha,
                )
            } catch (failure: Throwable) {
                opened.forEach { guard -> runCatching { guard.close() }.exceptionOrNull()?.let(failure::addSuppressed) }
                throw failure
            }
        }
    }
}

/**
 * Descriptor-backed access shared by owned fixture trees and lexically borrowed production trees.
 * Destructive cleanup is deliberately absent: ownership is a property of the concrete type.
 */
internal sealed interface ObservationRunTreeAccess {
    val path: Path

    fun <T> withPinnedDescriptor(action: (LinuxDescriptor) -> T): T
}

private fun materializeObservationClassPath(
    runPath: Path,
    descriptor: LinuxDescriptor,
    entries: List<Pair<FullTreeFunctionObservationClassPathEntry, StableControlFile>>,
): MaterializedObservationClassPath {
    val paths = mutableListOf<Path>()
    val expected = mutableListOf<Pair<Long, String>>()
    descriptor.whileOpen { fd ->
        LinuxFilesystemSyscalls.openDirectoryAt(fd, RUNTIME_DIRECTORY)
    }.use { runtime ->
        entries.forEachIndexed { index, (entry, source) ->
            val name = "classpath-$index.jar"
            val target = runtime.whileOpen { fd ->
                LinuxFilesystemSyscalls.createRegularFile(fd, name, OWNER_READ_WRITE_MODE)
            }
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                FileChannel.open(
                    LinuxFilesystemSyscalls.stableDescriptorPath(target.fd),
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                ).use { output ->
                    source.slice().use { input ->
                        val bytes = ByteArray(COPY_BUFFER_BYTES)
                        var total = 0L
                        while (true) {
                            val count = input.read(bytes)
                            if (count < 0) break
                            if (count == 0) continue
                            digest.update(bytes, 0, count)
                            var buffer = ByteBuffer.wrap(bytes, 0, count)
                            while (buffer.hasRemaining()) output.write(buffer)
                            total = addExact(total, count.toLong(), "materialized class-path bytes")
                        }
                        if (total != source.size) {
                            isolationFail("authenticated class-path snapshot has the wrong byte count")
                        }
                    }
                    output.force(true)
                }
                val actualDigest = digest.digest().hex()
                if (actualDigest != entry.expectedSha256) {
                    isolationFail("authenticated class-path snapshot has the wrong digest")
                }
                LinuxFilesystemSyscalls.chmod(target, OWNER_READ_ONLY_MODE)
                LinuxFilesystemSyscalls.synchronize(target)
                paths.add(runPath.resolve(RUNTIME_DIRECTORY).resolve(name))
                expected += source.size to actualDigest
            } finally {
                target.close()
            }
        }
        LinuxFilesystemSyscalls.synchronize(runtime)
    }
    return MaterializedObservationClassPath(paths, expected).also {
        it.verify("immediately after snapshotting")
    }
}

private fun initializeFreshObservationRunTree(descriptor: LinuxDescriptor) {
    requirePrivateDirectory(descriptor, "isolated run tree")
    val empty = try {
        LinuxFilesystemSyscalls.directoryEntryNames(descriptor, 1).isEmpty()
    } catch (_: LinuxResourceLimitException) {
        false
    }
    if (!empty) {
        isolationFail("isolated run tree must be empty before initialization")
    }
    descriptor.whileOpen { fd ->
        LinuxFilesystemSyscalls.createDirectory(fd, SCRATCH_DIRECTORY, OWNER_DIRECTORY_MODE)
        LinuxFilesystemSyscalls.createDirectory(fd, TEMP_DIRECTORY, OWNER_DIRECTORY_MODE)
        LinuxFilesystemSyscalls.createDirectory(fd, RUNTIME_DIRECTORY, OWNER_DIRECTORY_MODE)
    }
    listOf(
        SCRATCH_DIRECTORY to "isolated SQLite scratch directory",
        TEMP_DIRECTORY to "isolated JVM temporary directory",
        RUNTIME_DIRECTORY to "isolated authenticated runtime directory",
    ).forEach { (name, label) ->
        descriptor.whileOpen { fd ->
            LinuxFilesystemSyscalls.openDirectoryAt(fd, name)
        }.use { directory ->
            LinuxFilesystemSyscalls.chmod(directory, OWNER_DIRECTORY_MODE)
            requirePrivateDirectory(directory, label)
            LinuxFilesystemSyscalls.synchronize(directory)
        }
    }
    LinuxFilesystemSyscalls.synchronize(descriptor)
}

/** Fresh descriptor-pinned disk tree; cleanup is bounded and rejects links or special files. */
private class PrivateObservationRunTree private constructor(
    override val path: Path,
    private val parent: Path,
    private val parentIdentity: Any,
    private val parentDescriptor: LinuxDescriptor,
    private val name: String,
    val descriptor: LinuxDescriptor,
    private val cleanupLimits: AcpRuntimeClosureLimits,
) : ObservationRunTreeAccess, AutoCloseable {
    private var removed = false

    override fun <T> withPinnedDescriptor(action: (LinuxDescriptor) -> T): T =
        descriptor.whileOpen { action(descriptor) }

    fun cleanAndRemove() {
        if (removed) return
        requireParent("before isolated run-tree cleanup")
        requireNamedRoot("before isolated run-tree cleanup")
        deletePrivateTreeContents(descriptor, cleanupLimits)
        if (LinuxFilesystemSyscalls.directoryEntryNames(descriptor, 1).isNotEmpty()) {
            isolationFail("isolated run tree is not empty after bounded cleanup")
        }
        val quarantine = ".function-observation-run-delete-${UUID.randomUUID()}"
        parentDescriptor.whileOpen { parentFd ->
            LinuxFilesystemSyscalls.renameNoReplace(parentFd, name, quarantine)
            LinuxFilesystemSyscalls.openDirectoryAt(parentFd, quarantine).use { selected ->
                val pinned = LinuxFilesystemSyscalls.identity(descriptor.fd)
                if (!sameDirectory(pinned, selected.identity)) {
                    isolationFail("isolated run-tree cleanup selected a replacement directory")
                }
            }
            LinuxFilesystemSyscalls.removeDirectory(parentFd, quarantine)
            LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, name)?.use {
                isolationFail("isolated run tree remains linked after cleanup")
            }
            LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, quarantine)?.use {
                isolationFail("isolated run-tree quarantine remains linked after cleanup")
            }
        }
        LinuxFilesystemSyscalls.synchronize(parentDescriptor)
        if (LinuxFilesystemSyscalls.identity(descriptor.fd).linkCount != 0) {
            isolationFail("isolated run-tree descriptor remains linked after cleanup")
        }
        removed = true
    }

    private fun requireParent(label: String) {
        val (_, current) = requireStableDirectory(parent, "isolated scratch parent")
        if (current != parentIdentity) isolationFail("isolated scratch parent changed $label")
        parentDescriptor.whileOpen { fd ->
            if (!Files.isSameFile(parent, LinuxFilesystemSyscalls.stableDescriptorPath(fd))) {
                isolationFail("isolated scratch parent changed $label")
            }
        }
    }

    private fun requireNamedRoot(label: String) {
        parentDescriptor.whileOpen { fd ->
            LinuxFilesystemSyscalls.openDirectoryAt(fd, name).use { selected ->
                val pinned = LinuxFilesystemSyscalls.identity(descriptor.fd)
                if (!sameDirectory(pinned, selected.identity)) isolationFail("isolated run tree changed $label")
            }
        }
        requirePrivateDirectory(descriptor, "isolated run tree")
    }

    override fun close() {
        var failure: Throwable? = null
        try {
            cleanAndRemove()
        } catch (cleanupFailure: Throwable) {
            failure = cleanupFailure
        }
        try {
            descriptor.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        try {
            parentDescriptor.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }

    companion object {
        fun create(
            scratchParent: Path,
            resources: IsolatedObservationResources,
        ): PrivateObservationRunTree {
            LinuxFilesystemSyscalls.requireSupported(scratchParent)
            val (parent, identity) = requireStableDirectory(scratchParent, "isolated scratch parent")
            val fileSystemType = try {
                Files.getFileStore(parent).type().lowercase(java.util.Locale.ROOT)
            } catch (failure: Exception) {
                throw FullTreeFunctionObservationIsolationException(
                    "cannot prove the isolated scratch filesystem type",
                    failure,
                )
            }
            if (fileSystemType in MEMORY_BACKED_FILE_SYSTEMS) {
                isolationFail("isolated SQLite scratch must be disk-backed, not $fileSystemType")
            }
            val parentDescriptor = LinuxFilesystemSyscalls.openRoot(parent)
            try {
                if (!Files.isSameFile(parent, LinuxFilesystemSyscalls.stableDescriptorPath(parentDescriptor.fd))) {
                    isolationFail("isolated scratch parent changed during authorization")
                }
                repeat(MAXIMUM_RUN_NAME_ATTEMPTS) {
                    val name = ".function-observation-run-${randomHex(RUN_RANDOM_BYTES)}"
                    try {
                        parentDescriptor.whileOpen { fd ->
                            LinuxFilesystemSyscalls.createDirectory(fd, name, OWNER_DIRECTORY_MODE)
                        }
                    } catch (failure: LinuxSyscallException) {
                        if (failure.errno == LinuxFilesystemSyscalls.EEXIST) return@repeat
                        throw failure
                    }
                    val root = parentDescriptor.whileOpen { fd ->
                        LinuxFilesystemSyscalls.openDirectoryAt(fd, name)
                    }
                    try {
                        LinuxFilesystemSyscalls.chmod(root, OWNER_DIRECTORY_MODE)
                        requirePrivateDirectory(root, "created isolated run tree")
                        if (root.identity.mountId != parentDescriptor.identity.mountId) {
                            isolationFail("isolated run tree crossed its disk-backed scratch mount")
                        }
                        initializeFreshObservationRunTree(root)
                        LinuxFilesystemSyscalls.synchronize(parentDescriptor)
                        return PrivateObservationRunTree(
                            parent.resolve(name),
                            parent,
                            identity,
                            parentDescriptor,
                            name,
                            root,
                            resources.cleanupLimits,
                        )
                    } catch (failure: Throwable) {
                        runCatching { deletePrivateTreeContents(root, resources.cleanupLimits) }
                            .exceptionOrNull()?.let(failure::addSuppressed)
                        runCatching { root.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                        runCatching {
                            parentDescriptor.whileOpen { fd -> LinuxFilesystemSyscalls.removeDirectory(fd, name) }
                        }.exceptionOrNull()?.let(failure::addSuppressed)
                        throw failure
                    }
                }
                isolationFail("cannot allocate a unique isolated run directory")
            } catch (failure: Throwable) {
                parentDescriptor.close()
                throw failure
            }
        }
    }
}

/**
 * Non-owning adapter over a lease-issued lexical run-root borrow. Closing only invalidates this
 * adapter; the lease retains the descriptor, tree, and all cleanup/recovery responsibility.
 */
internal class BorrowedObservationRunTree private constructor(
    private val borrowed: FullTreeDiskScratchBorrowedRunRoot,
) : ObservationRunTreeAccess, AutoCloseable {
    private var closed = false

    override val path: Path
        @Synchronized get() {
            check(!closed) { "borrowed observation run tree is closed" }
            return borrowed.path
        }

    @Synchronized
    override fun <T> withPinnedDescriptor(action: (LinuxDescriptor) -> T): T {
        check(!closed) { "borrowed observation run tree is closed" }
        return borrowed.withPinnedDescriptor(action)
    }

    @Synchronized
    override fun close() {
        closed = true
    }

    companion object {
        internal fun initialize(borrowed: FullTreeDiskScratchBorrowedRunRoot): BorrowedObservationRunTree {
            val tree = BorrowedObservationRunTree(borrowed)
            try {
                tree.withPinnedDescriptor(::initializeFreshObservationRunTree)
                return tree
            } catch (failure: Throwable) {
                tree.close()
                throw failure
            }
        }

        internal fun access(borrowed: FullTreeDiskScratchBorrowedRunRoot): BorrowedObservationRunTree {
            val tree = BorrowedObservationRunTree(borrowed)
            try {
                tree.withPinnedDescriptor { descriptor ->
                    requirePrivateDirectory(descriptor, "borrowed observation run tree")
                }
                return tree
            } catch (failure: Throwable) {
                tree.close()
                throw failure
            }
        }
    }
}

private class PendingObservationLaunch(
    private val controller: ObservationSystemdController,
    private val testHooks: FullTreeFunctionObservationLaunchTestHooks?,
) : AutoCloseable {
    val unitName: String
        get() = controller.unitName
    var process: Process? = null
    var processHandle: decompengine.acp.LinuxProcessDescriptor? = null
    var cleaned = false
        private set

    /** Pins exact local-process cleanup ownership before control can escape a successful start. */
    fun start(builder: ProcessBuilder, forcedFailureDirectory: Path?): Process {
        check(process == null && processHandle == null) {
            "isolated process launch attempt is not linear"
        }
        forcedFailureDirectory?.let { builder.directory(it.toFile()) }
        val started = builder.start()
        process = started
        return try {
            val openedHandle = try {
                LinuxFilesystemSyscalls.openProcessHandle(started.pid())
            } catch (failure: Throwable) {
                throw FullTreeFunctionObservationIsolationException(
                    "isolated local scope process could not be pidfd-pinned",
                    failure,
                )
            }
            try {
                if (!started.isAlive || !LinuxFilesystemSyscalls.processExists(openedHandle)) {
                    isolationFail("isolated local scope process exited while its pidfd was pinned")
                }
                processHandle = openedHandle
            } catch (failure: Throwable) {
                openedHandle.close()
                throw failure
            }
            started
        } catch (failure: Throwable) {
            if (started.isAlive) {
                runCatching { started.destroyForcibly() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            throw failure
        }
    }

    override fun close() {
        if (cleaned) return
        val started = process
        if (started != null) {
            testHooks?.faultInjector?.at(
                FullTreeFunctionObservationLaunchFaultPoint.BEFORE_DESTRUCTIVE_CLEANUP,
                unitName,
            )
            controller.killLocalProcessAndRequireAbsentWithoutUnitMutation(
                process = started,
                processHandle = processHandle,
            )
        } else {
            controller.requireAbsent()
        }
        processHandle?.close()
        processHandle = null
        cleaned = true
    }
}

private class TrustedObservationBoundary(
    private val configuration: FullTreeFunctionObservationIsolationConfiguration,
    private val authenticatedRuntime: AuthenticatedObservationRuntime,
    private val materializedClassPath: MaterializedObservationClassPath,
    private val testHooks: FullTreeFunctionObservationLaunchTestHooks? = null,
) : AutoCloseable {
    private val java = PinnedSecurityExecutable.pin(
        configuration.javaExecutable,
        "isolated Java runtime",
        configuration.expectedJavaSha256,
    )
    private val bubblewrap = PinnedSecurityExecutable.pin(
        configuration.bubblewrapExecutable,
        "isolated bubblewrap boundary",
        configuration.expectedBubblewrapSha256,
    )
    private val resourceLimiter = PinnedSecurityExecutable.pin(
        configuration.resourceLimiterExecutable,
        "isolated resource limiter",
        configuration.expectedResourceLimiterSha256,
    )
    private val supervisor = PinnedSecurityExecutable.pin(
        configuration.scopeSupervisorExecutable,
        "isolated scope supervisor",
        configuration.expectedScopeSupervisorSha256,
    )
    private val inspector = PinnedSecurityExecutable.pin(
        configuration.scopeInspectorExecutable,
        "isolated scope inspector",
        configuration.expectedScopeInspectorSha256,
    )
    private val bus = PinnedSystemdBusEndpoint.pin(configuration.systemdUserRuntimeDirectory)
    private var active: ManagedObservationUnit? = null
    private var pendingLaunch: PendingObservationLaunch? = null
    private var retainedUnitName: String? = null

    init {
        probeBoundaries()
    }

    fun launch(
        request: IsolatedWorkerRequest,
        resources: IsolatedObservationResources,
    ): ManagedObservationUnit {
        val unitName = "decomp-oracle-function-${UUID.randomUUID()}.scope"
        check(unitName.matches(FIXTURE_OBSERVATION_UNIT_NAME))
        return launchValidated(
            unitName = unitName,
            request = request,
            resources = resources,
            immediatelyBeforeStart = {},
        )
    }

    fun launch(
        unitName: String,
        request: IsolatedWorkerRequest,
        resources: IsolatedObservationResources,
        immediatelyBeforeStart: () -> Unit,
    ): ManagedObservationUnit {
        if (!unitName.matches(PRODUCTION_OBSERVATION_UNIT_NAME)) {
            isolationFail("deterministic isolated systemd unit name is not canonical")
        }
        return launchValidated(unitName, request, resources, immediatelyBeforeStart)
    }

    fun launchKotlinBootKeeper(
        unitName: String,
        nonce: String,
        runTree: PrivateObservationRunTree,
        resources: IsolatedObservationResources,
    ): ManagedObservationUnit {
        if (!unitName.matches(PRODUCTION_KOTLIN_BOOT_UNIT_NAME)) {
            isolationFail("generic Kotlin BOOT unit name is not canonical")
        }
        if (!nonce.matches(SHA256)) isolationFail("generic Kotlin BOOT nonce is invalid")
        val worker = buildKotlinBootKeeperCommand(runTree.path, nonce)
        return launchPrebuilt(
            unitName = unitName,
            runDirectory = runTree.path,
            nonce = nonce,
            resources = resources,
            worker = worker,
            topology = ObservationBootProcessTopology.SINGLE_KOTLIN_KEEPER,
            forcedStartFailureDirectory = null,
            immediatelyBeforeStart = {
                authenticatedRuntime.verify("at generic Kotlin BOOT process-start gate")
                materializedClassPath.requirePreparedLayout(runTree)
            },
        )
    }

    /**
     * Reconstitutes only descriptor-backed ownership of an exact durable BOOT attachment during a
     * deliberate coordinator handoff. Production bubblewrap uses --die-with-parent, so an actual
     * coordinator-process death is expected to converge to absent recovery rather than this path.
     * Unlike a launch failure, an adoption mismatch never falls through the deterministic unit-name
     * cleanup path: no name mutation is safe until the receipt has matched the live invocation,
     * cgroup, and all four process identities.
     */
    fun adoptUnitAttached(
        binding: FullTreeFunctionObservationOperationBinding,
        receipt: FullTreeFunctionObservationUnitAttachmentReceipt,
        runDirectory: Path,
        resources: IsolatedObservationResources,
    ): ManagedObservationUnit {
        check(active == null && pendingLaunch == null && retainedUnitName == null) {
            "one isolation boundary may own only one worker"
        }
        if (
            binding.unitName != receipt.unitName || binding.operationId != receipt.operationId ||
            binding.requestSha256 != receipt.requestSha256 ||
            binding.bindingSha256 != receipt.bindingSha256 ||
            binding.isolationConfigurationSha256 != receipt.isolationConfigurationSha256 ||
            configuration.canonicalSha256 != binding.isolationConfigurationSha256
        ) isolationFail("cold unit-attachment receipt differs from its operation binding")
        if (readFullTreeFunctionObservationKernelBootId() != receipt.bootId) {
            isolationFail("cold unit-attachment receipt belongs to a previous kernel boot")
        }
        val outerPid = receipt.processes.singleOrNull {
            it.role == FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP
        }?.hostPid ?: isolationFail("cold unit-attachment receipt lacks one outer bubblewrap")
        var processHandle: decompengine.acp.LinuxProcessDescriptor? = null
        var managed: ManagedObservationUnit? = null
        try {
            requireUnchanged()
            authenticatedRuntime.verify("before cold unit-attachment adoption")
            materializedClassPath.verify("before cold unit-attachment adoption")
            val controller = ObservationSystemdController(
                inspector,
                bus,
                binding.unitName,
                testHooks?.systemctlCommandObserver,
            )
            val openedHandle = LinuxFilesystemSyscalls.openProcessHandle(outerPid)
            processHandle = openedHandle
            val adopted = ManagedObservationUnit(
                controller,
                runDirectory,
                binding.bindingSha256,
                bubblewrap,
                java,
                resources,
                process = null,
                processHandle = openedHandle,
                systemdUserRuntimeDirectory = configuration.systemdUserRuntimeDirectory,
            )
            managed = adopted
            processHandle = null
            adopted.adoptUnitAttachment(receipt)
            requireUnchanged()
            authenticatedRuntime.verify("after cold unit-attachment adoption")
            materializedClassPath.verify("after cold unit-attachment adoption")
            adopted.requireCurrentUnitAttachmentReceipt(receipt)
            retainUnitName(binding.unitName)
            active = adopted
            managed = null
            return adopted
        } catch (failure: Throwable) {
            managed?.let { unit ->
                runCatching { unit.abandonWithoutMutation() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            processHandle?.let { handle ->
                runCatching { handle.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            throw failure
        }
    }

    private fun launchValidated(
        unitName: String,
        request: IsolatedWorkerRequest,
        resources: IsolatedObservationResources,
        immediatelyBeforeStart: () -> Unit,
    ): ManagedObservationUnit = launchPrebuilt(
        unitName = unitName,
        runDirectory = request.runDirectory,
        nonce = request.nonce,
        resources = resources,
        worker = buildWorkerCommand(request, resources),
        topology = ObservationBootProcessTopology.FULL_TREE_SUPERVISOR,
        forcedStartFailureDirectory = request.paths.richArtifact.takeIf {
            testHooks?.forceProcessStartFailure == true
        },
        immediatelyBeforeStart = immediatelyBeforeStart,
    )

    private fun launchPrebuilt(
        unitName: String,
        runDirectory: Path,
        nonce: String,
        resources: IsolatedObservationResources,
        worker: List<String>,
        topology: ObservationBootProcessTopology,
        forcedStartFailureDirectory: Path?,
        immediatelyBeforeStart: () -> Unit,
    ): ManagedObservationUnit {
        check(active == null && pendingLaunch == null) {
            "one isolation boundary may launch only one worker"
        }
        retainUnitName(unitName)
        val controller = ObservationSystemdController(
            inspector,
            bus,
            unitName,
            testHooks?.systemctlCommandObserver,
        )
        val pending = PendingObservationLaunch(controller, testHooks)
        pendingLaunch = pending
        try {
            requireUnchanged()
            authenticatedRuntime.verify("at isolated boundary launch")
            materializedClassPath.verify("at isolated boundary launch")
            testHooks?.faultInjector?.at(
                FullTreeFunctionObservationLaunchFaultPoint.BEFORE_INITIAL_UNIT_ABSENCE,
                unitName,
            )
            controller.requireAbsent()
            val scoped = buildScopeCommand(unitName, resources, worker)
            val command = buildResourceLimitedCommand(resources, scoped)
            requireUnchanged()
            authenticatedRuntime.verify("immediately before isolated process start")
            materializedClassPath.verify("immediately before isolated process start")
            immediatelyBeforeStart()
            authenticatedRuntime.verify("at final isolated process start gate")
            materializedClassPath.verify("at final isolated process start gate")
            testHooks?.faultInjector?.at(
                FullTreeFunctionObservationLaunchFaultPoint.BEFORE_FINAL_UNIT_ABSENCE,
                unitName,
            )
            controller.requireAbsent()
            testHooks?.faultInjector?.at(
                FullTreeFunctionObservationLaunchFaultPoint.AFTER_FINAL_UNIT_ABSENCE,
                unitName,
            )
            requireUnchanged()
            val processBuilder = ProcessBuilder(command)
                .redirectInput(ProcessBuilder.Redirect.PIPE)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .also { builder ->
                    builder.environment().clear()
                    builder.environment().putAll(bus.controlEnvironment)
                }
            val started = pending.start(processBuilder, forcedStartFailureDirectory)
            testHooks?.faultInjector?.at(
                FullTreeFunctionObservationLaunchFaultPoint.AFTER_PROCESS_START_RETURNED,
                unitName,
            )
            val pinnedProcess = checkNotNull(pending.processHandle) {
                "isolated local scope process lost its pinned cleanup handle"
            }
            started.outputStream.close()
            val managedUnit = ManagedObservationUnit(
                controller,
                runDirectory,
                nonce,
                bubblewrap,
                java,
                resources,
                started,
                pinnedProcess,
                configuration.systemdUserRuntimeDirectory,
                topology,
            )
            managedUnit.awaitScopeAttached()
            active = managedUnit
            pending.processHandle = null
            pendingLaunch = null
            testHooks?.faultInjector?.at(
                FullTreeFunctionObservationLaunchFaultPoint.AFTER_SCOPE_ATTACHED,
                unitName,
            )
            requireUnchanged()
            authenticatedRuntime.verify("immediately after isolated scope attachment")
            materializedClassPath.verify("immediately after isolated scope attachment")
            return managedUnit
        } catch (failure: Throwable) {
            runCatching { close() }.exceptionOrNull()?.let { cleanupFailure ->
                if (cleanupFailure !== failure) failure.addSuppressed(cleanupFailure)
            }
            throw failure
        }
    }

    internal fun buildWorkerCommand(
        request: IsolatedWorkerRequest,
        resources: IsolatedObservationResources,
    ): List<String> {
        val readOnlyInputs = listOf(
            request.paths.richArtifact,
            request.paths.inventory,
            request.paths.scopeFiles.scope,
            request.paths.scopeFiles.sourceLock,
            request.paths.scopeFiles.artifactManifest,
        ).distinct()
        if (readOnlyInputs.any { it.startsWith(configuration.systemdUserRuntimeDirectory) }) {
            isolationFail("isolated inputs must not expose the systemd session runtime")
        }
        val mounts = authenticatedRuntime.mounts()
        val javaRelative = configuration.javaRuntime.source.relativize(java.path)
        val sandboxJava = configuration.javaRuntime.destination.resolve(javaRelative).normalize()
        requireSyntheticMountPlan(mounts, readOnlyInputs, request.runDirectory)
        val destinations = mounts.map { it.destination } + readOnlyInputs +
            materializedClassPath.paths + listOf(request.runDirectory)
        val directories = syntheticDestinationParents(destinations)
        return buildList {
            add(bubblewrap.path.toString())
            addAll(listOf("--die-with-parent", "--new-session", "--unshare-all", "--unshare-user"))
            addAll(listOf("--disable-userns", "--assert-userns-disabled", "--clearenv"))
            addAll(listOf("--cap-drop", "ALL", "--hostname", "decomp-oracle"))
            addAll(listOf("--tmpfs", "/"))
            directories.forEach { directory -> addAll(listOf("--dir", directory.toString())) }
            mounts.forEach { mount ->
                addAll(listOf("--ro-bind", mount.source.toString(), mount.destination.toString()))
            }
            readOnlyInputs.forEach { input ->
                addAll(listOf("--ro-bind", input.toString(), input.toString()))
            }
            addAll(listOf("--bind", request.runDirectory.toString(), request.runDirectory.toString()))
            materializedClassPath.paths.forEach { entry ->
                addAll(listOf("--ro-bind", entry.toString(), entry.toString()))
            }
            addAll(listOf("--proc", "/proc", "--dev", "/dev"))
            addAll(listOf("--chdir", request.runDirectory.toString()))
            addAll(listOf("--setenv", "HOME", request.runDirectory.toString()))
            addAll(listOf("--setenv", "TMPDIR", request.runDirectory.resolve(TEMP_DIRECTORY).toString()))
            add("--")
            add(sandboxJava.toString())
            add("-Xms16m")
            add("-Xmx64m")
            add("-XX:+UseSerialGC")
            add("-XX:ActiveProcessorCount=1")
            add("-XX:-UsePerfData")
            add("-XX:MaxMetaspaceSize=64m")
            add("-XX:ReservedCodeCacheSize=32m")
            add("-XX:MaxDirectMemorySize=16m")
            addAll(isolatedObservationJvmTemporaryArguments(request.runDirectory,
                configuration.javaRuntime.destination.resolve(OracleNativeLibraries.relativeDirectory)))
            add("-classpath")
            add(materializedClassPath.encoded)
            add(FullTreeFunctionObservationIsolatedSupervisor::class.java.name)
            add(SUPERVISOR_PROTOCOL_VERSION)
            add(sandboxJava.toString())
            add(materializedClassPath.encoded)
            add(configuration.javaRuntime.destination.resolve(OracleNativeLibraries.relativeDirectory).toString())
            addAll(request.arguments())
        }
    }

    private fun buildKotlinBootKeeperCommand(runDirectory: Path, nonce: String): List<String> {
        if (runDirectory.startsWith(configuration.systemdUserRuntimeDirectory)) {
            isolationFail("generic Kotlin BOOT run tree exposes the systemd session runtime")
        }
        val mounts = authenticatedRuntime.mounts()
        val javaRelative = configuration.javaRuntime.source.relativize(java.path)
        val sandboxJava = configuration.javaRuntime.destination.resolve(javaRelative).normalize()
        requireSyntheticMountPlan(mounts, emptyList(), runDirectory)
        val destinations = mounts.map { it.destination } + materializedClassPath.paths + listOf(runDirectory)
        destinations.forEachIndexed { index, destination ->
            if (!destination.isAbsolute || destination.normalize() != destination || destination == Path.of("/")) {
                isolationFail("generic Kotlin BOOT synthetic destination $index is invalid: $destination")
            }
        }
        val directories = syntheticDestinationParents(destinations)
        return buildList {
            add(bubblewrap.path.toString())
            addAll(listOf("--die-with-parent", "--new-session", "--unshare-all", "--unshare-user"))
            addAll(listOf("--disable-userns", "--assert-userns-disabled", "--clearenv"))
            addAll(listOf("--cap-drop", "ALL", "--hostname", "decomp-oracle"))
            addAll(listOf("--tmpfs", "/"))
            directories.forEach { directory -> addAll(listOf("--dir", directory.toString())) }
            mounts.forEach { mount ->
                addAll(listOf("--ro-bind", mount.source.toString(), mount.destination.toString()))
            }
            addAll(listOf("--bind", runDirectory.toString(), runDirectory.toString()))
            materializedClassPath.paths.forEach { entry ->
                addAll(listOf("--ro-bind", entry.toString(), entry.toString()))
            }
            addAll(listOf("--proc", "/proc", "--dev", "/dev"))
            addAll(listOf("--chdir", runDirectory.toString()))
            addAll(listOf("--setenv", "HOME", runDirectory.toString()))
            addAll(listOf("--setenv", "TMPDIR", runDirectory.resolve(TEMP_DIRECTORY).toString()))
            add("--")
            add(sandboxJava.toString())
            add("-Xms16m")
            add("-Xmx64m")
            add("-XX:+UseSerialGC")
            add("-XX:ActiveProcessorCount=1")
            add("-XX:-UsePerfData")
            add("-XX:MaxMetaspaceSize=64m")
            add("-XX:ReservedCodeCacheSize=32m")
            add("-XX:MaxDirectMemorySize=16m")
            addAll(isolatedObservationJvmTemporaryArguments(runDirectory,
                configuration.javaRuntime.destination.resolve(OracleNativeLibraries.relativeDirectory)))
            add("-classpath")
            add(materializedClassPath.encoded)
            add(KotlinSystemdCgroupBootKeeper::class.java.name)
            add(KOTLIN_BOOT_PROTOCOL_VERSION)
            add(runDirectory.toString())
            add(nonce)
        }
    }

    private fun requireSyntheticMountPlan(
        mounts: List<FullTreeFunctionObservationRuntimeMount>,
        readOnlyInputs: List<Path>,
        runDirectory: Path,
    ) {
        val reserved = listOf(Path.of("/proc"), Path.of("/dev"), configuration.systemdUserRuntimeDirectory)
        if (reserved.any { pathsOverlap(runDirectory, it) }) {
            isolationFail("isolated writable run tree overlaps a reserved synthetic-root path")
        }
        readOnlyInputs.forEach { input ->
            if (pathsOverlap(input, runDirectory) || reserved.any { pathsOverlap(input, it) }) {
                isolationFail("isolated input overlaps writable or reserved synthetic-root authority")
            }
        }
        mounts.forEach { mount ->
            if (
                pathsOverlap(mount.destination, runDirectory) ||
                readOnlyInputs.any { pathsOverlap(mount.destination, it) } ||
                reserved.any { pathsOverlap(mount.destination, it) }
            ) isolationFail("isolated runtime mount overlaps another synthetic-root authority")
        }
        val classPathRoot = runDirectory.resolve(RUNTIME_DIRECTORY)
        materializedClassPath.paths.forEach { entry ->
            if (entry.parent != classPathRoot || !Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
                isolationFail("isolated class-path snapshot escaped its private runtime directory")
            }
        }
    }

    private fun buildResourceLimitedCommand(
        resources: IsolatedObservationResources,
        command: List<String>,
    ): List<String> = buildList {
            add(resourceLimiter.path.toString())
            add("--nproc=$RLIMIT_NPROC:$RLIMIT_NPROC")
            add("--nofile=$RLIMIT_NOFILE:$RLIMIT_NOFILE")
            add("--fsize=${resources.maximumFileBytes}:${resources.maximumFileBytes}")
            add("--core=0:0")
            add("--as=${resources.maximumAddressSpaceBytes}:${resources.maximumAddressSpaceBytes}")
            add("--cpu=${resources.cpuSeconds}:${resources.cpuSeconds}")
            add("--")
            addAll(command)
    }

    internal fun buildScopeCommand(
        unitName: String,
        resources: IsolatedObservationResources,
        worker: List<String>,
    ): List<String> = buildList {
        add(supervisor.path.toString())
        add("--user")
        add("--scope")
        add("--quiet")
        add("--collect")
        add("--expand-environment=no")
        add("--unit=$unitName")
        add("--property=TasksMax=${resources.tasksMax}")
        add("--property=MemoryMax=${resources.maximumResidentBytes}")
        add("--property=MemorySwapMax=0")
        add("--property=OOMPolicy=kill")
        add("--property=CPUQuota=100%")
        add("--property=KillMode=control-group")
        add("--property=SendSIGKILL=yes")
        add("--property=RuntimeMaxSec=${resources.serviceRuntimeSeconds}s")
        add("--property=TimeoutStopSec=${resources.timeoutStopMillis / 1_000L}s")
        add("--property=Delegate=no")
        add("--")
        addAll(worker)
    }

    private fun probeBoundaries() {
        requireUnchanged()
        val bwrapVersion = runTrustedCommand(
            listOf(bubblewrap.path.toString(), "--version"),
            emptyMap(),
            PROBE_TIMEOUT,
            "bubblewrap version probe",
        )
        if (bwrapVersion.exitCode != 0 || !bwrapVersion.output.trim().matches(BUBBLEWRAP_VERSION)) {
            isolationFail("configured isolated bubblewrap returned an unrecognized version")
        }
        val bwrapHelp = runTrustedCommand(
            listOf(bubblewrap.path.toString(), "--help"),
            emptyMap(),
            PROBE_TIMEOUT,
            "bubblewrap feature probe",
        )
        REQUIRED_BWRAP_OPTIONS.forEach { option ->
            if (option !in bwrapHelp.output) isolationFail("isolated bubblewrap lacks $option")
        }
        val prlimit = runTrustedCommand(
            listOf(resourceLimiter.path.toString(), "--version"),
            emptyMap(),
            PROBE_TIMEOUT,
            "resource-limiter version probe",
        )
        if (prlimit.exitCode != 0 || !prlimit.output.lineSequence().first().startsWith("prlimit from util-linux ")) {
            isolationFail("configured isolated resource limiter is not util-linux prlimit")
        }
        val systemdHelp = runTrustedCommand(
            listOf(supervisor.path.toString(), "--help"),
            emptyMap(),
            PROBE_TIMEOUT,
            "systemd-run feature probe",
        )
        REQUIRED_SYSTEMD_RUN_OPTIONS.forEach { option ->
            if (option !in systemdHelp.output) isolationFail("isolated systemd supervisor lacks $option")
        }
        val manager = ObservationSystemdController(
            inspector,
            bus,
            "decomp-oracle-probe.scope",
            testHooks?.systemctlCommandObserver,
        )
            .managerVersion()
        if (!manager.matches(SYSTEMD_MANAGER_VERSION)) {
            isolationFail("systemd user manager is unavailable to the isolated worker")
        }
        val systemctlHelp = runTrustedCommand(
            listOf(inspector.path.toString(), "--help"),
            bus.controlEnvironment,
            PROBE_TIMEOUT,
            "systemd controller feature probe",
        )
        if (systemctlHelp.exitCode != 0) {
            isolationFail("configured systemd controller did not provide help")
        }
        REQUIRED_SYSTEMCTL_COMMANDS.forEach { command ->
            if (!Regex("(?m)^\\s+$command(?:\\s|$)").containsMatchIn(systemctlHelp.output)) {
                isolationFail("isolated systemd controller lacks $command")
            }
        }
        requireUnchanged()
    }

    private fun requireUnchanged() {
        java.requireUnchanged()
        bubblewrap.requireUnchanged()
        resourceLimiter.requireUnchanged()
        supervisor.requireUnchanged()
        inspector.requireUnchanged()
        bus.requireUnchanged()
    }

    fun verifyExecutablesForPublication() {
        requireUnchanged()
        authenticatedRuntime.verify("before parent publication")
    }

    fun verifyLiveOperation() {
        requireUnchanged()
        authenticatedRuntime.verify("while isolated operation is live")
        materializedClassPath.verify("while isolated operation is live")
    }

    fun closeAndProveUnitAbsent(unitName: String) {
        if (!unitName.matches(PRODUCTION_OBSERVATION_UNIT_NAME)) {
            isolationFail("cleanup unit name is not one deterministic operation unit")
        }
        retainUnitName(unitName)
        active?.let { unit ->
            if (unit.unitName != unitName) isolationFail("live cleanup unit identity changed")
        }
        pendingLaunch?.let { pending ->
            if (pending.unitName != unitName) isolationFail("pending cleanup unit identity changed")
        }
        if (active == null && pendingLaunch == null) {
            pendingLaunch = PendingObservationLaunch(
                ObservationSystemdController(inspector, bus, unitName, testHooks?.systemctlCommandObserver),
                testHooks,
            )
        }
        close()
    }

    /** Drops query/open-only cold adoption descriptors without touching the live unit or its PIDs. */
    fun abandonColdAdoption(unit: ManagedObservationUnit) {
        if (active !== unit || !unit.isColdAdopted || retainedUnitName != unit.unitName) {
            isolationFail("cold unit-attachment adoption ownership changed")
        }
        abandonObservationWithoutMutation(unit)
    }

    /** Releases this process's observation descriptors for a deliberate cold-coordinator handoff. */
    fun abandonObservationForColdRecovery(unit: ManagedObservationUnit) {
        if (active !== unit || retainedUnitName != unit.unitName) {
            isolationFail("live unit-attachment observation ownership changed")
        }
        abandonObservationWithoutMutation(unit)
    }

    private fun abandonObservationWithoutMutation(unit: ManagedObservationUnit) {
        unit.abandonWithoutMutation()
        active = null
        retainedUnitName = null
    }

    override fun close() {
        val unit = active
        if (unit != null && !unit.cleaned) {
            testHooks?.faultInjector?.at(
                FullTreeFunctionObservationLaunchFaultPoint.BEFORE_DESTRUCTIVE_CLEANUP,
                unit.unitName,
            )
            unit.close()
        }
        pendingLaunch?.let { pending ->
            pending.close()
            pendingLaunch = null
        }
        retainedUnitName?.let { unitName ->
            testHooks?.faultInjector?.at(
                FullTreeFunctionObservationLaunchFaultPoint.BEFORE_FINAL_CLEANUP_ABSENCE,
                unitName,
            )
            val finalAbsence = PendingObservationLaunch(
                ObservationSystemdController(inspector, bus, unitName, testHooks?.systemctlCommandObserver),
                testHooks,
            )
            pendingLaunch = finalAbsence
            finalAbsence.close()
            pendingLaunch = null
        }
    }

    private fun retainUnitName(unitName: String) {
        val retained = retainedUnitName
        if (retained != null && retained != unitName) {
            isolationFail("isolation boundary unit identity changed")
        }
        retainedUnitName = unitName
    }
}

/**
 * One stable low-level name/cgroup observation, never recovery or mutation authority.
 *
 * SYSTEMD_IDENTITY_CANDIDATE matches the non-loading unit inventory, exact cgroup receipt identity,
 * and properties read only through systemd's lifetime-bound invocation-ID object path. Returned
 * name-addressed object paths are compared but never dereferenced. This still does not match
 * receipt PIDs, prove a BOOT protocol stage, reconcile journal/disk state, authorize mutation, or
 * reserve the deterministic name.
 */
internal enum class FullTreeFunctionObservationColdUnitAttachmentObservationOutcome {
    ABSENT,
    SYSTEMD_IDENTITY_CANDIDATE,
    FOREIGN_REPLACEMENT,
    INCONSISTENT_OR_EXITING,
    CHANGED,
}

internal data class FullTreeFunctionObservationColdSystemdUnitInventoryEntry(
    val unitName: String,
    val loadState: String,
    val activeState: String,
    val subState: String,
    val description: String,
)

internal data class FullTreeFunctionObservationColdSystemdJobInventoryEntry(
    val jobId: Long,
    val unitName: String,
    val jobType: String,
    val jobState: String,
)

internal data class FullTreeFunctionObservationColdCgroupIdentity(
    val path: Path,
    val device: Long,
    val inode: Long,
    val mountId: Long,
)

internal data class FullTreeFunctionObservationColdUnitReceiptIdentity(
    val unitName: String,
    val invocationId: String,
    val controlGroup: String,
    val cgroupDevice: Long,
    val cgroupInode: Long,
    val cgroupMountId: Long,
) {
    internal companion object {
        fun from(
            receipt: FullTreeFunctionObservationUnitAttachmentReceipt,
        ): FullTreeFunctionObservationColdUnitReceiptIdentity =
            FullTreeFunctionObservationColdUnitReceiptIdentity(
                unitName = receipt.unitName,
                invocationId = receipt.invocationId,
                controlGroup = receipt.controlGroup,
                cgroupDevice = receipt.cgroupDevice,
                cgroupInode = receipt.cgroupInode,
                cgroupMountId = receipt.cgroupMountId,
            )
    }
}

internal data class FullTreeFunctionObservationColdSystemdIdentity(
    val nameObjectPath: String,
    val invocationObjectPath: String,
    val unitName: String,
    val invocationId: String,
    val transient: Boolean,
    val controlGroup: String,
)

internal data class FullTreeFunctionObservationColdUnitSnapshot(
    val managerFeatures: Set<String>,
    val unit: FullTreeFunctionObservationColdSystemdUnitInventoryEntry?,
    val job: FullTreeFunctionObservationColdSystemdJobInventoryEntry?,
    val cgroups: List<FullTreeFunctionObservationColdCgroupIdentity>,
    val systemdIdentity: FullTreeFunctionObservationColdSystemdIdentity? = null,
    val stable: Boolean = true,
)

private data class FullTreeFunctionObservationColdCgroupInventory(
    val cgroups: List<FullTreeFunctionObservationColdCgroupIdentity>,
    val stable: Boolean,
)

private data class FullTreeFunctionObservationColdSystemdIdentityObservation(
    val identity: FullTreeFunctionObservationColdSystemdIdentity?,
    val stable: Boolean,
)

internal fun classifyFullTreeFunctionObservationColdUnitSnapshots(
    expected: FullTreeFunctionObservationColdUnitReceiptIdentity,
    before: FullTreeFunctionObservationColdUnitSnapshot,
    after: FullTreeFunctionObservationColdUnitSnapshot,
): FullTreeFunctionObservationColdUnitAttachmentObservationOutcome {
    if (!before.stable || !after.stable || before != after) {
        return FullTreeFunctionObservationColdUnitAttachmentObservationOutcome.CHANGED
    }
    if (
        before.unit == null && before.job == null && before.cgroups.isEmpty() &&
        before.systemdIdentity == null
    ) {
        return FullTreeFunctionObservationColdUnitAttachmentObservationOutcome.ABSENT
    }

    val expectedCgroup = CGROUP_ROOT.resolve(expected.controlGroup.removePrefix("/")).normalize()
    val cgroupReplacement = before.cgroups.any { observed ->
        observed.path != expectedCgroup ||
            observed.device != expected.cgroupDevice ||
            observed.inode != expected.cgroupInode ||
            observed.mountId != expected.cgroupMountId
    }
    if (cgroupReplacement) {
        return FullTreeFunctionObservationColdUnitAttachmentObservationOutcome.FOREIGN_REPLACEMENT
    }

    val exactCgroup = before.cgroups.singleOrNull()?.let { observed ->
        observed.path == expectedCgroup &&
            observed.device == expected.cgroupDevice &&
            observed.inode == expected.cgroupInode &&
            observed.mountId == expected.cgroupMountId
    } == true
    val unit = before.unit
    val identity = before.systemdIdentity
    val systemdIdentityCandidate =
        unit != null &&
            unit.unitName == expected.unitName &&
            unit.loadState == "loaded" &&
            unit.activeState == "active" &&
            unit.subState == "running" && before.job == null && exactCgroup && identity != null &&
            identity.unitName == expected.unitName &&
            identity.invocationId == expected.invocationId &&
            identity.transient &&
            identity.controlGroup == expected.controlGroup &&
            identity.nameObjectPath.matches(SYSTEMD_UNIT_OBJECT_PATH) &&
            identity.nameObjectPath != identity.invocationObjectPath &&
            identity.invocationObjectPath == systemdInvocationObjectPath(expected.invocationId)
    return if (systemdIdentityCandidate) {
        FullTreeFunctionObservationColdUnitAttachmentObservationOutcome.SYSTEMD_IDENTITY_CANDIDATE
    } else {
        FullTreeFunctionObservationColdUnitAttachmentObservationOutcome.INCONSISTENT_OR_EXITING
    }
}

/**
 * Query-only, point-in-time observation of one binding-derived systemd name.
 *
 * The inventory commands do not request or load the named unit. Empty manager and job inventories
 * are observed around the bounded global cgroup scan. This is neither a name reservation nor an
 * exclusion claim: another same-UID process can create the name immediately after any observation.
 * Until OS-principal separation lands, endpoint pinning also assumes cooperative same-UID peers.
 */
internal class FullTreeFunctionObservationColdUnitAbsenceObserver private constructor(
    private val inspector: PinnedSecurityExecutable,
    private val busController: PinnedSecurityExecutable,
    private val bus: PinnedSystemdBusEndpoint,
    private val binding: FullTreeFunctionObservationOperationBinding,
    val isolationConfigurationSha256: String,
    private val commandObserver: FullTreeFunctionObservationSystemctlCommandObserver?,
    private val busctlCommandObserver: FullTreeFunctionObservationBusctlCommandObserver?,
) {
    val unitName: String = binding.unitName

    init {
        if (!unitName.matches(PRODUCTION_OBSERVATION_UNIT_NAME)) {
            isolationFail("cold systemd observation unit name is not canonical")
        }
        requireUnchanged()
    }

    fun requireAbsent() {
        requireUnchanged()
        requireUnfilteredUnitInventory()
        requireEnumerationEmpty(COLD_SYSTEMD_LIST_UNITS_ARGUMENTS + listOf("--", unitName), "unit inventory")
        requireEnumerationEmpty(COLD_SYSTEMD_LIST_JOBS_ARGUMENTS + listOf("--", unitName), "job inventory")
        requireUnchanged()
        if (findObservationCgroupsForUnit(unitName).isNotEmpty()) {
            isolationFail("cold systemd observation found an exact-name cgroup")
        }
        requireUnchanged()
        requireEnumerationEmpty(COLD_SYSTEMD_LIST_JOBS_ARGUMENTS + listOf("--", unitName), "job inventory")
        requireEnumerationEmpty(COLD_SYSTEMD_LIST_UNITS_ARGUMENTS + listOf("--", unitName), "unit inventory")
        requireUnfilteredUnitInventory()
        requireUnchanged()
    }

    /**
     * Repeated query-only observation of the exact durable receipt name.
     *
     * Name and control-group Manager lookups are non-loading and their returned paths are never
     * dereferenced. Properties are read only through the expected invocation-ID path, whose
     * lifetime is bound by systemd to that invocation. This method opens no receipt PID and retains
     * no cgroup descriptor; exact process adoption remains a later step. Its caller must separately
     * bracket this observation with boot and journal/disk reconciliation.
     */
    fun observeUnitAttachment(
        receipt: FullTreeFunctionObservationUnitAttachmentReceipt,
    ): FullTreeFunctionObservationColdUnitAttachmentObservationOutcome {
        requireReceiptBinding(receipt)
        requireUnchanged()
        val featuresBefore = observeUnfilteredUnitInventory()
        val unitBefore = observeUnitInventory()
        val jobBefore = observeJobInventory()
        val cgroupsBefore = observeCgroups()
        val shouldObserveIdentity =
            isSystemdIdentityCandidateWithoutIdentity(receipt, unitBefore, jobBefore, cgroupsBefore)
        val identityBefore = if (shouldObserveIdentity) {
            observeSystemdIdentity(receipt)
        } else {
            FullTreeFunctionObservationColdSystemdIdentityObservation(null, stable = true)
        }
        val identityAfter = if (shouldObserveIdentity) {
            observeSystemdIdentity(receipt)
        } else {
            FullTreeFunctionObservationColdSystemdIdentityObservation(null, stable = true)
        }
        val cgroupsAfter = observeCgroups()
        val jobAfter = observeJobInventory()
        val unitAfter = observeUnitInventory()
        val featuresAfter = observeUnfilteredUnitInventory()
        requireUnchanged()

        return classifyFullTreeFunctionObservationColdUnitSnapshots(
            expected = FullTreeFunctionObservationColdUnitReceiptIdentity.from(receipt),
            before = FullTreeFunctionObservationColdUnitSnapshot(
                managerFeatures = featuresBefore,
                unit = unitBefore,
                job = jobBefore,
                cgroups = cgroupsBefore.cgroups,
                systemdIdentity = identityBefore.identity,
                stable = cgroupsBefore.stable && identityBefore.stable,
            ),
            after = FullTreeFunctionObservationColdUnitSnapshot(
                managerFeatures = featuresAfter,
                unit = unitAfter,
                job = jobAfter,
                cgroups = cgroupsAfter.cgroups,
                systemdIdentity = identityAfter.identity,
                stable = cgroupsAfter.stable && identityAfter.stable,
            ),
        )
    }

    private fun requireReceiptBinding(
        receipt: FullTreeFunctionObservationUnitAttachmentReceipt,
    ) {
        if (
            receipt.operationId != binding.operationId ||
            receipt.requestSha256 != binding.requestSha256 ||
            receipt.bindingSha256 != binding.bindingSha256 ||
            receipt.isolationConfigurationSha256 != binding.isolationConfigurationSha256 ||
            receipt.unitName != binding.unitName
        ) isolationFail("cold systemd observation receipt differs from its operation binding")
    }

    private fun observeUnfilteredUnitInventory(): Set<String> {
        val version = runReadOnlySystemctl(
            COLD_SYSTEMD_MANAGER_VERSION_ARGUMENTS,
            "manager version",
        )
        val output = runReadOnlySystemctl(
            COLD_SYSTEMD_MANAGER_FEATURES_ARGUMENTS,
            "manager features",
        )
        requireColdSystemdManagerFeaturesUnfiltered(output, version)
        return (output.dropLast(1).split(' ') + "manager-version=${version.dropLast(1)}").toSortedSet()
    }

    private fun observeUnitInventory(): FullTreeFunctionObservationColdSystemdUnitInventoryEntry? =
        parseColdSystemdUnitInventory(
            runReadOnlySystemctl(
                COLD_SYSTEMD_LIST_UNITS_ARGUMENTS + listOf("--", unitName),
                "unit inventory",
            ),
            unitName,
        )

    private fun observeJobInventory(): FullTreeFunctionObservationColdSystemdJobInventoryEntry? =
        parseColdSystemdJobInventory(
            runReadOnlySystemctl(
                COLD_SYSTEMD_LIST_JOBS_ARGUMENTS + listOf("--", unitName),
                "job inventory",
            ),
            unitName,
        )

    private fun isSystemdIdentityCandidateWithoutIdentity(
        receipt: FullTreeFunctionObservationUnitAttachmentReceipt,
        unit: FullTreeFunctionObservationColdSystemdUnitInventoryEntry?,
        job: FullTreeFunctionObservationColdSystemdJobInventoryEntry?,
        cgroups: FullTreeFunctionObservationColdCgroupInventory,
    ): Boolean {
        if (
            unit == null || unit.unitName != receipt.unitName || unit.loadState != "loaded" ||
            unit.activeState != "active" || unit.subState != "running" || job != null || !cgroups.stable
        ) return false
        val expectedPath = CGROUP_ROOT.resolve(receipt.controlGroup.removePrefix("/")).normalize()
        return cgroups.cgroups.singleOrNull()?.let { observed ->
            observed.path == expectedPath &&
                observed.device == receipt.cgroupDevice &&
                observed.inode == receipt.cgroupInode &&
                observed.mountId == receipt.cgroupMountId
        } == true
    }

    private fun observeSystemdIdentity(
        receipt: FullTreeFunctionObservationUnitAttachmentReceipt,
    ): FullTreeFunctionObservationColdSystemdIdentityObservation {
        fun successful(arguments: List<String>, label: String): String? {
            val result = runReadOnlyBusctl(arguments, label)
            // The trusted command boundary merges stdout and stderr. Never expose that merged
            // text to a JSON parser unless busctl reported success.
            return if (result.exitCode == 0) result.output else null
        }

        val namePath = successful(
            COLD_SYSTEMD_BUSCTL_MANAGER_CALL + listOf("GetUnit", "s", receipt.unitName),
            "unit name lookup",
        )?.let { parseColdSystemdBusctlObjectPath(it, "unit name lookup") }
            ?: return FullTreeFunctionObservationColdSystemdIdentityObservation(null, stable = false)
        val cgroupPath = successful(
            COLD_SYSTEMD_BUSCTL_MANAGER_CALL +
                listOf("GetUnitByControlGroup", "s", receipt.controlGroup),
            "unit control-group lookup",
        )?.let { parseColdSystemdBusctlObjectPath(it, "unit control-group lookup") }
            ?: return FullTreeFunctionObservationColdSystemdIdentityObservation(null, stable = false)
        if (namePath != cgroupPath) {
            return FullTreeFunctionObservationColdSystemdIdentityObservation(null, stable = false)
        }

        val invocationArguments = buildList {
            addAll(COLD_SYSTEMD_BUSCTL_MANAGER_CALL)
            add("GetUnitByInvocationID")
            add("ay")
            add("16")
            addAll(systemdId128BusctlBytes(receipt.invocationId))
        }
        val invocationPath = successful(invocationArguments, "unit invocation lookup")
            ?.let { parseColdSystemdBusctlObjectPath(it, "unit invocation lookup") }
            ?: return FullTreeFunctionObservationColdSystemdIdentityObservation(null, stable = false)
        if (invocationPath != systemdInvocationObjectPath(receipt.invocationId)) {
            isolationFail("cold systemd unit invocation lookup returned an unbound object path")
        }

        // Dereference only the canonical invocation-addressed path reconstructed above. Its
        // decoded component is exactly 32 hexadecimal digits and therefore cannot be a valid
        // systemd unit name (it has no unit-type suffix), so an expired invocation cannot make
        // systemd's object-path resolver fall back to loading a name-addressed unit.

        fun property(interfaceName: String, propertyName: String): String? = successful(
            listOf(
                "get-property",
                SYSTEMD_BUS_SERVICE,
                invocationPath,
                interfaceName,
                propertyName,
            ),
            "unit invocation $propertyName property",
        )

        val observedUnitName = property(SYSTEMD_UNIT_INTERFACE, "Id")
            ?.let { parseColdSystemdBusctlStringProperty(it, "unit invocation Id property") }
            ?: return FullTreeFunctionObservationColdSystemdIdentityObservation(null, stable = false)
        val observedInvocationId = property(SYSTEMD_UNIT_INTERFACE, "InvocationID")
            ?.let { parseColdSystemdBusctlId128Property(it, "unit invocation InvocationID property") }
            ?: return FullTreeFunctionObservationColdSystemdIdentityObservation(null, stable = false)
        val transient = property(SYSTEMD_UNIT_INTERFACE, "Transient")
            ?.let { parseColdSystemdBusctlBooleanProperty(it, "unit invocation Transient property") }
            ?: return FullTreeFunctionObservationColdSystemdIdentityObservation(null, stable = false)
        val controlGroup = property(SYSTEMD_SCOPE_INTERFACE, "ControlGroup")
            ?.let { parseColdSystemdBusctlStringProperty(it, "unit invocation ControlGroup property") }
            ?: return FullTreeFunctionObservationColdSystemdIdentityObservation(null, stable = false)
        return FullTreeFunctionObservationColdSystemdIdentityObservation(
            FullTreeFunctionObservationColdSystemdIdentity(
                nameObjectPath = namePath,
                invocationObjectPath = invocationPath,
                unitName = observedUnitName,
                invocationId = observedInvocationId,
                transient = transient,
                controlGroup = controlGroup,
            ),
            stable = true,
        )
    }

    private fun observeCgroups(): FullTreeFunctionObservationColdCgroupInventory {
        val paths = try {
            findObservationCgroupsForUnit(unitName)
        } catch (_: java.nio.file.NoSuchFileException) {
            return FullTreeFunctionObservationColdCgroupInventory(emptyList(), stable = false)
        }
        var stable = true
        val cgroups = paths.sortedBy(Path::toString).mapNotNull { path ->
            val selected = LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)
            if (selected == null) {
                stable = false
                return@mapNotNull null
            }
            selected.use { descriptor ->
                val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
                if (
                    !identity.isDirectory || identity.isSymbolicLink ||
                    !sameDirectory(identity, descriptor.identity) ||
                    identity.key.device <= 0L || identity.key.inode <= 0L || identity.mountId <= 0L
                ) {
                    stable = false
                    return@use null
                }
                requireAuthenticatedCgroupV2Mount(identity)
                FullTreeFunctionObservationColdCgroupIdentity(
                    path = path,
                    device = identity.key.device,
                    inode = identity.key.inode,
                    mountId = identity.mountId,
                )
            }
        }
        return FullTreeFunctionObservationColdCgroupInventory(cgroups, stable)
    }

    private fun runReadOnlySystemctl(
        arguments: List<String>,
        label: String,
    ): String {
        inspector.requireUnchanged()
        bus.requireUnchanged()
        commandObserver?.beforeCommand(unitName, java.util.List.copyOf(arguments))
        val result = runTrustedCommand(
            listOf(inspector.path.toString(), "--user") + arguments,
            bus.controlEnvironment,
            SYSTEMD_CONTROL_TIMEOUT,
            "cold systemd $label",
        )
        if (result.exitCode != 0) isolationFail("cold systemd $label failed safely")
        inspector.requireUnchanged()
        bus.requireUnchanged()
        return result.output
    }

    private fun runReadOnlyBusctl(arguments: List<String>, label: String): TrustedCommandResult {
        inspector.requireUnchanged()
        busController.requireUnchanged()
        bus.requireUnchanged()
        val hardenedArguments = COLD_SYSTEMD_BUSCTL_OPTIONS + arguments
        busctlCommandObserver?.beforeCommand(unitName, java.util.List.copyOf(hardenedArguments))
        val result = runTrustedCommand(
            listOf(busController.path.toString()) + hardenedArguments,
            bus.controlEnvironment,
            SYSTEMD_CONTROL_TIMEOUT,
            "cold systemd $label",
        )
        inspector.requireUnchanged()
        busController.requireUnchanged()
        bus.requireUnchanged()
        return result
    }

    private fun requireUnfilteredUnitInventory() {
        observeUnfilteredUnitInventory()
    }

    private fun requireEnumerationEmpty(arguments: List<String>, label: String) {
        inspector.requireUnchanged()
        bus.requireUnchanged()
        commandObserver?.beforeCommand(unitName, java.util.List.copyOf(arguments))
        val result = runTrustedCommand(
            listOf(inspector.path.toString(), "--user") + arguments,
            bus.controlEnvironment,
            SYSTEMD_CONTROL_TIMEOUT,
            "cold systemd $label",
        )
        requireColdSystemdEnumerationEmpty(result.output, label, result.exitCode)
        inspector.requireUnchanged()
        bus.requireUnchanged()
    }

    private fun requireUnchanged() {
        inspector.requireUnchanged()
        busController.requireUnchanged()
        bus.requireUnchanged()
    }

    companion object {
        fun open(
            binding: FullTreeFunctionObservationOperationBinding,
            configuration: FullTreeFunctionObservationIsolationConfiguration,
        ): FullTreeFunctionObservationColdUnitAbsenceObserver = create(binding, configuration, null)

        internal fun openWithTestObserver(
            binding: FullTreeFunctionObservationOperationBinding,
            configuration: FullTreeFunctionObservationIsolationConfiguration,
            commandObserver: FullTreeFunctionObservationSystemctlCommandObserver,
            busctlCommandObserver: FullTreeFunctionObservationBusctlCommandObserver? = null,
        ): FullTreeFunctionObservationColdUnitAbsenceObserver =
            create(binding, configuration, commandObserver, busctlCommandObserver)

        private fun create(
            binding: FullTreeFunctionObservationOperationBinding,
            configuration: FullTreeFunctionObservationIsolationConfiguration,
            commandObserver: FullTreeFunctionObservationSystemctlCommandObserver?,
            busctlCommandObserver: FullTreeFunctionObservationBusctlCommandObserver? = null,
        ): FullTreeFunctionObservationColdUnitAbsenceObserver {
            if (configuration.canonicalSha256 != binding.isolationConfigurationSha256) {
                isolationFail("cold systemd observation configuration differs from its operation binding")
            }
            val inspector = PinnedSecurityExecutable.pin(
                configuration.scopeInspectorExecutable,
                "cold systemd scope inspector",
                configuration.expectedScopeInspectorSha256,
            )
            val busController = PinnedSecurityExecutable.pin(
                configuration.systemdBusControllerExecutable,
                "cold systemd bus controller",
                configuration.expectedSystemdBusControllerSha256,
            )
            val bus = PinnedSystemdBusEndpoint.pin(configuration.systemdUserRuntimeDirectory)
            return FullTreeFunctionObservationColdUnitAbsenceObserver(
                inspector,
                busController,
                bus,
                binding,
                configuration.canonicalSha256,
                commandObserver,
                busctlCommandObserver,
            )
        }
    }
}

internal fun requireColdSystemdEnumerationEmpty(output: String, label: String, exitCode: Int = 0) {
    if (exitCode != 0) isolationFail("cold systemd $label failed safely")
    if (output.isNotEmpty()) isolationFail("cold systemd $label was not empty")
}

internal fun parseColdSystemdUnitInventory(
    output: String,
    expectedUnitName: String,
): FullTreeFunctionObservationColdSystemdUnitInventoryEntry? {
    if (!expectedUnitName.matches(PRODUCTION_OBSERVATION_UNIT_NAME)) {
        isolationFail("cold systemd unit inventory name is not canonical")
    }
    val fields = parseColdSystemdInventoryFields(output, "unit inventory") ?: return null
    if (fields.size < 5 || fields.first() != expectedUnitName) {
        isolationFail("cold systemd unit inventory was malformed")
    }
    return FullTreeFunctionObservationColdSystemdUnitInventoryEntry(
        unitName = fields[0],
        loadState = fields[1],
        activeState = fields[2],
        subState = fields[3],
        description = fields.drop(4).joinToString(" "),
    )
}

internal fun parseColdSystemdJobInventory(
    output: String,
    expectedUnitName: String,
): FullTreeFunctionObservationColdSystemdJobInventoryEntry? {
    if (!expectedUnitName.matches(PRODUCTION_OBSERVATION_UNIT_NAME)) {
        isolationFail("cold systemd job inventory name is not canonical")
    }
    val fields = parseColdSystemdInventoryFields(output, "job inventory") ?: return null
    val jobId = fields.firstOrNull()?.toLongOrNull()
    if (fields.size != 4 || jobId == null || jobId <= 0L || fields[1] != expectedUnitName) {
        isolationFail("cold systemd job inventory was malformed")
    }
    return FullTreeFunctionObservationColdSystemdJobInventoryEntry(
        jobId = jobId,
        unitName = fields[1],
        jobType = fields[2],
        jobState = fields[3],
    )
}

private fun parseColdSystemdInventoryFields(output: String, label: String): List<String>? {
    if (output.isEmpty()) return null
    if (!output.endsWith('\n') || output.any { it == '\r' || it == '\u0000' }) {
        isolationFail("cold systemd $label was malformed")
    }
    val line = output.dropLast(1)
    if (line.isBlank() || line.contains('\n')) {
        isolationFail("cold systemd $label was malformed")
    }
    return line.trim().split(Regex("[ \\t]+"))
}

internal fun parseColdSystemdBusctlObjectPath(output: String, label: String): String {
    val (type, data) = parseColdSystemdBusctlEnvelope(output, label)
    val values = data as? JsonArray
    val path = values?.singleOrNull() as? JsonPrimitive
    if (
        type != "o" || path == null || !path.isString ||
        !path.content.matches(SYSTEMD_UNIT_OBJECT_PATH)
    ) isolationFail("cold systemd $label was malformed")
    return path.content
}

internal fun parseColdSystemdBusctlStringProperty(output: String, label: String): String {
    val (type, data) = parseColdSystemdBusctlEnvelope(output, label)
    val value = data as? JsonPrimitive
    if (type != "s" || value == null || !value.isString) {
        isolationFail("cold systemd $label was malformed")
    }
    return value.content
}

internal fun parseColdSystemdBusctlBooleanProperty(output: String, label: String): Boolean {
    val (type, data) = parseColdSystemdBusctlEnvelope(output, label)
    val value = data as? JsonPrimitive
    if (type != "b" || value == null || value.isString || value.content !in setOf("true", "false")) {
        isolationFail("cold systemd $label was malformed")
    }
    return value.content == "true"
}

internal fun parseColdSystemdBusctlId128Property(output: String, label: String): String {
    val (type, data) = parseColdSystemdBusctlEnvelope(output, label)
    val values = data as? JsonArray
    if (type != "ay" || values?.size != 16) isolationFail("cold systemd $label was malformed")
    val invocationId = values.joinToString("") { element ->
        val value = element as? JsonPrimitive
        val byte = value?.takeUnless(JsonPrimitive::isString)?.content?.toIntOrNull()
        if (byte == null || byte !in 0..255) isolationFail("cold systemd $label was malformed")
        byte.toString(16).padStart(2, '0')
    }
    if (invocationId in RESERVED_SYSTEMD_ID128S) {
        isolationFail("cold systemd $label contained a reserved invocation ID")
    }
    return invocationId
}

internal fun systemdInvocationObjectPath(invocationId: String): String {
    if (!invocationId.matches(SYSTEMD_ID128) || invocationId in RESERVED_SYSTEMD_ID128S) {
        isolationFail("cold systemd invocation ID is not canonical")
    }
    val label = if (invocationId.first().isDigit()) {
        "_3${invocationId.first()}${invocationId.drop(1)}"
    } else {
        invocationId
    }
    return "$SYSTEMD_UNIT_OBJECT_PATH_PREFIX$label"
}

private fun systemdId128BusctlBytes(invocationId: String): List<String> {
    systemdInvocationObjectPath(invocationId)
    return invocationId.chunked(2).map { byte -> byte.toInt(16).toString() }
}

private fun parseColdSystemdBusctlEnvelope(output: String, label: String): Pair<String, JsonElement> {
    if (
        !output.endsWith('\n') || output.dropLast(1).contains('\n') ||
        output.any { it == '\r' || it == '\u0000' }
    ) isolationFail("cold systemd $label was malformed")
    val root = try {
        OracleJson.parse(output.toByteArray(Charsets.UTF_8), COLD_SYSTEMD_BUSCTL_JSON_LIMITS)
    } catch (failure: Exception) {
        throw FullTreeFunctionObservationIsolationException("cold systemd $label was malformed", failure)
    }
    val envelope = root as? JsonObject
    if (envelope == null || envelope.keys != setOf("type", "data")) {
        isolationFail("cold systemd $label was malformed")
    }
    val type = envelope["type"] as? JsonPrimitive
    if (type == null || !type.isString) isolationFail("cold systemd $label was malformed")
    return type.content to envelope.getValue("data")
}

internal fun requireColdSystemdManagerFeaturesUnfiltered(output: String, managerVersionOutput: String) {
    if (managerVersionOutput.length > 256 || !managerVersionOutput.endsWith('\n')) {
        isolationFail("cold systemd manager version was malformed")
    }
    val managerVersion = COLD_SYSTEMD_MANAGER_VERSION.matchEntire(managerVersionOutput.dropLast(1))
        ?: isolationFail("cold systemd manager version was malformed")
    if (managerVersion.groupValues[1].toInt() !in 255..258) {
        isolationFail("cold systemd manager version is outside the reviewed unfiltered inventory range 255..258")
    }
    if (output.length > 16 * 1024 || !output.endsWith('\n')) {
        isolationFail("cold systemd manager features were malformed")
    }
    val line = output.dropLast(1)
    if (line.isEmpty() || line.any { it == '\r' || it == '\n' }) {
        isolationFail("cold systemd manager features were malformed")
    }
    val tokens = line.split(' ')
    val features = if (tokens.last().matches(COLD_SYSTEMD_DEFAULT_HIERARCHY)) tokens.dropLast(1) else tokens
    val featureNames = features.map { it.drop(1) }
    if (
        features.any { !it.matches(SYSTEMD_BUILD_FEATURE) } ||
        featureNames.toSet().size != features.size ||
        !featureNames.containsAll(COLD_SYSTEMD_REQUIRED_MAC_FEATURES)
    ) isolationFail("cold systemd manager features were malformed or incomplete")
}

private enum class ObservationUnitMutationTargetState {
    SAME,
    ABSENT,
    REPLACED,
}

private class ObservationSystemdController(
    private val inspector: PinnedSecurityExecutable,
    private val bus: PinnedSystemdBusEndpoint,
    val unitName: String,
    private val commandObserver: FullTreeFunctionObservationSystemctlCommandObserver? = null,
) {
    fun managerVersion(): String = systemctl(
        listOf("show", "--property=Version", "--value"),
    ).output.trim()

    fun requireAbsent() {
        if (show()["LoadState"] != "not-found" || findObservationCgroupsForUnit(unitName).isNotEmpty()) {
            isolationFail("isolated systemd unit or cgroup name is already in use")
        }
    }

    fun freeze(observeTarget: () -> ObservationUnitMutationTargetState) {
        requireSameMutationTarget("freeze", observeTarget)
        val result = systemctl(listOf("freeze", unitName))
        if (result.output.isNotBlank()) isolationFail("isolated systemd freeze was not quiet")
    }

    fun killFrozenKeeper(observeTarget: () -> ObservationUnitMutationTargetState) {
        requireSameMutationTarget("frozen-keeper kill", observeTarget)
        val result = systemctl(
            listOf("kill", "--kill-whom=all", "--signal=SIGKILL", unitName),
        )
        if (result.output.isNotBlank()) isolationFail("isolated frozen-keeper kill was not quiet")
    }

    /**
     * Cleans only the pidfd-pinned process returned by the local launch attempt. Until
     * [ManagedObservationUnit.awaitScopeAttached] proves that process belongs to this exact scope,
     * the deterministic unit name is merely an observed namespace candidate: stopping or killing
     * it could mutate a foreign winner of the StartTransientUnit name race.
     */
    fun killLocalProcessAndRequireAbsentWithoutUnitMutation(
        process: Process,
        processHandle: decompengine.acp.LinuxProcessDescriptor?,
    ) {
        val deadline = deadlineAfter(SERVICE_CLEANUP_TIMEOUT, "unattached local launch cleanup")
        var last: Throwable? = null
        while (System.nanoTime() < deadline) {
            runCatching {
                if (processHandle != null) LinuxFilesystemSyscalls.killProcess(processHandle)
                else if (process.isAlive) process.destroyForcibly()
            }.exceptionOrNull()?.let { last = it }
            runCatching { process.waitFor(SYSTEMD_POLL_MILLIS, TimeUnit.MILLISECONDS) }
                .exceptionOrNull()?.let { last = it }
            try {
                val unitAbsent = show()["LoadState"] == "not-found"
                val cgroupAbsent = findObservationCgroupsForUnit(unitName).isEmpty()
                if (!process.isAlive && unitAbsent && cgroupAbsent) return
            } catch (failure: Throwable) {
                last = failure
            }
            Thread.sleep(SYSTEMD_POLL_MILLIS)
        }
        throw FullTreeFunctionObservationIsolationException(
            "unattached local launch residue or a foreign same-name scope remains; " +
                "no unit-name mutation was attempted",
            last,
        )
    }

    fun show(): Map<String, String> {
        val result = systemctl(
            listOf(
                "show",
                unitName,
                "--property=${SYSTEMD_PROPERTIES.joinToString(",")}",
            ),
            allowedExitCodes = setOf(0, 1, 4),
        )
        val values = linkedMapOf<String, String>()
        result.output.lineSequence().filter(String::isNotBlank).forEach { line ->
            if ('=' !in line) isolationFail("systemd returned malformed isolated unit metadata")
            val name = line.substringBefore('=')
            if (name !in SYSTEMD_PROPERTIES || values.put(name, line.substringAfter('=')) != null) {
                isolationFail("systemd returned duplicate or unexpected isolated unit metadata")
            }
        }
        return values
    }

    fun killStopAndRequireAbsent(
        knownCgroup: Path,
        processHandle: decompengine.acp.LinuxProcessDescriptor,
        awaitLocalProcess: () -> Unit,
        observeTarget: () -> ObservationUnitMutationTargetState,
        killPinnedProcesses: () -> Unit,
    ) {
        val deadline = deadlineAfter(SERVICE_CLEANUP_TIMEOUT, "systemd cleanup")
        var last: Throwable? = null
        while (System.nanoTime() < deadline) {
            val guardedFailure = runCatching {
                runGuardedObservationSystemdCleanupFallback(
                    unitName = unitName,
                    beforeCommand = {
                        when (observeTarget()) {
                            ObservationUnitMutationTargetState.SAME -> true
                            ObservationUnitMutationTargetState.ABSENT -> false
                            ObservationUnitMutationTargetState.REPLACED ->
                                isolationFail("isolated cleanup refused a replacement systemd invocation")
                        }
                    },
                    command = { arguments, allowedExitCodes ->
                        systemctl(arguments, allowedExitCodes)
                    },
                    commandFailure = { failure ->
                        last = failure
                    },
                )
            }.exceptionOrNull()
            val pidfdFailure = runCatching(killPinnedProcesses).exceptionOrNull()
            if (guardedFailure != null) {
                if (pidfdFailure != null && pidfdFailure !== guardedFailure) {
                    guardedFailure.addSuppressed(pidfdFailure)
                }
                throw guardedFailure
            }
            pidfdFailure?.let { last = it }
            runCatching(awaitLocalProcess).exceptionOrNull()?.let { last = it }
            val absence = runCatching { show()["LoadState"] == "not-found" }
            absence.exceptionOrNull()?.let { last = it }
            absence.getOrNull()?.let { absent ->
                if (!absent && observeTarget() == ObservationUnitMutationTargetState.REPLACED) {
                    isolationFail("isolated cleanup observed a replacement systemd invocation")
                }
                runCatching {
                    val candidates = buildSet {
                        add(knownCgroup)
                        addAll(findObservationCgroupsForUnit(unitName))
                    }
                    val cgroupAbsent = candidates.none { Files.exists(it, LinkOption.NOFOLLOW_LINKS) }
                    if (
                        absent && cgroupAbsent &&
                        !LinuxFilesystemSyscalls.processExists(processHandle)
                    ) return
                }.exceptionOrNull()?.let { failure ->
                    last = failure
                }
            }
            Thread.sleep(SYSTEMD_POLL_MILLIS)
        }
        throw FullTreeFunctionObservationIsolationException(
            "isolated systemd unit or cgroup cleanup was not proven",
            last,
        )
    }

    private fun requireSameMutationTarget(
        action: String,
        observeTarget: () -> ObservationUnitMutationTargetState,
    ) {
        when (observeTarget()) {
            ObservationUnitMutationTargetState.SAME -> Unit
            ObservationUnitMutationTargetState.ABSENT ->
                isolationFail("isolated systemd target disappeared before $action")

            ObservationUnitMutationTargetState.REPLACED ->
                isolationFail("isolated systemd target was replaced before $action")
        }
    }

    private fun systemctl(
        arguments: List<String>,
        allowedExitCodes: Set<Int> = setOf(0),
    ): TrustedCommandResult {
        inspector.requireUnchanged()
        bus.requireUnchanged()
        commandObserver?.beforeCommand(unitName, java.util.List.copyOf(arguments))
        val result = runTrustedCommand(
            listOf(inspector.path.toString(), "--user") + arguments,
            bus.controlEnvironment,
            SYSTEMD_CONTROL_TIMEOUT,
            "isolated systemd control",
        )
        if (result.exitCode !in allowedExitCodes) isolationFail("isolated systemd control failed safely")
        inspector.requireUnchanged()
        bus.requireUnchanged()
        return result
    }
}

/** Ordered, best-effort teardown. Absence is still proved separately by the caller. */
internal fun runObservationSystemdCleanupFallback(
    unitName: String,
    command: (arguments: List<String>, allowedExitCodes: Set<Int>) -> Unit,
) = runGuardedObservationSystemdCleanupFallback(
    unitName = unitName,
    beforeCommand = { true },
    command = command,
)

internal fun runGuardedObservationSystemdCleanupFallback(
    unitName: String,
    beforeCommand: () -> Boolean,
    command: (arguments: List<String>, allowedExitCodes: Set<Int>) -> Unit,
    commandFailure: (Throwable) -> Unit = {},
) {
    observationSystemdCleanupCommands(unitName).forEach { arguments ->
        if (!beforeCommand()) return
        runCatching { command(arguments, OBSERVATION_SYSTEMD_CLEANUP_EXIT_CODES) }
            .exceptionOrNull()?.let(commandFailure)
    }
}

private fun observationSystemdCleanupCommands(unitName: String): List<List<String>> {
    val kill = listOf("kill", "--kill-whom=all", "--signal=SIGKILL", unitName)
    // Some manager/kernel combinations require an explicit thaw before a frozen unit can finish
    // teardown. The second kill also covers a process that raced or survived the first attempt.
    return listOf(
        kill,
        listOf("thaw", unitName),
        kill,
        listOf("stop", unitName),
        listOf("reset-failed", unitName),
    )
}

private data class RawObservationCgroupSample(
    val peakResidentBytes: Long,
    val cpuNanos: Long,
    val memoryMaxEvents: Long,
    val memoryOomEvents: Long,
    val memoryOomKillEvents: Long,
)

private data class ObservationProcessIdentity(
    val parentPid: Long,
    val namespacePids: List<Long>,
    val startTimeTicks: Long,
)

private enum class ObservationBootProcessTopology {
    FULL_TREE_SUPERVISOR,
    SINGLE_KOTLIN_KEEPER,
}

private data class ObservationAttachmentProcess(
    val role: FullTreeFunctionObservationAttachmentProcessRole,
    val hostPid: Long,
    val startTimeTicks: Long,
    val parentRole: FullTreeFunctionObservationAttachmentProcessRole?,
    val namespacePids: List<Long>,
    val executableDevice: Long,
    val executableInode: Long,
    val executableMountId: Long,
) {
    fun receiptIdentity() = FullTreeFunctionObservationAttachmentProcessIdentity(
        role = role,
        hostPid = hostPid,
        startTimeTicks = startTimeTicks,
        parentRole = parentRole,
        namespacePids = namespacePids,
        executableDevice = executableDevice,
        executableInode = executableInode,
        executableMountId = executableMountId,
    )
}

private data class ObservationBootPopulation(
    val processIds: Set<Long>,
    val processes: List<ObservationAttachmentProcess>,
)

private data class ObservationUnitAttachmentSnapshot(
    val bootId: String,
    val invocationId: String,
    val controlGroup: String,
    val cgroupIdentity: LinuxFileIdentity,
    val population: ObservationBootPopulation,
)

private fun sameAttachmentProcesses(
    first: List<FullTreeFunctionObservationAttachmentProcessIdentity>,
    second: List<FullTreeFunctionObservationAttachmentProcessIdentity>,
): Boolean = first.size == second.size && first.indices.all { index ->
    val left = first[index]
    val right = second[index]
    left.role == right.role && left.hostPid == right.hostPid &&
        left.startTimeTicks == right.startTimeTicks && left.parentRole == right.parentRole &&
        left.namespacePids == right.namespacePids &&
        left.executableDevice == right.executableDevice &&
        left.executableInode == right.executableInode &&
        left.executableMountId == right.executableMountId
}

/** Normalizes the kernel UUID spelling to the systemd ID128 spelling used by the receipt. */
internal fun normalizeFullTreeFunctionObservationKernelBootId(value: String): String {
    val line = if (value.endsWith('\n')) value.dropLast(1) else value
    if (
        line.any { it == '\r' || it == '\n' || it == '\u0000' } ||
        !line.matches(KERNEL_BOOT_UUID)
    ) isolationFail("kernel boot identity is malformed")
    val normalized = line.replace("-", "").lowercase()
    if (!normalized.matches(SYSTEMD_ID128) || normalized in RESERVED_SYSTEMD_ID128S) {
        isolationFail("kernel boot identity is reserved")
    }
    return normalized
}

private fun readFullTreeFunctionObservationKernelBootId(): String =
    normalizeFullTreeFunctionObservationKernelBootId(
        readBoundedText(KERNEL_BOOT_ID_PATH, MAXIMUM_KERNEL_BOOT_ID_BYTES),
    )

/**
 * Extracts Linux /proc PID stat field 22 without treating ')' or whitespace in comm as fields.
 * Only the suffix after the final kernel-added ") " delimiter participates in field indexing.
 */
internal fun parseFullTreeFunctionObservationProcessStartTimeTicks(
    hostPid: Long,
    value: String,
): Long {
    if (hostPid !in 1L..Int.MAX_VALUE) isolationFail("process stat PID is invalid")
    val record = if (value.endsWith('\n')) value.dropLast(1) else value
    val prefix = "$hostPid ("
    val delimiter = record.lastIndexOf(") ")
    if (
        !record.startsWith(prefix) || delimiter < prefix.length ||
        '\u0000' in record.substring(0, delimiter)
    ) isolationFail("process stat identity is malformed")
    val suffix = record.substring(delimiter + 2)
    if (suffix.any { it == '\r' || it == '\n' || it == '\t' || it == '\u0000' }) {
        isolationFail("process stat fields are malformed")
    }
    val fields = suffix.split(' ')
    if (
        fields.size < PROC_STAT_START_TIME_SUFFIX_FIELD_COUNT || fields.any(String::isEmpty) ||
        fields[0].length != 1 || !fields[0][0].isLetter()
    ) isolationFail("process stat fields are malformed")
    for (index in 1 until PROC_STAT_START_TIME_SUFFIX_FIELD_COUNT) {
        if (!fields[index].matches(PROC_STAT_INTEGER) || fields[index].toLongOrNull() == null) {
            isolationFail("process stat fields are malformed")
        }
    }
    return fields[PROC_STAT_START_TIME_SUFFIX_FIELD_COUNT - 1].toLong()
        .takeIf { it > 0L }
        ?: isolationFail("process stat start time is invalid")
}

internal fun requireNoHostSessionDescriptorAuthority(
    targets: Collection<String>,
    systemdUserRuntimeDirectory: Path,
) {
    val userRuntimeRoot = Path.of("/run/user")
    targets.forEach { target ->
        if (target.startsWith("socket:[")) {
            isolationFail("isolated JVM inherited a Unix or network socket descriptor")
        }
        val liveTarget = target.removeSuffix(" (deleted)")
        if (liveTarget.startsWith('/')) {
            val path = runCatching { Path.of(liveTarget).normalize() }.getOrNull()
            if (
                path != null &&
                (pathsOverlap(path, userRuntimeRoot) || pathsOverlap(path, systemdUserRuntimeDirectory))
            ) isolationFail("isolated JVM inherited a host session-runtime descriptor")
        }
    }
}

private class ManagedObservationUnit(
    private val controller: ObservationSystemdController,
    private val runDirectory: Path,
    private val nonce: String,
    private val bubblewrap: PinnedSecurityExecutable,
    private val java: PinnedSecurityExecutable,
    private val resources: IsolatedObservationResources,
    private val process: Process?,
    private val processHandle: decompengine.acp.LinuxProcessDescriptor,
    private val systemdUserRuntimeDirectory: Path,
    private val bootTopology: ObservationBootProcessTopology =
        ObservationBootProcessTopology.FULL_TREE_SUPERVISOR,
) : AutoCloseable {
    val unitName: String
        get() = controller.unitName
    val isColdAdopted: Boolean
        get() = process == null
    private var cgroupPath: Path? = null
    private var cgroupDescriptor: LinuxDescriptor? = null
    private var invocationId: String? = null
    private val mainPid: Long = process?.pid() ?: processHandle.pid
    private var keeperPids: Set<Long>? = null
    private var bootProcessHandles: Map<Long, decompengine.acp.LinuxProcessDescriptor>? = null
    private var frozen = false
    var cleaned: Boolean = false
        private set

    fun awaitScopeAttached() {
        val launchedProcess = process
            ?: isolationFail("a cold-adopted isolated scope cannot await a fresh attachment")
        check(cgroupPath == null && cgroupDescriptor == null && invocationId == null) {
            "isolated scope attachment was already established"
        }
        val deadline = deadlineAfter(SYSTEMD_LAUNCH_TIMEOUT, "isolated local scope attachment")
        var last: Throwable? = null
        while (System.nanoTime() < deadline) {
            if (!launchedProcess.isAlive) isolationFail("isolated local scope process exited before attachment")
            try {
                val before = controller.show()
                requireLiveProperties(before, resources, allowActivating = true)
                val attachedInvocationId = requireInvocationId(before)
                val controlGroup = before["ControlGroup"].orEmpty()
                val cgroup = requireCgroupPath(controlGroup)
                requireLocalLeader(cgroup)
                requireActualControllers(cgroup, resources)
                val pinned = pinCgroupDescriptor(cgroup)
                var retained = false
                try {
                    val after = controller.show()
                    requireLiveProperties(after, resources, allowActivating = true)
                    val afterCgroup = requireCgroupPath(after["ControlGroup"].orEmpty())
                    val pinnedIdentity = requirePinnedCgroupSelection(cgroup, pinned)
                    requireLocalLeader(afterCgroup)
                    requireActualControllers(afterCgroup, resources)
                    if (
                        before != after || afterCgroup != cgroup ||
                        requireInvocationId(after) != attachedInvocationId ||
                        LinuxFilesystemSyscalls.identity(pinned.fd) != pinnedIdentity
                    ) isolationFail("isolated scope identity changed while descriptor-pinned")
                    invocationId = attachedInvocationId
                    cgroupPath = cgroup
                    cgroupDescriptor = pinned
                    retained = true
                    return
                } finally {
                    if (!retained) pinned.close()
                }
            } catch (failure: FullTreeFunctionObservationIsolationException) {
                last = failure
            }
            Thread.sleep(SYSTEMD_POLL_MILLIS)
        }
        throw FullTreeFunctionObservationIsolationException(
            "isolated local scope could not be attached and verified",
            last,
        )
    }

    /**
     * Re-pins one exact durable BOOT receipt during a deliberate coordinator handoff. This method
     * observes and retains only the receipt-matched invocation; a mismatch closes the newly opened
     * pidfd and cgroup descriptors without issuing any mutating systemd command or process signal.
     */
    fun adoptUnitAttachment(expected: FullTreeFunctionObservationUnitAttachmentReceipt) {
        if (process != null) isolationFail("a freshly launched scope cannot be cold-adopted")
        check(cgroupPath == null && cgroupDescriptor == null && invocationId == null) {
            "isolated scope attachment was already established"
        }
        val outer = expected.processes.singleOrNull {
            it.role == FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP
        } ?: isolationFail("cold unit-attachment receipt lacks one outer bubblewrap")
        if (expected.unitName != unitName || outer.hostPid != mainPid) {
            isolationFail("cold unit-attachment receipt names a different scope leader")
        }
        var pinnedCgroup: LinuxDescriptor? = null
        try {
            val before = controller.show()
            requireLiveProperties(before, resources)
            val observedInvocation = requireInvocationId(before)
            val observedControlGroup = before["ControlGroup"].orEmpty()
            if (
                observedInvocation != expected.invocationId ||
                observedControlGroup != expected.controlGroup
            ) isolationFail("cold systemd invocation differs from its durable attachment receipt")
            val cgroup = requireCgroupPath(observedControlGroup)
            requireLocalLeader(cgroup)
            requireActualControllers(cgroup, resources)
            val pinned = pinCgroupDescriptor(cgroup)
            pinnedCgroup = pinned
            val pinnedIdentity = requirePinnedCgroupSelection(cgroup, pinned)
            if (
                pinnedIdentity.key.device != expected.cgroupDevice ||
                pinnedIdentity.key.inode != expected.cgroupInode ||
                pinnedIdentity.mountId != expected.cgroupMountId
            ) isolationFail("cold cgroup identity differs from its durable attachment receipt")
            invocationId = observedInvocation
            cgroupPath = cgroup
            cgroupDescriptor = pinned
            pinnedCgroup = null
            requireCurrentUnitAttachmentReceipt(expected)
        } catch (failure: Throwable) {
            pinnedCgroup?.let { runCatching { it.close() }.exceptionOrNull()?.let(failure::addSuppressed) }
            runCatching { abandonWithoutMutation() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    /** Descriptor-only unwind for a failed cold observation; never mutates the unit or its PIDs. */
    fun abandonWithoutMutation() {
        if (cleaned) return
        bootProcessHandles?.values?.forEach { it.close() }
        bootProcessHandles = null
        cgroupDescriptor?.close()
        cgroupDescriptor = null
        processHandle.close()
        cleaned = true
    }

    fun awaitBoot(
        expectedNonce: String,
        runTree: ObservationRunTreeAccess? = null,
    ) {
        check(expectedNonce == nonce)
        val deadline = deadlineAfter(WORKER_START_TIMEOUT, "isolated worker bootstrap")
        var nextStatus = 0L
        while (System.nanoTime() < deadline) {
            bootProtocolFileOrNull(runTree, BOOT_FILE)?.let { content ->
                if (content != protocol("BOOT", nonce)) isolationFail("isolated worker BOOT proof is invalid")
                return
            }
            bootProtocolFileOrNull(runTree, FAILURE_FILE)?.let {
                isolationFail("isolated worker failed before its BOOT proof")
            }
            bootProtocolFileOrNull(runTree, SUPERVISOR_FAILURE_FILE)?.let {
                isolationFail("isolated supervisor failed before the worker BOOT proof")
            }
            val now = System.nanoTime()
            if (now >= nextStatus) {
                requireUnitStillRunning(controller.show(), "before BOOT")
                nextStatus = addNanos(now, STATUS_POLL_INTERVAL.toNanos(), "status poll")
            }
            Thread.sleep(PROTOCOL_POLL_MILLIS)
        }
        isolationFail("isolated worker did not reach its BOOT barrier")
    }

    private fun bootProtocolFileOrNull(
        runTree: ObservationRunTreeAccess?,
        name: String,
    ): String? = if (runTree == null) {
        protocolFileOrNull(runDirectory, name)
    } else {
        runTree.withPinnedDescriptor { root -> protocolFileOrNull(root, name) }
    }

    fun verifyLiveContainment(expected: IsolatedObservationResources) {
        captureStableUnitAttachment(expected)
    }

    fun captureKotlinBootAttachment(
        expected: IsolatedObservationResources,
        runtimeConfigurationSha256: String,
        requestedResources: KotlinSystemdCgroupBootResources,
        deploymentClosureSha256: String,
    ): KotlinSystemdCgroupBootReceipt {
        if (bootTopology != ObservationBootProcessTopology.SINGLE_KOTLIN_KEEPER) {
            isolationFail("generic Kotlin BOOT receipt requires the single-keeper topology")
        }
        if (!runtimeConfigurationSha256.matches(SHA256)) {
            isolationFail("generic Kotlin BOOT runtime-closure digest is invalid")
        }
        if (!deploymentClosureSha256.matches(SHA256)) {
            isolationFail("generic Kotlin BOOT deployment-closure digest is invalid")
        }
        val snapshot = captureStableUnitAttachment(expected)
        val roles = mapOf(
            FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP to "scope-leader",
            FullTreeFunctionObservationAttachmentProcessRole.NAMESPACE_INIT_BUBBLEWRAP to "namespace-init",
            FullTreeFunctionObservationAttachmentProcessRole.SUPERVISOR_JVM to "kotlin-boot-keeper",
        )
        val processes = snapshot.population.processes.map { process ->
            val role = roles[process.role]
                ?: isolationFail("generic Kotlin BOOT receipt contains an unexpected process role")
            KotlinSystemdCgroupBootProcessReceipt(
                role = role,
                pid = process.hostPid,
                startTimeTicks = process.startTimeTicks,
                parentRole = process.parentRole?.let { parent ->
                    roles[parent] ?: isolationFail("generic Kotlin BOOT receipt has an unexpected parent role")
                },
                namespacePids = process.namespacePids,
                executableSha256 = when (process.role) {
                    FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP,
                    FullTreeFunctionObservationAttachmentProcessRole.NAMESPACE_INIT_BUBBLEWRAP -> bubblewrap.sha256
                    FullTreeFunctionObservationAttachmentProcessRole.SUPERVISOR_JVM -> java.sha256
                    FullTreeFunctionObservationAttachmentProcessRole.WORKER_JVM ->
                        isolationFail("generic Kotlin BOOT receipt unexpectedly contains a worker JVM")
                },
            )
        }
        return KotlinSystemdCgroupBootReceipt(
            unitName = unitName,
            nonce = nonce,
            bootId = systemdBootIdToKernelUuid(snapshot.bootId),
            invocationId = snapshot.invocationId,
            controlGroup = snapshot.controlGroup,
            cgroupDevice = snapshot.cgroupIdentity.key.device,
            cgroupInode = snapshot.cgroupIdentity.key.inode,
            cgroupMountId = snapshot.cgroupIdentity.mountId,
            runtimeClosureSha256 = runtimeConfigurationSha256,
            deploymentClosureSha256 = deploymentClosureSha256,
            resources = requestedResources,
            processes = processes,
        )
    }

    private fun systemdBootIdToKernelUuid(value: String): String {
        if (!value.matches(SYSTEMD_ID128) || value in RESERVED_SYSTEMD_ID128S) {
            isolationFail("generic Kotlin BOOT kernel identity is invalid")
        }
        return "${value.substring(0, 8)}-${value.substring(8, 12)}-${value.substring(12, 16)}-" +
            "${value.substring(16, 20)}-${value.substring(20)}"
    }

    /**
     * Captures only historical receipt data. The returned canonical object neither transfers the
     * live pidfds/cgroup descriptor nor appends UNIT_ATTACHED to the operation journal.
     */
    internal fun captureUnitAttachmentReceipt(
        binding: FullTreeFunctionObservationOperationBinding,
        leasedTransition: FullTreeFunctionObservationOperationTransition,
        runRootIdentity: LinuxFileIdentity,
    ): FullTreeFunctionObservationUnitAttachmentReceipt {
        if (binding.unitName != unitName) {
            isolationFail("unit-attachment binding names a different systemd scope")
        }
        val snapshot = captureStableUnitAttachment(resources)
        return FullTreeFunctionObservationUnitAttachmentReceipt.create(
            binding = binding,
            leasedTransition = leasedTransition,
            bootId = snapshot.bootId,
            invocationId = snapshot.invocationId,
            controlGroup = snapshot.controlGroup,
            cgroupDevice = snapshot.cgroupIdentity.key.device,
            cgroupInode = snapshot.cgroupIdentity.key.inode,
            cgroupMountId = snapshot.cgroupIdentity.mountId,
            runRootDevice = runRootIdentity.key.device,
            runRootInode = runRootIdentity.key.inode,
            runRootMountId = runRootIdentity.mountId,
            processes = snapshot.population.processes.map(ObservationAttachmentProcess::receiptIdentity),
        )
    }

    /** Reobserves all live-derived fields; journal/binding freshness remains the caller's job. */
    internal fun requireCurrentUnitAttachmentReceipt(
        expected: FullTreeFunctionObservationUnitAttachmentReceipt,
    ) {
        if (expected.unitName != unitName) {
            isolationFail("unit-attachment receipt names a different systemd scope")
        }
        val actual = captureStableUnitAttachment(resources)
        if (
            expected.bootId != actual.bootId ||
            expected.invocationId != actual.invocationId ||
            expected.controlGroup != actual.controlGroup ||
            expected.cgroupDevice != actual.cgroupIdentity.key.device ||
            expected.cgroupInode != actual.cgroupIdentity.key.inode ||
            expected.cgroupMountId != actual.cgroupIdentity.mountId ||
            !sameAttachmentProcesses(
                expected.processes,
                actual.population.processes.map(ObservationAttachmentProcess::receiptIdentity),
            )
        ) isolationFail("live unit attachment differs from its exact receipt")
    }

    private fun captureStableUnitAttachment(
        expected: IsolatedObservationResources,
    ): ObservationUnitAttachmentSnapshot {
        if (expected != resources) isolationFail("isolated attachment resource policy changed")
        val attachedPath = cgroupPath ?: isolationFail("isolated cgroup was not descriptor-pinned")
        val attachedInvocationId = invocationId
            ?: isolationFail("isolated systemd invocation was not retained")
        val beforeProperties = controller.show()
        requireLiveProperties(beforeProperties, expected)
        val beforeControlGroup = beforeProperties["ControlGroup"].orEmpty()
        val cgroup = requireCgroupPath(beforeControlGroup)
        if (cgroup != attachedPath || requireInvocationId(beforeProperties) != attachedInvocationId) {
            isolationFail("isolated scope attachment identity changed")
        }
        requireLocalLeader(cgroup)
        requireActualControllers(cgroup, expected)
        val cgroupBefore = requirePinnedCgroupSelection(cgroup)
        val bootIdBefore = readNormalizedKernelBootId()
        val populationBefore = requireBootProcesses(cgroup)
        retainBootProcessHandles(cgroup, populationBefore.processIds)
        requireRetainedBootProcessesLive(populationBefore.processIds)

        val populationAfter = requireBootProcesses(cgroup)
        val bootIdAfter = readNormalizedKernelBootId()
        val cgroupAfter = requirePinnedCgroupSelection(cgroup)
        requireLocalLeader(cgroup)
        requireActualControllers(cgroup, expected)
        val afterProperties = controller.show()
        requireLiveProperties(afterProperties, expected)
        val afterControlGroup = afterProperties["ControlGroup"].orEmpty()
        if (
            populationAfter != populationBefore || bootIdAfter != bootIdBefore ||
            cgroupAfter != cgroupBefore || beforeProperties != afterProperties ||
            afterControlGroup != beforeControlGroup ||
            requireCgroupPath(afterControlGroup) != cgroup ||
            requireInvocationId(afterProperties) != attachedInvocationId
        ) isolationFail("isolated unit attachment changed while its receipt was captured")
        requireRetainedBootProcessesLive(populationAfter.processIds)
        return ObservationUnitAttachmentSnapshot(
            bootId = bootIdAfter,
            invocationId = attachedInvocationId,
            controlGroup = afterControlGroup,
            cgroupIdentity = cgroupAfter,
            population = populationAfter,
        )
    }

    private fun requireBootProcesses(cgroup: Path): ObservationBootPopulation {
        val before = readCgroupProcesses(cgroup)
        val expectedProcessCount = when (bootTopology) {
            ObservationBootProcessTopology.FULL_TREE_SUPERVISOR -> BOOT_PROCESS_COUNT
            ObservationBootProcessTopology.SINGLE_KOTLIN_KEEPER -> KOTLIN_BOOT_PROCESS_COUNT
        }
        if (before.size != expectedProcessCount || mainPid !in before) {
            isolationFail("isolated BOOT cgroup has the wrong exact process population")
        }
        val processIdentities = mutableMapOf<Long, ObservationProcessIdentity>()
        val executableIdentities = mutableMapOf<Long, LinuxFileIdentity>()
        val bubblewrapProcesses = mutableListOf<Long>()
        val javaProcesses = mutableListOf<Long>()
        before.sorted().forEach { pid ->
            LinuxFilesystemSyscalls.openProcessExecutable(pid).use { executable ->
                val identity = LinuxFilesystemSyscalls.identity(executable.fd)
                if (!sameRegularFile(identity, executable.identity)) {
                    isolationFail("isolated BOOT executable changed while descriptor-pinned")
                }
                val isJava = identity.key.device == java.identity.device &&
                    identity.key.inode == java.identity.inode
                val isBubblewrap = identity.key.device == bubblewrap.identity.device &&
                    identity.key.inode == bubblewrap.identity.inode
                when {
                    isJava -> {
                        javaProcesses += pid
                        requireNoHostSessionAuthority(pid)
                    }

                    isBubblewrap -> bubblewrapProcesses += pid
                    else -> isolationFail("isolated BOOT cgroup contains an unexpected executable")
                }
                executableIdentities[pid] = identity
            }
            processIdentities[pid] = readProcessIdentity(pid)
        }
        val expectedJavaProcesses = when (bootTopology) {
            ObservationBootProcessTopology.FULL_TREE_SUPERVISOR -> 2
            ObservationBootProcessTopology.SINGLE_KOTLIN_KEEPER -> 1
        }
        if (
            bubblewrapProcesses.size != 2 || javaProcesses.size != expectedJavaProcesses ||
            mainPid !in bubblewrapProcesses
        ) {
            isolationFail("isolated BOOT cgroup lacks its exact bubblewrap and JVM population")
        }
        val outer = mainPid
        val inner = bubblewrapProcesses.single { it != outer }
        val outerIdentity = processIdentities.getValue(outer)
        val innerIdentity = processIdentities.getValue(inner)
        if (
            outerIdentity.namespacePids != listOf(outer) ||
            innerIdentity.parentPid != outer || innerIdentity.namespacePids != listOf(inner, 1L)
        ) isolationFail("isolated BOOT bubblewrap processes have the wrong PID-namespace chain")
        val supervisor = javaProcesses.singleOrNull { pid ->
            processIdentities.getValue(pid).parentPid == inner
        } ?: isolationFail("isolated BOOT cgroup lacks its direct keeper JVM")
        val supervisorIdentity = processIdentities.getValue(supervisor)
        val supervisorNamespacePid = supervisorIdentity.namespacePids.getOrNull(1)
        if (
            supervisorIdentity.namespacePids.size != 2 || supervisorNamespacePid == null ||
            supervisorNamespacePid <= 1L
        ) isolationFail("isolated BOOT keeper has the wrong PID-namespace chain")
        fun process(
            role: FullTreeFunctionObservationAttachmentProcessRole,
            pid: Long,
            parentRole: FullTreeFunctionObservationAttachmentProcessRole?,
        ): ObservationAttachmentProcess {
            val processIdentity = processIdentities.getValue(pid)
            val executableIdentity = executableIdentities.getValue(pid)
            return ObservationAttachmentProcess(
                role = role,
                hostPid = pid,
                startTimeTicks = processIdentity.startTimeTicks,
                parentRole = parentRole,
                namespacePids = processIdentity.namespacePids,
                executableDevice = executableIdentity.key.device,
                executableInode = executableIdentity.key.inode,
                executableMountId = executableIdentity.mountId,
            )
        }
        val fixedProcesses = listOf(
            process(FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP, outer, null),
            process(
                FullTreeFunctionObservationAttachmentProcessRole.NAMESPACE_INIT_BUBBLEWRAP,
                inner,
                FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP,
            ),
            process(
                FullTreeFunctionObservationAttachmentProcessRole.SUPERVISOR_JVM,
                supervisor,
                FullTreeFunctionObservationAttachmentProcessRole.NAMESPACE_INIT_BUBBLEWRAP,
            ),
        )
        val processes = when (bootTopology) {
            ObservationBootProcessTopology.SINGLE_KOTLIN_KEEPER -> fixedProcesses
            ObservationBootProcessTopology.FULL_TREE_SUPERVISOR -> {
                val worker = javaProcesses.single { it != supervisor }
                val workerIdentity = processIdentities.getValue(worker)
                val workerNamespacePid = workerIdentity.namespacePids.getOrNull(1)
                if (
                    workerIdentity.namespacePids.size != 2 || workerNamespacePid == null ||
                    workerNamespacePid <= 1L || supervisorNamespacePid == workerNamespacePid ||
                    workerIdentity.parentPid != supervisor
                ) isolationFail("isolated BOOT worker JVM has the wrong parent or PID-namespace chain")
                fixedProcesses + process(
                    FullTreeFunctionObservationAttachmentProcessRole.WORKER_JVM,
                    worker,
                    FullTreeFunctionObservationAttachmentProcessRole.SUPERVISOR_JVM,
                )
            }
        }
        val executableKeys = processes.associate { attachment ->
            attachment.role to listOf(
                attachment.executableDevice,
                attachment.executableInode,
                attachment.executableMountId,
            )
        }
        if (
            executableKeys.getValue(FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP) !=
            executableKeys.getValue(
                FullTreeFunctionObservationAttachmentProcessRole.NAMESPACE_INIT_BUBBLEWRAP,
            ) ||
            executableKeys.getValue(FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP) ==
            executableKeys.getValue(FullTreeFunctionObservationAttachmentProcessRole.SUPERVISOR_JVM)
        ) isolationFail("isolated BOOT executable mount identities do not match their roles")
        if (
            bootTopology == ObservationBootProcessTopology.FULL_TREE_SUPERVISOR &&
            executableKeys.getValue(FullTreeFunctionObservationAttachmentProcessRole.SUPERVISOR_JVM) !=
            executableKeys.getValue(FullTreeFunctionObservationAttachmentProcessRole.WORKER_JVM)
        ) isolationFail("isolated BOOT JVM executable mount identities differ")
        val after = readCgroupProcesses(cgroup)
        if (after != before) isolationFail("isolated BOOT process inventory changed while verified")
        return ObservationBootPopulation(before, processes)
    }

    private fun retainBootProcessHandles(cgroup: Path, processes: Set<Long>) {
        val retained = bootProcessHandles
        if (retained != null) {
            requireRetainedBootProcessesLive(processes)
            return
        }
        val opened = linkedMapOf<Long, decompengine.acp.LinuxProcessDescriptor>()
        try {
            processes.sorted().forEach { pid ->
                opened[pid] = LinuxFilesystemSyscalls.openProcessHandle(pid)
            }
            if (
                opened.values.any { !LinuxFilesystemSyscalls.processExists(it) } ||
                readCgroupProcesses(cgroup) != processes
            ) isolationFail("isolated BOOT process inventory changed during pidfd pinning")
            bootProcessHandles = opened.toMap()
        } catch (failure: Throwable) {
            opened.values.forEach { handle -> runCatching { handle.close() } }
            throw failure
        }
    }

    private fun requireRetainedBootProcessesLive(processes: Set<Long>) {
        val retained = bootProcessHandles
            ?: isolationFail("isolated BOOT pidfd inventory is absent")
        if (retained.keys != processes || retained.values.any { !LinuxFilesystemSyscalls.processExists(it) }) {
            isolationFail("isolated BOOT pidfd inventory is no longer live")
        }
    }

    private fun pinCgroupDescriptor(cgroup: Path): LinuxDescriptor {
        val descriptor = try {
            LinuxFilesystemSyscalls.openRoot(cgroup)
        } catch (failure: Throwable) {
            throw FullTreeFunctionObservationIsolationException(
                "cannot descriptor-pin the attached cgroup",
                failure,
            )
        }
        try {
            requirePinnedCgroupSelection(cgroup, descriptor)
            return descriptor
        } catch (failure: Throwable) {
            descriptor.close()
            throw failure
        }
    }

    private fun requirePinnedCgroupSelection(
        cgroup: Path,
        descriptor: LinuxDescriptor = cgroupDescriptor
            ?: isolationFail("isolated cgroup descriptor is absent"),
    ): LinuxFileIdentity {
        val current = descriptor.whileOpen(LinuxFilesystemSyscalls::identity)
        if (
            !sameDirectory(current, descriptor.identity) ||
            current.key.device <= 0L || current.key.inode <= 0L || current.mountId <= 0L
        ) isolationFail("descriptor-pinned isolated cgroup changed identity")
        requireAuthenticatedCgroupV2Mount(current)
        val selected = try {
            LinuxFilesystemSyscalls.openRoot(cgroup)
        } catch (failure: Throwable) {
            throw FullTreeFunctionObservationIsolationException(
                "cannot reselect the descriptor-pinned isolated cgroup",
                failure,
            )
        }
        selected.use { byPath ->
            val selectedCurrent = LinuxFilesystemSyscalls.identity(byPath.fd)
            if (
                !sameDirectory(current, byPath.identity) ||
                !sameDirectory(current, selectedCurrent)
            ) isolationFail("isolated cgroup path selected a replacement directory")
        }
        return current
    }

    private fun readNormalizedKernelBootId(): String = readFullTreeFunctionObservationKernelBootId()

    private fun requireActualControllers(cgroup: Path, expected: IsolatedObservationResources) {
        val pidsMax = readRequiredLong(cgroup.resolve("pids.max"), "isolated pids.max")
        val memoryMax = readRequiredLong(cgroup.resolve("memory.max"), "isolated memory.max")
        val swapMax = readRequiredLong(cgroup.resolve("memory.swap.max"), "isolated memory.swap.max")
        val oomGroup = readBoundedText(cgroup.resolve("memory.oom.group"), CGROUP_TEXT_BYTES).trim()
        val cpu = readBoundedText(cgroup.resolve("cpu.max"), CGROUP_TEXT_BYTES)
            .trim().split(Regex("\\s+"))
        val quota = cpu.getOrNull(0)?.toLongOrNull()
        val period = cpu.getOrNull(1)?.toLongOrNull()
        if (
            pidsMax != expected.tasksMax || memoryMax != expected.maximumResidentBytes ||
            swapMax != 0L || oomGroup != "1" || cpu.size != 2 || quota == null || period == null ||
            quota <= 0L || quota != period
        ) isolationFail("isolated cgroup controllers differ from the authenticated runtime policy")
        val procs = readCgroupProcesses(cgroup)
        if (mainPid !in procs) isolationFail("isolated bubblewrap leader is absent from its cgroup")
        val populated = parseFlatCounters(
            readBoundedText(cgroup.resolve("cgroup.events"), CGROUP_TEXT_BYTES),
            "cgroup.events",
        )["populated"]
        if (populated != 1L) isolationFail("isolated worker cgroup is not populated")
    }

    fun awaitReady(
        expectedNonce: String,
        wallSeconds: Long,
    ): FullTreeFunctionObservationPublishedShard {
        check(expectedNonce == nonce)
        val deadline = deadlineAfter(Duration.ofSeconds(wallSeconds), "isolated derivation")
        var nextStatus = 0L
        while (System.nanoTime() < deadline) {
            protocolFileOrNull(runDirectory, READY_FILE)?.let { return decodeReady(nonce, it) }
            protocolFileOrNull(runDirectory, FAILURE_FILE)?.let {
                isolationFail("isolated worker rejected the function-observation derivation")
            }
            protocolFileOrNull(runDirectory, SUPERVISOR_FAILURE_FILE)?.let {
                isolationFail("isolated supervisor failed during function-observation derivation")
            }
            val now = System.nanoTime()
            if (now >= nextStatus) {
                requireUnitStillRunning(controller.show(), "during derivation")
                nextStatus = addNanos(now, STATUS_POLL_INTERVAL.toNanos(), "status poll")
            }
            Thread.sleep(PROTOCOL_POLL_MILLIS)
        }
        isolationFail("isolated worker exceeded its authenticated wall-clock bound")
    }

    fun awaitDone(expectedNonce: String) {
        check(expectedNonce == nonce)
        val deadline = deadlineAfter(WORKER_EXIT_TIMEOUT, "isolated worker exit acknowledgement")
        while (System.nanoTime() < deadline) {
            protocolFileOrNull(runDirectory, DONE_FILE)?.let { content ->
                if (content != protocol("DONE", nonce)) isolationFail("isolated worker DONE proof is invalid")
                return
            }
            protocolFileOrNull(runDirectory, FAILURE_FILE)?.let {
                isolationFail("isolated worker failed after the parent ACK")
            }
            protocolFileOrNull(runDirectory, SUPERVISOR_FAILURE_FILE)?.let {
                isolationFail("isolated supervisor failed after the parent ACK")
            }
            Thread.sleep(PROTOCOL_POLL_MILLIS)
        }
        isolationFail("isolated worker did not acknowledge shutdown")
    }

    fun awaitWorkerExited(expectedNonce: String) {
        check(expectedNonce == nonce)
        val deadline = deadlineAfter(WORKER_EXIT_TIMEOUT, "isolated inner-worker exit")
        var nextStatus = 0L
        while (System.nanoTime() < deadline) {
            protocolFileOrNull(runDirectory, WORKER_EXITED_FILE)?.let { content ->
                val namespacePid = decodeKeeperProtocol(nonce, content)
                keeperPids = requireKeeperProcesses(namespacePid)
                return
            }
            protocolFileOrNull(runDirectory, FAILURE_FILE)?.let {
                isolationFail("isolated worker failed during its final exit")
            }
            protocolFileOrNull(runDirectory, SUPERVISOR_FAILURE_FILE)?.let {
                isolationFail("isolated supervisor rejected the inner-worker exit")
            }
            val now = System.nanoTime()
            if (now >= nextStatus) {
                requireUnitStillRunning(controller.show(), "while awaiting inner-worker exit")
                nextStatus = addNanos(now, STATUS_POLL_INTERVAL.toNanos(), "status poll")
            }
            Thread.sleep(PROTOCOL_POLL_MILLIS)
        }
        isolationFail("isolated supervisor did not prove inner-worker exit")
    }

    fun freezeAndSampleRawCgroup(expected: IsolatedObservationResources): RawObservationCgroupSample {
        val cgroup = cgroupPath ?: isolationFail("isolated cgroup was not verified")
        val expectedKeepers = keeperPids ?: isolationFail("isolated keeper inventory was not verified")
        val namespacePid = decodeKeeperProtocol(
            nonce,
            protocolFileOrNull(runDirectory, WORKER_EXITED_FILE)
                ?: isolationFail("isolated worker-exit proof disappeared before cgroup freeze"),
        )
        if (requireKeeperProcesses(namespacePid) != expectedKeepers) {
            isolationFail("isolated keeper process inventory changed before cgroup freeze")
        }
        controller.freeze(::observeUnitMutationTarget)
        val deadline = deadlineAfter(CGROUP_FREEZE_TIMEOUT, "isolated cgroup freeze")
        while (System.nanoTime() < deadline) {
            val events = parseFlatCounters(
                readBoundedText(cgroup.resolve("cgroup.events"), CGROUP_TEXT_BYTES),
                "cgroup.events",
            )
            if (events["frozen"] == 1L && events["populated"] == 1L) {
                frozen = true
                break
            }
            if (events["populated"] != 1L) {
                isolationFail("isolated cgroup emptied before its frozen accounting barrier")
            }
            Thread.sleep(SYSTEMD_POLL_MILLIS)
        }
        if (!frozen) isolationFail("isolated cgroup freeze was not proven")
        if (requireKeeperProcesses(namespacePid) != expectedKeepers) {
            isolationFail("isolated keeper process inventory changed at the frozen barrier")
        }
        requireLiveProperties(controller.show(), expected)

        val eventsBefore = readMemoryEvents(cgroup)
        val peakBefore = readRequiredLong(cgroup.resolve("memory.peak"), "isolated memory.peak")
        val cpuBefore = parseFlatCounters(
            readBoundedText(cgroup.resolve("cpu.stat"), CGROUP_TEXT_BYTES),
            "cpu.stat",
        )
        val eventsAfter = readMemoryEvents(cgroup)
        val peakAfter = readRequiredLong(cgroup.resolve("memory.peak"), "isolated memory.peak")
        val cpuAfter = parseFlatCounters(
            readBoundedText(cgroup.resolve("cpu.stat"), CGROUP_TEXT_BYTES),
            "cpu.stat",
        )
        val cgroupEvents = parseFlatCounters(
            readBoundedText(cgroup.resolve("cgroup.events"), CGROUP_TEXT_BYTES),
            "cgroup.events",
        )
        if (
            eventsBefore != eventsAfter || peakBefore != peakAfter || cpuBefore != cpuAfter ||
            cgroupEvents["frozen"] != 1L || cgroupEvents["populated"] != 1L
        ) isolationFail("isolated cgroup accounting changed across its frozen sample")

        val peak = peakAfter
        val cpuUsec = cpuAfter["usage_usec"] ?: isolationFail("isolated cpu.stat lacks usage_usec")
        val max = eventsAfter["max"] ?: isolationFail("isolated memory.events lacks max")
        val oom = eventsAfter["oom"] ?: isolationFail("isolated memory.events lacks oom")
        val oomKill = addExact(
            eventsAfter["oom_kill"] ?: isolationFail("isolated memory.events lacks oom_kill"),
            eventsAfter["oom_group_kill"] ?: 0L,
            "isolated OOM kill count",
        )
        val cpuNanos = multiplyExact(cpuUsec, 1_000L, "isolated cgroup CPU time")
        if (
            peak !in 1L..expected.maximumResidentBytes ||
            cpuNanos > secondsToNanos(expected.cpuSeconds, "CPU") ||
            max != 0L || oom != 0L || oomKill != 0L
        ) isolationFail("isolated cgroup exceeded a resource bound before its frozen sample")
        return RawObservationCgroupSample(peak, cpuNanos, max, oom, oomKill)
    }

    fun killFrozenKeeperAndProveRemoved(
        expected: IsolatedObservationResources,
        live: RawObservationCgroupSample,
    ) {
        val cgroup = cgroupPath ?: isolationFail("isolated cgroup was not verified")
        if (!frozen) isolationFail("isolated keeper cannot be terminated before cgroup freeze")
        val events = parseFlatCounters(
            readBoundedText(cgroup.resolve("cgroup.events"), CGROUP_TEXT_BYTES),
            "cgroup.events",
        )
        if (events["frozen"] != 1L || events["populated"] != 1L) {
            isolationFail("isolated cgroup left its frozen barrier before keeper termination")
        }
        val guardedFailure = runCatching {
            controller.killFrozenKeeper(::observeUnitMutationTarget)
        }.exceptionOrNull()
        val pidfdFailure = runCatching(::killRetainedProcessHandles).exceptionOrNull()
        if (guardedFailure != null) {
            if (pidfdFailure != null && pidfdFailure !== guardedFailure) {
                guardedFailure.addSuppressed(pidfdFailure)
            }
            throw guardedFailure
        }
        pidfdFailure?.let { throw it }
        val deadline = deadlineAfter(WORKER_EXIT_TIMEOUT, "isolated frozen-keeper cgroup drain")
        while (System.nanoTime() < deadline) {
            process?.waitFor(SYSTEMD_POLL_MILLIS, TimeUnit.MILLISECONDS)
            val absent = controller.show()["LoadState"] == "not-found"
            if (!leaderIsAlive() && absent && !Files.exists(cgroup, LinkOption.NOFOLLOW_LINKS)) break
            Thread.sleep(SYSTEMD_POLL_MILLIS)
        }
        if (
            leaderIsAlive() || process?.let { it.exitValue() != LOCAL_SIGKILL_EXIT } == true ||
            controller.show()["LoadState"] != "not-found" ||
            Files.exists(cgroup, LinkOption.NOFOLLOW_LINKS)
        ) isolationFail("isolated frozen keeper did not reach exact local SIGKILL and scope absence")
        if (LinuxFilesystemSyscalls.killProcess(processHandle)) {
            isolationFail("isolated pidfd remained live after local SIGKILL exit")
        }
        if (bootProcessHandles?.values?.any(LinuxFilesystemSyscalls::processExists) == true) {
            isolationFail("isolated retained BOOT pidfd remained live after keeper termination")
        }
        frozen = false
        if (
            live.peakResidentBytes !in 1L..expected.maximumResidentBytes ||
            live.cpuNanos > secondsToNanos(expected.cpuSeconds, "CPU")
        ) isolationFail("frozen final cgroup sample violates the authenticated resource bounds")
    }

    private fun requireKeeperProcesses(supervisorNamespacePid: Long): Set<Long> {
        val cgroup = cgroupPath ?: isolationFail("isolated cgroup was not verified")
        val leader = mainPid
        requireLiveProperties(controller.show(), resources)
        val before = readCgroupProcesses(cgroup)
        if (before.size != KEEPER_PROCESS_COUNT || leader !in before) {
            isolationFail("isolated keeper cgroup has an unexpected process count or leader")
        }
        var namespaceInit: Long? = null
        var javaKeeper: Long? = null
        before.forEach { pid ->
            LinuxFilesystemSyscalls.openProcessExecutable(pid).use { executable ->
                val identity = executable.identity
                val isJava = identity.key.device == java.identity.device &&
                    identity.key.inode == java.identity.inode
                val isBubblewrap = identity.key.device == bubblewrap.identity.device &&
                    identity.key.inode == bubblewrap.identity.inode
                when {
                    pid == leader -> {
                        if (!isBubblewrap) {
                            isolationFail("isolated keeper cgroup leader is not the pinned bubblewrap")
                        }
                        val status = readProcessIdentity(pid)
                        if (status.namespacePids != listOf(pid)) {
                            isolationFail("isolated outer bubblewrap has an unexpected PID namespace")
                        }
                    }

                    isJava -> {
                        if (javaKeeper != null) {
                            isolationFail("isolated cgroup contains multiple Kotlin keepers")
                        }
                        val status = readProcessIdentity(pid)
                        if (
                            status.namespacePids != listOf(pid, supervisorNamespacePid) ||
                            supervisorNamespacePid <= 1L
                        ) {
                            isolationFail("isolated Java keeper has the wrong PID-namespace identity")
                        }
                        javaKeeper = pid
                        requireNoHostSessionAuthority(pid)
                    }

                    isBubblewrap -> {
                        if (namespaceInit != null) {
                            isolationFail("isolated cgroup contains multiple namespace-init processes")
                        }
                        val status = readProcessIdentity(pid)
                        if (status.namespacePids != listOf(pid, 1L)) {
                            isolationFail("isolated inner bubblewrap is not the PID-namespace init")
                        }
                        namespaceInit = pid
                    }

                    else -> isolationFail("isolated keeper cgroup contains an unexpected executable")
                }
            }
        }
        val initPid = namespaceInit ?: isolationFail("isolated cgroup lacks its namespace-init bubblewrap")
        val keeperPid = javaKeeper ?: isolationFail("isolated cgroup lacks its Kotlin keeper")
        if (
            readProcessIdentity(initPid).parentPid != leader ||
            readProcessIdentity(keeperPid).parentPid != initPid
        ) isolationFail("isolated keeper processes do not have the exact expected parent chain")
        val after = readCgroupProcesses(cgroup)
        if (after != before) isolationFail("isolated keeper process inventory changed while verified")
        return before
    }

    private fun requireLocalLeader(cgroup: Path) {
        if (!leaderIsAlive()) isolationFail("isolated pidfd-pinned scope leader exited unexpectedly")
        val procCgroup = readBoundedText(Path.of("/proc/$mainPid/cgroup"), MAXIMUM_PROC_CGROUP_BYTES)
            .lineSequence().singleOrNull { it.startsWith("0::") }
            ?.removePrefix("0::")
            ?: isolationFail("isolated local process is not in one cgroup-v2 leaf")
        val actual = CGROUP_ROOT.resolve(procCgroup.removePrefix("/")).normalize()
        if (actual != cgroup) isolationFail("isolated local process is outside its reported scope")
        LinuxFilesystemSyscalls.openProcessExecutable(mainPid).use { executable ->
            if (
                executable.identity.key.device != bubblewrap.identity.device ||
                executable.identity.key.inode != bubblewrap.identity.inode
            ) isolationFail("pidfd-pinned local process did not transition to the pinned bubblewrap")
        }
    }

    private fun requireNoHostSessionAuthority(pid: Long) {
        val processRoot = Path.of("/proc/$pid/root")
        val sessionRelative = systemdUserRuntimeDirectory.toString().removePrefix("/")
        if (
            Files.exists(processRoot.resolve(sessionRelative), LinkOption.NOFOLLOW_LINKS) ||
            Files.exists(processRoot.resolve("run/user"), LinkOption.NOFOLLOW_LINKS)
        ) isolationFail("isolated synthetic root exposes a host session-runtime path")
        val environment = readBoundedText(Path.of("/proc/$pid/environ"), MAXIMUM_PROC_ENVIRONMENT_BYTES)
            .split('\u0000').filter(String::isNotEmpty)
        if (environment.any { value ->
                value.startsWith("DBUS_SESSION_BUS_ADDRESS=") || value.startsWith("XDG_RUNTIME_DIR=")
            }
        ) isolationFail("isolated JVM retained host session-bus environment authority")
        val descriptors = Files.newDirectoryStream(Path.of("/proc/$pid/fd")).use { entries ->
            entries.toList()
        }
        if (descriptors.size > RLIMIT_NOFILE) {
            isolationFail("isolated JVM exceeds its descriptor inventory bound")
        }
        val targets = descriptors.map { descriptor ->
            val number = descriptor.fileName.toString().toIntOrNull()
                ?.takeIf { it in 0 until RLIMIT_NOFILE }
                ?: isolationFail("isolated JVM has an invalid or out-of-policy descriptor number")
            val target = runCatching { Files.readSymbolicLink(descriptor).toString() }
                .getOrElse { failure ->
                    throw FullTreeFunctionObservationIsolationException(
                        "isolated JVM descriptor $number changed while inspected",
                        failure,
                    )
                }
            if (target.length > MAXIMUM_PROC_DESCRIPTOR_TARGET_CHARS || '\u0000' in target) {
                isolationFail("isolated JVM descriptor target exceeds its text bound")
            }
            target
        }
        requireNoHostSessionDescriptorAuthority(targets, systemdUserRuntimeDirectory)
    }

    private fun readCgroupProcesses(cgroup: Path): Set<Long> {
        val lines = readBoundedText(cgroup.resolve("cgroup.procs"), CGROUP_PROCS_BYTES)
            .lineSequence().filter(String::isNotBlank).toList()
        val processes = lines.map { line ->
            line.trim().toLongOrNull()?.takeIf { it in 1L..Int.MAX_VALUE }
                ?: isolationFail("isolated cgroup.procs contains an invalid PID")
        }
        if (processes.toSet().size != processes.size) {
            isolationFail("isolated cgroup.procs contains a duplicate PID")
        }
        return processes.toSet()
    }

    private fun readProcessIdentity(hostPid: Long): ObservationProcessIdentity {
        val status = readBoundedText(Path.of("/proc/$hostPid/status"), MAXIMUM_PROC_STATUS_BYTES)
        val namespaceLine = status.lineSequence().singleOrNull { it.startsWith("NSpid:") }
            ?: isolationFail("isolated keeper process lacks one NSpid record")
        val namespacePids = namespaceLine.removePrefix("NSpid:").trim().split(Regex("[ \\t]+"))
            .filter(String::isNotEmpty)
            .map { value ->
                value.toLongOrNull()?.takeIf { it in 1L..Int.MAX_VALUE }
                    ?: isolationFail("isolated keeper NSpid record is invalid")
            }
        if (namespacePids.firstOrNull() != hostPid || namespacePids.size !in 1..2) {
            isolationFail("isolated keeper NSpid record has an unexpected namespace chain")
        }
        val parentLine = status.lineSequence().singleOrNull { it.startsWith("PPid:") }
            ?: isolationFail("isolated keeper process lacks one PPid record")
        val parentPid = parentLine.removePrefix("PPid:").trim().toLongOrNull()
            ?.takeIf { it in 0L..Int.MAX_VALUE }
            ?: isolationFail("isolated keeper PPid record is invalid")
        val startTimeTicks = parseFullTreeFunctionObservationProcessStartTimeTicks(
            hostPid,
            readBoundedText(Path.of("/proc/$hostPid/stat"), MAXIMUM_PROC_STAT_BYTES),
        )
        return ObservationProcessIdentity(parentPid, namespacePids, startTimeTicks)
    }

    private fun readMemoryEvents(cgroup: Path): Map<String, Long> = parseFlatCounters(
        readBoundedText(cgroup.resolve("memory.events"), CGROUP_TEXT_BYTES),
        "memory.events",
    )

    fun stopAndProveRemoved() {
        if (cleaned) return
        val cgroup = cgroupPath ?: isolationFail("isolated cgroup was not retained for cleanup")
        controller.killStopAndRequireAbsent(
            knownCgroup = cgroup,
            processHandle = processHandle,
            awaitLocalProcess = {
                process?.waitFor(SYSTEMD_POLL_MILLIS, TimeUnit.MILLISECONDS)
            },
            observeTarget = ::observeUnitMutationTarget,
            killPinnedProcesses = ::killRetainedProcessHandles,
        )
        val retained = bootProcessHandles
        if (retained != null && retained.values.any { LinuxFilesystemSyscalls.processExists(it) }) {
            isolationFail("isolated BOOT pidfd remained live after unit and cgroup absence")
        }
        retained?.values?.forEach { it.close() }
        bootProcessHandles = null
        cgroupDescriptor?.close()
        cgroupDescriptor = null
        processHandle.close()
        cleaned = true
    }

    private fun killRetainedProcessHandles() {
        var failure: Throwable? = null
        val handles = buildList {
            bootProcessHandles?.values?.let(::addAll)
            add(processHandle)
        }
        handles.forEach { handle ->
            runCatching { LinuxFilesystemSyscalls.killProcess(handle) }.exceptionOrNull()?.let { next ->
                val primary = failure
                if (primary == null) failure = next else if (next !== primary) primary.addSuppressed(next)
            }
        }
        failure?.let { throw it }
    }

    /**
     * Authenticates the retained invocation and descriptor-selected cgroup immediately before a
     * unit-name mutation. ABSENT permits only pidfd backstops; REPLACED must fail without touching
     * the deterministic name. The check/command interval assumes cooperative same-UID peers.
     */
    private fun observeUnitMutationTarget(): ObservationUnitMutationTargetState {
        val expectedCgroup = cgroupPath
            ?: isolationFail("isolated cleanup lacks its retained cgroup path")
        cgroupDescriptor ?: isolationFail("isolated cleanup lacks its retained cgroup descriptor")
        val expectedInvocation = invocationId
            ?: isolationFail("isolated cleanup lacks its retained systemd invocation")
        val properties = controller.show()
        if (properties["LoadState"] == "not-found") {
            return ObservationUnitMutationTargetState.ABSENT
        }
        val observedInvocation = properties["InvocationID"].orEmpty()
        if (
            properties["Id"] != unitName || properties["Transient"] != "yes" ||
            observedInvocation != expectedInvocation ||
            !observedInvocation.matches(SYSTEMD_ID128) ||
            observedInvocation in RESERVED_SYSTEMD_ID128S
        ) return ObservationUnitMutationTargetState.REPLACED
        val controlGroup = properties["ControlGroup"].orEmpty()
        if (controlGroup.isBlank()) return ObservationUnitMutationTargetState.ABSENT
        if (!controlGroup.startsWith('/') || '\u0000' in controlGroup) {
            return ObservationUnitMutationTargetState.REPLACED
        }
        val selected = CGROUP_ROOT.resolve(controlGroup.removePrefix("/")).normalize()
        if (
            !selected.startsWith(CGROUP_ROOT) || selected == CGROUP_ROOT ||
            selected.fileName?.toString() != unitName || selected != expectedCgroup
        ) return ObservationUnitMutationTargetState.REPLACED
        if (Files.notExists(expectedCgroup, LinkOption.NOFOLLOW_LINKS)) {
            return ObservationUnitMutationTargetState.ABSENT
        }
        return runCatching { requirePinnedCgroupSelection(expectedCgroup) }.fold(
            onSuccess = { ObservationUnitMutationTargetState.SAME },
            onFailure = { ObservationUnitMutationTargetState.REPLACED },
        )
    }

    override fun close() {
        stopAndProveRemoved()
    }

    private fun requireUnitStillRunning(properties: Map<String, String>, label: String) {
        if (
            properties["LoadState"] != "loaded" || properties["ActiveState"] != "active" ||
            properties["SubState"] != "running" || !leaderIsAlive()
        ) isolationFail(
            "isolated worker systemd scope stopped $label " +
                "(load=${properties["LoadState"]}, active=${properties["ActiveState"]}, " +
                "sub=${properties["SubState"]}, localAlive=${leaderIsAlive()})",
        )
    }

    private fun requireLiveProperties(
        properties: Map<String, String>,
        expected: IsolatedObservationResources,
        allowActivating: Boolean = false,
    ) {
        val localAlive = leaderIsAlive()
        val stateOkay = properties["LoadState"] == "loaded" && localAlive &&
            if (allowActivating) properties["ActiveState"] in setOf("active", "activating")
            else properties["ActiveState"] == "active" && properties["SubState"] == "running"
        if (!stateOkay) isolationFail(
            "isolated systemd scope is not live during containment verification " +
                "(load=${properties["LoadState"]}, active=${properties["ActiveState"]}, " +
                "sub=${properties["SubState"]}, localAlive=$localAlive)",
        )
        val mismatches = buildList {
            addAll(staticPolicyMismatches(properties, expected))
        }
        if (mismatches.isNotEmpty()) {
            isolationFail("isolated systemd policy differs: ${mismatches.joinToString(",")}")
        }
        val retainedInvocationId = invocationId
        if (retainedInvocationId != null && requireInvocationId(properties) != retainedInvocationId) {
            isolationFail("isolated systemd invocation identity changed")
        }
    }

    private fun staticPolicyMismatches(
        properties: Map<String, String>,
        expected: IsolatedObservationResources,
    ): List<String> = buildList {
        if (properties["Id"] != controller.unitName) add("Id")
        if (properties["Transient"] != "yes") add("Transient")
        val invocation = properties["InvocationID"].orEmpty()
        if (!invocation.matches(SYSTEMD_ID128) || invocation in RESERVED_SYSTEMD_ID128S) {
            add("InvocationID")
        }
        if (properties["CollectMode"] != "inactive-or-failed") add("CollectMode")
        if (properties["TasksMax"] != expected.tasksMax.toString()) add("TasksMax")
        if (properties["MemoryMax"] != expected.maximumResidentBytes.toString()) add("MemoryMax")
        if (properties["MemorySwapMax"] != "0") add("MemorySwapMax")
        if (properties["OOMPolicy"] != "kill") add("OOMPolicy")
        if (properties["CPUQuotaPerSecUSec"] !in setOf("1s", "1000000us")) add("CPUQuota")
        if (properties["KillMode"] != "control-group") add("KillMode")
        if (properties["SendSIGKILL"] != "yes") add("SendSIGKILL")
        if (properties["Delegate"] != "no") add("Delegate")
        if (
            parseSystemdMicros(properties["RuntimeMaxUSec"]) !=
            multiplyExact(expected.serviceRuntimeSeconds, 1_000_000L, "systemd runtime microseconds")
        ) {
            add("RuntimeMaxUSec")
        }
        if (
            parseSystemdMicros(properties["TimeoutStopUSec"]) !=
            multiplyExact(expected.timeoutStopMillis, 1_000L, "systemd stop-timeout microseconds")
        ) add("TimeoutStopUSec")
    }

    private fun requireInvocationId(properties: Map<String, String>): String =
        properties["InvocationID"].orEmpty().takeIf { value ->
            value.matches(SYSTEMD_ID128) && value !in RESERVED_SYSTEMD_ID128S
        } ?: isolationFail("isolated systemd invocation identity is invalid")

    private fun requireCgroupPath(controlGroup: String): Path {
        if (!controlGroup.startsWith('/') || controlGroup.contains('\u0000')) {
            isolationFail("systemd returned an invalid isolated cgroup path")
        }
        val path = CGROUP_ROOT.resolve(controlGroup.removePrefix("/")).normalize()
        if (!path.startsWith(CGROUP_ROOT) || path.fileName?.toString() != controller.unitName ||
            !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
        ) isolationFail("systemd returned an unsafe or missing isolated cgroup")
        val previous = cgroupPath
        if (previous != null && previous != path) isolationFail("isolated cgroup path changed")
        if (cgroupDescriptor != null) requirePinnedCgroupSelection(path)
        return path
    }

    private fun leaderIsAlive(): Boolean = LinuxFilesystemSyscalls.processExists(processHandle)
}

private class PinnedObservationCandidate private constructor(
    private val descriptor: LinuxDescriptor,
    val channel: FileChannel,
    val bytes: Long,
    val sha256: String,
) : AutoCloseable {
    private var unlinked = false

    fun unlinkFrom(root: LinuxDescriptor) {
        if (unlinked) isolationFail("isolated candidate was already unlinked")
        root.whileOpen { rootFd ->
            LinuxFilesystemSyscalls.openRegularFileAtOrNull(rootFd, CANDIDATE_FILE).use { selected ->
                if (selected == null || !sameRegularFile(selected.identity, descriptor.identity)) {
                    isolationFail("isolated candidate changed before unlink")
                }
            }
            LinuxFilesystemSyscalls.unlink(rootFd, CANDIDATE_FILE)
            LinuxFilesystemSyscalls.openPathAtOrNull(rootFd, CANDIDATE_FILE)?.use {
                isolationFail("isolated candidate remains named after unlink")
            }
        }
        LinuxFilesystemSyscalls.synchronize(root)
        if (LinuxFilesystemSyscalls.identity(descriptor.fd).linkCount != 0) {
            isolationFail("isolated candidate remains linked after parent pinning")
        }
        unlinked = true
    }

    fun requireUnlinked() {
        if (!unlinked || LinuxFilesystemSyscalls.identity(descriptor.fd).linkCount != 0) {
            isolationFail("parent publication candidate is not an unlinked pinned inode")
        }
        val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!identity.isRegularFile || identity.isSymbolicLink || identity.mode.permissions != OWNER_READ_ONLY_MODE) {
            isolationFail("parent publication candidate changed type or mode")
        }
        if (channel.size() != bytes || digestChannel(channel, bytes) != sha256) {
            isolationFail("parent publication candidate changed after worker exit")
        }
    }

    override fun close() {
        var failure: Throwable? = null
        try {
            channel.close()
        } catch (closeFailure: Throwable) {
            failure = closeFailure
        }
        try {
            descriptor.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(
            root: LinuxDescriptor,
            expectedBytes: Long,
            expectedSha256: String,
            maximumBytes: Long,
        ): PinnedObservationCandidate {
            if (expectedBytes !in 1L..maximumBytes || !expectedSha256.matches(SHA256)) {
                isolationFail("isolated worker reported an invalid candidate digest")
            }
            val descriptor = root.whileOpen { fd ->
                LinuxFilesystemSyscalls.openRegularFileAtOrNull(fd, CANDIDATE_FILE)
                    ?: isolationFail("isolated worker candidate is absent")
            }
            try {
                val identity = descriptor.identity
                if (
                    !identity.isRegularFile || identity.isSymbolicLink || identity.linkCount != 1 ||
                    identity.mode.permissions != OWNER_READ_ONLY_MODE
                ) isolationFail("isolated worker candidate is not a private 0400 regular file")
                val channel = FileChannel.open(
                    LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd),
                    StandardOpenOption.READ,
                )
                try {
                    if (channel.size() != expectedBytes || digestChannel(channel, expectedBytes) != expectedSha256) {
                        isolationFail("isolated worker candidate differs from its READY receipt")
                    }
                    val after = LinuxFilesystemSyscalls.identity(descriptor.fd)
                    if (!sameRegularFile(identity, after)) {
                        isolationFail("isolated worker candidate changed while it was pinned")
                    }
                    return PinnedObservationCandidate(descriptor, channel, expectedBytes, expectedSha256)
                } catch (failure: Throwable) {
                    channel.close()
                    throw failure
                }
            } catch (failure: Throwable) {
                descriptor.close()
                throw failure
            }
        }
    }
}

private data class ParentPublishedDigest(val sha256: String, val bytes: Long)

private object ParentObservationPublisher {
    fun publish(
        candidate: PinnedObservationCandidate,
        target: Path,
        expectedBytes: Long,
        expectedSha256: String,
        maximumBytes: Long,
        beforeCommit: () -> Unit,
        afterCommit: () -> Unit,
    ): ParentPublishedDigest {
        candidate.requireUnlinked()
        val normalized = target.toAbsolutePath().normalize()
        val parentPath = normalized.parent ?: isolationFail("isolated publication target has no parent")
        val targetName = normalized.fileName?.toString()
            ?: isolationFail("isolated publication target has no file name")
        LinuxFilesystemSyscalls.requireSupported(parentPath)
        val (stableParent, parentIdentity) = requireStableDirectory(
            parentPath,
            "isolated publication parent",
        )
        LinuxFilesystemSyscalls.openRoot(stableParent).use { parent ->
            if (!Files.isSameFile(stableParent, LinuxFilesystemSyscalls.stableDescriptorPath(parent.fd))) {
                isolationFail("isolated publication parent changed during authorization")
            }
            parent.whileOpen { fd ->
                LinuxFilesystemSyscalls.openPathAtOrNull(fd, targetName)?.use {
                    isolationFail("isolated function-observation publication target already exists")
                }
            }
            val stageName = ".function-observation-parent-${randomHex(STAGE_RANDOM_BYTES)}.tmp"
            val stage = parent.whileOpen { fd ->
                LinuxFilesystemSyscalls.createRegularFile(fd, stageName, OWNER_READ_WRITE_MODE)
            }
            var linkedName = stageName
            var committed = false
            try {
                val digest = copyCandidate(candidate, stage, expectedBytes, expectedSha256, maximumBytes)
                LinuxFilesystemSyscalls.chmod(stage, OWNER_READ_ONLY_MODE)
                LinuxFilesystemSyscalls.synchronize(stage)
                requireStage(stage, expectedBytes, "parent staging output")
                if (digest.sha256 != expectedSha256 || digest.bytes != expectedBytes) {
                    isolationFail("parent staging output differs from the isolated candidate")
                }
                beforeCommit()
                val (_, currentParentIdentity) = requireStableDirectory(
                    stableParent,
                    "isolated publication parent",
                )
                if (currentParentIdentity != parentIdentity) {
                    isolationFail("isolated publication parent changed before commit")
                }
                parent.whileOpen { fd ->
                    LinuxFilesystemSyscalls.openPathAtOrNull(fd, targetName)?.use {
                        isolationFail("isolated function-observation publication target already exists")
                    }
                    try {
                        LinuxFilesystemSyscalls.renameNoReplace(fd, stageName, targetName)
                    } catch (failure: LinuxSyscallException) {
                        if (failure.errno == LinuxFilesystemSyscalls.EEXIST) {
                            throw FullTreeFunctionObservationIsolationException(
                                "isolated function-observation publication target already exists",
                                failure,
                            )
                        }
                        throw failure
                    }
                    linkedName = targetName
                }
                LinuxFilesystemSyscalls.synchronize(parent)
                parent.whileOpen { fd ->
                    LinuxFilesystemSyscalls.openRegularFileAtOrNull(fd, targetName).use { named ->
                        if (named == null || !sameRegularFile(named.identity, stage.identity)) {
                            isolationFail("parent publication selected a different output inode")
                        }
                    }
                }
                requireStage(stage, expectedBytes, "published isolated output")
                if (digestDescriptor(stage, expectedBytes) != expectedSha256) {
                    isolationFail("published isolated output differs from the pinned candidate")
                }
                afterCommit()
                committed = true
                return digest
            } finally {
                if (!committed) {
                    parent.whileOpen { fd ->
                        LinuxFilesystemSyscalls.openRegularFileAtOrNull(fd, linkedName).use { selected ->
                            if (selected != null) {
                                if (!sameRegularFile(selected.identity, stage.identity)) {
                                    isolationFail("refusing to revoke a replaced parent staging output")
                                }
                                LinuxFilesystemSyscalls.unlink(fd, linkedName)
                            }
                        }
                    }
                    LinuxFilesystemSyscalls.synchronize(parent)
                }
                stage.close()
            }
        }
    }

    private fun copyCandidate(
        candidate: PinnedObservationCandidate,
        stage: LinuxDescriptor,
        expectedBytes: Long,
        expectedSha256: String,
        maximumBytes: Long,
    ): ParentPublishedDigest {
        if (expectedBytes !in 1L..maximumBytes) isolationFail("isolated candidate exceeds output bound")
        candidate.requireUnlinked()
        val digest = MessageDigest.getInstance("SHA-256")
        candidate.channel.position(0L)
        LinuxFilesystemSyscalls.reopenWritable(stage).use { writable ->
            FileChannel.open(
                LinuxFilesystemSyscalls.stableDescriptorPath(writable.fd),
                StandardOpenOption.WRITE,
            ).use { output ->
                output.truncate(0L)
                val buffer = ByteBuffer.allocate(COPY_BUFFER_BYTES)
                var copied = 0L
                while (copied < expectedBytes) {
                    buffer.clear()
                    buffer.limit(minOf(buffer.capacity().toLong(), expectedBytes - copied).toInt())
                    val read = candidate.channel.read(buffer)
                    if (read <= 0) isolationFail("isolated candidate ended during parent copy")
                    digest.update(buffer.array(), 0, read)
                    buffer.flip()
                    while (buffer.hasRemaining()) output.write(buffer)
                    copied = addExact(copied, read.toLong(), "parent publication byte count")
                }
                if (candidate.channel.read(ByteBuffer.allocate(1)) >= 0) {
                    isolationFail("isolated candidate grew beyond its receipt")
                }
                output.force(true)
                val actualSha = digest.digest().hex()
                if (actualSha != expectedSha256) isolationFail("isolated candidate changed during parent copy")
                return ParentPublishedDigest(actualSha, copied)
            }
        }
    }

    private fun requireStage(stage: LinuxDescriptor, expectedBytes: Long, label: String) {
        val identity = LinuxFilesystemSyscalls.identity(stage.fd)
        if (
            !identity.isRegularFile || identity.isSymbolicLink || identity.linkCount != 1 ||
            identity.mode.permissions != OWNER_READ_ONLY_MODE ||
            Files.size(LinuxFilesystemSyscalls.stableDescriptorPath(stage.fd)) != expectedBytes
        ) isolationFail("$label changed identity, size, or mode")
    }
}

private fun requireWorkerReceipt(
    receipt: FullTreeFunctionObservationPublishedShard,
    authenticated: AuthenticatedFullTreeScope,
    guards: ParentObservationInputGuards,
    parentInputs: FullTreeFunctionObservationAuthenticatedInputs,
    shardId: String,
    resources: IsolatedObservationResources,
) {
    val projectedEntities = addExact(
        receipt.emittedRvas,
        receipt.nonEmitted,
        "isolated READY entity count",
    )
    if (
        receipt.shardId != shardId || receipt.scopeSha256 != authenticated.sha256 ||
        receipt.inputSha256 != parentInputs.shard.inputSha256 ||
        receipt.units != parentInputs.shard.units.size.toLong() ||
        receipt.inventoryArtifactSha256 != guards.inventorySha256 ||
        receipt.richArtifactSha256 != guards.richSha256 ||
        receipt.outputBytes !in 1L..resources.maximumOutputBytes ||
        receipt.databaseHighWaterBytes !in 1L..resources.maximumDatabaseBytes ||
        receipt.peakResidentBytes !in 1L..resources.maximumResidentBytes ||
        receipt.entities > resources.maximumEntities ||
        receipt.units <= 0L || receipt.entities < 0L || receipt.scannedDies < 0L ||
        receipt.subprograms < 0L || receipt.entities != projectedEntities ||
        receipt.nonEmittedDies < receipt.nonEmitted || receipt.scannedDies < receipt.subprograms ||
        !receipt.outputSha256.matches(SHA256)
    ) isolationFail("isolated worker READY receipt violates its authenticated bindings or bounds")
}

private fun writeProtocolFile(root: LinuxDescriptor, name: String, content: String) {
    val bytes = content.toByteArray(Charsets.UTF_8)
    if (bytes.isEmpty() || bytes.size > MAXIMUM_PROTOCOL_BYTES || !content.endsWith('\n')) {
        isolationFail("isolated worker protocol record is not bounded canonical text")
    }
    val stageName = ".protocol-${randomHex(PROTOCOL_STAGE_RANDOM_BYTES)}.tmp"
    val stage = root.whileOpen { fd ->
        LinuxFilesystemSyscalls.createRegularFile(fd, stageName, OWNER_READ_WRITE_MODE)
    }
    var linked = true
    try {
        FileChannel.open(
            LinuxFilesystemSyscalls.stableDescriptorPath(stage.fd),
            StandardOpenOption.WRITE,
            StandardOpenOption.TRUNCATE_EXISTING,
        ).use { channel ->
            var buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
        LinuxFilesystemSyscalls.chmod(stage, OWNER_READ_ONLY_MODE)
        LinuxFilesystemSyscalls.synchronize(stage)
        root.whileOpen { fd -> LinuxFilesystemSyscalls.renameNoReplace(fd, stageName, name) }
        linked = false
        LinuxFilesystemSyscalls.synchronize(root)
        root.whileOpen { fd ->
            LinuxFilesystemSyscalls.openRegularFileAtOrNull(fd, name).use { selected ->
                if (selected == null || !sameRegularFile(selected.identity, stage.identity)) {
                    isolationFail("isolated protocol publication selected a different inode")
                }
            }
        }
    } finally {
        if (linked) root.whileOpen { fd -> LinuxFilesystemSyscalls.unlinkIfPresent(fd, stageName) }
        stage.close()
    }
}

private fun protocolFileOrNull(rootPath: Path, name: String): String? =
    LinuxFilesystemSyscalls.openRoot(rootPath).use { root -> protocolFileOrNull(root, name) }

private fun protocolFileOrNull(root: LinuxDescriptor, name: String): String? = root.whileOpen { fd ->
    val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(fd, name) ?: return@whileOpen null
    selected.use { descriptor ->
        val identity = descriptor.identity
        if (
            !identity.isRegularFile || identity.isSymbolicLink || identity.linkCount != 1 ||
            identity.mode.permissions != OWNER_READ_ONLY_MODE
        ) isolationFail("isolated protocol file $name has unsafe identity or mode")
        val size = Files.size(LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd))
        if (size !in 1L..MAXIMUM_PROTOCOL_BYTES.toLong()) {
            isolationFail("isolated protocol file $name exceeds its byte bound")
        }
        val bytes = LinuxFilesystemSyscalls.openReadableFrom(descriptor).use { readable ->
            LinuxFilesystemSyscalls.read(readable, MAXIMUM_PROTOCOL_BYTES, {})
        }
        if (bytes.size.toLong() != size) isolationFail("isolated protocol file $name changed while read")
        val after = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!sameRegularFile(identity, after)) isolationFail("isolated protocol file $name changed identity")
        val text = bytes.toString(Charsets.UTF_8)
        if (!text.endsWith('\n') || text.dropLast(1).contains('\n') || text.contains('\r')) {
            isolationFail("isolated protocol file $name is not one canonical line")
        }
        text
    }
}

private fun awaitWorkerProtocol(
    root: LinuxDescriptor,
    name: String,
    expected: String,
    timeout: Duration,
) {
    val deadline = deadlineAfter(timeout, "isolated worker protocol wait")
    while (System.nanoTime() < deadline) {
        protocolFileOrNull(root, name)?.let { actual ->
            if (actual != expected) isolationFail("isolated worker protocol $name is invalid")
            return
        }
        Thread.sleep(PROTOCOL_POLL_MILLIS)
    }
    isolationFail("isolated worker protocol $name timed out")
}

private fun protocol(kind: String, nonce: String): String =
    "$kind\t$WORKER_PROTOCOL_VERSION\t$nonce\n"

private fun keeperProtocol(nonce: String, namespacePid: Long): String {
    if (namespacePid !in 1L..Int.MAX_VALUE) isolationFail("isolated keeper PID is invalid")
    return "WORKER_EXITED\t$WORKER_PROTOCOL_VERSION\t$nonce\t$namespacePid\n"
}

private fun decodeKeeperProtocol(nonce: String, value: String): Long {
    val fields = value.removeSuffix("\n").split('\t')
    if (
        fields.size != KEEPER_FIELD_COUNT || fields[0] != "WORKER_EXITED" ||
        fields[1] != WORKER_PROTOCOL_VERSION || fields[2] != nonce
    ) isolationFail("isolated worker-exit record has an unsupported shape")
    return fields[3].toLongOrNull()?.takeIf { it in 1L..Int.MAX_VALUE }
        ?: isolationFail("isolated worker-exit record has an invalid keeper PID")
}

private fun encodeReady(
    nonce: String,
    receipt: FullTreeFunctionObservationPublishedShard,
): String = listOf(
    "READY",
    WORKER_PROTOCOL_VERSION,
    nonce,
    receipt.shardId,
    receipt.inputSha256,
    receipt.inventoryArtifactSha256,
    receipt.richArtifactSha256,
    receipt.scopeSha256,
    receipt.outputSha256,
    receipt.outputBytes.toString(),
    receipt.units.toString(),
    receipt.emittedRvas.toString(),
    receipt.nonEmitted.toString(),
    receipt.nonEmittedDies.toString(),
    receipt.entities.toString(),
    receipt.scannedDies.toString(),
    receipt.subprograms.toString(),
    receipt.databaseHighWaterBytes.toString(),
    receipt.peakResidentBytes.toString(),
).joinToString("\t", postfix = "\n")

private fun decodeReady(
    nonce: String,
    value: String,
): FullTreeFunctionObservationPublishedShard {
    val fields = value.removeSuffix("\n").split('\t')
    if (
        fields.size != READY_FIELD_COUNT || fields[0] != "READY" ||
        fields[1] != WORKER_PROTOCOL_VERSION || fields[2] != nonce
    ) isolationFail("isolated worker READY record has an unsupported shape")
    val hashes = fields.slice(4..8)
    if (!fields[3].matches(SHARD_IDENTIFIER) || hashes.any { !it.matches(SHA256) }) {
        isolationFail("isolated worker READY record contains an invalid identity")
    }
    fun count(index: Int, label: String): Long = fields[index].toLongOrNull()
        ?.takeIf { it >= 0L }
        ?: isolationFail("isolated worker READY $label is invalid")
    return FullTreeFunctionObservationPublishedShard(
        shardId = fields[3],
        inputSha256 = fields[4],
        inventoryArtifactSha256 = fields[5],
        richArtifactSha256 = fields[6],
        scopeSha256 = fields[7],
        outputSha256 = fields[8],
        outputBytes = count(9, "output bytes"),
        units = count(10, "unit count"),
        emittedRvas = count(11, "emitted count"),
        nonEmitted = count(12, "non-emitted count"),
        nonEmittedDies = count(13, "non-emitted DIE count"),
        entities = count(14, "entity count"),
        scannedDies = count(15, "scanned-DIE count"),
        subprograms = count(16, "subprogram count"),
        databaseHighWaterBytes = count(17, "database high-water bytes"),
        peakResidentBytes = count(18, "resident peak"),
    )
}

private fun encodeFailure(nonce: String, failure: Throwable): String {
    val message = failure.message.orEmpty()
        .replace(Regex("[\\r\\n\\t\\p{Cc}]"), " ")
        .take(MAXIMUM_FAILURE_MESSAGE_CHARS)
    return listOf(
        "FAIL",
        WORKER_PROTOCOL_VERSION,
        nonce,
        failure::class.java.name.take(MAXIMUM_FAILURE_CLASS_CHARS),
        message,
    ).joinToString("\t", postfix = "\n")
}

private fun readRequiredLong(path: Path, label: String): Long =
    readBoundedText(path, CGROUP_TEXT_BYTES).trim().toLongOrNull()
        ?.takeIf { it >= 0L }
        ?: isolationFail("$label is not a finite non-negative integer")

private fun readBoundedText(path: Path, maximumBytes: Int): String {
    if (maximumBytes <= 0) isolationFail("bounded text limit is empty")
    val bytes = try {
        Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
            input.readNBytes(maximumBytes + 1)
        }
    } catch (failure: Exception) {
        throw FullTreeFunctionObservationIsolationException("cannot read isolated accounting file $path", failure)
    }
    if (bytes.size > maximumBytes) isolationFail("isolated accounting file exceeds its byte bound")
    return bytes.toString(Charsets.UTF_8)
}

private fun parseFlatCounters(value: String, label: String): Map<String, Long> {
    val counters = linkedMapOf<String, Long>()
    value.lineSequence().filter(String::isNotBlank).forEach { line ->
        val fields = line.trim().split(Regex("\\s+"))
        if (
            fields.size != 2 || !fields[0].matches(COUNTER_NAME) ||
            fields[1].toLongOrNull()?.takeIf { it >= 0L } == null ||
            counters.put(fields[0], fields[1].toLong()) != null
        ) isolationFail("isolated $label is malformed")
    }
    if (counters.isEmpty()) isolationFail("isolated $label is empty")
    return counters
}

private fun digestChannel(channel: FileChannel, expectedBytes: Long): String {
    if (expectedBytes <= 0L || channel.size() != expectedBytes) {
        isolationFail("pinned isolated file has an invalid size")
    }
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteBuffer.allocate(COPY_BUFFER_BYTES)
    var offset = 0L
    while (offset < expectedBytes) {
        buffer.clear()
        buffer.limit(minOf(buffer.capacity().toLong(), expectedBytes - offset).toInt())
        val read = channel.read(buffer, offset)
        if (read <= 0) isolationFail("pinned isolated file ended while hashing")
        digest.update(buffer.array(), 0, read)
        offset = addExact(offset, read.toLong(), "pinned isolated file byte count")
    }
    if (channel.read(ByteBuffer.allocate(1), expectedBytes) >= 0) {
        isolationFail("pinned isolated file grew while hashing")
    }
    return digest.digest().hex()
}

private fun digestDescriptor(descriptor: LinuxDescriptor, expectedBytes: Long): String =
    FileChannel.open(
        LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd),
        StandardOpenOption.READ,
    ).use { channel -> digestChannel(channel, expectedBytes) }

private fun requirePrivateDirectory(descriptor: LinuxDescriptor, label: String) {
    val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
    if (
        !identity.isDirectory || identity.isRegularFile || identity.isSymbolicLink ||
        identity.mode.permissions != OWNER_DIRECTORY_MODE || identity.linkCount < 1
    ) isolationFail("$label is not a private mode-0700 directory")
}

private fun sameRegularFile(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.isRegularFile && second.isRegularFile &&
        !first.isDirectory && !second.isDirectory &&
        !first.isSymbolicLink && !second.isSymbolicLink

private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.isDirectory && second.isDirectory &&
        !first.isRegularFile && !second.isRegularFile &&
        !first.isSymbolicLink && !second.isSymbolicLink

private data class TrustedCommandResult(val exitCode: Int, val output: String)

private fun runTrustedCommand(
    command: List<String>,
    environment: Map<String, String>,
    timeout: Duration,
    label: String,
): TrustedCommandResult {
    if (command.isEmpty() || command.size > MAXIMUM_COMMAND_ARGUMENTS ||
        command.sumOf { it.toByteArray(Charsets.UTF_8).size.toLong() } > MAXIMUM_COMMAND_BYTES
    ) isolationFail("$label command exceeds its argument bound")
    val process = ProcessBuilder(command).redirectErrorStream(true).also { builder ->
        builder.environment().clear()
        builder.environment().putAll(environment)
    }.start()
    val output = AtomicReference<ByteArray?>()
    val outputFailure = AtomicReference<Throwable?>()
    val reader = Thread({
        try {
            output.set(process.inputStream.use { it.readNBytes(MAXIMUM_TRUSTED_OUTPUT_BYTES + 1) })
        } catch (failure: Throwable) {
            outputFailure.set(failure)
        }
    }, "isolated-trusted-command-output").also { it.isDaemon = true; it.start() }
    val deadline = deadlineAfter(timeout, label)
    try {
        while (process.isAlive && System.nanoTime() < deadline) {
            process.waitFor(TRUSTED_PROCESS_POLL_MILLIS, TimeUnit.MILLISECONDS)
        }
        if (process.isAlive) isolationFail("$label timed out")
        reader.join(PROBE_READER_JOIN_TIMEOUT.toMillis())
        if (reader.isAlive) isolationFail("$label output reader did not terminate")
        outputFailure.get()?.let { throw it }
        val bytes = output.get() ?: isolationFail("$label produced no bounded output result")
        if (bytes.size > MAXIMUM_TRUSTED_OUTPUT_BYTES) isolationFail("$label output exceeds its byte bound")
        return TrustedCommandResult(process.exitValue(), bytes.toString(Charsets.UTF_8))
    } catch (failure: Throwable) {
        process.destroyForcibly()
        runCatching { process.waitFor(PROBE_READER_JOIN_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS) }
        throw failure
    }
}

private fun validatedClassPath(entries: List<Path>): String {
    if (entries.isEmpty() || entries.size > MAXIMUM_CLASSPATH_ENTRIES) {
        isolationFail("isolated worker class path has an invalid entry count")
    }
    entries.forEach { path ->
        if (!path.isAbsolute || path.normalize() != path ||
            (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        ) isolationFail("isolated worker class path contains an unavailable entry")
    }
    val encoded = entries.joinToString(java.io.File.pathSeparator, transform = Path::toString)
    if (encoded.toByteArray(Charsets.UTF_8).size > MAXIMUM_CLASSPATH_BYTES) {
        isolationFail("isolated worker class path exceeds its byte bound")
    }
    return encoded
}

private fun syntheticDestinationParents(destinations: Collection<Path>): List<Path> {
    val parents = LinkedHashSet<Path>()
    destinations.forEach { destination ->
        if (!destination.isAbsolute || destination.normalize() != destination || destination == Path.of("/")) {
            isolationFail("isolated synthetic-root destination is invalid: $destination")
        }
        var current = destination.parent
        while (current != null && current != Path.of("/")) {
            parents.add(current)
            if (parents.size > MAXIMUM_SYNTHETIC_DIRECTORIES) {
                isolationFail("isolated synthetic root exceeds its directory bound")
            }
            current = current.parent
        }
    }
    return parents.sortedWith(compareBy<Path>({ it.nameCount }, { it.toString() }))
}

/** Bounded global exact-name cgroup observation for cold absence and attachment-failure cleanup. */
internal fun findObservationCgroupsForUnit(unitName: String): List<Path> {
    if (
        !unitName.matches(PRODUCTION_OBSERVATION_UNIT_NAME) &&
        !unitName.matches(FIXTURE_OBSERVATION_UNIT_NAME) &&
        !unitName.matches(PRODUCTION_KOTLIN_BOOT_UNIT_NAME)
    ) {
        isolationFail("isolated scope name is unsafe for cgroup absence verification")
    }
    return LinuxFilesystemSyscalls.openRoot(CGROUP_ROOT).use { pinnedRoot ->
        val rootBefore = LinuxFilesystemSyscalls.identity(pinnedRoot.fd)
        if (!sameDirectory(rootBefore, pinnedRoot.identity)) {
            isolationFail("cgroup v2 root changed before exact-name search")
        }
        requireAuthenticatedCgroupV2Mount(rootBefore)
        val controllers = LinuxFilesystemSyscalls.openRegularFileAtOrNull(
            pinnedRoot.fd,
            "cgroup.controllers",
        ) ?: isolationFail("exact-name cgroup search requires a cgroup v2 root")
        controllers.use { marker ->
            val identity = LinuxFilesystemSyscalls.identity(marker.fd)
            if (!identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink) {
                isolationFail("cgroup v2 controller marker is not a regular file")
            }
        }
        val matches = mutableListOf<Path>()
        val pending = ArrayDeque<Pair<Path, Int>>()
        pending += CGROUP_ROOT to 0
        var entries = 0
        while (pending.isNotEmpty()) {
            val (directory, depth) = pending.removeFirst()
            Files.newDirectoryStream(directory).use { children ->
                children.forEach { child ->
                    entries = Math.addExact(entries, 1)
                    if (entries > MAXIMUM_CGROUP_SEARCH_ENTRIES) {
                        isolationFail("isolated cgroup cleanup search exceeds its entry bound")
                    }
                    val attributes = Files.readAttributes(
                        child,
                        java.nio.file.attribute.BasicFileAttributes::class.java,
                        LinkOption.NOFOLLOW_LINKS,
                    )
                    if (!attributes.isDirectory || attributes.isSymbolicLink) return@forEach
                    val normalized = child.toAbsolutePath().normalize()
                    if (!normalized.startsWith(CGROUP_ROOT)) {
                        isolationFail("isolated cgroup cleanup search escaped cgroup v2")
                    }
                    if (normalized.fileName?.toString() == unitName) matches.add(normalized)
                    if (depth >= MAXIMUM_CGROUP_SEARCH_DEPTH) {
                        Files.newDirectoryStream(normalized).use { descendants ->
                            descendants.forEach { descendant ->
                                entries = Math.addExact(entries, 1)
                                if (entries > MAXIMUM_CGROUP_SEARCH_ENTRIES) {
                                    isolationFail("isolated cgroup cleanup search exceeds its entry bound")
                                }
                                val descendantAttributes = Files.readAttributes(
                                    descendant,
                                    java.nio.file.attribute.BasicFileAttributes::class.java,
                                    LinkOption.NOFOLLOW_LINKS,
                                )
                                if (descendantAttributes.isDirectory && !descendantAttributes.isSymbolicLink) {
                                    isolationFail("isolated cgroup cleanup search exceeds its depth bound")
                                }
                            }
                        }
                    } else {
                        pending += normalized to depth + 1
                    }
                }
            }
        }
        val rootAfter = LinuxFilesystemSyscalls.identity(pinnedRoot.fd)
        if (!sameDirectory(rootBefore, rootAfter)) {
            isolationFail("cgroup v2 root changed during exact-name search")
        }
        requireAuthenticatedCgroupV2Mount(rootAfter)
        LinuxFilesystemSyscalls.openRoot(CGROUP_ROOT).use { selected ->
            if (!sameDirectory(rootAfter, selected.identity)) {
                isolationFail("cgroup v2 root name changed after exact-name search")
            }
        }
        matches
    }
}

private fun requireAuthenticatedCgroupV2Mount(identity: LinuxFileIdentity) {
    val mounts = try {
        parseFullTreeDiskMountTable(readBoundedText(Path.of("/proc/self/mountinfo"), PROC_MOUNTINFO_BYTES))
    } catch (failure: Throwable) {
        throw FullTreeFunctionObservationIsolationException(
            "cannot authenticate the cgroup v2 mount table",
            failure,
        )
    }
    val selected = mounts.singleOrNull { it.mountId == identity.mountId }
        ?: isolationFail("cgroup v2 mount identity is absent or ambiguous")
    if (
        selected.root != Path.of("/") ||
        selected.mountPoint != CGROUP_ROOT ||
        selected.fileSystemType != "cgroup2" ||
        Files.getFileStore(CGROUP_ROOT).type() != "cgroup2"
    ) isolationFail("exact-name cgroup search requires the global cgroup v2 mount")
    if (mounts.any { it.mountId != selected.mountId && it.mountPoint.startsWith(CGROUP_ROOT) }) {
        isolationFail("exact-name cgroup search rejects nested mounts")
    }
}

private fun parseSystemdMicros(raw: String?): Long? {
    val value = raw?.trim().orEmpty()
    if (value.isEmpty()) return null
    var total = 0L
    value.split(Regex("[ \\t]+")).forEach { component ->
        val match = Regex("([0-9]+)(us|ms|s|min|h)").matchEntire(component) ?: return null
        val amount = match.groupValues[1].toLongOrNull() ?: return null
        val factor = when (match.groupValues[2]) {
            "us" -> 1L
            "ms" -> 1_000L
            "s" -> 1_000_000L
            "min" -> 60_000_000L
            "h" -> 3_600_000_000L
            else -> return null
        }
        total = runCatching { Math.addExact(total, Math.multiplyExact(amount, factor)) }.getOrNull()
            ?: return null
    }
    return total
}

private fun deadlineAfter(timeout: Duration, label: String): Long =
    addNanos(System.nanoTime(), timeout.toNanos(), "$label deadline")

private fun monotonicElapsed(start: Long, end: Long, label: String): Long {
    if (end < start) isolationFail("$label clock moved backwards")
    return try {
        Math.subtractExact(end, start)
    } catch (failure: ArithmeticException) {
        throw FullTreeFunctionObservationIsolationException("$label elapsed time overflows", failure)
    }
}

private fun secondsToNanos(seconds: Long, label: String): Long =
    multiplyExact(seconds, 1_000_000_000L, "$label nanosecond bound")

private fun addNanos(start: Long, amount: Long, label: String): Long =
    addExact(start, amount, label)

private fun addExact(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeFunctionObservationIsolationException("$label overflows", failure)
}

internal fun isolatedObservationCleanupBytes(
    maximumOutputBytes: Long,
    maximumDatabaseBytes: Long,
    maximumDwarfScratchBytes: Long,
    protocolAllowanceBytes: Long,
): Long {
    if (
        maximumOutputBytes < 0L || maximumDatabaseBytes < 0L ||
        maximumDwarfScratchBytes < 0L || protocolAllowanceBytes < 0L
    ) isolationFail("private cleanup byte bound contains a negative component")
    return addExact(
        addExact(
            addExact(maximumOutputBytes, maximumDatabaseBytes, "private cleanup byte bound"),
            maximumDwarfScratchBytes,
            "private cleanup byte bound",
        ),
        protocolAllowanceBytes,
        "private cleanup byte bound",
    )
}

private fun multiplyExact(left: Long, right: Long, label: String): Long = try {
    Math.multiplyExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeFunctionObservationIsolationException("$label overflows", failure)
}

private fun randomHex(bytes: Int): String = ByteArray(bytes).also(SECURE_RANDOM::nextBytes).hex()

private inline fun <T> translateIsolationFailures(
    label: String = "publication",
    action: () -> T,
): T = try {
    action()
} catch (failure: KotlinSystemdCgroupBootLaunchException) {
    throw failure
} catch (failure: FullTreeFunctionObservationIsolationException) {
    throw failure
} catch (failure: Throwable) {
    throw FullTreeFunctionObservationIsolationException(
        "isolated function-observation $label failed: ${failure.message}",
        failure,
    )
}

private fun isolationFail(message: String): Nothing =
    throw FullTreeFunctionObservationIsolationException(message)

private const val ISOLATION_CONFIGURATION_SCHEMA_VERSION = 3
private const val ISOLATION_CONFIGURATION_PROVIDER =
    "kotlin-full-tree-function-observation-isolation-configuration-v3"
private const val WORKER_PROTOCOL_VERSION = "1"
private const val WORKER_ARGUMENTS = 9
private const val SUPERVISOR_PROTOCOL_VERSION = "2"
private const val SUPERVISOR_ARGUMENTS = WORKER_ARGUMENTS + 4
private const val KOTLIN_BOOT_PROTOCOL_VERSION = "1"
private const val KOTLIN_BOOT_ARGUMENTS = 3
private const val KOTLIN_BOOT_RUNTIME_PROVIDER = "kotlin-systemd-cgroup-boot-runtime-v2"
private const val READY_FIELD_COUNT = 19
private const val KEEPER_FIELD_COUNT = 4
private const val WORKER_FAILURE_EXIT = 73
private const val SUPERVISOR_FAILURE_EXIT = 74
private const val KOTLIN_BOOT_FAILURE_EXIT = 75
private const val LOCAL_SIGKILL_EXIT = 137
private const val BOOT_FILE = "worker.boot"
private const val START_FILE = "parent.start"
private const val READY_FILE = "worker.ready"
private const val ACK_FILE = "parent.ack"
private const val DONE_FILE = "worker.done"
private const val WORKER_RELEASE_FILE = "parent.worker-release"
private const val WORKER_EXITED_FILE = "supervisor.worker-exited"
private const val FAILURE_FILE = "worker.failure"
private const val SUPERVISOR_FAILURE_FILE = "supervisor.failure"
private const val CANDIDATE_FILE = "candidate.json"
private const val SCRATCH_DIRECTORY = "scratch"
private const val TEMP_DIRECTORY = "tmp"
private const val RUNTIME_DIRECTORY = "runtime"
private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val OWNER_READ_WRITE_MODE = 0x180 // 0600
private const val OWNER_READ_ONLY_MODE = 0x100 // 0400
private const val UNTRUSTED_RUNTIME_WRITE_MODE = 0x12 // 0022
private const val PROTOCOL_NONCE_BYTES = 32
private const val PROTOCOL_STAGE_RANDOM_BYTES = 12
private const val RUN_RANDOM_BYTES = 16
private const val STAGE_RANDOM_BYTES = 16
private const val MAXIMUM_RUN_NAME_ATTEMPTS = 32
private const val MAXIMUM_PROTOCOL_BYTES = 16 * 1024
private const val MAXIMUM_FAILURE_MESSAGE_CHARS = 1024
private const val MAXIMUM_FAILURE_CLASS_CHARS = 256
private const val COPY_BUFFER_BYTES = 1024 * 1024
private const val MAXIMUM_PRIVATE_ENTRIES = 100_000
private const val MAXIMUM_PRIVATE_DEPTH = 64
private const val PREPARED_ROOT_LINK_COUNT = 5
private const val PREPARED_CHILD_LINK_COUNT = 2
private const val PROTOCOL_CLEANUP_ALLOWANCE_BYTES = 64L * 1024L * 1024L
private const val SQLITE_EXPANSION = 4L
private const val MINIMUM_WORKER_MEMORY_BYTES = 256L * 1024L * 1024L
private const val MINIMUM_WORKER_ADDRESS_SPACE_BYTES = 8L * 1024L * 1024L * 1024L
private const val MAXIMUM_WORKER_ADDRESS_SPACE_BYTES = 64L * 1024L * 1024L * 1024L
private const val ADDRESS_SPACE_FACTOR = 4L
private const val CGROUP_TASKS_MAX = 256
private const val RLIMIT_NPROC = 4096
private const val RLIMIT_NOFILE = 512
private const val MAXIMUM_CLASSPATH_ENTRIES = 512
private const val MAXIMUM_CLASSPATH_BYTES = 1024 * 1024
private const val MAXIMUM_CLASSPATH_ENTRY_BYTES = 1024L * 1024L * 1024L
private const val MAXIMUM_AUTHENTICATED_CLASSPATH_BYTES = 2L * 1024L * 1024L * 1024L
private const val MAXIMUM_RUNTIME_MOUNTS = 16
private const val MAXIMUM_RUNTIME_TREE_ENTRIES = 100_000
private const val MAXIMUM_RUNTIME_TREE_DEPTH = 64
private const val MAXIMUM_SYNTHETIC_DIRECTORIES = 1024
private const val MAXIMUM_COMMAND_ARGUMENTS = 2048
private const val MAXIMUM_COMMAND_BYTES = 2L * 1024L * 1024L
private const val MAXIMUM_TRUSTED_OUTPUT_BYTES = 64 * 1024
private const val MAXIMUM_PROC_CGROUP_BYTES = 1024 * 1024
private const val MAXIMUM_PROC_STATUS_BYTES = 1024 * 1024
private const val MAXIMUM_PROC_STAT_BYTES = 64 * 1024
private const val MAXIMUM_PROC_ENVIRONMENT_BYTES = 1024 * 1024
private const val MAXIMUM_KERNEL_BOOT_ID_BYTES = 64
private const val PROC_MOUNTINFO_BYTES = 8 * 1024 * 1024
private const val CGROUP_TEXT_BYTES = 64 * 1024
private const val CGROUP_PROCS_BYTES = 1024 * 1024
private const val BOOT_PROCESS_COUNT = 4
private const val KOTLIN_BOOT_PROCESS_COUNT = 3
private const val PROC_STAT_START_TIME_SUFFIX_FIELD_COUNT = 20
private const val KEEPER_PROCESS_COUNT = 3
private const val MAXIMUM_PROC_DESCRIPTOR_TARGET_CHARS = 8192
private const val MAXIMUM_CGROUP_SEARCH_ENTRIES = 100_000
private const val MAXIMUM_CGROUP_SEARCH_DEPTH = 32
private val ISOLATION_CONFIGURATION_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 2 * 1024 * 1024,
    maximumCanonicalBytes = 2 * 1024 * 1024,
    maximumDepth = 6,
    maximumNodes = 4096,
    maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = 1024 * 1024,
    maximumNumberCharacters = 32,
)
private val COLD_SYSTEMD_BUSCTL_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 4096,
    maximumCanonicalBytes = 4096,
    maximumDepth = 4,
    maximumNodes = 64,
    maximumStringBytes = 1024,
    maximumTotalStringBytes = 2048,
    maximumNumberCharacters = 3,
)
private const val PROTOCOL_POLL_MILLIS = 20L
private const val SYSTEMD_POLL_MILLIS = 20L
private const val TRUSTED_PROCESS_POLL_MILLIS = 20L
private const val WORKER_FAILURE_OBSERVATION_MILLIS = 1_000L
private val WORKER_START_TIMEOUT = Duration.ofSeconds(30)
private val WORKER_ACK_TIMEOUT = Duration.ofMinutes(5)
private val WORKER_EXIT_TIMEOUT = Duration.ofSeconds(10)
private val CGROUP_FREEZE_TIMEOUT = Duration.ofSeconds(5)
private val SERVICE_CLEANUP_TIMEOUT = Duration.ofSeconds(5)
private val SYSTEMD_LAUNCH_TIMEOUT = Duration.ofSeconds(10)
private val SYSTEMD_CONTROL_TIMEOUT = Duration.ofSeconds(3)
private val PROBE_TIMEOUT = Duration.ofSeconds(3)
private val PROBE_READER_JOIN_TIMEOUT = Duration.ofSeconds(1)
private val STATUS_POLL_INTERVAL = Duration.ofSeconds(2)
private val ISOLATED_PUBLISHER_LIMITS = FullTreeFunctionObservationShardPublisherLimits()
private val DEFAULT_CONTROL_LIMITS = ISOLATED_PUBLISHER_LIMITS.control
private val WORKER_FAILURE_CLEANUP_LIMITS = AcpRuntimeClosureLimits(
    maximumEntries = MAXIMUM_PRIVATE_ENTRIES,
    maximumUserOwnedFileBytes = isolatedObservationCleanupBytes(
        ISOLATED_PUBLISHER_LIMITS.maximumOutputBytes,
        ISOLATED_PUBLISHER_LIMITS.maximumDatabaseBytes,
        DEFAULT_CONTROL_LIMITS.maximumDwarfScratchBytes,
        addExact(
            PROTOCOL_CLEANUP_ALLOWANCE_BYTES,
            MAXIMUM_AUTHENTICATED_CLASSPATH_BYTES,
            "worker-failure cleanup runtime allowance",
        ),
    ),
    maximumDepth = MAXIMUM_PRIVATE_DEPTH,
)
private val CGROUP_ROOT = Path.of("/sys/fs/cgroup")
private val KERNEL_BOOT_ID_PATH = Path.of("/proc/sys/kernel/random/boot_id")
private val SECURE_RANDOM = SecureRandom()
private val SHA256 = Regex("[0-9a-f]{64}")
private val SYSTEMD_ID128 = Regex("[0-9a-f]{32}")
private val KERNEL_BOOT_UUID =
    Regex("[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
private val RESERVED_SYSTEMD_ID128S = setOf("0".repeat(32), "f".repeat(32))
private val PROC_STAT_INTEGER = Regex("-?[0-9]+")
private val SYSTEMD_BUILD_FEATURE = Regex("[+-][A-Z0-9_]+")
private val COLD_SYSTEMD_MANAGER_VERSION = Regex("([0-9]{3})(?:[.+~:_-][0-9A-Za-z.+~:_-]+)?")
private val COLD_SYSTEMD_DEFAULT_HIERARCHY = Regex("default-hierarchy=(?:legacy|hybrid|unified)")
private val COLD_SYSTEMD_REQUIRED_MAC_FEATURES = setOf("SELINUX", "APPARMOR", "SMACK")
private const val SYSTEMD_BUS_SERVICE = "org.freedesktop.systemd1"
private const val SYSTEMD_MANAGER_OBJECT_PATH = "/org/freedesktop/systemd1"
private const val SYSTEMD_MANAGER_INTERFACE = "org.freedesktop.systemd1.Manager"
private const val SYSTEMD_UNIT_INTERFACE = "org.freedesktop.systemd1.Unit"
private const val SYSTEMD_SCOPE_INTERFACE = "org.freedesktop.systemd1.Scope"
private const val SYSTEMD_UNIT_OBJECT_PATH_PREFIX = "/org/freedesktop/systemd1/unit/"
private val SYSTEMD_UNIT_OBJECT_PATH = Regex("/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+")
private val PROTOCOL_NONCE = Regex("[0-9a-f]{64}")
private val SHARD_IDENTIFIER = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
private val PRODUCTION_OBSERVATION_UNIT_NAME =
    Regex("decomp-oracle-function-[0-9a-f]{64}\\.scope")
private val PRODUCTION_KOTLIN_BOOT_UNIT_NAME =
    Regex("[a-z][a-z0-9-]{0,95}-[0-9a-f]{32}\\.scope")
private val FIXTURE_OBSERVATION_UNIT_NAME =
    Regex("decomp-oracle-function-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.scope")
private val COUNTER_NAME = Regex("[a-z][a-z0-9_.]*")
private val KOTLIN_BOOT_PROCESS_ROLES =
    listOf("scope-leader", "namespace-init", "kotlin-boot-keeper")
private val KOTLIN_BOOT_PROCESS_PARENTS = mapOf(
    "scope-leader" to null,
    "namespace-init" to "scope-leader",
    "kotlin-boot-keeper" to "namespace-init",
)
private const val KOTLIN_BOOT_MINIMUM_MEMORY_BYTES = 256L * 1024L * 1024L
private const val KOTLIN_BOOT_MAXIMUM_MEMORY_BYTES = 64L * 1024L * 1024L * 1024L
private const val KOTLIN_BOOT_MAXIMUM_WALL_MILLIS = 24L * 60L * 60L * 1_000L
private const val KOTLIN_BOOT_MINIMUM_PIDS = 4L
private const val KOTLIN_BOOT_MAXIMUM_PIDS = 4_096L
private const val KOTLIN_BOOT_TIMEOUT_STOP_MILLIS = 30_000L
private const val KOTLIN_BOOT_MAXIMUM_PRIVATE_ENTRIES = 1_024
private const val KOTLIN_BOOT_MAXIMUM_PRIVATE_BYTES = 256L * 1024L * 1024L
private const val KOTLIN_BOOT_MAXIMUM_PRIVATE_DEPTH = 16
private val MEMORY_BACKED_FILE_SYSTEMS = setOf("tmpfs", "ramfs", "hugetlbfs")
private val BUBBLEWRAP_VERSION = Regex("bubblewrap [0-9]+(?:\\.[0-9]+){1,2}")
private val SYSTEMD_MANAGER_VERSION = Regex("[0-9][0-9A-Za-z.+~:_-]*")
private val REQUIRED_BWRAP_OPTIONS = listOf(
    "--unshare-all",
    "--unshare-user",
    "--new-session",
    "--die-with-parent",
    "--clearenv",
    "--disable-userns",
    "--assert-userns-disabled",
    "--proc",
    "--dev",
    "--tmpfs",
    "--dir",
    "--cap-drop",
    "--hostname",
    "--ro-bind",
    "--bind",
    "--chdir",
)
private val REQUIRED_SYSTEMD_RUN_OPTIONS = listOf(
    "--user",
    "--scope",
    "--collect",
    "--property",
    "--unit",
    "--expand-environment",
)
private val COLD_SYSTEMD_MANAGER_VERSION_ARGUMENTS = listOf(
    "--no-pager",
    "--property=Version",
    "--value",
    "show",
)
private val COLD_SYSTEMD_MANAGER_FEATURES_ARGUMENTS = listOf(
    "--no-pager",
    "--property=Features",
    "--value",
    "show",
)
private val COLD_SYSTEMD_LIST_UNITS_ARGUMENTS = listOf(
    "--no-pager",
    "--no-legend",
    "--plain",
    "--full",
    "--all",
    "list-units",
)
private val COLD_SYSTEMD_LIST_JOBS_ARGUMENTS = listOf(
    "--no-pager",
    "--no-legend",
    "--plain",
    "--full",
    "--all",
    "list-jobs",
)
private val COLD_SYSTEMD_BUSCTL_OPTIONS = listOf(
    "--user",
    "--no-pager",
    "--json=short",
    "--auto-start=no",
    "--allow-interactive-authorization=no",
    "--timeout=2",
)
private val COLD_SYSTEMD_BUSCTL_MANAGER_CALL = listOf(
    "call",
    SYSTEMD_BUS_SERVICE,
    SYSTEMD_MANAGER_OBJECT_PATH,
    SYSTEMD_MANAGER_INTERFACE,
)
private val REQUIRED_SYSTEMCTL_COMMANDS = listOf("freeze", "thaw", "kill")
private val OBSERVATION_SYSTEMD_CLEANUP_EXIT_CODES = setOf(0, 1, 4, 5)
private val SYSTEMD_PROPERTIES = setOf(
    "Id",
    "InvocationID",
    "Transient",
    "LoadState",
    "ActiveState",
    "SubState",
    "CollectMode",
    "ControlGroup",
    "TasksMax",
    "MemoryMax",
    "MemorySwapMax",
    "OOMPolicy",
    "CPUQuotaPerSecUSec",
    "KillMode",
    "SendSIGKILL",
    "RuntimeMaxUSec",
    "TimeoutStopUSec",
    "Delegate",
)
