package decompengine.oracle.fulltree

import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class FullTreeFunctionObservationIsolationException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

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
    val systemdUserRuntimeDirectory: Path,
    workerClassPath: List<FullTreeFunctionObservationClassPathEntry>,
    val expectedJavaSha256: String,
    val expectedBubblewrapSha256: String,
    val expectedResourceLimiterSha256: String,
    val expectedScopeSupervisorSha256: String,
    val expectedScopeInspectorSha256: String,
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
                "javaExecutable" to JsonPrimitive(javaExecutable.toString()),
                "javaRuntime" to javaRuntime.canonicalIdentity(),
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
) : AutoCloseable {
    val classPathBytes: Long = classPath.fold(0L) { total, (_, guard) ->
        addExact(total, guard.size, "authenticated class-path byte count")
    }

    fun materializeClassPath(runTree: ObservationRunTreeAccess): MaterializedObservationClassPath =
        runTree.withPinnedDescriptor { descriptor ->
            materializeObservationClassPath(runTree.path, descriptor, classPath)
        }

    fun mounts(): List<FullTreeFunctionObservationRuntimeMount> = runtimeMounts.map { it.first }

    fun verify(label: String) {
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
                opened.clear()
                return AuthenticatedObservationRuntime(verifiedMounts, classPath)
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
    fun authenticatePreparedLayout(runTree: ObservationRunTreeAccess) {
        check(preparedLayout == null) { "prepared class-path layout was already authenticated" }
        preparedLayout = runTree.withPinnedDescriptor { root ->
            authenticatePreparedObservationRunLayout(
                runTree.path,
                root,
                paths,
                expected,
                rootFiles = emptyList(),
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
    ) isolationFail("prepared function-observation root is not the exact private ext4 layout")
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
 * Production pre-launch composition for one durable LEASED operation.
 *
 * [prepareBeforeLaunch] authenticates the journal-bound inputs and runtime, transfers the linear
 * journal/disk authority before this layer's first run-tree mutation, initializes the deterministic
 * pinned run root, and snapshots the worker class path. [launchToBoot] may then pin the launch
 * boundary and create the deterministic live scope only through BOOT. Neither operation appends
 * UNIT_ATTACHED, publishes output, removes residue, or authorizes lease release.
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
    internal fun launchToBoot(): FullTreeFunctionObservationBootedIsolation {
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
            val openedBoundary = TrustedObservationBoundary(configuration, runtime, materializedClassPath)
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

private data class BootedObservationIsolationOwnership(
    val paths: IsolatedObservationPaths,
    val runDirectory: Path,
    val configuration: FullTreeFunctionObservationIsolationConfiguration,
    val authenticatedScope: AuthenticatedFullTreeScope,
    val authenticatedInputs: FullTreeFunctionObservationAuthenticatedInputs,
    val resources: IsolatedObservationResources,
    val runtime: AuthenticatedObservationRuntime,
    val inputGuards: ParentObservationInputGuards,
    val materializedClassPath: MaterializedObservationClassPath,
    val authority: FullTreeFunctionObservationPreparedIsolationAuthority,
    val boundary: TrustedObservationBoundary,
    val unit: ManagedObservationUnit,
)

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
        val binding = ownership.authority.leasedHistory.binding
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
        operationActive = true
        try {
            val binding = ownership.authority.leasedHistory.binding
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
            ownership.authority.requireCurrentAfterScopeAttachment()
            ownership.boundary.verifyLiveOperation()
            ownership.authority.withCurrentRunRootAfterScopeAttachment { borrowed ->
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
            ownership.authority.requireCurrentAfterScopeAttachment()
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
            ownership.authority.requireCurrentAfterCgroupAbsence()
            closed = true
            closePreparedIsolationResources(
                inputGuards = ownership.inputGuards,
                runtime = ownership.runtime,
                authority = ownership.authority,
                untransferred = null,
                priorFailure = null,
            )?.let { throw it }
        } finally {
            operationActive = false
        }
    }
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
                AcpRuntimeClosureLimits(
                    maximumEntries = MAXIMUM_PRIVATE_ENTRIES,
                    maximumUserOwnedFileBytes = cleanupBytes,
                    maximumDepth = MAXIMUM_PRIVATE_DEPTH,
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

private data class IsolatedSupervisorRequest(
    val javaExecutable: Path,
    val classPath: String,
    val worker: IsolatedWorkerRequest,
) {
    fun workerCommand(): List<String> = buildList {
        add(javaExecutable.toString())
        add("-XX:+UseSerialGC")
        add("-XX:ActiveProcessorCount=1")
        add("-XX:-UsePerfData")
        add("-XX:MaxRAMPercentage=50")
        add("-Djava.io.tmpdir=${worker.runDirectory.resolve(TEMP_DIRECTORY)}")
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
                worker = IsolatedWorkerRequest.parse(arguments.copyOfRange(3, arguments.size)),
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
    if (LinuxFilesystemSyscalls.directoryEntryNames(descriptor, 1).isNotEmpty()) {
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
) : AutoCloseable {
    val unitName: String
        get() = controller.unitName
    var process: Process? = null
    var processHandle: decompengine.acp.LinuxProcessDescriptor? = null
    var cleaned = false
        private set
    private var launchAttempted = false

    fun retainStartedProcess(started: Process) {
        check(!launchAttempted && process == null && processHandle == null) {
            "isolated process launch attempt is not linear"
        }
        launchAttempted = true
        process = started
    }

    override fun close() {
        if (cleaned) return
        if (launchAttempted) {
            controller.killStopAndRequireAbsent(
                process = process,
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

    private fun launchValidated(
        unitName: String,
        request: IsolatedWorkerRequest,
        resources: IsolatedObservationResources,
        immediatelyBeforeStart: () -> Unit,
    ): ManagedObservationUnit {
        check(active == null && pendingLaunch == null) {
            "one isolation boundary may launch only one worker"
        }
        retainUnitName(unitName)
        val controller = ObservationSystemdController(inspector, bus, unitName)
        val pending = PendingObservationLaunch(controller)
        pendingLaunch = pending
        try {
            requireUnchanged()
            authenticatedRuntime.verify("at isolated boundary launch")
            materializedClassPath.verify("at isolated boundary launch")
            controller.requireAbsent()
            val worker = buildWorkerCommand(request, resources)
            val scoped = buildScopeCommand(unitName, resources, worker)
            val command = buildResourceLimitedCommand(resources, scoped)
            requireUnchanged()
            authenticatedRuntime.verify("immediately before isolated process start")
            materializedClassPath.verify("immediately before isolated process start")
            immediatelyBeforeStart()
            authenticatedRuntime.verify("at final isolated process start gate")
            materializedClassPath.verify("at final isolated process start gate")
            controller.requireAbsent()
            requireUnchanged()
            val started = ProcessBuilder(command)
                .redirectInput(ProcessBuilder.Redirect.PIPE)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .also { builder ->
                    builder.environment().clear()
                    builder.environment().putAll(bus.controlEnvironment)
                }
                .start()
            pending.retainStartedProcess(started)
            val pinnedProcess = LinuxFilesystemSyscalls.openProcessHandle(started.pid())
            pending.processHandle = pinnedProcess
            if (!started.isAlive) isolationFail("isolated local scope process exited before pidfd pinning")
            started.outputStream.close()
            val managedUnit = ManagedObservationUnit(
                controller,
                request.runDirectory,
                request.nonce,
                bubblewrap,
                java,
                resources,
                started,
                pinnedProcess,
                configuration.systemdUserRuntimeDirectory,
            )
            active = managedUnit
            pending.processHandle = null
            pendingLaunch = null
            managedUnit.awaitScopeAttached()
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
            add("-Djava.io.tmpdir=${request.runDirectory.resolve(TEMP_DIRECTORY)}")
            add("-classpath")
            add(materializedClassPath.encoded)
            add(FullTreeFunctionObservationIsolatedSupervisor::class.java.name)
            add(SUPERVISOR_PROTOCOL_VERSION)
            add(sandboxJava.toString())
            add(materializedClassPath.encoded)
            addAll(request.arguments())
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
        add("--property=TasksMax=$CGROUP_TASKS_MAX")
        add("--property=MemoryMax=${resources.maximumResidentBytes}")
        add("--property=MemorySwapMax=0")
        add("--property=OOMPolicy=kill")
        add("--property=CPUQuota=100%")
        add("--property=KillMode=control-group")
        add("--property=SendSIGKILL=yes")
        add("--property=RuntimeMaxSec=${resources.serviceRuntimeSeconds}s")
        add("--property=TimeoutStopSec=${SERVICE_CLEANUP_TIMEOUT.seconds}s")
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
        val manager = ObservationSystemdController(inspector, bus, "decomp-oracle-probe.scope")
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
                ObservationSystemdController(inspector, bus, unitName),
            )
        }
        close()
    }

    override fun close() {
        val unit = active
        if (unit != null && !unit.cleaned) unit.close()
        pendingLaunch?.let { pending ->
            pending.close()
            pendingLaunch = null
        }
        retainedUnitName?.let { unitName ->
            val finalAbsence = PendingObservationLaunch(
                ObservationSystemdController(inspector, bus, unitName),
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

private class ObservationSystemdController(
    private val inspector: PinnedSecurityExecutable,
    private val bus: PinnedSystemdBusEndpoint,
    val unitName: String,
) {
    fun managerVersion(): String = systemctl(
        listOf("show", "--property=Version", "--value"),
    ).output.trim()

    fun requireAbsent() {
        if (show()["LoadState"] != "not-found" || findObservationCgroupsForUnit(unitName).isNotEmpty()) {
            isolationFail("isolated systemd unit or cgroup name is already in use")
        }
    }

    fun freeze() {
        val result = systemctl(listOf("freeze", unitName))
        if (result.output.isNotBlank()) isolationFail("isolated systemd freeze was not quiet")
    }

    fun killFrozenKeeper() {
        val result = systemctl(
            listOf("kill", "--kill-whom=all", "--signal=SIGKILL", unitName),
        )
        if (result.output.isNotBlank()) isolationFail("isolated frozen-keeper kill was not quiet")
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
        knownCgroup: Path? = null,
        process: Process? = null,
        processHandle: decompengine.acp.LinuxProcessDescriptor? = null,
    ) {
        val deadline = deadlineAfter(SERVICE_CLEANUP_TIMEOUT, "systemd cleanup")
        var last: Throwable? = null
        var exactCgroup = knownCgroup
        while (System.nanoTime() < deadline) {
            runCatching {
                if (processHandle != null) LinuxFilesystemSyscalls.killProcess(processHandle)
                else if (process?.isAlive == true) process.destroyForcibly()
            }.exceptionOrNull()?.let { last = it }
            val before = runCatching { show() }.getOrElse { failure ->
                last = failure
                emptyMap()
            }
            before["ControlGroup"]?.takeIf(String::isNotBlank)?.let { controlGroup ->
                runCatching { requireCgroupPathForUnit(controlGroup) }.onSuccess { discovered ->
                    if (exactCgroup != null && exactCgroup != discovered) {
                        isolationFail("isolated cleanup discovered a different cgroup")
                    }
                    exactCgroup = discovered
                }.exceptionOrNull()?.let { last = it }
            }
            if (before["LoadState"] != "not-found") {
                runObservationSystemdCleanupFallback(unitName) { arguments, allowedExitCodes ->
                    systemctl(arguments, allowedExitCodes)
                }
            }
            runCatching { process?.waitFor(SYSTEMD_POLL_MILLIS, TimeUnit.MILLISECONDS) }
            try {
                val absent = show()["LoadState"] == "not-found"
                val candidates = buildSet {
                    exactCgroup?.let(::add)
                    addAll(findObservationCgroupsForUnit(unitName))
                }
                val cgroupAbsent = candidates.none { Files.exists(it, LinkOption.NOFOLLOW_LINKS) }
                if (absent && cgroupAbsent && process?.isAlive != true) return
            } catch (failure: Throwable) {
                last = failure
            }
            Thread.sleep(SYSTEMD_POLL_MILLIS)
        }
        throw FullTreeFunctionObservationIsolationException(
            "isolated systemd unit or cgroup cleanup was not proven",
            last,
        )
    }

    private fun requireCgroupPathForUnit(controlGroup: String): Path {
        if (!controlGroup.startsWith('/') || controlGroup.contains('\u0000')) {
            isolationFail("systemd returned an invalid isolated cgroup path")
        }
        val path = CGROUP_ROOT.resolve(controlGroup.removePrefix("/")).normalize()
        if (!path.startsWith(CGROUP_ROOT) || path == CGROUP_ROOT || path.fileName?.toString() != unitName) {
            isolationFail("systemd returned an unsafe isolated cgroup path")
        }
        return path
    }

    private fun systemctl(
        arguments: List<String>,
        allowedExitCodes: Set<Int> = setOf(0),
    ): TrustedCommandResult {
        inspector.requireUnchanged()
        bus.requireUnchanged()
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
) {
    val allowed = setOf(0, 1, 4, 5)
    val kill = listOf("kill", "--kill-whom=all", "--signal=SIGKILL", unitName)
    // Some manager/kernel combinations require an explicit thaw before a frozen unit can finish
    // teardown. The second kill also covers a process that raced or survived the first attempt.
    listOf(
        kill,
        listOf("thaw", unitName),
        kill,
        listOf("stop", unitName),
        listOf("reset-failed", unitName),
    ).forEach { arguments -> runCatching { command(arguments, allowed) } }
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
)

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
    private val process: Process,
    private val processHandle: decompengine.acp.LinuxProcessDescriptor,
    private val systemdUserRuntimeDirectory: Path,
) : AutoCloseable {
    val unitName: String
        get() = controller.unitName
    private var cgroupPath: Path? = null
    private val mainPid: Long = process.pid()
    private var keeperPids: Set<Long>? = null
    private var bootProcessHandles: Map<Long, decompengine.acp.LinuxProcessDescriptor>? = null
    private var frozen = false
    var cleaned: Boolean = false
        private set

    fun awaitScopeAttached() {
        val deadline = deadlineAfter(SYSTEMD_LAUNCH_TIMEOUT, "isolated local scope attachment")
        var last: Throwable? = null
        while (System.nanoTime() < deadline) {
            if (!process.isAlive) isolationFail("isolated local scope process exited before attachment")
            try {
                val properties = controller.show()
                requireLiveProperties(properties, resources, allowActivating = true)
                val cgroup = requireCgroupPath(properties["ControlGroup"].orEmpty())
                requireLocalLeader(cgroup)
                requireActualControllers(cgroup, resources)
                cgroupPath = cgroup
                return
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
        val properties = controller.show()
        requireLiveProperties(properties, expected)
        val controlGroup = properties["ControlGroup"].orEmpty()
        val cgroup = requireCgroupPath(controlGroup)
        requireLocalLeader(cgroup)
        requireActualControllers(cgroup, expected)
        val processes = requireBootProcesses(cgroup)
        retainBootProcessHandles(cgroup, processes)
        if (requireBootProcesses(cgroup) != processes) {
            isolationFail("isolated BOOT process inventory changed after pidfd pinning")
        }
        requireRetainedBootProcessesLive(processes)
    }

    private fun requireBootProcesses(cgroup: Path): Set<Long> {
        val before = readCgroupProcesses(cgroup)
        if (before.size != BOOT_PROCESS_COUNT || mainPid !in before) {
            isolationFail("isolated BOOT cgroup does not contain exactly four processes and its leader")
        }
        val processIdentities = mutableMapOf<Long, ObservationProcessIdentity>()
        val bubblewrapProcesses = mutableListOf<Long>()
        val javaProcesses = mutableListOf<Long>()
        before.sorted().forEach { pid ->
            LinuxFilesystemSyscalls.openProcessExecutable(pid).use { executable ->
                val identity = executable.identity
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
            }
            processIdentities[pid] = readProcessIdentity(pid)
        }
        if (bubblewrapProcesses.size != 2 || javaProcesses.size != 2 || mainPid !in bubblewrapProcesses) {
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
        } ?: isolationFail("isolated BOOT cgroup lacks one supervisor JVM")
        val worker = javaProcesses.single { it != supervisor }
        val supervisorIdentity = processIdentities.getValue(supervisor)
        val workerIdentity = processIdentities.getValue(worker)
        val supervisorNamespacePid = supervisorIdentity.namespacePids.getOrNull(1)
        val workerNamespacePid = workerIdentity.namespacePids.getOrNull(1)
        if (
            supervisorIdentity.namespacePids.size != 2 || workerIdentity.namespacePids.size != 2 ||
            supervisorNamespacePid == null || workerNamespacePid == null ||
            supervisorNamespacePid <= 1L || workerNamespacePid <= 1L ||
            supervisorNamespacePid == workerNamespacePid || workerIdentity.parentPid != supervisor
        ) isolationFail("isolated BOOT JVMs have the wrong parent or PID-namespace chain")
        val after = readCgroupProcesses(cgroup)
        if (after != before) isolationFail("isolated BOOT process inventory changed while verified")
        return before
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
            pidsMax != CGROUP_TASKS_MAX.toLong() || memoryMax != expected.maximumResidentBytes ||
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
        controller.freeze()
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
        controller.killFrozenKeeper()
        val deadline = deadlineAfter(WORKER_EXIT_TIMEOUT, "isolated frozen-keeper cgroup drain")
        while (System.nanoTime() < deadline) {
            process.waitFor(SYSTEMD_POLL_MILLIS, TimeUnit.MILLISECONDS)
            val absent = controller.show()["LoadState"] == "not-found"
            if (!process.isAlive && absent && !Files.exists(cgroup, LinkOption.NOFOLLOW_LINKS)) break
            Thread.sleep(SYSTEMD_POLL_MILLIS)
        }
        if (
            process.isAlive || process.exitValue() != LOCAL_SIGKILL_EXIT ||
            controller.show()["LoadState"] != "not-found" ||
            Files.exists(cgroup, LinkOption.NOFOLLOW_LINKS)
        ) isolationFail("isolated frozen keeper did not reach exact local SIGKILL and scope absence")
        if (LinuxFilesystemSyscalls.killProcess(processHandle)) {
            isolationFail("isolated pidfd remained live after local SIGKILL exit")
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
        if (!process.isAlive) isolationFail("isolated pidfd-pinned scope leader exited unexpectedly")
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
        return ObservationProcessIdentity(parentPid, namespacePids)
    }

    private fun readMemoryEvents(cgroup: Path): Map<String, Long> = parseFlatCounters(
        readBoundedText(cgroup.resolve("memory.events"), CGROUP_TEXT_BYTES),
        "memory.events",
    )

    fun stopAndProveRemoved() {
        if (cleaned) return
        controller.killStopAndRequireAbsent(cgroupPath, process, processHandle)
        val retained = bootProcessHandles
        if (retained != null && retained.values.any { LinuxFilesystemSyscalls.processExists(it) }) {
            isolationFail("isolated BOOT pidfd remained live after unit and cgroup absence")
        }
        retained?.values?.forEach { it.close() }
        bootProcessHandles = null
        processHandle.close()
        cleaned = true
    }

    override fun close() {
        stopAndProveRemoved()
    }

    private fun requireUnitStillRunning(properties: Map<String, String>, label: String) {
        if (
            properties["LoadState"] != "loaded" || properties["ActiveState"] != "active" ||
            properties["SubState"] != "running" || !process.isAlive
        ) isolationFail(
            "isolated worker systemd scope stopped $label " +
                "(load=${properties["LoadState"]}, active=${properties["ActiveState"]}, " +
                "sub=${properties["SubState"]}, localAlive=${process.isAlive})",
        )
    }

    private fun requireLiveProperties(
        properties: Map<String, String>,
        expected: IsolatedObservationResources,
        allowActivating: Boolean = false,
    ) {
        val stateOkay = properties["LoadState"] == "loaded" && process.isAlive &&
            if (allowActivating) properties["ActiveState"] in setOf("active", "activating")
            else properties["ActiveState"] == "active" && properties["SubState"] == "running"
        if (!stateOkay) isolationFail("isolated systemd scope is not live during containment verification")
        val mismatches = buildList {
            addAll(staticPolicyMismatches(properties, expected))
        }
        if (mismatches.isNotEmpty()) {
            isolationFail("isolated systemd policy differs: ${mismatches.joinToString(",")}")
        }
    }

    private fun staticPolicyMismatches(
        properties: Map<String, String>,
        expected: IsolatedObservationResources,
    ): List<String> = buildList {
        if (properties["Id"] != controller.unitName) add("Id")
        if (properties["CollectMode"] != "inactive-or-failed") add("CollectMode")
        if (properties["TasksMax"] != CGROUP_TASKS_MAX.toString()) add("TasksMax")
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
            SERVICE_CLEANUP_TIMEOUT.toNanos() / 1_000L
        ) add("TimeoutStopUSec")
    }

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
        return path
    }
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
            isolationFail("isolated synthetic-root destination is invalid")
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

/** Bounded absence proof for attachment failures before systemd reports ControlGroup. */
private fun findObservationCgroupsForUnit(unitName: String): List<Path> {
    if (
        !unitName.matches(PRODUCTION_OBSERVATION_UNIT_NAME) &&
        !unitName.matches(FIXTURE_OBSERVATION_UNIT_NAME)
    ) {
        isolationFail("isolated scope name is unsafe for cgroup absence verification")
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
                if (!Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)) return@forEach
                val normalized = child.toAbsolutePath().normalize()
                if (!normalized.startsWith(CGROUP_ROOT)) {
                    isolationFail("isolated cgroup cleanup search escaped cgroup v2")
                }
                if (normalized.fileName?.toString() == unitName) matches.add(normalized)
                if (depth >= MAXIMUM_CGROUP_SEARCH_DEPTH) {
                    Files.newDirectoryStream(normalized).use { descendants ->
                        if (descendants.any { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }) {
                            isolationFail("isolated cgroup cleanup search exceeds its depth bound")
                        }
                    }
                } else {
                    pending += normalized to depth + 1
                }
            }
        }
    }
    return matches
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

private const val ISOLATION_CONFIGURATION_SCHEMA_VERSION = 1
private const val ISOLATION_CONFIGURATION_PROVIDER =
    "kotlin-full-tree-function-observation-isolation-configuration-v1"
private const val WORKER_PROTOCOL_VERSION = "1"
private const val WORKER_ARGUMENTS = 9
private const val SUPERVISOR_PROTOCOL_VERSION = "1"
private const val SUPERVISOR_ARGUMENTS = WORKER_ARGUMENTS + 3
private const val READY_FIELD_COUNT = 19
private const val KEEPER_FIELD_COUNT = 4
private const val WORKER_FAILURE_EXIT = 73
private const val SUPERVISOR_FAILURE_EXIT = 74
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
private const val MAXIMUM_PROC_ENVIRONMENT_BYTES = 1024 * 1024
private const val CGROUP_TEXT_BYTES = 64 * 1024
private const val CGROUP_PROCS_BYTES = 1024 * 1024
private const val BOOT_PROCESS_COUNT = 4
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
private val SECURE_RANDOM = SecureRandom()
private val SHA256 = Regex("[0-9a-f]{64}")
private val PROTOCOL_NONCE = Regex("[0-9a-f]{64}")
private val SHARD_IDENTIFIER = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
private val PRODUCTION_OBSERVATION_UNIT_NAME =
    Regex("decomp-oracle-function-[0-9a-f]{64}\\.scope")
private val FIXTURE_OBSERVATION_UNIT_NAME =
    Regex("decomp-oracle-function-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.scope")
private val COUNTER_NAME = Regex("[a-z][a-z0-9_.]*")
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
private val REQUIRED_SYSTEMCTL_COMMANDS = listOf("freeze", "thaw", "kill")
private val SYSTEMD_PROPERTIES = setOf(
    "Id",
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
