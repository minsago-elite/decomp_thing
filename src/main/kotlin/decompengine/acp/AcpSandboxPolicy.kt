package decompengine.acp

import decompengine.agent.AgentWorkspaceRoot
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.time.Duration
import java.util.Collections
import java.security.MessageDigest

enum class AcpSandboxRootMode { READ_ONLY, READ_WRITE }

internal val ACP_INTERNAL_SANDBOX_ROOT: Path = Path.of("/decomp-acp-internal")

/**
 * A fresh directory created for one workflow, rather than an adopted host workspace.
 *
 * The private constructor is intentional: terminal sandboxes may bind only roots created through
 * [create]. The workflow owns population and eventual deletion of the directory.
 */
class AcpWorkflowStagingRoot private constructor(
    val workspaceRoot: AgentWorkspaceRoot,
    internal val identity: LinuxFileIdentity,
    internal val quotaProof: AcpStagingQuotaProof?,
) {
    val rootId: String get() = workspaceRoot.id
    val path: Path get() = workspaceRoot.path

    internal fun requireCurrentIdentity(
        cancellationCheck: () -> Unit = {},
    ) {
        cancellationCheck()
        quotaProof?.requireCurrent(path, cancellationCheck)
        cancellationCheck()
        LinuxFilesystemSyscalls.openRoot(path).use { current ->
            if (
                current.identity.key != identity.key ||
                current.identity.mountId != identity.mountId ||
                !current.identity.isDirectory ||
                current.identity.isSymbolicLink ||
                current.identity.mode.permissions != OWNER_DIRECTORY_MODE
            ) {
                throw IllegalStateException("workflow staging root identity or mode changed")
            }
        }
    }

    companion object {
        /**
         * Creates a root on an otherwise dedicated, finite tmpfs supplied by the workflow.
         * The mount itself is the aggregate byte/inode authority; ordinary host directories are
         * deliberately not accepted for production terminal execution.
         */
        fun createQuotaBacked(
            rootId: String,
            dedicatedTmpfsMount: Path,
            limits: AcpStagingQuotaLimits,
            prefix: String = ".decomp-acp-stage-",
        ): AcpWorkflowStagingRoot = create(
            rootId,
            dedicatedTmpfsMount,
            prefix,
            AcpStagingQuotaProof.pinDedicatedTmpfs(dedicatedTmpfsMount, limits),
        )

        /** Creates a fresh mode-0700 token that can be granted read-only without quota proof. */
        fun createReadOnly(
            rootId: String,
            parent: Path,
            prefix: String = ".decomp-acp-readonly-stage-",
        ): AcpWorkflowStagingRoot = create(rootId, parent, prefix, quotaProof = null)

        private fun create(
            rootId: String,
            parent: Path,
            prefix: String,
            quotaProof: AcpStagingQuotaProof?,
        ): AcpWorkflowStagingRoot {
            require(rootId.matches(Regex("[A-Za-z][A-Za-z0-9._-]*"))) {
                "workflow staging root id is invalid: $rootId"
            }
            require(parent.isAbsolute && parent == parent.normalize()) {
                "workflow staging parent must be an absolute normalized path: $parent"
            }
            require(prefix.length >= 3 && '/' !in prefix && '\u0000' !in prefix) {
                "workflow staging prefix must be a safe file-name prefix"
            }
            LinuxFilesystemSyscalls.requireSupported(parent)
            val realParent = parent.toRealPath(LinkOption.NOFOLLOW_LINKS)
            require(realParent == parent && Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
                "workflow staging parent must be a real directory: $parent"
            }
            val created = Files.createTempDirectory(parent, prefix).normalize()
            try {
                Files.setPosixFilePermissions(created, OWNER_DIRECTORY_PERMISSIONS)
                val root = AgentWorkspaceRoot(rootId, created)
                val identity = LinuxFilesystemSyscalls.openRoot(created).use { it.identity }
                require(identity.mode.permissions == OWNER_DIRECTORY_MODE) {
                    "workflow staging root could not be restricted to mode 0700"
                }
                quotaProof?.bindCreatedRoot(created, identity)
                return AcpWorkflowStagingRoot(root, identity, quotaProof)
            } catch (failure: Throwable) {
                val cleanupFailure = runCatching { Files.deleteIfExists(created) }.exceptionOrNull()
                if (cleanupFailure != null) {
                    throw AcpCleanupProofFailure(
                        "workflow staging-root initialization failed and cleanup was not proven",
                        cleanupFailure,
                    ).also { it.addSuppressed(failure) }
                }
                throw failure
            }
        }

        private val OWNER_DIRECTORY_PERMISSIONS = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        )
        private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
    }
}

data class AcpStagingQuotaLimits(
    val maximumBytes: Long,
    val maximumEntries: Long,
) {
    init {
        require(maximumBytes > 0) { "staging aggregate byte limit must be positive" }
        require(maximumEntries >= 2) { "staging aggregate entry limit must cover the mount and staging root" }
    }
}

data class AcpStagingQuotaEvidence(
    val provider: String,
    val mountId: Long,
    val maximumBytes: Long,
    val maximumEntries: Long,
    val mountPathSha256: String,
)

/** Concrete proof for a pre-provisioned, dedicated tmpfs with finite bytes and inodes. */
internal class AcpStagingQuotaProof private constructor(
    private val mountPath: Path,
    private val mountIdentity: LinuxFileIdentity,
    private val limits: AcpStagingQuotaLimits,
    private val actualBytes: Long,
    private val actualEntries: Long,
) {
    private var rootPath: Path? = null
    private var rootIdentity: LinuxFileIdentity? = null

    val evidence: AcpStagingQuotaEvidence = AcpStagingQuotaEvidence(
        provider = "dedicated-tmpfs-size+nr_inodes",
        mountId = mountIdentity.mountId,
        maximumBytes = actualBytes,
        maximumEntries = actualEntries,
        mountPathSha256 = sandboxPolicySha256(mountPath.toString()),
    )

    @Synchronized
    fun bindCreatedRoot(path: Path, identity: LinuxFileIdentity) {
        check(rootPath == null) { "staging quota proof is already bound" }
        rootPath = path
        rootIdentity = identity
        requireCurrent(path)
    }

    @Synchronized
    fun requireCurrent(
        path: Path,
        cancellationCheck: () -> Unit = {},
    ) {
        cancellationCheck()
        val expectedPath = rootPath ?: return
        val expectedIdentity = rootIdentity ?: throw IllegalStateException("staging quota root identity is absent")
        if (path != expectedPath) throw IllegalStateException("staging quota proof was used for another path")
        val currentMount = pinDedicatedTmpfsMount(mountPath, limits, cancellationCheck)
        if (
            currentMount.identity.key != mountIdentity.key ||
            currentMount.identity.mountId != mountIdentity.mountId ||
            currentMount.totalBytes != actualBytes ||
            currentMount.totalEntries != actualEntries
        ) throw IllegalStateException("dedicated staging quota mount changed")
        cancellationCheck()
        LinuxFilesystemSyscalls.openRoot(path).use { current ->
            if (current.identity.key != expectedIdentity.key ||
                current.identity.mountId != mountIdentity.mountId ||
                current.identity.mode.permissions != 0x1c0
            ) throw IllegalStateException("quota-backed staging root changed")
        }
    }

    companion object {
        fun pinDedicatedTmpfs(path: Path, limits: AcpStagingQuotaLimits): AcpStagingQuotaProof {
            val pinned = pinDedicatedTmpfsMount(path, limits)
            Files.newDirectoryStream(path).use { entries ->
                require(!entries.iterator().hasNext()) {
                    "dedicated staging tmpfs must be empty before the workflow root is created"
                }
            }
            return AcpStagingQuotaProof(
                path,
                pinned.identity,
                limits,
                pinned.totalBytes,
                pinned.totalEntries,
            )
        }
    }
}

private data class PinnedDedicatedTmpfs(
    val identity: LinuxFileIdentity,
    val totalBytes: Long,
    val totalEntries: Long,
)

private fun pinDedicatedTmpfsMount(
    path: Path,
    limits: AcpStagingQuotaLimits,
    cancellationCheck: () -> Unit = {},
): PinnedDedicatedTmpfs {
    cancellationCheck()
    require(path.isAbsolute && path == path.normalize()) {
        "dedicated staging tmpfs path must be absolute and normalized"
    }
    LinuxFilesystemSyscalls.requireSupported(path)
    val real = path.toRealPath(LinkOption.NOFOLLOW_LINKS)
    cancellationCheck()
    require(real == path) { "dedicated staging tmpfs path must be canonical" }
    val identity = LinuxFilesystemSyscalls.openRoot(path).use { it.identity }
    cancellationCheck()
    val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
    require(identity.uid == uid && identity.mode.permissions == 0x1c0) {
        "dedicated staging tmpfs must be owned by this user and mode 0700"
    }
    val entry = readMountInfo(identity.mountId, cancellationCheck)
    require(entry.mountPoint == path && entry.fileSystemType == "tmpfs") {
        "staging quota parent must be the root of a dedicated tmpfs mount"
    }
    val inodes = entry.superOptions.firstNotNullOfOrNull { option ->
        option.removePrefix("nr_inodes=").takeIf { option.startsWith("nr_inodes=") }?.toLongOrNull()
    } ?: throw IllegalArgumentException("dedicated staging tmpfs must declare finite nr_inodes")
    val totalBytes = Files.getFileStore(path).totalSpace
    cancellationCheck()
    require(totalBytes in 1..limits.maximumBytes) {
        "dedicated staging tmpfs byte capacity exceeds workflow policy"
    }
    require(inodes in 2..limits.maximumEntries) {
        "dedicated staging tmpfs inode capacity exceeds workflow policy"
    }
    return PinnedDedicatedTmpfs(identity, totalBytes, inodes)
}

private data class SandboxMountInfo(
    val mountPoint: Path,
    val fileSystemType: String,
    val superOptions: List<String>,
)

private fun readMountInfo(
    expectedMountId: Long,
    cancellationCheck: () -> Unit,
): SandboxMountInfo {
    var match: String? = null
    Files.newBufferedReader(Path.of("/proc/self/mountinfo")).useLines { lines ->
        lines.forEach { candidate ->
            cancellationCheck()
            require(candidate.length <= MAXIMUM_MOUNTINFO_LINE_BYTES) {
                "staging quota mountinfo record exceeds the parser limit"
            }
            if (candidate.substringBefore(' ').toLongOrNull() == expectedMountId) {
                require(match == null) { "staging quota mount identity is ambiguous" }
                match = candidate
            }
        }
    }
    val line = match
        ?: throw IllegalArgumentException("staging quota mount identity is absent from mountinfo")
    val separator = line.indexOf(" - ")
    require(separator > 0) { "staging quota mountinfo record is malformed" }
    val left = line.substring(0, separator).split(' ')
    val right = line.substring(separator + 3).split(' ')
    require(left.size >= 6 && right.size >= 3) { "staging quota mountinfo record is incomplete" }
    return SandboxMountInfo(
        mountPoint = Path.of(decodeMountInfo(left[4])).normalize(),
        fileSystemType = right[0],
        superOptions = right[2].split(','),
    )
}

private const val MAXIMUM_MOUNTINFO_LINE_BYTES = 64 * 1024

private fun decodeMountInfo(value: String): String = value
    .replace("\\040", " ")
    .replace("\\011", "\t")
    .replace("\\012", "\n")
    .replace("\\134", "\\")

private fun sandboxPolicySha256(value: String): String =
    MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

class AcpSandboxRootGrant(
    val stagingRoot: AcpWorkflowStagingRoot,
    val mode: AcpSandboxRootMode,
) {
    /** Staging roots are deliberately mounted at the same absolute path inside the sandbox. */
    val sandboxPath: Path get() = stagingRoot.path
}

/** A read-only host resource made visible at one exact absolute sandbox path. */
class AcpSandboxReadOnlyMount private constructor(
    val source: Path,
    val destination: Path,
    /** Required for user-owned sources; files use their bytes, directories use the documented manifest. */
    val expectedManifestSha256: String?,
    allowInternalDestination: Boolean,
) {
    @JvmOverloads
    constructor(
        source: Path,
        destination: Path = source,
        expectedManifestSha256: String? = null,
    ) : this(source, destination, expectedManifestSha256, false)

    init {
        requireAbsoluteNormalized("sandbox mount source", source)
        requireAbsoluteNormalized("sandbox mount destination", destination)
        require(source != Path.of("/")) { "the host root may never be a sandbox mount source" }
        require(destination != Path.of("/")) { "the host root may never be mounted into an ACP sandbox" }
        require(SENSITIVE_SOURCE_ROOTS.none { source == it || source.startsWith(it) }) {
            "sandbox runtime mounts may not expose host configuration, secret, or kernel trees: $source"
        }
        require(source.none { component ->
            val value = component.toString()
            value in SENSITIVE_DIRECTORY_NAMES || SENSITIVE_PATH_COMPONENT.containsMatchIn(value)
        }) { "sandbox runtime mount source looks like a configuration or credential path: $source" }
        require(allowInternalDestination || RESERVED_DESTINATIONS.none { reserved ->
            destination == reserved || destination.startsWith(reserved) || reserved.startsWith(destination)
        }) {
            "sandbox runtime mounts may not replace private proc, dev, tmp, or helper paths: $destination"
        }
        expectedManifestSha256?.let { validateSha256("runtime manifest", it) }
    }

    internal companion object {
        fun trustedInternal(
            source: Path,
            destination: Path,
            expectedManifestSha256: String,
        ): AcpSandboxReadOnlyMount =
            AcpSandboxReadOnlyMount(source, destination, expectedManifestSha256, true)

        private val RESERVED_DESTINATIONS = listOf(
            Path.of("/proc"),
            Path.of("/dev"),
            Path.of("/tmp"),
            ACP_INTERNAL_SANDBOX_ROOT,
        )
        private val SENSITIVE_SOURCE_ROOTS = listOf(
            Path.of("/root"),
            Path.of("/etc"),
            Path.of("/run"),
            Path.of("/proc"),
            Path.of("/dev"),
            Path.of("/sys"),
        )
        private val SENSITIVE_PATH_COMPONENT = Regex(
            "(^|[-_.])(secret|token|password|passwd|credential|private[-_]?key|api[-_]?key)([-_.]|$)",
            RegexOption.IGNORE_CASE,
        )
        private val SENSITIVE_DIRECTORY_NAMES = setOf(".ssh", ".aws", ".gnupg", ".kube", ".docker")
    }

}

data class AcpSandboxResourceLimits(
    val maximumProcesses: Int = 32,
    val maximumOpenFiles: Int = 256,
    val maximumFileBytes: Long = 64L * 1024 * 1024,
    val maximumAddressSpaceBytes: Long = 2L * 1024 * 1024 * 1024,
    val maximumCpuSeconds: Int = 120,
) {
    init {
        require(maximumProcesses >= 6) {
            "sandbox process limit must allow the scoped bubblewrap and static-helper setup topology"
        }
        require(maximumOpenFiles >= 16) { "sandbox open-file limit is too small for safe startup" }
        require(maximumFileBytes > 0) { "sandbox file-size limit must be positive" }
        require(maximumAddressSpaceBytes >= 64L * 1024 * 1024) {
            "sandbox address-space limit must be at least 64 MiB"
        }
        require(maximumCpuSeconds > 0) { "sandbox CPU limit must be positive" }
    }
}

data class AcpRuntimeClosureLimits(
    val maximumEntries: Int = 100_000,
    val maximumUserOwnedFileBytes: Long = 2L * 1024 * 1024 * 1024,
    val maximumDepth: Int = 64,
) {
    init {
        require(maximumEntries in 1..100_000) { "runtime closure entry limit must be between 1 and 100000" }
        require(maximumUserOwnedFileBytes > 0) { "runtime closure byte limit must be positive" }
        require(maximumDepth > 0) { "runtime closure depth limit must be positive" }
    }
}

/**
 * Linux boundary configuration shared by the outer ACP agent and client-owned terminal children.
 * Runtime mounts are explicit and read-only; bubblewrap itself is never mounted into the sandbox.
 */
class AcpLinuxSandboxConfiguration(
    val bubblewrapExecutable: Path,
    val resourceLimiterExecutable: Path,
    val scopeSupervisorExecutable: Path,
    val scopeInspectorExecutable: Path,
    /** Root-owned constant launcher used only to open the private environment inode as fd 4. */
    val environmentFdOpenerExecutable: Path,
    /** Provisioned static gate/env/exec helper, executed only inside the completed sandbox. */
    val sandboxGateHelperExecutable: Path,
    launcherRuntimeMounts: Collection<AcpSandboxReadOnlyMount>,
    agentRuntimeMounts: Collection<AcpSandboxReadOnlyMount>,
    val systemdUserRuntimeDirectory: Path,
    val agentWorkingDirectory: Path = Path.of("/tmp"),
    val agentResourceLimits: AcpSandboxResourceLimits = AcpSandboxResourceLimits(),
    val runtimeClosureLimits: AcpRuntimeClosureLimits = AcpRuntimeClosureLimits(),
    val expectedBubblewrapSha256: String,
    val expectedResourceLimiterSha256: String,
    val expectedScopeSupervisorSha256: String,
    val expectedScopeInspectorSha256: String,
    val expectedEnvironmentFdOpenerSha256: String,
    val expectedSandboxGateHelperSha256: String,
    val expectedSandboxGateHelperManifestSha256: String,
    ninjaCompdbRuntimeMounts: Collection<AcpSandboxReadOnlyMount> = emptyList(),
    validationRuntimeMounts: Collection<AcpSandboxReadOnlyMount> = emptyList(),
) {
    val launcherRuntimeMounts: List<AcpSandboxReadOnlyMount> = immutableList(
        requireBoundedCollection("launcher runtime mounts", launcherRuntimeMounts, MAXIMUM_SANDBOX_MOUNTS),
    )
    val agentRuntimeMounts: List<AcpSandboxReadOnlyMount> = immutableList(
        requireBoundedCollection("agent runtime mounts", agentRuntimeMounts, MAXIMUM_SANDBOX_MOUNTS),
    )
    /** Operator-owned dynamic-loader closure available only to an isolated Ninja compdb query. */
    val ninjaCompdbRuntimeMounts: List<AcpSandboxReadOnlyMount> = immutableList(
        requireBoundedCollection(
            "Ninja compdb runtime mounts",
            ninjaCompdbRuntimeMounts,
            MAXIMUM_SANDBOX_MOUNTS,
        ),
    )
    /** Application-owned compiler/program validation closure; never selected by an ACP peer. */
    val validationRuntimeMounts: List<AcpSandboxReadOnlyMount> = immutableList(
        requireBoundedCollection("validation runtime mounts", validationRuntimeMounts, MAXIMUM_SANDBOX_MOUNTS),
    )

    init {
        requireAbsoluteNormalized("bubblewrap executable", bubblewrapExecutable)
        requireAbsoluteNormalized("resource limiter executable", resourceLimiterExecutable)
        requireAbsoluteNormalized("scope supervisor executable", scopeSupervisorExecutable)
        requireAbsoluteNormalized("scope inspector executable", scopeInspectorExecutable)
        requireAbsoluteNormalized("environment fd opener executable", environmentFdOpenerExecutable)
        requireAbsoluteNormalized("sandbox gate helper executable", sandboxGateHelperExecutable)
        requireAbsoluteNormalized("systemd user runtime directory", systemdUserRuntimeDirectory)
        requireAbsoluteNormalized("outer ACP agent working directory", agentWorkingDirectory)
        require(agentWorkingDirectory == Path.of("/tmp")) {
            "the outer ACP agent must start in the private sandbox /tmp"
        }
        validateSha256("bubblewrap", expectedBubblewrapSha256)
        validateSha256("resource limiter", expectedResourceLimiterSha256)
        validateSha256("scope supervisor", expectedScopeSupervisorSha256)
        validateSha256("scope inspector", expectedScopeInspectorSha256)
        validateSha256("environment fd opener", expectedEnvironmentFdOpenerSha256)
        validateSha256("sandbox gate helper", expectedSandboxGateHelperSha256)
        validateSha256("sandbox gate helper manifest", expectedSandboxGateHelperManifestSha256)
        require(this.ninjaCompdbRuntimeMounts.all { it.expectedManifestSha256 != null }) {
            "every Ninja compdb runtime mount requires an expected manifest SHA-256"
        }
        require(this.validationRuntimeMounts.all { it.expectedManifestSha256 != null }) {
            "every validation runtime mount requires an expected manifest SHA-256"
        }
        require(
            this.launcherRuntimeMounts.size +
                this.agentRuntimeMounts.size +
                this.ninjaCompdbRuntimeMounts.size + this.validationRuntimeMounts.size <= MAXIMUM_SANDBOX_MOUNTS,
        ) {
            "combined launcher, agent, and Ninja compdb runtime mounts exceed the sandbox mount-count limit"
        }
        requireUniqueDestinations(
            this.launcherRuntimeMounts + this.agentRuntimeMounts + this.ninjaCompdbRuntimeMounts + this.validationRuntimeMounts,
        )
    }
}

data class AcpTerminalLimits(
    val maximumConcurrentTerminals: Int = 4,
    val maximumTerminalCreates: Int = 16,
    val maximumRetainedOutputBytes: Int = 1024 * 1024,
    val maximumProducedOutputBytes: Long = 8L * 1024 * 1024,
    val maximumDuration: Duration = Duration.ofSeconds(30),
    val terminationGrace: Duration = Duration.ofMillis(250),
    val resourceLimits: AcpSandboxResourceLimits = AcpSandboxResourceLimits(
        maximumProcesses = 16,
        maximumOpenFiles = 128,
        maximumFileBytes = 32L * 1024 * 1024,
        maximumAddressSpaceBytes = 1024L * 1024 * 1024,
        maximumCpuSeconds = 35,
    ),
) {
    init {
        require(maximumConcurrentTerminals > 0) { "maximum concurrent terminals must be positive" }
        require(maximumConcurrentTerminals <= MAXIMUM_CONCURRENT_TERMINALS) {
            "maximum concurrent terminals exceeds the sandbox evidence/resource limit"
        }
        require(maximumTerminalCreates >= maximumConcurrentTerminals) {
            "maximum terminal creates must cover the concurrent-terminal limit"
        }
        require(maximumTerminalCreates <= MAXIMUM_SANDBOX_EVIDENCE_LAUNCHES - 1) {
            "maximum terminal creates exceeds the sandbox evidence launch limit"
        }
        require(maximumRetainedOutputBytes > 0) { "retained terminal output limit must be positive" }
        require(maximumProducedOutputBytes >= maximumRetainedOutputBytes.toLong()) {
            "produced terminal output limit must cover retained output"
        }
        requirePositiveMillis("terminal duration", maximumDuration)
        requirePositiveMillis("terminal termination grace", terminationGrace)
        require(resourceLimits.maximumCpuSeconds.toLong() <= maximumDuration.seconds + 5L) {
            "sandbox CPU limit must not materially exceed the terminal wall timeout"
        }
    }
}

/** One exact initial exec request. Descendant effects remain bounded by the declared sandbox roots. */
class AcpTerminalCommandRule(
    val executable: AcpSandboxReadOnlyMount,
    arguments: Collection<String>,
    val workingDirectory: Path,
    environment: Map<String, String> = emptyMap(),
    runtimeMounts: Collection<AcpSandboxReadOnlyMount> = emptyList(),
) {
    val arguments: List<String> = immutableList(requireBoundedTerminalArguments(arguments))
    val environment: Map<String, String> = immutableMap(
        requireBoundedEnvironment("terminal", environment),
    )
    val runtimeMounts: List<AcpSandboxReadOnlyMount> = immutableList(
        requireBoundedCollection("terminal runtime mounts", runtimeMounts, MAXIMUM_SANDBOX_MOUNTS),
    )

    /** The exact absolute command string accepted from ACP. */
    val command: String get() = executable.destination.toString()

    init {
        requireAbsoluteNormalized("terminal working directory", workingDirectory)
        require(this.arguments.none { '\u0000' in it }) { "terminal argv must not contain NUL" }
        require(this.environment.keys.all(::isValidEnvironmentName)) {
            "terminal environment names must use portable [A-Za-z_][A-Za-z0-9_]* syntax"
        }
        require(this.environment.values.none { '\u0000' in it }) {
            "terminal environment values must not contain NUL"
        }
        val helperControlName = this.environment.keys.firstOrNull(::isSandboxHelperControlEnvironmentName)
        require(helperControlName == null) {
            "terminal environment may not alter the authenticated sandbox helper: $helperControlName"
        }
        val credentialName = this.environment.keys.firstOrNull(::isCredentialEnvironmentName)
        require(credentialName == null) {
            "terminal environment may not contain credential-like variable $credentialName"
        }
        requireUniqueDestinations(listOf(executable) + this.runtimeMounts)
    }
}

private fun requireBoundedTerminalArguments(arguments: Collection<String>): Collection<String> {
    require(arguments.size < MAXIMUM_SANDBOX_ARGUMENTS) {
        "terminal argv exceeds the authenticated argument-count limit"
    }
    var encodedBytes = 0L
    arguments.forEach { argument ->
        encodedBytes = Math.addExact(encodedBytes, utf8Length(argument) + 1L)
        require(encodedBytes <= MAXIMUM_SANDBOX_ARGUMENT_BYTES) {
            "terminal argv exceeds the authenticated byte limit"
        }
    }
    return arguments
}

/** Immutable workflow authority frozen before the ACP session is initialized. */
class AcpTerminalExecutionPolicy(
    stagingRoots: Collection<AcpSandboxRootGrant>,
    commandRules: Collection<AcpTerminalCommandRule>,
    val limits: AcpTerminalLimits = AcpTerminalLimits(),
) {
    val stagingRoots: List<AcpSandboxRootGrant> = immutableList(
        requireBoundedCollection("terminal staging roots", stagingRoots, MAXIMUM_SANDBOX_ROOTS),
    )
    val commandRules: List<AcpTerminalCommandRule> = immutableList(
        requireBoundedCollection("terminal command rules", commandRules, MAXIMUM_TERMINAL_COMMAND_RULES),
    )

    init {
        require(this.stagingRoots.isNotEmpty()) { "terminal policy must declare a workflow staging root" }
        require(this.commandRules.isNotEmpty()) { "terminal policy must declare an exact command rule" }
        require(this.stagingRoots.map { it.stagingRoot.rootId }.distinct().size == this.stagingRoots.size) {
            "terminal staging root ids must be unique"
        }
        require(this.stagingRoots
            .filter { it.mode == AcpSandboxRootMode.READ_WRITE }
            .all { it.stagingRoot.quotaProof != null }
        ) {
            "production writable terminal roots require a verified aggregate byte/inode quota"
        }
        val paths = this.stagingRoots.map { it.stagingRoot.path }
        requireNonOverlappingPaths("terminal staging roots", paths)
        var authorityBytes = 0L
        this.commandRules.forEach { rule ->
            authorityBytes = addTerminalRuleAuthorityBytes(authorityBytes, rule)
            require(authorityBytes <= MAXIMUM_TERMINAL_POLICY_AUTHORITY_BYTES) {
                "terminal policy exceeds its aggregate authority-byte limit"
            }
            val containingRoots = paths.filter { rule.workingDirectory == it }
            require(containingRoots.size == 1) {
                "terminal working directory must be exactly one workflow staging root"
            }
            val runtime = listOf(rule.executable) + rule.runtimeMounts
            require(runtime.none { mount -> paths.any { root ->
                mount.destination == root || mount.destination.startsWith(root) || root.startsWith(mount.destination) ||
                    mount.source == root || mount.source.startsWith(root) || root.startsWith(mount.source)
            } }) { "terminal runtime mounts must not overlap workflow staging roots" }
        }
        val signatures = this.commandRules.map { rule ->
            listOf(
                rule.command,
                rule.arguments.joinToString("\u0000"),
                rule.workingDirectory.toString(),
                rule.environment.toSortedMap().entries.joinToString("\u0000") { "${it.key}=${it.value}" },
            ).joinToString("\u0001")
        }
        require(signatures.distinct().size == signatures.size) { "terminal command rules must not be duplicates" }
    }

}

internal fun isCredentialEnvironmentName(name: String): Boolean =
    CREDENTIAL_ENVIRONMENT_PATTERN.containsMatchIn(name) || name.uppercase() in CREDENTIAL_ENVIRONMENT_NAMES

private val CREDENTIAL_ENVIRONMENT_PATTERN = Regex(
    "(^|_)(API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?)(_|$)",
    RegexOption.IGNORE_CASE,
)

private val CREDENTIAL_ENVIRONMENT_NAMES = setOf(
    "SSH_AUTH_SOCK",
    "GIT_ASKPASS",
    "AWS_SESSION_TOKEN",
    "KUBECONFIG",
    "DOCKER_CONFIG",
)

private fun isValidEnvironmentName(name: String): Boolean =
    name.matches(Regex("[A-Za-z_][A-Za-z0-9_]*"))

internal fun isSandboxHelperControlEnvironmentName(name: String): Boolean {
    val upper = name.uppercase()
    return upper.startsWith("LD_") || upper.startsWith("BASH_") ||
        upper in SANDBOX_HELPER_CONTROL_ENVIRONMENT_NAMES
}

private val SANDBOX_HELPER_CONTROL_ENVIRONMENT_NAMES = setOf(
    "BASH_ENV", "BASHOPTS", "SHELLOPTS", "BASH_XTRACEFD", "ENV", "SHLVL",
    "PWD", "OLDPWD", "_", "IFS", "CDPATH", "GLOBIGNORE", "FIGNORE",
    "POSIXLY_CORRECT", "PROMPT_COMMAND", "PS0", "PS1", "PS2", "PS3", "PS4",
    "TIMEFORMAT", "TMOUT", "GCONV_PATH", "LOCPATH", "NLSPATH", "GLIBC_TUNABLES",
    "MALLOC_TRACE", "MALLOC_CHECK_", "TZDIR", "HOSTALIASES", "RES_OPTIONS", "LOCALDOMAIN",
)

private fun requireAbsoluteNormalized(name: String, path: Path) {
    require(path.isAbsolute && path == path.normalize() && '\u0000' !in path.toString()) {
        "$name must be an absolute normalized path: $path"
    }
    require(utf8Length(path.toString()) <= MAXIMUM_SANDBOX_PATH_BYTES) {
        "$name exceeds the authenticated path-byte limit"
    }
}

private fun requireUniqueDestinations(mounts: Collection<AcpSandboxReadOnlyMount>) {
    val destinations = mounts.map { it.destination }
    requireNonOverlappingPaths("sandbox runtime mount destinations", destinations)
}

private class SandboxPolicyPathNode {
    var terminal: Boolean = false
    val children = HashMap<String, SandboxPolicyPathNode>()
}

private fun requireNonOverlappingPaths(label: String, paths: Collection<Path>) {
    val root = SandboxPolicyPathNode()
    paths.forEach { path ->
        var node = root
        path.forEach { component ->
            require(!node.terminal) { "$label must be distinct and non-overlapping" }
            node = node.children.getOrPut(component.toString(), ::SandboxPolicyPathNode)
        }
        require(!node.terminal && node.children.isEmpty()) { "$label must be distinct and non-overlapping" }
        node.terminal = true
    }
}

private fun <T> requireBoundedCollection(
    label: String,
    values: Collection<T>,
    maximum: Int,
): Collection<T> {
    require(values.size <= maximum) { "$label exceed the authenticated count limit" }
    return values
}

private fun requireBoundedEnvironment(
    label: String,
    environment: Map<String, String>,
): Map<String, String> {
    require(environment.size <= MAXIMUM_SANDBOX_ENVIRONMENT_BINDINGS) {
        "$label environment exceeds the authenticated binding-count limit"
    }
    var bytes = 0L
    environment.forEach { (name, value) ->
        bytes = Math.addExact(bytes, utf8Length(name) + utf8Length(value) + 2L)
        require(bytes <= MAXIMUM_SANDBOX_ENVIRONMENT_BYTES) {
            "$label environment exceeds the authenticated byte limit"
        }
    }
    return environment
}

private fun addTerminalRuleAuthorityBytes(total: Long, rule: AcpTerminalCommandRule): Long {
    var result = total
    fun add(value: String) {
        result = Math.addExact(result, utf8Length(value) + 1L)
    }
    add(rule.command)
    rule.arguments.forEach(::add)
    add(rule.workingDirectory.toString())
    rule.environment.forEach { (name, value) -> add(name); add(value) }
    (listOf(rule.executable) + rule.runtimeMounts).forEach { mount ->
        add(mount.source.toString())
        add(mount.destination.toString())
        mount.expectedManifestSha256?.let(::add)
    }
    return result
}

internal fun utf8Length(
    value: String,
    cancellationCheck: () -> Unit = {},
): Long {
    var bytes = 0L
    var index = 0
    while (index < value.length) {
        if (index and 0xfff == 0) cancellationCheck()
        val character = value[index]
        bytes = Math.addExact(bytes, when {
            character.code <= 0x7f -> 1L
            character.code <= 0x7ff -> 2L
            Character.isHighSurrogate(character) && index + 1 < value.length &&
                Character.isLowSurrogate(value[index + 1]) -> {
                index++
                4L
            }
            Character.isSurrogate(character) -> 1L // UTF-8 encoder replacement byte ('?').
            else -> 3L
        })
        index++
    }
    cancellationCheck()
    return bytes
}

private fun validateSha256(name: String, digest: String) {
    require(digest.matches(Regex("[0-9a-f]{64}"))) {
        "expected $name digest must be a lowercase SHA-256 value"
    }
}

private fun <T> immutableList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))

private fun <K, V> immutableMap(values: Map<K, V>): Map<K, V> =
    Collections.unmodifiableMap(LinkedHashMap(values))

private fun requirePositiveMillis(name: String, duration: Duration) {
    require(!duration.isZero && !duration.isNegative && duration.toMillis() > 0) {
        "$name must be at least one millisecond"
    }
}

internal const val MAXIMUM_SANDBOX_MOUNTS = 256
internal const val MAXIMUM_SANDBOX_ROOTS = 64
internal const val MAXIMUM_SANDBOX_EMPTY_DIRECTORIES = 256
internal const val MAXIMUM_SANDBOX_ENVIRONMENT_BINDINGS = 1024
internal const val MAXIMUM_SANDBOX_ENVIRONMENT_BYTES = 1024 * 1024
internal const val MAXIMUM_TERMINAL_COMMAND_RULES = 256
internal const val MAXIMUM_CONCURRENT_TERMINALS = 64
internal const val MAXIMUM_SANDBOX_EVIDENCE_LAUNCHES = 1024
internal const val MAXIMUM_SANDBOX_EVIDENCE_RUNTIME_MOUNTS = 16_384
internal const val MAXIMUM_SANDBOX_EVIDENCE_AUDIT_RECORDS = 4096
internal const val MAXIMUM_SANDBOX_SECURITY_EXECUTABLES = 32
internal const val MAXIMUM_SANDBOX_EVIDENCE_BYTES = 64L * 1024L * 1024L
internal const val MAXIMUM_TERMINAL_POLICY_AUTHORITY_BYTES = 8 * 1024 * 1024L
internal const val MAXIMUM_SANDBOX_PATH_BYTES = 4096L
