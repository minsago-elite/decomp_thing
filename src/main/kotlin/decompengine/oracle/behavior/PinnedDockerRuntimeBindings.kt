package decompengine.oracle.behavior

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.requireStableDirectory
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class PinnedDockerRuntimeBindingsException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Descriptor-backed bindings for one authenticated Docker control plane.
 *
 * This object owns no command renderer or executor and accepts no response, parsed fact, callback,
 * or authority. The caller must derive the expected client bytes from independently authenticated
 * evidence. The Docker config is supplied to the client through the retained directory descriptor;
 * the Unix socket remains a canonical named path because a Unix-domain connect cannot use O_PATH.
 */
internal class PinnedDockerRuntimeBindings private constructor(
    val controlClientBytes: Long,
    val controlClientSha256: String,
    val executableDescriptorPath: Path,
    val dockerConfigDescriptorPath: Path,
    val runtimeSocketPath: Path,
    val environment: Map<String, String>,
    val controlClientIdentitySha256: String,
    val dockerConfigIdentitySha256: String,
    val dockerConfigPathSha256: String,
    val runtimeSocketIdentitySha256: String,
    val runtimeSocketParentIdentitySha256: String,
    val runtimeSocketPathSha256: String,
    val runtimeSocketMode: String,
    private val controlClientPath: Path,
    private val controlClientIdentity: LinuxFileIdentity,
    private val controlClientGuard: StableControlFile,
    private val controlClientDescriptor: LinuxDescriptor,
    private val dockerConfigPath: Path,
    private val dockerConfigIdentity: LinuxFileIdentity,
    private val dockerConfigDescriptor: LinuxDescriptor,
    private val runtimeSocketParent: LinuxDescriptor,
    private val runtimeSocketDescriptor: LinuxDescriptor,
    private val runtimeSocketParentIdentity: LinuxFileIdentity,
    private val runtimeSocketIdentity: LinuxFileIdentity,
) : AutoCloseable {
    fun requireCurrent() = translateBindingFailures("verify pinned Docker runtime bindings") {
        requireCurrentControlClient()
        requireCurrentDockerConfig()
        requireCurrentRuntimeSocket()
    }

    private fun requireCurrentControlClient() {
        val pinned = LinuxFilesystemSyscalls.identity(controlClientDescriptor.fd)
        if (pinned != controlClientIdentity || !pinned.isRegularFile || pinned.isSymbolicLink) {
            bindingFail("pinned runtime control-client descriptor changed")
        }
        val pinnedAuthentication = authenticatePinnedControlClient(
            controlClientDescriptor,
            controlClientBytes,
            "runtime control-client terminal authentication",
        )
        if (pinnedAuthentication.bytes != controlClientBytes || pinnedAuthentication.sha256 != controlClientSha256) {
            bindingFail("runtime control-client bytes changed while pinned")
        }
        controlClientGuard.verifyUnchanged("runtime control client")
        if (controlClientGuard.size != controlClientBytes) {
            bindingFail("runtime control-client byte length changed")
        }
        requireExecutableControlClient(controlClientPath)
        val terminal = LinuxFilesystemSyscalls.openAbsolutePathOrNull(controlClientPath)
            ?: bindingFail("runtime control-client path disappeared")
        terminal.use {
            val terminalIdentity = LinuxFilesystemSyscalls.identity(terminal.fd)
            if (
                terminalIdentity != controlClientIdentity ||
                !Files.isSameFile(controlClientPath, LinuxFilesystemSyscalls.descriptorPath(controlClientDescriptor))
            ) {
                bindingFail("runtime control-client path changed identity")
            }
        }
    }

    private fun requireCurrentDockerConfig() {
        val pinned = LinuxFilesystemSyscalls.identity(dockerConfigDescriptor.fd)
        if (pinned != dockerConfigIdentity) bindingFail("pinned Docker config directory changed")
        requireEmptyPrivateDirectory(dockerConfigDescriptor, "Docker config directory")
        val named = LinuxFilesystemSyscalls.openRoot(dockerConfigPath)
        named.use {
            if (
                LinuxFilesystemSyscalls.identity(named.fd) != dockerConfigIdentity ||
                !Files.isSameFile(dockerConfigPath, dockerConfigDescriptorPath)
            ) {
                bindingFail("Docker config directory path changed identity")
            }
        }
    }

    private fun requireCurrentRuntimeSocket() {
        if (LinuxFilesystemSyscalls.identity(runtimeSocketParent.fd) != runtimeSocketParentIdentity) {
            bindingFail("pinned runtime socket parent changed")
        }
        if (LinuxFilesystemSyscalls.identity(runtimeSocketDescriptor.fd) != runtimeSocketIdentity) {
            bindingFail("pinned runtime socket changed")
        }
        requirePrivateSocketIdentity(runtimeSocketIdentity, runtimeSocketParentIdentity)
        val namedParent = LinuxFilesystemSyscalls.openRoot(runtimeSocketPath.parent)
        namedParent.use {
            if (LinuxFilesystemSyscalls.identity(namedParent.fd) != runtimeSocketParentIdentity) {
                bindingFail("runtime socket parent path changed identity")
            }
        }
        val namedSocket = LinuxFilesystemSyscalls.openAbsolutePathOrNull(runtimeSocketPath)
            ?: bindingFail("runtime socket disappeared")
        namedSocket.use {
            if (LinuxFilesystemSyscalls.identity(namedSocket.fd) != runtimeSocketIdentity) {
                bindingFail("runtime socket path changed identity")
            }
        }
    }

    override fun close() {
        runtimeSocketDescriptor.close()
        runtimeSocketParent.close()
        dockerConfigDescriptor.close()
        controlClientDescriptor.close()
        controlClientGuard.close()
    }

    companion object {
        fun capture(
            controlClientPath: Path,
            expectedControlClientBytes: Long,
            expectedControlClientSha256: String,
            maximumControlClientBytes: Long,
            dockerConfigPath: Path,
            runtimeSocketPath: Path,
        ): PinnedDockerRuntimeBindings = translateBindingFailures("capture pinned Docker runtime bindings") {
            if (maximumControlClientBytes <= 0L) {
                bindingFail("runtime control-client byte ceiling must be positive")
            }
            if (expectedControlClientBytes !in 1L..maximumControlClientBytes) {
                bindingFail("runtime control-client byte length exceeds its authenticated ceiling")
            }
            if (!expectedControlClientSha256.matches(SHA256)) {
                bindingFail("runtime control-client SHA-256 is malformed")
            }

            requireExecutableControlClient(controlClientPath)
            val guard = StableControlFile.open(
                controlClientPath,
                maximumControlClientBytes,
                "runtime control client",
            )
            var clientDescriptor: LinuxDescriptor? = null
            var configDescriptor: LinuxDescriptor? = null
            var socketParent: LinuxDescriptor? = null
            var socketDescriptor: LinuxDescriptor? = null
            try {
                if (guard.size != expectedControlClientBytes) {
                    bindingFail("runtime control-client byte length differs from authenticated evidence")
                }
                val openedClient = LinuxFilesystemSyscalls.openAbsolutePathOrNull(controlClientPath)
                    ?: bindingFail("runtime control client is unavailable")
                clientDescriptor = openedClient
                val clientIdentity = LinuxFilesystemSyscalls.identity(openedClient.fd)
                requireControlClientIdentity(clientIdentity)
                if (!Files.isSameFile(controlClientPath, LinuxFilesystemSyscalls.descriptorPath(openedClient))) {
                    bindingFail("runtime control-client descriptor differs from its authenticated path")
                }
                val pinnedAuthentication = authenticatePinnedControlClient(
                    openedClient,
                    maximumControlClientBytes,
                    "runtime control client",
                )
                if (
                    pinnedAuthentication.bytes != expectedControlClientBytes ||
                    pinnedAuthentication.sha256 != expectedControlClientSha256
                ) {
                    bindingFail("runtime control-client bytes differ from authenticated evidence")
                }
                val guardSha256 = guard.sha256(label = "runtime control client path guard")
                if (guardSha256 != pinnedAuthentication.sha256) {
                    bindingFail("runtime control-client path guard and executable descriptor differ")
                }
                guard.verifyUnchanged("runtime control client")
                if (!Files.isSameFile(controlClientPath, LinuxFilesystemSyscalls.descriptorPath(openedClient))) {
                    bindingFail("runtime control-client path changed during authentication")
                }

                requireCanonicalDirectoryPath(dockerConfigPath, "Docker config directory")
                val openedConfig = LinuxFilesystemSyscalls.openRoot(dockerConfigPath)
                configDescriptor = openedConfig
                requireEmptyPrivateDirectory(openedConfig, "Docker config directory")
                val configIdentity = LinuxFilesystemSyscalls.identity(openedConfig.fd)
                val configExecutionPath = LinuxFilesystemSyscalls.stableDescriptorPath(openedConfig.fd)
                if (!Files.isSameFile(dockerConfigPath, configExecutionPath)) {
                    bindingFail("Docker config directory descriptor differs from its authenticated path")
                }

                requireCanonicalFilePath(runtimeSocketPath, "runtime socket")
                requireCanonicalDirectoryPath(runtimeSocketPath.parent, "runtime socket parent")
                val openedSocketParent = LinuxFilesystemSyscalls.openRoot(runtimeSocketPath.parent)
                socketParent = openedSocketParent
                val socketParentIdentity = LinuxFilesystemSyscalls.identity(openedSocketParent.fd)
                val openedSocket = LinuxFilesystemSyscalls.openAbsolutePathOrNull(runtimeSocketPath)
                    ?: bindingFail("runtime socket is unavailable")
                socketDescriptor = openedSocket
                val socketIdentity = LinuxFilesystemSyscalls.identity(openedSocket.fd)
                requirePrivateSocketIdentity(socketIdentity, socketParentIdentity)
                if (!Files.isSameFile(runtimeSocketPath.parent, LinuxFilesystemSyscalls.descriptorPath(openedSocketParent))) {
                    bindingFail("runtime socket parent descriptor differs from its authenticated path")
                }
                if (!Files.isSameFile(runtimeSocketPath, LinuxFilesystemSyscalls.descriptorPath(openedSocket))) {
                    bindingFail("runtime socket descriptor differs from its authenticated path")
                }

                val executablePath = LinuxFilesystemSyscalls.stableDescriptorPath(openedClient.fd)
                val fixedEnvironment = Collections.unmodifiableMap(
                    linkedMapOf(
                        "DOCKER_CONFIG" to configExecutionPath.toString(),
                        "DOCKER_HOST" to "unix://$runtimeSocketPath",
                        "HOME" to "/nonexistent",
                        "LANG" to "C",
                        "LC_ALL" to "C",
                    ),
                )
                return@translateBindingFailures PinnedDockerRuntimeBindings(
                    controlClientBytes = pinnedAuthentication.bytes,
                    controlClientSha256 = pinnedAuthentication.sha256,
                    executableDescriptorPath = executablePath,
                    dockerConfigDescriptorPath = configExecutionPath,
                    runtimeSocketPath = runtimeSocketPath,
                    environment = fixedEnvironment,
                    controlClientIdentitySha256 = identityCommitment(clientIdentity),
                    dockerConfigIdentitySha256 = identityCommitment(configIdentity),
                    dockerConfigPathSha256 = pathCommitment(dockerConfigPath),
                    runtimeSocketIdentitySha256 = identityCommitment(socketIdentity),
                    runtimeSocketParentIdentitySha256 = identityCommitment(socketParentIdentity),
                    runtimeSocketPathSha256 = pathCommitment(runtimeSocketPath),
                    runtimeSocketMode = "0o${socketIdentity.mode.permissions.toString(8).padStart(3, '0')}",
                    controlClientPath = controlClientPath,
                    controlClientIdentity = clientIdentity,
                    controlClientGuard = guard,
                    controlClientDescriptor = openedClient,
                    dockerConfigPath = dockerConfigPath,
                    dockerConfigIdentity = configIdentity,
                    dockerConfigDescriptor = openedConfig,
                    runtimeSocketParent = openedSocketParent,
                    runtimeSocketDescriptor = openedSocket,
                    runtimeSocketParentIdentity = socketParentIdentity,
                    runtimeSocketIdentity = socketIdentity,
                ).also {
                    clientDescriptor = null
                    configDescriptor = null
                    socketParent = null
                    socketDescriptor = null
                }
            } catch (failure: Throwable) {
                socketDescriptor?.close()
                socketParent?.close()
                configDescriptor?.close()
                clientDescriptor?.close()
                guard.close()
                throw failure
            }
        }
    }
}

private data class PinnedControlClientAuthentication(
    val bytes: Long,
    val sha256: String,
)

private fun authenticatePinnedControlClient(
    descriptor: LinuxDescriptor,
    maximumBytes: Long,
    label: String,
): PinnedControlClientAuthentication {
    val digest = MessageDigest.getInstance("SHA-256")
    val sink = object : OutputStream() {
        override fun write(value: Int) {
            digest.update(value.toByte())
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            digest.update(bytes, offset, length)
        }
    }
    val bytes = LinuxFilesystemSyscalls.copyReadableTo(descriptor, sink, maximumBytes)
    if (bytes !in 1L..maximumBytes) bindingFail("$label must contain 1..$maximumBytes bytes")
    return PinnedControlClientAuthentication(bytes, digest.digest().toHex())
}

private fun requireExecutableControlClient(path: Path) {
    requireCanonicalFilePath(path, "runtime control client")
    requireStableDirectory(path.parent, "runtime control-client parent")
    val descriptor = LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)
        ?: bindingFail("runtime control client is unavailable")
    descriptor.use {
        requireControlClientIdentity(LinuxFilesystemSyscalls.identity(descriptor.fd))
    }
}

private fun requireControlClientIdentity(identity: LinuxFileIdentity) {
    if (
        !identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink || identity.linkCount != 1 ||
        identity.mode.permissions and OWNER_EXECUTE == 0 ||
        identity.mode.permissions and UNTRUSTED_WRITE_PERMISSIONS != 0
    ) {
        bindingFail("runtime control client must be an owner-executable, single-link regular file without untrusted writes")
    }
}

private fun requireEmptyPrivateDirectory(descriptor: LinuxDescriptor, label: String) {
    val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
    if (
        !identity.isDirectory || identity.isSymbolicLink || identity.uid != currentUid() ||
        identity.mode.permissions != OWNER_DIRECTORY_MODE
    ) {
        bindingFail("$label must be a pinned current-user mode-0700 directory")
    }
    if (LinuxFilesystemSyscalls.directoryEntryNames(descriptor, maximumEntries = 1).isNotEmpty()) {
        bindingFail("$label must be empty")
    }
}

private fun requirePrivateSocketIdentity(socket: LinuxFileIdentity, parent: LinuxFileIdentity) {
    if (
        !parent.isDirectory || parent.isSymbolicLink || parent.uid != currentUid() ||
        parent.mode.permissions != OWNER_DIRECTORY_MODE
    ) {
        bindingFail("runtime socket parent must be a pinned current-user mode-0700 directory")
    }
    if (
        socket.mode and FILE_TYPE_MASK != SOCKET_FILE_TYPE || socket.isRegularFile || socket.isDirectory ||
        socket.isSymbolicLink || socket.uid != currentUid() || socket.linkCount != 1 ||
        socket.mode.permissions and OWNER_SOCKET_PERMISSIONS != OWNER_SOCKET_PERMISSIONS ||
        socket.mode.permissions and SPECIAL_MODE_BITS != 0
    ) {
        bindingFail("runtime endpoint must be a current-user Unix socket in its private parent")
    }
}

private fun requireCanonicalFilePath(path: Path, label: String) {
    if (!path.isAbsolute || path.normalize() != path || path.fileName == null || path.parent == null) {
        bindingFail("$label path must be absolute, normalized, and name a file")
    }
    if (path.toRealPath() != path) bindingFail("$label path may not contain symbolic links")
}

private fun requireCanonicalDirectoryPath(path: Path, label: String) {
    if (!path.isAbsolute || path.normalize() != path || path.fileName == null || path.parent == null) {
        bindingFail("$label path must be absolute, normalized, and name a non-root directory")
    }
    val attributes = Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null || path.toRealPath() != path) {
        bindingFail("$label must be a canonical identified directory")
    }
}

private fun identityCommitment(identity: LinuxFileIdentity): String = canonicalIdentitySha256(
    JsonObject(
        linkedMapOf(
            "device" to JsonPrimitive(identity.key.device),
            "gid" to JsonPrimitive(identity.gid),
            "inode" to JsonPrimitive(identity.key.inode),
            "linkCount" to JsonPrimitive(identity.linkCount),
            "mode" to JsonPrimitive(identity.mode),
            "mountId" to JsonPrimitive(identity.mountId),
            "uid" to JsonPrimitive(identity.uid),
        ),
    ),
)

private fun canonicalIdentitySha256(value: JsonObject): String =
    OracleArtifacts.sha256(OracleJson.canonicalBytes(value, IDENTITY_JSON_LIMITS))

private fun pathCommitment(path: Path): String = OracleArtifacts.sha256(path.toString().encodeToByteArray())

private inline fun <T> translateBindingFailures(label: String, action: () -> T): T = try {
    action()
} catch (failure: PinnedDockerRuntimeBindingsException) {
    throw failure
} catch (failure: Exception) {
    bindingFail("cannot $label", failure)
}

private fun bindingFail(message: String, cause: Throwable? = null): Nothing =
    throw PinnedDockerRuntimeBindingsException(message, cause)

private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte) }

private val SHA256 = Regex("[0-9a-f]{64}")
private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val OWNER_EXECUTE = 0x40
private const val UNTRUSTED_WRITE_PERMISSIONS = 0x12 // group/other write
private const val OWNER_SOCKET_PERMISSIONS = 0x180 // 0600
private const val SPECIAL_MODE_BITS = 0xe00 // setuid, setgid, sticky
private const val FILE_TYPE_MASK = 0xf000
private const val SOCKET_FILE_TYPE = 0xc000
private val IDENTITY_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 1024 * 1024,
    maximumCanonicalBytes = 1024 * 1024,
    maximumDepth = 32,
    maximumNodes = 20_000,
    maximumStringBytes = 256 * 1024,
    maximumTotalStringBytes = 1024 * 1024,
)

private fun currentUid(): Int =
    (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
