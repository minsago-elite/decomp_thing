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
import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import java.io.OutputStream
import java.lang.reflect.InvocationTargetException
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFileAttributes
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.TimeUnit
import jdk.net.ExtendedSocketOptions
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class PinnedDockerRuntimeBindingsException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Retained identity binding for exactly one private Docker Unix endpoint.
 *
 * This owner exposes no pathname, control client, Docker config, environment, command, byte
 * transport, request, HTTP, build, CREATE, or START operation. The sealed fixed Engine coordinator
 * can consume it once through an internal typed bridge which rechecks the named socket immediately
 * around connect; this binding alone is not usable Engine authority.
 */
internal sealed interface PinnedDockerEndpointBinding : AutoCloseable {
    fun requireCurrent()

    override fun close()
}

/**
 * Non-operational endpoint ownership after the private fixed Docker Engine v1.55 preflight.
 * No operation-bearing transport owner escapes the exact endpoint-plus-fresh-lease coordinator.
 */
internal sealed interface PinnedDockerEngineV155VerifiedEndpointOwner : AutoCloseable {
    fun requireCurrent()

    override fun close()
}

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
    private val endpointState: PinnedDockerEndpointState,
) : AutoCloseable {
    private var closed = false
    private var ownsEndpointState = true

    @Synchronized
    fun requireCurrent() = translateBindingFailures("verify pinned Docker runtime bindings") {
        requireOpen()
        requireCurrentBindings()
    }

    /**
     * Irreversibly narrows these CLI bindings to their retained private endpoint identity.
     *
     * Transfer succeeds only after a terminal check of every binding. It closes the executable,
     * executable guard, and Docker-config descriptors before returning, and this object becomes
     * unusable. The returned owner exposes only currentness and close while privately retaining the
     * socket pathname and the parent/socket identity descriptors.
     */
    @Synchronized
    fun retainEndpointBinding(): PinnedDockerEndpointBinding =
        translateBindingFailures("retain pinned Docker endpoint binding") {
            requireOpen()
            requireCurrentBindings()
            try {
                closeControlBindings()
            } catch (failure: Throwable) {
                closed = true
                ownsEndpointState = false
                endpointState.close()
                throw failure
            }
            ownsEndpointState = false
            closed = true
            try {
                val constructor = BoundPinnedDockerEndpointBinding::class.java
                    .getDeclaredConstructor(PinnedDockerEndpointState::class.java)
                check(constructor.trySetAccessible())
                constructor.newInstance(endpointState)
            } catch (failure: Throwable) {
                endpointState.close()
                throw failure
            }
        }

    private fun requireCurrentBindings() {
        requireCurrentControlClient()
        requireCurrentDockerConfig()
        endpointState.requireCurrent()
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

    private fun requireOpen() {
        if (closed) bindingFail("pinned Docker runtime bindings are closed or transferred")
    }

    private fun closeControlBindings() {
        dockerConfigDescriptor.close()
        controlClientDescriptor.close()
        controlClientGuard.close()
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        if (ownsEndpointState) endpointState.close()
        ownsEndpointState = false
        closeControlBindings()
    }

    companion object {
        /**
         * Consumes the endpoint and untouched fresh lease together, performs the private one-shot
         * preflight, and returns only the final non-operational Engine owner.
         */
        private fun openHostedToolchainImageEngineV1(
            binding: PinnedDockerEndpointBinding,
            freshLeaseOwner: LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner,
        ): LlvmBehaviorHostedToolchainImageEngineV1Owner {
            val retained = binding as? BoundPinnedDockerEndpointBinding
                ?: bindingFail("retained Docker endpoint binding is not owned here")
            var state: PinnedDockerEndpointState? = null
            var endpoint: PinnedDockerEngineV155VerifiedEndpointOwner? = null
            var lease: LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner? = null
            try {
                val consumeEndpoint = BoundPinnedDockerEndpointBinding::class.java.declaredMethods
                    .single { it.name == "consumeForFixedEngineV155" }
                check(consumeEndpoint.trySetAccessible())
                val consumedState = try {
                    consumeEndpoint.invoke(retained) as PinnedDockerEndpointState
                } catch (failure: InvocationTargetException) {
                    throw failure.targetException
                }
                state = consumedState
                val consumeLease = LlvmBehaviorHostedToolchainImageBuildLeaseV2::class.java
                    .declaredMethods
                    .single { it.name == "consumeFreshForHostedToolchainImageEngineV1" }
                check(consumeLease.trySetAccessible())
                val consumedLease = try {
                    consumeLease.invoke(
                        LlvmBehaviorHostedToolchainImageBuildLeaseV2,
                        freshLeaseOwner,
                    ) as LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner
                } catch (failure: InvocationTargetException) {
                    throw failure.targetException
                }
                lease = consumedLease
                consumedLease.requireCurrentBinding()
                val headPing = PinnedDockerEndpointState::class.java.declaredMethods
                    .single { it.name == "requireFixedHeadPing" }
                check(headPing.trySetAccessible())
                try {
                    headPing.invoke(consumedState)
                } catch (failure: InvocationTargetException) {
                    throw failure.targetException
                }
                consumedState.requireCurrent()
                consumedLease.requireCurrentBinding()
                val verifiedConstructor = BoundPinnedDockerEngineV155VerifiedEndpointOwner::class.java
                    .getDeclaredConstructor(PinnedDockerEndpointState::class.java)
                check(verifiedConstructor.trySetAccessible())
                val verifiedEndpoint = try {
                    verifiedConstructor.newInstance(consumedState)
                } catch (failure: InvocationTargetException) {
                    throw failure.targetException
                }
                endpoint = verifiedEndpoint
                state = null
                val retainEngine = LlvmBehaviorHostedToolchainImageEngineV1::class.java
                    .declaredMethods
                    .single { it.name == "retainVerified" }
                check(retainEngine.trySetAccessible())
                val engineOwner = try {
                    retainEngine.invoke(
                        LlvmBehaviorHostedToolchainImageEngineV1,
                        verifiedEndpoint,
                        consumedLease,
                    ) as LlvmBehaviorHostedToolchainImageEngineV1Owner
                } catch (failure: InvocationTargetException) {
                    throw failure.targetException
                }
                endpoint = null
                lease = null
                return engineOwner
            } catch (failure: Throwable) {
                runCatching { endpoint?.close() }
                runCatching { state?.close() }
                runCatching { lease?.close() }
                throw failure
            } finally {
                runCatching { binding.close() }
                runCatching { freshLeaseOwner.close() }
            }
        }

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
                val socketIdentitySha256 = identityCommitment(socketIdentity)
                val socketParentIdentitySha256 = identityCommitment(socketParentIdentity)
                val socketPathSha256 = pathCommitment(runtimeSocketPath)
                val socketMode = "0o${socketIdentity.mode.permissions.toString(8).padStart(3, '0')}"
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
                    runtimeSocketIdentitySha256 = socketIdentitySha256,
                    runtimeSocketParentIdentitySha256 = socketParentIdentitySha256,
                    runtimeSocketPathSha256 = socketPathSha256,
                    runtimeSocketMode = socketMode,
                    controlClientPath = controlClientPath,
                    controlClientIdentity = clientIdentity,
                    controlClientGuard = guard,
                    controlClientDescriptor = openedClient,
                    dockerConfigPath = dockerConfigPath,
                    dockerConfigIdentity = configIdentity,
                    dockerConfigDescriptor = openedConfig,
                    endpointState = PinnedDockerEndpointState::class.java.getDeclaredConstructor(
                        Path::class.java,
                        LinuxDescriptor::class.java,
                        LinuxDescriptor::class.java,
                        LinuxFileIdentity::class.java,
                        LinuxFileIdentity::class.java,
                    ).also { constructor -> check(constructor.trySetAccessible()) }.newInstance(
                        runtimeSocketPath,
                        openedSocketParent,
                        openedSocket,
                        socketParentIdentity,
                        socketIdentity,
                    ),
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

private class BoundPinnedDockerEndpointBinding private constructor(
    initial: PinnedDockerEndpointState,
) : PinnedDockerEndpointBinding {
    private var state: PinnedDockerEndpointState? = initial
    private var closed = false
    private var poisoned = false
    private var transferred = false

    @Synchronized
    override fun requireCurrent() = translateBindingFailures(
        "verify retained Docker endpoint binding",
    ) {
        val owned = currentState()
        try {
            owned.requireCurrent()
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    @Synchronized
    private fun consumeForFixedEngineV155(): PinnedDockerEndpointState {
        val owned = currentState()
        try {
            owned.requireCurrent()
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
        state = null
        transferred = true
        return owned
    }

    private fun currentState(): PinnedDockerEndpointState {
        if (closed) bindingFail("retained Docker endpoint binding is closed")
        if (transferred) bindingFail("retained Docker endpoint binding was transferred")
        if (poisoned) bindingFail("retained Docker endpoint binding is poisoned")
        return checkNotNull(state) { "retained Docker endpoint binding has no endpoint state" }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        val owned = state
        state = null
        owned?.close()
    }
}

private class BoundPinnedDockerEngineV155VerifiedEndpointOwner private constructor(
    private val state: PinnedDockerEndpointState,
) : PinnedDockerEngineV155VerifiedEndpointOwner {
    private var closed = false
    private var poisoned = false

    @Synchronized
    override fun requireCurrent() = guarded("verify fixed Docker Engine endpoint") {
        state.requireCurrent()
    }

    private inline fun guarded(label: String, action: () -> Unit) =
        translateBindingFailures(label) {
            if (closed) bindingFail("fixed Docker Engine endpoint owner is closed")
            if (poisoned) bindingFail("fixed Docker Engine endpoint owner is poisoned")
            try {
                action()
            } catch (failure: Throwable) {
                poisoned = true
                throw failure
            }
        }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        state.close()
    }
}

private class PinnedDockerEndpointState private constructor(
    private val runtimeSocketPath: Path,
    private val runtimeSocketParent: LinuxDescriptor,
    private val runtimeSocketDescriptor: LinuxDescriptor,
    private val runtimeSocketParentIdentity: LinuxFileIdentity,
    private val runtimeSocketIdentity: LinuxFileIdentity,
) : AutoCloseable {
    private var closed = false
    private var headPingAttempted = false

    @Synchronized
    fun requireCurrent() {
        if (closed) bindingFail("retained Docker endpoint descriptors are closed")
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

    /** The only request operation in the private endpoint implementation. */
    @Synchronized
    private fun requireFixedHeadPing() {
        if (closed) bindingFail("retained Docker endpoint descriptors are closed")
        if (headPingAttempted) bindingFail("fixed Docker Engine HEAD /_ping was already attempted")
        headPingAttempted = true
        requireCurrent()

        EndpointDirectoryMutationWatch.open(runtimeSocketParent).use { mutationWatch ->
            try {
                // Registration is descriptor-relative and precedes the last currentness check
                // before connect. Do not drain a baseline: every queued mutation is hostile.
                requireCurrent()
                mutationWatch.requireQuiet()
                val deadline = FixedHeadPingDeadline.start()
                SocketChannel.open(StandardProtocolFamily.UNIX).use { channel ->
                    Selector.open().use { selector ->
                        channel.configureBlocking(false)
                        val key = channel.register(selector, SelectionKey.OP_CONNECT)
                        deadline.requireRemaining("connect")
                        requireCurrent()
                        mutationWatch.requireQuiet()
                        val connected = channel.connect(UnixDomainSocketAddress.of(runtimeSocketPath))
                        if (!connected) {
                            while (true) {
                                mutationWatch.requireQuiet()
                                deadline.requireRemaining("connect")
                                if (channel.finishConnect()) break
                                deadline.await(selector, mutationWatch, "connect")
                            }
                        }

                        // The native queue closes a transient swap-and-restore race which endpoint
                        // identity sampling and same-UID SO_PEERCRED cannot detect on their own.
                        mutationWatch.requireQuiet()
                        requireCurrent()
                        mutationWatch.requireQuiet()
                        requireCurrentUserPeer(channel)

                        key.interestOps(SelectionKey.OP_WRITE)
                        val request = ByteBuffer.wrap(
                            FIXED_HEAD_PING_REQUEST_TEXT.toByteArray(StandardCharsets.US_ASCII),
                        )
                        while (request.hasRemaining()) {
                            mutationWatch.requireQuiet()
                            deadline.requireRemaining("write request")
                            if (channel.write(request) == 0) {
                                deadline.await(selector, mutationWatch, "write request")
                            }
                        }

                        key.interestOps(SelectionKey.OP_READ)
                        val response = ByteArray(FIXED_HEAD_PING_RESPONSE_BYTES)
                        var responseBytes = 0
                        val readBuffer = ByteBuffer.allocate(FIXED_HEAD_PING_READ_BUFFER_BYTES)
                        while (true) {
                            mutationWatch.requireQuiet()
                            deadline.requireRemaining("read response")
                            readBuffer.clear()
                            val read = channel.read(readBuffer)
                            if (read < 0) break
                            if (read == 0) {
                                deadline.await(selector, mutationWatch, "read response")
                                continue
                            }
                            if (responseBytes + read > response.size) {
                                bindingFail("fixed Docker Engine HEAD /_ping response exceeds its byte ceiling")
                            }
                            readBuffer.flip()
                            readBuffer.get(response, responseBytes, read)
                            responseBytes += read
                        }

                        // EOF is required framing. Mutations are checked on both sides of the
                        // terminal name/descriptor check so no accepted response spans an event.
                        deadline.requireRemaining("complete response")
                        mutationWatch.requireQuiet()
                        requireCurrent()
                        mutationWatch.requireQuiet()
                        requireFixedHeadPingResponse(response, responseBytes)
                        mutationWatch.requireQuiet()
                    }
                }
            } catch (failure: Throwable) {
                // If an I/O error raced a directory mutation, report the mutation as the primary
                // failure instead of accidentally treating the transport error as sufficient.
                try {
                    mutationWatch.requireQuiet()
                } catch (mutationFailure: Throwable) {
                    mutationFailure.addSuppressed(failure)
                    throw mutationFailure
                }
                throw failure
            }
        }
    }

    private fun requireCurrentUserPeer(channel: SocketChannel) {
        val peer = try {
            if (ExtendedSocketOptions.SO_PEERCRED !in channel.supportedOptions()) {
                bindingFail("SO_PEERCRED is unavailable for the fixed Docker Engine endpoint")
            }
            channel.getOption(ExtendedSocketOptions.SO_PEERCRED)
                ?: bindingFail("SO_PEERCRED returned no Docker Engine peer")
        } catch (failure: PinnedDockerRuntimeBindingsException) {
            throw failure
        } catch (failure: Exception) {
            bindingFail("cannot authenticate the fixed Docker Engine peer with SO_PEERCRED", failure)
        }
        val socketOwner = try {
            Files.readAttributes(
                runtimeSocketPath,
                PosixFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            ).owner()
        } catch (failure: Exception) {
            bindingFail("cannot re-read the fixed Docker Engine socket owner", failure)
        }
        if (peer.user() != socketOwner) {
            bindingFail("SO_PEERCRED user differs from the pinned Docker Engine socket owner")
        }
    }

    private fun requireFixedHeadPingResponse(response: ByteArray, responseBytes: Int) {
        if (responseBytes !in 1..FIXED_HEAD_PING_RESPONSE_BYTES) {
            bindingFail("fixed Docker Engine HEAD /_ping response has an invalid byte length")
        }
        var lineBytes = 0
        for (index in 0 until responseBytes) {
            val value = response[index].toInt() and 0xff
            when {
                value == '\r'.code -> {
                    if (index + 1 >= responseBytes || (response[index + 1].toInt() and 0xff) != '\n'.code) {
                        bindingFail("fixed Docker Engine HEAD /_ping response contains a bare carriage return")
                    }
                }
                value == '\n'.code -> {
                    if (index == 0 || (response[index - 1].toInt() and 0xff) != '\r'.code) {
                        bindingFail("fixed Docker Engine HEAD /_ping response contains a bare line feed")
                    }
                    if (lineBytes > FIXED_HEAD_PING_LINE_BYTES) {
                        bindingFail("fixed Docker Engine HEAD /_ping response line exceeds its byte ceiling")
                    }
                    lineBytes = 0
                }
                value !in 0x20..0x7e ->
                    bindingFail("fixed Docker Engine HEAD /_ping response contains a non-ASCII control byte")
                else -> lineBytes += 1
            }
        }
        val text = String(response, 0, responseBytes, StandardCharsets.US_ASCII)
        val delimiter = text.indexOf("\r\n\r\n")
        if (delimiter < 0 || delimiter + 4 != text.length) {
            bindingFail("fixed Docker Engine HEAD /_ping response has invalid header or body framing")
        }
        val lines = text.substring(0, delimiter).split("\r\n")
        if (lines.isEmpty() || lines.first() != FIXED_HEAD_PING_STATUS) {
            bindingFail("fixed Docker Engine HEAD /_ping response status differs from HTTP/1.1 200 OK")
        }
        val expected = mapOf(
            "Api-Version" to "1.55",
            "Builder-Version" to "2",
            "Cache-Control" to "no-cache, no-store, must-revalidate",
            "Connection" to "close",
            "Content-Length" to "0",
            "Content-Type" to "text/plain; charset=utf-8",
            "Date" to "",
            "Docker-Experimental" to "false",
            "Ostype" to "linux",
            "Pragma" to "no-cache",
            "Server" to "Docker/29.7.2 (linux)",
            "Swarm" to "inactive",
        )
        if (lines.size - 1 != expected.size) {
            bindingFail("fixed Docker Engine HEAD /_ping response has an unexpected header count")
        }
        val actual = linkedMapOf<String, String>()
        val headerName = Regex("[A-Za-z0-9!#$%&'*+.^_`|~-]+")
        val imfFixdate = Regex(
            "(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} " +
                "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} " +
                "[0-9]{2}:[0-9]{2}:[0-9]{2} GMT",
        )
        lines.drop(1).forEach { line ->
            if (line.startsWith(' ') || line.startsWith('\t')) {
                bindingFail("fixed Docker Engine HEAD /_ping response contains folded headers")
            }
            val colon = line.indexOf(':')
            if (colon <= 0 || colon + 2 > line.length || line[colon + 1] != ' ') {
                bindingFail("fixed Docker Engine HEAD /_ping response contains malformed header framing")
            }
            val name = line.substring(0, colon)
            val value = line.substring(colon + 2)
            if (!name.matches(headerName) || value.isEmpty() || value.first() == ' ' || value.last() == ' ') {
                bindingFail("fixed Docker Engine HEAD /_ping response contains a malformed header")
            }
            if (actual.put(name, value) != null) {
                bindingFail("fixed Docker Engine HEAD /_ping response contains a duplicate header")
            }
        }
        if (actual.keys != expected.keys) {
            bindingFail("fixed Docker Engine HEAD /_ping response contains an unexpected header name")
        }
        expected.forEach { (name, expectedValue) ->
            val value = actual.getValue(name)
            if (name == "Date") {
                if (!value.matches(imfFixdate)) {
                    bindingFail("fixed Docker Engine HEAD /_ping response Date header is malformed")
                }
            } else if (value != expectedValue) {
                bindingFail("fixed Docker Engine HEAD /_ping response $name policy differs")
            }
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        runCatching { runtimeSocketDescriptor.close() }.exceptionOrNull()?.let { failure = it }
        runCatching { runtimeSocketParent.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        failure?.let { throw it }
    }

    private class FixedHeadPingDeadline private constructor(
        private val startedNanos: Long,
        private val durationNanos: Long,
    ) {
        fun requireRemaining(phase: String): Long {
            val elapsed = System.nanoTime() - startedNanos
            val remaining = durationNanos - elapsed
            if (remaining <= 0L) {
                bindingFail("fixed Docker Engine HEAD /_ping $phase exceeded its absolute deadline")
            }
            return remaining
        }

        fun await(selector: Selector, mutationWatch: EndpointDirectoryMutationWatch, phase: String) {
            while (true) {
                mutationWatch.requireQuiet()
                val remaining = requireRemaining(phase)
                val timeoutMillis = minOf(
                    MAXIMUM_SELECTOR_WAIT_MILLISECONDS,
                    maxOf(1L, (remaining + NANOS_PER_MILLISECOND - 1L) / NANOS_PER_MILLISECOND),
                )
                val selected = selector.select(timeoutMillis)
                mutationWatch.requireQuiet()
                if (selected > 0) {
                    selector.selectedKeys().clear()
                    return
                }
            }
        }

        companion object {
            fun start(): FixedHeadPingDeadline = FixedHeadPingDeadline(
                System.nanoTime(),
                TimeUnit.MILLISECONDS.toNanos(FIXED_HEAD_PING_TIMEOUT_MILLISECONDS),
            )
        }
    }

    private class EndpointDirectoryMutationWatch private constructor(
        private val libc: InotifyLibC,
        private var descriptor: Int,
    ) : AutoCloseable {
        fun requireQuiet() {
            val buffer = Memory(INOTIFY_READ_BYTES.toLong())
            while (true) {
                val count = libc.read(descriptor, buffer, NativeLong(INOTIFY_READ_BYTES.toLong())).toLong()
                val error = if (count < 0L) Native.getLastError() else 0
                when {
                    count > 0L -> bindingFail(
                        "fixed Docker Engine socket directory mutated during HEAD /_ping",
                    )
                    count == 0L -> bindingFail(
                        "fixed Docker Engine socket directory watch ended during HEAD /_ping",
                    )
                    error == EINTR -> continue
                    error == EAGAIN -> return
                    else -> bindingFail(
                        "cannot read the fixed Docker Engine socket directory watch (errno=$error)",
                    )
                }
            }
        }

        override fun close() {
            val owned = descriptor
            if (owned < 0) return
            var quietFailure: Throwable? = null
            try {
                requireQuiet()
            } catch (failure: Throwable) {
                quietFailure = failure
            }
            descriptor = -1
            val closeResult = libc.close(owned)
            if (quietFailure != null) {
                if (closeResult != 0) {
                    quietFailure.addSuppressed(
                        IllegalStateException(
                            "cannot close inotify descriptor (errno=${Native.getLastError()})",
                        ),
                    )
                }
                throw quietFailure
            }
            if (closeResult != 0) {
                bindingFail(
                    "cannot close the fixed Docker Engine socket directory watch " +
                        "(errno=${Native.getLastError()})",
                )
            }
        }

        companion object {
            fun open(parent: LinuxDescriptor): EndpointDirectoryMutationWatch {
                val libc = Native.load(Platform.C_LIBRARY_NAME, InotifyLibC::class.java)
                val descriptor = libc.inotify_init1(O_NONBLOCK or O_CLOEXEC)
                if (descriptor < 0) {
                    bindingFail(
                        "cannot open the fixed Docker Engine socket directory watch " +
                            "(errno=${Native.getLastError()})",
                    )
                }
                try {
                    val watched = libc.inotify_add_watch(
                        descriptor,
                        LinuxFilesystemSyscalls.stableDescriptorPath(parent.fd).toString(),
                        IN_ONLYDIR or IN_ATTRIB or IN_MODIFY or IN_CLOSE_WRITE or IN_MOVED_FROM or
                            IN_MOVED_TO or IN_CREATE or IN_DELETE or IN_DELETE_SELF or IN_MOVE_SELF,
                    )
                    if (watched < 0) {
                        bindingFail(
                            "cannot register the fixed Docker Engine socket directory watch " +
                                "(errno=${Native.getLastError()})",
                        )
                    }
                    return EndpointDirectoryMutationWatch(libc, descriptor)
                } catch (failure: Throwable) {
                    libc.close(descriptor)
                    throw failure
                }
            }
        }
    }

    private interface InotifyLibC : Library {
        fun inotify_init1(flags: Int): Int
        fun inotify_add_watch(descriptor: Int, path: String, mask: Int): Int
        fun read(descriptor: Int, buffer: Memory, count: NativeLong): NativeLong
        fun close(descriptor: Int): Int
    }

    companion object {
        private const val FIXED_HEAD_PING_REQUEST_TEXT =
            "HEAD /_ping HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
        private const val FIXED_HEAD_PING_STATUS = "HTTP/1.1 200 OK"
        private const val FIXED_HEAD_PING_TIMEOUT_MILLISECONDS = 2_000L
        private const val FIXED_HEAD_PING_RESPONSE_BYTES = 4 * 1024
        private const val FIXED_HEAD_PING_READ_BUFFER_BYTES = 512
        private const val FIXED_HEAD_PING_LINE_BYTES = 512
        private const val NANOS_PER_MILLISECOND = 1_000_000L
        private const val MAXIMUM_SELECTOR_WAIT_MILLISECONDS = 100L
        private const val INOTIFY_READ_BYTES = 4 * 1024
        private const val O_NONBLOCK = 0x800
        private const val O_CLOEXEC = 0x80000
        private const val EAGAIN = 11
        private const val EINTR = 4
        private const val IN_MODIFY = 0x00000002
        private const val IN_ATTRIB = 0x00000004
        private const val IN_CLOSE_WRITE = 0x00000008
        private const val IN_MOVED_FROM = 0x00000040
        private const val IN_MOVED_TO = 0x00000080
        private const val IN_CREATE = 0x00000100
        private const val IN_DELETE = 0x00000200
        private const val IN_DELETE_SELF = 0x00000400
        private const val IN_MOVE_SELF = 0x00000800
        private const val IN_ONLYDIR = 0x01000000
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
