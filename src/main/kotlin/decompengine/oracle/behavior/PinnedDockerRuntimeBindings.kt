package decompengine.oracle.behavior

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.analysis.AnalysisDeadline
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
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import java.io.OutputStream
import java.io.InputStream
import java.io.ByteArrayOutputStream
import java.io.BufferedInputStream
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
import kotlinx.serialization.json.JsonArray

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
    private var nativeMeasurementTerminalFailed = false

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

    private fun requireCurrentBindings(checkpoint: (String) -> Unit = {}) {
        checkpoint("before pinned Docker binding terminal authentication")
        requireCurrentControlClient(checkpoint)
        requireCurrentDockerConfig()
        endpointState.requireCurrent()
        checkpoint("after pinned Docker binding terminal authentication")
    }

    private fun requireCurrentControlClient(checkpoint: (String) -> Unit) {
        val pinned = LinuxFilesystemSyscalls.identity(controlClientDescriptor.fd)
        if (pinned != controlClientIdentity || !pinned.isRegularFile || pinned.isSymbolicLink) {
            bindingFail("pinned runtime control-client descriptor changed")
        }
        val pinnedAuthentication = authenticatePinnedControlClient(
            controlClientDescriptor,
            controlClientBytes,
            "runtime control-client terminal authentication",
            checkpoint,
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
        var failure: Throwable? = null
        if (ownsEndpointState) runCatching { endpointState.close() }.exceptionOrNull()?.let { failure = it }
        ownsEndpointState = false
        listOf(dockerConfigDescriptor, controlClientDescriptor, controlClientGuard).forEach { owned ->
            runCatching { owned.close() }.exceptionOrNull()?.let { closeFailure ->
                failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
            }
        }
        failure?.let { throw it }
    }

    /** Retains every binding across the fixed read-only measurement without exporting endpoint state. */
    @Synchronized
    private fun measureNativeRuntimeV2Owned(
        image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
        deadline: AnalysisDeadline,
    ): JsonObject {
        requireOpen()
        deadline.checkpoint("before fixed native runtime measurement")
        requireCurrentBindings(deadline::checkpoint)
        image.requireCurrent(deadline::checkpoint)
        val measure = PinnedDockerEndpointState::class.java.declaredMethods.single {
            it.name == "measureNativeRuntimeV2"
        }
        check(measure.trySetAccessible())
        val facts = try {
            measure.invoke(endpointState, image, deadline) as JsonObject
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
        image.requireCurrent(deadline::checkpoint)
        requireCurrentBindings(deadline::checkpoint)
        deadline.checkpoint("after fixed native runtime measurement terminal checks")
        return JsonObject(facts + linkedMapOf(
            "controlClientBytes" to JsonPrimitive(controlClientBytes),
            "controlClientSha256" to JsonPrimitive(controlClientSha256),
            "controlClientIdentitySha256" to JsonPrimitive(controlClientIdentitySha256),
            "dockerConfigIdentitySha256" to JsonPrimitive(dockerConfigIdentitySha256),
            "runtimeSocketIdentitySha256" to JsonPrimitive(runtimeSocketIdentitySha256),
            "runtimeSocketParentIdentitySha256" to JsonPrimitive(runtimeSocketParentIdentitySha256),
        ))
    }

    @Synchronized
    private fun verifyNativeRuntimeV2TerminalOwned(deadline: AnalysisDeadline) {
        requireOpen()
        if (nativeMeasurementTerminalFailed) bindingFail("native runtime terminal authentication is poisoned")
        val verify = PinnedDockerEndpointState::class.java.declaredMethods.single {
            it.name == "requireNativeMeasurementQuiet"
        }
        check(verify.trySetAccessible())
        fun requireQuiet() {
            try {
                verify.invoke(endpointState, deadline)
            } catch (failure: InvocationTargetException) {
                throw failure.targetException
            }
        }
        try {
            requireQuiet()
            requireCurrentBindings(deadline::checkpoint)
            requireQuiet()
            deadline.checkpoint("after final native runtime tuple authentication")
        } catch (failure: Throwable) {
            nativeMeasurementTerminalFailed = true
            throw failure
        }
    }

    companion object {
        /** Measurement alone consumes no lease and cannot arm an operational journal. */
        private fun measureNativeRuntimeV2(
            bindings: PinnedDockerRuntimeBindings,
            image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
            deadline: AnalysisDeadline,
        ): JsonObject {
            // A direct companion field read would emit a public JVM accessor for the retained endpoint.
            val measure = PinnedDockerRuntimeBindings::class.java.declaredMethods.single {
                it.name == "measureNativeRuntimeV2Owned"
            }
            check(measure.trySetAccessible())
            return try {
                measure.invoke(bindings, image, deadline) as JsonObject
            } catch (failure: InvocationTargetException) {
                throw failure.targetException
            }
        }

        private fun verifyNativeRuntimeV2Terminal(
            bindings: PinnedDockerRuntimeBindings,
            deadline: AnalysisDeadline,
        ) {
            val verify = PinnedDockerRuntimeBindings::class.java.declaredMethods.single {
                it.name == "verifyNativeRuntimeV2TerminalOwned"
            }
            check(verify.trySetAccessible())
            try {
                verify.invoke(bindings, deadline)
            } catch (failure: InvocationTargetException) {
                throw failure.targetException
            }
        }

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
        ): PinnedDockerRuntimeBindings = captureWithCheckpoint(
            controlClientPath, expectedControlClientBytes, expectedControlClientSha256, maximumControlClientBytes,
            dockerConfigPath, runtimeSocketPath, {}, false,
        )

        private fun captureForNativeRuntimeV2(
            controlClientPath: Path,
            dockerConfigPath: Path,
            runtimeSocketPath: Path,
            deadline: AnalysisDeadline,
        ): PinnedDockerRuntimeBindings = captureWithCheckpoint(
            controlClientPath, 42_677_472L,
            "e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13",
            42_677_472L, dockerConfigPath, runtimeSocketPath, deadline::checkpoint, false,
        )

        /** Opt-in kernel listener continuity; legacy capture deliberately keeps its old profile. */
        private fun captureForNativeRuntimeV3(
            controlClientPath: Path,
            dockerConfigPath: Path,
            runtimeSocketPath: Path,
            deadline: AnalysisDeadline,
        ): PinnedDockerRuntimeBindings = captureWithCheckpoint(
            controlClientPath, 42_677_472L,
            "e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13",
            42_677_472L, dockerConfigPath, runtimeSocketPath, deadline::checkpoint, true,
        )

        private fun captureWithCheckpoint(
            controlClientPath: Path,
            expectedControlClientBytes: Long,
            expectedControlClientSha256: String,
            maximumControlClientBytes: Long,
            dockerConfigPath: Path,
            runtimeSocketPath: Path,
            checkpoint: (String) -> Unit,
            listenerContinuity: Boolean,
        ): PinnedDockerRuntimeBindings = translateBindingFailures("capture pinned Docker runtime bindings") {
            checkpoint("before pinned Docker runtime binding capture")
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
            val guard = StableControlFile.openWithCheckpoint(
                controlClientPath,
                maximumControlClientBytes,
                "runtime control client",
                checkpoint,
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
                    checkpoint,
                )
                if (
                    pinnedAuthentication.bytes != expectedControlClientBytes ||
                    pinnedAuthentication.sha256 != expectedControlClientSha256
                ) {
                    bindingFail("runtime control-client bytes differ from authenticated evidence")
                }
                val guardSha256 = guard.sha256(checkpoint, label = "runtime control client path guard")
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
                checkpoint("after pinned Docker client and endpoint capture")

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
                        Boolean::class.javaPrimitiveType,
                    ).also { constructor -> check(constructor.trySetAccessible()) }.newInstance(
                        runtimeSocketPath,
                        openedSocketParent,
                        openedSocket,
                        socketParentIdentity,
                        socketIdentity,
                        listenerContinuity,
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
    private val listenerContinuity: Boolean,
) : AutoCloseable {
    private var closed = false
    private var listenerAnchor: ListenerSnapshot? = null
    private var listenerExchanges = 0
    private var headPingAttempted = false
    private var nativeMeasurementWatch: EndpointDirectoryMutationWatch? = null
    private var nativeMeasurementCompleted = false

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
    private fun requireFixedHeadPing() = performFixedHeadPing(FixedHeadPingDeadline.start())

    private fun performFixedHeadPing(deadline: FixedHeadPingDeadline) {
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
                if (listenerContinuity) {
                    performListenerHeadPing(deadline, mutationWatch)
                    return@use
                }
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

    /** Linux reports the listening socket's credential snapshot, not the HTTP responder. */
    private data class ListenerCredentials(val pid: Int, val uid: Long, val gid: Long)

    private interface ListenerLibC : Library {
        fun socket(domain: Int, type: Int, protocol: Int): Int
        fun connect(fd: Int, address: Pointer, length: Int): Int
        fun getsockopt(fd: Int, level: Int, option: Int, value: Pointer, length: IntByReference): Int
        fun send(fd: Int, buffer: Pointer, count: NativeLong, flags: Int): NativeLong
        fun recv(fd: Int, buffer: Pointer, count: NativeLong, flags: Int): NativeLong
        fun poll(descriptors: Pointer?, count: NativeLong, timeout: Int): Int
        fun fcntl(fd: Int, command: Int): Int
        fun close(fd: Int): Int
    }

    /** Retire ownership before close: an EINTR result must never cause a reused fd to be closed. */
    private class ListenerDescriptor(private val libc: ListenerLibC, descriptor: Int) : AutoCloseable {
        private var descriptor = descriptor
        fun fd(): Int = descriptor.takeIf { it >= 0 } ?: bindingFail("listener descriptor is closed")
        fun requireCloseOnExec() {
            val flags = libc.fcntl(fd(), 1 /* F_GETFD */)
            if (flags < 0 || flags and 1 == 0) bindingFail("listener descriptor lacks FD_CLOEXEC")
        }
        fun requireAlive() {
            Memory(8).use { pollfd ->
                pollfd.clear()
                pollfd.setInt(0, fd())
                pollfd.setShort(4, 1 /* POLLIN */)
                val result = libc.poll(pollfd, NativeLong(1), 0)
                if (result < 0) {
                    if (Native.getLastError() == EINTR) bindingFail("listener liveness probe was interrupted")
                    bindingFail("cannot probe retained listener pidfd (errno=${Native.getLastError()})")
                }
                if (result != 0 || pollfd.getShort(6).toInt() != 0) {
                    bindingFail("retained kernel listener exited or its pidfd is invalid")
                }
            }
        }
        override fun close() {
            val owned = descriptor
            if (owned < 0) return
            descriptor = -1
            if (libc.close(owned) != 0) bindingFail("cannot close listener descriptor (errno=${Native.getLastError()})")
        }
    }

    private class ListenerSnapshot(val credentials: ListenerCredentials, private val pidfd: ListenerDescriptor) : AutoCloseable {
        fun requireAlive() = pidfd.requireAlive()
        override fun close() = pidfd.close()
    }

    private fun requireListenerAlive() {
        if (listenerContinuity) {
            val anchor = listenerAnchor ?: bindingFail("strict native measurement lacks its retained kernel listener")
            anchor.requireAlive()
        }
    }

    private fun listenerFacts(): JsonObject {
        requireListenerAlive()
        if (listenerExchanges != 5) bindingFail("strict native measurement did not complete its five listener exchanges")
        val peer = listenerAnchor!!.credentials
        return JsonObject(linkedMapOf(
            "schemaVersion" to JsonPrimitive(1),
            "identityKind" to JsonPrimitive("linux-af-unix-listener-credential-snapshot"),
            "pid" to JsonPrimitive(peer.pid), "uid" to JsonPrimitive(peer.uid), "gid" to JsonPrimitive(peer.gid),
            "identifierNamespace" to JsonPrimitive("observer"),
            "peerHandleMechanism" to JsonPrimitive("SO_PEERPIDFD"),
            "fixedExchangeCount" to JsonPrimitive(5),
            "sameListenerSnapshot" to JsonPrimitive(true),
            "retentionBoundary" to JsonPrimitive("final-factory-guard"),
            "daemonExecutableApproved" to JsonPrimitive(false),
            "httpResponderIdentityProved" to JsonPrimitive(false),
        ))
    }

    private fun listenerLibC(): ListenerLibC {
        if (!Platform.isLinux() || Native.POINTER_SIZE != 8 || NativeLong.SIZE != 8) {
            bindingFail("kernel listener continuity requires the Linux LP64 profile")
        }
        return Native.load(Platform.C_LIBRARY_NAME, ListenerLibC::class.java)
    }

    private fun readListenerCredentials(libc: ListenerLibC, fd: Int): ListenerCredentials = Memory(12).use { value ->
        value.clear()
        val length = IntByReference(12)
        if (libc.getsockopt(fd, 1 /* SOL_SOCKET */, 17 /* SO_PEERCRED */, value, length) != 0 || length.value != 12) {
            bindingFail("cannot read exact Linux SO_PEERCRED listener snapshot (errno=${Native.getLastError()})")
        }
        val peer = ListenerCredentials(value.getInt(0), Integer.toUnsignedLong(value.getInt(4)),
            Integer.toUnsignedLong(value.getInt(8)))
        if (peer.pid <= 0 || peer.uid != runtimeSocketIdentity.uid.toLong()) {
            bindingFail("kernel listener PID or socket-owner UID is invalid")
        }
        peer
    }

    private fun readListenerSnapshot(libc: ListenerLibC, fd: Int): ListenerSnapshot {
        val before = readListenerCredentials(libc, fd)
        return Memory(4).use { value ->
            value.setInt(0, -1)
            val length = IntByReference(4)
            if (libc.getsockopt(fd, 1 /* SOL_SOCKET */, 77 /* SO_PEERPIDFD */, value, length) != 0) {
                bindingFail("Linux SO_PEERPIDFD is required for listener continuity (errno=${Native.getLastError()})")
            }
            // Successful getsockopt installs an owned fd. Adopt it before any length/coherence check.
            val handle = ListenerDescriptor(libc, value.getInt(0))
            try {
                if (length.value != 4 || value.getInt(0) < 0) bindingFail("SO_PEERPIDFD returned a malformed owned descriptor")
                handle.requireCloseOnExec()
                handle.requireAlive()
                if (readListenerCredentials(libc, fd) != before) bindingFail("kernel listener credentials changed during pidfd capture")
                handle.requireAlive()
                ListenerSnapshot(before, handle)
            } catch (failure: Throwable) {
                runCatching { handle.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }

    /** The connected socket and its transient pidfd never escape the fixed request scope. */
    private inner class ListenerConnection(
        private val libc: ListenerLibC,
        private val socket: ListenerDescriptor,
        private val transientPeer: ListenerSnapshot?,
        private val remaining: (String) -> Long,
        private val watch: EndpointDirectoryMutationWatch,
    ) : AutoCloseable {
        private fun checkpoint(phase: String): Long {
            val left = remaining(phase)
            watch.requireQuiet()
            requireListenerAlive()
            transientPeer?.requireAlive()
            return left
        }
        private fun await(events: Int, phase: String) {
            val left = checkpoint(phase)
            Memory(8).use { pollfd ->
                pollfd.clear()
                pollfd.setInt(0, socket.fd())
                pollfd.setShort(4, events.toShort())
                val result = libc.poll(pollfd, NativeLong(1),
                    minOf(100L, maxOf(1L, left / 1_000_000L)).toInt())
                if (result < 0 && Native.getLastError() != EINTR) {
                    bindingFail("cannot wait for fixed listener transport (errno=${Native.getLastError()})")
                }
                if (pollfd.getShort(6).toInt() and 0x20 /* POLLNVAL */ != 0) bindingFail("fixed listener transport descriptor is invalid")
                // HUP is not EOF: the next recv must drain any queued response bytes.
            }
            checkpoint(phase)
        }
        fun writeAll(bytes: ByteArray) {
            Memory(bytes.size.toLong()).use { buffer ->
                buffer.write(0, bytes, 0, bytes.size)
                var written = 0
                while (written < bytes.size) {
                    checkpoint("write request")
                    val count = libc.send(socket.fd(), buffer.share(written.toLong()), NativeLong((bytes.size - written).toLong()),
                        0x4000 /* MSG_NOSIGNAL */).toLong()
                    when {
                        count > 0 -> {
                            if (count > bytes.size - written) bindingFail("fixed listener send exceeded its supplied buffer")
                            written += count.toInt()
                        }
                        count == 0L -> bindingFail("fixed listener send made no progress")
                        Native.getLastError() == EINTR -> Unit
                        Native.getLastError() == EAGAIN -> await(4 /* POLLOUT */, "write request")
                        else -> bindingFail("cannot send fixed listener request (errno=${Native.getLastError()})")
                    }
                }
                checkpoint("after request write")
            }
        }
        fun input(): InputStream = object : InputStream() {
            private val single = ByteArray(1)
            override fun read(): Int = if (read(single, 0, 1) < 0) -1 else single[0].toInt() and 255
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                java.util.Objects.checkFromIndexSize(offset, length, bytes.size)
                if (length == 0) return 0
                val bound = minOf(length, 32 * 1024)
                Memory(bound.toLong()).use { buffer ->
                    while (true) {
                        checkpoint("read response")
                        val count = libc.recv(socket.fd(), buffer, NativeLong(bound.toLong()), 0).toLong()
                        when {
                            count > 0 -> {
                                if (count > bound) bindingFail("fixed listener recv exceeded its supplied buffer")
                                buffer.read(0, bytes, offset, count.toInt())
                                checkpoint("after response read")
                                return count.toInt()
                            }
                            count == 0L -> { checkpoint("after response EOF"); return -1 }
                            Native.getLastError() == EINTR -> Unit
                            Native.getLastError() == EAGAIN -> await(1 /* POLLIN */, "read response")
                            else -> bindingFail("cannot receive fixed listener response (errno=${Native.getLastError()})")
                        }
                    }
                }
            }
            override fun close() = Unit
        }
        fun requireTerminal() { checkpoint("terminal response"); requireCurrent(); checkpoint("after terminal identity") }
        override fun close() {
            var failure: Throwable? = null
            runCatching { transientPeer?.close() }.exceptionOrNull()?.let { failure = it }
            runCatching { socket.close() }.exceptionOrNull()?.let { closeFailure ->
                failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
            }
            failure?.let { throw it }
        }
    }

    private fun connectListener(
        remaining: (String) -> Long,
        watch: EndpointDirectoryMutationWatch,
        establishAnchor: Boolean,
    ): ListenerConnection {
        val libc = listenerLibC()
        remaining("before connect")
        watch.requireQuiet()
        requireCurrent()
        if (!establishAnchor) requireListenerAlive()
        val raw = libc.socket(1 /* AF_UNIX */, 1 /* SOCK_STREAM */ or O_NONBLOCK or O_CLOEXEC, 0)
        if (raw < 0) bindingFail("cannot open fixed listener socket (errno=${Native.getLastError()})")
        val socket = ListenerDescriptor(libc, raw)
        var snapshot: ListenerSnapshot? = null
        try {
            socket.requireCloseOnExec()
            runtimeSocketParent.whileOpen { parentFd ->
                val name = runtimeSocketPath.fileName.toString()
                if (name.isEmpty() || name.indexOf('\u0000') >= 0 || name.contains('/') ||
                    Path.of(name).toString() != name) bindingFail("fixed listener basename is not exact")
                val address = "/proc/self/fd/$parentFd/$name"
                val encoded = address.toByteArray(StandardCharsets.UTF_8)
                if (String(encoded, StandardCharsets.UTF_8) != address || encoded.size >= 108 || encoded.any { it == 0.toByte() }) {
                    bindingFail("fixed listener sockaddr_un path is aliased or exceeds its ceiling")
                }
                Memory(110).use { sockaddr ->
                    sockaddr.clear()
                    sockaddr.setShort(0, 1 /* AF_UNIX */)
                    sockaddr.write(2, encoded, 0, encoded.size)
                    var pending = false
                    while (true) {
                        remaining("connect")
                        watch.requireQuiet()
                        if (!establishAnchor) requireListenerAlive()
                        if (!pending) {
                            val result = libc.connect(raw, sockaddr, 2 + encoded.size + 1)
                            val error = if (result < 0) Native.getLastError() else 0
                            if (result == 0 || error == 106 /* EISCONN */) break
                            if (error == EINTR) continue
                            if (error == EAGAIN) {
                                // AF_UNIX backlog EAGAIN is not an in-progress connect. Retry only after a bounded wait.
                                val left = remaining("connect backlog wait")
                                val waited = libc.poll(Pointer.NULL, NativeLong(0), minOf(10L, maxOf(1L, left / 1_000_000L)).toInt())
                                if (waited < 0 && Native.getLastError() != EINTR) bindingFail("cannot wait for listener backlog")
                                continue
                            }
                            if (error != 115 /* EINPROGRESS */ && error != 114 /* EALREADY */) {
                                bindingFail("cannot connect fixed listener socket (errno=$error)")
                            }
                            pending = true
                        }
                        Memory(8).use { pollfd ->
                            pollfd.clear(); pollfd.setInt(0, raw); pollfd.setShort(4, 4)
                            val left = remaining("connect wait")
                            val result = libc.poll(pollfd, NativeLong(1), minOf(100L, maxOf(1L, left / 1_000_000L)).toInt())
                            if (result < 0) {
                                if (Native.getLastError() != EINTR) bindingFail("cannot wait for listener connection")
                            } else if (result > 0) {
                                Memory(4).use { errorValue ->
                                    val length = IntByReference(4)
                                    if (libc.getsockopt(raw, 1, 4 /* SO_ERROR */, errorValue, length) != 0 || length.value != 4) {
                                        bindingFail("cannot authenticate fixed listener connect completion")
                                    }
                                    val error = errorValue.getInt(0)
                                    if (error != 0) bindingFail("fixed listener connect failed (errno=$error)")
                                }
                                // SO_PEERCRED/SO_PEERPIDFD below establish that this socket actually connected.
                                pending = false
                                break
                            }
                        }
                    }
                }
            }
            remaining("after connect")
            watch.requireQuiet()
            requireCurrent()
            if (!establishAnchor) requireListenerAlive()
            snapshot = readListenerSnapshot(libc, raw)
            val observed = snapshot
            if (establishAnchor) {
                if (listenerAnchor != null || listenerExchanges != 0) bindingFail("kernel listener anchor was already captured")
                listenerAnchor = observed
                snapshot = null
            } else {
                val anchor = listenerAnchor ?: bindingFail("kernel listener anchor is absent")
                anchor.requireAlive(); observed.requireAlive()
                if (anchor.credentials != observed.credentials) bindingFail("fixed requests have different kernel listener snapshots")
                observed.requireAlive(); anchor.requireAlive()
            }
            remaining("before request bytes")
            watch.requireQuiet()
            requireListenerAlive()
            observed.requireAlive()
            listenerExchanges++
            return ListenerConnection(libc, socket, snapshot, remaining, watch).also { snapshot = null }
        } catch (failure: Throwable) {
            runCatching { snapshot?.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            runCatching { socket.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    private fun performListenerHeadPing(deadline: FixedHeadPingDeadline, watch: EndpointDirectoryMutationWatch) {
        connectListener(deadline::requireRemaining, watch, true).use { connection ->
            connection.writeAll(FIXED_HEAD_PING_REQUEST_TEXT.toByteArray(StandardCharsets.US_ASCII))
            val response = ByteArray(FIXED_HEAD_PING_RESPONSE_BYTES)
            var bytes = 0
            val input = connection.input()
            val buffer = ByteArray(FIXED_HEAD_PING_READ_BUFFER_BYTES)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (bytes + count > response.size) bindingFail("fixed Docker Engine HEAD /_ping response exceeds its byte ceiling")
                System.arraycopy(buffer, 0, response, bytes, count)
                bytes += count
            }
            connection.requireTerminal()
            requireFixedHeadPingResponse(response, bytes)
            connection.requireTerminal()
        }
    }

    private fun <T> withListenerMeasurementBody(
        operation: NativeMeasurementGet,
        target: String,
        deadline: AnalysisDeadline,
        watch: EndpointDirectoryMutationWatch,
        parse: (InputStream) -> T,
    ): T = connectListener(deadline::remainingNanos, watch, false).use { connection ->
        connection.writeAll("GET $target HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
        val raw = BufferedInputStream(connection.input(), 32 * 1024)
        val headers = readMeasurementHeaders(raw, operation)
        val body = FixedMeasurementBody(raw, headers, operation.maximumBytes, deadline::checkpoint)
        val result = parse(body)
        if (body.read() != -1) bindingFail("fixed Docker GET $target parser left body bytes unconsumed")
        connection.requireTerminal()
        result
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

    /** Exactly five fixed read-only requests; no socket or byte transport leaves this owner. */
    @Synchronized
    private fun measureNativeRuntimeV2(
        image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
        deadline: AnalysisDeadline,
    ): JsonObject {
        if (closed || headPingAttempted) bindingFail("fixed native measurement endpoint was already consumed")
        val checkpoint: (String) -> Unit = deadline::checkpoint
        val watch = EndpointDirectoryMutationWatch.open(runtimeSocketParent)
        nativeMeasurementWatch = watch
        return try {
            watch.requireQuiet()
            requireCurrent()
            performFixedHeadPing(FixedHeadPingDeadline.start(deadline))
            val version = nativeMeasurementObject(
                readFixedMeasurementJson(NativeMeasurementGet.VERSION, image.configSha256, deadline, watch),
                "Docker version", checkpoint,
            )
            if (version.nativeMeasurementString("Version") != "29.7.2" ||
                version.nativeMeasurementString("ApiVersion") != "1.55" ||
                version.nativeMeasurementString("Os") != "linux" ||
                version.nativeMeasurementString("Arch") != "amd64" ||
                version.nativeMeasurementString("GitCommit") != "6a43e3d"
            ) measurementFail("actual Docker version is outside the fixed 29.7.2/Linux/amd64/API-1.55 measurement")
            val info = nativeMeasurementObject(
                readFixedMeasurementJson(NativeMeasurementGet.INFO, image.configSha256, deadline, watch),
                "Docker info", checkpoint,
            )
            val security = info["SecurityOptions"] as? JsonArray
                ?: measurementFail("actual Docker info lacks security options")
            if (info.nativeMeasurementString("ServerVersion") != "29.7.2" ||
                info.nativeMeasurementString("OSType") != "linux" ||
                info.nativeMeasurementString("Driver") != "overlay2" ||
                info.nativeMeasurementString("CgroupVersion") != "2" ||
                security.none { it == JsonPrimitive("name=rootless") }
            ) measurementFail("actual Docker measurement requires rootless Linux, overlay2, and cgroup v2")
            val inspect = nativeMeasurementObject(
                readFixedMeasurementJson(NativeMeasurementGet.IMAGE_INSPECT, image.configSha256, deadline, watch),
                "Docker image inspect", checkpoint,
            )
            if (inspect.nativeMeasurementString("Id") != "sha256:${image.configSha256}" ||
                inspect.nativeMeasurementString("Os") != "linux" ||
                inspect.nativeMeasurementString("Architecture") != "amd64"
            ) measurementFail("actual inspected image differs from the raw config selector")
            val exported = withFixedMeasurementBody(
                NativeMeasurementGet.IMAGE_EXPORT, image.configSha256, deadline, watch,
            ) { body -> LlvmBehaviorNativeOciImageV2.readDockerExport(body, image, checkpoint) }
            val rootFs = inspect["RootFS"] as? JsonObject ?: measurementFail("inspected image lacks RootFS")
            if (rootFs.nativeMeasurementString("Type") != "layers") measurementFail("inspected RootFS is not layers")
            val inspectedLayers = rootFs["Layers"] as? JsonArray ?: measurementFail("inspected RootFS lacks layers")
            if (inspectedLayers != JsonArray(exported.layerDiffIds.map { JsonPrimitive("sha256:$it") })) {
                measurementFail("inspected layer order differs from actual exported bytes")
            }
            image.requireCurrent(checkpoint)
            watch.requireQuiet()
            requireCurrent()
            watch.requireQuiet()
            checkpoint("after actual Docker image export authentication")
            val facts = JsonObject(linkedMapOf(
                "apiVersion" to JsonPrimitive("1.55"),
                "serverVersion" to JsonPrimitive("29.7.2"),
                "fixedReadOnlyRequests" to JsonArray(listOf(
                    JsonPrimitive("HEAD /_ping"), JsonPrimitive("GET /version"), JsonPrimitive("GET /info"),
                    JsonPrimitive("GET /v1.55/images/sha256:${image.configSha256}/json"),
                    JsonPrimitive("GET /v1.55/images/sha256:${image.configSha256}/get"),
                )),
                "version" to version,
                "versionCanonicalSha256" to JsonPrimitive(nativeMeasurementJsonHash(version, checkpoint)),
                "info" to info,
                "infoCanonicalSha256" to JsonPrimitive(nativeMeasurementJsonHash(info, checkpoint)),
                "inspect" to inspect,
                "inspectCanonicalSha256" to JsonPrimitive(nativeMeasurementJsonHash(inspect, checkpoint)),
                "exportConfigSha256" to JsonPrimitive(exported.configSha256),
                "exportLayerDiffIds" to JsonArray(exported.layerDiffIds.map(::JsonPrimitive)),
                "exportSha256" to JsonPrimitive(exported.exportSha256),
                "exportBytes" to JsonPrimitive(exported.exportBytes),
                "exportMergedNamespaceSha256" to JsonPrimitive(exported.namespaceSha256),
            ) + if (listenerContinuity) mapOf("observedListenerContinuity" to listenerFacts()) else emptyMap())
            watch.requireQuiet()
            nativeMeasurementCompleted = true
            facts
        } catch (failure: Throwable) {
            if (listenerContinuity) {
                val retained = listenerAnchor
                listenerAnchor = null
                runCatching { retained?.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                val retainedWatch = nativeMeasurementWatch
                nativeMeasurementWatch = null
                runCatching { retainedWatch?.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            throw failure
        }
    }

    @Synchronized
    private fun requireNativeMeasurementQuiet(deadline: AnalysisDeadline) {
        deadline.checkpoint("during final native endpoint watch authentication")
        if (closed || !nativeMeasurementCompleted) bindingFail("fixed native measurement has no completed retained exchange")
        val watch = nativeMeasurementWatch ?: bindingFail("fixed native measurement has no retained endpoint watch")
        watch.requireQuiet()
        requireListenerAlive()
        requireCurrent()
        watch.requireQuiet()
        requireListenerAlive()
        deadline.checkpoint("after final native endpoint watch authentication")
    }

    private enum class NativeMeasurementGet {
        VERSION, INFO, IMAGE_INSPECT, IMAGE_EXPORT;

        fun target(configSha256: String): String {
            if (!configSha256.matches(SHA256)) bindingFail("raw measured config SHA-256 is malformed")
            return when (this) {
                VERSION -> "/version"
                INFO -> "/info"
                IMAGE_INSPECT -> "/v1.55/images/sha256:$configSha256/json"
                IMAGE_EXPORT -> "/v1.55/images/sha256:$configSha256/get"
            }
        }

        val maximumBytes: Long get() = if (this == IMAGE_EXPORT) 8L * 1024 * 1024 * 1024 else 4L * 1024 * 1024
        val contentType: String get() = if (this == IMAGE_EXPORT) "application/x-tar" else "application/json"
    }

    private fun readFixedMeasurementJson(
        operation: NativeMeasurementGet,
        configSha256: String,
        deadline: AnalysisDeadline,
        watch: EndpointDirectoryMutationWatch,
    ): ByteArray = withFixedMeasurementBody(operation, configSha256, deadline, watch) { body ->
        val result = ByteArrayOutputStream()
        val buffer = ByteArray(32 * 1024)
        while (true) {
            val count = body.read(buffer)
            if (count < 0) break
            result.write(buffer, 0, count)
        }
        result.toByteArray()
    }

    private fun <T> withFixedMeasurementBody(
        operation: NativeMeasurementGet,
        configSha256: String,
        deadline: AnalysisDeadline,
        watch: EndpointDirectoryMutationWatch,
        parse: (InputStream) -> T,
    ): T {
        val target = operation.target(configSha256)
        deadline.checkpoint("before fixed Docker GET $target")
        watch.requireQuiet()
        requireCurrent()
        if (listenerContinuity) {
            return withListenerMeasurementBody(operation, target, deadline, watch, parse)
        }
        return SocketChannel.open(StandardProtocolFamily.UNIX).use { channel ->
            Selector.open().use { selector ->
                channel.configureBlocking(false)
                val key = channel.register(selector, SelectionKey.OP_CONNECT)
                requireCurrent()
                watch.requireQuiet()
                val connected = channel.connect(UnixDomainSocketAddress.of(runtimeSocketPath))
                if (!connected) {
                    while (!channel.finishConnect()) awaitMeasurement(selector, deadline, watch, "connect $target")
                }
                watch.requireQuiet()
                requireCurrent()
                requireCurrentUserPeer(channel)
                watch.requireQuiet()
                key.interestOps(SelectionKey.OP_WRITE)
                val request = ByteBuffer.wrap(
                    "GET $target HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
                        .toByteArray(StandardCharsets.US_ASCII),
                )
                while (request.hasRemaining()) {
                    deadline.checkpoint("while writing fixed Docker GET $target")
                    watch.requireQuiet()
                    if (channel.write(request) == 0) awaitMeasurement(selector, deadline, watch, "write $target")
                }
                key.interestOps(SelectionKey.OP_READ)
                val raw = BufferedInputStream(object : InputStream() {
                    private val single = ByteArray(1)
                    override fun read(): Int = if (read(single, 0, 1) < 0) -1 else single[0].toInt() and 255
                    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                        java.util.Objects.checkFromIndexSize(offset, length, bytes.size)
                        if (length == 0) return 0
                        val destination = ByteBuffer.wrap(bytes, offset, length)
                        while (true) {
                            deadline.checkpoint("while reading fixed Docker GET $target")
                            watch.requireQuiet()
                            val read = channel.read(destination)
                            if (read != 0) return read
                            awaitMeasurement(selector, deadline, watch, "read $target")
                        }
                    }
                    override fun close() = Unit // The socket remains exclusively owned by this scope.
                }, 32 * 1024)
                val headers = readMeasurementHeaders(raw, operation)
                val body = FixedMeasurementBody(raw, headers, operation.maximumBytes, deadline::checkpoint)
                val result = parse(body)
                if (body.read() != -1) bindingFail("fixed Docker GET $target parser left body bytes unconsumed")
                deadline.checkpoint("after fixed Docker GET $target EOF")
                watch.requireQuiet()
                requireCurrent()
                watch.requireQuiet()
                result
            }
        }
    }

    private fun awaitMeasurement(
        selector: Selector,
        deadline: AnalysisDeadline,
        watch: EndpointDirectoryMutationWatch,
        phase: String,
    ) {
        watch.requireQuiet()
        val remaining = deadline.remainingNanos("during fixed Docker $phase")
        selector.select(minOf(100L, maxOf(1L, (remaining + 999_999L) / 1_000_000L)))
        selector.selectedKeys().clear()
        watch.requireQuiet()
        deadline.checkpoint("after fixed Docker $phase wait")
    }

    private fun readMeasurementHeaders(input: InputStream, operation: NativeMeasurementGet): Map<String, String> {
        var bytes = 0
        fun line(): String = measurementHttpLine(input, 8192).also {
            bytes = Math.addExact(bytes, it.length + 2)
            if (bytes > 32 * 1024) bindingFail("fixed Docker measurement HTTP headers exceed their byte ceiling")
        }
        if (line() != "HTTP/1.1 200 OK") bindingFail("fixed Docker measurement HTTP status is not 200 OK")
        val headers = linkedMapOf<String, String>()
        while (true) {
            val value = line()
            if (value.isEmpty()) break
            if (headers.size >= 64) bindingFail("fixed Docker measurement has too many HTTP headers")
            val colon = value.indexOf(':')
            if (colon <= 0 || colon + 2 > value.length || value[colon + 1] != ' ') {
                bindingFail("fixed Docker measurement has malformed HTTP header framing")
            }
            val name = value.substring(0, colon)
            val field = value.substring(colon + 2)
            if (!name.matches(Regex("[A-Za-z0-9!#$%&'*+.^_`|~-]+")) || field.isEmpty() ||
                field.first() == ' ' || field.last() == ' '
            ) bindingFail("fixed Docker measurement has malformed HTTP headers")
            if (headers.put(name.lowercase(java.util.Locale.ROOT), field) != null) {
                bindingFail("fixed Docker measurement has duplicate HTTP headers")
            }
        }
        if (headers["connection"] != "close" || headers.containsKey("content-encoding")) {
            bindingFail("fixed Docker measurement requires close framing without HTTP content encoding")
        }
        val type = headers["content-type"] ?: bindingFail("fixed Docker measurement lacks Content-Type")
        if (type != operation.contentType && type != "${operation.contentType}; charset=utf-8") {
            bindingFail("fixed Docker measurement has an unexpected Content-Type")
        }
        if (("content-length" in headers) == ("transfer-encoding" in headers)) {
            bindingFail("fixed Docker measurement requires exactly one bounded HTTP body framing")
        }
        if ("trailer" in headers || (headers["transfer-encoding"] != null && headers["transfer-encoding"] != "chunked")) {
            bindingFail("fixed Docker measurement does not accept HTTP trailers or chained encodings")
        }
        return headers
    }

    private class FixedMeasurementBody(
        private val input: InputStream,
        headers: Map<String, String>,
        private val maximumBytes: Long,
        private val checkpoint: (String) -> Unit,
    ) : InputStream() {
        private val chunked = headers["transfer-encoding"] == "chunked"
        private var remaining = if (chunked) 0L else headers.getValue("content-length").let { value ->
            if (!value.matches(Regex("[0-9]{1,19}"))) bindingFail("fixed Docker measurement Content-Length is malformed")
            value.toLongOrNull()?.takeIf { it in 0..maximumBytes }
                ?: bindingFail("fixed Docker measurement Content-Length exceeds its bound")
        }
        private var total = 0L
        private var needChunkTerminator = false
        private var ended = false
        private val single = ByteArray(1)

        override fun read(): Int = if (read(single, 0, 1) < 0) -1 else single[0].toInt() and 255
        override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
            java.util.Objects.checkFromIndexSize(offset, length, bytes.size)
            if (length == 0) return 0
            checkpoint("during fixed Docker measurement body")
            if (ended) return -1
            if (remaining == 0L && chunked) {
                if (needChunkTerminator) requireCrlf()
                val line = measurementHttpLine(input, 32)
                if (!line.matches(Regex("[0-9a-fA-F]{1,16}"))) bindingFail("fixed Docker measurement chunk size is malformed")
                remaining = line.toLongOrNull(16)?.takeIf {
                    it >= 0L && it <= 16L * 1024 * 1024 && it <= maximumBytes - total
                } ?: bindingFail("fixed Docker measurement chunk exceeds its byte ceiling")
                if (remaining == 0L) {
                    requireCrlf()
                    return finish()
                }
                needChunkTerminator = true
            }
            if (remaining == 0L) return finish()
            val read = input.read(bytes, offset, minOf(length.toLong(), remaining, 32L * 1024).toInt())
            if (read <= 0) bindingFail("fixed Docker measurement HTTP body ended before its framing")
            remaining -= read
            total = Math.addExact(total, read.toLong())
            if (total > maximumBytes) bindingFail("fixed Docker measurement HTTP body exceeds its byte ceiling")
            checkpoint("after fixed Docker measurement body bytes")
            return read
        }

        private fun finish(): Int {
            if (input.read() != -1) bindingFail("fixed Docker measurement HTTP response has trailing bytes")
            ended = true
            checkpoint("after fixed Docker measurement response EOF")
            return -1
        }

        private fun requireCrlf() {
            if (input.read() != '\r'.code || input.read() != '\n'.code) {
                bindingFail("fixed Docker measurement HTTP chunk framing lacks CRLF")
            }
        }
        override fun close() = Unit
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        runCatching { listenerAnchor?.close() }.exceptionOrNull()?.let { failure = it }
        listenerAnchor = null
        runCatching { nativeMeasurementWatch?.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        nativeMeasurementWatch = null
        runCatching { runtimeSocketDescriptor.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        runCatching { runtimeSocketParent.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        failure?.let { throw it }
    }

    private class FixedHeadPingDeadline private constructor(
        private val startedNanos: Long,
        private val durationNanos: Long,
        private val parent: AnalysisDeadline? = null,
    ) {
        fun requireRemaining(phase: String): Long {
            if (Thread.currentThread().isInterrupted) throw InterruptedException("fixed Docker request cancelled")
            val elapsed = System.nanoTime() - startedNanos
            val remaining = durationNanos - elapsed
            if (remaining <= 0L) {
                bindingFail("fixed Docker Engine HEAD /_ping $phase exceeded its absolute deadline")
            }
            return minOf(remaining, parent?.remainingNanos("during Docker HEAD /_ping $phase") ?: Long.MAX_VALUE)
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
            fun start(parent: AnalysisDeadline? = null): FixedHeadPingDeadline = FixedHeadPingDeadline(
                System.nanoTime(),
                TimeUnit.MILLISECONDS.toNanos(FIXED_HEAD_PING_TIMEOUT_MILLISECONDS),
                parent,
            )
        }
    }

    private class EndpointDirectoryMutationWatch private constructor(
        private val libc: InotifyLibC,
        private var descriptor: Int,
    ) : AutoCloseable {
        fun requireQuiet() {
            val buffer = Memory(INOTIFY_READ_BYTES.toLong())
            repeat(4) {
                val count = libc.read(descriptor, buffer, NativeLong(INOTIFY_READ_BYTES.toLong())).toLong()
                val error = if (count < 0L) Native.getLastError() else 0
                when {
                    count > 0L -> bindingFail(
                        "fixed Docker Engine socket directory mutated during HEAD /_ping",
                    )
                    count == 0L -> bindingFail(
                        "fixed Docker Engine socket directory watch ended during HEAD /_ping",
                    )
                    error == EINTR -> Unit
                    error == EAGAIN -> return
                    else -> bindingFail(
                        "cannot read the fixed Docker Engine socket directory watch (errno=$error)",
                    )
                }
            }
            bindingFail("fixed Docker Engine socket directory watch exceeded bounded interruption retries")
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
    checkpoint: (String) -> Unit = {},
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
    val bytes = LinuxFilesystemSyscalls.copyReadableTo(descriptor, sink, maximumBytes) {
        checkpoint("while hashing $label")
    }
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

private fun measurementHttpLine(input: InputStream, maximumBytes: Int): String {
    val bytes = ByteArrayOutputStream()
    while (true) {
        val next = input.read()
        if (next < 0) bindingFail("fixed Docker measurement HTTP line ended before CRLF")
        if (next == '\r'.code) {
            if (input.read() != '\n'.code) bindingFail("fixed Docker measurement HTTP line has a bare carriage return")
            return bytes.toString(StandardCharsets.US_ASCII)
        }
        if (next !in 0x20..0x7e || bytes.size() >= maximumBytes) {
            bindingFail("fixed Docker measurement HTTP line has invalid bytes or exceeds its byte ceiling")
        }
        bytes.write(next)
    }
}

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
