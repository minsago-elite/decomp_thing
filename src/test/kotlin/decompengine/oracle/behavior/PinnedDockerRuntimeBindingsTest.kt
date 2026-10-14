package decompengine.oracle.behavior

import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleArtifacts
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.channels.ServerSocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PinnedDockerRuntimeBindingsTest {
    @Test
    fun `capture exposes only exact immutable descriptor-backed runtime bindings`() {
        RuntimeBindingFixture().use { fixture ->
            fixture.capture().use { bindings ->
                bindings.requireCurrent()

                assertTrue(Files.isSameFile(fixture.controlClient, bindings.executableDescriptorPath))
                assertTrue(Files.isSameFile(fixture.dockerConfig, bindings.dockerConfigDescriptorPath))
                assertContentEquals(fixture.controlClientBytes, Files.readAllBytes(bindings.executableDescriptorPath))
                assertTrue(bindings.executableDescriptorPath.toString().startsWith(currentProcessFdPrefix()))
                assertTrue(bindings.dockerConfigDescriptorPath.toString().startsWith(currentProcessFdPrefix()))
                assertEquals(fixture.controlClientBytes.size.toLong(), bindings.controlClientBytes)
                assertEquals(fixture.controlClientSha256, bindings.controlClientSha256)
                assertEquals(fixture.runtimeSocket, bindings.runtimeSocketPath)
                assertEquals("0o600", bindings.runtimeSocketMode)
                assertEquals(
                    linkedMapOf(
                        "DOCKER_CONFIG" to bindings.dockerConfigDescriptorPath.toString(),
                        "DOCKER_HOST" to "unix://${fixture.runtimeSocket}",
                        "HOME" to "/nonexistent",
                        "LANG" to "C",
                        "LC_ALL" to "C",
                    ),
                    bindings.environment,
                )
                @Suppress("UNCHECKED_CAST")
                val mutableEnvironment = bindings.environment as MutableMap<String, String>
                assertFailsWith<UnsupportedOperationException> {
                    mutableEnvironment["DOCKER_HOST"] = "unix:///different.sock"
                }
                listOf(
                    bindings.controlClientIdentitySha256,
                    bindings.dockerConfigIdentitySha256,
                    bindings.dockerConfigPathSha256,
                    bindings.runtimeSocketIdentitySha256,
                    bindings.runtimeSocketParentIdentitySha256,
                    bindings.runtimeSocketPathSha256,
                ).forEach { commitment -> assertTrue(commitment.matches(SHA256), commitment) }
                assertEquals(
                    OracleArtifacts.sha256(fixture.dockerConfig.toString().encodeToByteArray()),
                    bindings.dockerConfigPathSha256,
                )
                assertEquals(
                    OracleArtifacts.sha256(fixture.runtimeSocket.toString().encodeToByteArray()),
                    bindings.runtimeSocketPathSha256,
                )

                assertTrue(
                    PinnedDockerRuntimeBindings::class.java.declaredMethods.none {
                        it.name.lowercase() in setOf("run", "exec", "execute", "start")
                    },
                )
                assertTrue(
                    PinnedDockerRuntimeBindings::class.java.declaredFields.none {
                        it.type == Process::class.java || it.type == ProcessBuilder::class.java ||
                            it.type.name.startsWith("kotlin.jvm.functions.")
                    },
                )
                assertFalse(bindings.environment.containsKey("PYTHONPATH"))
            }
        }
    }

    @Test
    fun `native terminal verification remains private without publishing endpoint or watch access`() {
        val runtime = PinnedDockerRuntimeBindings::class.java
        val companion = PinnedDockerRuntimeBindings.Companion::class.java
        val bridge = companion.declaredMethods.single { it.name == "verifyNativeRuntimeV2Terminal" }
        val owned = runtime.declaredMethods.single { it.name == "verifyNativeRuntimeV2TerminalOwned" }
        assertTrue(Modifier.isPrivate(bridge.modifiers), bridge.toString())
        assertTrue(Modifier.isPrivate(owned.modifiers), owned.toString())
        assertEquals(Void.TYPE, bridge.returnType)
        assertEquals(Void.TYPE, owned.returnType)
        assertContentEquals(arrayOf(runtime, AnalysisDeadline::class.java), bridge.parameterTypes)
        assertContentEquals(arrayOf(AnalysisDeadline::class.java), owned.parameterTypes)

        val endpoint = runtime.declaredClasses.single { it.simpleName == "PinnedDockerEndpointState" }
        val privateStateNames = setOf(endpoint.name,
            endpoint.declaredClasses.single { it.simpleName == "EndpointDirectoryMutationWatch" }.name)
        for (type in listOf(runtime, companion, endpoint)) {
            val exposed = type.declaredMethods.filter { method ->
                Modifier.isPublic(method.modifiers) && (
                    method.returnType.name in privateStateNames ||
                        (method.isSynthetic && (method.name.startsWith("access\$get") || method.name.startsWith("access\$set")) &&
                            (method.name.contains("EndpointState") || method.name.contains("Watch"))) ||
                        method.name.contains("verifyNativeRuntimeV2Terminal") ||
                        method.name.contains("measureNativeRuntimeV2") ||
                        method.name.lowercase() in setOf("run", "exec", "execute", "start", "request", "exchange")
                    )
            }
            assertTrue(exposed.isEmpty(), "native endpoint/watch or generic API became public: $exposed")
        }
    }

    @Test
    fun `listener continuity bridge and native declarations remain private and exact`() {
        val runtime = PinnedDockerRuntimeBindings::class.java
        val companion = PinnedDockerRuntimeBindings.Companion::class.java
        val endpoint = runtime.declaredClasses.single { it.simpleName == "PinnedDockerEndpointState" }
        val privateTypes = setOf("ListenerLibC", "ListenerDescriptor", "ListenerSnapshot", "ListenerCredentials")
            .map { name -> endpoint.declaredClasses.single { it.simpleName == name } }
        privateTypes.forEach { type -> assertTrue(Modifier.isPrivate(type.modifiers), type.toString()) }

        val bridge = companion.declaredMethods.single { it.name == "captureForNativeRuntimeV3" }
        assertTrue(Modifier.isPrivate(bridge.modifiers), bridge.toString())
        assertEquals(runtime, bridge.returnType)
        assertContentEquals(arrayOf(Path::class.java, Path::class.java, Path::class.java, AnalysisDeadline::class.java),
            bridge.parameterTypes)
        val capture = companion.declaredMethods.single { it.name == "captureWithCheckpoint" }
        assertTrue(Modifier.isPrivate(capture.modifiers), capture.toString())
        assertContentEquals(arrayOf(Path::class.java, java.lang.Long.TYPE, String::class.java, java.lang.Long.TYPE,
            Path::class.java, Path::class.java, kotlin.jvm.functions.Function1::class.java, java.lang.Boolean.TYPE),
            capture.parameterTypes)

        val libc = privateTypes.single { it.simpleName == "ListenerLibC" }
        val int = Integer.TYPE
        val signatures = linkedMapOf(
            "socket" to (int to arrayOf(int, int, int)),
            "connect" to (int to arrayOf(int, Pointer::class.java, int)),
            "getsockopt" to (int to arrayOf(int, int, int, Pointer::class.java, IntByReference::class.java)),
            "send" to (NativeLong::class.java to arrayOf(int, Pointer::class.java, NativeLong::class.java, int)),
            "recv" to (NativeLong::class.java to arrayOf(int, Pointer::class.java, NativeLong::class.java, int)),
            "poll" to (int to arrayOf(Pointer::class.java, NativeLong::class.java, int)),
            "fcntl" to (int to arrayOf(int, int)),
            "close" to (int to arrayOf(int)),
        )
        assertEquals(signatures.keys, libc.declaredMethods.map { it.name }.toSet())
        signatures.forEach { (name, signature) ->
            val method = libc.declaredMethods.single { it.name == name }
            assertEquals(signature.first, method.returnType, name)
            assertEquals(signature.second.toList(), method.parameterTypes.toList(), name)
        }

        val privateTypeNames = privateTypes.map { it.name }.toSet()
        for (type in listOf(runtime, companion, endpoint)) {
            val exposed = type.declaredMethods.filter { method ->
                Modifier.isPublic(method.modifiers) && (
                    method.returnType.name in privateTypeNames ||
                        method.parameterTypes.any { it.name in privateTypeNames } ||
                        method.name.contains("captureForNativeRuntimeV3") ||
                        (method.isSynthetic && (method.name.startsWith("access\$get") ||
                            method.name.startsWith("access\$set")) && method.name.contains("Listener"))
                    )
            }
            assertTrue(exposed.isEmpty(), "private listener state or bridge became public: $exposed")
        }
    }

    @Test
    fun `simulated ucred and pinned socket UID agree across the unsigned 32 bit boundary`() {
        val boundaries = listOf(
            0x7fffffff to 2_147_483_647L,
            Int.MIN_VALUE /* 0x80000000 uid_t bits */ to 2_147_483_648L,
            -1 /* 0xffffffff uid_t bits */ to 4_294_967_295L,
        )
        for ((rawUid, unsignedUid) in boundaries) {
            withSimulatedPinnedListenerUidForTest(rawUid) { endpoint ->
                val control = ListenerNativeFaultControl(rawUid)
                val credentials = checkNotNull(readListenerCredentialsForTest(endpoint, control.proxy))
                val uid = credentials.javaClass.declaredMethods.single { it.name == "getUid" }
                assertEquals(unsignedUid, invokeListenerForTest(uid, credentials))
                assertEquals(listOf(17 /* SO_PEERCRED */), control.socketOptions)
                assertEquals(1, control.credentialReads)
                assertTrue(control.descriptorCommands.isEmpty())
                assertEquals(0, control.livenessProbes)
                assertTrue(control.closedDescriptors.isEmpty())
            }
        }
    }

    @Test
    fun `simulated unsigned UID mismatch is refused before pidfd acquisition including across sign boundary`() {
        val boundaries = listOf(0x7fffffff, Int.MIN_VALUE /* 0x80000000 */, -1 /* 0xffffffff */)
        for (pinnedUid in boundaries) {
            for (peerUid in boundaries.filter { it != pinnedUid }) {
                withSimulatedPinnedListenerUidForTest(pinnedUid) { endpoint ->
                    val control = ListenerNativeFaultControl(peerUid)
                    val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                        readListenerSnapshotForTest(endpoint, control.proxy)
                    }
                    assertTrue(failure.message.orEmpty().contains("socket-owner UID is invalid"), failure.message)
                    assertEquals(listOf(17 /* SO_PEERCRED */), control.socketOptions)
                    assertEquals(1, control.credentialReads)
                    assertTrue(control.descriptorCommands.isEmpty())
                    assertEquals(0, control.livenessProbes)
                    assertTrue(control.closedDescriptors.isEmpty())
                }
            }
        }
    }

    @Test
    fun `simulated malformed peer pidfd length closes the installed descriptor exactly once`() {
        withListenerEndpointForTest { endpoint, uid ->
            val control = ListenerNativeFaultControl(uid, pidfdLength = 3)
            val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                readListenerSnapshotForTest(endpoint, control.proxy)
            }
            assertTrue(failure.message.orEmpty().contains("malformed owned descriptor"), failure.message)
            assertEquals(listOf(17, 77), control.socketOptions)
            assertEquals(listOf(LISTENER_TEST_PIDFD), control.closedDescriptors)
            assertTrue(control.descriptorCommands.isEmpty())
            assertEquals(0, control.livenessProbes)
            assertTrue(failure.suppressed.isEmpty())
        }
    }

    @Test
    fun `simulated unsupported peer pidfd and option acquisition exhaustion fail without a fallback`() {
        for (errno in listOf(92 /* ENOPROTOOPT */, 24 /* EMFILE */)) {
            withListenerEndpointForTest { endpoint, uid ->
                val control = ListenerNativeFaultControl(uid, peerPidfdErrno = errno)
                val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                    readListenerSnapshotForTest(endpoint, control.proxy)
                }
                assertTrue(failure.message.orEmpty().contains("SO_PEERPIDFD is required"), failure.message)
                assertTrue(failure.message.orEmpty().contains("errno=$errno"), failure.message)
                assertEquals(listOf(17, 77), control.socketOptions)
                assertEquals(1, control.credentialReads)
                assertTrue(control.closedDescriptors.isEmpty())
                assertTrue(control.descriptorCommands.isEmpty())
                assertEquals(0, control.livenessProbes)
                assertTrue(failure.suppressed.isEmpty())
            }
        }
    }

    @Test
    fun `simulated peer pidfd missing cloexec is refused using only F_GETFD and closed once`() {
        withListenerEndpointForTest { endpoint, uid ->
            val control = ListenerNativeFaultControl(uid, descriptorFlags = 0)
            val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                readListenerSnapshotForTest(endpoint, control.proxy)
            }
            assertTrue(failure.message.orEmpty().contains("FD_CLOEXEC"), failure.message)
            assertEquals(listOf(17, 77), control.socketOptions)
            assertEquals(listOf(LISTENER_TEST_PIDFD to 1 /* F_GETFD */), control.descriptorCommands)
            assertEquals(listOf(LISTENER_TEST_PIDFD), control.closedDescriptors)
            assertEquals(0, control.livenessProbes)
        }
    }

    @Test
    fun `simulated credential change after pidfd installation closes only its owned descriptor`() {
        withListenerEndpointForTest { endpoint, uid ->
            val control = ListenerNativeFaultControl(uid, changeSecondCredentialPid = true)
            val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                readListenerSnapshotForTest(endpoint, control.proxy)
            }
            assertTrue(failure.message.orEmpty().contains("credentials changed"), failure.message)
            assertEquals(listOf(17, 77, 17), control.socketOptions)
            assertEquals(2, control.credentialReads)
            assertEquals(listOf(LISTENER_TEST_PIDFD to 1 /* F_GETFD */), control.descriptorCommands)
            assertEquals(1, control.livenessProbes)
            assertEquals(listOf(LISTENER_TEST_PIDFD), control.closedDescriptors)
            assertFalse(control.closedDescriptors.contains(LISTENER_TEST_SOCKET_FD))
        }
    }

    @Test
    fun `simulated pidfd close EINTR retires descriptor ownership without retry`() {
        val control = ListenerNativeFaultControl(0, closeErrno = 4 /* EINTR */)
        val descriptorType = listenerEndpointType().declaredClasses.single { it.simpleName == "ListenerDescriptor" }
        val constructor = descriptorType.declaredConstructors.single()
        assertTrue(constructor.trySetAccessible())
        val descriptor = constructor.newInstance(control.proxy, LISTENER_TEST_PIDFD)
        val close = descriptorType.declaredMethods.single { it.name == "close" }
        val fd = descriptorType.declaredMethods.single { it.name == "fd" }
        val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> { invokeListenerForTest(close, descriptor) }
        assertTrue(failure.message.orEmpty().contains("errno=4"), failure.message)
        invokeListenerForTest(close, descriptor)
        invokeListenerForTest(close, descriptor)
        val retired = assertFailsWith<PinnedDockerRuntimeBindingsException> { invokeListenerForTest(fd, descriptor) }
        assertTrue(retired.message.orEmpty().contains("closed"), retired.message)
        assertEquals(listOf(LISTENER_TEST_PIDFD), control.closedDescriptors)
    }

    @Test
    fun `simulated cleanup failure preserves malformed snapshot refusal and adds one close failure`() {
        withListenerEndpointForTest { endpoint, uid ->
            val control = ListenerNativeFaultControl(uid, pidfdLength = 3, closeErrno = 4 /* EINTR */)
            val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                readListenerSnapshotForTest(endpoint, control.proxy)
            }
            assertTrue(failure.message.orEmpty().contains("malformed owned descriptor"), failure.message)
            assertEquals(1, failure.suppressed.size)
            assertTrue(failure.suppressed.single() is PinnedDockerRuntimeBindingsException)
            assertTrue(failure.suppressed.single().message.orEmpty().contains("errno=4"))
            assertEquals(listOf(LISTENER_TEST_PIDFD), control.closedDescriptors)
        }
    }

    @Test
    fun `terminal native verification rejects a valid binding before its fixed measurement`() {
        RuntimeBindingFixture().use { fixture ->
            fixture.capture().use { bindings ->
                bindings.requireCurrent()
                val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                    verifyNativeTerminalForTest(bindings)
                }
                assertTrue(failure.message.orEmpty().contains("measurement") ||
                    failure.message.orEmpty().contains("watch"), failure.message)
                fixture.assertNoPendingConnection()
            }
        }
    }

    @Test
    fun `terminal native verification cannot reopen closed bindings or owned resources`() {
        RuntimeBindingFixture().use { fixture ->
            val bindings = fixture.capture()
            bindings.close()
            val terminal = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                verifyNativeTerminalForTest(bindings)
            }
            assertTrue(terminal.message.orEmpty().contains("closed"), terminal.message)
            val ordinary = assertFailsWith<PinnedDockerRuntimeBindingsException> { bindings.requireCurrent() }
            assertTrue(ordinary.message.orEmpty().contains("closed"), ordinary.message)
            bindings.close()
            fixture.assertNoPendingConnection()
        }
    }

    @Test
    fun `named control-client replacement cannot change the pinned executable`() {
        RuntimeBindingFixture().use { fixture ->
            fixture.capture().use { bindings ->
                val displaced = fixture.root.resolve("control-client.displaced")
                Files.move(fixture.controlClient, displaced, StandardCopyOption.ATOMIC_MOVE)
                Files.write(fixture.controlClient, "replacement-client".encodeToByteArray())
                Files.setPosixFilePermissions(fixture.controlClient, OWNER_EXECUTABLE)

                assertContentEquals(fixture.controlClientBytes, Files.readAllBytes(bindings.executableDescriptorPath))
                assertFailsWith<PinnedDockerRuntimeBindingsException> { bindings.requireCurrent() }
            }
        }
    }

    @Test
    fun `Docker config contamination fails while the pinned directory remains selected`() {
        RuntimeBindingFixture().use { fixture ->
            fixture.capture().use { bindings ->
                Files.writeString(fixture.dockerConfig.resolve("config.json"), "{}")

                assertTrue(Files.isSameFile(fixture.dockerConfig, bindings.dockerConfigDescriptorPath))
                val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> { bindings.requireCurrent() }
                assertTrue(failure.message.orEmpty().contains("Docker config"), failure.message)
            }
        }
    }

    @Test
    fun `runtime socket pathname replacement fails against the retained socket identity`() {
        RuntimeBindingFixture().use { fixture ->
            fixture.capture().use { bindings ->
                fixture.replaceRuntimeSocket()

                val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> { bindings.requireCurrent() }
                assertTrue(failure.message.orEmpty().contains("socket"), failure.message)
            }
        }
    }

    @Test
    fun `one-way transfer retains only the current private endpoint binding`() {
        RuntimeBindingFixture().use { fixture ->
            val bindings = fixture.capture()
            val endpoint = bindings.retainEndpointBinding()
            endpoint.use {
                bindings.close()
                assertFailsWith<PinnedDockerRuntimeBindingsException> { bindings.requireCurrent() }
                assertFailsWith<PinnedDockerRuntimeBindingsException> {
                    bindings.retainEndpointBinding()
                }

                val displaced = fixture.root.resolve("control-client.after-transfer")
                Files.move(fixture.controlClient, displaced, StandardCopyOption.ATOMIC_MOVE)
                Files.write(fixture.controlClient, "untrusted-replacement".encodeToByteArray())
                Files.setPosixFilePermissions(fixture.controlClient, OWNER_EXECUTABLE)
                Files.writeString(fixture.dockerConfig.resolve("config.json"), "{}")
                endpoint.requireCurrent()

                val methods = PinnedDockerEndpointBinding::class.java.declaredMethods
                assertTrue(methods.all { it.parameterCount == 0 })
                assertEquals(setOf("close", "requireCurrent"), methods.map { it.name }.toSet())
                assertTrue(
                    methods.none {
                        it.name.lowercase().contains("http") || it.name.lowercase().contains("request") ||
                            it.name.lowercase().contains("build") || it.name.lowercase().contains("create") ||
                            it.name.lowercase().contains("start") || it.name.lowercase().contains("execute") ||
                            it.name.lowercase().contains("command") || it.name.lowercase().contains("python")
                    },
                )
            }
        }
    }

    @Test
    fun `transfer rejects drift and retained endpoint drift permanently poisons the owner`() {
        RuntimeBindingFixture().use { fixture ->
            fixture.capture().use { bindings ->
                Files.writeString(fixture.dockerConfig.resolve("config.json"), "{}")
                val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                    bindings.retainEndpointBinding()
                }
                assertTrue(failure.message.orEmpty().contains("Docker config"), failure.message)
            }
        }

        RuntimeBindingFixture().use { fixture ->
            val bindings = fixture.capture()
            val endpoint = bindings.retainEndpointBinding()
            try {
                fixture.replaceRuntimeSocket()
                val drift = assertFailsWith<PinnedDockerRuntimeBindingsException> { endpoint.requireCurrent() }
                assertTrue(drift.message.orEmpty().contains("socket"), drift.message)
                val poisoned = assertFailsWith<PinnedDockerRuntimeBindingsException> { endpoint.requireCurrent() }
                assertTrue(poisoned.message.orEmpty().contains("poisoned"), poisoned.message)
            } finally {
                endpoint.close()
            }
            val closed = assertFailsWith<PinnedDockerRuntimeBindingsException> { endpoint.requireCurrent() }
            assertTrue(closed.message.orEmpty().contains("closed"), closed.message)
        }
    }

    @Test
    fun `capture rejects digest drift hard links and a nonempty Docker config`() {
        RuntimeBindingFixture().use { fixture ->
            assertFailsWith<PinnedDockerRuntimeBindingsException> {
                fixture.capture(expectedSha256 = "0".repeat(64))
            }

            val link = fixture.root.resolve("control-client-link")
            Files.createLink(link, fixture.controlClient)
            assertFailsWith<PinnedDockerRuntimeBindingsException> { fixture.capture() }
            Files.delete(link)

            Files.writeString(fixture.dockerConfig.resolve("config.json"), "{}")
            assertFailsWith<PinnedDockerRuntimeBindingsException> { fixture.capture() }
        }
    }
}

private fun listenerEndpointType(): Class<*> = PinnedDockerRuntimeBindings::class.java.declaredClasses.single {
    it.simpleName == "PinnedDockerEndpointState"
}

private fun withListenerEndpointForTest(action: (Any, Int) -> Unit) {
    RuntimeBindingFixture().use { fixture ->
        fixture.capture().use { bindings ->
            val field = PinnedDockerRuntimeBindings::class.java.getDeclaredField("endpointState")
            assertTrue(field.trySetAccessible())
            action(field.get(bindings), Files.getAttribute(fixture.runtimeSocket, "unix:uid") as Int)
            fixture.assertNoPendingConnection()
        }
    }
}

/** Only the pinned identity and ucred ABI are simulated; the host socket retains its real UID. */
private fun withSimulatedPinnedListenerUidForTest(uid: Int, action: (Any) -> Unit) {
    withListenerEndpointForTest { endpoint, _ ->
        val type = listenerEndpointType()
        fun field(name: String): Any = type.getDeclaredField(name).also {
            assertTrue(it.trySetAccessible())
        }.get(endpoint)
        val constructor = type.getDeclaredConstructor(
            Path::class.java, LinuxDescriptor::class.java, LinuxDescriptor::class.java,
            LinuxFileIdentity::class.java, LinuxFileIdentity::class.java, java.lang.Boolean.TYPE,
        )
        assertTrue(constructor.trySetAccessible())
        // This read-only private fixture borrows existing descriptors. Its operations do not use
        // or close them; the original runtime binding remains their sole cleanup owner.
        val simulated = constructor.newInstance(
            field("runtimeSocketPath"), field("runtimeSocketParent"), field("runtimeSocketDescriptor"),
            field("runtimeSocketParentIdentity"), (field("runtimeSocketIdentity") as LinuxFileIdentity).copy(uid = uid),
            true,
        )
        action(simulated)
    }
}

private fun readListenerCredentialsForTest(endpoint: Any, libc: Any): Any? {
    val method = listenerEndpointType().declaredMethods.single { it.name == "readListenerCredentials" }
    return invokeListenerForTest(method, endpoint, libc, LISTENER_TEST_SOCKET_FD)
}

private fun readListenerSnapshotForTest(endpoint: Any, libc: Any): Any? {
    val method = listenerEndpointType().declaredMethods.single { it.name == "readListenerSnapshot" }
    return invokeListenerForTest(method, endpoint, libc, LISTENER_TEST_SOCKET_FD)
}

private fun invokeListenerForTest(method: java.lang.reflect.Method, receiver: Any, vararg arguments: Any?): Any? {
    assertTrue(method.trySetAccessible())
    return try {
        method.invoke(receiver, *arguments)
    } catch (failure: InvocationTargetException) {
        throw failure.targetException
    }
}

/** Test-only native option faults; these controls do not execute socket or pidfd kernel calls. */
private class ListenerNativeFaultControl(
    private val uid: Int,
    private val pidfdLength: Int = 4,
    private val peerPidfdErrno: Int? = null,
    private val descriptorFlags: Int = 1,
    private val changeSecondCredentialPid: Boolean = false,
    private val closeErrno: Int? = null,
) {
    val socketOptions = mutableListOf<Int>()
    val descriptorCommands = mutableListOf<Pair<Int, Int>>()
    val closedDescriptors = mutableListOf<Int>()
    var credentialReads = 0
        private set
    var livenessProbes = 0
        private set
    private val libcType = listenerEndpointType().declaredClasses.single { it.simpleName == "ListenerLibC" }
    val proxy: Any = Proxy.newProxyInstance(libcType.classLoader, arrayOf(libcType)) { _, method, supplied ->
        val arguments = supplied ?: emptyArray()
        when (method.name) {
            "getsockopt" -> {
                assertEquals(LISTENER_TEST_SOCKET_FD, arguments[0])
                assertEquals(1 /* SOL_SOCKET */, arguments[1])
                val option = arguments[2] as Int
                val value = arguments[3] as Pointer
                val length = arguments[4] as IntByReference
                socketOptions += option
                when (option) {
                    17 /* SO_PEERCRED */ -> {
                        assertEquals(12, length.value)
                        credentialReads++
                        value.setInt(0, if (changeSecondCredentialPid && credentialReads > 1) 32_002 else 32_001)
                        value.setInt(4, uid)
                        value.setInt(8, 32_003)
                        0
                    }
                    77 /* SO_PEERPIDFD */ -> {
                        assertEquals(4, length.value)
                        assertEquals(-1, value.getInt(0))
                        if (peerPidfdErrno != null) {
                            Native.setLastError(peerPidfdErrno)
                            -1
                        } else {
                            value.setInt(0, LISTENER_TEST_PIDFD)
                            length.value = pidfdLength
                            0
                        }
                    }
                    else -> error("unexpected simulated listener socket option $option")
                }
            }
            "fcntl" -> {
                val descriptor = arguments[0] as Int
                val command = arguments[1] as Int
                assertEquals(LISTENER_TEST_PIDFD, descriptor)
                assertEquals(1 /* F_GETFD */, command)
                descriptorCommands += descriptor to command
                descriptorFlags
            }
            "poll" -> {
                val pollfd = arguments[0] as Pointer
                assertEquals(1L, (arguments[1] as NativeLong).toLong())
                assertEquals(0, arguments[2])
                assertEquals(LISTENER_TEST_PIDFD, pollfd.getInt(0))
                assertEquals(1 /* POLLIN */, pollfd.getShort(4).toInt())
                assertEquals(0, pollfd.getShort(6).toInt())
                livenessProbes++
                0
            }
            "close" -> {
                closedDescriptors += arguments[0] as Int
                if (closeErrno != null) {
                    Native.setLastError(closeErrno)
                    -1
                } else 0
            }
            "toString" -> "test-only-listener-native-option-control"
            else -> error("unexpected native call in simulated option fault: ${method.name}")
        }
    }
}

private const val LISTENER_TEST_SOCKET_FD = 4_301
private const val LISTENER_TEST_PIDFD = 4_302

private fun verifyNativeTerminalForTest(bindings: PinnedDockerRuntimeBindings) {
    val bridge = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single {
        it.name == "verifyNativeRuntimeV2Terminal"
    }
    assertTrue(bridge.trySetAccessible())
    try {
        bridge.invoke(PinnedDockerRuntimeBindings.Companion, bindings,
            AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(2), "test native terminal binding verification"))
    } catch (failure: InvocationTargetException) {
        throw failure.targetException
    }
}

private class RuntimeBindingFixture : AutoCloseable {
    val root: Path = Files.createTempDirectory("pinned-docker-runtime-").toAbsolutePath().normalize()
    val controlClient: Path = root.resolve("docker-client")
    val dockerConfig: Path = root.resolve("docker-config")
    private val socketParent: Path = root.resolve("runtime")
    val runtimeSocket: Path = socketParent.resolve("docker.sock")
    val controlClientBytes = "authenticated-docker-client-fixture\n".encodeToByteArray()
    val controlClientSha256: String = OracleArtifacts.sha256(controlClientBytes)
    private var socketServer: ServerSocketChannel

    init {
        Files.setPosixFilePermissions(root, OWNER_DIRECTORY)
        Files.write(controlClient, controlClientBytes)
        Files.setPosixFilePermissions(controlClient, OWNER_EXECUTABLE)
        Files.createDirectory(dockerConfig)
        Files.setPosixFilePermissions(dockerConfig, OWNER_DIRECTORY)
        Files.createDirectory(socketParent)
        Files.setPosixFilePermissions(socketParent, OWNER_DIRECTORY)
        socketServer = bindRuntimeSocket(runtimeSocket)
    }

    fun capture(expectedSha256: String = controlClientSha256): PinnedDockerRuntimeBindings =
        PinnedDockerRuntimeBindings.capture(
            controlClientPath = controlClient,
            expectedControlClientBytes = controlClientBytes.size.toLong(),
            expectedControlClientSha256 = expectedSha256,
            maximumControlClientBytes = 1024 * 1024,
            dockerConfigPath = dockerConfig,
            runtimeSocketPath = runtimeSocket,
        )

    fun assertNoPendingConnection() {
        socketServer.configureBlocking(false)
        val pending = socketServer.accept()
        pending?.close()
        assertTrue(pending == null, "terminal verification contacted the native runtime socket")
    }

    fun replaceRuntimeSocket() {
        socketServer.close()
        Files.delete(runtimeSocket)
        socketServer = bindRuntimeSocket(runtimeSocket)
    }

    override fun close() {
        socketServer.close()
        Files.deleteIfExists(runtimeSocket)
        root.toFile().deleteRecursively()
    }
}

private fun bindRuntimeSocket(path: Path): ServerSocketChannel =
    ServerSocketChannel.open(StandardProtocolFamily.UNIX).also { channel ->
        channel.bind(UnixDomainSocketAddress.of(path))
        Files.setPosixFilePermissions(path, OWNER_SOCKET)
    }

private fun currentProcessFdPrefix(): String = "/proc/${ProcessHandle.current().pid()}/fd/"

private val OWNER_DIRECTORY = setOf(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
    PosixFilePermission.OWNER_EXECUTE,
)
private val OWNER_EXECUTABLE = setOf(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_EXECUTE,
)
private val OWNER_SOCKET = setOf(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
)
private val SHA256 = Regex("[0-9a-f]{64}")
