package decompengine.oracle.behavior

import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleArtifacts
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
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
