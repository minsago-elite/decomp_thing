package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import java.io.ByteArrayOutputStream
import java.lang.reflect.InvocationTargetException
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.system.measureNanoTime
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import sun.misc.Unsafe

class PinnedDockerEngineV155EndpointTest {
    @Test
    fun `private fixed HEAD ping accepts split framing and consumes both owners once`() {
        FakeUnixEngine(EngineBehavior.SPLIT_VALID).use { fixture ->
            val endpoint = fixture.captureEndpoint()
            val admittedEndpoint = wrapAsPrivateRetainedPreflightBinding(endpoint)
            val lease = fixture.freshLease()
            val operationId = lease.operationId
            val engine = LlvmBehaviorHostedToolchainImageEngineV1.open(admittedEndpoint, lease)

            assertFailsWith<PinnedDockerRuntimeBindingsException> { endpoint.requireCurrent() }
            assertFailsWith<LlvmBehaviorRuntimePreflightException> { admittedEndpoint.requireCurrent() }
            assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                lease.requireCurrentBinding()
            }
            endpoint.close()
            lease.close()
            assertEquals(operationId, engine.operationId)
            assertEquals(operationId, engine.buildId)
            assertEquals("1.55", engine.apiVersion)
            assertEquals("2", engine.builderVersion)
            assertEquals("linux", engine.operatingSystem)
            assertEquals("Docker/29.7.2 (linux)", engine.server)
            assertTrue(engine.headPingVerified)
            engine.requireCurrentBindings()
            assertContentEquals(FIXED_REQUEST, fixture.request())

            engine.close()
            engine.close()
            assertFailsWith<IllegalStateException> { engine.requireCurrentBindings() }
        }
    }

    @Test
    fun `sole public factory rejects an already armed fresh lease without issuing HEAD`() {
        FakeUnixEngine(EngineBehavior.SPLIT_VALID).use { fixture ->
            val endpoint = fixture.captureEndpoint()
            val admittedEndpoint = wrapAsPrivateRetainedPreflightBinding(endpoint)
            val lease = fixture.freshLease()
            lease.recordRecoveryLocatorsAbsent()
            lease.armImageBuildPost()
            val before = fixture.journalSnapshot()

            assertFailsWith<LlvmBehaviorHostedToolchainImageEngineV1Exception> {
                LlvmBehaviorHostedToolchainImageEngineV1.open(admittedEndpoint, lease)
            }

            assertEquals(before, fixture.journalSnapshot())
            assertFalse(fixture.awaitConnection(300), "an already-armed lease must not reach HEAD /_ping")
            assertFailsWith<PinnedDockerRuntimeBindingsException> { endpoint.requireCurrent() }
            assertFailsWith<LlvmBehaviorRuntimePreflightException> { admittedEndpoint.requireCurrent() }
            assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                lease.requireCurrentBinding()
            }
        }
    }

    @Test
    fun `public factory failure consumes endpoint and lease aliases on malformed response`() {
        FakeUnixEngine(EngineBehavior.RAW, "HTTP/1.1 500 Nope\r\n\r\n".encodeToByteArray()).use { fixture ->
            val endpoint = fixture.captureEndpoint()
            val admittedEndpoint = wrapAsPrivateRetainedPreflightBinding(endpoint)
            val lease = fixture.freshLease()

            assertFailsWith<LlvmBehaviorHostedToolchainImageEngineV1Exception> {
                LlvmBehaviorHostedToolchainImageEngineV1.open(admittedEndpoint, lease)
            }

            assertTrue(fixture.awaitConnection(2_000), "the malformed-response fixture was not contacted")
            assertFailsWith<PinnedDockerRuntimeBindingsException> { endpoint.requireCurrent() }
            assertFailsWith<LlvmBehaviorRuntimePreflightException> { admittedEndpoint.requireCurrent() }
            assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                lease.requireCurrentBinding()
            }
        }
    }

    @Test
    fun `strict bounded parser rejects malformed status headers framing and bodies`() {
        listOf(
            GOOD_RESPONSE.replace("HTTP/1.1 200 OK", "HTTP/1.0 200 OK"),
            GOOD_RESPONSE.replace("\r\n", "\n"),
            GOOD_RESPONSE.replace(
                "Content-Length: 0\r\n",
                "Content-Length: 0\r\nContent-Length: 0\r\n",
            ),
            GOOD_RESPONSE.replace("Content-Length: 0", "Transfer-Encoding: chunked"),
            GOOD_RESPONSE.replace("Api-Version: 1.55", "Api-Version: 1.54"),
            GOOD_RESPONSE.replace("Builder-Version: 2", "Builder-Version: 1"),
            GOOD_RESPONSE.replace("Ostype: linux", "Ostype: windows"),
            GOOD_RESPONSE.replace("Server: Docker/29.7.2 (linux)", "Server: Docker/29.7.1 (linux)"),
            GOOD_RESPONSE + "x",
            GOOD_RESPONSE.replace("Connection: close\r\n", ""),
            "HTTP/1.1 200 OK\r\nX-Fill: ${"x".repeat(4_200)}\r\n\r\n",
        ).forEachIndexed { index, response ->
            FakeUnixEngine(EngineBehavior.RAW, response.encodeToByteArray()).use { fixture ->
                val failure = assertFailsWith<PinnedDockerRuntimeBindingsException>("case $index") {
                    openPrivateEngine(fixture.captureEndpoint(), fixture.freshLease())
                }
                assertTrue(failure.message.orEmpty().contains("HEAD /_ping"), failure.message)
            }
        }
    }

    @Test
    fun `slow drip cannot renew the single monotonic response deadline`() {
        FakeUnixEngine(EngineBehavior.SLOW_DRIP).use { fixture ->
            val elapsed = measureNanoTime {
                val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                    openPrivateEngine(fixture.captureEndpoint(), fixture.freshLease())
                }
                assertTrue(failure.message.orEmpty().contains("deadline"), failure.message)
            }
            assertTrue(elapsed < TimeUnit.SECONDS.toNanos(5), "deadline took ${elapsed / 1_000_000} ms")
        }
    }

    @Test
    fun `persistent endpoint replacement fails closed`() {
        FakeUnixEngine(EngineBehavior.REPLACE_AFTER_REQUEST).use { fixture ->
            val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                openPrivateEngine(fixture.captureEndpoint(), fixture.freshLease())
            }
            assertTrue(failure.message.orEmpty().contains("socket directory mutated"), failure.message)
            assertContentEquals(FIXED_REQUEST, fixture.request())
        }
    }

    @Test
    fun `transient same UID socket swap and restore is detected by descriptor anchored inotify`() {
        FakeUnixEngine(EngineBehavior.TRANSIENT_SWAP_RESTORE).use { fixture ->
            val before = fixture.socketIdentity()
            val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                openPrivateEngine(fixture.captureEndpoint(), fixture.freshLease())
            }
            assertTrue(failure.message.orEmpty().contains("socket directory mutated"), failure.message)
            assertTrue(fixture.awaitTransientRestore(), "fake Engine did not restore the original socket name")
            assertEquals(before, fixture.socketIdentity(), "the hostile swap must be transient")
        }
    }
}

private fun openPrivateEngine(
    endpoint: PinnedDockerEndpointBinding,
    lease: LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner,
): LlvmBehaviorHostedToolchainImageEngineV1Owner {
    val method = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single {
        it.name == "openHostedToolchainImageEngineV1"
    }
    assertTrue(method.trySetAccessible())
    return try {
        method.invoke(PinnedDockerRuntimeBindings.Companion, endpoint, lease)
            as LlvmBehaviorHostedToolchainImageEngineV1Owner
    } catch (failure: InvocationTargetException) {
        throw failure.targetException
    }
}

/**
 * Test-only construction of the exact private preflight implementation. Production has no such
 * seam; this lets the fake Unix server exercise the public Engine factory without Docker.
 */
private fun wrapAsPrivateRetainedPreflightBinding(
    endpoint: PinnedDockerEndpointBinding,
): LlvmBehaviorRetainedDockerEndpointBinding {
    val implementation = LlvmBehaviorRuntimePreflightPublisher::class.java.declaredClasses.single {
        LlvmBehaviorRetainedDockerEndpointBinding::class.java.isAssignableFrom(it)
    }
    val unsafeField = Unsafe::class.java.getDeclaredField("theUnsafe")
    assertTrue(unsafeField.trySetAccessible())
    val unsafe = unsafeField.get(null) as Unsafe
    val binding = unsafe.allocateInstance(implementation) as LlvmBehaviorRetainedDockerEndpointBinding
    val endpointField = implementation.getDeclaredField("endpoint")
    assertTrue(endpointField.trySetAccessible())
    endpointField.set(binding, endpoint)
    return binding
}

private enum class EngineBehavior {
    SPLIT_VALID,
    RAW,
    SLOW_DRIP,
    REPLACE_AFTER_REQUEST,
    TRANSIENT_SWAP_RESTORE,
}

private class FakeUnixEngine(
    private val behavior: EngineBehavior,
    private val rawResponse: ByteArray = GOOD_RESPONSE.encodeToByteArray(),
) : AutoCloseable {
    private val root = Files.createTempDirectory("fixed-docker-engine-").toAbsolutePath().normalize()
    private val controlClient = root.resolve("docker-client")
    private val dockerConfig = root.resolve("docker-config")
    private val socketParent = root.resolve("runtime")
    private val socketPath = socketParent.resolve("docker.sock")
    private val recipeRoot = root.resolve("recipe")
    private val journalRoot = root.resolve("journal")
    private var server: ServerSocketChannel
    private var replacement: ServerSocketChannel? = null
    private val finished = CountDownLatch(1)
    private val connectionAccepted = CountDownLatch(1)
    private val transientRestored = CountDownLatch(1)
    @Volatile private var observedRequest: ByteArray? = null
    private val thread: Thread

    init {
        privateDirectory(root)
        Files.write(controlClient, "authenticated-client\n".encodeToByteArray())
        Files.setPosixFilePermissions(controlClient, PosixFilePermissions.fromString("r-x------"))
        privateDirectory(Files.createDirectory(dockerConfig))
        privateDirectory(Files.createDirectory(socketParent))
        privateDirectory(Files.createDirectory(recipeRoot))
        privateDirectory(Files.createDirectory(journalRoot))
        listOf("toolchain-reproduction.json", "build-record.json", "build-toolchain.Dockerfile")
            .forEach { name ->
                Files.copy(
                    CHECKED_RECIPE_ROOT.resolve(name),
                    recipeRoot.resolve(name),
                    StandardCopyOption.COPY_ATTRIBUTES,
                )
            }

        server = bindUnixServer(socketPath)
        thread = Thread.ofPlatform().daemon().name("fixed-docker-engine-fixture").start {
            try {
                server.accept().use { peer ->
                    connectionAccepted.countDown()
                    serve(peer)
                }
            } catch (_: Throwable) {
                // Deadline, mutation rejection, and teardown intentionally close live peers.
            } finally {
                finished.countDown()
            }
        }
    }

    fun captureEndpoint(): PinnedDockerEndpointBinding {
        val bytes = Files.readAllBytes(controlClient)
        return PinnedDockerRuntimeBindings.capture(
            controlClientPath = controlClient,
            expectedControlClientBytes = bytes.size.toLong(),
            expectedControlClientSha256 = OracleArtifacts.sha256(bytes),
            maximumControlClientBytes = 1024 * 1024,
            dockerConfigPath = dockerConfig,
            runtimeSocketPath = socketPath,
        ).retainEndpointBinding()
    }

    fun freshLease(): LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner {
        val recipe = LlvmBehaviorHostedToolchainImageRecipeV1.open(
            recipeRoot.resolve("toolchain-reproduction.json"),
            recipeRoot.resolve("build-record.json"),
            recipeRoot.resolve("build-toolchain.Dockerfile"),
        )
        return LlvmBehaviorHostedToolchainImageBuildLeaseV2.createFresh(
            journalRoot,
            recipe.transferToImageBuildLease(),
        )
    }

    fun request(): ByteArray {
        assertTrue(finished.await(5, TimeUnit.SECONDS), "fake Engine did not finish")
        return checkNotNull(observedRequest).copyOf()
    }

    fun awaitTransientRestore(): Boolean = transientRestored.await(5, TimeUnit.SECONDS)

    fun awaitConnection(milliseconds: Long): Boolean =
        connectionAccepted.await(milliseconds, TimeUnit.MILLISECONDS)

    fun journalSnapshot(): Map<String, List<Byte>> = Files.list(journalRoot).use { paths ->
        paths.sorted().map { path ->
            path.fileName.toString() to Files.readAllBytes(path).toList()
        }.toList().toMap()
    }

    fun socketIdentity(): Pair<Long, Long> =
        (Files.getAttribute(socketPath, "unix:dev", LinkOption.NOFOLLOW_LINKS) as Number).toLong() to
            (Files.getAttribute(socketPath, "unix:ino", LinkOption.NOFOLLOW_LINKS) as Number).toLong()

    private fun serve(peer: SocketChannel) {
        if (behavior == EngineBehavior.TRANSIENT_SWAP_RESTORE) transientSwapAndRestore()
        observedRequest = readRequest(peer)
        when (behavior) {
            EngineBehavior.SPLIT_VALID -> rawResponse.forEach { byte -> writeFully(peer, byteArrayOf(byte)) }
            EngineBehavior.RAW,
            EngineBehavior.TRANSIENT_SWAP_RESTORE,
            -> writeFully(peer, rawResponse)
            EngineBehavior.SLOW_DRIP -> rawResponse.forEach { byte ->
                writeFully(peer, byteArrayOf(byte))
                Thread.sleep(100)
            }
            EngineBehavior.REPLACE_AFTER_REQUEST -> {
                Files.delete(socketPath)
                replacement = bindUnixServer(socketPath)
                writeFully(peer, rawResponse)
            }
        }
    }

    private fun transientSwapAndRestore() {
        val displaced = socketParent.resolve("docker-original.sock")
        Files.move(socketPath, displaced)
        replacement = bindUnixServer(socketPath)
        replacement?.close()
        Files.delete(socketPath)
        Files.move(displaced, socketPath)
        transientRestored.countDown()
    }

    private fun readRequest(peer: SocketChannel): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteBuffer.allocate(64)
        while (output.size() <= 512) {
            buffer.clear()
            val read = peer.read(buffer)
            if (read < 0) break
            if (read == 0) continue
            output.write(buffer.array(), 0, read)
            if (output.toString(StandardCharsets.US_ASCII).endsWith("\r\n\r\n")) break
        }
        return output.toByteArray()
    }

    override fun close() {
        thread.interrupt()
        runCatching { server.close() }
        runCatching { replacement?.close() }
        finished.await(2, TimeUnit.SECONDS)
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach { path ->
                    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
                    } else if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
                    }
                    Files.deleteIfExists(path)
                }
            }
        }
    }
}

private fun privateDirectory(path: Path) {
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
}

private fun bindUnixServer(path: Path): ServerSocketChannel =
    ServerSocketChannel.open(StandardProtocolFamily.UNIX).also { channel ->
        channel.bind(UnixDomainSocketAddress.of(path))
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
    }

private fun writeFully(channel: SocketChannel, bytes: ByteArray) {
    val buffer = ByteBuffer.wrap(bytes)
    while (buffer.hasRemaining()) channel.write(buffer)
}

private val FIXED_REQUEST =
    "HEAD /_ping HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
        .toByteArray(StandardCharsets.US_ASCII)
private val GOOD_RESPONSE = listOf(
    "HTTP/1.1 200 OK",
    "Api-Version: 1.55",
    "Builder-Version: 2",
    "Cache-Control: no-cache, no-store, must-revalidate",
    "Connection: close",
    "Content-Length: 0",
    "Content-Type: text/plain; charset=utf-8",
    "Date: Tue, 01 Sep 2026 12:34:56 GMT",
    "Docker-Experimental: false",
    "Ostype: linux",
    "Pragma: no-cache",
    "Server: Docker/29.7.2 (linux)",
    "Swarm: inactive",
).joinToString("\r\n", postfix = "\r\n\r\n")
private val CHECKED_RECIPE_ROOT = Path.of("oracle/llvm/22.1.6")
