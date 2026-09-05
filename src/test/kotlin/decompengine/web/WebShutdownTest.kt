package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import java.net.HttpURLConnection
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WebShutdownTest {
    @Test
    fun `JVM shutdown interrupts owned workers and persists discarded queued jobs`() {
        verifyShutdown(swallowInterruption = false)
    }

    @Test
    fun `workers returning after shutdown cannot report successful completion`() {
        verifyShutdown(swallowInterruption = true)
    }

    @Test
    fun `uncooperative workers exhaust the grace period and remain interrupted on restart`() {
        verifyShutdown(swallowInterruption = true, keepWaiting = true)
    }

    @Test
    fun `abrupt JVM death releases ownership and recovery marks active and queued jobs interrupted`() {
        verifyShutdown(swallowInterruption = false, abruptExit = true)
    }

    private fun verifyShutdown(swallowInterruption: Boolean, keepWaiting: Boolean = false, abruptExit: Boolean = false) {
        val root = createTempDirectory("web-shutdown-")
        val log = root.resolve("child.log")
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}",
            "-cp", System.getProperty("java.class.path"),
            WebShutdownFixture::class.java.name, root.toString(), swallowInterruption.toString(), keepWaiting.toString(),
        ).redirectErrorStream(true).redirectOutput(log.toFile()).apply { environment().clear() }.start()
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
            while (!Files.exists(root.resolve("ready")) && process.isAlive && System.nanoTime() < deadline) {
                Thread.sleep(20)
            }
            assertTrue(Files.exists(root.resolve("ready")), Files.readString(log))
            val ownershipFailure = kotlin.test.assertFailsWith<IllegalStateException> {
                UploadServer("127.0.0.1", 0, root.resolve("jobs"),
                    analyzer = JobAnalyzer { _, _ -> error("a second owner must not run work") })
            }
            assertEquals("Job store already has a live web server owner", ownershipFailure.message)
            val activeIds = Files.readAllLines(root.resolve("ready"))
            val activeStore = JobStore(root.resolve("jobs"))
            activeIds.take(2).forEach { assertEquals("analyzing", activeStore.get(it).status) }
            assertEquals("queued", activeStore.get(activeIds.last()).status)
            val shutdownStarted = System.nanoTime()
            if (abruptExit) process.destroyForcibly() else process.destroy()
            assertTrue(process.waitFor(15, TimeUnit.SECONDS), "child JVM did not terminate")
            val ids = Files.readAllLines(root.resolve("ready"))
            val store = JobStore(root.resolve("jobs"))
            ids.take(2).forEach { id ->
                assertEquals(!keepWaiting && !abruptExit, Files.exists(root.resolve("interrupted-$id")))
                assertEquals(if (keepWaiting || abruptExit) "analyzing" else "failed", store.get(id).status)
                if (swallowInterruption && !keepWaiting) {
                    assertEquals("Server stopped before the operation reported completion", store.get(id).statusMessage)
                }
            }
            assertEquals(if (abruptExit) "queued" else "failed", store.get(ids.last()).status)
            if (!abruptExit) assertEquals("Server stopped before the operation started", store.get(ids.last()).statusMessage)
            assertTrue(!Files.exists(root.resolve("interrupted-${ids.last()}")))
            if (keepWaiting) {
                assertTrue(System.nanoTime() - shutdownStarted >= TimeUnit.SECONDS.toNanos(5))
                assertTrue(Files.readString(log).contains("Web shutdown did not complete cleanly; recovery is required"))
            }
            if (abruptExit) {
                assertTrue(!Files.readString(log).contains("Web shutdown did not complete cleanly"))
            }
            if (keepWaiting || abruptExit) {
                val restarted = UploadServer("127.0.0.1", 0, root.resolve("jobs"),
                    analyzer = JobAnalyzer { _, _ -> error("recovery must not rerun a job") })
                try {
                    restarted.start()
                    (if (abruptExit) ids else ids.take(2)).forEach { id ->
                        // Recovery projects interruption without overwriting historical legacy metadata.
                        assertTrue(store.get(id).status in setOf("analyzing", "queued"))
                        val response = URI("http://127.0.0.1:${restarted.serverPort}/api/jobs/$id").toURL().openStream().use {
                            kotlinx.serialization.json.Json.parseToJsonElement(it.readBytes().decodeToString())
                        } as kotlinx.serialization.json.JsonObject
                        assertEquals(kotlinx.serialization.json.JsonPrimitive("failed"), response["status"])
                        assertTrue(response["status_message"].toString().contains("interrupted"))
                    }
                    if (!abruptExit) assertEquals("Server stopped before the operation started", store.get(ids.last()).statusMessage)
                } finally {
                    restarted.stop()
                }
            }
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
        }
    }
}

/** Only waits on latches; never analyzes or executes the uploaded fixture. */
object WebShutdownFixture {
    @JvmStatic
    fun main(args: Array<String>) {
        val root = Path.of(args[0])
        val swallowInterruption = args[1].toBooleanStrict()
        val keepWaiting = args[2].toBooleanStrict()
        val started = CountDownLatch(2)
        val neverReleased = CountDownLatch(1)
        val server = UploadServer("127.0.0.1", 0, root.resolve("jobs"),
            analyzer = JobAnalyzer { job, _ ->
                started.countDown()
                try {
                    neverReleased.await()
                } catch (failure: InterruptedException) {
                    if (!swallowInterruption) throw failure
                    if (keepWaiting) neverReleased.await()
                } finally {
                    Files.writeString(root.resolve("interrupted-${job.id}"), "worker exited")
                }
            })
        startWebServerWithShutdownHook(server)
        val localFailure = kotlin.test.assertFailsWith<IllegalStateException> { UploadServer("127.0.0.1", 0, root.resolve("jobs")) }
        check(localFailure.message == "Job store already has a live web server owner")
        val store = JobStore(root.resolve("jobs"))
        val ids = (0..2).map { store.createFromUpload("benign-$it.elf", elfFixture()).id }
        ids.forEachIndexed { index, id ->
            val connection = URI("http://127.0.0.1:${server.serverPort}/jobs/$id/explore")
                .toURL().openConnection() as HttpURLConnection
            try {
                connection.requestMethod = "POST"
                connection.instanceFollowRedirects = false
                connection.connectTimeout = 5000
                connection.readTimeout = 5000
                check(connection.responseCode == 303)
            } finally {
                connection.disconnect()
            }
            if (index == 1) check(started.await(5, TimeUnit.SECONDS))
        }
        Files.write(root.resolve("ready.tmp"), ids)
        Files.move(root.resolve("ready.tmp"), root.resolve("ready"), java.nio.file.StandardCopyOption.ATOMIC_MOVE)
    }
}
