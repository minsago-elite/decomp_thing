package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
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

    private fun verifyShutdown(swallowInterruption: Boolean, keepWaiting: Boolean = false) {
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
            val shutdownStarted = System.nanoTime()
            process.destroy()
            assertTrue(process.waitFor(15, TimeUnit.SECONDS), "shutdown hook did not finish")
            val ids = Files.readAllLines(root.resolve("ready"))
            val store = JobStore(root.resolve("jobs"))
            ids.take(2).forEach { id ->
                assertEquals(!keepWaiting, Files.exists(root.resolve("interrupted-$id")))
                assertEquals(if (keepWaiting) "analyzing" else "failed", store.get(id).status)
                if (swallowInterruption && !keepWaiting) {
                    assertEquals("Server stopped before the operation reported completion", store.get(id).statusMessage)
                }
            }
            assertEquals("failed", store.get(ids.last()).status)
            assertEquals("Server stopped before the operation started", store.get(ids.last()).statusMessage)
            assertTrue(!Files.exists(root.resolve("interrupted-${ids.last()}")))
            if (keepWaiting) {
                assertTrue(System.nanoTime() - shutdownStarted >= TimeUnit.SECONDS.toNanos(5))
                assertTrue(Files.readString(log).contains("Web shutdown did not complete cleanly; recovery is required"))
                val restarted = UploadServer("127.0.0.1", 0, root.resolve("jobs"),
                    analyzer = JobAnalyzer { _, _ -> error("recovery must not rerun a job") })
                try {
                    restarted.start()
                    ids.take(2).forEach { id ->
                        // Recovery projects interruption without overwriting historical legacy metadata.
                        assertEquals("analyzing", store.get(id).status)
                        val response = URI("http://127.0.0.1:${restarted.serverPort}/api/jobs/$id").toURL().openStream().use {
                            kotlinx.serialization.json.Json.parseToJsonElement(it.readBytes().decodeToString())
                        } as kotlinx.serialization.json.JsonObject
                        assertEquals(kotlinx.serialization.json.JsonPrimitive("failed"), response["status"])
                        // Recovery state is public; persisted/raw diagnostics and paths are not.
                        assertTrue("status_message" !in response)
                        assertTrue("binary_path" !in response)
                    }
                    assertEquals("Server stopped before the operation started", store.get(ids.last()).statusMessage)
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
        val store = JobStore(root.resolve("jobs"))
        val ids = (0..2).map { store.createFromUpload("benign-$it.elf", elfFixture()).id }
        val client = java.net.http.HttpClient.newHttpClient()
        ids.forEachIndexed { index, id ->
            val origin = "http://127.0.0.1:${server.serverPort}"
            val request = java.net.http.HttpRequest.newBuilder(URI("$origin/jobs/$id/explore"))
                .header("Origin", origin).timeout(java.time.Duration.ofSeconds(5))
                .POST(java.net.http.HttpRequest.BodyPublishers.noBody()).build()
            check(client.send(request, java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode() == 303)
            if (index == 1) check(started.await(5, TimeUnit.SECONDS))
        }
        Files.write(root.resolve("ready.tmp"), ids)
        Files.move(root.resolve("ready.tmp"), root.resolve("ready"), java.nio.file.StandardCopyOption.ATOMIC_MOVE)
    }
}
