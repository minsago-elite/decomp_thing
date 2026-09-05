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
        val root = createTempDirectory("web-shutdown-")
        val log = root.resolve("child.log")
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}",
            "-cp", System.getProperty("java.class.path"),
            WebShutdownFixture::class.java.name, root.toString(),
        ).redirectErrorStream(true).redirectOutput(log.toFile()).apply { environment().clear() }.start()
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
            while (!Files.exists(root.resolve("ready")) && process.isAlive && System.nanoTime() < deadline) {
                Thread.sleep(20)
            }
            assertTrue(Files.exists(root.resolve("ready")), Files.readString(log))
            process.destroy()
            assertTrue(process.waitFor(15, TimeUnit.SECONDS), "shutdown hook did not finish")
            val ids = Files.readAllLines(root.resolve("ready"))
            val store = JobStore(root.resolve("jobs"))
            ids.take(2).forEach { id ->
                assertTrue(Files.exists(root.resolve("interrupted-$id")))
                assertEquals("failed", store.get(id).status)
            }
            assertEquals("failed", store.get(ids.last()).status)
            assertEquals("Server stopped before the operation started", store.get(ids.last()).statusMessage)
            assertTrue(!Files.exists(root.resolve("interrupted-${ids.last()}")))
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
        }
    }
}

/** Only waits on latches; never analyzes or executes the uploaded fixture. */
object WebShutdownFixture {
    @JvmStatic
    fun main(args: Array<String>) {
        val root = Path.of(args.single())
        val started = CountDownLatch(2)
        val neverReleased = CountDownLatch(1)
        val server = UploadServer("127.0.0.1", 0, root.resolve("jobs"),
            analyzer = JobAnalyzer { job, _ ->
                started.countDown()
                try {
                    neverReleased.await()
                } finally {
                    Files.writeString(root.resolve("interrupted-${job.id}"), "worker exited")
                }
            })
        startWebServerWithShutdownHook(server)
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
