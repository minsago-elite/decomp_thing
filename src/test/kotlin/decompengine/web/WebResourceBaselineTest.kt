package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.net.ConnectException
import java.net.Socket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Shutdown and resource-recovery qualification with harmless fake workers: shutdown closes admission
 * before it coordinates workers, interrupted work is persisted truthfully, and after repeated workload,
 * overload, slow-client and shutdown cycles the server's threads, descriptors, staging storage and heap
 * return to the baseline measured before the first server existed. Measurements are retained under
 * build/reports/web-resource-baseline/.
 */
class WebResourceBaselineTest {
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build()

    private data class Measurement(val threads: List<String>, val descriptors: Int, val heapBytes: Long)

    private fun measure(): Measurement {
        repeat(3) { System.gc(); Thread.sleep(50) }
        val runtime = Runtime.getRuntime()
        // The request-diagnostic sink is one process-wide daemon shared by every listener.
        val threads = Thread.getAllStackTraces().keys.filter { it.isAlive }.map { it.name }
            .filter { (it.startsWith("decomp-web") && it != "decomp-web-diagnostics") || it.startsWith("HTTP-Dispatcher") }.sorted()
        return Measurement(threads, descriptorCount(), runtime.totalMemory() - runtime.freeMemory())
    }

    private fun descriptorCount(): Int = Path.of("/proc/self/fd").let {
        if (Files.isDirectory(it)) Files.list(it).use { entries -> entries.count().toInt() } else 0
    }

    private fun awaitBaseline(baseline: Measurement): Measurement {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        var current = measure()
        while ((current.threads.isNotEmpty() || current.descriptors > baseline.descriptors + DESCRIPTOR_TOLERANCE) &&
            System.nanoTime() < deadline) {
            Thread.sleep(100)
            current = measure()
        }
        return current
    }

    @Test fun `shutdown refuses admission, persists interrupted work and every cycle returns to the recorded baseline`() {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-resource-baseline").toAbsolutePath())
        val root = Files.createTempDirectory(parent, "store-")
        val baseline = measure()
        val cycles = mutableListOf<Measurement>()
        try {
            repeat(CYCLES) { cycle ->
                runLegacyShutdownCycle(root.resolve("legacy"), cycle)
                runSpaWorkloadCycle(root.resolve("spa"))
                val after = awaitBaseline(baseline)
                cycles += after
                assertEquals(emptyList(), after.threads, "cycle $cycle left listener, worker or deadline threads alive")
                assertTrue(after.descriptors <= baseline.descriptors + DESCRIPTOR_TOLERANCE,
                    "cycle $cycle retained descriptors: baseline ${baseline.descriptors}, now ${after.descriptors}")
                listOf(root.resolve("legacy"), root.resolve("spa")).filter(Files::isDirectory).forEach { store ->
                    Files.list(store).use { entries ->
                        assertTrue(entries.noneMatch { it.fileName.toString().startsWith(".upload-") }, "retained upload staging in $store")
                    }
                }
            }
            val heapGrowth = cycles.last().heapBytes - baseline.heapBytes
            assertTrue(heapGrowth < HEAP_TOLERANCE_BYTES, "heap grew by $heapGrowth bytes across $CYCLES cycles")
        } finally {
            val report = buildJsonObject {
                put("schemaVersion", 1)
                put("cycles", CYCLES)
                put("descriptorTolerance", DESCRIPTOR_TOLERANCE)
                put("heapToleranceBytes", HEAP_TOLERANCE_BYTES)
                put("baseline", buildJsonObject { put("descriptors", baseline.descriptors); put("heapBytes", baseline.heapBytes); put("webThreads", baseline.threads.size) })
                put("afterEachCycle", buildJsonArray { cycles.forEach { m -> add(buildJsonObject {
                    put("descriptors", m.descriptors); put("heapBytes", m.heapBytes); put("webThreads", m.threads.size)
                }) } })
            }
            val reports = Files.createDirectories(Path.of("build/reports/web-resource-baseline"))
            Files.writeString(reports.resolve("measurements.json"), report.toString() + "\n")
            root.toFile().deleteRecursively()
        }
    }

    /** A legacy worker that is still unwinding after interruption cannot be joined by new requests. */
    private fun runLegacyShutdownCycle(store: Path, cycle: Int) {
        val jobId = JobStore(store).createFromUpload("cycle-$cycle.elf", elfFixture()).id
        val queuedId = JobStore(store).createFromUpload("queued-$cycle.elf", elfFixture()).id
        val running = CountDownLatch(1)
        val interrupted = CountDownLatch(1)
        val release = CountDownLatch(1)
        val server = UploadServer("127.0.0.1", 0, store, analyzer = JobAnalyzer { _, _ ->
            running.countDown()
            try { Thread.sleep(60_000) } catch (_: InterruptedException) {
                interrupted.countDown()
                // Unwind slowly, as a real tool would, so admission can be observed while workers stop.
                release.await(5, TimeUnit.SECONDS)
            }
        })
        server.start()
        val port = server.serverPort
        val headers = legacySessionHeaders(server)
        for (id in listOf(jobId, queuedId)) {
            val response = client.send(HttpRequest.newBuilder(URI("http://127.0.0.1:$port/jobs/$id/explore"))
                .header("Origin", "http://127.0.0.1:$port").header("Content-Type", "application/json")
                .header("Accept", "application/json").apply { headers.forEach { (k, v) -> header(k, v) } }
                .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.discarding())
            assertTrue(response.statusCode() in 200..399, "explore admission ${response.statusCode()}")
            if (id == jobId) assertTrue(running.await(10, TimeUnit.SECONDS), "the fake worker started")
        }
        val stopping = Thread { server.stop() }.apply { start() }
        assertTrue(interrupted.await(10, TimeUnit.SECONDS), "shutdown interrupts the running worker")
        assertFailsWith<ConnectException>("the listener refuses connections while workers stop") { Socket("127.0.0.1", port).close() }
        release.countDown()
        stopping.join(15_000)
        assertTrue(!stopping.isAlive, "stop completed")
        val persisted = JobStore(store)
        assertEquals("failed", persisted.get(jobId).status, "running work is persisted as stopped, never as complete")
        assertEquals("failed", persisted.get(queuedId).status, "queued work is persisted as discarded")
        assertTrue(persisted.get(jobId).statusMessage.orEmpty().contains("stopped", ignoreCase = true))
    }

    /** Completed uploads, refusals, overload-free slow clients and an orderly stop. */
    private fun runSpaWorkloadCycle(store: Path) {
        val server = UploadServer("127.0.0.1", 0, store, uiMode = WebUiMode.SPA, basePath = "/w/",
            admissionLimits = WebAdmissionLimits(headerDeadlineMs = 2_000, uploadDeadlineMs = 10_000))
        server.start()
        val port = server.serverPort
        val origin = "http://127.0.0.1:$port"
        val peers = mutableListOf<Socket>()
        try {
            val token = server.issueBrowserBootstrap().token
            val login = client.send(HttpRequest.newBuilder(URI("$origin/w/api/v1/session")).header("Origin", origin)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$token\"}")).build(), HttpResponse.BodyHandlers.ofString())
            val cookie = login.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            val csrf = Json.parseToJsonElement(login.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
            repeat(8) { index ->
                val boundary = "baseline_$index"
                val body = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"b$index.elf\"\r\n\r\n".toByteArray() +
                    elfFixture() + "\r\n--$boundary--\r\n".toByteArray()
                val response = client.send(HttpRequest.newBuilder(URI("$origin/w/api/v1/jobs")).header("Origin", origin)
                    .header("Cookie", cookie).header("X-CSRF-Token", csrf).header("Accept", "application/json")
                    .header("Idempotency-Key", "baseline_upload_key_$index${System.nanoTime()}")
                    .header("Content-Type", "multipart/form-data; boundary=$boundary")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(), HttpResponse.BodyHandlers.discarding())
                assertEquals(201, response.statusCode())
            }
            repeat(8) {
                val response = client.send(HttpRequest.newBuilder(URI("$origin/w/api/v1/jobs/${"f".repeat(32)}"))
                    .header("Cookie", cookie).header("Accept", "application/json").build(), HttpResponse.BodyHandlers.discarding())
                assertEquals(404, response.statusCode())
            }
            // Keep every peer open through EOF/reset AND worker/descriptor recovery. A timeout is
            // a failure, never permission for test-side cleanup to unblock the server's worker.
            val descriptorsBeforePeers = descriptorCount()
            repeat(4) {
                Socket("127.0.0.1", port).also { peers += it }.apply {
                    getOutputStream().write("GET /w/api/v1/bootstrap HTTP/1.1\r\nHost: x\r\nX-Slow: ".toByteArray())
                }
            }
            Socket("127.0.0.1", port).also { peers += it }.apply {
                getOutputStream().write(("POST /w/api/v1/jobs HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: $origin\r\nCookie: $cookie\r\n" +
                    "X-CSRF-Token: $csrf\r\nIdempotency-Key: stalled_baseline_0123456789\r\nAccept: application/json\r\n" +
                    "Content-Type: multipart/form-data; boundary=b\r\nContent-Length: 1048576\r\n\r\n" +
                    "--b\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"s.elf\"\r\n\r\n\u007fELF").toByteArray())
            }
            peers.forEach { socket ->
                socket.soTimeout = 30_000
                requireResourcePeerClosedByServer(socket)
            }
            // Only the client descriptors may remain; the pre-existing cycle bounds are unchanged.
            val descriptorLimit = descriptorsBeforePeers + peers.size + DESCRIPTOR_TOLERANCE
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while ((server.admissionSample().activeWorkers != 0 || descriptorCount() > descriptorLimit) &&
                System.nanoTime() < deadline) Thread.sleep(20)
            assertTrue(peers.none { it.isClosed }, "no client was closed to cause server recovery")
            assertEquals(0, server.admissionSample().activeWorkers, "workers recover with peers still open")
            assertTrue(descriptorCount() <= descriptorLimit, "server descriptors recover with peers still open")
            assertTrue(server.capacity.headerDeadlineClosures.get() >= 4)
            assertTrue(server.capacity.requestDeadlineClosures.get() >= 1)
        } finally {
            try { peers.forEach { it.close() } } finally { server.stop() }
        }
    }

    private companion object {
        const val CYCLES = 3
        const val DESCRIPTOR_TOLERANCE = 4
        const val HEAP_TOLERANCE_BYTES = 64L * 1024 * 1024
    }
}
