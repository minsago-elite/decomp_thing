package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.repair.StableFileDigest
import java.io.IOException
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Structure record delivery verifies the committed digest before headers and streams with a held-back final chunk. */
class WebStructureRecordDeliveryTest {
    private val bytes = ByteArray(200_000) { (it % 251).toByte() }
    private val identity = LinuxFileIdentity(LinuxFileKey(1, 7), 0x8180, 1000, 1000, 1, 1, true, false, false)
    private fun sha(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }

    private class Reads { var passes = 0; var largestChunk = 0; var changeSecondPass = false; @Volatile var failure: Throwable? = null }

    private fun <T> listener(record: WebProgramStructurePages.RecordDownload, reads: Reads, block: (String) -> T): T {
        val delivery = WebStructureRecordDelivery { _, runId, path, declared, consume, cancellation ->
            assertEquals(record.runId, runId); assertEquals(record.path, path)
            reads.passes++
            val source = if (reads.changeSecondPass && reads.passes == 2) bytes.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
                else bytes
            declared(source.size.toLong())
            var offset = 0
            while (offset < source.size) {
                cancellation()
                val count = minOf(64 * 1024, source.size - offset)
                reads.largestChunk = maxOf(reads.largestChunk, count)
                consume(source.copyOfRange(offset, offset + count), count)
                offset += count
            }
            StableFileDigest(sha(source), source.size.toLong(), identity, false)
        }
        val http = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val worker = Executors.newFixedThreadPool(2)
        http.executor = worker
        http.createContext("/") { exchange ->
            try { delivery.send(exchange, "a".repeat(32), record) }
            catch (failure: WebAccessDenied) {
                exchange.sendResponseHeaders(failure.status, -1); exchange.close()
            } catch (failure: Exception) {
                // Escaping the handler makes the JDK server close the short connection.
                reads.failure = failure; throw failure
            }
        }
        http.start()
        try { return block("http://127.0.0.1:${http.address.port}/") }
        finally { http.stop(0); worker.shutdownNow(); worker.awaitTermination(3, TimeUnit.SECONDS) }
    }

    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
    private fun record(sha256: String = sha(bytes), maximum: Long = 64L * 1024 * 1024) =
        WebProgramStructurePages.RecordDownload("program_model.json", "run_1", "source-tree/reports/program_model.json", sha256, maximum)

    @Test fun `a committed record streams exactly after its digest is reproduced`() {
        val reads = Reads()
        listener(record(), reads) { origin ->
            val response = client.send(HttpRequest.newBuilder(URI(origin)).timeout(Duration.ofSeconds(20)).build(), HttpResponse.BodyHandlers.ofByteArray())
            assertEquals(200, response.statusCode())
            assertContentEquals(bytes, response.body())
            assertEquals(bytes.size.toString(), response.headers().firstValue("Content-Length").orElseThrow())
            assertEquals(sha(bytes), response.headers().firstValue("X-Decomp-Content-SHA256").orElseThrow())
            assertEquals("committed-digest", response.headers().firstValue("X-Decomp-Content-Verification").orElseThrow())
            assertTrue(response.headers().firstValue("Content-Disposition").orElseThrow().endsWith("filename*=UTF-8''program_model.json"))
            assertEquals("application/octet-stream", response.headers().firstValue("Content-Type").orElseThrow())
        }
        // One verification pass and one delivery pass, each in bounded chunks: the record is never buffered whole.
        assertEquals(2, reads.passes); assertTrue(reads.largestChunk <= 64 * 1024)
    }

    @Test fun `HEAD verifies without streaming the body`() {
        val reads = Reads()
        listener(record(), reads) { origin ->
            val response = client.send(HttpRequest.newBuilder(URI(origin)).timeout(Duration.ofSeconds(20)).method("HEAD", HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofByteArray())
            assertEquals(200, response.statusCode()); assertEquals(0, response.body().size)
        }
        assertEquals(1, reads.passes)
    }

    @Test fun `a record that no longer has its committed digest is refused before any header`() {
        val reads = Reads()
        listener(record(sha256 = "0".repeat(64)), reads) { origin ->
            assertEquals(409, client.send(HttpRequest.newBuilder(URI(origin)).timeout(Duration.ofSeconds(20)).build(), HttpResponse.BodyHandlers.ofByteArray()).statusCode())
        }
        assertEquals(1, reads.passes)
        listener(record(maximum = bytes.size - 1L), Reads()) { origin ->
            assertEquals(413, client.send(HttpRequest.newBuilder(URI(origin)).timeout(Duration.ofSeconds(20)).build(), HttpResponse.BodyHandlers.ofByteArray()).statusCode())
        }
    }

    @Test fun `a record that changes while streaming is closed short of its declared length`() {
        val reads = Reads().apply { changeSecondPass = true }
        listener(record(), reads) { origin ->
            val received = try {
                client.send(HttpRequest.newBuilder(URI(origin)).timeout(Duration.ofSeconds(20)).build(), HttpResponse.BodyHandlers.ofByteArray()).body()
            } catch (_: IOException) { null }
            // The final chunk, which carries the change, is never released.
            if (received != null) assertTrue(received.size < bytes.size)
        }
        assertEquals(2, reads.passes)
        // The failure after the headers is an abort the listener sees, wrapping the digest mismatch.
        assertTrue(reads.failure is WebResponseAborted && reads.failure?.cause is IllegalStateException, reads.failure.toString())
    }
}
