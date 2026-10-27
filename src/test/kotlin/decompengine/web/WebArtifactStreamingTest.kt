package decompengine.web

import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.io.InputStream
import java.io.RandomAccessFile
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import kotlin.io.path.createTempDirectory
import kotlin.test.*

/** Actual listener, store and descriptor-pinned reads over synthetic artifact bytes; no workflow executes. */
class WebArtifactStreamingTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    private val octets = "application/octet-stream"

    private class Fixture(val server: UploadServer, val root: Path, val jobId: String, val runId: String, val cookie: String) {
        val reports: Path = root.resolve(jobId).resolve("reports/runs/$runId")
        val api = "/w/api/v1/jobs/$jobId"
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-artifacts").toAbsolutePath())
        val root = createTempDirectory(parent, "stream-")
        val store = JobStore(root)
        val job = store.createFromUpload("inert.elf", elfFixture())
        val run = WorkflowAttemptStore.open(root).use { owner ->
            val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        }
        Files.createDirectories(root.resolve(job.id).resolve("reports/runs/${run.runId}"))
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") }, uiMode = WebUiMode.SPA, basePath = "/w/")
        server.start()
        try {
            val token = server.issueBrowserBootstrap().token
            val origin = "http://127.0.0.1:${server.serverPort}"
            val session = client.send(HttpRequest.newBuilder(URI("$origin/w/api/v1/session")).header("Origin", origin)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$token\"}")).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, session.statusCode())
            block(Fixture(server, root, job.id, run.runId, session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')))
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    private fun builder(fixture: Fixture, path: String, accept: String, headers: Map<String, String>): HttpRequest.Builder {
        val request = HttpRequest.newBuilder(URI("http://127.0.0.1:${fixture.server.serverPort}$path")).timeout(Duration.ofSeconds(30))
            .header("Accept", accept).header("Cookie", fixture.cookie)
        headers.forEach { (key, value) -> request.header(key, value) }
        return request
    }

    private fun get(fixture: Fixture, path: String, accept: String = "application/json", headers: Map<String, String> = emptyMap(), method: String = "GET") =
        client.send(builder(fixture, path, accept, headers).method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofByteArray())

    private fun json(response: HttpResponse<ByteArray>): JsonObject = Json.parseToJsonElement(String(response.body())).jsonObject

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun catalog(fixture: Fixture): List<JsonObject> {
        val response = get(fixture, "${fixture.api}/artifacts?runId=${fixture.runId}")
        assertEquals(200, response.statusCode(), String(response.body()))
        assertEquals("artifacts", json(response).getValue("kind").jsonPrimitive.content)
        return json(response).getValue("data").jsonObject.getValue("items").jsonArray.map { it.jsonObject }
    }

    private fun waitFor(condition: () -> Boolean) {
        val stop = System.nanoTime() + 10_000_000_000
        while (!condition() && System.nanoTime() < stop) Thread.sleep(10)
        assertTrue(condition())
    }

    private fun openDescriptorsTo(target: Path): Int = Files.list(Path.of("/proc/self/fd")).use { links ->
        links.toList().count { link -> try { Files.readSymbolicLink(link).toString() == target.toAbsolutePath().toString() } catch (_: Exception) { false } }
    }

    @Test fun `catalog detail and digest bound downloads stream exact bytes with HTTP range and precondition semantics`() = withFixture { fixture ->
        val archive = ByteArray(24 * 1024 * 1024 + 17) { (it * 31 + it / 4096).toByte() }
        Files.write(fixture.reports.resolve("source-tree.zip"), archive)
        Files.writeString(fixture.reports.resolve("exploration.json"), "{\"x\":\"<script>inert</script>\"}")
        val items = catalog(fixture)
        assertEquals(listOf("exploration-report", "source-archive"), items.map { it.getValue("family").jsonPrimitive.content })
        val item = items.last()
        assertEquals(sha256(archive), item.getValue("sha256").jsonPrimitive.content)
        assertEquals(archive.size.toString(), item.getValue("sizeBytes").jsonPrimitive.content)
        assertEquals("not-verified", item.getValue("verification").jsonPrimitive.content)
        val id = item.getValue("artifactId").jsonPrimitive.content
        val href = item.getValue("contentHref").jsonPrimitive.content
        assertEquals("${fixture.api}/artifacts/$id/content", href)
        val detail = get(fixture, "${fixture.api}/artifacts/$id")
        assertEquals(200, detail.statusCode()); assertEquals(item, json(detail).getValue("data").jsonObject)

        val full = get(fixture, href, octets)
        assertEquals(200, full.statusCode()); assertContentEquals(archive, full.body())
        val headers = full.headers()
        assertEquals(octets, headers.firstValue("Content-Type").orElseThrow())
        assertEquals("attachment; filename=\"source-tree.zip\"; filename*=UTF-8''source-tree.zip", headers.firstValue("Content-Disposition").orElseThrow())
        assertEquals("nosniff", headers.firstValue("X-Content-Type-Options").orElseThrow())
        assertEquals(WEB_INERT_CONTENT_SECURITY_POLICY, headers.firstValue("Content-Security-Policy").orElseThrow())
        assertEquals("no-store", headers.firstValue("Cache-Control").orElseThrow())
        assertEquals("bytes", headers.firstValue("Accept-Ranges").orElseThrow())
        val etag = "\"${sha256(archive)}\""
        assertEquals(etag, headers.firstValue("ETag").orElseThrow())
        assertEquals(sha256(archive), headers.firstValue("X-Decomp-Content-SHA256").orElseThrow())

        val head = get(fixture, href, octets, method = "HEAD")
        assertEquals(200, head.statusCode()); assertEquals(0, head.body().size)
        assertEquals(archive.size.toString(), head.headers().firstValue("Content-Length").orElseThrow())
        assertEquals(etag, head.headers().firstValue("ETag").orElseThrow())

        val middle = get(fixture, href, octets, mapOf("Range" to "bytes=1000-70000"))
        assertEquals(206, middle.statusCode()); assertContentEquals(archive.copyOfRange(1000, 70001), middle.body())
        assertEquals("bytes 1000-70000/${archive.size}", middle.headers().firstValue("Content-Range").orElseThrow())
        val suffix = get(fixture, href, octets, mapOf("Range" to "bytes=-5"))
        assertContentEquals(archive.copyOfRange(archive.size - 5, archive.size), suffix.body())
        val resumed = get(fixture, href, octets, mapOf("Range" to "bytes=${archive.size - 100}-", "If-Range" to etag))
        assertEquals(206, resumed.statusCode()); assertContentEquals(archive.copyOfRange(archive.size - 100, archive.size), resumed.body())
        val staleResume = get(fixture, href, octets, mapOf("Range" to "bytes=0-9", "If-Range" to "\"${"0".repeat(64)}\""))
        assertEquals(200, staleResume.statusCode()); assertEquals(archive.size, staleResume.body().size)
        assertEquals(200, get(fixture, href, octets, mapOf("Range" to "bytes=0-1,4-5")).statusCode())
        val unsatisfiable = get(fixture, href, octets, mapOf("Range" to "bytes=${archive.size}-"))
        assertEquals(416, unsatisfiable.statusCode())
        assertEquals("bytes */${archive.size}", unsatisfiable.headers().firstValue("Content-Range").orElseThrow())
        assertEquals(304, get(fixture, href, octets, mapOf("If-None-Match" to etag)).statusCode())
        assertEquals(304, get(fixture, href, octets, mapOf("If-None-Match" to etag), "HEAD").statusCode())
        assertEquals(304, get(fixture, href, octets, mapOf("If-None-Match" to "\"other\", W/$etag")).statusCode())
        assertEquals(200, get(fixture, href, octets, mapOf("If-None-Match" to "W/\"${"0".repeat(64)}\""), "HEAD").statusCode())
        // If-Match keeps strong comparison: a weak validator never satisfies it.
        assertEquals(412, get(fixture, href, octets, mapOf("If-Match" to "W/$etag"), "HEAD").statusCode())
        assertEquals(412, get(fixture, href, octets, mapOf("If-Match" to "\"${"0".repeat(64)}\"")).statusCode())
        assertEquals(200, get(fixture, href, octets, mapOf("If-Match" to etag), "HEAD").statusCode())
        assertEquals(400, get(fixture, href, octets, mapOf("If-Unmodified-Since" to "Mon, 01 Jan 2024 00:00:00 GMT")).statusCode())
        assertEquals(406, get(fixture, href, "text/html").statusCode())
        assertEquals(400, get(fixture, "$href?path=../input.elf", octets).statusCode())
        // Foreign and forged identities never reach another job or path.
        assertEquals(404, get(fixture, "/w/api/v1/jobs/${"b".repeat(32)}/artifacts/$id/content", octets).statusCode())
        assertEquals(404, get(fixture, "${fixture.api}/artifacts/archive_${"0".repeat(32)}_${sha256(archive)}/content", octets).statusCode())
        waitFor { fixture.server.activeArtifactDownloads() == 0 }

        Files.write(fixture.reports.resolve("source-tree.zip"), archive.copyOf().also { it[5] = (it[5] + 1).toByte() })
        assertEquals(409, get(fixture, href, octets).statusCode())
        assertEquals(409, get(fixture, "${fixture.api}/artifacts/$id").statusCode())
        Files.delete(fixture.reports.resolve("source-tree.zip"))
        assertEquals(404, get(fixture, href, octets).statusCode())
    }

    @Test fun `aborted and concurrent downloads release descriptors and admission without blocking other reads`() = withFixture { fixture ->
        val file = fixture.reports.resolve("source-tree.zip")
        val archive = ByteArray(48 * 1024 * 1024) { (it % 251).toByte() }
        Files.write(file, archive)
        val href = catalog(fixture).single().getValue("contentHref").jsonPrimitive.content
        fun open(): HttpResponse<InputStream> = client.send(builder(fixture, href, octets, emptyMap()).GET().build(), HttpResponse.BodyHandlers.ofInputStream())
        val first = open(); val second = open()
        assertEquals(200, first.statusCode()); assertEquals(200, second.statusCode())
        first.body().readNBytes(1024); second.body().readNBytes(1024)
        // The same heavy-IO admission covers catalog/detail hashing, including bodyless HEAD.
        assertEquals(429, get(fixture, href, octets).statusCode())
        for (method in listOf("GET", "HEAD")) {
            assertEquals(429, get(fixture, "${fixture.api}/artifacts", method = method).statusCode())
            assertEquals(429, get(fixture, href.removeSuffix("/content"), method = method).statusCode())
        }
        assertEquals(200, get(fixture, "${fixture.api}/runs").statusCode())
        assertTrue(openDescriptorsTo(file) >= 1)
        first.body().close(); second.body().close()
        waitFor { fixture.server.activeArtifactDownloads() == 0 }
        waitFor { openDescriptorsTo(file) == 0 }
        assertEquals(200, get(fixture, "${fixture.api}/artifacts").statusCode())
        assertEquals(200, get(fixture, href.removeSuffix("/content")).statusCode())
        assertContentEquals(archive, get(fixture, href, octets).body())
        waitFor { fixture.server.activeArtifactDownloads() == 0 }
    }

    @Test fun `a growing artifact is refused before bytes beyond its authorized size are consumed`() {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-artifacts").toAbsolutePath())
        val root = createTempDirectory(parent, "grow-")
        try {
            val store = JobStore(root)
            val job = store.createFromUpload("inert.elf", elfFixture())
            val file = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/run_1")).resolve("source-tree.zip")
            val initial = ByteArray(256 * 1024) { it.toByte() }
            Files.write(file, initial)
            var declared = -1L; var consumed = 0L; var grown = false
            val failure = assertFailsWith<IllegalArgumentException> {
                store.streamArtifact(job.id, "reports/runs/run_1/source-tree.zip", { declared = it }, { _, count ->
                    consumed += count
                    if (!grown) { grown = true; Files.write(file, ByteArray(4 * 1024 * 1024), java.nio.file.StandardOpenOption.APPEND) }
                }, {})
            }
            assertTrue(failure.message.orEmpty().contains("grew"))
            assertEquals(initial.size.toLong(), declared)
            assertTrue(consumed <= declared, "consumed $consumed bytes beyond the authorized $declared")
            // Cancellation is observed between chunks as well.
            Files.write(file, ByteArray(1024 * 1024))
            var chunks = 0
            assertFailsWith<java.util.concurrent.CancellationException> {
                store.streamArtifact(job.id, "reports/runs/run_1/source-tree.zip", {}, { _, _ -> chunks++ }, {
                    if (chunks >= 2) throw java.util.concurrent.CancellationException("closed")
                })
            }
            assertEquals(2, chunks)
        } finally { root.toFile().deleteRecursively() }
    }

    @Test fun `bytes changed during a stream are never delivered as a complete download`() = withFixture { fixture ->
        val file = fixture.reports.resolve("source-tree.zip")
        val archive = ByteArray(48 * 1024 * 1024) { (it % 239).toByte() }
        Files.write(file, archive)
        val href = catalog(fixture).single().getValue("contentHref").jsonPrimitive.content
        val response = client.send(builder(fixture, href, octets, emptyMap()).GET().build(), HttpResponse.BodyHandlers.ofInputStream())
        assertEquals(200, response.statusCode())
        assertEquals(archive.size.toString(), response.headers().firstValue("Content-Length").orElseThrow())
        val received = response.body().readNBytes(1024 * 1024)
        assertContentEquals(archive.copyOf(received.size), received)
        RandomAccessFile(file.toFile(), "rw").use { it.seek(archive.size - 10L); it.write(byteArrayOf(1, 2, 3)) }
        val rest = try { response.body().readAllBytes() } catch (_: java.io.IOException) { ByteArray(0) }
        assertTrue(received.size + rest.size < archive.size, "a changed artifact completed its declared length")
        waitFor { fixture.server.activeArtifactDownloads() == 0 }
        waitFor { openDescriptorsTo(file) == 0 }
    }
}
