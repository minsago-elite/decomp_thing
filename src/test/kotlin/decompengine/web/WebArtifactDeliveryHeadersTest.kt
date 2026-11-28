package decompengine.web

import decompengine.jobs.*
import kotlinx.serialization.json.*
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

/**
 * Response contract per trust level over the actual listener (#491): verbatim job bytes and redacted server reports are
 * inert private attachments, catalog metadata is private JSON, and every refusal is private JSON that carries no artifact
 * identity, validator or byte. Access is only by server-issued artifact IDs; no route accepts a browser path.
 */
class WebArtifactDeliveryHeadersTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    private val octets = "application/octet-stream"

    private class Fixture(val server: UploadServer, val root: Path, val jobId: String, val runId: String, val cookie: String) {
        val reports: Path = root.resolve(jobId).resolve("reports/runs/$runId")
        val api = "/w/api/v1/jobs/$jobId"
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-artifact-headers").toAbsolutePath())
        val root = createTempDirectory(parent, "headers-")
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

    private fun send(fixture: Fixture, path: String, accept: String = "application/json", headers: Map<String, String> = emptyMap(),
        method: String = "GET", cookie: Boolean = true): HttpResponse<ByteArray> {
        val request = HttpRequest.newBuilder(URI("http://127.0.0.1:${fixture.server.serverPort}$path")).timeout(Duration.ofSeconds(30))
            .header("Accept", accept)
        if (cookie) request.header("Cookie", fixture.cookie)
        headers.forEach { (key, value) -> request.header(key, value) }
        return client.send(request.method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofByteArray())
    }

    private fun header(response: HttpResponse<*>, name: String): String? = response.headers().firstValue(name).orElse(null)

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** Headers shared by every private response: never stored, never framed, never sniffed, never given script authority. */
    private fun assertPrivateInert(response: HttpResponse<*>) {
        assertEquals("no-store", header(response, "Cache-Control"), response.uri().toString())
        assertEquals("nosniff", header(response, "X-Content-Type-Options"))
        assertEquals("no-referrer", header(response, "Referrer-Policy"))
        assertEquals("DENY", header(response, "X-Frame-Options"))
        assertEquals(WEB_INERT_CONTENT_SECURITY_POLICY, header(response, "Content-Security-Policy"))
        assertNotNull(header(response, "X-Request-ID"))
    }

    /** Job or report bytes: an inert octet-stream attachment whatever the listed media type, bound to its artifact ID. */
    private fun assertAttachment(response: HttpResponse<*>, name: String, artifactId: String, projection: String) {
        assertPrivateInert(response)
        if (response.statusCode() != 304) assertEquals(octets, header(response, "Content-Type"))
        assertEquals("attachment; filename=\"$name\"; filename*=UTF-8''$name", header(response, "Content-Disposition"))
        assertEquals(artifactId, header(response, "X-Decomp-Artifact-ID"))
        assertEquals(projection, header(response, "X-Decomp-Content-Projection"))
        assertEquals("\"${header(response, "X-Decomp-Content-SHA256")}\"", header(response, "ETag"))
    }

    /** A refusal is fixed private JSON: no disposition, validator, artifact identity or artifact byte. */
    private fun assertRefusal(response: HttpResponse<ByteArray>, status: Int, code: String, vararg withheld: ByteArray) {
        assertEquals(status, response.statusCode(), String(response.body()))
        assertPrivateInert(response)
        assertEquals("application/json; charset=utf-8", header(response, "Content-Type"))
        for (name in listOf("Content-Disposition", "ETag", "Accept-Ranges", "X-Decomp-Artifact-ID", "X-Decomp-Content-SHA256",
            "X-Decomp-Artifact-SHA256", "X-Decomp-Content-Projection")) assertNull(header(response, name), "$name on $status $code")
        if (response.request().method() != "HEAD") {
            val error = Json.parseToJsonElement(String(response.body())).jsonObject.getValue("error").jsonObject
            assertEquals(code, error.getValue("code").jsonPrimitive.content)
            for (bytes in withheld) assertFalse(String(response.body()).contains(String(bytes)), "refusal leaked artifact bytes")
        }
    }

    @Test fun `verbatim and redacted artifact content are inert private attachments and refusals carry no artifact bytes`() = withFixture { fixture ->
        // Active markup canaries: neither the archive nor the report may ever be served as trusted UI.
        val archive = "PK\u0003\u0004<html><script>parent.archiveCanary=1</script></html>".toByteArray() + ByteArray(4096) { it.toByte() }
        val report = "{\"x\":\"<script>parent.reportCanary=1</script>\"}".toByteArray()
        Files.write(fixture.reports.resolve("source-tree.zip"), archive)
        Files.write(fixture.reports.resolve("exploration.json"), report)

        val catalog = send(fixture, "${fixture.api}/artifacts?runId=${fixture.runId}")
        assertEquals(200, catalog.statusCode())
        assertPrivateInert(catalog)
        assertEquals("application/json; charset=utf-8", header(catalog, "Content-Type"))
        assertNull(header(catalog, "Content-Disposition"))
        // The catalog is the only source of access paths: server-issued routes, no host or job-store path.
        assertFalse(String(catalog.body()).contains(fixture.root.toString()))
        assertFalse(String(catalog.body()).contains("reports/runs"))
        val items = Json.parseToJsonElement(String(catalog.body())).jsonObject.getValue("data").jsonObject.getValue("items").jsonArray
            .map { it.jsonObject }.associateBy { it.getValue("family").jsonPrimitive.content }
        val archiveItem = items.getValue("source-archive"); val reportItem = items.getValue("exploration-report")
        val archiveId = archiveItem.getValue("artifactId").jsonPrimitive.content
        val reportId = reportItem.getValue("artifactId").jsonPrimitive.content
        val archiveHref = archiveItem.getValue("contentHref").jsonPrimitive.content
        val reportHref = reportItem.getValue("contentHref").jsonPrimitive.content
        assertEquals("${fixture.api}/artifacts/$archiveId/content", archiveHref)
        assertEquals("${fixture.api}/artifacts/$reportId/content", reportHref)
        assertEquals("application/zip", archiveItem.getValue("mediaType").jsonPrimitive.content)
        assertEquals("application/json", reportItem.getValue("mediaType").jsonPrimitive.content)

        val detail = send(fixture, "${fixture.api}/artifacts/$archiveId")
        assertEquals(200, detail.statusCode()); assertPrivateInert(detail); assertNull(header(detail, "Content-Disposition"))

        // Verbatim job content: exact bytes for GET, HEAD, ranges and revalidation, all under the same attachment headers.
        val etag = "\"${sha256(archive)}\""
        val full = send(fixture, archiveHref, octets)
        assertEquals(200, full.statusCode()); assertContentEquals(archive, full.body())
        assertAttachment(full, "source-tree.zip", archiveId, "verbatim")
        assertEquals(archive.size.toString(), header(full, "Content-Length"))
        assertEquals("bytes", header(full, "Accept-Ranges"))
        val head = send(fixture, archiveHref, octets, method = "HEAD")
        assertEquals(200, head.statusCode()); assertEquals(0, head.body().size)
        assertAttachment(head, "source-tree.zip", archiveId, "verbatim")
        assertEquals(archive.size.toString(), header(head, "Content-Length"))
        val partial = send(fixture, archiveHref, octets, mapOf("Range" to "bytes=4-9"))
        assertEquals(206, partial.statusCode()); assertContentEquals(archive.copyOfRange(4, 10), partial.body())
        assertAttachment(partial, "source-tree.zip", archiveId, "verbatim")
        assertEquals("bytes 4-9/${archive.size}", header(partial, "Content-Range"))
        assertEquals("6", header(partial, "Content-Length"))
        val notModified = send(fixture, archiveHref, octets, mapOf("If-None-Match" to etag))
        assertEquals(304, notModified.statusCode()); assertEquals(0, notModified.body().size)
        assertAttachment(notModified, "source-tree.zip", archiveId, "verbatim")
        assertNull(header(notModified, "Content-Type"))

        // Server-produced reports are served as the redacted projection, never raw, under the same inert headers.
        val projected = send(fixture, reportHref, octets)
        assertEquals(200, projected.statusCode())
        assertAttachment(projected, "exploration.json", reportId, "redacted")
        assertEquals(sha256(report), header(projected, "X-Decomp-Artifact-SHA256"))
        assertEquals(sha256(projected.body()), header(projected, "X-Decomp-Content-SHA256"))
        assertEquals(projected.body().size.toString(), header(projected, "Content-Length"))

        // Refusals: authorization first, then server-resolved identity, then representation checks.
        assertRefusal(send(fixture, archiveHref, octets, cookie = false), 401, "SESSION_REQUIRED", archive)
        val unauthenticatedHead = send(fixture, archiveHref, octets, method = "HEAD", cookie = false)
        assertRefusal(unauthenticatedHead, 401, "SESSION_REQUIRED")
        assertEquals("SESSION_REQUIRED", header(unauthenticatedHead, "X-Decomp-Session-Error"))
        assertRefusal(send(fixture, "${fixture.api}/artifacts?runId=${fixture.runId}", cookie = false), 401, "SESSION_REQUIRED")
        assertRefusal(send(fixture, "/w/api/v1/jobs/${"b".repeat(32)}/artifacts/$archiveId/content", octets), 404, "NOT_FOUND", archive)
        assertRefusal(send(fixture, "${fixture.api}/artifacts/archive_${"0".repeat(32)}_${sha256(archive)}/content", octets), 404, "NOT_FOUND", archive)
        // Browser-supplied paths are never identities: a filename, a traversal or a path query reaches no file.
        assertRefusal(send(fixture, "${fixture.api}/artifacts/source-tree.zip/content", octets), 404, "NOT_FOUND", archive)
        assertEquals(404, send(fixture, "${fixture.api}/artifacts/..%2F..%2Finput.elf/content", octets).statusCode())
        assertRefusal(send(fixture, "$archiveHref?path=source-tree.zip", octets), 400, "VALIDATION_FAILED", archive)
        assertRefusal(send(fixture, archiveHref, "text/html"), 406, "NOT_ACCEPTABLE", archive)
        assertRefusal(send(fixture, archiveHref, octets, mapOf("If-Match" to "\"${"0".repeat(64)}\"")), 412, "PRECONDITION_FAILED", archive)
        val unsatisfiable = send(fixture, archiveHref, octets, mapOf("Range" to "bytes=${archive.size}-"))
        assertRefusal(unsatisfiable, 416, "RANGE_NOT_SATISFIABLE", archive)
        assertEquals("bytes */${archive.size}", header(unsatisfiable, "Content-Range"))
        // Changed bytes are refused before any header or byte of the replacement is sent.
        val replacement = archive.copyOf().also { it[20] = 'X'.code.toByte() }
        Files.write(fixture.reports.resolve("source-tree.zip"), replacement)
        assertRefusal(send(fixture, archiveHref, octets), 409, "ARTIFACT_CHANGED", replacement)
        Files.delete(fixture.reports.resolve("source-tree.zip"))
        assertRefusal(send(fixture, archiveHref, octets), 404, "NOT_FOUND")
    }
}
