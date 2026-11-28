package decompengine.web

import decompengine.jobs.*
import decompengine.project.*
import kotlinx.serialization.json.*
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.RandomAccessFile
import java.net.InetSocketAddress
import java.net.Socket
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
 * The production record route on an actual listener and store: a committed record that changes while it streams is
 * cut short promptly, and the delivery lease and download admission are released. The generated project is built
 * once as fixture setup; no request executes a compiler, workflow or subject program.
 */
class WebStructureRecordRouteTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    private val limits = WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u)
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** Larger than any loopback socket buffering, so the second pass is still reading when the record changes. */
    private val padding = 24 * 1024 * 1024

    @Test fun `a record that changes mid-stream is truncated promptly and its delivery released`() {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-structure-records").toAbsolutePath())
        val root = createTempDirectory(parent, "records-")
        val input = elfFixture()
        val job = JobStore(root).createFromUpload("records.elf", input)
        val created = WorkflowAttemptStore.open(root).use { owner ->
            val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            val queued = owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, limits))
            owner.transition(job.id, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start).attempt
        }
        val tree = root.resolve(job.id).resolve("reports/runs/${created.runId}/source-tree")
        SourceTreeGenerator.generate(RecoveredProgramModel(inputSha256 = sha256(input),
            functions = listOf(RecoveredFunction("fn_1000", "core", 0x1000uL, "int core(void)"))), tree)
        assertEquals(0, MakeProjectBuilder.build(tree).returnCode)
        // Pad the program model with trailing whitespace (still the same JSON) and recommit its digest.
        val model = tree.resolve("reports/program_model.json")
        val original = Files.readAllBytes(model)
        val padded = original + ByteArray(padding) { ' '.code.toByte() }
        Files.write(model, padded)
        val manifest = tree.resolve("source_tree_manifest.json")
        val manifestText = Files.readString(manifest)
        assertEquals(1, Regex(sha256(original)).findAll(manifestText).count())
        Files.writeString(manifest, manifestText.replace(sha256(original), sha256(padded)))
        val contract = Json.parseToJsonElement(Files.readString(tree.resolve("reports/build_contract.json"))).jsonObject
        WorkflowAttemptStore.open(root).use { owner ->
            owner.transition(job.id, created.runId, created.version, WorkflowTransition.Finish(WorkflowRunState.COMPLETED,
                WorkflowTerminalReason.COMPLETED, WorkflowCandidate("revision_1", contract.getValue("sourceRevisionSha256").jsonPrimitive.content)))
        }
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") }, uiMode = WebUiMode.SPA, basePath = "/w/")
        server.start()
        try {
            val origin = "http://127.0.0.1:${server.serverPort}"
            val session = client.send(HttpRequest.newBuilder(URI("$origin/w/api/v1/session")).header("Origin", origin)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"${server.issueBrowserBootstrap().token}\"}")).build(),
                HttpResponse.BodyHandlers.ofString())
            assertEquals(200, session.statusCode())
            val cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            val revision = "/w/api/v1/jobs/${job.id}/runs/${created.runId}/revisions/revision_1"
            val functions = client.send(HttpRequest.newBuilder(URI("$origin$revision/functions")).timeout(Duration.ofSeconds(60))
                .header("Accept", "application/json").header("Cookie", cookie).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, functions.statusCode(), functions.body())
            val version = Json.parseToJsonElement(functions.body()).jsonObject.getValue("data").jsonObject.getValue("structureVersion").jsonPrimitive.content
            val path = "$revision/records/program-model?structureVersion=$version"

            Socket().use { socket ->
                // A small fixed receive buffer keeps the in-flight bytes far below the record size.
                socket.receiveBufferSize = 64 * 1024
                socket.connect(InetSocketAddress("127.0.0.1", server.serverPort), 5_000)
                socket.soTimeout = 15_000
                socket.getOutputStream().write(("GET $path HTTP/1.1\r\nHost: 127.0.0.1:${server.serverPort}\r\n" +
                    "Accept: application/octet-stream\r\nCookie: $cookie\r\nConnection: close\r\n\r\n").toByteArray())
                val stream = socket.getInputStream()
                val headers = readHeaders(stream)
                assertTrue(headers.first().startsWith("HTTP/1.1 200"), headers.toString())
                val length = headers.single { it.startsWith("Content-Length:", ignoreCase = true) }.substringAfter(':').trim().toLong()
                assertEquals(padded.size.toLong(), length)
                var received = readSome(stream, 256 * 1024)
                // The listener is now blocked writing the second pass. Change the final byte in place.
                Thread.sleep(1_000)
                RandomAccessFile(model.toFile(), "rw").use { it.seek(padded.size - 1L); it.write('\n'.code) }
                val started = System.nanoTime()
                // A timeout here is a failure: the connection must be dropped, not left open with the length unmet.
                val buffer = ByteArray(64 * 1024)
                while (true) { val count = stream.read(buffer); if (count < 0) break; received += count }
                val elapsedMs = (System.nanoTime() - started) / 1_000_000
                assertTrue(received < length, "the changed final chunk must be withheld: $received of $length")
                assertTrue(elapsedMs < 10_000, "truncation took $elapsedMs ms")
            }
            val deadline = System.nanoTime() + 5_000_000_000L
            while (server.activeDownloads(job.id) != (0 to 0) && System.nanoTime() < deadline) Thread.sleep(20)
            assertEquals(0 to 0, server.activeDownloads(job.id), "the delivery lease and download admission are released")

            // With the committed bytes back, the same route serves the record in full.
            RandomAccessFile(model.toFile(), "rw").use { it.seek(padded.size - 1L); it.write(' '.code) }
            val complete = client.send(HttpRequest.newBuilder(URI("$origin$path")).timeout(Duration.ofSeconds(60))
                .header("Accept", "application/octet-stream").header("Cookie", cookie).build(), HttpResponse.BodyHandlers.ofByteArray())
            assertEquals(200, complete.statusCode())
            assertEquals(sha256(padded), sha256(complete.body()))
            assertEquals(sha256(padded), complete.headers().firstValue("X-Decomp-Content-SHA256").orElseThrow())
            assertEquals(0 to 0, server.activeDownloads(job.id))
        } finally {
            server.stop()
            root.toFile().deleteRecursively()
        }
    }

    private fun readHeaders(stream: InputStream): List<String> {
        val bytes = ByteArrayOutputStream()
        while (!bytes.toString(Charsets.ISO_8859_1).endsWith("\r\n\r\n")) {
            val next = stream.read()
            check(next >= 0) { "connection closed inside the response headers" }
            bytes.write(next)
        }
        return bytes.toString(Charsets.ISO_8859_1).trimEnd().split("\r\n")
    }

    private fun readSome(stream: InputStream, total: Int): Int {
        val buffer = ByteArray(16 * 1024)
        var read = 0
        while (read < total) { val count = stream.read(buffer, 0, minOf(buffer.size, total - read)); check(count > 0); read += count }
        return read
    }
}
