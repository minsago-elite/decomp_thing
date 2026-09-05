package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UploadServerSpaTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()

    @Test
    fun `SPA shell and runtime deep link serve packaged entries without opening job services`() {
        val parent = createTempDirectory("web-spa-")
        val data = parent.resolve("jobs")
        var executions = 0
        val server = UploadServer(
            "127.0.0.1", 0, data,
            analyzer = JobAnalyzer { _, _ -> executions++ },
            reconstructor = JobReconstructor { _, _ -> executions++ },
            uiMode = WebUiMode.SPA,
        )
        server.start()
        try {
            for (path in listOf("/", "/runtime", "/runtime?capability=fixture")) {
                val response = request(server, path)
                assertEquals(200, response.statusCode())
                assertTrue(response.body().contains("/assets/ui/assets/index-"))
                assertTrue(response.body().contains("decomp-ui-build"))
                assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow())
            }
            for (path in listOf("/api/v1/missing", "/api/jobs/fixture", "/jobs/fixture", "/missing.js")) {
                val response = request(server, path)
                assertEquals(if (path.startsWith("/api/")) 401 else 404, response.statusCode(), path)
                assertTrue(response.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"))
                assertFalse(response.body().contains("<!doctype html>"))
            }
            assertEquals(405, request(server, "/jobs", "POST").statusCode())
            assertEquals(405, request(server, "/runtime", "POST").statusCode())
            assertEquals(0, executions)
            assertFalse(Files.exists(data))
        } finally {
            server.stop()
            parent.toFile().deleteRecursively()
        }
    }

    @Test
    fun `SPA base paths keep assets and canonical redirects within deployment prefix`() {
        val data = createTempDirectory("web-spa-prefix-")
        val server = UploadServer("127.0.0.1", 0, data, uiMode = WebUiMode.SPA, basePath = "/workbench/")
        server.start()
        try {
            val response = request(server, "/workbench/runtime")
            assertEquals(200, response.statusCode())
            assertTrue(response.body().contains("/workbench/assets/ui/assets/index-"))
            val redirect = request(server, "/workbench?selection=fixture")
            assertEquals(308, redirect.statusCode())
            assertEquals("/workbench/?selection=fixture", redirect.headers().firstValue("Location").orElseThrow())
            assertEquals("/workbench/runtime", request(server, "/workbench/runtime/").headers().firstValue("Location").orElseThrow())
            assertEquals(404, request(server, "/runtime").statusCode())
            assertEquals(404, request(server, "/w%6Frkbench/runtime").statusCode())
            assertEquals(404, request(server, "/workbench/assets/ui/missing.js").statusCode())
            val head = request(server, "/workbench/runtime", "HEAD")
            assertEquals(200, head.statusCode())
            assertTrue(head.body().isEmpty())
            assertTrue(head.headers().firstValue("Content-Length").orElseThrow().toLong() > 0)
        } finally {
            server.stop()
            data.toFile().deleteRecursively()
        }
    }

    @Test
    fun `startup records historical interruption while public reads preserve original legacy metadata`() {
        val data = createTempDirectory("web-spa-history-")
        val store = JobStore(data)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        store.updateStatus(job.id, "analyzing", "historical active record")
        val metadata = data.resolve(job.id).resolve("job.json")
        val before = Files.readString(metadata)
        val server = UploadServer("127.0.0.1", 0, data, uiMode = WebUiMode.SPA)
        server.start()
        try {
            val state = data.resolve(job.id).resolve("workflow-state.json")
            val recovered = Files.readString(state)
            assertTrue(Json.parseToJsonElement(recovered).jsonObject.getValue("legacy")
                .jsonObject.getValue("recoveredInterrupted").jsonPrimitive.boolean)
            assertEquals(200, request(server, "/").statusCode())
            assertEquals(before, Files.readString(metadata))
            assertEquals(recovered, Files.readString(state))
        } finally {
            server.stop()
            data.toFile().deleteRecursively()
        }
    }

    private fun request(server: UploadServer, path: String, method: String = "GET"): HttpResponse<String> =
        client.send(
            HttpRequest.newBuilder(URI("http://127.0.0.1:${server.serverPort}$path"))
                .method(method, HttpRequest.BodyPublishers.noBody()).build(),
            HttpResponse.BodyHandlers.ofString(),
        )
}
