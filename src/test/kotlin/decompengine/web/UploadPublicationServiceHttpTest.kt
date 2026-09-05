package decompengine.web

import decompengine.jobs.*
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.time.Duration
import kotlinx.serialization.json.*
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class UploadPublicationServiceHttpTest {
    @Test fun `production adapters retain uncertain identity and fence retries without leaking causes`() {
        for (mode in listOf("legacy-json", "legacy-html", "spa")) {
            val root = createTempDirectory("uncertain-service-http-")
            val spa = mode == "spa"
            val server = UploadServer("127.0.0.1", 0, root,
                JobAnalyzer { _, _ -> error("Unexpected execution") },
                JobReconstructor { _, _ -> error("Unexpected execution") },
                uiMode = if (spa) WebUiMode.SPA else WebUiMode.LEGACY,
                basePath = if (spa) "/workbench/" else "/")
            val privateCause = "PRIVATE_PUBLICATION_PATH_AND_CONTENT"
            // Inject the existing publisher checkpoint without adding a production HTTP fault switch.
            val service = UploadServer::class.java.getDeclaredField("jobs").apply { isAccessible = true }.get(server) as WebJobService
            WebJobService::class.java.getDeclaredField("uploadPublisher").apply { isAccessible = true }
                .set(service, StagedJobUpload(root) { point ->
                    if (point == UploadPublishPoint.AFTER_RENAME) throw IOException(privateCause)
                })
            server.start()
            try {
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build().use { client ->
                    val origin = "http://127.0.0.1:${server.serverPort}"
                    fun request(path: String, method: String = "GET", bytes: ByteArray = byteArrayOf(), headers: Map<String, String> = emptyMap()): HttpResponse<String> {
                        val builder = HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(10))
                            .method(method, HttpRequest.BodyPublishers.ofByteArray(bytes))
                        headers.forEach { (key, value) -> builder.header(key, value) }
                        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
                    }
                    val headers = mutableMapOf("Accept" to if (mode == "legacy-html") "text/html" else "application/json")
                    val path = if (spa) "/workbench/api/v1/jobs" else "/jobs"
                    if (spa) {
                        val token = server.issueBrowserBootstrap().token
                        val login = request("/workbench/api/v1/session", "POST", "{\"token\":\"$token\"}".toByteArray(),
                            mapOf("Origin" to origin, "Content-Type" to "application/json", "Accept" to "application/json"))
                        assertEquals(200, login.statusCode())
                        headers["Cookie"] = login.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
                        val bootstrap = request("/workbench/api/v1/bootstrap", headers = headers)
                        assertEquals(200, bootstrap.statusCode())
                        headers["X-CSRF-Token"] = Json.parseToJsonElement(bootstrap.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
                        headers["Origin"] = origin
                        headers["Idempotency-Key"] = "uncertain_upload_fixture"
                    }
                    headers["Content-Type"] = "multipart/form-data; boundary=uncertain_fixture"
                    val body = "--uncertain_fixture\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"fixture.elf\"\r\n\r\n".toByteArray() +
                        elfFixture() + "\r\n--uncertain_fixture--\r\n".toByteArray()
                    val response = request(path, "POST", body, headers)
                    assertEquals(409, response.statusCode(), "$mode: ${response.body()}")
                    val location = response.headers().firstValue("Location").orElseThrow()
                    val id = location.substringAfterLast('/')
                    assertTrue(id.matches(Regex("[a-f0-9]{32}")))
                    assertEquals(if (spa) "$path/$id" else "/jobs/$id", location)
                    assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow())
                    assertFalse(response.headers().firstValue("Retry-After").isPresent)
                    assertFalse(response.body().contains(privateCause))
                    assertTrue(response.body().contains(id))
                    if (spa) {
                        val error = Json.parseToJsonElement(response.body()).jsonObject.getValue("error").jsonObject
                        assertEquals("RECOVERY_REQUIRED", error.getValue("code").jsonPrimitive.content)
                        assertEquals(false, error.getValue("retryable").jsonPrimitive.boolean)
                    } else if (mode == "legacy-json") {
                        val error = Json.parseToJsonElement(response.body()).jsonObject
                        assertEquals(id, error.getValue("job_id").jsonPrimitive.content)
                        assertEquals(false, error.getValue("retry_upload").jsonPrimitive.boolean)
                    } else assertTrue(response.body().contains("href=\"$location\""))
                    assertContentEquals(elfFixture(), Files.readAllBytes(root.resolve(id).resolve("input.elf")))
                    assertEquals(WebWorkflowAdmission.Unavailable, service.start(id, WebWorkflow.EXPLORE))
                    assertEquals(503, request(path, "POST", body, headers).statusCode())
                    assertEquals(listOf(id), JobStore(root).jobIds())
                }
            } finally {
                server.stop()
                root.toFile().deleteRecursively()
            }
        }
    }
}
