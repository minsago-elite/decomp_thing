package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.jobs.JobStore
import decompengine.jobs.StagedJobUpload
import decompengine.jobs.UploadPublishPoint
import decompengine.jobs.elfFixture
import java.io.IOException
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class UploadUncertaintyHttpTest {
    @Test
    fun `HTTP upload uncertainty identifies the published job in JSON and HTML without retry hints`() {
        assertUncertainUploadResponse(acceptJson = true)
        assertUncertainUploadResponse(acceptJson = false)
    }

    /** Each variant uses an isolated root and service: after RECOVERY_REQUIRED the service refuses further uploads. */
    private fun assertUncertainUploadResponse(acceptJson: Boolean) {
        val root = createTempDirectory("upload-uncertainty-http-")
        val privateDiagnostic = "private filesystem failure details"
        val service = WebJobService(JobStore(root), JobAnalyzer { _, _ -> error("uncertainty precedes analysis") },
            JobReconstructor { _, _ -> error("uncertainty precedes reconstruction") })
        service.uploadPublisher = StagedJobUpload(root, fault = { point ->
            if (point == UploadPublishPoint.AFTER_RENAME) throw IOException(privateDiagnostic)
        })
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 4)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val mutations = WebJobMutationBoundary(access, service)
        val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
        server.createContext("/jobs") { exchange ->
            try {
                handleAuthorizedUploadRequest(exchange,
                    mutations.authorizeUpload(exchange))
            } catch (failure: WebAccessDenied) {
                access.sendDenied(exchange, failure)
            }
        }
        server.createContext("/api/v1/session") { exchange ->
            try { WebSessionController(access).handle(exchange) }
            catch (failure: WebAccessDenied) { access.sendDenied(exchange, failure) }
        }
        server.start()
        try {
            val token = access.issueBootstrap().token
            val login = client.send(HttpRequest.newBuilder(URI("$origin/api/v1/session"))
                .timeout(Duration.ofSeconds(5))
                .header("Origin", origin)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$token\"}"))
                .build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, login.statusCode(), login.body())
            val session = login.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';') to
                Json.parseToJsonElement(login.body()).jsonObject.getValue("data").jsonObject
                    .getValue("csrfToken").jsonPrimitive.content
            val boundary = "decomp-uncertain-upload"
            val body = ("--$boundary\r\n" +
                "Content-Disposition: form-data; name=\"binary\"; filename=\"fixture.elf\"\r\n" +
                "Content-Type: application/x-elf\r\n\r\n").toByteArray() +
                elfFixture() + "\r\n--$boundary--\r\n".toByteArray()
            val response = client.send(HttpRequest.newBuilder(URI("$origin/jobs"))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "multipart/form-data; boundary=$boundary")
                .header("Accept", if (acceptJson) "application/json" else "text/html")
                .header("Origin", origin)
                .header("Cookie", session.first)
                .header("X-CSRF-Token", session.second)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(409, response.statusCode(), response.body())
            val location = response.headers().firstValue("Location").orElseThrow()
            assertTrue(location.matches(Regex("/jobs/[a-f0-9]{32}")))
            assertNull(response.headers().firstValue("Retry-After").orElse(null))
            assertFalse(response.body().contains(privateDiagnostic))
            val id = location.substringAfterLast('/')
            if (acceptJson) {
                assertTrue(response.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"))
                val problem = Json.parseToJsonElement(response.body()).jsonObject
                assertEquals("upload_publication_uncertain", problem["error"]!!.jsonPrimitive.content)
                assertEquals(id, problem["job_id"]!!.jsonPrimitive.content)
                assertEquals(location, problem["job_url"]!!.jsonPrimitive.content)
                assertEquals("false", problem["retry_upload"].toString())
            } else {
                assertTrue(response.headers().firstValue("Content-Type").orElseThrow().startsWith("text/html"))
                assertTrue(response.body().contains("href=\"$location\""))
                assertTrue(response.body().contains("Check job"))
            }
            val published = JobStore(root).get(id)
            assertEquals("uploaded", published.status)
            assertContentEquals(elfFixture(), published.binaryPath.readBytes())
        } finally {
            server.stop(0)
            client.close()
            access.close()
            service.close()
            root.toFile().deleteRecursively()
        }
    }
}
