package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.jobs.JobStore
import decompengine.jobs.StagedJobUpload
import decompengine.jobs.UploadPublishPoint
import decompengine.jobs.elfFixture
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.URI
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
        val root = createTempDirectory("upload-uncertainty-http-")
        val privateDiagnostic = "private filesystem failure details"
        val service = WebJobService(JobStore(root), JobAnalyzer { _, _ -> error("uncertainty precedes analysis") },
            JobReconstructor { _, _ -> error("uncertainty precedes reconstruction") })
        service.uploadPublisher = StagedJobUpload(root, fault = { point ->
            if (point == UploadPublishPoint.AFTER_RENAME) throw IOException(privateDiagnostic)
        })
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 4)
        server.createContext("/jobs") { handleUploadRequest(it, service) }
        server.start()
        try {
            for (acceptJson in listOf(true, false)) {
                val boundary = "decomp-uncertain-upload"
                val body = ("--$boundary\r\n" +
                    "Content-Disposition: form-data; name=\"binary\"; filename=\"fixture.elf\"\r\n" +
                    "Content-Type: application/x-elf\r\n\r\n").toByteArray() +
                    elfFixture() + "\r\n--$boundary--\r\n".toByteArray()
                val connection = URI("http://127.0.0.1:${server.address.port}/jobs")
                    .toURL().openConnection() as HttpURLConnection
                try {
                    connection.requestMethod = "POST"
                    connection.instanceFollowRedirects = false
                    connection.connectTimeout = 5000
                    connection.readTimeout = 5000
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
                    connection.setRequestProperty("Accept", if (acceptJson) "application/json" else "text/html")
                    connection.outputStream.use { it.write(body) }
                    assertEquals(409, connection.responseCode)
                    val location = connection.getHeaderField("Location")
                    assertTrue(location.matches(Regex("/jobs/[a-f0-9]{32}")))
                    assertNull(connection.getHeaderField("Retry-After"))
                    val response = connection.errorStream.use { it.readBytes().decodeToString() }
                    assertFalse(response.contains(privateDiagnostic))
                    val id = location.substringAfterLast('/')
                    if (acceptJson) {
                        assertTrue(connection.contentType.startsWith("application/json"))
                        val problem = Json.parseToJsonElement(response).jsonObject
                        assertEquals("upload_publication_uncertain", problem["error"]!!.jsonPrimitive.content)
                        assertEquals(id, problem["job_id"]!!.jsonPrimitive.content)
                        assertEquals(location, problem["job_url"]!!.jsonPrimitive.content)
                        assertEquals("false", problem["retry_upload"].toString())
                    } else {
                        assertTrue(connection.contentType.startsWith("text/html"))
                        assertTrue(response.contains("href=\"$location\""))
                        assertTrue(response.contains("Check job"))
                    }
                    val published = JobStore(root).get(id)
                    assertEquals("uploaded", published.status)
                    assertContentEquals(elfFixture(), published.binaryPath.readBytes())
                } finally {
                    connection.disconnect()
                }
            }
            assertEquals(2, JobStore(root).list().size)
        } finally {
            server.stop(0)
        }
    }
}
