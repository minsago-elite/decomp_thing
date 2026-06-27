package decompengine.web

import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class UploadServerTest {
    @Test
    fun `upload page has ELF form`() {
        withServer { server, _ ->
            val response = request(server, "GET", "/")

            assertEquals(200, response.status)
            assertTrue(response.body.decodeToString().contains("multipart/form-data"))
            assertTrue(response.body.decodeToString().contains("name=\"binary\""))
        }
    }

    @Test
    fun `web UI uploads ELF and returns job JSON`() {
        withServer { server, dataDir ->
            val response = upload(server, "fixture.elf", elfFixture(), acceptJson = true)

            assertEquals(201, response.status)
            val job = Json.parseToJsonElement(response.body.decodeToString()).jsonObject
            val jobId = job["id"].toString().trim('"')
            assertEquals("fixture.elf", job["filename"].toString().trim('"'))
            assertEquals("uploaded", job["status"].toString().trim('"'))
            assertEquals("ELF64", job["metadata"]!!.jsonObject["format"].toString().trim('"'))
            assertEquals("x86-64", job["metadata"]!!.jsonObject["machine"].toString().trim('"'))
            assertTrue(dataDir.resolve(jobId).resolve("input.elf").readBytes().startsWith(byteArrayOf(0x7f, 0x45, 0x4c, 0x46)))
            assertTrue(dataDir.resolve(jobId).resolve("job.json").exists())
        }
    }

    @Test
    fun `job state page shows status metadata and repair iteration history`() {
        withServer { server, dataDir ->
            val upload = upload(server, "fixture.elf", elfFixture(), acceptJson = true)
            val job = Json.parseToJsonElement(upload.body.decodeToString()).jsonObject
            val jobId = job["id"].toString().trim('"')
            val reportsDir = dataDir.resolve(jobId).resolve("reports").createDirectories()
            reportsDir.resolve("repair_history.json").writeText(
                """
                {
                  "iterations": [
                    {
                      "index": 1,
                      "failureKind": "behavior",
                      "summary": "match observed stdout",
                      "retainedRegressionIds": ["hello_default"]
                    }
                  ]
                }
                """.trimIndent(),
            )

            val page = request(server, "GET", "/jobs/$jobId")
            val body = page.body.decodeToString()

            assertEquals(200, page.status)
            assertTrue(body.contains("uploaded"))
            assertTrue(body.contains("fixture.elf"))
            assertTrue(body.contains("ELF64"))
            assertTrue(body.contains("x86-64"))
            assertTrue(body.contains("Repair History"))
            assertTrue(body.contains("Iteration 1"))
            assertTrue(body.contains("match observed stdout"))
            assertTrue(body.contains("hello_default"))
        }
    }

    @Test
    fun `upload rejects non-ELF content`() {
        withServer { server, _ ->
            val response = upload(server, "not-elf.bin", "not an elf".toByteArray(), acceptJson = false)

            assertEquals(400, response.status)
            assertTrue(response.body.decodeToString().contains("ELF"))
        }
    }

    private fun withServer(block: (UploadServer, java.nio.file.Path) -> Unit) {
        val dataDir = createTempDirectory("web-jobs-")
        val server = UploadServer("127.0.0.1", 0, dataDir)
        server.start()
        try {
            block(server, dataDir)
        } finally {
            server.stop(0)
        }
    }

    private fun upload(server: UploadServer, filename: String, content: ByteArray, acceptJson: Boolean): Response {
        val boundary = "----decomp-engine-test-boundary"
        val body = buildList<ByteArray> {
            add("--$boundary\r\n".toByteArray())
            add("Content-Disposition: form-data; name=\"binary\"; filename=\"$filename\"\r\n".toByteArray())
            add("Content-Type: application/x-elf\r\n\r\n".toByteArray())
            add(content)
            add("\r\n--$boundary--\r\n".toByteArray())
        }.fold(ByteArray(0)) { acc, bytes -> acc + bytes }
        return request(
            server,
            "POST",
            "/jobs",
            body,
            mapOf(
                "Content-Type" to "multipart/form-data; boundary=$boundary",
                "Accept" to if (acceptJson) "application/json" else "*/*",
            ),
        )
    }

    private fun request(
        server: UploadServer,
        method: String,
        path: String,
        body: ByteArray = ByteArray(0),
        headers: Map<String, String> = emptyMap(),
    ): Response {
        val connection = URL("http://127.0.0.1:${server.serverPort}$path").openConnection() as HttpURLConnection
        connection.requestMethod = method
        headers.forEach { (key, value) -> connection.setRequestProperty(key, value) }
        if (body.isNotEmpty()) {
            connection.doOutput = true
            connection.outputStream.use { it.write(body) }
        }
        val status = connection.responseCode
        val stream = if (status >= 400) connection.errorStream else connection.inputStream
        return Response(status, stream?.readBytes() ?: ByteArray(0))
    }

    private data class Response(val status: Int, val body: ByteArray)
}

private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
    size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
