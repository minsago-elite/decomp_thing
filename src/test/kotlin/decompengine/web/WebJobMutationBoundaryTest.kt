package decompengine.web

import com.sun.net.httpserver.Headers
import com.sun.net.httpserver.HttpContext
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpPrincipal
import decompengine.jobs.JobStore
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.URI
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class WebJobMutationBoundaryTest {
    @Test
    fun `authorization and service lifecycle both precede upload body consumption and publication`() {
        val root = createTempDirectory("web-job-mutation-boundary-")
        val store = JobStore(root)
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") })
        val access = LocalWebAccess(LocalWebAccessConfiguration(ORIGIN))
        val boundary = WebJobMutationBoundary(access, service)
        try {
            service.initializeExistingStorage()
            val deniedBody = ObservedInput("untrusted request body".toByteArray())
            val denied = mutationRequest(deniedBody)
            val denial = assertFailsWith<WebAccessDenied> {
                boundary.authorizeUpload(denied)
            }
            assertEquals("SESSION_REQUIRED", denial.code)
            assertEquals(0, deniedBody.bytesRead)
            assertTrue(store.jobIds().isEmpty())

            val credentials = access.establishSession(loginRequest(access.issueBootstrap().token))
            val stoppedBody = ObservedInput("still must not be consumed".toByteArray())
            val authorized = mutationRequest(stoppedBody).apply {
                requestHeaders.set("Cookie", checkNotNull(credentials.setCookie).substringBefore(';'))
                requestHeaders.set("X-CSRF-Token", credentials.csrfToken)
            }
            val mutation = boundary.authorizeUpload(authorized)
            service.beginShutdown()
            val stopped = assertFailsWith<WebJobServiceException> {
                mutation.uploadMultipartReceipt(authorized.requestBody,
                    checkNotNull(authorized.requestHeaders.getFirst("Content-Type")))
            }
            assertEquals("SERVICE_STOPPED", stopped.code)
            assertEquals(0, stoppedBody.bytesRead)
            assertTrue(store.jobIds().isEmpty())
        } finally {
            access.close()
            service.close()
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `each operation selects its own policy and cannot reuse another operation request`() {
        val root = createTempDirectory("web-job-mutation-policy-")
        val service = WebJobService(JobStore(root), JobAnalyzer { _, _ -> }, JobReconstructor { _, _ -> })
        val access = LocalWebAccess(LocalWebAccessConfiguration(ORIGIN))
        try {
            val boundary = WebJobMutationBoundary(access, service)
            val credentials = access.establishSession(loginRequest(access.issueBootstrap().token))
            fun authorized(method: String, path: String, contentType: String) =
                MemoryExchange(method, path).apply {
                    requestHeaders.set("Host", AUTHORITY)
                    requestHeaders.set("Origin", ORIGIN)
                    requestHeaders.set("Content-Type", contentType)
                    requestHeaders.set("Cookie", checkNotNull(credentials.setCookie).substringBefore(';'))
                    requestHeaders.set("X-CSRF-Token", credentials.csrfToken)
                }

            val multipart = authorized("POST", "/jobs", "multipart/form-data; boundary=boundary")
            boundary.authorizeUpload(multipart)
            val multipartAsStart = assertFailsWith<WebAccessDenied> {
                boundary.authorizeLegacyStart(multipart)
            }
            assertEquals("UNSUPPORTED_MEDIA_TYPE", multipartAsStart.code)

            val jsonStart = authorized("POST", "/jobs/id/explore", "application/json")
            boundary.authorizeLegacyStart(jsonStart)
            val startAsUpload = assertFailsWith<WebAccessDenied> {
                boundary.authorizeUpload(jsonStart)
            }
            assertEquals("UNSUPPORTED_MEDIA_TYPE", startAsUpload.code)

            val jsonPin = authorized("PUT", "/api/v1/jobs/id/runs/run/progress-pin", "application/json")
            boundary.authorizeProgressPin(jsonPin)
            val pinAsStart = assertFailsWith<WebAccessDenied> {
                boundary.authorizeLegacyStart(jsonPin)
            }
            assertEquals("METHOD_NOT_ALLOWED", pinAsStart.code)
            assertTrue(JobStore(root).jobIds().isEmpty())
        } finally {
            access.close()
            service.close()
            root.toFile().deleteRecursively()
        }
    }

    private fun loginRequest(token: String) = MemoryExchange(
        "POST", "/api/v1/session", "{\"token\":\"$token\"}".byteInputStream(),
    ).apply {
        requestHeaders.set("Host", AUTHORITY)
        requestHeaders.set("Origin", ORIGIN)
        requestHeaders.set("Content-Type", "application/json")
    }

    private fun mutationRequest(input: InputStream) = MemoryExchange("POST", "/jobs", input).apply {
        requestHeaders.set("Host", AUTHORITY)
        requestHeaders.set("Origin", ORIGIN)
        requestHeaders.set("Content-Type", "multipart/form-data; boundary=boundary")
    }

    private class ObservedInput(bytes: ByteArray) : ByteArrayInputStream(bytes) {
        var bytesRead = 0
            private set
        override fun read(): Int = super.read().also { if (it >= 0) bytesRead++ }
        override fun read(target: ByteArray, offset: Int, length: Int): Int =
            super.read(target, offset, length).also { if (it > 0) bytesRead += it }
    }

    private class MemoryExchange(
        private val method: String,
        path: String,
        private val input: InputStream = InputStream.nullInputStream(),
    ) : HttpExchange() {
        private val uri = URI.create(path)
        private val incoming = Headers()
        private val outgoing = Headers()
        private val output = ByteArrayOutputStream()
        private var status = -1
        override fun getRequestHeaders(): Headers = incoming
        override fun getResponseHeaders(): Headers = outgoing
        override fun getRequestURI(): URI = uri
        override fun getRequestMethod(): String = method
        override fun getHttpContext(): HttpContext = throw UnsupportedOperationException()
        override fun close() = Unit
        override fun getRequestBody(): InputStream = input
        override fun getResponseBody(): OutputStream = output
        override fun sendResponseHeaders(code: Int, length: Long) { status = code }
        override fun getRemoteAddress(): InetSocketAddress = InetSocketAddress("127.0.0.1", 1)
        override fun getResponseCode(): Int = status
        override fun getLocalAddress(): InetSocketAddress = InetSocketAddress("127.0.0.1", 8000)
        override fun getProtocol(): String = "HTTP/1.1"
        override fun getAttribute(name: String): Any? = null
        override fun setAttribute(name: String, value: Any?) = Unit
        override fun setStreams(input: InputStream?, output: OutputStream?) = Unit
        override fun getPrincipal(): HttpPrincipal? = null
    }

    private companion object {
        const val AUTHORITY = "127.0.0.1:8000"
        const val ORIGIN = "http://$AUTHORITY"
    }
}
