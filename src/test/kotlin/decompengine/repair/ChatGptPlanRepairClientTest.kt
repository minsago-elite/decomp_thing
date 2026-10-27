package decompengine.repair

import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailureKind
import decompengine.chatgpt.ChatGptPlanCredentialStore
import decompengine.chatgpt.NewChatGptPlanAccount
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.Authenticator
import java.net.CookieHandler
import java.net.ProxySelector
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import java.util.Optional
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSession
import kotlinx.serialization.json.JsonPrimitive
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ChatGptPlanRepairClientTest {
    @Test
    fun `completed Responses streams work with absent or compatible Content-Type`() {
        for (contentType in listOf(null, "text/event-stream", "Text/Event-Stream; charset=utf-8")) {
            val transport = FakeResponsesClient(contentType, completedStream())
            val response = client(transport).requestRepair(request())
            assertEquals("src/test.c", response.patches.single().relativePath)
            assertEquals("int test(void) { return 17; }", response.patches.single().replacement)
            assertTrue(transport.closed)
        }
    }

    @Test
    fun `explicit incompatible media types are rejected even for an SSE body`() {
        for (contentType in listOf("application/json", "text/html", "text/event-stream-invalid", "")) {
            val transport = FakeResponsesClient(contentType, completedStream())
            val failure = assertFailsWith<AgentExecutionException> { client(transport).requestRepair(request()) }
            assertEquals(AgentFailureKind.PROTOCOL, failure.failure.kind)
            assertTrue(transport.closed)
        }
    }

    @Test
    fun `missing Content-Type does not bypass stream and patch validation`() {
        for (body in listOf(
            "<html>upstream error</html>",
            "data: {malformed}\n\n",
            "event: response.output_text.delta\ndata: {\"delta\":\"{}\"}\n\n",
            "event: response.completed\ndata: {}\n\n",
            "event: response.incomplete\ndata: {}\n\n",
        )) {
            val transport = FakeResponsesClient(null, body)
            val failure = assertFailsWith<AgentExecutionException> { client(transport).requestRepair(request()) }
            assertEquals(AgentFailureKind.PROTOCOL, failure.failure.kind)
            assertTrue(transport.closed)
        }
    }

    @Test
    fun `transient connection failure retries and emits only safe diagnostics`() {
        val logs = mutableListOf<String>()
        val transport = FakeResponsesClient(null, completedStream(), failures = 1)
        val response = client(transport, logs::add).requestRepair(request())
        assertEquals(1, response.patches.size)
        assertEquals(2, transport.calls)
        assertTrue(logs.any { "cause=connection-failed" in it && "retry=true" in it })
        assertTrue(logs.any { "completed patches=1" in it })
        assertTrue(logs.none { "private-error" in it || "test-access-token" in it || "Implement src/test.c" in it })
    }

    @Test
    fun `repeated transport failures exhaust a bounded number of attempts`() {
        val transport = FakeResponsesClient(null, completedStream(), failures = 10)
        val failure = assertFailsWith<AgentExecutionException> { client(transport).requestRepair(request()) }
        assertEquals(3, transport.calls)
        assertEquals("connection-failed", failure.failure.details["diagnosticCode"])
    }

    @Test
    fun `all retry attempts share the invocation wall deadline`() {
        val transport = FakeResponsesClient(null, completedStream(), failures = 10)
        val invocation = RepairClientInvocation(RepairResourceBudget(),
            decompengine.agent.AgentExecutionLimits(wallClockTimeout = Duration.ofMillis(100)),
            decompengine.agent.AgentCancellation.NONE)
        val failure = assertFailsWith<AgentExecutionException> { client(transport).requestRepair(request(), invocation) }
        assertEquals(1, transport.calls)
        assertEquals(AgentFailureKind.TIMEOUT, failure.failure.kind)
    }

    @Test
    fun `explicit empty patch set is a no-change response rather than malformed JSON`() {
        val patch = """{"summary":"insufficient interfaces","patches":[]}"""
        val transport = FakeResponsesClient(null, textStream(patch))
        val response = client(transport).requestRepair(request())
        assertTrue(response.patches.isEmpty())
        assertEquals(1, transport.calls)
    }

    private fun request() = RepairRequest("reconstruction", "Implement src/test.c", mapOf("src/test.c" to ""), emptyList())

    private fun completedStream(): String {
        val patch = """{"summary":"implemented","patches":[{"relativePath":"src/test.c","replacement":"int test(void) { return 17; }"}]}"""
        return textStream(patch)
    }

    private fun textStream(text: String) =
        "event: response.output_text.delta\ndata: {\"delta\":${JsonPrimitive(text)}}\n\n" +
            "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n"

    private fun client(transport: HttpClient, log: (String) -> Unit = {}): ChatGptPlanRepairClient {
        val store = ChatGptPlanCredentialStore.create(createTempDirectory("chatgpt-stream-test-").resolve("credentials"))
        store.saveNewAccount(NewChatGptPlanAccount(
            email = null, clientId = "test-client", subject = "test-subject", idToken = "test-id-token",
            accessToken = "test-access-token", refreshToken = "test-refresh-token",
            expiresAt = Instant.now().plusSeconds(3600),
            scopes = setOf("offline_access", "resource.invoke", "chatgpt.tokens.use.direct"),
        ))
        store.setModel(null, "test-model")
        return ChatGptPlanRepairClient(store = store, profileId = null, httpClient = transport, diagnosticLog = log)
    }

    private class FakeResponsesClient(private val contentType: String?, private val body: String, private val failures: Int = 0) : HttpClient() {
        var closed = false
        var calls = 0
        override fun <T> sendAsync(request: HttpRequest, handler: HttpResponse.BodyHandler<T>): CompletableFuture<HttpResponse<T>> {
            calls++
            if (calls <= failures) return CompletableFuture.failedFuture(java.net.ConnectException("private-error"))
            assertEquals("https://api.openai.com/v1/responses", request.uri().toString())
            assertEquals("text/event-stream", request.headers().firstValue("Accept").orElseThrow())
            val input = object : ByteArrayInputStream(body.toByteArray()) {
                override fun close() { closed = true; super.close() }
            }
            val response = object : HttpResponse<InputStream> {
                override fun statusCode() = 200
                override fun request() = request
                override fun previousResponse(): Optional<HttpResponse<InputStream>> = Optional.empty()
                override fun headers(): HttpHeaders = HttpHeaders.of(
                    contentType?.let { mapOf("Content-Type" to listOf(it)) } ?: emptyMap(),
                ) { _, _ -> true }
                override fun body(): InputStream = input
                override fun sslSession(): Optional<SSLSession> = Optional.empty()
                override fun uri(): URI = request.uri()
                override fun version() = Version.HTTP_1_1
            }
            @Suppress("UNCHECKED_CAST")
            return CompletableFuture.completedFuture(response as HttpResponse<T>)
        }
        override fun <T> send(request: HttpRequest, handler: HttpResponse.BodyHandler<T>): HttpResponse<T> = error("unexpected synchronous request")
        override fun <T> sendAsync(request: HttpRequest, handler: HttpResponse.BodyHandler<T>, push: HttpResponse.PushPromiseHandler<T>): CompletableFuture<HttpResponse<T>> = error("unexpected server push")
        override fun cookieHandler(): Optional<CookieHandler> = Optional.empty()
        override fun connectTimeout(): Optional<Duration> = Optional.empty()
        override fun followRedirects() = Redirect.NEVER
        override fun proxy(): Optional<ProxySelector> = Optional.empty()
        override fun sslContext(): SSLContext = SSLContext.getDefault()
        override fun sslParameters() = SSLParameters()
        override fun authenticator(): Optional<Authenticator> = Optional.empty()
        override fun version() = Version.HTTP_1_1
        override fun executor(): Optional<Executor> = Optional.empty()
    }
}
