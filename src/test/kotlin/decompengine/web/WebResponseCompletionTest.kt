package decompengine.web

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Completion of real JDK exchanges, including exchange closes that race a body close. */
class WebResponseCompletionTest {
    /** Runs [respond] against a real JDK exchange and returns whether the wrapper confirmed completion. */
    private fun completion(respond: (WebResponseCompletion) -> Unit): Boolean {
        val http = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val result = CompletableFuture<Boolean>()
        http.createContext("/") { received ->
            val exchange = WebResponseCompletion(received)
            try { respond(exchange) } catch (_: java.io.IOException) { } finally { result.complete(WebResponseCompletion.completed(exchange)) }
        }
        http.start()
        val client = HttpClient.newHttpClient()
        try {
            // A truncated response never completes for the client; only the server-side result matters.
            val response = client.sendAsync(HttpRequest.newBuilder(URI("http://127.0.0.1:${http.address.port}/"))
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.discarding())
            return result.get(10, TimeUnit.SECONDS).also { response.cancel(true) }
        } finally { http.stop(0); client.close() }
    }

    @Test fun `a full fixed-length body closed cleanly is complete`() {
        assertTrue(completion { exchange -> exchange.sendResponseHeaders(200, 2); exchange.responseBody.use { it.write("ok".toByteArray()) } })
    }

    @Test fun `a full body whose clean close is overlapped by an exchange close stays complete`() {
        // The deadline thread closes the exchange after the body close returned but before its completion check.
        assertTrue(completion { exchange ->
            exchange.afterBodyClose = { exchange.close() }
            exchange.sendResponseHeaders(200, 2)
            exchange.responseBody.use { it.write("ok".toByteArray()) }
        })
    }

    @Test fun `a short body closed after its exchange closed is not complete`() {
        // The JDK swallows the short body inside the exchange close, so the later body close returns normally.
        assertFalse(completion { exchange ->
            exchange.sendResponseHeaders(200, 10)
            exchange.responseBody.write("ok".toByteArray())
            exchange.close()
            exchange.responseBody.close()
        })
    }

    @Test fun `a declared body never written and closed after its exchange closed is not complete`() {
        assertFalse(completion { exchange ->
            exchange.sendResponseHeaders(200, 10)
            exchange.close()
            exchange.responseBody.close()
        })
    }

    @Test fun `a short body whose own close fails is not complete even when the exchange close overlaps`() {
        assertFalse(completion { exchange ->
            exchange.afterBodyClose = { exchange.close() }
            exchange.sendResponseHeaders(200, 10)
            exchange.responseBody.use { it.write("ok".toByteArray()) }
        })
    }
}
