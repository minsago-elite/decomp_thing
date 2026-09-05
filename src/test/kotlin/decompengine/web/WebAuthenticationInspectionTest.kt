package decompengine.web

import com.agentclientprotocol.model.AuthMethod
import com.agentclientprotocol.model.AuthMethodId
import decompengine.acp.AcpAuthenticationInventory
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class WebAuthenticationInspectionTest {
    @Test fun `web inspection is explicit and returns only redacted previews`() {
        val calls = AtomicInteger()
        val inventory = AcpAuthenticationInventory.capture(listOf(AuthMethod.AgentAuth(
            AuthMethodId("private-value"), "Login private-value", "Bearer private-value")), listOf("private-value"))
        val server = UploadServer("127.0.0.1", 0, createTempDirectory("web-auth-"),
            authenticationInspector = { calls.incrementAndGet(); inventory })
        server.start()
        try {
            val dashboard = request(server, "/", false)
            assertEquals(200, dashboard.statusCode())
            assertTrue(dashboard.body().contains("Inspect authentication methods"))
            assertEquals(0, calls.get())
            assertTrue(request(server, "/api/operator/auth-methods", false).body().contains("\"status\":\"idle\""))
            assertEquals(400, request(server, "/api/operator/auth-methods", true, explicit = false).statusCode())
            assertEquals(0, calls.get())
            assertEquals(202, request(server, "/api/operator/auth-methods", true).statusCode())
            val response = awaitResult(server)
            assertEquals(200, response.statusCode())
            assertEquals(1, calls.get())
            assertFalse(response.body().contains("private-value"))
            assertFalse(response.body().contains("\"id\":"))
            assertTrue(response.body().contains("\"loginSupported\":false"))
            assertTrue(response.body().contains("[redacted]"))
        } finally { server.stop(0) }
    }

    @Test fun `failed inspection hides raw errors and permits another explicit attempt`() {
        val calls = AtomicInteger()
        val server = UploadServer("127.0.0.1", 0, createTempDirectory("web-auth-failure-"),
            authenticationInspector = {
                if (calls.incrementAndGet() == 1) error("private-provider-token")
                AcpAuthenticationInventory.capture(emptyList(), emptyList())
            })
        server.start()
        try {
            assertEquals(202, request(server, "/api/operator/auth-methods", true).statusCode())
            val failure = awaitResult(server)
            assertTrue(failure.body().contains("\"status\":\"failed\""))
            assertFalse(failure.body().contains("private-provider-token"))
            assertEquals(202, request(server, "/api/operator/auth-methods", true).statusCode())
            val success = awaitResult(server)
            assertEquals(200, success.statusCode())
            assertTrue(success.body().contains("\"methods\":[]"))
            assertEquals(2, calls.get())
        } finally { server.stop(0) }
    }

    @Test fun `slow inspection leaves HTTP responsive and rejects concurrent admission`() {
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val server = UploadServer("127.0.0.1", 0, createTempDirectory("web-auth-slow-"),
            authenticationInspector = {
                entered.countDown()
                check(release.await(10, java.util.concurrent.TimeUnit.SECONDS))
                AcpAuthenticationInventory.capture(emptyList(), emptyList())
            })
        server.start()
        try {
            assertEquals(202, request(server, "/api/operator/auth-methods", true).statusCode())
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals(200, request(server, "/", false).statusCode())
            assertEquals(409, request(server, "/api/operator/auth-methods", true).statusCode())
            assertTrue(request(server, "/api/operator/auth-methods", false).body().contains("inspecting"))
            release.countDown()
            assertTrue(awaitResult(server).body().contains("ready"))
        } finally { release.countDown(); server.stop(0) }
    }

    @Test fun `shutdown retains ownership until the admitted inspection finishes`() {
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val root = createTempDirectory("web-auth-stop-")
        val server = UploadServer("127.0.0.1", 0, root, authenticationInspector = {
            entered.countDown()
            check(release.await(15, java.util.concurrent.TimeUnit.SECONDS))
            AcpAuthenticationInventory.capture(emptyList(), emptyList())
        })
        server.start()
        try {
            assertEquals(202, request(server, "/api/operator/auth-methods", true).statusCode())
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals("HTTP requests remain active after server stop",
                assertFailsWith<IllegalStateException> { server.stop(0) }.message)
            val contender = UploadServer("127.0.0.1", 0, root)
            try {
                assertEquals("Job store already has a live web server owner",
                    assertFailsWith<IllegalStateException> { contender.start() }.message)
            } finally { contender.stop(0) }
            release.countDown()
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5)
            var stopped = false
            while (!stopped && System.nanoTime() < deadline) {
                try { server.stop(0); stopped = true } catch (_: IllegalStateException) { Thread.sleep(20) }
            }
            assertTrue(stopped, "inspection did not release server ownership")
            val replacement = UploadServer("127.0.0.1", 0, root)
            try { replacement.start() } finally { replacement.stop(0) }
        } finally { release.countDown(); server.stop(0) }
    }

    @Test fun `explicit cancellation reaches the current inspector and publishes only its terminal result`() {
        val entered = java.util.concurrent.CountDownLatch(1)
        val cancellationObserved = java.util.concurrent.CountDownLatch(1)
        val cleanupReleased = java.util.concurrent.CountDownLatch(1)
        val root = createTempDirectory("web-auth-cancel-")
        val request = decompengine.agent.AgentExecutionRequest("cancel fixture",
            listOf(decompengine.agent.AgentWorkspaceRoot("fixture", root)),
            accessPolicy = decompengine.agent.AgentAccessPolicy(emptyList()))
        val receipt = decompengine.agent.AgentExecutionReceipt(
            decompengine.agent.AgentExecutionRequestBinding.capture(request),
            decompengine.agent.AgentExecutionOutcome.Returned(decompengine.agent.AgentExecutionResult(
                decompengine.agent.AgentStopReason.CANCELLED)))
        val server = UploadServer("127.0.0.1", 0, root, authenticationInspector = { cancellation ->
            entered.countDown()
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5)
            while (!cancellation.isCancellationRequested() && System.nanoTime() < deadline) Thread.sleep(10)
            check(cancellation.isCancellationRequested())
            cancellationObserved.countDown()
            check(cleanupReleased.await(5, java.util.concurrent.TimeUnit.SECONDS))
            throw decompengine.acp.AcpPreflightCancelledException(receipt)
        })
        server.start()
        try {
            val cancelPath = "/api/operator/auth-methods/cancel"
            assertEquals(409, request(server, cancelPath, true, action = "cancel-auth-inspection").statusCode())
            assertEquals(202, request(server, "/api/operator/auth-methods", true).statusCode())
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals(400, request(server, cancelPath, true, explicit = false).statusCode())
            assertEquals(202, request(server, cancelPath, true, action = "cancel-auth-inspection").statusCode())
            assertTrue(cancellationObserved.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertTrue(request(server, "/api/operator/auth-methods", false).body().contains("inspecting"))
            assertEquals(409, request(server, "/api/operator/auth-methods", true).statusCode())
            cleanupReleased.countDown()
            assertTrue(awaitResult(server).body().contains("\"status\":\"cancelled\""))
        } finally { cleanupReleased.countDown(); server.stop(0) }
    }

    private fun awaitResult(server: UploadServer): HttpResponse<String> {
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            val result = request(server, "/api/operator/auth-methods", false)
            if (!result.body().contains("\"status\":\"inspecting\"")) return result
            Thread.sleep(20)
        }
        error("inspection did not finish")
    }

    private fun request(server: UploadServer, path: String, post: Boolean, explicit: Boolean = true, action: String = "inspect-auth"): HttpResponse<String> {
        val request = HttpRequest.newBuilder(URI("http://127.0.0.1:${server.serverPort}$path"))
            .timeout(java.time.Duration.ofSeconds(5))
        if (post) request.POST(HttpRequest.BodyPublishers.noBody()) else request.GET()
        if (explicit) request.header("X-Decomp-Operator-Action", action)
        return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString())
    }
}
