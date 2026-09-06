package decompengine.web

import com.agentclientprotocol.model.AuthMethod
import com.agentclientprotocol.model.AuthMethodId
import decompengine.acp.AcpAuthenticationInventory
import decompengine.jobs.JobRecoveryInventory
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createTempDirectory
import kotlin.test.*
import kotlinx.serialization.json.*

class WebAuthenticationInspectionTest {
    @Test fun `shutdown waits for cancelled inspection cleanup before returning`() {
        val entered = java.util.concurrent.CountDownLatch(1)
        val cancelled = java.util.concurrent.CountDownLatch(1)
        val finish = java.util.concurrent.CountDownLatch(1)
        val cleaned = java.util.concurrent.atomic.AtomicBoolean(false)
        val root = createTempDirectory("web-auth-join-")
        val server = UploadServer("127.0.0.1", 0, root, authenticationInspector = { cancellation ->
            entered.countDown()
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10)
            while (!cancellation.isCancellationRequested() && System.nanoTime() < deadline) Thread.sleep(5)
            check(cancellation.isCancellationRequested())
            cancelled.countDown()
            check(finish.await(10, java.util.concurrent.TimeUnit.SECONDS))
            cleaned.set(true)
            AcpAuthenticationInventory.capture(emptyList(), emptyList())
        })
        val stopper = java.util.concurrent.Executors.newSingleThreadExecutor()
        server.start()
        try {
            assertEquals(202, request(server, "/api/operator/auth-methods", true).statusCode())
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
            val stopped = stopper.submit { server.stop(0) }
            assertTrue(cancelled.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertFailsWith<java.util.concurrent.TimeoutException> {
                stopped.get(100, java.util.concurrent.TimeUnit.MILLISECONDS)
            }
            assertFalse(cleaned.get())
            finish.countDown()
            stopped.get(5, java.util.concurrent.TimeUnit.SECONDS)
            assertTrue(cleaned.get())
            val replacement = UploadServer("127.0.0.1", 0, root)
            try { replacement.start() } finally { replacement.stop(0) }
        } finally {
            finish.countDown()
            stopper.shutdownNow()
            server.stop(0)
        }
    }

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

    @Test fun `shutdown waits past five seconds and preserves caller interruption and ownership`() {
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val interrupted = java.util.concurrent.atomic.AtomicBoolean(false)
        val root = createTempDirectory("web-auth-stop-")
        val server = UploadServer("127.0.0.1", 0, root, authenticationInspector = {
            entered.countDown()
            check(release.await(20, java.util.concurrent.TimeUnit.SECONDS))
            AcpAuthenticationInventory.capture(emptyList(), emptyList())
        })
        val stopped = java.util.concurrent.FutureTask {
            Thread.currentThread().interrupt()
            server.stop(0)
            interrupted.set(Thread.currentThread().isInterrupted)
        }
        val stopper = Thread(stopped, "web-auth-stop-test")
        server.start()
        try {
            assertEquals(202, request(server, "/api/operator/auth-methods", true).statusCode())
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
            stopper.start()
            assertFailsWith<java.util.concurrent.TimeoutException> {
                stopped.get(5500, java.util.concurrent.TimeUnit.MILLISECONDS)
            }
            stopper.interrupt()
            assertFailsWith<java.util.concurrent.TimeoutException> {
                stopped.get(100, java.util.concurrent.TimeUnit.MILLISECONDS)
            }
            assertEquals("Job store already has a live web server owner",
                assertFailsWith<IllegalStateException> { UploadServer("127.0.0.1", 0, root) }.message)
            release.countDown()
            stopped.get(5, java.util.concurrent.TimeUnit.SECONDS)
            assertTrue(interrupted.get(), "shutdown must restore its caller's interrupt flag")
            val replacement = UploadServer("127.0.0.1", 0, root)
            try { replacement.start() } finally { replacement.stop(0) }
        } finally {
            release.countDown()
            stopper.join(5000)
            server.stop(0)
        }
    }

    @Test fun `shutdown waits for the running inspection to finish before returning`() {
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val cleaned = java.util.concurrent.CountDownLatch(1)
        val root = createTempDirectory("web-auth-await-")
        val server = UploadServer("127.0.0.1", 0, root, authenticationInspector = {
            entered.countDown()
            check(release.await(15, java.util.concurrent.TimeUnit.SECONDS))
            cleaned.countDown()
            AcpAuthenticationInventory.capture(emptyList(), emptyList())
        })
        server.start()
        try {
            assertEquals(202, request(server, "/api/operator/auth-methods", true).statusCode())
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
            val stopped = java.util.concurrent.CountDownLatch(1)
            val stopper = Thread({
                try { server.stop(0) } catch (_: IllegalStateException) { }
                stopped.countDown()
            }, "test-shutdown")
            stopper.start()
            Thread.sleep(200)
            assertEquals(1, stopped.count)
            assertEquals(1, cleaned.count)
            release.countDown()
            assertTrue(stopped.await(10, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals(0, cleaned.count)
            val replacement = UploadServer("127.0.0.1", 0, root)
            try { replacement.start() } finally { replacement.stop(0) }
        } finally { release.countDown(); server.stop(0) }
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

    @Test fun `delayed cancellation cannot cancel a replacement inspection`() {
        val entered = Array(2) { java.util.concurrent.CountDownLatch(1) }
        val release = Array(2) { java.util.concurrent.CountDownLatch(1) }
        val calls = AtomicInteger()
        val cancellations = java.util.concurrent.atomic.AtomicReferenceArray<decompengine.agent.AgentCancellation>(2)
        val root = createTempDirectory("web-auth-generation-")
        val server = UploadServer("127.0.0.1", 0, root, authenticationInspector = { cancellation ->
            val index = calls.getAndIncrement()
            cancellations.set(index, cancellation)
            entered[index].countDown()
            check(release[index].await(10, java.util.concurrent.TimeUnit.SECONDS))
            AcpAuthenticationInventory.capture(emptyList(), emptyList())
        })
        fun id(response: HttpResponse<String>) = Json.parseToJsonElement(response.body()).jsonObject.getValue("inspectionId").jsonPrimitive.content
        server.start()
        try {
            val first = request(server, "/api/operator/auth-methods", true)
            assertEquals(202, first.statusCode())
            assertTrue(entered[0].await(5, java.util.concurrent.TimeUnit.SECONDS))
            val firstId = id(first)
            release[0].countDown()
            assertEquals(firstId, id(awaitResult(server)))
            val second = request(server, "/api/operator/auth-methods", true)
            assertEquals(202, second.statusCode())
            assertTrue(entered[1].await(5, java.util.concurrent.TimeUnit.SECONDS))
            val secondId = id(second)
            assertNotEquals(firstId, secondId)
            assertEquals(400, request(server, "/api/operator/auth-methods/cancel", true,
                action = "cancel-auth-inspection", includeInspectionId = false).statusCode())
            assertFalse(cancellations.get(1).isCancellationRequested())
            val attached = request(server, "/api/operator/auth-methods", true)
            assertEquals(409, attached.statusCode())
            assertEquals(secondId, id(attached))
            repeat(2) {
                assertEquals(409, request(server, "/api/operator/auth-methods/cancel", true,
                    action = "cancel-auth-inspection", inspectionId = firstId).statusCode())
                assertFalse(cancellations.get(1).isCancellationRequested())
            }
            assertEquals(202, request(server, "/api/operator/auth-methods/cancel", true,
                action = "cancel-auth-inspection", inspectionId = secondId).statusCode())
            assertTrue(cancellations.get(1).isCancellationRequested())
            release[1].countDown()
            assertEquals(secondId, id(awaitResult(server)))
        } finally {
            release.forEach { it.countDown() }
            server.stop()
            root.toFile().deleteRecursively()
        }
    }

    @Test fun `rendered polling rejects status updates from a replacement inspection`() {
        val dashboard = renderDashboard(emptyList(), JobRecoveryInventory(0, 0, 0, 0L, 0, true))
        assertTrue(dashboard.contains("observed.inspectionId !== authInspectionId"),
            "polling must compare the observed identity against the admitted identity")
        assertTrue(dashboard.contains("This inspection is no longer active; start a new inspection."),
            "an identity mismatch must end polling instead of adopting the replacement")
        assertTrue(dashboard.contains("if (!authInspectionId) {"),
            "the observed identity may only be adopted while no identity is captured")
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

    private fun request(server: UploadServer, path: String, post: Boolean, explicit: Boolean = true, action: String = "inspect-auth", inspectionId: String? = null, includeInspectionId: Boolean = true): HttpResponse<String> {
        val request = HttpRequest.newBuilder(URI("http://127.0.0.1:${server.serverPort}$path"))
            .timeout(java.time.Duration.ofSeconds(5))
        if (post) request.POST(HttpRequest.BodyPublishers.noBody()) else request.GET()
        if (explicit) request.header("X-Decomp-Operator-Action", action)
        if (explicit && action == "cancel-auth-inspection" && includeInspectionId) {
            val selected = inspectionId ?: Json.parseToJsonElement(
                request(server, "/api/operator/auth-methods", false).body()).jsonObject["inspectionId"]?.jsonPrimitive?.contentOrNull
            if (selected != null) request.header("X-Decomp-Inspection-Id", selected)
        }
        return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString())
    }
}
