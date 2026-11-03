package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowTransition
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Legacy migration, restart reconciliation and upload idempotency through the real v1 listener. Restart
 * marks abandoned work interrupted exactly once, never rewrites legacy metadata or launches a workflow,
 * and retained upload keys replay or refuse instead of creating a second job.
 */
class WebRestartReconciliationHttpTest {
    private val root: Path = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp")), "web-restart-")
    private val workflows = AtomicInteger()

    @AfterTest fun cleanup() { root.toFile().deleteRecursively() }

    private fun server() = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> workflows.incrementAndGet() },
        JobReconstructor { _, _ -> workflows.incrementAndGet() }, uiMode = WebUiMode.SPA, basePath = "/w/",
        sensitiveValues = emptyList()).also { it.start() }

    private fun <T> withServer(block: (WebTestBrowser) -> T): T {
        val server = server()
        try { return WebTestBrowser(server).use(block) } finally { server.stop() }
    }

    private fun sha(path: Path) = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)).joinToString("") { "%02x".format(it) }

    @Test
    fun `restart interrupts legacy running and cancelling work once without rewriting metadata or launching workflows`() {
        val store = JobStore(root)
        val legacy = store.createFromUpload("legacy.elf", elfFixture()).id
        store.updateStatus(legacy, "analyzing", "historical legacy work")
        val running = store.createFromUpload("running.elf", elfFixture()).id
        val cancelling = store.createFromUpload("cancelling.elf", elfFixture()).id
        val runs = WorkflowAttemptStore.open(root).use { owner ->
            listOf(running, cancelling).associateWith { id ->
                val current = (owner.inspect(id) as WorkflowJobInspection.Available).snapshot
                val created = owner.create(id, current.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
                var attempt = owner.transition(id, created.runId, created.version, WorkflowTransition.Start).attempt
                if (id == cancelling) attempt = owner.transition(id, attempt.runId, attempt.version, WorkflowTransition.RequestCancellation).attempt
                assertEquals(if (id == cancelling) "cancelling" else "running", attempt.state.wireName)
                attempt.runId
            }
        }
        val metadata = listOf(legacy, running, cancelling).associateWith { sha(root.resolve(it).resolve("job.json")) }

        val first = withServer { browser ->
            val job = browser.get("/w/api/v1/jobs/$legacy")
            assertEquals(200, job.statusCode(), job.text())
            assertEquals("interrupted", job.data().getValue("status").jsonPrimitive.content, "legacy work has no live owner after restart")
            runs.map { (id, run) ->
                val response = browser.get("/w/api/v1/jobs/$id/runs/$run")
                assertEquals(200, response.statusCode(), response.text())
                val data = response.data()
                assertEquals("interrupted", data.getValue("state").jsonPrimitive.content, "$id attempt")
                assertEquals("PROCESS_INTERRUPTED", data.getValue("terminalReason").jsonPrimitive.content)
                assertNotEquals(JsonNull, data.getValue("endedAt"))
                assertTrue(Instant.parse(data.getValue("endedAt").jsonPrimitive.content) >=
                    Instant.parse(data.getValue("startedAt").jsonPrimitive.content))
                data.getValue("version").jsonPrimitive.content
            }
        }
        // A second restart is idempotent: the reconciled attempts keep their versions and terminal state.
        val second = withServer { browser ->
            runs.map { (id, run) -> browser.get("/w/api/v1/jobs/$id/runs/$run").data().getValue("version").jsonPrimitive.content }
        }
        assertEquals(first, second, "an already reconciled attempt must not change on a later restart")
        assertEquals(metadata, listOf(legacy, running, cancelling).associateWith { sha(root.resolve(it).resolve("job.json")) },
            "restart never rewrites historical job metadata")
        assertEquals(0, workflows.get(), "restart never launches a workflow")
    }

    @Test
    fun `retained upload keys replay across restart race to one job and refuse an unreadable receipt`() {
        val key = "restart-upload-key-0001"
        val created = withServer { browser ->
            // Two simultaneous uploads with one key admit at most one publication.
            val ready = CountDownLatch(2)
            val go = CountDownLatch(1)
            val racers = List(2) {
                CompletableFuture.supplyAsync {
                    ready.countDown(); go.await(30, TimeUnit.SECONDS)
                    browser.upload("raced.elf", elfFixture(), key)
                }
            }
            assertTrue(ready.await(30, TimeUnit.SECONDS))
            go.countDown()
            val outcomes = racers.map { it.get(60, TimeUnit.SECONDS) }
            val published = outcomes.filter { it.statusCode() == 201 }
            assertTrue(published.isNotEmpty(), outcomes.map { "${it.statusCode()} ${it.text()}" }.toString())
            assertEquals(1, published.map { it.data().getValue("jobId") }.toSet().size, "one key publishes one job")
            outcomes.filter { it.statusCode() != 201 }.forEach { refused ->
                // A loser is a typed retryable refusal; it never creates or names a second job.
                assertTrue(refused.statusCode() in setOf(409, 429, 503), refused.text())
                assertTrue(refused.headers().firstValue("Location").isEmpty)
            }
            published.first().data().getValue("jobId").jsonPrimitive.content
        }
        assertEquals(listOf(created), JobStore(root).jobIds().toList())
        withServer { browser ->
            val replay = browser.upload("raced.elf", elfFixture(), key)
            assertEquals(201, replay.statusCode(), replay.text())
            assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElse(null))
            assertEquals(created, replay.data().getValue("jobId").jsonPrimitive.content)
            assertEquals("/w/api/v1/jobs/$created", replay.headers().firstValue("Location").orElse(null))
            val conflict = browser.upload("other.elf", elfFixture(), key)
            assertEquals(409, conflict.statusCode())
            assertEquals("IDEMPOTENCY_CONFLICT", conflict.errorCode())
        }
        // An unreadable retained receipt is refused, not silently replaced by a fresh job.
        Files.writeString(root.resolve(created).resolve("upload-receipt.json"), "{\"schemaVersion\":1}")
        withServer { browser ->
            val refused = browser.upload("raced.elf", elfFixture(), key)
            assertEquals(503, refused.statusCode(), refused.text())
            assertEquals("UPLOAD_RECEIPT_UNAVAILABLE", refused.errorCode())
            assertTrue(refused.headers().firstValue("Location").isEmpty)
        }
        assertEquals(listOf(created), JobStore(root).jobIds().toList())
        assertEquals(0, workflows.get())
    }
}
