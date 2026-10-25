package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.jobs.*
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import decompengine.repair.StableFileDigest
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Synthetic store and a controllable verifier; no archive is read and nothing executes. */
class WebSourceArchivesTest {
    private val jobId = "a".repeat(32)
    private val digest = "b".repeat(64)
    private val identity = LinuxFileIdentity(LinuxFileKey(1, 1), 0x8180, 1000, 1000, 1, 1, true, false, false)
    private val snapshot = WebRevisionSourceSnapshot(WebRevisionSourceReference(jobId, "run_1", "revision_1", "c".repeat(64), "version_1"),
        "d".repeat(64), "e".repeat(64), listOf(WebRevisionSourceFile(GeneratedFileEvidence("Makefile", "f".repeat(64), "fixture",
            roles = setOf(ProjectFileRole.BUILD_INPUT), contentKind = ProjectContentKind.UTF8_TEXT), 1)))

    private fun archives(release: CountDownLatch, verified: CountDownLatch, observe: () -> Unit = {},
        shutdownTimeoutMs: Long = 60_000): WebSourceArchives {
        val at = Instant.parse("2026-10-25T00:00:00Z")
        val attempt = WorkflowAttempt("run_1", jobId, WorkflowKind.RECONSTRUCT, WorkflowRunState.COMPLETED, "version_1", at, at, at, null, null, null,
            WorkflowExecutionLimits(1u, 1u, 1u, 0u), WorkflowTerminalReason.COMPLETED, null, WorkflowCandidate("revision_1", "c".repeat(64)), null)
        val store = object : WebArtifactStore {
            override fun attempts(jobId: String) = listOf(attempt)
            override fun present(jobId: String, runId: String, path: String) = true
            override fun stream(jobId: String, runId: String, path: String, declaredSize: (Long) -> Unit,
                consume: (ByteArray, Int) -> Unit, cancellationCheck: () -> Unit): StableFileDigest { observe(); return StableFileDigest(digest, 10, identity) }
            override fun revisionCommitments(jobId: String, runId: String, revisionId: String) = null
        }
        return WebSourceArchives({ _, _, _ -> snapshot }, { _, _ -> attempt }, store, { _, _ -> null }, { _, _, sha ->
            // Like ZIP extraction, this verifier does not stop when interrupted.
            var waiting = true
            while (waiting) try { assertTrue(release.await(10, TimeUnit.SECONDS)); waiting = false } catch (_: InterruptedException) { }
            verified.countDown()
            WebArchiveSnapshot(ByteArray(0), sha, WebSourceArchivesTestViews.view, kotlinx.serialization.json.JsonObject(emptyMap()), snapshot.descriptorSha256)
        }, Executors.newSingleThreadExecutor(), shutdownTimeoutMs = shutdownTimeoutMs)
    }

    @Test fun `a deduplicated request binds its own key to the returned operation`() {
        val release = CountDownLatch(1); val verified = CountDownLatch(1)
        archives(release, verified).use { archives ->
            val first = archives.start(jobId, "run_1", "revision_1", digest, "key-first-000000001")
            val second = archives.start(jobId, "run_1", "revision_1", digest, "key-second-00000001")
            assertSame(first.record, second.record); assertFalse(second.replayed)
            release.countDown(); assertTrue(verified.await(10, TimeUnit.SECONDS))
            val deadline = System.nanoTime() + 10_000_000_000
            while (!first.record.terminal && System.nanoTime() < deadline) Thread.sleep(5)
            assertEquals("completed", first.record.state)
            // Replaying the second key after completion returns the same operation instead of starting another.
            val replay = archives.start(jobId, "run_1", "revision_1", digest, "key-second-00000001")
            assertSame(first.record, replay.record); assertTrue(replay.replayed)
            assertEquals("IDEMPOTENCY_CONFLICT", assertFailsWith<WebAccessDenied> {
                archives.start(jobId, "run_1", "revision_2", digest, "key-second-00000001") }.code)
        }
    }

    @Test fun `a key admitted concurrently for another intent conflicts instead of being overwritten`() {
        val release = CountDownLatch(1); val verified = CountDownLatch(1)
        val firstObserving = CountDownLatch(1); val secondAdmitted = CountDownLatch(1)
        var observations = 0
        archives(release, verified, observe = {
            // The first request pauses after its initial key check until the second has been admitted.
            if (synchronized(this) { ++observations } == 1) { firstObserving.countDown(); assertTrue(secondAdmitted.await(10, TimeUnit.SECONDS)) }
        }).use { archives ->
            val key = "key-shared-0000001"
            val first = java.util.concurrent.CompletableFuture.supplyAsync { runCatching { archives.start(jobId, "run_1", "revision_1", digest, key) } }
            assertTrue(firstObserving.await(10, TimeUnit.SECONDS))
            val second = archives.start(jobId, "run_1", "revision_2", digest, key)
            assertFalse(second.replayed); secondAdmitted.countDown()
            val failure = first.get(10, TimeUnit.SECONDS).exceptionOrNull()
            assertEquals("IDEMPOTENCY_CONFLICT", (failure as WebAccessDenied).code)
            assertEquals(second.record, archives.start(jobId, "run_1", "revision_2", digest, key).record)
            release.countDown()
        }
    }

    @Test fun `shutdown waits for a running verifier and reports an unfinished one`() {
        val release = CountDownLatch(1); val verified = CountDownLatch(1)
        val archives = archives(release, verified)
        archives.start(jobId, "run_1", "revision_1", digest, "key-shutdown-00001")
        val closing = Thread { archives.close() }.apply { start() }
        closing.join(300)
        assertTrue(closing.isAlive, "close must wait while the verifier still reads storage")
        release.countDown(); closing.join(10_000)
        assertFalse(closing.isAlive); assertEquals(0, verified.count)

        val stuck = CountDownLatch(1)
        val bounded = archives(stuck, CountDownLatch(1), shutdownTimeoutMs = 100)
        val record = bounded.start(jobId, "run_1", "revision_1", digest, "key-shutdown-00002").record
        assertEquals("SHUTDOWN_INCOMPLETE", assertFailsWith<WebJobServiceException> { bounded.close() }.code)
        assertEquals("interrupted", record.state)
        stuck.countDown()
    }
}

/** Concurrent polling must only ever observe one transition's complete set of fields. */
class WebSourceArchivesConsistencyTest {
    @Test fun `status and operation projections stay consistent while verifications finish concurrently`() {
        val digest = "b".repeat(64)
        val jobId = "a".repeat(32)
        val identity = LinuxFileIdentity(LinuxFileKey(1, 1), 0x8180, 1000, 1000, 1, 1, true, false, false)
        val snapshot = WebRevisionSourceSnapshot(WebRevisionSourceReference(jobId, "run_1", "revision_1", "c".repeat(64), "version_1"),
            "d".repeat(64), "e".repeat(64), listOf(WebRevisionSourceFile(GeneratedFileEvidence("Makefile", "f".repeat(64), "fixture",
                roles = setOf(ProjectFileRole.BUILD_INPUT), contentKind = ProjectContentKind.UTF8_TEXT), 1)))
        val at = Instant.parse("2026-10-25T00:00:00Z")
        val attempt = WorkflowAttempt("run_1", jobId, WorkflowKind.RECONSTRUCT, WorkflowRunState.COMPLETED, "version_1", at, at, at, null, null, null,
            WorkflowExecutionLimits(1u, 1u, 1u, 0u), WorkflowTerminalReason.COMPLETED, null, WorkflowCandidate("revision_1", "c".repeat(64)), null)
        val store = object : WebArtifactStore {
            override fun attempts(jobId: String) = listOf(attempt)
            override fun present(jobId: String, runId: String, path: String) = true
            override fun stream(jobId: String, runId: String, path: String, declaredSize: (Long) -> Unit,
                consume: (ByteArray, Int) -> Unit, cancellationCheck: () -> Unit) = StableFileDigest(digest, 10, identity)
            override fun revisionCommitments(jobId: String, runId: String, revisionId: String) = null
        }
        var round = 0
        val archives = WebSourceArchives({ _, _, _ -> snapshot }, { _, _ -> attempt }, store, { _, _ -> null }, { _, _, sha ->
            // Alternate verified and failed outcomes so both terminal shapes are polled.
            if (synchronized(this) { round++ } % 2 == 1) throw IllegalArgumentException("payload differs")
            WebArchiveSnapshot(ByteArray(0), sha, SourceTreeView(emptyList(), null), kotlinx.serialization.json.JsonObject(emptyMap()), snapshot.descriptorSha256)
        }, Executors.newSingleThreadExecutor())
        archives.use {
            val stop = java.util.concurrent.atomic.AtomicBoolean(false)
            val problems = java.util.concurrent.ConcurrentLinkedQueue<String>()
            val poller = Thread {
                while (!stop.get()) {
                    val verification = archives.status("/", jobId, "run_1", "revision_1").getValue("verification") as kotlinx.serialization.json.JsonObject
                    val state = (verification.getValue("state") as kotlinx.serialization.json.JsonPrimitive).content
                    val verifiedAt = verification.getValue("verifiedAt") != kotlinx.serialization.json.JsonNull
                    val failure = verification.getValue("failureCode") != kotlinx.serialization.json.JsonNull
                    if (verifiedAt != (state == "verified") || failure != (state == "failed")) problems += verification.toString()
                }
            }.apply { start() }
            repeat(200) { index ->
                val record = archives.start(jobId, "run_1", "revision_1", digest, "key-consistency-${index.toString().padStart(4, '0')}").record
                while (!record.terminal) {
                    val operation = webArchiveOperation(record)
                    val ended = operation.getValue("endedAt") != kotlinx.serialization.json.JsonNull
                    val state = (operation.getValue("state") as kotlinx.serialization.json.JsonPrimitive).content
                    if (ended != (state in setOf("completed", "failed", "interrupted"))) problems += operation.toString()
                }
            }
            stop.set(true); poller.join(10_000)
            assertEquals(emptyList(), problems.toList())
        }
    }
}

private object WebSourceArchivesTestViews {
    val view: SourceTreeView = SourceTreeView(emptyList(), null)
}
