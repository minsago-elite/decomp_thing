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

    private fun archives(release: CountDownLatch, verified: CountDownLatch): WebSourceArchives {
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
        return WebSourceArchives({ _, _, _ -> snapshot }, { _, _ -> attempt }, store, { _, _ -> null }, { _, _, sha ->
            assertTrue(release.await(10, TimeUnit.SECONDS))
            verified.countDown()
            WebArchiveSnapshot(ByteArray(0), sha, WebSourceArchivesTestViews.view, kotlinx.serialization.json.JsonObject(emptyMap()), snapshot.descriptorSha256)
        }, Executors.newSingleThreadExecutor())
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
}

private object WebSourceArchivesTestViews {
    val view: SourceTreeView = SourceTreeView(emptyList(), null)
}
