package decompengine.web

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WebAuditLogTest {
    private val session = "ab".repeat(32)
    private val job = "0123456789abcdef0123456789abcdef"
    private val clock = Clock.fixed(Instant.parse("2026-10-01T00:00:00Z"), ZoneOffset.UTC)

    private fun root(name: String): Path =
        Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/web-audit").toAbsolutePath()), "$name-")

    private fun WebAuditLog.cancel(runId: String = "run_1", outcome: WebAuditOutcome = WebAuditOutcome.ACCEPTED,
                                    status: Int = 202, reason: String? = null) = record(
        WebAuditActor.browserSession(session), WebAuditAction.RUN_CANCEL,
        WebAuditTarget(job, runId, "version_1", "version_2"), outcome, status, reason, "0f3c2b1a-1111-4222-8333-944455556666")

    @Test fun `entries are durable, attributed by digest and resume their sequence after reopen`() {
        val root = root("durable")
        try {
            val log = WebAuditLog(root, clock)
            val first = checkNotNull(log.cancel())
            assertEquals(1, first.sequence)
            val digest = checkNotNull(first.actor.sessionDigest)
            assertNotEquals(session, digest)
            assertTrue(digest.matches(Regex("[0-9a-f]{64}")))
            log.record(WebAuditActor.UNAUTHENTICATED, WebAuditAction.JOB_UPLOAD, WebAuditTarget(), WebAuditOutcome.REJECTED,
                403, "CSRF_DENIED", null)
            val reopened = WebAuditLog(root, clock)
            assertEquals(3, reopened.cancel(outcome = WebAuditOutcome.REPLAYED, status = 200)?.sequence)
            val page = reopened.read()
            assertEquals(listOf(1L, 2L, 3L), page.entries.map { it.sequence })
            assertEquals(listOf("accepted", "rejected", "replayed"), page.entries.map { it.outcome.wireName })
            assertEquals("CSRF_DENIED", page.entries[1].reasonCode)
            assertTrue(page.complete)
            assertEquals(0, page.omittedBefore)
            assertEquals(listOf(1L, 3L), reopened.read(jobId = job).entries.map { it.sequence })
            val stored = Files.readString(root.resolve(".web-audit/current.jsonl"))
            assertFalse(stored.contains(session), "raw session identity must not be stored")
        } finally { root.toFile().deleteRecursively() }
    }

    @Test fun `values outside their closed syntax are dropped rather than stored`() {
        val root = root("sanitize")
        try {
            val log = WebAuditLog(root, clock)
            val entry = checkNotNull(log.record(WebAuditActor.OPERATOR, WebAuditAction.RUN_START,
                WebAuditTarget("/home/user/secret", "run with spaces", "\"quoted\"", "ok_version"), WebAuditOutcome.FAILED,
                999, "lower-case message: password=x", "not-a-request-id"))
            assertNull(entry.target.jobId); assertNull(entry.target.runId); assertNull(entry.target.expectedVersion)
            assertEquals("ok_version", entry.target.resultVersion)
            assertEquals(500, entry.status)
            assertNull(entry.reasonCode); assertNull(entry.requestId)
            val stored = Files.readString(root.resolve(".web-audit/current.jsonl"))
            listOf("/home/user", "password", "spaces", "quoted").forEach { assertFalse(stored.contains(it), it) }
        } finally { root.toFile().deleteRecursively() }
    }

    @Test fun `two bounded segments retain recent entries with exact omitted-prefix accounting`() {
        val root = root("rotate")
        try {
            val log = WebAuditLog(root, clock, segmentEntries = 3)
            repeat(10) { log.cancel(runId = "run_$it") }
            val page = log.read()
            // After the latest rotation the previous segment holds 7..9 and the current one 10.
            assertEquals((7L..10L).toList(), page.entries.map { it.sequence })
            assertEquals(6, page.omittedBefore)
            assertEquals(listOf(9L, 10L), log.read(limit = 2).entries.map { it.sequence })
            assertFalse(log.read(limit = 2).complete)
            assertEquals(11, WebAuditLog(root, clock, segmentEntries = 3).cancel()?.sequence)
        } finally { root.toFile().deleteRecursively() }
    }

    @Test fun `a torn final append is discarded and an unwritable store is counted, never thrown`() {
        val root = root("torn")
        try {
            WebAuditLog(root, clock).cancel()
            Files.write(root.resolve(".web-audit/current.jsonl"), "{\"schemaVersion\":1,\"entry\":{\"seq".toByteArray(),
                StandardOpenOption.APPEND)
            val reopened = WebAuditLog(root, clock)
            assertEquals(2, reopened.cancel()?.sequence)
            assertEquals(listOf(1L, 2L), reopened.read().entries.map { it.sequence })
        } finally { root.toFile().deleteRecursively() }
        val blocked = root("blocked")
        try {
            Files.writeString(blocked.resolve(WebAuditLog.DIRECTORY), "not a directory")
            val log = WebAuditLog(blocked, clock)
            assertNull(log.cancel())
            val page = log.read()
            assertEquals(1, page.unrecordedEntries)
            assertFalse(page.complete)
        } finally { blocked.toFile().deleteRecursively() }
    }

    @Test fun `a failed partial append is rolled back so later records and earlier entries stay readable`() {
        val root = root("partial")
        try {
            var failNext = false
            val log = WebAuditLog(root, clock, append = { channel, buffer ->
                if (failNext) {
                    failNext = false
                    buffer.limit(buffer.limit() / 2)
                    while (buffer.hasRemaining()) channel.write(buffer)
                    throw java.io.IOException("No space left on device")
                }
                while (buffer.hasRemaining()) channel.write(buffer)
            })
            assertEquals(1, log.cancel()?.sequence)
            failNext = true
            assertNull(log.cancel())
            assertEquals(2, log.cancel()?.sequence)
            val page = log.read()
            assertEquals(listOf(1L, 2L), page.entries.map { it.sequence })
            assertEquals(1, page.unrecordedEntries)
            assertEquals(listOf(1L, 2L), WebAuditLog(root, clock).read().entries.map { it.sequence }, "reopen reads every entry")
        } finally { root.toFile().deleteRecursively() }
    }

    @Test fun `versioned and legacy routes map to the closed action vocabulary`() {
        val run = WebAuditRecorder.versionedAction("POST", "jobs/$job/runs/run_1/cancel")
        assertEquals(WebAuditAction.RUN_CANCEL to WebAuditTarget(job, "run_1"), run)
        assertEquals(WebAuditAction.JOB_DELETE, WebAuditRecorder.versionedAction("DELETE", "jobs/$job")?.first)
        assertEquals(WebAuditAction.JOB_UPDATE, WebAuditRecorder.versionedAction("PATCH", "jobs/$job")?.first)
        assertEquals(WebAuditAction.RUN_RECOVER, WebAuditRecorder.versionedAction("POST", "jobs/$job/runs/r/recover")?.first)
        assertEquals(WebAuditAction.PROGRESS_PIN, WebAuditRecorder.versionedAction("PUT", "jobs/$job/runs/r/progress-pin")?.first)
        assertEquals(WebAuditTarget(null, "r"), WebAuditRecorder.versionedAction("PUT", "jobs/../runs/r/progress-pin")?.second)
        assertNull(WebAuditRecorder.versionedAction("GET", "jobs/$job"))
        assertNull(WebAuditRecorder.versionedAction("GET", "jobs/$job/runs/r/events"))
        assertEquals(WebAuditAction.RUN_START, WebAuditRecorder.legacyAction("POST", listOf("jobs", job, "explore"))?.first)
        assertNull(WebAuditRecorder.legacyAction("GET", listOf("jobs")))
        assertEquals(WebAuditAction.SESSION_START, WebAuditRecorder.legacyAction("POST", listOf("api", "v1", "session"))?.first)
        assertEquals(WebAuditAction.SESSION_END, WebAuditRecorder.legacyAction("DELETE", listOf("api", "v1", "session"))?.first)
        assertNull(WebAuditRecorder.legacyAction("GET", listOf("api", "v1", "session")))
    }
}
