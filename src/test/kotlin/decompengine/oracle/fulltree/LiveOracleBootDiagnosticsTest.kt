package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class LiveOracleBootDiagnosticsTest {
    private val unitName = "decomp-oracle-function-${"a".repeat(64)}.scope"

    @Test
    fun `journal query is bounded newest first and names only an exact owned unit`() {
        val since = 1_788_572_160L
        assertEquals(
            listOf(
                "/usr/bin/journalctl", "--user", "--boot", "--no-pager", "--quiet", "--reverse",
                "--output=short-monotonic", "--lines=80", "--since=@$since", "--user-unit=$unitName",
            ),
            liveOracleUnitJournalCommand(unitName, since),
        )
        for (invalid in listOf(
            "*.scope", "$unitName\n", "another-$unitName", "--all", unitName.uppercase(),
            "decomp-oracle-function-${"a".repeat(63)}.scope", "decomp-gcc-${"a".repeat(256)}.scope",
        )) {
            assertFailsWith<IllegalArgumentException> { liveOracleUnitJournalCommand(invalid, since) }
        }
        assertFailsWith<IllegalArgumentException> { liveOracleUnitJournalCommand(unitName, -1L) }
    }

    @Test
    fun `trace retains bounded first observations after worker cleanup removes protocol files`() =
        inControlTemporaryDirectory { root ->
            LiveOracleBootTrace(root).use { trace ->
                val boot = protocolFile(root, "worker.boot", "BOOT\tfixture\n")
                trace.sample()
                Files.delete(boot)
                val failure = protocolFile(root, "worker.failure", "FAIL\tparent.start timed out\n")
                trace.sample()
                Files.delete(failure)
                trace.sample()
                assertTrue(trace.snapshot().contains("worker.boot observed at"))
                assertTrue(trace.snapshot().contains("BOOT\tfixture"))
                assertTrue(trace.snapshot().contains("worker.failure observed at"))
                assertTrue(trace.snapshot().contains("parent.start timed out"))
                assertFalse(trace.snapshot().contains("unavailable"))
            }
            Unit
        }

    @Test
    fun `trace rejects oversized writable linked and nonregular protocol members without reading them`() =
        inControlTemporaryDirectory { root ->
            val secret = protocolFile(root, "unrelated", "unrelated secret")
            Files.createSymbolicLink(root.resolve("worker.boot"), secret)
            Files.createLink(root.resolve("parent.start"), secret)
            protocolFile(root, "worker.failure", "oversized secret".repeat(512))
            Files.createDirectory(root.resolve("supervisor.failure"))
            LiveOracleBootTrace(root).use { trace ->
                trace.sample()
                val captured = trace.snapshot()
                assertEquals(4, captured.lineSequence().count { "unavailable:" in it })
                assertFalse(captured.contains("unrelated secret"))
                assertFalse(captured.contains("oversized secret"))
                assertFalse(captured.contains("observed at"))
            }
            Files.delete(root.resolve("parent.start"))
            Files.delete(root.resolve("worker.boot"))
            Files.writeString(root.resolve("worker.boot"), "writable secret")
            LiveOracleBootTrace(root).use { trace ->
                trace.sample()
                assertFalse(trace.snapshot().contains("writable secret"))
                assertTrue(trace.snapshot().contains("worker.boot unavailable:"))
            }
            assertEquals("unrelated secret", Files.readString(secret))
        }

    @Test
    fun `trace stays on the pinned run root after its pathname is replaced`() =
        inControlTemporaryDirectory { root ->
            val runRoot = Files.createDirectory(root.resolve("run"))
            LiveOracleBootTrace(runRoot).use { trace ->
                val retained = Files.move(runRoot, root.resolve("retained"))
                Files.createDirectory(runRoot)
                protocolFile(runRoot, "worker.boot", "replacement secret")
                protocolFile(retained, "worker.boot", "BOOT\tretained root\n")
                trace.sample()
                assertTrue(trace.snapshot().contains("BOOT\tretained root"))
                assertFalse(trace.snapshot().contains("replacement secret"))
            }
            Unit
        }

    @Test
    fun `failure diagnostics preserve the primary failure and never mutate protocol evidence`() =
        inControlTemporaryDirectory { root ->
            val boot = protocolFile(root, "worker.boot", "BOOT\tfixture\n")
            val original = AssertionError("primary BOOT failure")
            var journalCalls = 0
            val observed = assertFailsWith<AssertionError> {
                withLiveOracleBootDiagnostics(unitName, root, journal = { requested, since ->
                    assertEquals(unitName, requested)
                    assertTrue(since > 0L)
                    journalCalls += 1
                    "bounded exact-unit journal"
                }) { throw original }
            }
            assertSame(original, observed)
            assertEquals(1, journalCalls)
            val details = observed.suppressed.single().message.orEmpty()
            assertTrue(details.contains("diagnostic only"))
            assertTrue(details.contains("BOOT\tfixture"))
            assertTrue(details.contains("bounded exact-unit journal"))
            assertEquals("BOOT\tfixture\n", Files.readString(boot))
        }

    @Test
    fun `successful action does not query the journal and a closed trace does not read again`() =
        inControlTemporaryDirectory { root ->
            assertEquals(
                "complete",
                withLiveOracleBootDiagnostics(unitName, root, journal = { _, _ ->
                    error("successful action must not query journal")
                }) { "complete" },
            )
            val trace = LiveOracleBootTrace(root)
            trace.close()
            protocolFile(root, "worker.boot", "must not be read")
            trace.sample()
            assertEquals("no allowlisted BOOT protocol files observed", trace.snapshot())
            trace.close()
        }

    @Test
    fun `unavailable diagnostics cannot replace the primary failure or clear interruption`() =
        inControlTemporaryDirectory { root ->
            val original = AssertionError("primary failure")
            Thread.currentThread().interrupt()
            try {
                val observed = assertFailsWith<AssertionError> {
                    withLiveOracleBootDiagnostics(unitName, root.resolve("absent")) { throw original }
                }
                assertSame(original, observed)
                assertTrue(Thread.currentThread().isInterrupted)
                val details = observed.suppressed.single().message.orEmpty()
                assertTrue(details.contains("protocol trace unavailable"))
                assertTrue(details.contains("journal diagnostics cannot run on an interrupted thread"))
            } finally {
                Thread.interrupted()
            }
        }

    private fun protocolFile(root: Path, name: String, content: String): Path =
        root.resolve(name).also { path ->
            Files.writeString(path, content)
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
        }
}
