package decompengine

import decompengine.repair.*
import decompengine.project.sha256
import decompengine.validation.ProcessInput
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readBytes
import kotlin.io.path.writeText
import kotlin.test.*

class RecordedRepairHistoryCliTest {
    @Test
    fun `actual read only CLI reconnects to canonical history without another repair or private text`() {
        val root = root()
        val profile = DeclarativeRepairIndexProfile("PRIVATE-profile", RepairIndexLayout(listOf("code.c"),
            listOf("code.c"), modules = listOf(RepairModuleEvidence("PRIVATE-module", listOf("code.c")))))
        root.resolve("code.c").writeText("PRIVATE-original-source")
        ModuleRevisionGraph.open(root, profile).use { graph ->
            graph.enableRunContract()
            graph.retainRegressionInputs(listOf(ProcessInput("PRIVATE-case", listOf("PRIVATE-argv"), "PRIVATE-stdin".toByteArray())))
            graph.beginRun(2, 60_000)
            graph.bindOriginalBinary(sha256("reference".toByteArray()))
            graph.bindExpectedObservations(sha256("expected".toByteArray()))
            val corpus = graph.retainedRegressionCorpus()
            val metadata = RevisionRepairMetadata(1, "compile", "PRIVATE-prompt", "PRIVATE-summary", corpus.inputs.map { it.id },
                RepairEvidence("compile", "PRIVATE-diagnostic", "reports/PRIVATE-before.json"), corpus.sha256,
                publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)
            val attempt = graph.beginAttempt(listOf("code.c"), metadata)
            graph.installCandidate(attempt, mapOf("code.c" to "PRIVATE-candidate-source".toByteArray()))
            graph.reject(attempt, RepairEvidence("rejected", "PRIVATE-peer"))
        }
        val before = contents(root)
        val first = captureCli(root)
        val second = captureCli(root)
        assertEquals(first, second)
        assertTrue("Recorded repair metadata" in first)
        assertTrue("repair iteration 1: rejected" in first)
        assertTrue("Recorded restoration completed and was verified." in first)
        assertTrue("fully accepted revision: none" in first)
        assertTrue("retained regression cases: 1" in first)
        for (private in listOf("PRIVATE-", "code.c", "reports/")) assertFalse(private in first, first)
        val after = contents(root)
        assertEquals(before.keys, after.keys)
        for (name in before.keys) assertContentEquals(before.getValue(name), after.getValue(name), name)
    }

    @Test
    fun `absent and invalid canonical histories have different closed CLI results`() {
        val absent = presentRecordedRepairHistory(readProjectRecordedRepairHistory(root()))
        assertEquals(0, absent.exitCode)
        assertEquals(listOf("No canonical repair history is recorded."), absent.lines)
        val invalidRoot = root()
        Files.createDirectories(invalidRoot.resolve("reports/repair-revisions"))
        invalidRoot.resolve("reports/repair-revisions/graph.json").writeText("PRIVATE-invalid")
        val invalid = presentRecordedRepairHistory(readProjectRecordedRepairHistory(invalidRoot))
        assertEquals(1, invalid.exitCode)
        assertEquals(listOf("Recorded repair history is unavailable or invalid."), invalid.lines)
    }

    private fun root(): Path {
        val parent = Path.of("build/test-tmp/recorded-history-cli").toAbsolutePath()
        Files.createDirectories(parent)
        return Files.createTempDirectory(parent, "case-")
    }

    private fun captureCli(root: Path): String {
        val bytes = ByteArrayOutputStream()
        val original = System.out
        try {
            PrintStream(bytes, true, Charsets.UTF_8).use { output ->
                System.setOut(output)
                main(arrayOf("repair-history", root.toString()))
            }
        } finally { System.setOut(original) }
        return bytes.toString(Charsets.UTF_8)
    }

    private fun contents(root: Path): Map<String, ByteArray> = Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it) }.toList().associate { root.relativize(it).toString() to it.readBytes() }
    }
}
