package decompengine.web

import decompengine.repair.*
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.*

class RecordedRepairEvidenceTest {
    @Test
    fun `history query is closed and page references cannot be borrowed from another capture`() {
        val graph = "a".repeat(64)
        val parsed = parseRecordedRepairHistoryQuery("runId=run_selected&historyPage=2&historyCasesPage=2&historyGraph=$graph")
        assertEquals("run_selected", parsed.runId)
        assertEquals(RepairRecordedHistorySelection(2, 2, graph), parsed.selection)
        for (query in listOf("", "historyPage=2", "historyCasesPage=2", "historyPage=1&historyPage=1",
            "runId=one&runId=two", "historyGraph=PRIVATE", "unknown=1", "historyPage=01",
            "historyPage=2147483648", "historyPage=%31", "runId=../private", "historyPage=")) {
            assertFailsWith<IllegalArgumentException>(query) { parseRecordedRepairHistoryQuery(query) }
        }
        val (reports, snapshot) = fixture()
        val other = fixture().second
        val foreignPage = RepairRecordedHistoryPage.select(other, RepairRecordedHistorySelection(), 100)
        assertFailsWith<IllegalArgumentException> { recordedRepairArtifactReferences(snapshot, foreignPage) }
        assertFailsWith<IllegalArgumentException> { listLegacyArtifactSummaries(WebReportContext(reports), snapshot, foreignPage) }
    }

    @Test
    fun `opaque targets require one checked selected namespace match and reject ambiguity`() {
        val (reports, snapshot) = fixture()
        val context = WebReportContext(reports, "reports/runs/run_selected", "run_selected")
        val reference = recordedRepairArtifactReference(snapshot.corpusSha256, "reports/after.json")
        val target = "reports/runs/run_selected/source-tree/reports/after.json"
        val entry = WebArtifactSummary(target, "Repair evidence", 2)
        assertEquals(target, recordedRepairEvidenceTarget(reference, snapshot, context, listOf(entry)))
        assertNull(recordedRepairEvidenceTarget(reference, snapshot, context, null))
        assertNull(recordedRepairEvidenceTarget(reference, snapshot, context, listOf(entry, entry)))
        assertNull(recordedRepairEvidenceTarget(reference, snapshot, context,
            listOf(entry, entry.copy(relativePath = "reports/runs/run_selected/after.json"))))
        assertNull(recordedRepairEvidenceTarget(reference, snapshot, context,
            listOf(entry.copy(relativePath = target.replace("run_selected", "run_other")))))
        assertNull(recordedRepairEvidenceTarget(recordedRepairArtifactReference("0".repeat(64), "reports/after.json"),
            snapshot, context, listOf(entry)))
        for (denied in listOf("reports/repair_history.json", "reports/repair-revisions/graph.json",
            "reports/repair-revisions/recovery-binding.json", "reports/repair-revisions/blobs/abc",
            "reports/runs/run_other/after.json", "reports/../after.json", "reports//after.json")) {
            val ref = recordedRepairArtifactReference(snapshot.corpusSha256, denied)
            val path = "${context.artifactPrefix}/source-tree/$denied"
            assertNull(recordedRepairEvidenceTarget(ref, snapshot, context, listOf(entry.copy(relativePath = path))), denied)
        }
    }

    @Test
    fun `checked listing adds only referenced regular source tree reports and never source or canonical payloads`() {
        val (reports, snapshot) = fixture()
        val context = WebReportContext(reports)
        assertTrue(listLegacyArtifactSummaries(context).isEmpty())
        val listed = listLegacyArtifactSummaries(context, snapshot)
        assertEquals(listOf("reports/source-tree/reports/after.json"), listed.map { it.relativePath })
        assertEquals(listOf("Repair evidence"), listed.map { it.displayName })
        val report = reports.resolve("source-tree/reports/after.json")
        val foreign = reports.resolve("PRIVATE-foreign.json")
        foreign.writeText("PRIVATE-unrelated")
        Files.delete(report)
        Files.createSymbolicLink(report, foreign)
        val linked = listLegacyArtifactSummaries(context, snapshot)
        assertFalse(linked.any { it.relativePath == "reports/source-tree/reports/after.json" })
        assertNull(recordedRepairEvidenceTarget(requireNotNull(snapshot.attempts.single().after?.artifact), snapshot, context, linked))
    }

    @Test
    fun `source entries do not consume the report listing budget but report entries still do`() {
        val (reports, snapshot) = fixture()
        val project = reports.resolve("source-tree")
        repeat(10_001) { index ->
            if (index % 2 == 0) Files.createFile(project.resolve("extra-$index.c"))
            else Files.createDirectory(project.resolve("extra-directory-$index"))
        }
        val context = WebReportContext(reports)
        val listed = listLegacyArtifactSummaries(context, snapshot)
        assertEquals(listOf("reports/source-tree/reports/after.json"), listed.map { it.relativePath })
        assertEquals("reports/source-tree/reports/after.json", recordedRepairEvidenceTarget(
            requireNotNull(snapshot.attempts.single().after?.artifact), snapshot, context, listed))

        repeat(10_001) { index -> Files.createFile(project.resolve("reports/overflow-$index.json")) }
        val failure = assertFailsWith<IllegalArgumentException> { listLegacyArtifactSummaries(context, snapshot) }
        assertTrue(failure.message.orEmpty().startsWith("report listing exceeds its "), failure.message)
    }

    @Test
    fun `fixed source report traversal never follows a linked report root`() {
        val (reports, snapshot) = fixture()
        val context = WebReportContext(reports)
        val project = reports.resolve("source-tree")
        val sourceReports = project.resolve("reports")
        val displaced = project.resolve("PRIVATE-displaced-reports")
        Files.move(sourceReports, displaced)
        Files.createSymbolicLink(sourceReports, displaced)
        val listed = listLegacyArtifactSummaries(context, snapshot)
        assertTrue(listed.isEmpty(), listed.toString())
        assertNull(recordedRepairEvidenceTarget(requireNotNull(snapshot.attempts.single().after?.artifact),
            snapshot, context, listed))
    }

    private fun fixture(): Pair<Path, RepairHistorySnapshot> {
        val parent = Path.of("build/test-tmp/recorded-repair-artifacts").toAbsolutePath().createDirectories()
        val reports = Files.createTempDirectory(parent, "case-")
        val project = reports.resolve("source-tree").createDirectories()
        project.resolve("code.c").writeText("PRIVATE-source")
        val profile = DeclarativeRepairIndexProfile("PRIVATE-profile", RepairIndexLayout(listOf("code.c"), listOf("code.c"),
            modules = listOf(RepairModuleEvidence("PRIVATE-module", listOf("code.c")))))
        ModuleRevisionGraph.open(project, profile).use { graph ->
            graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf("code.c"))
            graph.installCandidate(attempt, mapOf("code.c" to "PRIVATE-candidate".toByteArray()))
            graph.reject(attempt, RepairEvidence("valid", "PRIVATE-summary", "reports/after.json"))
        }
        project.resolve("reports/after.json").writeText("{}")
        project.resolve("reports/PRIVATE-unreferenced.json").writeText("PRIVATE-unreferenced")
        return reports to requireNotNull(readProjectRecordedRepairHistory(project).snapshot)
    }
}
