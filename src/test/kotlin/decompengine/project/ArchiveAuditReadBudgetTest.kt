package decompengine.project

import decompengine.repair.StableFileChangedException
import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.io.TempDir
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ArchiveAuditReadBudgetTest {
    @TempDir
    lateinit var project: Path
    private val profile = GeneratedCMakeReconstructionProfile.descriptor

    private fun snapshot() = Files.walk(project).use { stream ->
        stream.toList().associate { path ->
            project.relativize(path).toString() to if (Files.isDirectory(path)) null else sha256(Files.readAllBytes(path))
        }
    }

    private fun writeManifest(): Int {
        val model = RecoveredProgramModel(inputSha256 = "1".repeat(64), functions = emptyList())
        val bytes = model.toJson().encodeToByteArray()
        val declaration = profile.layout.declaration("program-model-evidence")
        val relative = declaration.materialize()
        val modelPath = project.resolve(relative)
        Files.createDirectories(modelPath.parent)
        Files.write(modelPath, bytes)
        val manifest = SourceTreeManifest(profileId = profile.id, profileSha256 = profile.sha256,
            inputSha256 = model.inputSha256, files = listOf(GeneratedFileEvidence(relative, sha256(bytes),
                "fixture", roles = declaration.roles, contentKind = declaration.contentKind)), unresolvedEntityIds = emptyList())
        Files.writeString(project.resolve("source_tree_manifest.json"), manifest.toJson())
        return bytes.size
    }

    @Test
    fun `zero byte allowance accepts an empty file and rejects a nonempty zero size descriptor`() {
        Files.createFile(project.resolve("empty"))
        val budget = ArchiveAuditReadBudget(0, 2)
        assertEquals(0, budget.read(project, "empty", 0).bytes.size)

        // Linux procfs exposes the kernel version as a regular file with a declared size of zero.
        val proc = Path.of("/proc")
        assertEquals(0L, Files.size(proc.resolve("version")))
        assertFailsWith<StableFileChangedException> { budget.read(proc, "version", 0) }
        assertEquals(0L, budget.bytesRead)
        assertEquals(2, budget.entriesVisited)
    }

    @Test
    fun `nested reads and repeated walks consume the same audit allowance`() {
        val modelBytes = writeManifest()
        val manifestPath = project.resolve("source_tree_manifest.json")
        Files.createDirectories(project.resolve("reports/empty"))
        val initial = snapshot()
        val scanEntries = Files.walk(project.resolve("reports")).use { it.count().toInt() }
        // Manifest and payload are verified twice, and reconstruction independently reads the model.
        val expectedBytes = 2 * Files.size(manifestPath) + 3 * modelBytes
        val expectedEntries = 5 + 2 * scanEntries
        val exact = ArchiveAuditReadBudget(expectedBytes, expectedEntries)
        assertNull(ArchivalProjectAuditor.auditRepairEvidence(project, profile, exact).graphHeadId)
        assertEquals(expectedBytes, exact.bytesRead)
        assertEquals(expectedEntries, exact.entriesVisited)

        val short = ArchiveAuditReadBudget(expectedBytes - 1, expectedEntries)
        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.auditRepairEvidence(project, profile, short) }
        assertEquals(expectedBytes - modelBytes, short.bytesRead)

        val inventory = ArchiveAuditReadBudget(expectedBytes, expectedEntries - 1)
        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.auditRepairEvidence(project, profile, inventory) }
        assertEquals(expectedEntries - 1, inventory.entriesVisited)
        assertEquals(initial, snapshot())
    }

    @Test
    fun `repair verifier refuses a repeated graph read before decoding its body`() {
        val modelBytes = writeManifest()
        val graph = project.resolve("reports/repair-revisions/graph.json")
        Files.createDirectories(graph.parent)
        Files.writeString(graph, "invalid graph")
        val history = Files.writeString(project.resolve("reports/repair_history.json"), "[]")
        val initial = snapshot()
        val firstPass = Files.size(project.resolve("source_tree_manifest.json")) + modelBytes +
            Files.size(history) + Files.size(graph)
        val budget = ArchiveAuditReadBudget(firstPass, 100)
        val refusal = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.auditRepairEvidence(project, profile, budget)
        }
        assertEquals("archive audit read byte budget exhausted", refusal.message)
        assertEquals(firstPass, budget.bytesRead)
        assertEquals(initial, snapshot())
    }

    @Test
    fun `refusal precedes the first byte and cancellation charges only completed chunks`() {
        val bytes = ByteArray(128 * 1024) { 65 }
        Files.write(project.resolve("source_tree_manifest.json"), bytes)
        val initial = snapshot()
        val short = ArchiveAuditReadBudget(bytes.size.toLong() - 1, 1)
        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.auditRepairEvidence(project, profile, short) }
        assertEquals(0L, short.bytesRead)

        lateinit var cancelled: ArchiveAuditReadBudget
        cancelled = ArchiveAuditReadBudget(bytes.size.toLong(), 1) {
            if (cancelled.bytesRead > 0) throw InterruptedException("cancel during stable read")
        }
        assertFailsWith<InterruptedException> { ArchivalProjectAuditor.auditRepairEvidence(project, profile, cancelled) }
        assertTrue(cancelled.bytesRead in 1L until bytes.size.toLong())
        assertEquals(initial, snapshot())
    }
}
