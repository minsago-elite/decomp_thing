package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import kotlinx.serialization.json.*
import kotlin.io.path.*
import kotlin.test.*

class ReconstructionOutputWorkspaceTest {
    @Test
    fun `changed exporter preserves old capture and matching exporter keeps resumable analysis`() {
        val root = createTempDirectory("exporter-rollover-")
        val input = root.resolve("input").apply { writeText("a") }
        val oldHash = "a".repeat(64)
        val newHash = "b".repeat(64)
        ReconstructionOutputWorkspace.open(root, input).use { workspace ->
            root.resolve("analysis/reports/program_model.json.export").createDirectories()
                .resolve("state.json").writeText("{\"exporterSha256\":\"$oldHash\"}")
            root.resolve("analysis/marker").writeText("prior capture")
            assertFalse(workspace.preserveIncompatibleAnalysis(oldHash))
            assertTrue(workspace.preserveIncompatibleAnalysis(newHash))
            assertFalse(root.resolve("analysis").exists())
            val prior = root.resolve(".analysis-history").listDirectoryEntries().single()
            assertEquals("prior capture", prior.resolve("marker").readText())
            assertFalse(workspace.preserveIncompatibleAnalysis(newHash))
        }
    }

    @Test
    fun `different binaries preserve active results and switch back to original receipt paths`() {
        val base = createTempDirectory("input-workspaces-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("input-a") }
        val b = base.resolve("b").apply { writeText("input-b") }
        ReconstructionOutputWorkspace.open(root, a).use {
            root.resolve("analysis").createDirectory().resolve("marker").writeText("analysis-a")
            root.resolve("source-tree").createDirectory().resolve("marker").writeText("source-a")
            root.resolve("source-tree.zip").writeText("archive-a")
        }
        ReconstructionOutputWorkspace.open(root, b).use {
            assertFalse(root.resolve("source-tree").exists())
            root.resolve("source-tree").createDirectory().resolve("marker").writeText("source-b")
            root.resolve("source-tree.zip").writeText("archive-b")
        }
        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals("analysis-a", root.resolve("analysis/marker").readText())
            assertEquals("source-a", root.resolve("source-tree/marker").readText())
            assertEquals("archive-a", root.resolve("source-tree.zip").readText())
            assertEquals("archive-b", root.resolve("input-cache/${sha256(b.readBytes())}/source-tree.zip").readText())
        }
    }

    @Test
    fun `existing input-bound output is migrated without dropping its checkpoint state`() {
        val root = createTempDirectory("input-migration-")
        val a = root.resolveSibling(root.fileName.toString() + "-input").apply { writeText("a") }
        root.resolve("analysis/reports").createDirectories().resolve("program_model.json")
            .writeText("{\"inputSha256\":\"${sha256(a.readBytes())}\"}")
        root.resolve("source-tree").createDirectory().resolve("receipt").writeText("kept")
        ReconstructionOutputWorkspace.open(root, a).use { assertEquals("kept", root.resolve("source-tree/receipt").readText()) }
        assertTrue(root.resolve(ReconstructionOutputWorkspace.ACTIVE).exists())
        assertFalse(root.resolve(ReconstructionOutputWorkspace.CACHE).exists())
    }

    @Test
    fun `exclusive leases reject concurrent writers and can be reacquired after close`() {
        val base = createTempDirectory("input-lease-")
        val input = base.resolve("input").apply { writeText("a") }
        val root = base.resolve("output")
        ReconstructionOutputWorkspace.open(root, input).use {
            assertFailsWith<ReconstructionOutputBusyException> { ReconstructionOutputWorkspace.open(root, input) }
        }
        ReconstructionOutputWorkspace.open(root, input).close()
    }

    @Test
    fun `interrupted archive and restore phases resume without replacing preserved entries`() {
        for (phase in listOf("archive", "restore")) {
            val base = createTempDirectory("input-switch-recovery-")
            val root = base.resolve("output")
            val a = base.resolve("a").apply { writeText("a") }
            val b = base.resolve("b").apply { writeText("b") }
            val from = sha256(a.readBytes()); val to = sha256(b.readBytes())
            ReconstructionOutputWorkspace.open(root, a).use { root.resolve("source-tree.zip").writeText("a") }
            val outgoing = root.resolve("input-cache/$from").createDirectories()
            val incoming = root.resolve("input-cache/$to").createDirectories()
            incoming.resolve("source-tree.zip").writeText("b")
            Files.move(root.resolve("source-tree.zip"), outgoing.resolve("source-tree.zip"), ATOMIC_MOVE)
            if (phase == "restore") Files.move(incoming.resolve("source-tree.zip"), root.resolve("source-tree.zip"), ATOMIC_MOVE)
            root.resolve(ReconstructionOutputWorkspace.SWITCH).writeText(transaction(from, to, phase).toString())
            ReconstructionOutputWorkspace.open(root, b).use {
                assertEquals("b", root.resolve("source-tree.zip").readText())
                assertEquals("a", outgoing.resolve("source-tree.zip").readText())
                assertFalse(root.resolve(ReconstructionOutputWorkspace.SWITCH).exists())
            }
        }
    }

    @Test
    fun `malformed switch records and links cannot move or overwrite existing results`() {
        val base = createTempDirectory("input-switch-invalid-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("a") }
        val b = base.resolve("b").apply { writeText("b") }
        ReconstructionOutputWorkspace.open(root, a).use { root.resolve("source-tree.zip").writeText("a") }
        val bad = JsonObject(transaction(sha256(a.readBytes()), sha256(b.readBytes()), "archive") +
            ("restoreEntries" to JsonArray(listOf(JsonPrimitive("../outside")))))
        root.resolve(ReconstructionOutputWorkspace.SWITCH).writeText(bad.toString())
        assertFailsWith<IllegalArgumentException> { ReconstructionOutputWorkspace.open(root, b) }
        assertEquals("a", root.resolve("source-tree.zip").readText())
        Files.delete(root.resolve(ReconstructionOutputWorkspace.SWITCH))
        Files.createSymbolicLink(root.resolve("source-tree"), base.resolve("outside"))
        assertFailsWith<IllegalArgumentException> { ReconstructionOutputWorkspace.open(root, a) }
        assertEquals("a", root.resolve("source-tree.zip").readText())
    }

    private fun transaction(from: String, to: String, phase: String) = buildJsonObject {
        put("schemaVersion", 1); put("from", from); put("to", to); put("phase", phase)
        put("archiveEntries", JsonArray(listOf(JsonPrimitive("source-tree.zip"))))
        put("restoreEntries", JsonArray(listOf(JsonPrimitive("source-tree.zip"))))
    }
}
