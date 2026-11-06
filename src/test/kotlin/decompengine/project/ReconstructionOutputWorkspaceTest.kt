package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption.READ
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import decompengine.testing.RecoveryMatrixEvidence
import org.junit.jupiter.api.extension.ExtendWith
import kotlinx.serialization.json.*
import kotlin.io.path.*
import kotlin.test.*

@ExtendWith(RecoveryMatrixEvidence::class)
class ReconstructionOutputWorkspaceTest {
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
            root.resolve(ModuleObservedBehavior.FILE_NAME).writeText("observations-a")
        }
        ReconstructionOutputWorkspace.open(root, b).use {
            assertFalse(root.resolve("source-tree").exists())
            assertFalse(root.resolve(ModuleObservedBehavior.FILE_NAME).exists())
            root.resolve("source-tree").createDirectory().resolve("marker").writeText("source-b")
            root.resolve("source-tree.zip").writeText("archive-b")
            root.resolve(ModuleObservedBehavior.FILE_NAME).writeText("observations-b")
        }
        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals("analysis-a", root.resolve("analysis/marker").readText())
            assertEquals("source-a", root.resolve("source-tree/marker").readText())
            assertEquals("archive-a", root.resolve("source-tree.zip").readText())
            assertEquals("observations-a", root.resolve(ModuleObservedBehavior.FILE_NAME).readText())
            assertEquals("archive-b", root.resolve("input-cache/${sha256(b.readBytes())}/source-tree.zip").readText())
            assertEquals("observations-b", root.resolve("input-cache/${sha256(b.readBytes())}/${ModuleObservedBehavior.FILE_NAME}").readText())
        }
    }

    @Test
    fun `cache and per-input parent entries are synced before moving active results`() {
        for (failedSync in 0..3) {
            val base = createTempDirectory("input-cache-parent-sync-")
            val root = base.resolve("output")
            val a = base.resolve("a").apply { writeText("input-a") }
            val b = base.resolve("b").apply { writeText("input-b") }
            ReconstructionOutputWorkspace.open(root, a).use {
                root.resolve("source-tree.zip").writeText("accepted-a")
            }

            val synced = mutableListOf<Path>()
            assertFailsWith<IOException> {
                ReconstructionOutputWorkspace.openWithParentSyncForTest(root, b) { parent ->
                    synced.add(parent)
                    if (synced.lastIndex == failedSync) throw IOException("injected parent sync failure")
                    FileChannel.open(parent, READ).use { it.force(true) }
                }
            }

            val cache = root.resolve(ReconstructionOutputWorkspace.CACHE)
            assertEquals(listOf(root, cache, root, cache).take(failedSync + 1), synced)
            assertEquals("accepted-a", root.resolve("source-tree.zip").readText())
            assertFalse(root.resolve(ReconstructionOutputWorkspace.SWITCH).exists())
            assertEquals(sha256(a.readBytes()),
                Json.parseToJsonElement(root.resolve(ReconstructionOutputWorkspace.ACTIVE).readText())
                    .jsonObject.getValue("inputSha256").jsonPrimitive.content)

            // The failed sync may have left created directories in place. A retry must sync
            // their parents again before archiving the accepted active result.
            ReconstructionOutputWorkspace.open(root, b).use {
                assertFalse(root.resolve("source-tree.zip").exists())
                assertEquals("accepted-a", root.resolve("input-cache/${sha256(a.readBytes())}/source-tree.zip").readText())
            }
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
    fun `module observation identity routes the initial handoff to its input`() {
        val base = createTempDirectory("input-observation-identity-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("input-a") }
        val b = base.resolve("b").apply { writeText("input-b") }
        val aHash = sha256(a.readBytes())
        ModuleObservedBehavior.write(root, aHash, emptyList())

        ReconstructionOutputWorkspace.open(root, b).use {
            assertFalse(root.resolve(ModuleObservedBehavior.FILE_NAME).exists())
            assertTrue(root.resolve("input-cache/$aHash/${ModuleObservedBehavior.FILE_NAME}").exists())
        }
        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals(aHash, ModuleObservedBehavior.parse(root.resolve(ModuleObservedBehavior.FILE_NAME).readText()).inputSha256)
        }
    }

    @Test
    fun `unscoped initial exploration is bound to first activated input and isolated on switch`() {
        val base = createTempDirectory("input-unscoped-exploration-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("input-a") }
        val b = base.resolve("b").apply { writeText("input-b") }
        val aHash = sha256(a.readBytes())
        root.resolve("exploration.json").apply { parent.createDirectories(); writeText("exploration-a") }
        root.resolve("agent-progress.json").writeText("progress-a")
        root.resolve("run-history/a/events.jsonl").apply { parent.createDirectories(); writeText("history-a") }

        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals("exploration-a", root.resolve("exploration.json").readText())
            assertEquals("progress-a", root.resolve("agent-progress.json").readText())
            assertEquals("history-a", root.resolve("run-history/a/events.jsonl").readText())
        }
        ReconstructionOutputWorkspace.open(root, b).use {
            assertFalse(root.resolve("exploration.json").exists())
            assertFalse(root.resolve("agent-progress.json").exists())
            assertFalse(root.resolve("run-history").exists())
            assertEquals("exploration-a", root.resolve("input-cache/$aHash/exploration.json").readText())
            assertEquals("progress-a", root.resolve("input-cache/$aHash/agent-progress.json").readText())
            assertEquals("history-a", root.resolve("input-cache/$aHash/run-history/a/events.jsonl").readText())
        }
        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals("exploration-a", root.resolve("exploration.json").readText())
            assertEquals("progress-a", root.resolve("agent-progress.json").readText())
            assertEquals("history-a", root.resolve("run-history/a/events.jsonl").readText())
        }
    }

    @Test
    fun `progress snapshot and full run history follow the selected input`() {
        val base = createTempDirectory("input-history-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("input-a") }
        val b = base.resolve("b").apply { writeText("input-b") }
        val aHash = sha256(a.readBytes())
        val bHash = sha256(b.readBytes())
        ReconstructionOutputWorkspace.open(root, a).use {
            root.resolve("agent-progress.json").writeText("progress-a")
            root.resolve("run-history/a").createDirectories().resolve("events.jsonl").writeText("history-a")
            root.resolve(ModuleCompilerFeedbackStore.DIRECTORY).createDirectory().resolve("parse.json").writeText("feedback-a")
        }
        ReconstructionOutputWorkspace.open(root, b).use {
            assertFalse(root.resolve("agent-progress.json").exists())
            assertFalse(root.resolve("run-history").exists())
            assertFalse(root.resolve(ModuleCompilerFeedbackStore.DIRECTORY).exists())
            root.resolve("agent-progress.json").writeText("progress-b")
            root.resolve("run-history/b").createDirectories().resolve("events.jsonl").writeText("history-b")
            root.resolve(ModuleCompilerFeedbackStore.DIRECTORY).createDirectory().resolve("parse.json").writeText("feedback-b")
        }
        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals("progress-a", root.resolve("agent-progress.json").readText())
            assertEquals("history-a", root.resolve("run-history/a/events.jsonl").readText())
            assertEquals("feedback-a", root.resolve("${ModuleCompilerFeedbackStore.DIRECTORY}/parse.json").readText())
            assertEquals("progress-b", root.resolve("input-cache/$bHash/agent-progress.json").readText())
            assertEquals("history-b", root.resolve("input-cache/$bHash/run-history/b/events.jsonl").readText())
            assertEquals("feedback-b", root.resolve("input-cache/$bHash/${ModuleCompilerFeedbackStore.DIRECTORY}/parse.json").readText())
            assertEquals(aHash, it.inputSha256)
        }
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
    fun `publication ownership validates lock lifetime and canonical directory identity`() {
        val base = createTempDirectory("input-publication-ownership-")
        val root = base.resolve("output")
        val input = base.resolve("input").apply { writeText("a") }
        val workspace = ReconstructionOutputWorkspace.open(root, input)
        workspace.publicationLock.validate()
        assertSame(workspace.publicationLock, workspace.publicationLock.borrow(root, workspace.inputSha256))
        assertFailsWith<IllegalArgumentException> {
            workspace.publicationLock.borrow(base.resolve("other"), workspace.inputSha256)
        }
        assertFailsWith<IllegalArgumentException> {
            workspace.publicationLock.borrow(root, "0".repeat(64))
        }

        val displaced = base.resolve("displaced-output")
        Files.move(root, displaced, ATOMIC_MOVE)
        Files.createDirectory(root)
        assertFailsWith<IllegalStateException> { workspace.publicationLock.validate() }
        workspace.close()
        assertFailsWith<IllegalStateException> { workspace.publicationLock.validate() }
    }

    @Test
    fun `publication borrowing refuses input bytes changed after workspace admission`() {
        val base = createTempDirectory("input-publication-input-change-")
        val root = base.resolve("output")
        val input = base.resolve("input").apply { writeText("before") }
        ReconstructionOutputWorkspace.open(root, input).use { workspace ->
            input.writeText("after")
            assertFailsWith<IllegalStateException> {
                workspace.publicationLock.borrow(root, workspace.inputSha256)
            }
        }
    }

    @Test
    fun `closed publication ownership cannot be reused`() {
        val base = createTempDirectory("input-publication-closed-")
        val workspace = ReconstructionOutputWorkspace.open(
            base.resolve("output"), base.resolve("input").apply { writeText("a") },
        )
        val ownership = workspace.publicationLock
        workspace.close()
        assertFailsWith<IllegalStateException> { ownership.validate() }
    }

    @Test
    fun `pending publication journal blocks activation before input recovery moves entries`() {
        val base = createTempDirectory("input-publication-pending-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("a") }
        val b = base.resolve("b").apply { writeText("b") }
        val from = sha256(a.readBytes())
        val to = sha256(b.readBytes())
        ReconstructionOutputWorkspace.open(root, a).use { root.resolve("source-tree.zip").writeText("a") }
        val incoming = root.resolve("input-cache/$to").createDirectories()
        incoming.resolve("source-tree.zip").writeText("b")
        root.resolve(ReconstructionOutputWorkspace.SWITCH).writeText(transaction(from, to, "archive").toString())
        root.resolve(ReconstructionOutputWorkspace.PUBLICATION).writeText("pending")

        assertFailsWith<IllegalStateException> { ReconstructionOutputWorkspace.open(root, b) }
        assertEquals("a", root.resolve("source-tree.zip").readText())
        assertEquals("b", incoming.resolve("source-tree.zip").readText())
        assertTrue(root.resolve(ReconstructionOutputWorkspace.SWITCH).exists())
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
