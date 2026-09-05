package decompengine.acp

import decompengine.agent.*
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class WorkspaceSnapshotLimitsTest {
    @Test
    fun `descriptor hash streams exact bytes under the snapshot budget`() {
        val root = workspace()
        val bytes = ByteArray(150_000) { (it % 251).toByte() }
        Files.write(root.resolve("src/data"), bytes)
        val chunks = mutableListOf<Int>()
        var declared = -1L
        val result = decompengine.repair.hashStableRegularFile(root, "src/data",
            { declared = it }, { count, _ -> chunks += count }, {})
        val expected = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        assertEquals(expected, result.sha256)
        assertEquals(bytes.size.toLong(), result.size)
        assertEquals(result.size, declared)
        assertEquals(bytes.size, chunks.sum())
        assertTrue(chunks.size > 1 && chunks.all { it in 1..65536 })
    }

    @Test
    fun `recursive inventory rejects symlinks instead of silently omitting them`() {
        val root = workspace()
        val outside = root.resolve("outside")
        outside.writeText("retained private content")
        Files.createSymbolicLink(root.resolve("src/link"), outside)
        assertEquals("symbolic-link", assertFailsWith<WorkspaceSnapshotInvalidEntry> {
            capture(request(root), WorkspaceSnapshotLimits())
        }.reason)
        assertEquals("retained private content", Files.readString(outside))
    }

    @Test
    fun `dangling links are unsupported entries rather than absent authorized paths`() {
        val root = workspace()
        Files.createSymbolicLink(root.resolve("src/link"), root.resolve("missing"))
        assertEquals("symbolic-link", assertFailsWith<WorkspaceSnapshotInvalidEntry> {
            capture(request(root), WorkspaceSnapshotLimits())
        }.reason)
    }

    @Test
    fun `special socket entries are rejected without opening their content`() {
        val root = workspace()
        val socket = root.resolve("src/socket")
        java.nio.channels.ServerSocketChannel.open(java.net.StandardProtocolFamily.UNIX).use { server ->
            server.bind(java.net.UnixDomainSocketAddress.of(socket))
            assertEquals("special-file", assertFailsWith<WorkspaceSnapshotInvalidEntry> {
                capture(request(root), WorkspaceSnapshotLimits())
            }.reason)
        }
        assertTrue(Files.exists(socket))
    }

    @Test
    fun `missing explicitly authorized target remains eligible for later creation`() {
        val root = workspace()
        val path = AgentWorkspacePath("project", "src/new")
        val request = AgentExecutionRequest("creation fixture", listOf(AgentWorkspaceRoot("project", root)),
            emptyList(), AgentAccessPolicy(listOf(AgentPathRule(path,
                setOf(AgentOperation.READ_FILE, AgentOperation.CREATE_FILE)))))
        val before = capture(request, WorkspaceSnapshotLimits())
        root.resolve("src/new").writeText("new")
        val after = capture(request, WorkspaceSnapshotLimits())
        assertEquals(AgentFileChangeKind.CREATED, before.diff(after, request, budget(WorkspaceSnapshotLimits())).single().kind)
    }

    @Test
    fun `directory entries consume budget without any regular files`() {
        val root = workspace()
        repeat(4) { Files.createDirectory(root.resolve("src/d$it")) }
        val failure = assertFailsWith<WorkspaceSnapshotLimitExceeded> {
            capture(request(root), WorkspaceSnapshotLimits(entries = 3))
        }
        assertEquals("entry-count", failure.dimension)
    }

    @Test
    fun `unique file inventory fails before producing a partial snapshot`() {
        val root = workspace()
        repeat(3) { root.resolve("src/f$it").writeText("x") }
        val failure = assertFailsWith<WorkspaceSnapshotLimitExceeded> {
            capture(request(root), WorkspaceSnapshotLimits(files = 2))
        }
        assertEquals("file-count", failure.dimension)
    }

    @Test
    fun `oversized individual file is refused`() {
        val root = workspace()
        root.resolve("src/file").writeText("123456")
        val failure = assertFailsWith<WorkspaceSnapshotLimitExceeded> {
            capture(request(root), WorkspaceSnapshotLimits(fileBytes = 5))
        }
        assertEquals("file-bytes", failure.dimension)
    }

    @Test
    fun `aggregate file bytes are bounded independently of each file`() {
        val root = workspace()
        root.resolve("src/one").writeText("1234")
        root.resolve("src/two").writeText("5678")
        val failure = assertFailsWith<WorkspaceSnapshotLimitExceeded> {
            capture(request(root), WorkspaceSnapshotLimits(fileBytes = 4, totalBytes = 7))
        }
        assertEquals("total-bytes", failure.dimension)
    }

    @Test
    fun `overlapping rules count and hash each file once while preserving exact diff`() {
        val root = workspace()
        val source = root.resolve("src/file")
        source.writeText("old")
        val request = request(root, overlap = true)
        val limits = WorkspaceSnapshotLimits(files = 1, totalBytes = 3)
        val before = capture(request, limits)
        source.writeText("new")
        val after = capture(request, limits)
        val changes = before.diff(after, request, budget(limits))
        assertEquals(1, changes.size)
        assertEquals(AgentFileChangeKind.MODIFIED, changes.single().kind)
        assertTrue(changes.single().beforeSha256 != changes.single().afterSha256)
    }

    @Test
    fun `stream accounting rejects growth beyond declared file or remaining aggregate bytes`() {
        val fileBudget = budget(WorkspaceSnapshotLimits(fileBytes = 4))
        fileBudget.declaredSize(3)
        fileBudget.readBytes(3, 3)
        assertEquals("file-bytes", assertFailsWith<WorkspaceSnapshotLimitExceeded> {
            fileBudget.readBytes(2, 5)
        }.dimension)
        val totalBudget = budget(WorkspaceSnapshotLimits(totalBytes = 4))
        totalBudget.readBytes(3, 3)
        assertEquals("total-bytes", assertFailsWith<WorkspaceSnapshotLimitExceeded> {
            totalBudget.readBytes(2, 2)
        }.dimension)
    }

    private fun workspace(): Path = createTempDirectory("ws-").also {
        Files.createDirectory(it.resolve("src"))
    }

    private fun request(root: Path, overlap: Boolean = false): AgentExecutionRequest {
        val operations = setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)
        val rules = mutableListOf(AgentPathRule(AgentWorkspacePath("project", "src"), operations, recursive = true))
        if (overlap) rules.add(AgentPathRule(AgentWorkspacePath("project", "src/file"), operations))
        return AgentExecutionRequest("snapshot fixture", listOf(AgentWorkspaceRoot("project", root)),
            emptyList(), AgentAccessPolicy(rules))
    }

    private fun budget(limits: WorkspaceSnapshotLimits) = WorkspaceSnapshotBudget(
        AgentCancellation.NONE, MonotonicDeadline(Duration.ofSeconds(10)), true, limits)

    private fun capture(request: AgentExecutionRequest, limits: WorkspaceSnapshotLimits) =
        WorkspaceSnapshot.capture(request, budget(limits))
}
