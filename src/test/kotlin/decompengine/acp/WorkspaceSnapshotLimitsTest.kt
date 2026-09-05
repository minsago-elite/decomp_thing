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
    fun `unsupported extended attributes are rejected without reading or exposing their values`() {
        verifyExtendedAttributeRejection("private metadata value".toByteArray())
    }

    @Test
    fun `empty extended attributes are still unsupported metadata`() {
        verifyExtendedAttributeRejection(byteArrayOf())
    }

    private fun verifyExtendedAttributeRejection(value: ByteArray) {
        val root = workspace()
        val file = root.resolve("src/data")
        file.writeText("unchanged")
        val attributes = Files.getFileAttributeView(file, java.nio.file.attribute.UserDefinedFileAttributeView::class.java)
        attributes.write("private-name", java.nio.ByteBuffer.wrap(value))
        val failure = assertFailsWith<WorkspaceSnapshotInvalidEntry> {
            capture(request(root), WorkspaceSnapshotLimits())
        }
        assertEquals("unsupported-extended-attributes", failure.reason)
        assertEquals(null, failure.message)
        assertEquals("unchanged", Files.readString(file))
        val retained = java.nio.ByteBuffer.allocate(attributes.size("private-name"))
        attributes.read("private-name", retained)
        kotlin.test.assertContentEquals(value, retained.array())
    }

    @Test
    fun `unchanged bytes cannot hide an unauthorized permission change`() {
        verifyMetadataRejection(changeContent = false)
    }

    @Test
    fun `authorized content write does not authorize a permission change`() {
        verifyMetadataRejection(changeContent = true)
    }

    private fun verifyMetadataRejection(changeContent: Boolean) {
        val root = workspace()
        val file = root.resolve("src/data")
        file.writeText("before")
        val request = request(root)
        val before = capture(request, WorkspaceSnapshotLimits())
        if (changeContent) file.writeText("after")
        val permissions = Files.getPosixFilePermissions(file).toMutableSet()
        val execute = java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE
        if (!permissions.add(execute)) permissions.remove(execute)
        Files.setPosixFilePermissions(file, permissions)
        val after = capture(request, WorkspaceSnapshotLimits())
        val failure = assertFailsWith<AgentExecutionException> {
            before.diff(after, request, budget(WorkspaceSnapshotLimits()))
        }.failure
        assertEquals(AgentFailureKind.WORKSPACE_VIOLATION, failure.kind)
        assertEquals("file-metadata-changed", failure.details["reason"])
    }

    @Test
    fun `atomic same-content replacement preserving metadata remains unchanged`() {
        val root = workspace()
        val file = root.resolve("src/data")
        file.writeText("same bytes")
        val request = request(root)
        val before = capture(request, WorkspaceSnapshotLimits())
        val replacement = root.resolve("replacement")
        replacement.writeText("same bytes")
        Files.setPosixFilePermissions(replacement, Files.getPosixFilePermissions(file))
        Files.move(replacement, file, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
            java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        val after = capture(request, WorkspaceSnapshotLimits())
        assertTrue(before.diff(after, request, budget(WorkspaceSnapshotLimits())).isEmpty())
    }

    @Test
    fun `non-default filesystem roots are rejected before native path resolution`() {
        val archive = createTempDirectory("snapshot-provider-").resolve("workspace.zip")
        java.nio.file.FileSystems.newFileSystem(archive, mapOf("create" to "true")).use { filesystem ->
            val root = Files.createDirectory(filesystem.getPath("/workspace"))
            assertEquals("unsupported-filesystem", assertFailsWith<WorkspaceSnapshotInvalidEntry> {
                capture(request(root), WorkspaceSnapshotLimits())
            }.reason)
        }
    }

    @Test
    fun `nested descriptor discovery preserves relative change identity`() {
        val root = workspace()
        val nested = Files.createDirectories(root.resolve("src/one/two"))
        val file = nested.resolve("data")
        file.writeText("before")
        val request = request(root)
        val before = capture(request, WorkspaceSnapshotLimits())
        file.writeText("after")
        val after = capture(request, WorkspaceSnapshotLimits())
        val change = before.diff(after, request, budget(WorkspaceSnapshotLimits())).single()
        assertEquals(AgentWorkspacePath("project", "src/one/two/data"), change.path)
        assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
    }

    @Test
    fun `recursive depth is bounded before retaining an excessive handle chain`() {
        val root = workspace()
        var directory = root.resolve("src")
        repeat(64) { directory = Files.createDirectory(directory.resolve("d")) }
        assertEquals("directory-depth", assertFailsWith<WorkspaceSnapshotLimitExceeded> {
            capture(request(root), WorkspaceSnapshotLimits())
        }.dimension)
    }

    @Test
    fun `root handle count is bounded even when authorized targets are absent`() {
        val base = createTempDirectory("snapshot-roots-")
        val roots = (0..64).map { AgentWorkspaceRoot("r$it", Files.createDirectory(base.resolve("r$it"))) }
        val rules = roots.map { AgentPathRule(AgentWorkspacePath(it.id, "missing"), setOf(AgentOperation.READ_FILE)) }
        val request = AgentExecutionRequest("root budget fixture", roots, emptyList(), AgentAccessPolicy(rules))
        assertEquals("root-count", assertFailsWith<WorkspaceSnapshotLimitExceeded> {
            capture(request, WorkspaceSnapshotLimits())
        }.dimension)
    }

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
