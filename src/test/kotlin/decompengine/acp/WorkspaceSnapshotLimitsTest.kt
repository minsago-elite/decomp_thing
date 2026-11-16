package decompengine.acp

import decompengine.agent.*
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class WorkspaceSnapshotLimitsTest {
    @Test
    fun `snapshot hashing preserves valid Linux filenames for exact and recursive rules`() {
        for (recursive in listOf(false, true)) {
            val root = workspace()
            val names = listOf("back\\slash", "line\nbreak", "tab\tname", "control\u0001name", "delete\u007fname")
            names.forEach { root.resolve("src/$it").writeText("old") }
            val operations = setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)
            val rules = if (recursive) listOf(AgentPathRule(AgentWorkspacePath("project", "src"), operations, recursive = true))
                else names.map { AgentPathRule(AgentWorkspacePath("project", "src/$it"), operations) }
            val request = AgentExecutionRequest("snapshot fixture", listOf(AgentWorkspaceRoot("project", root)),
                emptyList(), AgentAccessPolicy(rules))
            val limits = WorkspaceSnapshotLimits()
            val before = capture(request, limits)
            names.forEach { root.resolve("src/$it").writeText("new") }
            val changes = before.diff(capture(request, limits), request, budget(limits))
            assertEquals(names.size, changes.size)
            assertTrue(changes.all { it.kind == AgentFileChangeKind.MODIFIED && it.beforeSha256 != it.afterSha256 })
        }
    }

    @Test
    fun `role-bound snapshot rejects invalid UTF-8 and bytes beyond its grant limit`() {
        val root = workspace()
        val file = root.resolve("src/data")
        file.writeText("before")
        val path = AgentWorkspacePath("project", "src/data")
        val operations = setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)
        val grant = AgentMutationGrant(
            path, setOf(AgentOperation.WRITE_FILE), "test-owner", "a".repeat(64), "source",
            setOf("editable"), AgentMutationContentKind.UTF8_TEXT, 8,
        )
        val authority = AgentMutationAuthority("declared-role-test-v1", "test-owner", "a".repeat(64), listOf(grant))
        val request = AgentExecutionRequest(
            "role-bound snapshot", listOf(AgentWorkspaceRoot("project", root)),
            accessPolicy = AgentAccessPolicy(
                listOf(AgentPathRule(path, operations)), mutationAuthority = authority,
            ),
        )
        val before = capture(request, WorkspaceSnapshotLimits())
        file.writeBytes(byteArrayOf(0xc3.toByte(), 0x28))
        assertFailsWith<AgentExecutionException> {
            before.diff(capture(request, WorkspaceSnapshotLimits()), request, budget(WorkspaceSnapshotLimits()))
        }
        file.writeBytes(ByteArray(9) { 'x'.code.toByte() })
        assertFailsWith<AgentExecutionException> {
            before.diff(capture(request, WorkspaceSnapshotLimits()), request, budget(WorkspaceSnapshotLimits()))
        }
    }

    @Test
    fun `role-bound snapshot authorizes deletion independently from modification`() {
        for ((operations, shouldSucceed) in listOf(
            setOf(AgentOperation.DELETE_FILE) to true,
            setOf(AgentOperation.WRITE_FILE) to false,
        )) {
            val root = workspace()
            val file = root.resolve("src/data")
            val original = "payload".toByteArray()
            Files.write(file, original)
            val path = AgentWorkspacePath("project", "src/data")
            val request = roleBoundRequest(root, listOf(mutationGrant(path, operations)))
            val before = capture(request, WorkspaceSnapshotLimits())
            Files.delete(file)
            val after = capture(request, WorkspaceSnapshotLimits())

            if (shouldSucceed) {
                val change = before.diff(after, request, budget(WorkspaceSnapshotLimits())).single()
                assertEquals(AgentFileChangeKind.DELETED, change.kind)
                assertEquals(path, change.path)
                assertEquals(java.security.MessageDigest.getInstance("SHA-256").digest(original)
                    .joinToString("") { "%02x".format(it) }, change.beforeSha256)
                assertEquals(null, change.afterSha256)
                assertEquals(null, change.sizeBytes)
            } else {
                assertMutationRefused(before, after, request, path.relativePath)
            }
        }
    }

    @Test
    fun `role-bound snapshot authorizes move source deletion and destination creation independently`() {
        val cases = listOf(
            // Source sorts first: its DELETE is allowed, then the destination CREATE must be refused.
            MoveAuthorizationCase(
                sourceOperations = setOf(AgentOperation.DELETE_FILE),
                destinationOperations = setOf(AgentOperation.WRITE_FILE),
                refusedPath = "src/z-target",
            ),
            // Source sorts first and must be refused even though destination CREATE is allowed.
            MoveAuthorizationCase(
                sourceOperations = setOf(AgentOperation.WRITE_FILE),
                destinationOperations = setOf(AgentOperation.CREATE_FILE),
                refusedPath = "src/a-source",
            ),
            MoveAuthorizationCase(
                sourceOperations = setOf(AgentOperation.DELETE_FILE),
                destinationOperations = setOf(AgentOperation.CREATE_FILE),
                refusedPath = null,
            ),
        )

        for (case in cases) {
            val root = workspace()
            val sourcePath = AgentWorkspacePath("project", "src/a-source")
            val destinationPath = AgentWorkspacePath("project", "src/z-target")
            Files.write(root.resolve(sourcePath.relativePath), "payload".toByteArray())
            val request = roleBoundRequest(root, listOf(
                mutationGrant(sourcePath, case.sourceOperations),
                mutationGrant(destinationPath, case.destinationOperations),
            ))
            val before = capture(request, WorkspaceSnapshotLimits())
            Files.move(root.resolve(sourcePath.relativePath), root.resolve(destinationPath.relativePath))
            val after = capture(request, WorkspaceSnapshotLimits())

            if (case.refusedPath != null) {
                assertMutationRefused(before, after, request, case.refusedPath)
            } else {
                val changes = before.diff(after, request, budget(WorkspaceSnapshotLimits())).associateBy { it.path }
                assertEquals(setOf(sourcePath, destinationPath), changes.keys)
                assertEquals(AgentFileChangeKind.DELETED, changes.getValue(sourcePath).kind)
                assertEquals(AgentFileChangeKind.CREATED, changes.getValue(destinationPath).kind)
                assertEquals(changes.getValue(sourcePath).beforeSha256, changes.getValue(destinationPath).afterSha256)
                assertEquals(7L, changes.getValue(destinationPath).sizeBytes)
            }
        }

        // Replacing an existing destination is a WRITE, not a CREATE. Keep the
        // source grant independent so the destination operation cannot mask a
        // missing DELETE grant on the source.
        val replacementCases = listOf(
            MoveAuthorizationCase(
                sourceOperations = setOf(AgentOperation.DELETE_FILE),
                destinationOperations = setOf(AgentOperation.CREATE_FILE),
                refusedPath = "src/z-target",
            ),
            MoveAuthorizationCase(
                sourceOperations = setOf(AgentOperation.WRITE_FILE),
                destinationOperations = setOf(AgentOperation.WRITE_FILE),
                refusedPath = "src/a-source",
            ),
            MoveAuthorizationCase(
                sourceOperations = setOf(AgentOperation.DELETE_FILE),
                destinationOperations = setOf(AgentOperation.WRITE_FILE),
                refusedPath = null,
            ),
        )

        for (case in replacementCases) {
            val root = workspace()
            val sourcePath = AgentWorkspacePath("project", "src/a-source")
            val destinationPath = AgentWorkspacePath("project", "src/z-target")
            val sourceBytes = "payload".toByteArray()
            val destinationBytes = "old-target".toByteArray()
            Files.write(root.resolve(sourcePath.relativePath), sourceBytes)
            Files.write(root.resolve(destinationPath.relativePath), destinationBytes)
            val request = roleBoundRequest(root, listOf(
                mutationGrant(sourcePath, case.sourceOperations),
                mutationGrant(destinationPath, case.destinationOperations),
            ))
            val before = capture(request, WorkspaceSnapshotLimits())
            Files.move(
                root.resolve(sourcePath.relativePath), root.resolve(destinationPath.relativePath),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
            val after = capture(request, WorkspaceSnapshotLimits())

            if (case.refusedPath != null) {
                assertMutationRefused(before, after, request, case.refusedPath)
            } else {
                val changes = before.diff(after, request, budget(WorkspaceSnapshotLimits())).associateBy { it.path }
                assertEquals(setOf(sourcePath, destinationPath), changes.keys)
                val sourceChange = changes.getValue(sourcePath)
                assertEquals(AgentFileChangeKind.DELETED, sourceChange.kind)
                assertEquals(sourcePath, sourceChange.path)
                assertEquals(sha256(sourceBytes), sourceChange.beforeSha256)
                assertEquals(null, sourceChange.afterSha256)
                assertEquals(null, sourceChange.sizeBytes)

                val destinationChange = changes.getValue(destinationPath)
                assertEquals(AgentFileChangeKind.MODIFIED, destinationChange.kind)
                assertEquals(destinationPath, destinationChange.path)
                assertEquals(sha256(destinationBytes), destinationChange.beforeSha256)
                assertEquals(sha256(sourceBytes), destinationChange.afterSha256)
                assertEquals(sourceBytes.size.toLong(), destinationChange.sizeBytes)
            }
        }
    }

    @Test
    fun `streaming UTF-8 validation accepts multibyte sequences split across read chunks`() {
        val sequences = listOf(
            byteArrayOf(0xc2.toByte(), 0xa2.toByte()),
            byteArrayOf(0xe2.toByte(), 0x82.toByte(), 0xac.toByte()),
            byteArrayOf(0xf0.toByte(), 0x9f.toByte(), 0x98.toByte(), 0x80.toByte()),
        )
        for (sequence in sequences) {
            for (split in 1 until sequence.size) {
                val root = workspace()
                val file = root.resolve("src/data")
                file.writeText("before")
                val path = AgentWorkspacePath("project", "src/data")
                val request = roleBoundRequest(root, listOf(mutationGrant(path, setOf(AgentOperation.WRITE_FILE))))
                val before = capture(request, WorkspaceSnapshotLimits())
                val prefix = ByteArray(65_536 - split) { 'x'.code.toByte() }
                Files.write(file, prefix + sequence)
                val change = before.diff(capture(request, WorkspaceSnapshotLimits()), request,
                    budget(WorkspaceSnapshotLimits())).single()
                assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
                assertEquals(path, change.path)
            }
        }
    }

    @Test
    fun `streaming UTF-8 validation rejects truncated overlong surrogate and out of range encodings`() {
        val invalidSequences = listOf(
            byteArrayOf(0x80.toByte()),
            byteArrayOf(0xc0.toByte(), 0xaf.toByte()),
            byteArrayOf(0xe0.toByte(), 0x80.toByte(), 0xaf.toByte()),
            byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()),
            byteArrayOf(0xf4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()),
            byteArrayOf(0xc2.toByte()),
            byteArrayOf(0xe2.toByte(), 0x82.toByte()),
            byteArrayOf(0xf0.toByte(), 0x9f.toByte(), 0x98.toByte()),
        )
        for (invalid in invalidSequences) {
            val root = workspace()
            val file = root.resolve("src/data")
            file.writeText("before")
            val path = AgentWorkspacePath("project", "src/data")
            val request = roleBoundRequest(root, listOf(mutationGrant(path, setOf(AgentOperation.WRITE_FILE))))
            val before = capture(request, WorkspaceSnapshotLimits())
            Files.write(file, ByteArray(65_535) { 'x'.code.toByte() } + invalid)
            val after = capture(request, WorkspaceSnapshotLimits())
            assertMutationRefused(before, after, request, path.relativePath)
        }
    }

    @Test
    fun `binary mutation grants continue to accept non UTF-8 content`() {
        val root = workspace()
        val file = root.resolve("src/data")
        file.writeText("before")
        val path = AgentWorkspacePath("project", "src/data")
        val grant = mutationGrant(path, setOf(AgentOperation.WRITE_FILE), AgentMutationContentKind.BINARY)
        val request = roleBoundRequest(root, listOf(grant))
        val before = capture(request, WorkspaceSnapshotLimits())
        Files.write(file, byteArrayOf(0xc0.toByte(), 0xaf.toByte()))
        val change = before.diff(capture(request, WorkspaceSnapshotLimits()), request,
            budget(WorkspaceSnapshotLimits())).single()
        assertEquals(AgentFileChangeKind.MODIFIED, change.kind)
    }

    private data class MoveAuthorizationCase(
        val sourceOperations: Set<AgentOperation>,
        val destinationOperations: Set<AgentOperation>,
        val refusedPath: String?,
    )

    private fun mutationGrant(
        path: AgentWorkspacePath,
        operations: Set<AgentOperation>,
        contentKind: AgentMutationContentKind = AgentMutationContentKind.UTF8_TEXT,
    ) = AgentMutationGrant(
        path, operations, "test-owner", "a".repeat(64), path.relativePath.substringAfterLast('/'),
        setOf("editable"), contentKind, 70_000,
    )

    private fun sha256(bytes: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    private fun roleBoundRequest(root: Path, grants: List<AgentMutationGrant>): AgentExecutionRequest {
        val allowed = setOf(
            AgentOperation.READ_FILE,
            AgentOperation.WRITE_FILE,
            AgentOperation.CREATE_FILE,
            AgentOperation.DELETE_FILE,
        )
        val authority = AgentMutationAuthority("declared-role-test-v1", "test-owner", "a".repeat(64), grants)
        return AgentExecutionRequest(
            "role-bound snapshot", listOf(AgentWorkspaceRoot("project", root)),
            accessPolicy = AgentAccessPolicy(grants.map { AgentPathRule(it.path, allowed) }, mutationAuthority = authority),
        )
    }

    private fun assertMutationRefused(
        before: WorkspaceSnapshot,
        after: WorkspaceSnapshot,
        request: AgentExecutionRequest,
        relativePath: String,
    ) {
        val failure = assertFailsWith<AgentExecutionException> {
            before.diff(after, request, budget(WorkspaceSnapshotLimits()))
        }.failure
        assertEquals(AgentFailureKind.WORKSPACE_VIOLATION, failure.kind)
        assertEquals("final-workspace-snapshot", failure.details["phase"])
        assertEquals("project", failure.details["rootId"])
        assertEquals(relativePath, failure.details["relativePath"])
    }

    @Test
    fun `snapshot hash paths still reject absolute traversal empty and NUL segments`() {
        val root = workspace()
        for (path in listOf("", "/src/data", "../data", "src/../data", "src/./data", "src//data", "src/data/", "src/\u0000data")) {
            assertFailsWith<IllegalArgumentException> {
                decompengine.repair.hashStableRegularFile(root, path,
                    declaredSize = { error("invalid path must not reach file accounting") },
                    readBytes = { _, _ -> error("invalid path must not read bytes") }, cancellationCheck = {})
            }
        }
    }

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
    fun `stable hashing allows ordinary reads by default and preserves atime when explicitly required`() {
        val root = workspace()
        val file = root.resolve("src/data")
        Files.writeString(file, "stable readable content")
        val oldAtime = java.nio.file.attribute.FileTime.from(java.time.Instant.parse("2000-01-01T00:00:00Z"))
        Files.setAttribute(file, "basic:lastAccessTime", oldAtime)
        Files.setLastModifiedTime(file, java.nio.file.attribute.FileTime.from(java.time.Instant.parse("2020-01-01T00:00:00Z")))
        fun atime() = Files.getAttribute(file, "basic:lastAccessTime") as java.nio.file.attribute.FileTime

        decompengine.repair.hashStableRegularFile(root, "src/data", {}, { _, _ -> }, {})
        assertTrue(atime().compareTo(oldAtime) > 0,
            "default hashing must not require O_NOATIME ownership permission")

        Files.setAttribute(file, "basic:lastAccessTime", oldAtime)
        decompengine.repair.hashStableRegularFile(root, "src/data", {}, { _, _ -> }, {},
            requireAtimeNeutralOpen = true)
        assertEquals(oldAtime, atime(),
            "the opt-in metadata-neutral path must preserve atime when available")
    }

    @Test
    fun `stable hashing rejects same-size content mutation even when mtime is restored`() {
        val root = workspace()
        val file = root.resolve("src/data")
        val original = ByteArray(128 * 1024) { 'A'.code.toByte() }
        val replacement = ByteArray(original.size) { 'B'.code.toByte() }
        Files.write(file, original)
        val originalMtime = Files.getLastModifiedTime(file)
        var changed = false

        val failure = assertFailsWith<IllegalArgumentException> {
            decompengine.repair.hashStableRegularFile(root, "src/data", {}, { _, total ->
                if (!changed && total >= 64 * 1024) {
                    // The first chunk has already been read. Replace the entire same-sized file,
                    // then put mtime back; the stream would otherwise combine old and new bytes.
                    Files.write(file, replacement)
                    Files.setLastModifiedTime(file, originalMtime)
                    changed = true
                }
            }, {})
        }
        assertTrue(changed)
        assertTrue(failure.message.orEmpty().contains("file changed during reading"))
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
