package decompengine.web

import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import kotlinx.serialization.json.*
import kotlin.test.*

/** Already captured commitment DTOs only: no directory, source body, store or listener is opened. */
class WebRevisionDirectoriesTest {
    private val jobId = "a".repeat(32)
    private val runId = "run_1"
    private val revisionId = "revision_1"
    private fun makeSnapshot(paths: List<String>, job: String = jobId, run: String = runId, revision: String = revisionId,
        descriptor: String = "c".repeat(64)): WebRevisionSourceSnapshot = WebRevisionSourceSnapshot(
        WebRevisionSourceReference(job, run, revision, "a".repeat(64), "version_1"), "b".repeat(64), descriptor,
        paths.map { path -> WebRevisionSourceFile(GeneratedFileEvidence(path, "d".repeat(64), "fixture",
            roles = setOf(ProjectFileRole.BUILD_INPUT, ProjectFileRole.VIEWABLE), contentKind = ProjectContentKind.UTF8_TEXT), 8) })
    private fun items(page: JsonObject) = page.getValue("items").jsonArray.map { it.jsonObject }
    private fun id(item: JsonObject) = item.getValue("directoryId").jsonPrimitive.content
    private fun cursor(page: JsonObject) = page.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.contentOrNull

    @Test fun `immediate children retain directory grouping breadcrumbs and the flat listing file identities`() {
        val snapshot = makeSnapshot(listOf("Makefile", "src/a.c", "src/nested/b.c", "src/nested/c.c", "src/nested/😀.c", "src/nested/.c"))
        val pages = WebRevisionDirectoryPages { _, _, _ -> snapshot }
        val root = pages.page("owner", jobId, runId, revisionId, "root", null)
        assertEquals(listOf("src", "Makefile"), items(root).map { it.getValue("displayName").jsonPrimitive.content })
        assertEquals(6, root.getValue("sourceFileCount").jsonPrimitive.int)
        assertEquals(JsonNull, root.getValue("parentDirectoryId"))
        assertEquals("not-recorded", root.getValue("emptyDirectories").jsonPrimitive.content)
        val srcId = id(items(root).first())
        assertFalse(srcId.contains('/')); assertNotEquals("src", srcId)
        val src = pages.page("owner", jobId, runId, revisionId, srcId, null)
        assertEquals(listOf("nested", "a.c"), items(src).map { it.getValue("displayName").jsonPrimitive.content })
        assertEquals("root", src.getValue("parentDirectoryId").jsonPrimitive.content)
        val nestedId = id(items(src).first())
        val nested = pages.page("owner", jobId, runId, revisionId, nestedId, null)
        assertEquals(srcId, nested.getValue("parentDirectoryId").jsonPrimitive.content)
        assertEquals(listOf("b.c", "c.c", "😀.c", ".c"), items(nested).map { it.getValue("displayName").jsonPrimitive.content })
        assertEquals(listOf("root", srcId, nestedId), nested.getValue("breadcrumbs").jsonArray.map { id(it.jsonObject) })
        val flat = WebRevisionSourcePages { _, _, _ -> snapshot }.page("owner", jobId, runId, revisionId, null)
        val flatIds = items(flat).associate { it.getValue("displayName").jsonPrimitive.content to it.getValue("fileId") }
        for (file in items(nested)) assertEquals(flatIds["src/nested/${file.getValue("displayName").jsonPrimitive.content}"], file.getValue("fileId"))
    }

    @Test fun `25000 wide child directories are paged exactly once without recursive source capture`() {
        val snapshot = makeSnapshot((0 until 25_000).map { "d_${it.toString().padStart(5, '0')}/file.c" })
        var captures = 0
        val pages = WebRevisionDirectoryPages { _, _, _ -> captures++; snapshot }
        val seen = mutableListOf<String>(); val ids = mutableSetOf<String>(); var next: String? = null
        do {
            val page = pages.page("owner", jobId, runId, revisionId, "root", "limit=200" + (next?.let { "&cursor=$it" } ?: ""))
            assertEquals(25_000, page.getValue("totalChildren").jsonPrimitive.int)
            assertTrue(items(page).size <= 200)
            for (entry in items(page)) {
                seen += entry.getValue("displayName").jsonPrimitive.content
                assertTrue(ids.add(id(entry))); assertEquals(1, entry.getValue("sourceFileCount").jsonPrimitive.int)
            }
            next = cursor(page)
        } while (next != null)
        assertEquals((0 until 25_000).map { "d_${it.toString().padStart(5, '0')}" }, seen)
        assertEquals(125, captures) // One metadata callback per requested page; no child expansion cascade.
    }

    @Test fun `deep Unicode and space labels retain bounded breadcrumbs and a complete parent chain`() {
        val segments = (0 until 60).map { "é space $it" }
        val snapshot = makeSnapshot(listOf(segments.joinToString("/") + "/leaf.c"))
        val pages = WebRevisionDirectoryPages { _, _, _ -> snapshot }
        var selected = "root"
        for (depth in 1..60) {
            val parent = pages.page("owner", jobId, runId, revisionId, selected, null)
            val child = items(parent).single(); selected = id(child)
            val page = pages.page("owner", jobId, runId, revisionId, selected, null)
            assertEquals(depth, page.getValue("depth").jsonPrimitive.int)
            assertEquals(segments[depth - 1], page.getValue("displayName").jsonPrimitive.content)
            assertEquals(1 + minOf(depth, 31), page.getValue("breadcrumbs").jsonArray.size)
            assertEquals(maxOf(0, depth - 31), page.getValue("omittedAncestors").jsonPrimitive.int)
        }
        val deepest = pages.page("owner", jobId, runId, revisionId, selected, null)
        assertEquals("leaf.c", items(deepest).single().getValue("displayName").jsonPrimitive.content)
        for (depth in 60 downTo 1) {
            val page = pages.page("owner", jobId, runId, revisionId, selected, null)
            assertEquals(depth, page.getValue("depth").jsonPrimitive.int)
            selected = page.getValue("parentDirectoryId").jsonPrimitive.content
        }
        assertEquals("root", selected)
    }

    @Test fun `continuations bind session job run revision directory limit and captured metadata`() {
        val paths = (0 until 60).map { "one/d_$it/file.c" } + (0 until 60).map { "two/d_$it/file.c" }
        var snapshot = makeSnapshot(paths); var captures = 0
        val pages = WebRevisionDirectoryPages { _, _, _ -> captures++; snapshot }
        val first = pages.page("owner", jobId, runId, revisionId, "root", "limit=1")
        val next = checkNotNull(cursor(first)); val child = id(items(first).single()); val before = captures
        for ((owner, job, run, revision, directory) in listOf(
            listOf("other", jobId, runId, revisionId, "root"), listOf("owner", "b".repeat(32), runId, revisionId, "root"),
            listOf("owner", jobId, "run_2", revisionId, "root"), listOf("owner", jobId, runId, "revision_2", "root"),
            listOf("owner", jobId, runId, revisionId, child),
        )) assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> {
            pages.page(owner, job, run, revision, directory, "limit=1&cursor=$next")
        }.code)
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> {
            pages.page("owner", jobId, runId, revisionId, "root", "limit=2&cursor=$next")
        }.code)
        assertEquals(before, captures)
        snapshot = makeSnapshot(paths, descriptor = "e".repeat(64))
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> {
            pages.page("owner", jobId, runId, revisionId, "root", "limit=1&cursor=$next")
        }.code)
    }

    @Test fun `opaque prefix selectors reject alternate representatives foreign bindings and sibling prefixes`() {
        val paths = listOf("foo/a.c", "foo/b.c", "foo/nested/x.c", "foobar/z.c")
        val snapshot = makeSnapshot(paths)
        val pages = WebRevisionDirectoryPages { job, run, revision -> makeSnapshot(paths, job, run, revision) }
        val root = pages.page("owner", jobId, runId, revisionId, "root", null)
        val foo = id(items(root).first { it.getValue("displayName").jsonPrimitive.content == "foo" })
        assertEquals(3, pages.page("owner", jobId, runId, revisionId, foo, null).getValue("sourceFileCount").jsonPrimitive.int)
        val forgedHash = revisionSourceDigest(listOf("revision-source-directory-v1", jobId, runId, revisionId,
            snapshot.reference.sourceSha256, "foo", "1", "1").joinToString("\u0000"))
        for (selector in listOf("dir_1_1_$forgedHash", "../foo", "/foo", "%2Ffoo", "dir_00_1_${"a".repeat(64)}", "dir_25000_1_${"a".repeat(64)}")) {
            assertEquals("SOURCE_DIRECTORY_NOT_FOUND", assertFailsWith<WebAccessDenied> {
                pages.page("owner", jobId, runId, revisionId, selector, null)
            }.code)
        }
        assertEquals("SOURCE_DIRECTORY_NOT_FOUND", assertFailsWith<WebAccessDenied> {
            pages.page("owner", "b".repeat(32), runId, revisionId, foo, null)
        }.code)
        val renewed = WebRevisionDirectoryPages { _, _, _ -> snapshot }
            .page("new-session", jobId, runId, revisionId, "root", null)
        assertEquals(items(root), items(renewed))
    }

    @Test fun `file directory conflicts fail closed and unrecorded empty directories are never invented`() {
        val conflict = WebRevisionDirectoryPages { _, _, _ -> makeSnapshot(listOf("a", "a/b.c")) }
        assertEquals("SOURCE_REVISION_CHANGED", assertFailsWith<WebAccessDenied> {
            conflict.page("owner", jobId, runId, revisionId, "root", null)
        }.code)
        val hash = revisionSourceDigest(listOf("revision-source-directory-v1", jobId, runId, revisionId,
            "a".repeat(64), "a", "1", "1").joinToString("\u0000"))
        assertEquals("SOURCE_REVISION_CHANGED", assertFailsWith<WebAccessDenied> {
            conflict.page("owner", jobId, runId, revisionId, "dir_1_1_$hash", null)
        }.code)
        val pages = WebRevisionDirectoryPages { _, _, _ -> makeSnapshot(listOf("a/file.c")) }
        val root = pages.page("owner", jobId, runId, revisionId, "root", null)
        assertEquals("not-recorded", root.getValue("emptyDirectories").jsonPrimitive.content)
        assertEquals("SOURCE_DIRECTORY_NOT_FOUND", assertFailsWith<WebAccessDenied> {
            pages.page("owner", jobId, runId, revisionId, "dir_0_2_${"a".repeat(64)}", null)
        }.code)
    }

    @Test fun `maximum labels stay within the response ceiling and foreign captures cannot be serialized`() {
        val snapshot = makeSnapshot((0 until 200).map { "\"".repeat(240) + it.toString().padStart(5, '0') })
        val pages = WebRevisionDirectoryPages { _, _, _ -> snapshot }
        val page = pages.page("owner", jobId, runId, revisionId, "root", "limit=200")
        assertEquals(200, items(page).size); assertTrue(page.toString().toByteArray().size < 1_048_000)
        assertEquals(JsonNull, page.getValue("page").jsonObject.getValue("nextCursor"))
        assertFailsWith<IllegalStateException> { pages.page("owner", "b".repeat(32), runId, revisionId, "root", null) }
    }
}
