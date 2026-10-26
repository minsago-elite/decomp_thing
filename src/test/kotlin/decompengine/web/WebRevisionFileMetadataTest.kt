package decompengine.web

import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import kotlinx.serialization.json.*
import kotlin.test.*

/** Captured declarations and path classification only. No store, body, listener or browser is opened. */
class WebRevisionFileMetadataTest {
    private val jobId = "a".repeat(32)
    private val runId = "run_1"
    private val revisionId = "revision_1"
    private fun makeSnapshot(paths: List<String>, size: Long = 8, roles: Set<ProjectFileRole> = setOf(ProjectFileRole.BUILD_INPUT)) =
        WebRevisionSourceSnapshot(WebRevisionSourceReference(jobId, runId, revisionId, "a".repeat(64), "version_1"),
            "b".repeat(64), "c".repeat(64), paths.map { path -> WebRevisionSourceFile(GeneratedFileEvidence(
                path, "d".repeat(64), "fixture", roles = roles, contentKind = ProjectContentKind.BINARY), size) })
    private fun fileId(snapshot: WebRevisionSourceSnapshot, index: Int) = revisionSourceFileId(snapshot.reference, index, snapshot.files[index].evidence.path)

    @Test fun `recorded metadata retains exact declarations without requiring body permissions`() {
        val snapshot = makeSnapshot(listOf("Makefile"), Long.MAX_VALUE)
        var captures = 0
        val metadata = WebRevisionFileMetadata { _, _, _ -> captures++; snapshot }
            .read(jobId, runId, revisionId, fileId(snapshot, 0))
        assertEquals(1, captures)
        assertEquals("source-input-commitments", metadata.getValue("authority").jsonPrimitive.content)
        assertEquals("not-performed", metadata.getValue("contentVerification").jsonPrimitive.content)
        assertEquals("root", metadata.getValue("parentDirectoryId").jsonPrimitive.content)
        assertEquals(revisionId, metadata.getValue("binding").jsonObject.getValue("revisionId").jsonPrimitive.content)
        val item = metadata.getValue("item").jsonObject
        assertEquals(Long.MAX_VALUE.toString(), item.getValue("sizeBytes").jsonPrimitive.content)
        assertFalse(item.getValue("declaredViewable").jsonPrimitive.boolean)
        assertFalse(item.getValue("declaredArchivable").jsonPrimitive.boolean)
        assertFalse(item.getValue("declaredUtf8Text").jsonPrimitive.boolean)
        assertFalse(metadata.containsKey("text")); assertFalse(metadata.containsKey("acceptance"))
    }

    @Test fun `nullable manifest implementation claims remain declarations rather than verification`() {
        for ((claim, expected) in listOf(true to "accepted", false to "unaccepted", null to "not-classified")) {
            val snapshot = WebRevisionSourceSnapshot(
                WebRevisionSourceReference(jobId, runId, revisionId, "a".repeat(64), "version_1"),
                "b".repeat(64), "c".repeat(64), listOf(WebRevisionSourceFile(GeneratedFileEvidence(
                    "src/body.c", "d".repeat(64), "fixture", acceptedImplementation = claim,
                    roles = setOf(ProjectFileRole.BUILD_INPUT), contentKind = ProjectContentKind.UTF8_TEXT), 8)))
            var captures = 0
            val metadata = WebRevisionFileMetadata { _, _, _ -> captures++; snapshot }
                .read(jobId, runId, revisionId, fileId(snapshot, 0))
            assertEquals(1, captures)
            assertEquals(expected, metadata.getValue("implementationDeclaration").jsonPrimitive.content)
            assertEquals("source-input-commitments", metadata.getValue("authority").jsonPrimitive.content)
            assertEquals("not-performed", metadata.getValue("contentVerification").jsonPrimitive.content)
            assertEquals(snapshot.reference.sourceSha256, metadata.getValue("sourceSha256").jsonPrimitive.content)
            assertEquals(snapshot.metadataVersion, metadata.getValue("metadataVersion").jsonPrimitive.content)
            assertFalse(metadata.containsKey("acceptance"))
            assertFalse(metadata.containsKey("text"))
        }
    }

    @Test fun `file identities reject foreign candidate bindings and malformed selectors before capture`() {
        val snapshot = makeSnapshot(listOf("src/a.c")); var captures = 0
        val metadata = WebRevisionFileMetadata { job, run, revision ->
            captures++
            WebRevisionSourceSnapshot(snapshot.reference.copy(jobId = job, runId = run, revisionId = revision),
                snapshot.manifestSha256, snapshot.descriptorSha256, snapshot.files)
        }
        val id = fileId(snapshot, 0)
        for ((job, run, revision) in listOf(Triple("b".repeat(32), runId, revisionId), Triple(jobId, "other", revisionId), Triple(jobId, runId, "other"))) {
            assertEquals("SOURCE_FILE_NOT_FOUND", assertFailsWith<WebAccessDenied> { metadata.read(job, run, revision, id) }.code)
        }
        val before = captures
        for (id in listOf("../src/a.c", "%2Fsrc", "file_25000_${"a".repeat(64)}", "file_00_${"a".repeat(64)}", "file_0_bad")) {
            assertEquals("SOURCE_FILE_NOT_FOUND", assertFailsWith<WebAccessDenied> { metadata.read(jobId, runId, revisionId, id) }.code)
        }
        assertEquals(before, captures)
        val foreign = WebRevisionFileMetadata { _, _, _ -> snapshot }
        assertFailsWith<IllegalStateException> { foreign.read("b".repeat(32), runId, revisionId, id) }
    }

    @Test fun `file parents match directory selectors including deep Unicode prefixes`() {
        val parts = (0 until 60).map { "é space $it" }
        val snapshot = makeSnapshot(listOf("Makefile", parts.joinToString("/") + "/leaf.c"))
        val id = fileId(snapshot, 1)
        val metadata = WebRevisionFileMetadata { _, _, _ -> snapshot }.read(jobId, runId, revisionId, id)
        val parent = metadata.getValue("parentDirectoryId").jsonPrimitive.content
        val directory = WebRevisionDirectoryPages { _, _, _ -> snapshot }.page("owner", jobId, runId, revisionId, parent, null)
        assertEquals(60, directory.getValue("depth").jsonPrimitive.int)
        val entry = directory.getValue("items").jsonArray.single().jsonObject
        assertEquals(id, entry.getValue("fileId").jsonPrimitive.content)
        assertEquals("leaf.c", entry.getValue("displayName").jsonPrimitive.content)
        assertEquals(parts.joinToString("/") + "/leaf.c", metadata.getValue("item").jsonObject.getValue("displayName").jsonPrimitive.content)
    }

    @Test fun `flat and detail metadata share stable file identity and explicit host flags`() {
        val roles = setOf(ProjectFileRole.BUILD_INPUT, ProjectFileRole.VIEWABLE, ProjectFileRole.ARCHIVE_PAYLOAD)
        val snapshot = makeSnapshot(listOf("a.c", "folder/b.c"), roles = roles)
        val flat = WebRevisionSourcePages { _, _, _ -> snapshot }.page("owner", jobId, runId, revisionId, null)
        for ((index, entry) in flat.getValue("items").jsonArray.withIndex()) {
            val detail = WebRevisionFileMetadata { _, _, _ -> snapshot }.read(jobId, runId, revisionId, fileId(snapshot, index))
            val item = detail.getValue("item").jsonObject
            assertEquals(entry.jsonObject, JsonObject(item - "declaredArchivable"))
            assertTrue(item.getValue("declaredArchivable").jsonPrimitive.boolean)
            assertTrue(item.getValue("declaredViewable").jsonPrimitive.boolean)
            assertEquals(snapshot.metadataVersion, detail.getValue("metadataVersion").jsonPrimitive.content)
        }
    }

    @Test fun `saved input file and directory links survive an unchanged revision gaining manifest inventory coverage`() {
        val legacy = makeSnapshot(listOf("Makefile", "src/nested/a.c"))
        val legacyFileId = fileId(legacy, 1)
        val legacyDirectoryId = revisionSourceDirectoryId(legacy, "src/nested")
        val reports = listOf("A/report.json", "src/earlier.json", "src/nested/0.json").map { path ->
            WebRevisionSourceFile(GeneratedFileEvidence(path, "e".repeat(64), "fixture",
                roles = setOf(ProjectFileRole.VIEWABLE), contentKind = ProjectContentKind.UTF8_TEXT), null)
        }
        // Only the adapter's coverage changes. All persisted metadata and the old URL's pins are identical.
        val current = WebRevisionSourceSnapshot(legacy.reference, legacy.manifestSha256, legacy.descriptorSha256, legacy.files + reports)
        assertEquals(legacy.metadataVersion, current.metadataVersion)
        assertEquals(legacyFileId, current.fileId(current.files.single { it.evidence.path == "src/nested/a.c" }))
        assertEquals(legacyDirectoryId, revisionSourceDirectoryId(current, "src/nested"))
        val detail = WebRevisionFileMetadata { _, _, _ -> current }.read(jobId, runId, revisionId, legacyFileId)
        assertEquals("src/nested/a.c", detail.getValue("item").jsonObject.getValue("displayName").jsonPrimitive.content)
        assertEquals(legacyDirectoryId, detail.getValue("parentDirectoryId").jsonPrimitive.content)
        assertSame(legacy.files[1], resolveRevisionSourceFile(current, legacyFileId))
        val directory = WebRevisionDirectoryPages { _, _, _ -> current }.page("owner", jobId, runId, revisionId, legacyDirectoryId, null, includeManifest = true)
        assertEquals(legacyDirectoryId, directory.getValue("directoryId").jsonPrimitive.content)
        assertEquals(legacyDirectoryId, directory.getValue("breadcrumbs").jsonArray.last().jsonObject.getValue("directoryId").jsonPrimitive.content)
        assertEquals(legacyFileId, directory.getValue("items").jsonArray.last().jsonObject.getValue("fileId").jsonPrimitive.content)
        for (file in reports) assertSame(file, resolveRevisionSourceFile(current, current.fileId(file)))
        // An index is never sufficient: a valid digest belonging to a different input index is refused.
        val forged = legacyFileId.replace("file_1_", "file_0_")
        assertEquals("SOURCE_FILE_NOT_FOUND", assertFailsWith<WebAccessDenied> { resolveRevisionSourceFile(current, forged) }.code)
    }

    @Test fun `manifest inventory requires negotiation and cursors cannot switch inventory modes`() {
        val inputs = makeSnapshot(listOf("Makefile", "src/a.c"))
        val report = WebRevisionSourceFile(GeneratedFileEvidence("A/report.json", "e".repeat(64), "fixture",
            roles = setOf(ProjectFileRole.VIEWABLE), contentKind = ProjectContentKind.UTF8_TEXT), null)
        val snapshot = WebRevisionSourceSnapshot(inputs.reference, inputs.manifestSha256, inputs.descriptorSha256, inputs.files + report)
        val pages = WebRevisionSourcePages { _, _, _ -> snapshot }
        val directories = WebRevisionDirectoryPages { _, _, _ -> snapshot }
        val metadata = WebRevisionFileMetadata { _, _, _ -> snapshot }
        val legacy = pages.page("owner", jobId, runId, revisionId, null)
        assertEquals(2, legacy.getValue("totalFiles").jsonPrimitive.int)
        assertTrue(legacy.getValue("items").jsonArray.all { it.jsonObject.getValue("sizeBytes") != JsonNull })
        val expanded = pages.page("owner", jobId, runId, revisionId, null, includeManifest = true)
        assertEquals(3, expanded.getValue("totalFiles").jsonPrimitive.int)
        assertEquals(JsonNull, expanded.getValue("items").jsonArray.first().jsonObject.getValue("sizeBytes"))
        val reportId = snapshot.fileId(report)
        assertEquals("SOURCE_FILE_NOT_FOUND", assertFailsWith<WebAccessDenied> { metadata.read(jobId, runId, revisionId, reportId) }.code)
        assertEquals(JsonNull, metadata.read(jobId, runId, revisionId, reportId, includeManifest = true).getValue("item").jsonObject.getValue("sizeBytes"))
        val reportDirectory = revisionSourceDirectoryId(snapshot, "A")
        assertEquals("SOURCE_DIRECTORY_NOT_FOUND", assertFailsWith<WebAccessDenied> {
            directories.page("owner", jobId, runId, revisionId, reportDirectory, null)
        }.code)
        for (include in listOf(false, true)) {
            val cursor = pages.page("owner", jobId, runId, revisionId, "limit=1", include).getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.content
            assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> {
                pages.page("owner", jobId, runId, revisionId, "limit=1&cursor=$cursor", !include)
            }.code)
            val directoryCursor = directories.page("owner", jobId, runId, revisionId, "root", "limit=1", include)
                .getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.content
            assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> {
                directories.page("owner", jobId, runId, revisionId, "root", "limit=1&cursor=$directoryCursor", !include)
            }.code)
        }
        assertFalse(sourceInventoryIncludesManifest(null))
        assertTrue(sourceInventoryIncludesManifest(listOf("manifest")))
        for (header in listOf(emptyList(), listOf("unknown"), listOf("manifest", "manifest"), listOf("manifest,manifest"))) {
            assertEquals("VALIDATION_FAILED", assertFailsWith<WebAccessDenied> { sourceInventoryIncludesManifest(header) }.code)
        }
    }

    @Test fun `embedded document classification accepts exact source links and refuses encoded authority`() {
        val base = "/nested/"; val job = "${base}jobs/$jobId"; val run = "$job/runs/$runId"
        val valid = listOf(base, "${base}runtime", "${base}upload", job, "$job/runs", run,
            "$run/revisions/$revisionId/sources/root", "$run/revisions/$revisionId/source-files/file_0_${"a".repeat(64)}",
            "$run/revisions/$revisionId/functions", "$run/revisions/$revisionId/modules", "$run/revisions/$revisionId/modules/core",
            "$run/revisions/$revisionId/functions/fn_0000000000401000", "$run/revisions/$revisionId/globals/global_1",
            "$run/revisions/$revisionId/types/type_${"c".repeat(64)}")
        for (path in valid) {
            assertEquals(path, canonicalSpaDocumentPath(base, path))
            if (path != base) assertEquals(path, canonicalSpaDocumentPath(base, "$path/"))
        }
        for (path in listOf("$run/revisions/$revisionId/sources/../private", "$run/revisions/$revisionId/sources/%2Froot",
            "$run/revisions/$revisionId/source-files/file/a", "$run/revisions/$revisionId/source-files/é.c", "$run/revisions/$revisionId/unknown/root",
            "$run/revisions/$revisionId/sources/root/extra", "/other/jobs/$jobId/runs/$runId", "${base}api/v1/jobs/$jobId",
            "$run/revisions/$revisionId/globals", "$run/revisions/$revisionId/types", "$run/revisions/$revisionId/functions/a/b",
            "$run/revisions/$revisionId/modules/core.c", "$run/revisions/$revisionId/functions/%66n")) {
            assertNull(canonicalSpaDocumentPath(base, path))
        }
        // Named attempt views are document routes under both root and nested deployments.
        // These are string-only classifier decisions; no server or browser is constructed.
        for (prefix in listOf("/", "/nested/")) {
            val selected = "${prefix}jobs/$jobId/runs/$runId"
            for (view in listOf("activity", "evidence", "logs")) {
                val path = "$selected/$view"
                assertEquals(path, canonicalSpaDocumentPath(prefix, path))
                assertEquals(path, canonicalSpaDocumentPath(prefix, "$path/"))
            }
            for (suffix in listOf("unknown", "Activity", "%61ctivity", "evidence/extra", "activity/../private", "evidence//", "logs/build", "Logs")) {
                assertNull(canonicalSpaDocumentPath(prefix, "$selected/$suffix"))
            }
        }
    }
}
