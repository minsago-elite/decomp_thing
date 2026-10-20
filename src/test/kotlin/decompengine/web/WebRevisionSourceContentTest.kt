package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.project.*
import decompengine.repair.StableRegularFile
import kotlinx.serialization.json.*
import kotlin.test.*

/** Captured byte arrays, synthetic identities and synchronous callbacks only. No store or listener is opened. */
class WebRevisionSourceContentTest {
    private val jobId = "a".repeat(32)
    private val runId = "run_1"
    private val revisionId = "revision_1"
    private val roles = setOf(ProjectFileRole.BUILD_INPUT, ProjectFileRole.VIEWABLE, ProjectFileRole.ARCHIVE_PAYLOAD)
    private fun captured(bytes: ByteArray, inode: Long = 1) = StableRegularFile(bytes, WebExplorationArtifact.sha256(bytes),
        LinuxFileIdentity(LinuxFileKey(1, inode), 0x8180, 1000, 1000, 1, 1, true, false, false))
    private fun makeSnapshot(bytes: ByteArray, kind: ProjectContentKind = ProjectContentKind.UTF8_TEXT,
        selectedRoles: Set<ProjectFileRole> = roles, size: Long = bytes.size.toLong(), path: String = "src/é space.c"): WebRevisionSourceSnapshot {
        val file = WebRevisionSourceFile(GeneratedFileEvidence(path, WebExplorationArtifact.sha256(bytes), "fixture",
            roles = selectedRoles, contentKind = kind), size)
        val sha = revisionSourceDigest("${path.length}:$path:$size:${file.evidence.sha256}\n")
        return WebRevisionSourceSnapshot(WebRevisionSourceReference(jobId, runId, revisionId, sha, "version_1"),
            "b".repeat(64), "c".repeat(64), listOf(file))
    }
    private fun makeContent(bytes: ByteArray, kind: ProjectContentKind = ProjectContentKind.UTF8_TEXT): WebRevisionSourceContent {
        val snapshot = makeSnapshot(bytes, kind)
        return WebRevisionSourceContent(snapshot, revisionSourceFileId(snapshot.reference, 0, snapshot.files.single().evidence.path),
            snapshot.files.single(), captured(bytes))
    }
    private fun chunk(content: WebRevisionSourceContent, query: String? = null) = content.chunk(WebSourceChunkQuery.parse(query))
    private fun text(page: JsonObject) = page.getValue("text").jsonPrimitive.content
    private fun next(page: JsonObject) = page.getValue("nextOffsetBytes").jsonPrimitive.contentOrNull

    @Test fun `UTF8 ranges preserve exact bytes CRLF markup and revision line positions`() {
        val original = "α😀\r\n<script>\" & x\nfinal".toByteArray()
        val content = makeContent(original)
        val pages = mutableListOf<JsonObject>(); var offset = "0"
        do {
            val page = chunk(content, "offset=$offset&maxBytes=7"); pages += page
            assertEquals("utf8", page.getValue("representation").jsonPrimitive.content)
            assertEquals(JsonNull, page.getValue("fallbackReason"))
            assertEquals(revisionId, page.getValue("binding").jsonObject.getValue("revisionId").jsonPrimitive.content)
            val start = page.getValue("offsetBytes").jsonPrimitive.int
            assertEquals((1 + original.take(start).count { it == 10.toByte() }).toString(), page.getValue("firstLine").jsonPrimitive.content)
            assertTrue(page.getValue("lengthBytes").jsonPrimitive.int <= 7)
            assertEquals(start > 0 && original[start - 1] != 10.toByte(), page.getValue("startsMidLine").jsonPrimitive.boolean)
            offset = next(page) ?: break
        } while (true)
        assertContentEquals(original, pages.joinToString("") { text(it) }.toByteArray())
        assertContentEquals(original, content.download())
        assertFalse(pages.last().getValue("endsMidLine").jsonPrimitive.boolean)
        assertTrue(pages.all { !it.getValue("completeFile").jsonPrimitive.boolean })
        assertFalse(text(chunk(content)).contains("�"))
    }

    @Test fun `eight MiB captured input is available through bounded complete byte ranges`() {
        val original = (("x".repeat(127) + "\n").repeat(65_536)).toByteArray()
        assertEquals(WebRevisionSourceContent.MAXIMUM_FILE_BYTES, original.size.toLong())
        val content = makeContent(original); var offset = "0"; var consumed = 0; var pages = 0
        do {
            val page = chunk(content, "offset=$offset&maxBytes=131072")
            val bytes = text(page).toByteArray(); assertTrue(bytes.size <= 131_072)
            assertContentEquals(original.copyOfRange(consumed, consumed + bytes.size), bytes)
            assertTrue(page.toString().toByteArray().size < 1_048_576)
            consumed += bytes.size; pages++; offset = next(page) ?: break
        } while (true)
        assertEquals(original.size, consumed); assertEquals(64, pages)
        assertContentEquals(original, content.download())
        val escaped = chunk(makeContent(ByteArray(131_072) { if (it % 128 == 0) 10 else 1 }), "maxBytes=131072")
        assertTrue(escaped.toString().toByteArray().size < 1_048_576)
    }

    @Test fun `invalid UTF8 and binary declarations retain raw bytes in deterministic hex fallback`() {
        val malformed = listOf(byteArrayOf(0x80.toByte()), byteArrayOf(0xc0.toByte(), 0x80.toByte()),
            byteArrayOf(0xe0.toByte(), 0x80.toByte(), 0x80.toByte()), byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()),
            byteArrayOf(0xf0.toByte(), 0x80.toByte(), 0x80.toByte(), 0x80.toByte()),
            byteArrayOf(0xf4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()), byteArrayOf(0xf5.toByte()), byteArrayOf(0xc2.toByte()))
        for (bytes in malformed) {
            val content = makeContent(bytes); val page = chunk(content)
            assertEquals("hex", page.getValue("representation").jsonPrimitive.content)
            assertEquals("invalid-utf8", page.getValue("fallbackReason").jsonPrimitive.content)
            assertEquals(bytes.joinToString("") { "%02x".format(it) }, text(page))
            assertEquals(JsonNull, page.getValue("firstLine")); assertEquals(JsonNull, page.getValue("startsMidLine"))
            assertEquals(JsonNull, page.getValue("endsMidLine")); assertContentEquals(bytes, content.download())
        }
        assertEquals("declared-binary", chunk(makeContent("valid text".toByteArray(), ProjectContentKind.BINARY))
            .getValue("fallbackReason").jsonPrimitive.content)
        for (text in listOf("é", "€", "😀", "\u007f", "\u0080", "\u0800", "\ud7ff", "\ue000", "\udbff\udfff")) {
            assertEquals("utf8", chunk(makeContent(text.toByteArray())).getValue("representation").jsonPrimitive.content)
        }
    }

    @Test fun `line byte ceiling switches the whole captured representation without losing original bytes`() {
        val atLimit = makeContent(("é".repeat(131_072) + "\n").toByteArray())
        assertEquals("utf8", chunk(atLimit).getValue("representation").jsonPrimitive.content)
        val over = ("x".repeat(262_145) + "\n").toByteArray(); val content = makeContent(over)
        val first = chunk(content, "maxBytes=4")
        assertEquals("line-too-long", first.getValue("fallbackReason").jsonPrimitive.content)
        assertEquals("78787878", text(first)); assertEquals("4", next(first)); assertContentEquals(over, content.download())
    }

    @Test fun `canonical query bounds character boundaries empty files and metadata expiry are explicit`() {
        for (query in listOf("offset=-1", "offset=01", "offset=8388609", "maxBytes=3", "maxBytes=131073", "offset=1&offset=2",
            "maxBytes=x", "path=src/a.c", "offset=%30", "metadataVersion=unknown", "offset=0&")) {
            assertEquals("VALIDATION_FAILED", assertFailsWith<WebAccessDenied> { WebSourceChunkQuery.parse(query) }.code)
        }
        val content = makeContent("😀x".toByteArray())
        assertEquals("😀", text(chunk(content, "maxBytes=4")))
        for (offset in listOf(1, 2, 3, 5, 6)) assertEquals("SOURCE_RANGE_INVALID", assertFailsWith<WebAccessDenied> {
            chunk(content, "offset=$offset")
        }.code)
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { chunk(content, "metadataVersion=${"d".repeat(64)}") }.code)
        val empty = chunk(makeContent(byteArrayOf())); assertEquals("", text(empty)); assertNull(next(empty))
        assertEquals("0", empty.getValue("lengthBytes").jsonPrimitive.content); assertTrue(empty.getValue("completeFile").jsonPrimitive.boolean)
    }

    @Test fun `file selectors enforce candidate identity declarations and file size before exposing bytes`() {
        val bytes = "input".toByteArray(); val snapshot = makeSnapshot(bytes)
        val file = snapshot.files.single(); val id = revisionSourceFileId(snapshot.reference, 0, file.evidence.path)
        assertSame(file, selectRevisionSourceFile(snapshot, id, WebSourceReadPurpose.PREVIEW))
        for (ref in listOf(snapshot.reference.copy(jobId = "b".repeat(32)), snapshot.reference.copy(runId = "other"),
            snapshot.reference.copy(revisionId = "other"), snapshot.reference.copy(sourceSha256 = "d".repeat(64)))) {
            val foreign = WebRevisionSourceSnapshot(ref, snapshot.manifestSha256, snapshot.descriptorSha256, snapshot.files)
            assertEquals("SOURCE_FILE_NOT_FOUND", assertFailsWith<WebAccessDenied> { selectRevisionSourceFile(foreign, id, WebSourceReadPurpose.PREVIEW) }.code)
        }
        for ((selectedRoles, purpose) in listOf(setOf(ProjectFileRole.BUILD_INPUT) to WebSourceReadPurpose.PREVIEW,
            setOf(ProjectFileRole.BUILD_INPUT, ProjectFileRole.VIEWABLE) to WebSourceReadPurpose.DOWNLOAD)) {
            val denied = makeSnapshot(bytes, selectedRoles = selectedRoles)
            assertEquals("SOURCE_REPRESENTATION_UNAVAILABLE", assertFailsWith<WebAccessDenied> { selectRevisionSourceFile(denied, id, purpose) }.code)
        }
        val large = makeSnapshot(bytes, size = WebRevisionSourceContent.MAXIMUM_FILE_BYTES + 1)
        val largeId = revisionSourceFileId(large.reference, 0, large.files.single().evidence.path)
        assertEquals("SOURCE_FILE_TOO_LARGE", assertFailsWith<WebAccessDenied> { selectRevisionSourceFile(large, largeId, WebSourceReadPurpose.PREVIEW) }.code)
        val deep = makeSnapshot(bytes, path = (0 until 60).joinToString("/") { "é space $it" } + "/file.c")
        val deepId = revisionSourceFileId(deep.reference, 0, deep.files.single().evidence.path)
        assertSame(deep.files.single(), selectRevisionSourceFile(deep, deepId, WebSourceReadPurpose.DOWNLOAD))
    }

    @Test fun `capture rechecks source and all metadata while sharing admission with catalog reads`() {
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val payload = "int x;\n".toByteArray(); val input = captured("input".toByteArray(), 1)
        val paths = listOf("Makefile", "src/modules/unit.c")
        val files = paths.map { path ->
            val declaration = profile.layout.declarationForPath(path)
            GeneratedFileEvidence(path, WebExplorationArtifact.sha256(if (path == "Makefile") byteArrayOf() else payload), "fixture",
                acceptedImplementation = if (ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles) false else null,
                roles = declaration.roles, contentKind = declaration.contentKind)
        }
        val canonical = files.joinToString("") { "${it.path.length}:${it.path}:${if (it.path == "Makefile") 0 else payload.size}:${it.sha256}\n" }
        val reference = WebRevisionSourceReference(jobId, runId, revisionId, revisionSourceDigest(canonical), "version_1")
        val manifest = captured(SourceTreeManifest(profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = input.sha256,
            files = files, unresolvedEntityIds = emptyList()).toJson().toByteArray(), 2)
        val descriptor = captured(buildJsonObject {
            put("schemaVersion", 3); put("sourceRevisionSha256", reference.sourceSha256)
            put("sourceInputs", JsonArray(files.map { file -> buildJsonObject {
                put("path", file.path); put("bytes", if (file.path == "Makefile") 0 else payload.size); put("sha256", file.sha256)
            } }))
        }.toString().toByteArray(), 3)
        val id = revisionSourceFileId(reference, 1, paths[1])
        for (mode in listOf("valid", "body-identity", "body-bytes", "manifest", "descriptor", "input", "expiry", "busy")) {
            val reads = mutableMapOf<String, Int>(); var bodies = 0
            fun observe(key: String, value: StableRegularFile): StableRegularFile {
                val count = (reads[key] ?: 0) + 1; reads[key] = count
                return if (mode == key && count > 1) captured(value.bytes, 99) else value
            }
            lateinit var evidence: WebSourceCatalogEvidence
            evidence = WebSourceCatalogEvidence(listOf(profile), { observe("input", input) }, { _, path, _ ->
                when {
                    path.endsWith("/source_tree_manifest.json") -> observe("manifest", manifest)
                    path.endsWith("/build_contract.json") -> observe("descriptor", descriptor)
                    else -> error("Unexpected metadata path")
                }
            })
            val invoke = {
                evidence.readFile(reference, id, WebSourceReadPurpose.PREVIEW, if (mode == "expiry") "e".repeat(64) else null) { job, run, path, maximum ->
                    assertEquals(jobId, job); assertEquals(runId, run); assertEquals(paths[1], path)
                    assertEquals(WebRevisionSourceContent.MAXIMUM_FILE_BYTES, maximum); bodies++
                    if (mode == "busy" && bodies == 1) assertEquals("SOURCE_CATALOG_BUSY", assertFailsWith<WebAccessDenied> { evidence.readRevision(reference) }.code)
                    when {
                        mode == "body-identity" && bodies > 1 -> captured(payload, 99)
                        mode == "body-bytes" && bodies > 1 -> captured("changed".toByteArray(), 4)
                        else -> captured(payload, 4)
                    }
                }
            }
            if (mode in listOf("valid", "busy")) { assertContentEquals(payload, invoke().download()); assertEquals(2, bodies) }
            else assertFailsWith<WebAccessDenied> { invoke() }
            if (mode == "expiry") assertEquals(0, bodies)
            // Admission always releases after either outcome, including nested refusal.
            evidence.readRevision(reference)
        }
    }

    @Test fun `captured bytes are owned and declared digests cannot substitute for the actual content`() {
        val original = "source".toByteArray(); val snapshot = makeSnapshot(original); val file = snapshot.files.single()
        val id = revisionSourceFileId(snapshot.reference, 0, file.evidence.path); val observed = captured(original)
        val content = WebRevisionSourceContent(snapshot, id, file, observed)
        original.fill(0); val downloaded = content.download(); downloaded.fill(0)
        assertEquals("source", text(chunk(content)))
        assertEquals("SOURCE_REVISION_CHANGED", assertFailsWith<WebAccessDenied> { content.requireSame(observed) }.code)
        val forged = captured("wrong!".toByteArray()).copy(sha256 = file.evidence.sha256)
        assertEquals("SOURCE_REVISION_CHANGED", assertFailsWith<WebAccessDenied> { WebRevisionSourceContent(snapshot, id, file, forged) }.code)
    }

    @Test fun `download integrity headers identify the exact captured commitment without adding acceptance authority`() {
        for (original in listOf(byteArrayOf(), "<script>source</script>".toByteArray(), byteArrayOf(0x80.toByte(), 0))) {
            val snapshot = makeSnapshot(original, ProjectContentKind.BINARY); val file = snapshot.files.single()
            val id = revisionSourceFileId(snapshot.reference, 0, file.evidence.path)
            val content = WebRevisionSourceContent(snapshot, id, file, captured(original))
            val headers = content.verifiedDownloadHeaders()
            assertEquals(mapOf(
                "X-Decomp-Content-Verification" to "committed-digest",
                "X-Decomp-File-ID" to id,
                "X-Decomp-Source-SHA256" to snapshot.reference.sourceSha256,
                "X-Decomp-Metadata-Version" to snapshot.metadataVersion,
                "X-Decomp-Content-SHA256" to file.evidence.sha256,
            ), headers)
            assertContentEquals(original, content.download())
            original.fill(0)
            assertEquals(headers, content.verifiedDownloadHeaders())
            assertTrue(headers.values.none { it.contains("<script>") || it.contains("accepted") || it.contains("/private/") })
        }
    }

    @Test fun `download integrity headers cannot bypass archive role or actual byte verification`() {
        val original = "source".toByteArray()
        val snapshot = makeSnapshot(original, selectedRoles = roles - ProjectFileRole.ARCHIVE_PAYLOAD)
        val file = snapshot.files.single(); val id = revisionSourceFileId(snapshot.reference, 0, file.evidence.path)
        val content = WebRevisionSourceContent(snapshot, id, file, captured(original))
        assertEquals("SOURCE_REPRESENTATION_UNAVAILABLE", assertFailsWith<WebAccessDenied> { content.verifiedDownloadHeaders() }.code)
        assertEquals("SOURCE_REPRESENTATION_UNAVAILABLE", assertFailsWith<WebAccessDenied> { content.download() }.code)
        val forged = captured("wrong!".toByteArray()).copy(sha256 = file.evidence.sha256)
        assertEquals("SOURCE_REVISION_CHANGED", assertFailsWith<WebAccessDenied> {
            WebRevisionSourceContent(snapshot, id, file, forged).verifiedDownloadHeaders()
        }.code)
    }
}
