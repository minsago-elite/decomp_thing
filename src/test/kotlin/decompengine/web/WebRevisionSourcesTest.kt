package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.jobs.*
import decompengine.project.*
import decompengine.repair.StableRegularFile
import java.security.MessageDigest
import java.time.Instant
import kotlinx.serialization.json.*
import kotlin.test.*

/** Synthetic records and synchronous callbacks only; no store, listener, compiler or graph is opened. */
class WebRevisionSourcesTest {
    private data class Input(val path: String, val bytes: Long, val sha256: String)
    private val jobId = "a".repeat(32)
    private val runId = "run_1"
    private val revisionId = "revision_1"
    private val profile = GeneratedCMakeReconstructionProfile.descriptor
    private val input = captured("input".toByteArray(), 1)
    private val small = listOf(Input("Makefile", 0, "a".repeat(64)), Input("src/modules/unit.c", 8, "b".repeat(64)))
    private fun digest(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        .joinToString("") { "%02x".format(it) }
    private fun sourceDigest(inputs: List<Input>) = digest(inputs.sortedBy { it.path }
        .joinToString("") { "${it.path.length}:${it.path}:${it.bytes}:${it.sha256}\n" })
    private fun reference(inputs: List<Input> = small) = WebRevisionSourceReference(jobId, runId, revisionId, sourceDigest(inputs), "version_1")
    private fun evidence(item: Input, selected: ReconstructionProfile = profile): GeneratedFileEvidence {
        val declaration = selected.layout.declarationForPath(item.path)
        return GeneratedFileEvidence(item.path, item.sha256, "fixture",
            acceptedImplementation = if (ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles) false else null,
            roles = declaration.roles, contentKind = declaration.contentKind)
    }
    private fun manifest(inputs: List<Input> = small, selected: ReconstructionProfile = profile,
        recorded: List<Input> = emptyList()): StableRegularFile = captured(
        SourceTreeManifest(profileId = selected.id, profileSha256 = selected.sha256, inputSha256 = input.sha256,
            files = (inputs + recorded).map { evidence(it, selected) }, unresolvedEntityIds = emptyList()).toJson().toByteArray(), 2)
    private fun descriptor(inputs: List<Input> = small): JsonObject = buildJsonObject {
        put("schemaVersion", 3); put("sourceRevisionSha256", sourceDigest(inputs))
        put("sourceInputs", JsonArray(inputs.sortedBy { it.path }.map { item -> buildJsonObject {
            put("path", item.path); put("bytes", item.bytes); put("sha256", item.sha256)
        } }))
        put("command", JsonArray(listOf(JsonPrimitive("PRIVATE-build-command"))))
    }
    private fun captured(bytes: ByteArray, inode: Long): StableRegularFile = StableRegularFile(bytes,
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) },
        LinuxFileIdentity(LinuxFileKey(1, inode), 0x8180, 1000, 1000, 1, 1, true, false, false))
    private fun capture(inputs: List<Input> = small, selected: ReconstructionProfile = profile,
        document: JsonObject = descriptor(inputs)): WebRevisionSourceSnapshot {
        val manifest = manifest(inputs, selected)
        val descriptor = captured(document.toString().toByteArray(), 3)
        return WebSourceCatalogEvidence(listOf(selected), { input }, { _, path, maximum ->
            assertEquals(WebSourceCatalogEvidence.MAXIMUM_MANIFEST_BYTES, maximum)
            when (path) {
                "reports/runs/run_1/source-tree/source_tree_manifest.json" -> manifest
                "reports/runs/run_1/source-tree/reports/build_contract.json" -> descriptor
                else -> error("Source bodies must not be read by metadata capture")
            }
        }).readRevision(reference(inputs))
    }
    private fun attempt(run: String = runId, candidate: WorkflowCandidate? = WorkflowCandidate(revisionId, sourceDigest(small))): WorkflowAttempt {
        val at = Instant.parse("2026-10-20T00:00:00Z")
        return WorkflowAttempt(run, jobId, WorkflowKind.RECONSTRUCT, WorkflowRunState.COMPLETED, "version_1",
            at, at, at, null, null, null, WorkflowExecutionLimits(1000u, 1000u, 1024u, 0u),
            WorkflowTerminalReason.COMPLETED, null, candidate, null)
    }
    private fun stored(attempts: List<WorkflowAttempt> = listOf(attempt())) = WorkflowJobSnapshot(jobId, "job_version_1",
        LegacyWorkflowObservation(input.sha256, "uploaded", false), attempts, null)
    private fun cursor(page: JsonObject) = page.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.contentOrNull

    @Test fun `only an actual retained candidate supplies revision identity and conflicting reuse is refused`() {
        assertEquals(reference(), selectWebRevisionSource(stored(), jobId, runId, revisionId))
        for ((run, revision) in listOf("foreign" to revisionId, runId to "foreign")) {
            assertEquals(404, assertFailsWith<WebAccessDenied> { selectWebRevisionSource(stored(), jobId, run, revision) }.status)
        }
        assertEquals("REVISION_NOT_FOUND", assertFailsWith<WebAccessDenied> {
            selectWebRevisionSource(stored(listOf(attempt(candidate = null))), jobId, runId, revisionId)
        }.code)
        val conflict = attempt("run_2", WorkflowCandidate(revisionId, "f".repeat(64)))
        assertEquals("SOURCE_REVISION_CHANGED", assertFailsWith<WebAccessDenied> {
            selectWebRevisionSource(stored(listOf(attempt(), conflict)), jobId, runId, revisionId)
        }.code)
        assertEquals(reference(), selectWebRevisionSource(stored(listOf(attempt(), attempt("run_2"))), jobId, runId, revisionId))
        assertFailsWith<IllegalStateException> { selectWebRevisionSource(stored(), "b".repeat(32), runId, revisionId) }
    }

    @Test fun `canonical commitments capture only fixed metadata leaves and recheck the complete observation`() {
        val manifest = manifest(); val descriptor = captured(descriptor().toString().toByteArray(), 3)
        val reads = mutableListOf<String>()
        val snapshot = WebSourceCatalogEvidence(listOf(profile), { reads += "input"; input }, { _, path, _ ->
            reads += path
            when (path) {
                "reports/runs/run_1/source-tree/source_tree_manifest.json" -> manifest
                "reports/runs/run_1/source-tree/reports/build_contract.json" -> descriptor
                else -> error("Unexpected source body read")
            }
        }).readRevision(reference())
        assertEquals(listOf("input", "reports/runs/run_1/source-tree/source_tree_manifest.json",
            "reports/runs/run_1/source-tree/reports/build_contract.json", "reports/runs/run_1/source-tree/reports/build_contract.json",
            "reports/runs/run_1/source-tree/source_tree_manifest.json", "input"), reads)
        assertEquals(digest("8:Makefile:0:${"a".repeat(64)}\n18:src/modules/unit.c:8:${"b".repeat(64)}\n"), snapshot.reference.sourceSha256)
        assertEquals(small.map { it.bytes }, snapshot.files.map { it.sizeBytes })
        val page = WebRevisionSourcePages { _, _, _ -> snapshot }.page("owner", jobId, runId, revisionId, null)
        assertEquals(revisionId, page.getValue("binding").jsonObject.getValue("revisionId").jsonPrimitive.content)
        assertEquals("source-input-commitments", page.getValue("authority").jsonPrimitive.content)
        assertFalse(page.toString().contains("PRIVATE")); assertFalse(page.containsKey("acceptance"))
    }

    @Test fun `descriptor inventory size digest schema and number representation cannot override a registered source`() {
        val original = descriptor()
        val rows = original.getValue("sourceInputs").jsonArray
        fun changedRow(key: String, value: JsonElement) = JsonArray(listOf(JsonObject(rows[0].jsonObject + (key to value)), rows[1]))
        val invalid = listOf(
            JsonObject(original + ("schemaVersion" to JsonPrimitive(4))),
            JsonObject(original + ("sourceRevisionSha256" to JsonPrimitive("f".repeat(64)))),
            JsonObject(original + ("sourceInputs" to changedRow("bytes", JsonPrimitive(1)))),
            JsonObject(original + ("sourceInputs" to changedRow("bytes", JsonPrimitive("0")))),
            JsonObject(original + ("sourceInputs" to changedRow("sha256", JsonPrimitive("f".repeat(64))))),
            JsonObject(original + ("sourceInputs" to JsonArray(listOf(rows[0])))),
            JsonObject(original + ("sourceInputs" to JsonArray(listOf(rows[1], rows[0])))),
            JsonObject(original + ("sourceInputs" to JsonArray(listOf(rows[0], rows[0], rows[1])))),
            JsonObject(original + ("sourceInputs" to changedRow("path", JsonPrimitive("../input.elf")))),
        )
        for (document in invalid) assertFails { capture(document = document) }
    }

    @Test fun `changed descriptor identity or uploaded input never publishes a partial source listing`() {
        val manifest = manifest(); val descriptor = captured(descriptor().toString().toByteArray(), 3)
        var captures = 0
        val changed = WebSourceCatalogEvidence(listOf(profile), { input }, { _, path, _ ->
            if (path.endsWith("source_tree_manifest.json")) manifest else {
                captures++; if (captures == 1) descriptor else captured(descriptor.bytes, 4)
            }
        })
        assertEquals("SOURCE_CATALOG_CHANGED", assertFailsWith<WebAccessDenied> { changed.readRevision(reference()) }.code)
        var inputReads = 0
        val changedInput = WebSourceCatalogEvidence(listOf(profile), {
            inputReads++; if (inputReads == 1) input else captured("replacement".toByteArray(), 5)
        }, { _, path, _ -> if (path.endsWith("source_tree_manifest.json")) manifest else descriptor })
        assertEquals("SOURCE_CATALOG_CHANGED", assertFailsWith<WebAccessDenied> { changedInput.readRevision(reference()) }.code)
    }

    @Test fun `unicode path lengths and sizes above the JavaScript safe integer remain exact`() {
        val module = profile.layout.declarationForPath("src/modules/unit.c")
        val custom = ReconstructionProfile(profile.schemaVersion, "unicode-source-test", ProjectLayoutProfile(1,
            profile.layout.declarations + ProjectFileDeclaration("unicode-input", "src/é.c", module.roles, module.contentKind)),
            profile.budgets, profile.adapterConfiguration)
        val inputs = listOf(small[0], Input("src/é.c", 9_007_199_254_740_993L, "b".repeat(64)))
        val snapshot = capture(inputs, custom)
        assertEquals(digest("8:Makefile:0:${"a".repeat(64)}\n7:src/é.c:9007199254740993:${"b".repeat(64)}\n"), snapshot.reference.sourceSha256)
        val page = WebRevisionSourcePages { _, _, _ -> snapshot }.page("owner", jobId, runId, revisionId, null)
        assertEquals("9007199254740993", page.getValue("items").jsonArray[1].jsonObject.getValue("sizeBytes").jsonPrimitive.content)
    }

    @Test fun `25000 canonical input commitments page without eager source body reads or duplicate identities`() {
        val inputs = listOf(small[0]) + (0 until 24_999).map { Input("src/modules/m_${it.toString().padStart(5, '0')}.c", 8, "b".repeat(64)) }
        val snapshot = capture(inputs)
        val pages = WebRevisionSourcePages { _, _, _ -> snapshot }
        val seen = mutableListOf<String>(); val ids = mutableSetOf<String>(); var next: String? = null
        do {
            val page = pages.page("owner", jobId, runId, revisionId, "limit=200" + (next?.let { "&cursor=$it" } ?: ""))
            assertTrue(page.getValue("items").jsonArray.size <= 200)
            for (item in page.getValue("items").jsonArray) {
                seen += item.jsonObject.getValue("displayName").jsonPrimitive.content
                assertTrue(ids.add(item.jsonObject.getValue("fileId").jsonPrimitive.content))
            }
            next = cursor(page)
        } while (next != null)
        assertEquals(inputs.map { it.path }, seen)
        assertFailsWith<IllegalArgumentException> { WebRevisionSourceSnapshot(snapshot.reference, snapshot.manifestSha256,
            snapshot.descriptorSha256, snapshot.files + snapshot.files.first()) }
    }

    @Test fun `continuations bind all selected identities while file identities survive a new reader session`() {
        val inputs = listOf(small[0]) + (0 until 59).map { Input("src/modules/m_$it.c", 8, "b".repeat(64)) }
        var snapshot = capture(inputs); var captures = 0
        val pages = WebRevisionSourcePages { _, _, _ -> captures++; snapshot }
        val first = pages.page("owner", jobId, runId, revisionId, null); val next = checkNotNull(cursor(first)); val before = captures
        for ((owner, job, run, revision, query) in listOf(
            listOf("other", jobId, runId, revisionId, "cursor=$next"),
            listOf("owner", "b".repeat(32), runId, revisionId, "cursor=$next"),
            listOf("owner", jobId, "run_2", revisionId, "cursor=$next"),
            listOf("owner", jobId, runId, "revision_2", "cursor=$next"),
            listOf("owner", jobId, runId, revisionId, "limit=25&cursor=$next"),
        )) assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { pages.page(owner, job, run, revision, query) }.code)
        assertEquals(before, captures)
        val renewed = WebRevisionSourcePages { _, _, _ -> snapshot }.page("new-session", jobId, runId, revisionId, null)
        assertEquals(first.getValue("items"), renewed.getValue("items"))
        snapshot = WebRevisionSourceSnapshot(snapshot.reference, snapshot.manifestSha256, "f".repeat(64), snapshot.files)
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { pages.page("owner", jobId, runId, revisionId, "cursor=$next") }.code)
    }

    @Test fun `byte limited windows preserve complete long display names and the actual continuation offset`() {
        val prefix = ("\"".repeat(250) + "/").repeat(13)
        val module = profile.layout.declarationForPath("src/modules/unit.c")
        val files = (0 until 200).map { index -> WebRevisionSourceFile(GeneratedFileEvidence(
            prefix + "m_${index.toString().padStart(5, '0')}.c", "b".repeat(64), "fixture", acceptedImplementation = false,
            roles = module.roles, contentKind = module.contentKind), 8) }.toMutableList()
        val snapshot = WebRevisionSourceSnapshot(reference(), "a".repeat(64), "b".repeat(64), files)
        files.clear()
        val pages = WebRevisionSourcePages { _, _, _ -> snapshot }; val seen = mutableListOf<String>(); var next: String? = null
        do {
            val page = pages.page("owner", jobId, runId, revisionId, "limit=200" + (next?.let { "&cursor=$it" } ?: ""))
            assertTrue(page.toString().toByteArray().size < 1_048_000)
            val items = page.getValue("items").jsonArray; assertTrue(items.size in 1..199)
            seen += items.map { it.jsonObject.getValue("displayName").jsonPrimitive.content }; next = cursor(page)
        } while (next != null)
        assertEquals(snapshot.files.map { it.evidence.path }, seen)
    }

    @Test fun `both source capture modes share admission and release it after parser failure`() {
        val manifest = manifest(); var document = captured(descriptor().toString().toByteArray(), 3); var nested = true
        lateinit var reader: WebSourceCatalogEvidence
        reader = WebSourceCatalogEvidence(listOf(profile), {
            if (nested) {
                nested = false
                assertEquals("SOURCE_CATALOG_BUSY", assertFailsWith<WebAccessDenied> { reader.read(jobId, runId) }.code)
            }
            input
        }, { _, path, _ -> if (path.endsWith("source_tree_manifest.json")) manifest else document })
        assertEquals(2, reader.readRevision(reference()).files.size)
        document = captured("{}".toByteArray(), 3)
        assertFails { reader.readRevision(reference()) }
        document = captured(descriptor().toString().toByteArray(), 3)
        assertEquals(2, reader.readRevision(reference()).files.size)
        assertEquals(2, reader.read(jobId, runId).files.size)
    }

    @Test fun `manifest-only reports and notes are reachable with digest bindings but no invented size or source commitment`() {
        val json = "{\"note\":\"<b>inert</b>\"}\n".toByteArray(); val markdown = "# Unresolved\n\n- fn_1\n".toByteArray()
        fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        val recorded = listOf(Input("UNRESOLVED.md", -1, sha(markdown)), Input("reports/confidence.json", -1, sha(json)))
        val manifestFile = manifest(recorded = recorded); val descriptorFile = captured(descriptor().toString().toByteArray(), 3)
        val bodies = mutableMapOf("UNRESOLVED.md" to markdown, "reports/confidence.json" to json)
        val evidence = WebSourceCatalogEvidence(listOf(profile), { input }, { _, path, _ ->
            if (path.endsWith("source_tree_manifest.json")) manifestFile else descriptorFile })
        val snapshot = evidence.readRevision(reference())
        // The revision digest is still the canonical input preimage; manifest-only entries never change it.
        assertEquals(reference().sourceSha256, snapshot.reference.sourceSha256)
        assertEquals(listOf("Makefile", "UNRESOLVED.md", "reports/confidence.json", "src/modules/unit.c"), snapshot.files.map { it.evidence.path })
        assertEquals(listOf(true, false, false, true), snapshot.files.map { it.committedInput })
        val flat = WebRevisionSourcePages { _, _, _ -> snapshot }.page("owner", jobId, runId, revisionId, null, includeManifest = true)
            .getValue("items").jsonArray.map { it.jsonObject }
        assertEquals(listOf("source-input", "manifest-digest", "manifest-digest", "source-input"), flat.map { it.getValue("commitment").jsonPrimitive.content })
        assertEquals(listOf("0", null, null, "8"), flat.map { it.getValue("sizeBytes").jsonPrimitive.contentOrNull })
        val root = WebRevisionDirectoryPages { _, _, _ -> snapshot }.page("owner", jobId, runId, revisionId, "root", null, includeManifest = true)
        assertEquals(listOf("reports", "src", "Makefile", "UNRESOLVED.md"),
            root.getValue("items").jsonArray.map { it.jsonObject.getValue("displayName").jsonPrimitive.content })
        val note = root.getValue("items").jsonArray.map { it.jsonObject }.single { it.getValue("displayName").jsonPrimitive.content == "UNRESOLVED.md" }
        assertEquals(JsonNull, note.getValue("sizeBytes")); assertEquals("manifest-digest", note.getValue("commitment").jsonPrimitive.content)
        val noteId = note.getValue("fileId").jsonPrimitive.content
        val detail = WebRevisionFileMetadata { _, _, _ -> snapshot }.read(jobId, runId, revisionId, noteId, includeManifest = true).getValue("item").jsonObject
        assertTrue(detail.getValue("declaredViewable").jsonPrimitive.boolean && detail.getValue("declaredArchivable").jsonPrimitive.boolean)
        fun read(id: String, purpose: WebSourceReadPurpose = WebSourceReadPurpose.PREVIEW) = evidence.readFile(reference(), id, purpose, null) { _, _, path, _ ->
            captured(bodies.getValue(path), 9) }
        val chunk = read(noteId).chunk(WebSourceChunkQuery.parse(null))
        assertEquals(String(markdown), chunk.getValue("text").jsonPrimitive.content)
        assertEquals(markdown.size.toString(), chunk.getValue("sizeBytes").jsonPrimitive.content)
        assertEquals("utf8", chunk.getValue("representation").jsonPrimitive.content)
        val jsonId = flat[2].getValue("fileId").jsonPrimitive.content
        assertContentEquals(json, read(jsonId, WebSourceReadPurpose.DOWNLOAD).download())
        // The manifest digest is the only binding, so substituted bytes are refused rather than displayed.
        bodies["reports/confidence.json"] = "{}".toByteArray()
        assertEquals("SOURCE_REVISION_CHANGED", assertFailsWith<WebAccessDenied> { read(jsonId) }.code)
        val oversized = WebSourceCatalogEvidence(listOf(profile), { input }, { _, path, _ ->
            if (path.endsWith("source_tree_manifest.json")) manifestFile else descriptorFile })
        assertEquals("SOURCE_FILE_TOO_LARGE", assertFailsWith<WebAccessDenied> {
            oversized.readFile(reference(), noteId, WebSourceReadPurpose.PREVIEW, null) { _, _, _, _ ->
                throw decompengine.repair.RepairBudgetExceededException("over the reader limit") }
        }.code)
    }
}
